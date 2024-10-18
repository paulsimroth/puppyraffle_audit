### [M-#] Looping through players array to check for duplicates in `PuppyRaffle::enterRaffle` is a potential DoS attack, increasing gas costs for future users

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