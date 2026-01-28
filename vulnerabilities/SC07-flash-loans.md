# SC07: Flash Loan Attacks

**Severity:** Critical  
**2024 Losses:** $33.8M  
**DeFi Specific**

## Description

Flash loans allow borrowing large amounts without collateral, as long as the loan is repaid within the same transaction. Attackers use this to manipulate prices, exploit logic flaws, or attack governance systems.

## Attack Patterns

### 1. Price Manipulation
```solidity
// Attack flow:
// 1. Flash loan large amount of Token A
// 2. Dump Token A on DEX, crashing price
// 3. Exploit protocol using manipulated price
// 4. Profit, repay flash loan

// VULNERABLE - uses spot price
function liquidate(address user) external {
    uint price = dex.getSpotPrice(collateral);  // Manipulatable
    require(getDebt(user) > getCollateralValue(user, price));
    // ... liquidation logic
}

// FIXED - use TWAP or Chainlink
function liquidate(address user) external {
    uint price = oracle.getTWAP(collateral, 30 minutes);
    require(getDebt(user) > getCollateralValue(user, price));
}
```

### 2. Governance Attacks
```solidity
// Attack flow:
// 1. Flash loan governance tokens
// 2. Create and vote on malicious proposal
// 3. Execute proposal in same block
// 4. Return tokens

// VULNERABLE - no timelock
function vote(uint proposalId) external {
    uint votes = token.balanceOf(msg.sender);  // Can be flash loaned
    proposals[proposalId].votes += votes;
}

// FIXED - use checkpoints/snapshots
function vote(uint proposalId) external {
    uint votes = token.getPastVotes(msg.sender, proposals[proposalId].snapshot);
    proposals[proposalId].votes += votes;
}
```

### 3. Arbitrage Exploitation
```solidity
// Attack flow:
// 1. Flash loan
// 2. Find mispriced asset across protocols
// 3. Buy low, sell high
// 4. Repay with profit

// This is actually intended behavior of flash loans
// But protocols should protect against price impact
```

### 4. Donation Attacks (Vault Inflation)
```solidity
// Attack on first depositor:
// 1. Deposit 1 wei to be first depositor, get 1 share
// 2. Flash loan large amount
// 3. Donate to vault, inflating share price
// 4. Next depositor gets 0 shares due to rounding
// 5. Attacker redeems for more than deposited

// VULNERABLE - first depositor can inflate
function deposit(uint assets) external returns (uint shares) {
    shares = totalSupply == 0 ? assets : assets * totalSupply / totalAssets;
    _mint(msg.sender, shares);
    totalAssets += assets;
}

// FIXED - virtual shares/assets
uint constant VIRTUAL_SHARES = 1e6;
uint constant VIRTUAL_ASSETS = 1e6;

function deposit(uint assets) external returns (uint shares) {
    shares = (assets * (totalSupply + VIRTUAL_SHARES)) / (totalAssets + VIRTUAL_ASSETS);
    _mint(msg.sender, shares);
    totalAssets += assets;
}
```

## Detection

### Manual Review
1. Can any function be exploited with temporary large balance?
2. Are prices read within same transaction they're used?
3. Is governance protected against flash-borrowed votes?
4. Are vaults protected against donation/inflation attacks?

### Red Flags
- `getReserves()` for pricing
- Same-block price reads
- No voting snapshots
- First depositor edge cases

## Remediation

### 1. Time-Weighted Prices
```solidity
// Use prices averaged over time, not spot
uint price = oracle.getTWAP(token, 30 minutes);
```

### 2. Snapshot-Based Governance
```solidity
// OpenZeppelin ERC20Votes
function getPastVotes(address account, uint blockNumber) public view returns (uint);
```

### 3. Multi-Block Operations
```solidity
// Require operations to span multiple blocks
mapping(address => uint) public lastActionBlock;

function sensitiveAction() external {
    require(block.number > lastActionBlock[msg.sender] + MIN_BLOCKS);
    lastActionBlock[msg.sender] = block.number;
}
```

### 4. Access Controls on Donations
```solidity
// Don't allow arbitrary donations
function donate(uint amount) external onlyWhitelisted {
    // ...
}
```

## Real-World Exploits

- **bZx (2020):** $1M - First major flash loan attack
- **Pancake Bunny (2021):** $45M - Price manipulation
- **Cream Finance (2021):** $130M - Multiple flash loan attacks
- **Beanstalk (2022):** $182M - Flash loan governance attack
