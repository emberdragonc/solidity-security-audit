# SC03: Logic Errors

**Severity:** Critical  
**2024 Losses:** $63.8M  
**Hardest to Detect**

## Description

Logic errors occur when contract code doesn't behave as intended due to flawed business logic, incorrect assumptions, or edge case handling failures. These are often the hardest bugs to find because the code compiles and runs without errors.

## Common Patterns

### 1. Incorrect Order of Operations
```solidity
// VULNERABLE - fee calculated on wrong amount
function swap(uint amount) external {
    uint fee = amount * FEE_BPS / 10000;
    uint amountAfterFee = amount - fee;
    token.transferFrom(msg.sender, address(this), amount);
    token.transfer(msg.sender, amountAfterFee);  // User pays fee twice
}

// FIXED - transfer exact amount received
function swap(uint amount) external {
    uint fee = amount * FEE_BPS / 10000;
    uint amountAfterFee = amount - fee;
    token.transferFrom(msg.sender, address(this), amountAfterFee);
    token.transfer(treasury, fee);
}
```

### 2. Rounding Errors
```solidity
// VULNERABLE - rounds to zero for small amounts
function calculateShare(uint amount, uint total) public view returns (uint) {
    return amount * sharePrice / total;  // If amount * sharePrice < total, returns 0
}

// FIXED - check for dust and use proper scaling
function calculateShare(uint amount, uint total) public view returns (uint) {
    require(amount * sharePrice >= total, "Amount too small");
    return amount * sharePrice / total;
}
```

### 3. Off-by-One Errors
```solidity
// VULNERABLE - wrong loop bounds
for (uint i = 0; i <= users.length; i++) {  // <= causes out of bounds
    users[i].reward();
}

// FIXED
for (uint i = 0; i < users.length; i++) {
    users[i].reward();
}
```

### 4. Incorrect State Transitions
```solidity
// VULNERABLE - can claim multiple times
function claim() external {
    require(eligible[msg.sender], "Not eligible");
    token.transfer(msg.sender, REWARD);
    // Missing: eligible[msg.sender] = false;
}

// FIXED
function claim() external {
    require(eligible[msg.sender], "Not eligible");
    eligible[msg.sender] = false;  // Update state BEFORE transfer
    token.transfer(msg.sender, REWARD);
}
```

### 5. Flawed Reward/Share Calculations
```solidity
// VULNERABLE - first depositor can steal funds
function deposit(uint amount) external {
    uint shares = totalSupply == 0 
        ? amount 
        : amount * totalSupply / totalAssets;  // Donation attack possible
    
    _mint(msg.sender, shares);
    totalAssets += amount;
}

// FIXED - use virtual shares/assets or minimum deposit
function deposit(uint amount) external {
    require(amount >= MIN_DEPOSIT, "Too small");
    uint shares = (amount * (totalSupply + VIRTUAL_SHARES)) / (totalAssets + VIRTUAL_ASSETS);
    _mint(msg.sender, shares);
    totalAssets += amount;
}
```

## Detection

### Manual Review Focus
1. Trace every code path manually
2. Check all mathematical operations for edge cases
3. Verify state machine transitions
4. Test with minimum and maximum values
5. Review business logic against specifications

### Testing Approaches
- Invariant/fuzzing tests (Foundry, Echidna)
- Property-based testing
- Edge case unit tests
- Formal verification for critical logic

## Remediation

### 1. Comprehensive Testing
```solidity
// Foundry invariant test example
function invariant_totalSupplyMatchesBalances() public {
    uint sum = 0;
    for (uint i = 0; i < actors.length; i++) {
        sum += token.balanceOf(actors[i]);
    }
    assertEq(token.totalSupply(), sum);
}
```

### 2. Use Well-Tested Patterns
- OpenZeppelin for standard patterns
- Solmate for gas-optimized standards
- Don't reinvent basic mechanisms

### 3. Formal Specification
Document expected behavior explicitly:
```solidity
/// @notice Deposits tokens and mints shares
/// @dev shares = amount * totalSupply / totalAssets
/// @dev INVARIANT: sum(balances) == totalSupply
/// @dev INVARIANT: totalAssets >= sum(deposits) - sum(withdrawals)
```

## Real-World Exploits

- **Compound (2021):** $80M - Logic error in reward distribution
- **Level Finance (2023):** $1.1M - Referral logic exploitation
- **Sentiment (2023):** $1M - Logic error in position calculation
