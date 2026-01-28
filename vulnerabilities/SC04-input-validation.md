# SC04: Lack of Input Validation

**Severity:** High  
**Common Attack Vector**

## Description

Input validation failures occur when contracts don't properly verify user-supplied data, leading to unexpected behavior, exploits, or denial of service.

## Common Patterns

### 1. Missing Zero Address Checks
```solidity
// VULNERABLE
function setOwner(address newOwner) external onlyOwner {
    owner = newOwner;  // Can accidentally set to address(0)
}

// FIXED
function setOwner(address newOwner) external onlyOwner {
    require(newOwner != address(0), "Zero address");
    owner = newOwner;
}
```

### 2. Missing Amount Validation
```solidity
// VULNERABLE
function withdraw(uint amount) external {
    balances[msg.sender] -= amount;  // Can underflow in pre-0.8
    payable(msg.sender).transfer(amount);
}

// FIXED
function withdraw(uint amount) external {
    require(amount > 0, "Zero amount");
    require(amount <= balances[msg.sender], "Insufficient balance");
    balances[msg.sender] -= amount;
    payable(msg.sender).transfer(amount);
}
```

### 3. Missing Array Bounds
```solidity
// VULNERABLE
function getUser(uint index) external view returns (address) {
    return users[index];  // Can revert with unhelpful error
}

// FIXED
function getUser(uint index) external view returns (address) {
    require(index < users.length, "Index out of bounds");
    return users[index];
}
```

### 4. Unvalidated External Contract Addresses
```solidity
// VULNERABLE - user can pass malicious contract
function swapTokens(address tokenIn, address tokenOut, uint amount) external {
    IERC20(tokenIn).transferFrom(msg.sender, address(this), amount);
    // tokenIn could be a malicious contract
}

// FIXED - use allowlist
mapping(address => bool) public allowedTokens;

function swapTokens(address tokenIn, address tokenOut, uint amount) external {
    require(allowedTokens[tokenIn], "Token not allowed");
    require(allowedTokens[tokenOut], "Token not allowed");
    IERC20(tokenIn).transferFrom(msg.sender, address(this), amount);
}
```

### 5. Missing Slippage Protection
```solidity
// VULNERABLE - no slippage protection
function swap(uint amountIn) external returns (uint amountOut) {
    amountOut = calculateOutput(amountIn);
    tokenIn.transferFrom(msg.sender, address(this), amountIn);
    tokenOut.transfer(msg.sender, amountOut);
}

// FIXED - user specifies minimum output
function swap(uint amountIn, uint minAmountOut) external returns (uint amountOut) {
    amountOut = calculateOutput(amountIn);
    require(amountOut >= minAmountOut, "Slippage exceeded");
    tokenIn.transferFrom(msg.sender, address(this), amountIn);
    tokenOut.transfer(msg.sender, amountOut);
}
```

### 6. Missing Deadline Validation
```solidity
// VULNERABLE - transaction can be held and executed later
function swap(uint amount, uint minOut) external {
    // No deadline - MEV bots can delay execution
}

// FIXED
function swap(uint amount, uint minOut, uint deadline) external {
    require(block.timestamp <= deadline, "Expired");
    // ...
}
```

## Detection

### Slither Detectors
- `missing-zero-check`
- `controlled-array-length`

### Manual Checks
1. All external function parameters validated
2. Zero address checks on address parameters
3. Non-zero checks on amounts
4. Array bounds validation
5. Slippage and deadline parameters

## Remediation

### Use a Validation Library
```solidity
library Validation {
    function requireNonZero(address addr, string memory param) internal pure {
        require(addr != address(0), string.concat(param, " is zero"));
    }
    
    function requirePositive(uint amount, string memory param) internal pure {
        require(amount > 0, string.concat(param, " must be positive"));
    }
    
    function requireInRange(uint value, uint min, uint max) internal pure {
        require(value >= min && value <= max, "Out of range");
    }
}
```

### Modifier Pattern
```solidity
modifier validAddress(address addr) {
    require(addr != address(0), "Invalid address");
    _;
}

modifier positiveAmount(uint amount) {
    require(amount > 0, "Amount must be positive");
    _;
}

function transfer(address to, uint amount) 
    external 
    validAddress(to) 
    positiveAmount(amount) 
{
    // ...
}
```

## Real-World Exploits

- **Wormhole (2022):** $326M - Missing signature validation
- **Qubit (2022):** $80M - Missing input validation on deposit
