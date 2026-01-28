# SC01: Access Control Vulnerabilities

**Severity:** Critical  
**2024 Losses:** $953.2M  
**Prevalence:** #1 most exploited

## Description

Access control flaws allow unauthorized users to access or modify contract data or functions. These occur when code fails to enforce proper permission checks.

## Common Patterns

### 1. Missing Access Modifiers
```solidity
// VULNERABLE
function withdraw(uint amount) public {
    payable(msg.sender).transfer(amount);
}

// FIXED
function withdraw(uint amount) public onlyOwner {
    payable(msg.sender).transfer(amount);
}
```

### 2. Unprotected Initialize Functions
```solidity
// VULNERABLE - anyone can call
function initialize(address _owner) public {
    owner = _owner;
}

// FIXED - use initializer modifier
function initialize(address _owner) public initializer {
    owner = _owner;
}
```

### 3. tx.origin Authentication
```solidity
// VULNERABLE - can be phished
require(tx.origin == owner);

// FIXED - use msg.sender
require(msg.sender == owner);
```

### 4. Incorrect Visibility
```solidity
// VULNERABLE - public by default in old Solidity
function _internalLogic() { ... }

// FIXED - explicitly internal/private
function _internalLogic() internal { ... }
```

## Detection

### Slither Detectors
- `unprotected-upgrade`
- `suicidal`
- `arbitrary-send-eth`
- `protected-vars`

### Manual Checks
1. All admin functions have access control
2. Initialize can only be called once
3. No tx.origin for authentication
4. Role-based access properly implemented
5. Ownership transfer is two-step

## Remediation

1. Use OpenZeppelin's `Ownable` or `AccessControl`
2. Use `initializer` modifier for upgradeable contracts
3. Never use `tx.origin` for authorization
4. Implement two-step ownership transfers
5. Use explicit visibility modifiers

## Real-World Exploits

- **Ronin Bridge (2022):** $624M - Compromised validator keys
- **Wormhole (2022):** $326M - Unprotected initialization
- **Nomad Bridge (2022):** $190M - Failed access control on process()
