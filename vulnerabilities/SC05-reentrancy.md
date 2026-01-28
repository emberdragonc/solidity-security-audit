# SC05: Reentrancy Attacks

**Severity:** Critical  
**2024 Losses:** $35.7M  
**Classic Attack Vector**

## Description

Reentrancy occurs when an external call allows the called contract to re-enter the calling function before it completes, potentially causing repeated state changes.

## Types of Reentrancy

### 1. Single-Function Reentrancy
```solidity
// VULNERABLE
function withdraw() public {
    uint bal = balances[msg.sender];
    (bool sent, ) = msg.sender.call{value: bal}("");
    require(sent);
    balances[msg.sender] = 0;  // State update AFTER call
}

// FIXED - Checks-Effects-Interactions pattern
function withdraw() public {
    uint bal = balances[msg.sender];
    balances[msg.sender] = 0;  // State update BEFORE call
    (bool sent, ) = msg.sender.call{value: bal}("");
    require(sent);
}
```

### 2. Cross-Function Reentrancy
```solidity
// VULNERABLE - attacker can call transfer() during withdraw()
function withdraw() public {
    uint bal = balances[msg.sender];
    (bool sent, ) = msg.sender.call{value: bal}("");
    require(sent);
    balances[msg.sender] = 0;
}

function transfer(address to, uint amount) public {
    require(balances[msg.sender] >= amount);
    balances[to] += amount;
    balances[msg.sender] -= amount;
}
```

### 3. Cross-Contract Reentrancy
When multiple contracts share state, attacker can reenter through a different contract.

### 4. Read-Only Reentrancy
Exploits view functions that read inconsistent state during external calls.
```solidity
// VULNERABLE - price() reads during external call
function getPrice() public view returns (uint) {
    return totalAssets / totalSupply;  // Can be stale during reentrant call
}
```

## Detection

### Slither Detectors
- `reentrancy-eth`
- `reentrancy-no-eth`
- `reentrancy-benign`
- `reentrancy-events`

### Pattern Matching
1. External calls before state updates
2. Missing ReentrancyGuard on state-changing functions
3. Callbacks to untrusted addresses

## Remediation

### 1. Checks-Effects-Interactions Pattern
```solidity
function withdraw() public {
    // CHECKS
    uint bal = balances[msg.sender];
    require(bal > 0, "No balance");
    
    // EFFECTS (state changes)
    balances[msg.sender] = 0;
    
    // INTERACTIONS (external calls)
    (bool sent, ) = msg.sender.call{value: bal}("");
    require(sent);
}
```

### 2. ReentrancyGuard
```solidity
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract MyContract is ReentrancyGuard {
    function withdraw() public nonReentrant {
        // Safe from reentrancy
    }
}
```

### 3. Pull Over Push
```solidity
// Instead of sending directly, let users withdraw
mapping(address => uint) public pendingWithdrawals;

function asyncWithdraw() public {
    uint amount = pendingWithdrawals[msg.sender];
    pendingWithdrawals[msg.sender] = 0;
    payable(msg.sender).transfer(amount);
}
```

## Real-World Exploits

- **The DAO (2016):** $60M - First major reentrancy attack
- **Curve (2023):** $70M - Read-only reentrancy in Vyper
- **Fei Protocol (2022):** $80M - Cross-contract reentrancy
