# SC06: Unchecked External Calls

**Severity:** High  
**Silent Failure**

## Description

When external calls fail silently without proper error handling, contracts can continue execution in an inconsistent state. This is especially dangerous with low-level calls that don't automatically revert.

## Common Patterns

### 1. Unchecked Low-Level Call
```solidity
// VULNERABLE - ignores return value
function sendETH(address to, uint amount) external {
    to.call{value: amount}("");  // Could fail silently
}

// FIXED - check return value
function sendETH(address to, uint amount) external {
    (bool success, ) = to.call{value: amount}("");
    require(success, "Transfer failed");
}
```

### 2. Unchecked Token Transfer
```solidity
// VULNERABLE - some tokens don't return bool
function transferToken(address token, address to, uint amount) external {
    IERC20(token).transfer(to, amount);  // USDT returns nothing!
}

// FIXED - use SafeERC20
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

function transferToken(address token, address to, uint amount) external {
    IERC20(token).safeTransfer(to, amount);
}
```

### 3. Multiple Calls Without Checks
```solidity
// VULNERABLE
function batchTransfer(address[] calldata recipients, uint[] calldata amounts) external {
    for (uint i = 0; i < recipients.length; i++) {
        recipients[i].call{value: amounts[i]}("");  // Any failure is ignored
    }
}

// FIXED - track failures or revert
function batchTransfer(address[] calldata recipients, uint[] calldata amounts) external {
    for (uint i = 0; i < recipients.length; i++) {
        (bool success, ) = recipients[i].call{value: amounts[i]}("");
        require(success, "Transfer failed");
    }
}
```

### 4. Delegatecall Without Check
```solidity
// VULNERABLE
function upgrade(address newImpl) external onlyOwner {
    newImpl.delegatecall(abi.encodeWithSignature("initialize()"));
}

// FIXED
function upgrade(address newImpl) external onlyOwner {
    (bool success, ) = newImpl.delegatecall(abi.encodeWithSignature("initialize()"));
    require(success, "Initialization failed");
}
```

## Non-Standard Token Behaviors

Some tokens don't follow ERC20 exactly:

| Token | Behavior |
|-------|----------|
| USDT | No return value on transfer |
| BNB | No return value on transfer |
| Some tokens | Return false instead of reverting |
| Fee tokens | Transfer less than specified amount |

## Detection

### Slither Detectors
- `unchecked-lowlevel`
- `unchecked-send`
- `unchecked-transfer`

### Pattern Matching
```bash
# Find unchecked calls
grep -rn "\.call{" *.sol | grep -v "bool"
grep -rn "\.delegatecall" *.sol | grep -v "bool"
```

## Remediation

### 1. Always Check Return Values
```solidity
(bool success, bytes memory data) = target.call{value: msg.value}(callData);
require(success, "Call failed");
```

### 2. Use OpenZeppelin SafeERC20
```solidity
using SafeERC20 for IERC20;

// These revert on failure
token.safeTransfer(to, amount);
token.safeTransferFrom(from, to, amount);
token.safeApprove(spender, amount);
```

### 3. Use Address Library for ETH
```solidity
import "@openzeppelin/contracts/utils/Address.sol";

using Address for address payable;

// Reverts on failure
payable(recipient).sendValue(amount);
```

## Real-World Exploits

- **King of the Ether (2016):** Early example of unchecked send
- **Multiple DEXs:** Issues with non-standard tokens
