# SC10: Denial of Service (DoS) Attacks

**Severity:** Medium-High  
**Availability Impact**

## Description

DoS attacks prevent legitimate users from using the contract. Unlike traditional DoS, blockchain DoS can be permanent if the contract reaches an unrecoverable state.

## Attack Patterns

### 1. Unbounded Loops
```solidity
// VULNERABLE - gas limit DoS
function distributeRewards() external {
    for (uint i = 0; i < users.length; i++) {
        payable(users[i]).transfer(rewards[users[i]]);
    }
    // If users.length too large, always exceeds gas limit
}

// FIXED - pagination
function distributeRewards(uint start, uint end) external {
    require(end <= users.length && start < end);
    for (uint i = start; i < end; i++) {
        payable(users[i]).transfer(rewards[users[i]]);
    }
}

// BEST - pull over push
function claimReward() external {
    uint reward = rewards[msg.sender];
    rewards[msg.sender] = 0;
    payable(msg.sender).transfer(reward);
}
```

### 2. External Call Failures
```solidity
// VULNERABLE - single failure blocks everyone
function distributeToAll() external {
    for (uint i = 0; i < recipients.length; i++) {
        // If one recipient reverts, all fail
        recipients[i].transfer(amounts[i]);
    }
}

// FIXED - handle failures gracefully
function distributeToAll() external {
    for (uint i = 0; i < recipients.length; i++) {
        (bool success, ) = recipients[i].call{value: amounts[i]}("");
        if (!success) {
            failedTransfers[recipients[i]] = amounts[i];
        }
    }
}
```

### 3. Block Gas Limit DoS
```solidity
// VULNERABLE - attacker can add many small deposits
mapping(address => uint[]) public userDeposits;

function deposit() external payable {
    userDeposits[msg.sender].push(msg.value);
}

function withdraw() external {
    uint total = 0;
    uint[] storage deposits = userDeposits[msg.sender];
    for (uint i = 0; i < deposits.length; i++) {
        total += deposits[i];  // Unbounded loop
    }
    delete userDeposits[msg.sender];
    payable(msg.sender).transfer(total);
}

// FIXED - track total separately
mapping(address => uint) public balances;

function deposit() external payable {
    balances[msg.sender] += msg.value;
}

function withdraw() external {
    uint amount = balances[msg.sender];
    balances[msg.sender] = 0;
    payable(msg.sender).transfer(amount);
}
```

### 4. Owner/Admin DoS
```solidity
// VULNERABLE - if owner key lost, contract stuck
function withdraw() external onlyOwner {
    payable(owner).transfer(address(this).balance);
}

// FIXED - timelocked emergency withdrawal
uint public emergencyWithdrawTime;

function initiateEmergencyWithdraw() external onlyOwner {
    emergencyWithdrawTime = block.timestamp + 7 days;
}

function emergencyWithdraw() external {
    require(block.timestamp >= emergencyWithdrawTime);
    require(emergencyWithdrawTime > 0);
    // Allow withdrawal after timelock
}
```

### 5. Unexpected Revert in Receive/Fallback
```solidity
// VULNERABLE - contract that always reverts on receive
contract Attacker {
    receive() external payable {
        revert("No thanks");  // Blocks any contract sending ETH
    }
}

// FIXED - use pull pattern or call() with failure handling
function sendReward(address winner) internal {
    (bool success, ) = winner.call{value: reward}("");
    if (!success) {
        pendingRewards[winner] += reward;  // Let them claim later
    }
}
```

### 6. Storage/Array Manipulation
```solidity
// VULNERABLE - attacker can grow array indefinitely
address[] public participants;

function join() external {
    participants.push(msg.sender);  // No limit
}

// FIXED - limit array size
uint constant MAX_PARTICIPANTS = 1000;

function join() external {
    require(participants.length < MAX_PARTICIPANTS);
    participants.push(msg.sender);
}
```

## Detection

### Slither Detectors
- `costly-loop`
- `calls-loop`
- `controlled-array-length`
- `msg-value-loop`

### Manual Checks
1. Any unbounded loops?
2. External calls in loops?
3. Single points of failure?
4. Array growth limits?
5. Pull vs push patterns?

## Remediation

### 1. Pull Over Push
```solidity
// Let users withdraw instead of pushing to them
mapping(address => uint) public pendingWithdrawals;

function withdraw() external {
    uint amount = pendingWithdrawals[msg.sender];
    pendingWithdrawals[msg.sender] = 0;
    payable(msg.sender).transfer(amount);
}
```

### 2. Pagination
```solidity
function processUsers(uint offset, uint limit) external {
    uint end = min(offset + limit, users.length);
    for (uint i = offset; i < end; i++) {
        // Process user
    }
}
```

### 3. Gas Limits on External Calls
```solidity
// Limit gas forwarded
(bool success, ) = recipient.call{value: amount, gas: 2300}("");
```

### 4. Circuit Breakers
```solidity
bool public paused;

modifier whenNotPaused() {
    require(!paused, "Paused");
    _;
}

function pause() external onlyOwner {
    paused = true;
}
```

## Real-World Exploits

- **GovernMental (2016):** Jackpot stuck due to gas limit
- **Parity Multisig (2017):** Wallet "accidentally" killed
- **King of the Ether:** Winners blocking new kings
