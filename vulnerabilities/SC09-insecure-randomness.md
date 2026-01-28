# SC09: Insecure Randomness

**Severity:** High  
**Common in Games/NFTs**

## Description

Blockchain data is deterministic and public. Using on-chain data as randomness source allows miners/validators to predict or manipulate outcomes. This affects lotteries, NFT reveals, games, and any random selection.

## Vulnerable Sources

| Source | Why It's Bad |
|--------|-------------|
| `block.timestamp` | Validator can manipulate within ~15 seconds |
| `block.number` | Predictable, miner-chosen |
| `blockhash()` | Miner can choose to publish or not |
| `block.prevrandao` | Validator-biasable in PoS |
| `keccak256(abi.encodePacked(...on-chain-data))` | All inputs visible |

## Vulnerable Patterns

### 1. Block-Based Randomness
```solidity
// VULNERABLE - miner/validator can manipulate
function random() public view returns (uint) {
    return uint(keccak256(abi.encodePacked(
        block.timestamp,
        block.number,
        msg.sender
    )));
}

function pickWinner() external {
    uint index = random() % participants.length;
    winner = participants[index];  // Predictable!
}
```

### 2. Blockhash Randomness
```solidity
// VULNERABLE - miner can withhold block
function random() public view returns (uint) {
    return uint(blockhash(block.number - 1));
}

// Also vulnerable - blockhash returns 0 for blocks > 256 ago
function futureRandom(uint blockNumber) public view returns (uint) {
    return uint(blockhash(blockNumber));  // Returns 0 if too old!
}
```

### 3. prevrandao (Post-Merge)
```solidity
// SOMEWHAT BETTER but still biasable
function random() public view returns (uint) {
    return block.prevrandao;  // Validators can influence
}
```

## Secure Patterns

### 1. Chainlink VRF (Recommended)
```solidity
import "@chainlink/contracts/src/v0.8/vrf/VRFConsumerBaseV2.sol";

contract SecureRandom is VRFConsumerBaseV2 {
    function requestRandomness() external returns (uint256 requestId) {
        requestId = COORDINATOR.requestRandomWords(
            keyHash,
            subscriptionId,
            requestConfirmations,
            callbackGasLimit,
            numWords
        );
    }
    
    function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) 
        internal override 
    {
        // Use randomWords[0] - cryptographically secure
        winner = participants[randomWords[0] % participants.length];
    }
}
```

### 2. Commit-Reveal Scheme
```solidity
// Phase 1: Users commit hash of their secret
mapping(address => bytes32) public commitments;

function commit(bytes32 hash) external {
    commitments[msg.sender] = hash;
}

// Phase 2: Users reveal secrets
bytes32 public combinedRandomness;

function reveal(bytes32 secret) external {
    require(keccak256(abi.encodePacked(secret)) == commitments[msg.sender]);
    combinedRandomness = keccak256(abi.encodePacked(combinedRandomness, secret));
}

// Phase 3: Use combined randomness
function pickWinner() external {
    // Only after all reveals
    uint index = uint(combinedRandomness) % participants.length;
    winner = participants[index];
}
```

### 3. External Oracle
```solidity
// Use any trusted external randomness source
interface IRandomOracle {
    function getRandomNumber() external returns (uint256);
}

function pickWinner() external {
    uint256 random = randomOracle.getRandomNumber();
    winner = participants[random % participants.length];
}
```

## Detection

### Pattern Matching
```bash
grep -rn "block.timestamp\|block.number\|blockhash\|prevrandao" *.sol
```

### Slither
- `weak-prng` detector

### Manual Review
1. Is randomness used for value distribution?
2. What's the source?
3. Can outcome be predicted/manipulated?

## Remediation Priority

| Use Case | Minimum Security |
|----------|-----------------|
| High-value lottery | Chainlink VRF |
| NFT reveal | Chainlink VRF or commit-reveal |
| Game outcomes | Chainlink VRF |
| Low-value random | Commit-reveal acceptable |
| Non-financial | Block-based may be okay |

## Real-World Exploits

- **Fomo3D (2018):** Block stuffing to win jackpot
- **SmartBillions (2017):** Predictable randomness exploit
- **Meebits (2021):** NFT trait prediction
