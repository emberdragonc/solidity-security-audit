# SC02: Oracle Manipulation

**Severity:** Critical  
**2024 Losses:** $8.8M  
**Common in DeFi**

## Description

Oracle manipulation occurs when attackers exploit price feeds or external data sources to manipulate contract behavior. This is especially dangerous in lending protocols, DEXs, and derivatives platforms.

## Attack Vectors

### 1. Spot Price Manipulation
```solidity
// VULNERABLE - uses spot price from DEX
function getPrice() public view returns (uint) {
    (uint reserve0, uint reserve1,) = pair.getReserves();
    return reserve1 * 1e18 / reserve0;  // Easily manipulated with flash loan
}

// FIXED - use TWAP (Time-Weighted Average Price)
function getPrice() public view returns (uint) {
    return oracle.consult(token, 1e18);  // Chainlink or Uniswap TWAP
}
```

### 2. Single Oracle Dependency
```solidity
// VULNERABLE - single point of failure
function getPrice() public view returns (uint) {
    return chainlinkOracle.latestAnswer();
}

// FIXED - use multiple oracles with fallback
function getPrice() public view returns (uint) {
    (uint price, bool valid) = primaryOracle.getPrice();
    if (!valid) {
        (price, valid) = fallbackOracle.getPrice();
    }
    require(valid, "No valid price");
    return price;
}
```

### 3. Stale Price Data
```solidity
// VULNERABLE - no freshness check
(, int price,,,) = priceFeed.latestRoundData();
return uint(price);

// FIXED - check timestamp
(, int price,, uint updatedAt,) = priceFeed.latestRoundData();
require(block.timestamp - updatedAt < MAX_DELAY, "Stale price");
require(price > 0, "Invalid price");
return uint(price);
```

## Detection

### Manual Checks
1. What oracles are used?
2. Is there freshness validation?
3. Single or multiple data sources?
4. Can spot prices be manipulated within a transaction?
5. Is TWAP used for DEX prices?

### Red Flags
- `getReserves()` for pricing
- No `updatedAt` check on Chainlink
- Single oracle dependency
- No price bounds/sanity checks

## Remediation

### 1. Use Time-Weighted Average Prices (TWAP)
```solidity
// Uniswap V3 TWAP example
function getTWAP(address pool, uint32 period) internal view returns (uint) {
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = period;
    secondsAgos[1] = 0;
    
    (int56[] memory tickCumulatives,) = IUniswapV3Pool(pool).observe(secondsAgos);
    int56 tickCumulativesDelta = tickCumulatives[1] - tickCumulatives[0];
    int24 avgTick = int24(tickCumulativesDelta / int56(uint56(period)));
    
    return OracleLibrary.getQuoteAtTick(avgTick, 1e18, token0, token1);
}
```

### 2. Use Chainlink with Proper Validation
```solidity
function getChainlinkPrice() internal view returns (uint) {
    (
        uint80 roundId,
        int256 price,
        ,
        uint256 updatedAt,
        uint80 answeredInRound
    ) = priceFeed.latestRoundData();
    
    require(price > 0, "Negative price");
    require(updatedAt > 0, "Round not complete");
    require(answeredInRound >= roundId, "Stale price");
    require(block.timestamp - updatedAt < HEARTBEAT, "Price too old");
    
    return uint256(price);
}
```

### 3. Circuit Breakers
```solidity
uint public lastPrice;
uint public constant MAX_DEVIATION = 10; // 10%

function validatePrice(uint newPrice) internal view {
    if (lastPrice > 0) {
        uint deviation = newPrice > lastPrice 
            ? (newPrice - lastPrice) * 100 / lastPrice
            : (lastPrice - newPrice) * 100 / lastPrice;
        require(deviation <= MAX_DEVIATION, "Price deviation too high");
    }
}
```

## Real-World Exploits

- **Mango Markets (2022):** $114M - Oracle manipulation via self-trading
- **Inverse Finance (2022):** $15.6M - TWAP manipulation
- **Bonq (2023):** $120M - Oracle price feed manipulation
