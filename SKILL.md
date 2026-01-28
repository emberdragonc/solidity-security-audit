---
name: solidity-security-audit
version: 1.0.0
description: |
  Comprehensive Solidity smart contract security audit skill. Checks for 
  OWASP Top 10 vulnerabilities, integrates with Slither, and provides 
  remediation guidance. Open source - contributions welcome!
author: Ember 🐉 (emberclawd.eth)
repo: https://github.com/emberdragonc/solidity-security-audit
---

# Solidity Security Audit Skill

A comprehensive security audit framework for Solidity smart contracts.

## Quick Start

```bash
# Audit a contract
./audit.sh path/to/Contract.sol

# Or with Foundry project
./audit.sh path/to/foundry/project
```

## What It Checks

Based on **OWASP Smart Contract Top 10 (2025)** and industry best practices.

### 🔴 Critical Vulnerabilities

| ID | Vulnerability | 2024 Losses | Detection |
|----|--------------|-------------|-----------|
| SC01 | Access Control | $953.2M | Manual + Slither |
| SC02 | Oracle Manipulation | $8.8M | Manual review |
| SC03 | Logic Errors | $63.8M | Manual + Tests |
| SC05 | Reentrancy | $35.7M | Slither + Pattern |
| SC07 | Flash Loan Attacks | $33.8M | Manual review |

### 🟠 High Vulnerabilities

| ID | Vulnerability | Detection |
|----|--------------|-----------|
| SC04 | Input Validation | Slither + Manual |
| SC06 | Unchecked External Calls | Slither |
| SC08 | Integer Overflow/Underflow | Slither (pre-0.8) |
| SC09 | Insecure Randomness | Pattern matching |
| SC10 | DoS Attacks | Slither + Manual |

### 🟡 Medium/Low Issues

- Gas optimization
- Code quality
- Documentation
- Test coverage
- Upgrade safety

## Audit Methodology

### Phase 1: Automated Analysis
1. Run Slither static analysis
2. Run custom pattern detectors
3. Check compiler warnings
4. Analyze test coverage

### Phase 2: Manual Review
1. Access control review
2. Business logic validation
3. External interaction analysis
4. Economic attack vectors
5. Upgrade mechanism review

### Phase 3: Reporting
1. Severity classification
2. Proof of concept (where applicable)
3. Remediation recommendations
4. Re-audit verification

## Integration

### With Foundry
```bash
cd your-foundry-project
forge build
../../audit.sh .
```

### With Hardhat
```bash
cd your-hardhat-project
npx hardhat compile
../../audit.sh .
```

## Contributing

This is an open source project. Contributions welcome!

- Add new vulnerability patterns
- Improve detection logic
- Add remediation examples
- Report false positives/negatives

See CONTRIBUTING.md for guidelines.

## References

- [OWASP Smart Contract Top 10 (2025)](https://owasp.org/www-project-smart-contract-top-10/)
- [SWC Registry](https://swcregistry.io/)
- [Slither Detectors](https://github.com/crytic/slither)
- [EEA EthTrust Security Levels](https://entethalliance.org/specs/ethtrust-sl)
- [Rekt Leaderboard](https://rekt.news/leaderboard/)

## License

MIT - Use freely, contribute back!
