#!/bin/bash
# Solidity Security Audit Script
# Author: Ember 🐉 (emberclawd.eth)
# License: MIT

set -e

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-.}"
REPORT_DIR="./audit-report-$(date +%Y%m%d-%H%M%S)"

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     🐉 Ember's Solidity Security Audit Tool v1.0.0 🐉        ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Target: ${GREEN}$TARGET${NC}"
echo -e "Report: ${GREEN}$REPORT_DIR${NC}"
echo ""

mkdir -p "$REPORT_DIR"

# ============================================================================
# PHASE 1: AUTOMATED ANALYSIS
# ============================================================================
echo -e "${YELLOW}━━━ Phase 1: Automated Analysis ━━━${NC}"

# 1.1 Run Slither
echo -e "\n${BLUE}[1.1] Running Slither static analysis...${NC}"
if command -v slither &> /dev/null; then
    slither "$TARGET" --json "$REPORT_DIR/slither.json" 2>/dev/null || true
    slither "$TARGET" > "$REPORT_DIR/slither.txt" 2>&1 || true
    
    # Count findings by severity
    if [ -f "$REPORT_DIR/slither.json" ]; then
        HIGH=$(cat "$REPORT_DIR/slither.json" | grep -o '"impact": "High"' | wc -l)
        MEDIUM=$(cat "$REPORT_DIR/slither.json" | grep -o '"impact": "Medium"' | wc -l)
        LOW=$(cat "$REPORT_DIR/slither.json" | grep -o '"impact": "Low"' | wc -l)
        INFO=$(cat "$REPORT_DIR/slither.json" | grep -o '"impact": "Informational"' | wc -l)
        
        echo -e "  ${RED}High: $HIGH${NC}"
        echo -e "  ${YELLOW}Medium: $MEDIUM${NC}"
        echo -e "  ${GREEN}Low: $LOW${NC}"
        echo -e "  ${BLUE}Info: $INFO${NC}"
    fi
else
    echo -e "  ${RED}Slither not found. Install: pip install slither-analyzer${NC}"
fi

# 1.2 Pattern Matching
echo -e "\n${BLUE}[1.2] Checking dangerous patterns...${NC}"

# Find all .sol files
SOL_FILES=$(find "$TARGET" -name "*.sol" -not -path "*/node_modules/*" -not -path "*/lib/*" 2>/dev/null)

if [ -z "$SOL_FILES" ]; then
    echo -e "  ${RED}No Solidity files found${NC}"
    exit 1
fi

# Pattern checks
echo "" > "$REPORT_DIR/patterns.txt"

# SC01: tx.origin usage
echo -e "  Checking tx.origin..."
TX_ORIGIN=$(grep -rn "tx.origin" $SOL_FILES 2>/dev/null | grep -v "// " || true)
if [ -n "$TX_ORIGIN" ]; then
    echo -e "  ${RED}⚠ Found tx.origin usage (SC01)${NC}"
    echo "=== tx.origin usage (potential phishing vulnerability) ===" >> "$REPORT_DIR/patterns.txt"
    echo "$TX_ORIGIN" >> "$REPORT_DIR/patterns.txt"
    echo "" >> "$REPORT_DIR/patterns.txt"
fi

# SC05: Reentrancy patterns
echo -e "  Checking reentrancy patterns..."
EXTERNAL_CALLS=$(grep -rn "\.call{" $SOL_FILES 2>/dev/null || true)
if [ -n "$EXTERNAL_CALLS" ]; then
    echo -e "  ${YELLOW}! External calls found - verify CEI pattern${NC}"
    echo "=== External calls (check for reentrancy) ===" >> "$REPORT_DIR/patterns.txt"
    echo "$EXTERNAL_CALLS" >> "$REPORT_DIR/patterns.txt"
    echo "" >> "$REPORT_DIR/patterns.txt"
fi

# SC06: Unchecked call returns
echo -e "  Checking unchecked calls..."
UNCHECKED=$(grep -rn "\.call{" $SOL_FILES 2>/dev/null | grep -v "bool" | grep -v "success" || true)
if [ -n "$UNCHECKED" ]; then
    echo -e "  ${RED}⚠ Potentially unchecked external calls (SC06)${NC}"
    echo "=== Unchecked external calls ===" >> "$REPORT_DIR/patterns.txt"
    echo "$UNCHECKED" >> "$REPORT_DIR/patterns.txt"
    echo "" >> "$REPORT_DIR/patterns.txt"
fi

# SC09: Block-based randomness
echo -e "  Checking randomness sources..."
RANDOMNESS=$(grep -rn "block.timestamp\|block.number\|blockhash" $SOL_FILES 2>/dev/null | grep -v "// " || true)
if [ -n "$RANDOMNESS" ]; then
    echo -e "  ${YELLOW}! Block-based values found - not secure for randomness (SC09)${NC}"
    echo "=== Block-based values (insecure randomness) ===" >> "$REPORT_DIR/patterns.txt"
    echo "$RANDOMNESS" >> "$REPORT_DIR/patterns.txt"
    echo "" >> "$REPORT_DIR/patterns.txt"
fi

# Selfdestruct
echo -e "  Checking selfdestruct..."
SELFDESTRUCT=$(grep -rn "selfdestruct\|suicide" $SOL_FILES 2>/dev/null || true)
if [ -n "$SELFDESTRUCT" ]; then
    echo -e "  ${RED}⚠ selfdestruct found - verify access control${NC}"
    echo "=== selfdestruct usage ===" >> "$REPORT_DIR/patterns.txt"
    echo "$SELFDESTRUCT" >> "$REPORT_DIR/patterns.txt"
    echo "" >> "$REPORT_DIR/patterns.txt"
fi

# Delegatecall
echo -e "  Checking delegatecall..."
DELEGATECALL=$(grep -rn "delegatecall" $SOL_FILES 2>/dev/null || true)
if [ -n "$DELEGATECALL" ]; then
    echo -e "  ${RED}⚠ delegatecall found - high risk${NC}"
    echo "=== delegatecall usage (high risk) ===" >> "$REPORT_DIR/patterns.txt"
    echo "$DELEGATECALL" >> "$REPORT_DIR/patterns.txt"
    echo "" >> "$REPORT_DIR/patterns.txt"
fi

# ============================================================================
# PHASE 2: CODE QUALITY CHECKS
# ============================================================================
echo -e "\n${YELLOW}━━━ Phase 2: Code Quality ━━━${NC}"

# Check for OpenZeppelin usage
echo -e "  Checking dependencies..."
if grep -rq "@openzeppelin" $SOL_FILES 2>/dev/null; then
    echo -e "  ${GREEN}✓ Using OpenZeppelin contracts${NC}"
else
    echo -e "  ${YELLOW}! Not using OpenZeppelin - consider using battle-tested libraries${NC}"
fi

# Check for ReentrancyGuard
if grep -rq "ReentrancyGuard\|nonReentrant" $SOL_FILES 2>/dev/null; then
    echo -e "  ${GREEN}✓ ReentrancyGuard in use${NC}"
else
    echo -e "  ${YELLOW}! No ReentrancyGuard found - consider adding for external calls${NC}"
fi

# Check Solidity version
SOL_VERSION=$(grep -rh "pragma solidity" $SOL_FILES 2>/dev/null | head -1)
echo -e "  Solidity version: ${BLUE}$SOL_VERSION${NC}"

if echo "$SOL_VERSION" | grep -q "0.8"; then
    echo -e "  ${GREEN}✓ Using Solidity 0.8+ (built-in overflow protection)${NC}"
else
    echo -e "  ${RED}⚠ Using older Solidity - check for overflow/underflow${NC}"
fi

# ============================================================================
# GENERATE REPORT
# ============================================================================
echo -e "\n${YELLOW}━━━ Generating Report ━━━${NC}"

cat > "$REPORT_DIR/REPORT.md" << EOF
# Security Audit Report

**Generated by:** Ember's Solidity Security Audit Tool 🐉  
**Date:** $(date)  
**Target:** $TARGET

## Executive Summary

This automated audit checks for common vulnerabilities based on:
- OWASP Smart Contract Top 10 (2025)
- Slither static analysis
- Common dangerous patterns

**⚠️ Note:** This is an automated scan. A full security audit requires manual review.

## Findings Overview

| Severity | Count |
|----------|-------|
| High | $HIGH |
| Medium | $MEDIUM |
| Low | $LOW |
| Informational | $INFO |

## Automated Analysis

### Slither Results
See \`slither.txt\` for full output.

### Pattern Matches
See \`patterns.txt\` for dangerous pattern detections.

## Recommendations

1. Address all High and Medium severity findings before deployment
2. Consider professional audit for contracts handling significant value
3. Implement comprehensive test coverage (aim for >90%)
4. Use battle-tested libraries (OpenZeppelin) where possible

## References

- [OWASP Smart Contract Top 10](https://owasp.org/www-project-smart-contract-top-10/)
- [Slither Documentation](https://github.com/crytic/slither)
- [OpenZeppelin Security](https://docs.openzeppelin.com/contracts)

---
*Generated by Ember 🐉 - Open Source Security Audit Tool*
*https://github.com/emberdragonc/solidity-security-audit*
EOF

echo -e "${GREEN}✓ Report generated: $REPORT_DIR/REPORT.md${NC}"

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    Audit Complete! 🐉                        ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Results saved to: ${GREEN}$REPORT_DIR/${NC}"
echo ""
echo -e "${YELLOW}Remember: Automated tools catch ~30% of vulnerabilities.${NC}"
echo -e "${YELLOW}For high-value contracts, always get a professional audit!${NC}"
