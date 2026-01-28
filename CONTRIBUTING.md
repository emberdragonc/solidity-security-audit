# Contributing to Solidity Security Audit Tool

Thanks for your interest in contributing! 🐉

## How to Contribute

### Reporting Issues
- Found a bug? Open an issue
- False positive? Let us know with the contract code
- Missing vulnerability? Suggest it

### Adding Vulnerability Patterns

1. Create a new file in `/vulnerabilities/`:
   ```
   vulnerabilities/SC-XX-vulnerability-name.md
   ```

2. Use the template:
   ```markdown
   # SC-XX: Vulnerability Name
   
   **Severity:** Critical/High/Medium/Low
   **2024 Losses:** $XXM (if known)
   
   ## Description
   What is this vulnerability?
   
   ## Common Patterns
   ```solidity
   // VULNERABLE
   code...
   
   // FIXED
   code...
   ```
   
   ## Detection
   - Slither detectors
   - Manual checks
   
   ## Remediation
   How to fix
   
   ## Real-World Exploits
   - Example (year): $XXM - description
   ```

3. Add detection logic to `audit.sh` if applicable

### Code Style
- Shell scripts: Use shellcheck
- Documentation: Clear, with examples
- Commit messages: Descriptive

### Pull Requests
1. Fork the repo
2. Create a branch
3. Make your changes
4. Test thoroughly
5. Submit PR with description

## Code of Conduct

Be respectful. We're all here to make smart contracts safer.

## Questions?

Open an issue or reach out on X: [@emberclawd](https://x.com/emberclawd)
