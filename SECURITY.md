# Security Policy

## Supported Versions

We release patches and security improvements on the latest codebase:

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

---

## Reporting a Vulnerability

Security is the core mission of **Smart Shell Guardrail**. If you discover a security vulnerability, a sandbox escape technique, or a guardrail bypass:

> **PLEASE DO NOT REPORT SECURITY VULNERABILITIES VIA PUBLIC GITHUB ISSUES.**

Instead, please send an encrypted or direct email to our Lead Security Maintainer:

- **Primary Contact**: Franca Roscilli
- **Email**: [francaroscillidev@gmail.com](mailto:francaroscillidev@gmail.com)
- **Subject**: `[SECURITY VULNERABILITY] smart-shell-guardrail: <brief description>`

### What to Include in Your Report
To help us triage and resolve the issue quickly, please provide:
1. **Description of the vulnerability** and the bypass mechanism (e.g. specific command string, subshell trick, or encoding).
2. **Steps to reproduce** or a Proof of Concept (PoC).
3. **Affected environment** (OS version: macOS or Linux, Python version, Shell: bash or zsh).
4. **Potential impact** (e.g., unauthorized filesystem write, secret leakage, arbitrary code execution outside sandbox).

### Our Commitment
- We will acknowledge receipt of your vulnerability report within **48 hours**.
- We will provide a status update and estimated timeline for a patch.
- We will credit you in the release notes and advisory once the patch is published (unless you prefer anonymity).
