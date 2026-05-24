# Security Scanner AI

AI-driven cybersecurity scanner detecting OWASP Top 10 vulnerabilities in source code.

## Features
- OWASP Top 10 (2021) coverage - all 10 categories
- Multi-language: Python, JS, TS, Java, Go, Ruby, PHP, Rust
- Pattern-based regex detection rules
- Security scoring: 0-100 with A-F grading
- Category-grouped findings with severity icons

## Usage
```bash
python3 scanner.py /path/to/project
```

## OWASP Categories
A01: Broken Access Control | A02: Cryptographic Failures
A03: Injection | A04: Insecure Design | A05: Misconfiguration
A06: Vulnerable Components | A07: Auth Failures
A08: Data Integrity | A09: Logging | A10: SSRF

## Built With
- Claude Code + KiloCode
- MiMo + Claude series models
