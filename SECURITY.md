# Security Policy

This document covers repo-specific security boundaries. See the [BTCDecoded Security Policy](https://github.com/BTCDecoded/.github/blob/main/SECURITY.md) for organization-wide policy.

## Supported Versions

Security updates are provided for supported protocol versions. See [GitHub Releases](https://github.com/BTCDecoded/blvm-protocol/releases) and `Cargo.toml` for version history.

## Reporting a Vulnerability

**This software provides protocol abstraction for Bitcoin implementations. Security vulnerabilities could affect Bitcoin node compatibility and network consensus.**

### Critical Security Issues

If you discover a security vulnerability in blvm-protocol, please report it immediately:

1. **DO NOT** create a public GitHub issue
2. **DO NOT** discuss the vulnerability publicly
3. **DO NOT** post on social media or forums

### How to Report

**Email:** security@thebitcoincommons.org  
**Subject:** [SECURITY] blvm-protocol vulnerability

Include the following information:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)
- Your contact information

### Response Timeline

- **Acknowledgment:** Within 24 hours
- **Initial Assessment:** Within 72 hours
- **Fix Development:** 1-2 weeks (depending on severity)
- **Public Disclosure:** Coordinated with fix release

### Vulnerability Types

#### Critical (P0)
- Protocol variant confusion attacks
- Network parameter manipulation
- Validation rule bypasses
- Genesis block spoofing
- Magic number conflicts

#### High (P1)
- Denial of service through protocol parameters
- Resource exhaustion via network constants
- Input validation bypasses
- Logic errors in protocol selection

#### Medium (P2)
- Information disclosure through protocol metadata
- Performance issues with protocol switching
- Documentation errors in protocol specifications

### Responsible Disclosure

We follow responsible disclosure practices:

1. **Private reporting** - Report privately first
2. **Coordinated disclosure** - We'll work with you on timing
3. **Credit** - We'll credit you (unless you prefer anonymity)
4. **No legal action** - We won't pursue legal action for good-faith research

### Security Considerations

#### Protocol Abstraction
- All protocol variants must be clearly separated
- No cross-contamination between networks
- Network parameters must be immutable
- Protocol selection must be secure

#### Network Parameters
- Magic bytes must be unique per network
- Genesis blocks must be cryptographically verified
- Network constants must be tamper-proof
- Protocol versions must be clearly defined

#### Validation Rules
- Protocol-specific rules must be enforced
- No rule bypassing through protocol switching
- All validation must be deterministic
- Edge cases must be handled correctly

### Testing Requirements

Before reporting, please verify:
- [ ] The issue reproduces consistently
- [ ] The issue affects protocol abstraction
- [ ] The issue is not already known
- [ ] The issue is not a feature request

### Bug Bounty

We may offer bug bounties for critical vulnerabilities. Contact us for details.

### Security Updates

Security updates will be:
- Released as patch versions for security fixes
- Clearly marked as security fixes
- Backported to all supported versions
- Announced on our security mailing list

### Contact Information

- **Security Team:** security@thebitcoincommons.org
- **General Inquiries:** info@btcdecoded.org
- **Website:** https://btcdecoded.org

### Acknowledgments

We thank the security researchers who help keep Bitcoin protocol implementations secure through responsible disclosure.

---

**Remember:** This software provides critical protocol abstraction for Bitcoin implementations. Any bugs could affect Bitcoin node compatibility and network consensus. Please report responsibly.
