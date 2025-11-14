# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly:

### **Do NOT** create a public GitHub issue for security vulnerabilities

Instead, please:

1. **Email:** Send details to [security@indicio.tech](mailto:security@indicio.tech)
2. **Subject Line:** Include "SECURITY: isomdl-uniffi vulnerability report"
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- **Initial Response:** Within 48 hours
- **Investigation:** 7-14 days for assessment
- **Fix Timeline:** Critical issues addressed within 7 days, others within 30 days
- **Disclosure:** Coordinated disclosure after fix is available

### Security Considerations

This library handles sensitive cryptographic operations and personal identity data. Key security areas include:

#### **Cryptographic Operations**
- Key generation and management
- Digital signatures (ECDSA)
- Certificate validation
- Random number generation

#### **Data Handling**
- Mobile Driver's License (mDL) documents
- Personal Identifiable Information (PII)
- Biometric data references
- Session management

#### **Memory Safety**
- Rust's memory safety guarantees
- Foreign Function Interface (FFI) boundaries
- Python memory management
- Kotlin/JVM memory management and garbage collection

### Security Best Practices for Users

1. **Key Management:**
   - Use hardware security modules (HSMs) when available
   - Rotate keys regularly
   - Secure key storage

2. **Data Protection:**
   - Encrypt sensitive data at rest
   - Use secure channels for transmission
   - Implement proper access controls

3. **Validation:**
   - Always validate certificates
   - Verify digital signatures
   - Check data integrity

4. **Updates:**
   - Keep dependencies updated
   - Monitor security advisories
   - Apply patches promptly

### Known Security Considerations

1. **Pre-1.0 Status:** This library is pre-1.0 and has not undergone formal security audit
2. **Cryptographic Dependencies:** Security depends on underlying Rust crates
3. **FFI Boundaries:** Extra care needed at Rust-Python boundaries

### Responsible Disclosure

We follow responsible disclosure practices:

1. **Acknowledgment:** Security researchers will be credited (unless they prefer anonymity)
2. **Timeline:** We coordinate with reporters on disclosure timeline
3. **Advisory:** Security advisories published through GitHub Security Advisory

## Contact

For security-related questions or concerns:
- **Email:** [security@indicio.tech](mailto:security@indicio.tech)
- **General Issues:** Create a public GitHub issue (non-security related only)

Thank you for helping keep the ISO MDL UniFFI project secure!
