# Security Policy

## Supported Cryptographic Algorithms

OpenTDFKit implements the OpenTDF specification with the following cryptographic algorithms:

### Standard TDF (ZIP-based)
- **Symmetric Encryption**: AES-256-GCM with 128-bit authentication tags
- **Key Wrapping**: RSA-OAEP-SHA256 (minimum 2048-bit keys)
- **Policy Binding**: HMAC-SHA256
- **Integrity**: GMAC for segment hashing, HMAC-SHA256 for root signature
- **Random Generation**: Apple CryptoKit's SystemRandomNumberGenerator

### NanoTDF (Compact Binary)
- **Symmetric Encryption**: AES-256-GCM (64, 96, 104, 112, 120, 128-bit tags)
- **Key Agreement**: ECDH with P-256, P-384, P-521 curves
- **Key Derivation**: HKDF-SHA256
- **Policy Binding**: GMAC (64-bit truncated tag)
- **Digital Signatures**: ECDSA with P-256, P-384, P-521

## Security Requirements

### Key Size Requirements

#### RSA Keys
- **Minimum**: 2048 bits
- **Recommended**: 3072 bits or higher
- **Validation**: All RSA keys are validated at load time
- **Rejection**: Keys smaller than 2048 bits are rejected with an error

#### Elliptic Curve Keys (NanoTDF)
- **Supported Curves**: P-256 (secp256r1), P-384 (secp384r1), P-521 (secp521r1)
- **NIST Approved**: All curves are NIST-approved for government use
- **Default**: P-256 for optimal performance and security balance

### Memory Security

OpenTDFKit implements secure memory handling practices:

1. **In-Memory Processing**: All sensitive data (keys, plaintext) kept in memory only
2. **No Temporary Files**: Eliminates disk-based data leakage risks
3. **Secure Memory Clearing**: Cryptographic material is securely zeroed using `memset_s`
4. **Automatic Cleanup**: `defer` blocks ensure memory is cleared even on error paths

### Authentication & Authorization

#### KAS Rewrap Protocol
- **JWT Signing**: ES256 (ECDSA with P-256 and SHA-256)
- **Token Lifetime**: 60 seconds maximum
- **OAuth Bearer**: All KAS requests require valid OAuth access tokens
- **Request Validation**: JWT includes request body hash for integrity

#### Policy Enforcement
- **Cryptographic Binding**: HMAC-SHA256 binds policy to encrypted keys
- **Tamper Detection**: Any policy modification invalidates the binding
- **KAS Validation**: Policy checked by KAS before key release

## Security Best Practices

### For Application Developers

1. **Environment Variables**
   - Never hardcode credentials or keys in source code
   - Use environment variables or secure configuration management
   - Rotate OAuth tokens regularly

2. **Key Management**
   - Generate RSA keys with at least 2048 bits
   - Store private keys securely (Keychain, HSM, or secure storage)
   - Never commit private keys to version control
   - Use separate key pairs for different environments (dev/staging/prod)

3. **Error Handling**
   - Production builds use sanitized error messages
   - Debug builds provide detailed crypto error information
   - Never log sensitive data (keys, plaintext)

4. **File Size Considerations**
   - Standard TDF loads entire payload into memory
   - Recommended maximum: 100MB on iOS, 1GB on macOS
   - For larger files, implement external chunking before encryption

### For Security Auditors

1. **Code Review Focus Areas**
   - Cryptographic operations in `StandardTDFCrypto.swift` and `CryptoHelper.swift`
   - Memory handling in `StandardTDFProcessor.swift` and `NanoTDF.swift`
   - Input validation in `TDFArchive.swift` and `Commands.swift`
   - Network operations in `KASRewrapClient.swift`

2. **Test Coverage**
   - 18 Standard TDF unit tests covering edge cases
   - Integration tests for KAS rewrap flows
   - Weak key rejection tests
   - Malformed data handling tests

3. **Third-Party Dependencies**
   - Apple CryptoKit (system framework)
   - ZIPFoundation (0.9.20+) for archive handling
   - CryptoSwift (1.9.0) for specialized GCM tag sizes

## Known Limitations

### Current Implementation

1. **Single-Segment TDFs Only**
   - Multi-segment TDFs not yet supported
   - Large files must fit in memory

2. **Memory-Bound Operations**
   - Entire payload loaded into memory during encryption/decryption
   - No streaming encryption/decryption API yet

3. **RSA-Only Key Wrapping for Standard TDF**
   - EC key wrapping not implemented for Standard TDF
   - NanoTDF supports EC key wrapping

### Roadmap Items

- Streaming encryption/decryption for large files
- Multi-segment TDF support
- Hardware security module (HSM) integration
- Certificate pinning for KAS communication

## Vulnerability Reporting

If you discover a security vulnerability in OpenTDFKit, please report it responsibly:

### Reporting Process

1. **Do NOT** disclose the vulnerability publicly
2. Email security details to: [security contact - to be added]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if available)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Vulnerability Assessment**: Within 7 days
- **Fix Development**: Based on severity (critical: 1-2 weeks)
- **Disclosure**: Coordinated disclosure after fix is available

### Severity Levels

- **Critical**: Remote code execution, key extraction, authentication bypass
- **High**: Data leakage, DoS, privilege escalation
- **Medium**: Information disclosure, limited DoS
- **Low**: Minor issues with minimal impact

## Security Audit History

| Date | Auditor | Scope | Findings | Status |
|------|---------|-------|----------|--------|
| 2025-09-28 | Internal Review | Standard TDF Implementation | 4 recommendations | Addressed |

## Compliance

### NIST Standards
- FIPS 186-5: Digital Signature Standard (ECDSA)
- FIPS 197: AES encryption
- SP 800-38D: GCM mode
- SP 800-56A: Key agreement (ECDH)
- SP 800-108: Key derivation (HKDF)

### OpenTDF Specification
- Compliant with OpenTDF Specification v4.3.0
- Implements both NanoTDF and Standard TDF formats
- Compatible with reference implementation (otdfctl)

## Security Testing

### Automated Testing
```bash
# Run all security-focused tests
swift test --filter StandardTDFTests
swift test --filter KASRewrapClientTests
swift test --filter IntegrationTests

# Run with address sanitizer (memory safety)
swift test --sanitize=address

# Run with thread sanitizer (concurrency safety)
swift test --sanitize=thread
```

### Manual Security Testing
1. Weak key rejection: `testWeakRSAKeyRejection`
2. Malformed data handling: `testMalformedZIPArchive`, `testTruncatedPayload`
3. Wrong key decryption: `testWrongKeyDecryption`
4. Multi-KAS reconstruction: `testMultiKASKeyReconstruction`

## Contact

For security-related questions or concerns:
- GitHub Issues: https://github.com/arkavo-org/OpenTDFKit/issues
- Security Contact: [To be added]

---

**Last Updated**: 2025-09-28
**Version**: 1.0.0