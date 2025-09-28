# OpenTDF Specification Analysis

## Investigation Results

### Current OpenTDF Specification

**Version**: 4.3.0 (as of 2025)
**Source**: https://github.com/opentdf/spec
**Format**: JSON-based manifest

### Key Findings

#### 1. Schema Version Discovery

**otdfctl (v0.24.0) creates TDFs with**:
```json
{
  "schemaVersion": "4.3.0",
  "encryptionInformation": {...},
  "payload": {...}
}
```

**OpenTDFKit creates TDFs with**:
```json
{
  "schemaVersion": "1.0.0",
  "encryptionInformation": {...},
  "payload": {...}
}
```

**Verdict**: ✅ **Field names are correct (camelCase)**, but schema version is outdated

#### 2. Critical Differences Between Implementations

| Feature | otdfctl (4.3.0) | OpenTDFKit (1.0.0) | Spec Requirement |
|---------|-----------------|---------------------|------------------|
| **Schema Version** | "4.3.0" | "1.0.0" | **4.3.0** |
| **JSON Format** | camelCase | camelCase ✓ | camelCase ✓ |
| **method.iv** | "" (empty) | base64 string | base64 (optional) |
| **method.isStreamable** | true | false | Required |
| **segmentHashAlg** | "GMAC" | "HS256" | GMAC or HS256 |
| **keyAccess.schemaVersion** | "1.0" | null | Optional |

#### 3. IV Storage Clarification

**From otdfctl manifest**: `"iv": ""`

This appears to be because:
1. IV is embedded in the payload (standard practice for streaming)
2. Empty string in manifest indicates "look in payload"
3. Our implementation stores IV in manifest (also valid but different approach)

**Analysis**: Both approaches are valid, but otdfctl's is more common for streaming TDFs.

#### 4. Segment Hash Algorithm

**otdfctl uses**: `"segmentHashAlg": "GMAC"`
**OpenTDFKit uses**: `"segmentHashAlg": "HS256"`

**GMAC** (Galois Message Authentication Code):
- Part of GCM mode (AES-GCM includes GMAC)
- More performant (single-pass with encryption)
- Standard for TDF integrity

**HS256** (HMAC-SHA256):
- Separate operation from encryption
- More widely supported
- Still cryptographically sound

**Recommendation**: Support both, prefer GMAC to match otdfctl

### Root Cause of Incompatibility

The incompatibility is **NOT** due to JSON format (we fixed that). It's due to:

1. **Schema version mismatch**: 4.3.0 vs 1.0.0
2. **IV storage strategy**: Empty string vs base64
3. **Segment hash algorithm**: GMAC vs HS256
4. **Streamable flag**: true vs false

### Implementation Path Forward

#### Option A: Strict 4.3.0 Compliance (Recommended)
**Pros**:
- Full otdfctl compatibility
- Matches current spec
- Future-proof

**Cons**:
- Breaking change (v2.0.0)
- Need to implement GMAC
- IV handling changes

**Changes Needed**:
1. Update schema version to "4.3.0"
2. Implement GMAC for integrity
3. Move IV to payload (or keep in manifest but support reading empty)
4. Set isStreamable based on implementation
5. Add keyAccess.schemaVersion = "1.0"

#### Option B: Hybrid Approach
**Pros**:
- Maintain backward compat
- Gradual migration

**Cons**:
- More complex
- Still not otdfctl compatible

**Not Recommended**

#### Option C: Document as Separate Profile
**Pros**:
- No code changes
- Clear documentation

**Cons**:
- Perpetuates incompatibility
- Confusing for users

**Not Recommended**

## Recommended Implementation Plan

### Phase 1: Update to Spec 4.3.0 (Immediate)

1. **Update schema version constant**
   ```swift
   // In StandardTDFProcessor.swift
   let specVersion = env["TDF_SPEC_VERSION"] ?? "4.3.0"  // Change from "1.0.0"
   ```

2. **Add GMAC support** (alongside HS256)
   ```swift
   // In StandardTDFCrypto.swift
   public static func segmentSignatureGMAC(segmentCiphertext: Data, symmetricKey: SymmetricKey) -> Data {
       // Use AES-GCM with empty plaintext for GMAC
       let nonce = try! AES.GCM.Nonce(data: Data(count: 12))
       let sealed = try! AES.GCM.seal(Data(), using: symmetricKey, nonce: nonce, authenticating: segmentCiphertext)
       return Data(sealed.tag)
   }
   ```

3. **Support both IV strategies**
   ```swift
   // In StandardTDFProcessor.swift
   // If method.iv is empty, IV is in payload
   // If method.iv has value, IV is in manifest (our current approach)
   ```

4. **Add keyAccess.schemaVersion**
   ```swift
   let kasObject = TDFKeyAccessObject(
       // ... existing fields ...
       schemaVersion: "1.0",  // Add this
       // ...
   )
   ```

### Phase 2: KAS Rewrap Implementation

Similar to NanoTDF KASRewrapClient but for Standard TDF:

```swift
public protocol StandardTDFRewrapProtocol {
    func rewrapStandardTDF(
        manifest: TDFManifest,
        clientPrivateKey: SecKey,
        oauthToken: String
    ) async throws -> SymmetricKey
}
```

**Key Differences from NanoTDF Rewrap**:
1. Uses RSA instead of ECDH
2. Sends full manifest instead of just header
3. Different JWT payload structure
4. No HKDF needed (direct RSA unwrap)

### Phase 3: Testing & Validation

1. Create TDF with OpenTDFKit
2. Verify with otdfctl
3. Decrypt with otdfctl
4. Create TDF with otdfctl
5. Verify with OpenTDFKit
6. Decrypt with OpenTDFKit (KAS rewrap)

## Specification Reference

### Official Spec Location
- **Current**: https://github.com/opentdf/spec (v4.3.0)
- **Legacy**: https://github.com/virtru/tdf-spec (archived)

### Key Spec Documents
- Schema: `/schema/` directory
- Protocol: `/protocol/` directory
- Examples: `/examples/` directory

### Semantic Versioning
The spec follows SemVer 2.0.0:
- Major version: Breaking changes
- Minor version: New features
- Patch version: Bug fixes

Current is 4.3.0 = Major version 4, minor 3, patch 0

## Decision: Update to 4.3.0

**Recommendation**: ✅ **Update OpenTDFKit to create spec 4.3.0 compliant TDFs**

**Rationale**:
1. Matches current official spec
2. Enables otdfctl compatibility
3. Future-proof implementation
4. Only breaking change is version number

**Impact**:
- Change default schema version from 1.0.0 to 4.3.0
- Add GMAC support (keep HS256 for compatibility)
- Support reading both IV strategies
- Add keyAccess.schemaVersion field

**Version Bump**: 1.x → 2.0.0 (breaking change)