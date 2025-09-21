# NanoTDF Interoperability Findings

## Executive Summary

During integration testing between OpenTDFKit and otdfctl (OpenTDF platform CLI), we discovered format incompatibilities that prevent OpenTDFKit from parsing NanoTDFs created by otdfctl. The primary issue is that otdfctl wraps the ephemeral public key with additional metadata, resulting in a 101-byte field instead of the standard compressed EC public key sizes (33, 49, or 67 bytes) as specified in the NanoTDF specification.

## Test Environment

- **OpenTDFKit**: Current main branch
- **otdfctl**: Binary from OpenTDF platform
- **Test Platform**: OpenTDF services at 10.0.0.138:8080 (platform) and :8888 (OIDC)
- **Test File**: `test_output.ntdf.tdf` (237 bytes) created via otdfctl

## Key Findings

### 1. Ephemeral Key Format Incompatibility

**Issue**: otdfctl generates a 101-byte ephemeral key field, while the NanoTDF specification (Section 3.3.1.6) states that the ephemeral key should be 33-67 bytes (standard compressed EC public key sizes).

**Specification Reference** (SPEC_NANOTDF.md):
- Section 3.3.1: Header structure specifies "Ephemeral Key: 33-67 bytes"
- Section 3.3.1.6: "Key - This section contains an ephemeral public key"

**Analysis**:
- Standard compressed EC public key sizes per spec:
  - secp256r1 (P-256): 33 bytes
  - secp384r1 (P-384): 49 bytes
  - secp521r1 (P-521): 67 bytes
- otdfctl output: 101 bytes total (non-compliant)
  - First 68 bytes: Metadata/wrapper (possibly containing KAS key identifier "e1")
  - Last 33 bytes: Actual P-256 public key material

**Evidence**:
```
Hex dump of ephemeral key field (101 bytes at offset 0x19):
31 00 01 02 00 68 2a 30 35 f5 d7 3c 94 39 c1 7b ...
[68 bytes of metadata]
26 c8 6f 99 5a 7a 72 a7 a6 f0 e4 6f 7d 5d a8 ad ... [33 bytes matching P-256 size]
```

### 2. Curve Support Differences

**otdfctl**: Only supports secp256r1 (P-256) according to NanoTDF SDK documentation
- Source: `/Users/paul/Projects/opentdf/platform/docs/NanoTDF_SDK.md`
- Quote: "Only the `secp256r1` curve is currently supported"

**OpenTDFKit**: Supports multiple curves
- secp256r1 (P-256)
- secp384r1 (P-384)
- secp521r1 (P-521)

### 3. Curve Value Mapping Consistency

The NanoTDF specification defines curve values consistently across sections:
- Section 3.3.1.3.2 (Ephemeral ECC Params Enum)
- Section 3.3.1.4.2 (Signature ECC Mode)

**Specification Values**:
- `0x00` = secp256r1
- `0x01` = secp384r1
- `0x02` = secp521r1
- `0x03` = secp256k1

**OpenTDFKit**: Correctly implements the specification mapping.

**otdfctl**: The policy binding byte contains `0x02` but only supports secp256r1, suggesting either:
1. Incorrect curve value encoding
2. The wrapped ephemeral key format uses different semantics

### 4. Parser Failure

**Result**: OpenTDFKit's `BinaryParser` fails with `invalidFormat` error when parsing otdfctl-generated NanoTDFs.

**Root Cause**: The parser expects the ephemeral key length to match standard EC key sizes and fails validation when encountering the 101-byte wrapped format.

## Technical Details

### otdfctl NanoTDF Structure (237 bytes)

```
Offset  Size  Field                   Value
------  ----  ----                    -----
0x0000  3     Magic + Version         "L1L" (0x4C314C)
0x0003  1     KAS Protocol            0x10
0x0004  1     KAS Body Length         19
0x0005  19    KAS URL                 "10.0.0.138:8080/kas"
0x0018  1     Ephemeral Key Length    101 (0x65)
0x0019  101   Ephemeral Key           [wrapped structure]
0x007E  1     Policy Binding          0x12 (GMAC, curve 0x02)
0x007F  1     Payload Config          0xEE (signed, curve 0x06, cipher 0x0E)
0x0080  109   Policy + Payload        [remaining data]
```

### otdfctl inspect output

```json
{
  "cipher": "AES-96",
  "ecdsaEnabled": false,
  "kas": "http://10.0.0.138:8080/kas",
  "kid": "e1"
}
```

The `kid: "e1"` likely corresponds to the metadata wrapped around the ephemeral key.

## Impact

1. **Interoperability**: OpenTDFKit cannot decrypt NanoTDFs created by otdfctl
2. **Integration**: Cannot use OpenTDFKit as a Swift SDK for OpenTDF platform without modifications
3. **Standards Compliance**: Unclear which format follows the official NanoTDF specification

## Recommendations

### Short-term Solutions

1. **Add Compatibility Mode**: Modify OpenTDFKit's parser to handle otdfctl's wrapped ephemeral key format
2. **Document Format Variants**: Clearly document the differences between implementations

### Long-term Solutions

1. **Standardize Format**: Work with OpenTDF community to standardize the ephemeral key encoding
2. **Update Specification**: Ensure the NanoTDF specification clearly defines:
   - Whether ephemeral keys can be wrapped with metadata
   - Standard curve enumeration values
   - Required vs optional fields

### Implementation Considerations

For OpenTDFKit to support otdfctl-generated NanoTDFs:

1. **Parser Updates Required**:
   - Accept 101-byte ephemeral key fields
   - Extract actual key from wrapped structure (last 33 bytes for P-256)
   - Handle different curve value mappings

2. **Potential Code Changes**:
   ```swift
   // In BinaryParser.swift
   if ephemeralKeyLength == 101 {
       // otdfctl wrapped format
       // Extract last 33 bytes as actual P-256 key
       ephemeralKey = data.suffix(33)
   }
   ```

## Testing Artifacts

- **Test NanoTDF**: `test_output.ntdf.tdf` (created by otdfctl)
- **OpenTDFKitCLI**: Minimal CLI tool using OpenTDFKit's parser
- **Integration Scripts**: Various Python and Swift scripts for analysis

## Specification Compliance

Based on the NanoTDF specification (SPEC_NANOTDF.md):

1. **OpenTDFKit**: Appears to correctly implement the NanoTDF v1 specification
   - Expects ephemeral keys of 33-67 bytes as specified
   - Correctly maps curve enum values
   - Follows the binary structure defined in the spec

2. **otdfctl**: Deviates from the specification in the ephemeral key field
   - Uses 101-byte wrapped format (not defined in spec)
   - May be implementing an extended or proprietary version
   - The wrapping might be for backward compatibility or additional features

## Conclusion

The incompatibility stems from otdfctl's deviation from the NanoTDF v1 specification, specifically in the ephemeral key encoding. While OpenTDFKit correctly implements the published specification, it cannot parse otdfctl-generated files without modifications to handle the non-standard 101-byte ephemeral key format.

This represents a significant barrier to using OpenTDFKit as a Swift implementation for the OpenTDF ecosystem. The resolution requires either:
1. otdfctl conforming to the NanoTDF specification
2. OpenTDFKit adding compatibility mode for otdfctl's format
3. Updating the NanoTDF specification to document otdfctl's extensions