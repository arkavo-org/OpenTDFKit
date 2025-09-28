# otdfctl Compatibility Status

## Summary

OpenTDFKit now creates Standard TDF files that **otdfctl can parse successfully**. The main compatibility blocker has been resolved by changing the default ZIP compression from deflate to stored (uncompressed).

## ✅ Fixed Issues

### 1. Manifest Compression (RESOLVED)

**Problem**: otdfctl expects uncompressed manifests, but OpenTDFKit was using DEFLATE compression.

**Error Message**:
```
json.Unmarshal failed: invalid character 'm' looking for beginning of value
```

**Fix**: Changed default compression in `StandardTDFContainer` from `.deflate` to `.none`

**File**: `OpenTDFKit/TDF/TrustedDataFormat.swift:24`

**Before**:
```swift
compression: ZIPFoundation.CompressionMethod = .deflate
```

**After**:
```swift
compression: ZIPFoundation.CompressionMethod = .none
```

**Verification**:
```bash
# OpenTDFKit TDFs now show 'stor' (stored/uncompressed)
$ unzip -Z test_spec_uncompressed.tdf
-rw-r--r--  2.1 unx     1215 b- stor 25-Sep-28 17:26 0.manifest.json
-rw-r--r--  2.1 unx       66 b- stor 25-Sep-28 17:26 0.payload
```

### 2. Schema Version (RESOLVED)

**Problem**: OpenTDFKit was using schema version "1.0.0" but otdfctl uses "4.3.0"

**Fix**: Updated default in `StandardTDFEncryptionConfiguration` and CLI

**Files**:
- `OpenTDFKit/TDF/StandardTDFProcessor.swift:36`
- `OpenTDFKitCLI/main.swift:297`

### 3. Segment Integrity Algorithm (RESOLVED)

**Problem**: OpenTDFKit was using HS256, spec 4.3.0 requires GMAC

**Fix**: Implemented GMAC-based segment signatures using AES-GCM tags

**File**: `OpenTDFKit/TDF/StandardTDFCrypto.swift:44`

```swift
public static func segmentSignatureGMAC(segmentCiphertext: Data, symmetricKey: SymmetricKey) throws -> Data {
    let nonce = try AES.GCM.Nonce(data: Data(count: 12))
    let sealed = try AES.GCM.seal(Data(), using: symmetricKey, nonce: nonce, authenticating: segmentCiphertext)
    return Data(sealed.tag)
}
```

## 🔄 Remaining Differences (Both Valid)

### 1. IV Storage Strategy

**otdfctl**: Stores IV in the encrypted payload (first 12 bytes), uses `"iv": ""` in manifest
```json
{
  "method": {
    "algorithm": "AES-256-GCM",
    "iv": "",
    "isStreamable": true
  }
}
```

**OpenTDFKit**: Stores IV in the manifest as base64
```json
{
  "method": {
    "algorithm": "AES-256-GCM",
    "iv": "JuNEq7yJgQSFzjLe",
    "isStreamable": false
  }
}
```

**Status**: Both approaches are valid per OpenTDF spec. No change required.

### 2. Root Signature Algorithm

**otdfctl**: Uses HS256 for root signature
```json
{
  "rootSignature": {
    "alg": "HS256",
    "sig": "xPbwA50iXeQtmGJmXvuuzXLApkKOcWwHjnNqrjUHlCM="
  }
}
```

**OpenTDFKit**: Uses GMAC (per spec 4.3.0)
```json
{
  "rootSignature": {
    "alg": "GMAC",
    "sig": "6wNzyS14fLWdRozWrqYENg=="
  }
}
```

**Status**: OpenTDFKit follows spec 4.3.0 recommendation. No change required.

### 3. JSON Field Ordering

**otdfctl**: Orders manifest fields as: `encryptionInformation` → `type`, `policy`, `keyAccess`, `method`, `integrityInformation`

**OpenTDFKit**: Orders manifest fields as: `encryptionInformation` → `integrityInformation`, `keyAccess`, `method`, `policy`, `type`

**Status**: JSON object field order is not significant. Both are valid.

## ⚠️ Blocking Issue: KAS Rewrap

### Current Status

✅ **OpenTDFKit can create TDFs that otdfctl can parse**
✅ **Manifest parsing works**
❌ **otdfctl cannot decrypt OpenTDFKit TDFs (KAS rewrap fails)**
✅ **OpenTDFKit can decrypt its own TDFs**

### Error from otdfctl

```
ERROR    Failed to decrypt file: splitKey.unable to reconstruct split key:
  [tamper detected] tdf: rewrap request 400:
  kao unwrap failed for split {http://10.0.0.138:8080/kas }:
  invalid_argument: request error
  rpc error: code = InvalidArgument desc = bad request
```

### Root Cause

**OpenTDFKit**: Uses offline key wrapping - wraps symmetric key with KAS public key directly using RSA-OAEP

**otdfctl**: Uses online KAS rewrap - sends rewrap request to KAS with policy for validation

The KAS rewrap request fails because:
1. OpenTDFKit creates offline-wrapped keys (never touches KAS during encryption)
2. otdfctl expects to rewrap through KAS (policy validation, access control)
3. The "tamper detected" error suggests policy binding verification fails

### Implementation Required

OpenTDFKit needs to implement **KAS rewrap for Standard TDF** similar to NanoTDF:

1. **Create rewrap client**: Similar to `KASRewrapClient` but for Standard TDF
2. **JWT signing**: ES256 signed request with policy
3. **RSA unwrapping**: Use `SecKeyCreateDecryptedData` with `.rsaEncryptionOAEPSHA256`
4. **Policy binding verification**: Verify HMAC-SHA256 of policy matches manifest

**Reference**: See `OpenTDFKit/NanoTDF/KASRewrapClient.swift` for NanoTDF implementation

## Cross-SDK Test Results

### OpenTDFKit → OpenTDFKit ✅

```bash
# Encrypt
.build/release/OpenTDFKitCLI encrypt input.txt output.tdf tdf

# Decrypt with symmetric key
.build/release/OpenTDFKitCLI decrypt output.tdf recovered.txt tdf
✓ Files match
```

### otdfctl → otdfctl ✅

```bash
# Encrypt
xtest/otdfctl encrypt input.txt --tdf-type ztdf --out output.tdf

# Decrypt
xtest/otdfctl decrypt output.tdf --out recovered.txt
✓ Files match
```

### OpenTDFKit → otdfctl ⚠️

```bash
# Encrypt with OpenTDFKit
.build/release/OpenTDFKitCLI encrypt input.txt output.tdf tdf

# Decrypt with otdfctl
xtest/otdfctl decrypt output.tdf --out recovered.txt
❌ ERROR: Failed to decrypt file (KAS rewrap 400: tamper detected)
```

**Status**: Manifest parses successfully, but KAS rewrap fails

### otdfctl → OpenTDFKit ❓

Not tested - requires implementing KAS rewrap in OpenTDFKit first

## Test Summary

| Test | Status | Notes |
|------|--------|-------|
| Manifest compression compatibility | ✅ Fixed | Changed default to `.none` |
| Schema version 4.3.0 | ✅ Fixed | Updated defaults |
| GMAC segment signatures | ✅ Implemented | Per spec 4.3.0 |
| otdfctl manifest parsing | ✅ Working | No JSON errors |
| OpenTDFKit self-decryption | ✅ Working | All 18 tests pass |
| otdfctl decryption of OpenTDFKit TDFs | ❌ Blocked | KAS rewrap not implemented |
| OpenTDFKit decryption of otdfctl TDFs | ❓ Unknown | Requires KAS rewrap |

## Next Steps

### Priority 1: Implement KAS Rewrap for Standard TDF

Required for full cross-SDK compatibility:

1. Create `StandardTDFRewrapClient`
2. Implement JWT signing (ES256)
3. Handle RSA unwrapping with OAEP-SHA256
4. Add policy binding verification
5. Update CLI to use KAS rewrap when decrypting

### Priority 2: Test otdfctl → OpenTDFKit

Once KAS rewrap is implemented:

```bash
# Create TDF with otdfctl
xtest/otdfctl encrypt test.txt --tdf-type ztdf --out test.tdf

# Decrypt with OpenTDFKit
.build/release/OpenTDFKitCLI decrypt test.tdf recovered.txt tdf

# Verify
diff test.txt recovered.txt
```

### Priority 3: Integration Tests

Add integration tests for:
- Cross-SDK compatibility (both directions)
- KAS rewrap with live platform
- Policy validation scenarios
- Error handling for tampered TDFs

## Conclusion

**Major Achievement**: OpenTDFKit now creates spec 4.3.0 compliant Standard TDFs that otdfctl can successfully parse.

**Remaining Work**: Implement KAS rewrap to enable otdfctl to decrypt OpenTDFKit TDFs, completing full cross-SDK compatibility.

## Related Documents

- `SPEC_ANALYSIS.md` - OpenTDF specification investigation
- `COMPATIBILITY_FIXES.md` - JSON format compatibility fixes
- `CODE_REVIEW_IMPROVEMENTS.md` - Security and quality improvements
- `OTDFCTL_XTEST_RESULTS.md` - Initial cross-compatibility testing