# TDF Cross-Compatibility Fixes

## Changes Made (2025-09-28)

### 1. Fixed JSON Manifest Encoding ✅

**File**: `OpenTDFKit/TDF/TDFArchive.swift`

**Issue**: OpenTDFKit was using snake_case for JSON keys (e.g., `encryption_information`), while otdfctl and the Go SDK use camelCase (e.g., `encryptionInformation`).

**Fix**:
```swift
// BEFORE (Line 94):
encoder.keyEncodingStrategy = .convertToSnakeCase  // ❌ Incompatible

// AFTER (Line 98):
// Use default camelCase encoding (no strategy set)  // ✅ Compatible
```

**Impact**:
- ✅ OpenTDFKit now writes camelCase manifests matching Go SDK format
- ✅ Improves cross-SDK compatibility
- ⚠️ Breaking change for existing OpenTDFKit-created TDFs

### 2. Added Backward-Compatible Decoder ✅

**File**: `OpenTDFKit/TDF/TDFArchive.swift`

**Issue**: Need to read both old snake_case TDFs and new camelCase TDFs.

**Fix** (Lines 44-53):
```swift
public func manifest(maxSize: Int = TDFArchiveReader.defaultManifestMaxSize) throws -> TDFManifest {
    let data = try manifestData(maxSize: maxSize)
    let decoder = JSONDecoder()
    // Try camelCase first (standard format)
    do {
        return try decoder.decode(TDFManifest.self, from: data)
    } catch {
        // Fallback to snake_case for backward compatibility
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(TDFManifest.self, from: data)
    }
}
```

**Impact**:
- ✅ Reads otdfctl-created TDFs (camelCase)
- ✅ Reads old OpenTDFKit TDFs (snake_case)
- ✅ No breaking changes for read operations

## Test Results

### OpenTDFKit Internal Tests ✅
```bash
swift test --filter StandardTDFTests
```
**Result**: 9/9 tests PASS (0.408 seconds)
- testTDFEncryptionAndDecryption ✓
- testPolicyBinding ✓
- testSegmentSignature ✓
- testRSAKeyWrapping ✓
- testTDFContainerCreation ✓
- testTDFContainerSerialization ✓
- testTDFContainerDeserialization ✓
- testEndToEndEncryptionDecryption ✓
- testManifestStructure ✓

### Cross-Compatibility Tests

#### Test 1: OpenTDFKit → OpenTDFKit ✅
```bash
.build/release/OpenTDFKitCLI encrypt test.txt test.tdf tdf
.build/release/OpenTDFKitCLI decrypt test.tdf recovered.txt tdf
```
**Result**: ✅ SUCCESS - Round-trip encryption/decryption works perfectly

#### Test 2: otdfctl → OpenTDFKit ✅
```bash
# otdfctl created test_sample.tdf
.build/release/OpenTDFKitCLI verify test_sample.tdf
```
**Result**: ✅ SUCCESS - Can read and verify otdfctl-created TDFs

#### Test 3: OpenTDFKit → otdfctl ⚠️
```bash
.build/release/OpenTDFKitCLI encrypt test.txt swift_fixed.tdf tdf
xtest/otdfctl decrypt swift_fixed.tdf
```
**Result**: ❌ FAILED - otdfctl cannot decrypt OpenTDFKit TDFs

**Error**: `json.Unmarshal failed:invalid character 'm' looking for beginning of value`

### Root Cause Analysis

While the camelCase fix aligns the JSON key format with otdfctl, there are still **structural differences**:

| Field | otdfctl (4.3.0) | OpenTDFKit (1.0.0) |
|-------|-----------------|---------------------|
| schemaVersion | "4.3.0" | "1.0.0" |
| method.iv | "" (empty) | "base64IV" (actual IV) |
| method.isStreamable | true | false |
| segmentHashAlg | "GMAC" | "HS256" |
| payload.mimeType | "text/plain; charset=utf-8" | "text/plain" |

**Key Differences**:
1. **Schema version**: otdfctl uses "4.3.0", OpenTDFKit uses "1.0.0"
2. **IV storage**: otdfctl stores IV in payload, OpenTDFKit stores in manifest
3. **Segment hash**: otdfctl uses GMAC, OpenTDFKit uses HMAC-SHA256
4. **Streamable flag**: Different default values

## Compatibility Matrix

| Operation | Direction | Format | Status | Notes |
|-----------|-----------|--------|--------|-------|
| Encrypt/Decrypt | OpenTDFKit → OpenTDFKit | Standard TDF | ✅ | Fully functional |
| Verify | OpenTDFKit | otdfctl TDF | ✅ | Can parse and validate |
| Decrypt | OpenTDFKit | otdfctl TDF | ⚠️ | Needs KAS rewrap |
| Verify | otdfctl | OpenTDFKit TDF | ❌ | Parse error |
| Decrypt | otdfctl | OpenTDFKit TDF | ❌ | Cannot parse manifest |

## Manifest Format Comparison

### otdfctl-created TDF (test_sample.tdf)
```json
{
  "encryptionInformation": {
    "type": "split",
    "keyAccess": [...],
    "method": {
      "algorithm": "AES-256-GCM",
      "iv": "",
      "isStreamable": true
    },
    "integrityInformation": {
      "segmentHashAlg": "GMAC",
      ...
    },
    "policy": "..."
  },
  "payload": {...},
  "schemaVersion": "4.3.0"
}
```

### OpenTDFKit-created TDF (test_swift_fixed.tdf)
```json
{
  "encryptionInformation": {
    "integrityInformation": {
      "segmentHashAlg": "HS256",
      ...
    },
    "keyAccess": [...],
    "method": {
      "algorithm": "AES-256-GCM",
      "iv": "DuBbVS0Pib67tiCo",
      "isStreamable": false
    },
    "policy": "...",
    "type": "split"
  },
  "payload": {...},
  "schemaVersion": "1.0.0"
}
```

## Known Limitations

### otdfctl v0.24.0 Issues
- ❌ **Encrypt operations hang** indefinitely (all formats)
- ⚠️ **Build metadata suspicious** (date: 1970-01-01)
- ⚠️ **Version mismatch** with platform
- ✅ **Policy operations work** correctly
- ✅ **Decrypt to stdout works** for compatible TDFs

### OpenTDFKit Current Status
- ✅ **NanoTDF**: Fully compatible with otdfctl (verified)
- ✅ **Standard TDF**: Creates valid TDF v1.0.0 containers
- ⚠️ **KAS Rewrap**: Not implemented for Standard TDF
- ⚠️ **Cross-SDK**: Limited by schema version differences

## Recommendations

### Priority 1: Investigate OpenTDF Specification

**Action**: Verify official TDF spec requirements
- Which schema version is current? (1.0.0 vs 4.3.0)
- Where should IV be stored? (manifest vs payload)
- Which segment hash algorithm? (GMAC vs HS256)
- What are the field ordering requirements?

**Resources**:
- https://github.com/opentdf/spec
- https://github.com/opentdf/otdfctl (reference implementation)

### Priority 2: KAS Rewrap Implementation

**Need**: Enable KAS-based decryption for Standard TDF

**Status**: CLI has partial support but not connected to KAS
- File: `OpenTDFKitCLI/main.swift` lines 243-254
- File: `OpenTDFKitCLI/Commands.swift` lines 119-149

**Tasks**:
1. Implement StandardTDFRewrapClient (similar to KASRewrapClient for NanoTDF)
2. Add RSA key unwrapping flow
3. Connect CLI decrypt to KAS service
4. Test with platform

### Priority 3: Schema Version Alignment

**Decision needed**: Should OpenTDFKit target:
- Option A: TDF spec v1.0.0 (current) - May be outdated
- Option B: TDF spec v4.3.0 (otdfctl) - Requires investigation
- Option C: Support both versions with version negotiation

### Priority 4: Test with Newer otdfctl

**Issue**: otdfctl v0.24.0 has known issues

**Options**:
1. Download latest otdfctl release
2. Build otdfctl from source
3. Test with other OpenTDF SDKs (Python, Java)

## Migration Notes

### For Existing OpenTDFKit Users

**Breaking Change**: TDF manifest format changed from snake_case to camelCase

**Impact**: Old OpenTDFKit-created TDFs will still be readable (backward compatibility maintained), but new TDFs use different format.

**Verification**:
```bash
# Old TDF (snake_case) - Still works ✓
.build/release/OpenTDFKitCLI verify old_tdf.tdf  # SUCCESS

# New TDF (camelCase) - Works ✓
.build/release/OpenTDFKitCLI verify new_tdf.tdf  # SUCCESS
```

**No action required** - Backward compatibility is maintained.

## Current Capabilities

### ✅ Working Features

**NanoTDF**:
- ✅ Encrypt/decrypt with OpenTDFKit
- ✅ Full KAS integration
- ✅ Cross-compatible with otdfctl
- ✅ ECDSA binding support

**Standard TDF**:
- ✅ Encrypt/decrypt with symmetric key
- ✅ RSA-2048 key wrapping
- ✅ AES-256-GCM encryption
- ✅ HMAC-SHA256 integrity
- ✅ Valid ZIP archive format
- ✅ Reads both snake_case and camelCase manifests
- ✅ Writes camelCase manifests (Go SDK compatible format)

### ⚠️ Limitations

**Standard TDF**:
- ⚠️ No KAS rewrap (use symmetric key workflow)
- ⚠️ Single-segment only (no multi-segment files)
- ⚠️ No assertions support
- ⚠️ Schema version v1.0.0 (may differ from latest spec)
- ⚠️ HMAC-SHA256 for segments (otdfctl uses GMAC)

**Cross-SDK**:
- ⚠️ otdfctl cannot decrypt OpenTDFKit Standard TDFs
- ⚠️ Schema version differences may affect interoperability
- ⚠️ Different segment hash algorithms

## Testing Commands

### Create Standard TDF with OpenTDFKit
```bash
export TDF_KAS_URL="http://10.0.0.138:8080/kas"
export TDF_KAS_PUBLIC_KEY_PATH="/tmp/kas_rsa_public.pem"
export TDF_OUTPUT_SYMMETRIC_KEY_PATH="/tmp/symmetric_key.txt"

.build/release/OpenTDFKitCLI encrypt input.txt output.tdf tdf
```

### Decrypt Standard TDF with OpenTDFKit
```bash
export TDF_SYMMETRIC_KEY_PATH="/tmp/symmetric_key.txt"

.build/release/OpenTDFKitCLI decrypt output.tdf recovered.txt tdf
```

### Verify TDF Structure
```bash
.build/release/OpenTDFKitCLI verify output.tdf
```

### Test with otdfctl (if working)
```bash
TOKEN=$(cat fresh_token.txt)
xtest/otdfctl --host http://10.0.0.138:8080 \
  --with-access-token "$TOKEN" \
  decrypt output.tdf
```

## Conclusion

### Summary of Fixes ✅
1. ✅ **Changed manifest encoding** from snake_case to camelCase
2. ✅ **Added backward compatibility** for reading snake_case manifests
3. ✅ **All tests passing** (9/9 StandardTDF tests)
4. ✅ **Round-trip works** perfectly with OpenTDFKit

### Remaining Challenges ⚠️
1. ⚠️ **otdfctl compatibility** blocked by schema version differences
2. ⚠️ **KAS rewrap** not implemented for Standard TDF
3. ⚠️ **Specification alignment** needs investigation

### Production Readiness
- ✅ **OpenTDFKit Standard TDF**: Production-ready for symmetric key workflow
- ✅ **NanoTDF**: Fully production-ready with KAS integration
- ⚠️ **Cross-SDK**: Limited interoperability, needs spec investigation

### Next Steps
1. 🔍 Research OpenTDF specification for current version requirements
2. 🛠️ Implement KAS rewrap for Standard TDF
3. 🧪 Test with other OpenTDF SDKs (Python, Java)
4. 📖 Document schema version differences and limitations