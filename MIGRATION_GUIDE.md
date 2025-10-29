# OpenTDFKit Migration Guide

This guide covers breaking changes across all OpenTDFKit versions.

## v4.0.0 - StandardTDF → TDF Rename

**Release Date:** October 2025

### Breaking Changes

**What changed:** Renamed all "StandardTDF" types to "TDF" to reflect the architectural reality that TDF is the parent format with multiple envelope types (archive, future JSON), with NanoTDF as a binary subset.

### Type Renames

| Old Name (v3.x) | New Name (v4.0) |
|----------------|-----------------|
| `StandardTDFContainer` | `TDFContainer` |
| `StandardTDFEncryptor` | `TDFEncryptor` |
| `StandardTDFDecryptor` | `TDFDecryptor` |
| `StandardTDFEncryptionResult` | `TDFEncryptionResult` |
| `StandardTDFEncryptionConfiguration` | `TDFEncryptionConfiguration` |
| `StandardTDFKasInfo` | `TDFKasInfo` |
| `StandardTDFPolicy` | `TDFPolicy` |
| `StandardTDFPolicyError` | `TDFPolicyError` |
| `StandardTDFCrypto` | `TDFCrypto` |
| `StandardTDFCryptoError` | `TDFCryptoError` |
| `StreamingStandardTDFCrypto` | `StreamingTDFCrypto` |
| `TDFDecryptError` | `TDFDecryptError` |
| `StandardTDFBuilder` | `TDFBuilder` |
| `StandardTDFLoader` | `TDFLoader` |
| `StandardTDFKASRewrapResult` | `TDFKASRewrapResult` |
| `TrustedDataFormatKind.standard` | `TrustedDataFormatKind.archive` |

### Method Renames

| Old Name | New Name |
|----------|----------|
| `KASRewrapClient.rewrapStandardTDF()` | `KASRewrapClient.rewrapTDF()` |
| `KASRewrapError.invalidStandardTDFRequest` | `KASRewrapError.invalidTDFRequest` |

### Migration Steps

1. **Global Find & Replace** - Use your editor's find-and-replace to update all references:
   ```
   StandardTDFContainer → TDFContainer
   TDFEncryptor → TDFEncryptor
   StandardTDFDecryptor → TDFDecryptor
   StandardTDFCrypto → TDFCrypto
   StreamingStandardTDFCrypto → StreamingTDFCrypto
   rewrapStandardTDF → rewrapTDF
   .standard → .archive (for TrustedDataFormatKind only)
   ```

2. **Update Imports** - No import changes needed; all types remain in OpenTDFKit module

3. **Environment Variables** - No changes to environment variables (already use `TDF_` prefix)

### Example: Before and After

**Before (v3.x):**
```swift
import OpenTDFKit

let kasInfo = StandardTDFKasInfo(
    url: kasURL,
    publicKeyPEM: publicKey
)

let policy = try StandardTDFPolicy(json: policyJSON)

let configuration = StandardTDFEncryptionConfiguration(
    kas: kasInfo,
    policy: policy
)

let encryptor = TDFEncryptor()
let result = try encryptor.encryptFile(
    inputURL: inputURL,
    outputURL: outputURL,
    configuration: configuration
)

let container: StandardTDFContainer = result.container
print("Format: \(container.formatKind)") // .standard
```

**After (v4.0):**
```swift
import OpenTDFKit

let kasInfo = TDFKasInfo(
    url: kasURL,
    publicKeyPEM: publicKey
)

let policy = try TDFPolicy(json: policyJSON)

let configuration = TDFEncryptionConfiguration(
    kas: kasInfo,
    policy: policy
)

let encryptor = TDFEncryptor()
let result = try encryptor.encryptFile(
    inputURL: inputURL,
    outputURL: outputURL,
    configuration: configuration
)

let container: TDFContainer = result.container
print("Format: \(container.formatKind)") // .archive
```

### Rationale

The rename clarifies the architectural hierarchy:
- **TDF** is the parent format supporting multiple envelope types
  - **Archive envelope** (current "StandardTDF") - ZIP-based
  - **JSON envelope** (future) - JSON-based
  - **NanoTDF** - Binary envelope (compact subset)

This naming better reflects the OpenTDF specification and positions the codebase for future JSON envelope support.

---

## v3.0.0 - Developer Ergonomics Updates

This section covers breaking changes and new features introduced in the developer ergonomics update.

## Breaking Changes

### Optional TDFIntegrityInformation

**What changed:** `TDFIntegrityInformation` is now optional in `TDFEncryptionInformation`.

**Before:**
```swift
let encryptionInfo = TDFEncryptionInformation(
    type: .split,
    keyAccess: [kasObject],
    method: method,
    integrityInformation: TDFIntegrityInformation(...), // Required
    policy: policyBase64
)
```

**After:**
```swift
// Option 1: Omit integrity information for simple cases
let encryptionInfo = TDFEncryptionInformation(
    type: .split,
    keyAccess: [kasObject],
    method: method,
    policy: policyBase64
)

// Option 2: Use minimal integrity info
let encryptionInfo = TDFEncryptionInformation(
    type: .split,
    keyAccess: [kasObject],
    method: method,
    integrityInformation: .minimal,
    policy: policyBase64
)

// Option 3: Provide full integrity information (as before)
let encryptionInfo = TDFEncryptionInformation(
    type: .split,
    keyAccess: [kasObject],
    method: method,
    integrityInformation: TDFIntegrityInformation(...),
    policy: policyBase64
)
```

**Migration steps:**
1. If you're creating TDF manifests without segment integrity, you can now omit the `integrityInformation` parameter entirely
2. If you need placeholder integrity info, use `.minimal` static factory
3. Code that provides explicit integrity information continues to work unchanged

### Decryption with Multi-Segment TDFs

**What changed:** Multi-segment decryption now requires integrity information.

**Before:**
```swift
// Would fail silently or produce undefined behavior if integrityInformation was missing
```

**After:**
```swift
// Throws TDFDecryptError.missingIntegrityInformation if integrity info is nil
try decryptor.decryptFileMultiSegment(
    inputURL: inputURL,
    outputURL: outputURL,
    symmetricKey: symmetricKey
)
```

**Migration steps:**
- Multi-segment TDFs created by `TDFEncryptor` always include integrity information, so no changes needed for normal workflows
- If manually constructing manifests for multi-segment decryption, ensure `integrityInformation` is provided

## New Features

### 1. TDFManifestBuilder - Reduce Boilerplate

**Purpose:** Simplify manifest creation for common use cases.

**Example - Single KAS:**
```swift
let builder = TDFManifestBuilder()

// Before: ~50 lines of manual construction
let manifest = builder.buildStandardManifest(
    wrappedKey: wrappedDEK,
    kasURL: URL(string: "https://kas.arkavo.net")!,
    policy: policyBase64,
    iv: ivBase64,
    mimeType: "video/mp2t",
    policyBinding: policyBinding
)
// After: ~8 lines
```

**Example - Multi-KAS (Split Key):**
```swift
let kasObjects = [
    TDFKeyAccessObject(...), // KAS 1
    TDFKeyAccessObject(...), // KAS 2
]

let manifest = builder.buildMultiKASManifest(
    keyAccessObjects: kasObjects,
    policy: policyBase64,
    iv: ivBase64
)
```

**Parameters:**
- `wrappedKey`: Base64-encoded wrapped symmetric key
- `kasURL`: KAS endpoint URL
- `policy`: Base64-encoded policy JSON
- `iv`: Base64-encoded initialization vector
- `mimeType`: Content MIME type (default: `"application/octet-stream"`)
- `tdfSpecVersion`: TDF spec version (default: `"4.3.0"`)
- `policyBinding`: Policy binding hash
- `integrityInformation`: Optional integrity info (default: `nil`)

### 2. TDFArchiveWriter.buildArchiveToFile - Memory Efficiency

**Purpose:** Write archives directly to disk, avoiding in-memory overhead.

**Example - From Data:**
```swift
let writer = TDFArchiveWriter()
try writer.buildArchiveToFile(
    manifest: manifest,
    payload: encryptedPayload,
    outputURL: URL(fileURLWithPath: "/path/to/output.tdf")
)
```

**Example - From File:**
```swift
try writer.buildArchiveToFile(
    manifest: manifest,
    payloadURL: URL(fileURLWithPath: "/path/to/payload.bin"),
    outputURL: URL(fileURLWithPath: "/path/to/output.tdf")
)
```

**Benefits:**
- Avoids double-buffering large payloads
- Better memory usage for large files
- Cleaner API - no need to capture intermediate `Data` result

### 3. TDFIntegrityInformation.minimal - Placeholder Helper

**Purpose:** Quick placeholder for simple use cases without segment integrity.

**Example:**
```swift
// Instead of:
let integrity = TDFIntegrityInformation(
    rootSignature: TDFRootSignature(alg: "HS256", sig: ""),
    segmentHashAlg: "GMAC",
    segmentSizeDefault: 0,
    segments: []
)

// Use:
let integrity = TDFIntegrityInformation.minimal
```

**Properties:**
- `rootSignature.alg`: `"HS256"`
- `rootSignature.sig`: `""`
- `segmentHashAlg`: `"GMAC"`
- `segmentSizeDefault`: `0`
- `encryptedSegmentSizeDefault`: `nil`
- `segments`: `[]`

## Platform Compatibility

All new features work on:
- macOS 14.0+
- iOS 18.0+
- watchOS 11.0+
- tvOS 18.0+

File operations (`buildArchiveToFile`) use standard `FileHandle` and `FileManager` APIs available on all platforms.

## Example: Before and After

### Creating a Simple TDF Manifest

**Before:**
```swift
// 55 lines of boilerplate
let kasObject = TDFKeyAccessObject(
    type: .wrapped,
    url: "https://kas.example.com",
    protocolValue: .kas,
    wrappedKey: wrappedKey,
    policyBinding: policyBinding,
    encryptedMetadata: nil,
    kid: nil,
    sid: nil,
    schemaVersion: "1.0",
    ephemeralPublicKey: nil
)

let method = TDFMethodDescriptor(
    algorithm: "AES-256-GCM",
    iv: ivBase64,
    isStreamable: true
)

let rootSig = TDFRootSignature(alg: "HS256", sig: "")
let integrity = TDFIntegrityInformation(
    rootSignature: rootSig,
    segmentHashAlg: "GMAC",
    segmentSizeDefault: 0,
    encryptedSegmentSizeDefault: nil,
    segments: []
)

let encryptionInfo = TDFEncryptionInformation(
    type: .split,
    keyAccess: [kasObject],
    method: method,
    integrityInformation: integrity,
    policy: policyBase64
)

let payloadDescriptor = TDFPayloadDescriptor(
    type: .reference,
    url: "0.payload",
    protocolValue: .zip,
    isEncrypted: true,
    mimeType: "video/mp2t"
)

let manifest = TDFManifest(
    schemaVersion: "4.3.0",
    payload: payloadDescriptor,
    encryptionInformation: encryptionInfo,
    assertions: nil
)
```

**After:**
```swift
// 9 lines, same result
let builder = TDFManifestBuilder()
let manifest = builder.buildStandardManifest(
    wrappedKey: wrappedKey,
    kasURL: URL(string: "https://kas.example.com")!,
    policy: policyBase64,
    iv: ivBase64,
    mimeType: "video/mp2t",
    policyBinding: policyBinding
)
```

## Questions?

See [OPENTDFKIT_API_RECOMMENDATIONS.md](./OPENTDFKIT_API_RECOMMENDATIONS.md) for the original API feedback and design rationale.
