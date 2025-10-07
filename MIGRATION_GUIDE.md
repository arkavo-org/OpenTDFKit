# Migration Guide: Developer Ergonomics Updates

This guide covers breaking changes and new features introduced in the developer ergonomics update.

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
// Throws StandardTDFDecryptError.missingIntegrityInformation if integrity info is nil
try decryptor.decryptFileMultiSegment(
    inputURL: inputURL,
    outputURL: outputURL,
    symmetricKey: symmetricKey
)
```

**Migration steps:**
- Multi-segment TDFs created by `StandardTDFEncryptor` always include integrity information, so no changes needed for normal workflows
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
