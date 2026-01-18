# NanoTDF to TDF-CBOR Migration Guide

## Deprecation Notice

**NanoTDF is deprecated as of OpenTDFKit 2.0.** New applications should use TDF-CBOR instead. NanoTDF will be removed in a future major version.

### Why TDF-CBOR?

| Feature | NanoTDF | TDF-CBOR |
|---------|---------|----------|
| Format | Custom binary | Standard CBOR (RFC 8949) |
| Manifest | Binary-encoded, limited | Full TDF manifest, extensible |
| Policy | Embedded binding only | Full JSON policy with attributes |
| Assertions | Not supported | Fully supported |
| Multi-KAS | Not supported | Supported |
| Tooling | Custom parsers needed | Standard CBOR tools work |
| Size | ~250 bytes overhead | ~460 bytes overhead |
| Cross-SDK | Complex, version-sensitive | Simple, well-defined |

### When to Still Use NanoTDF

- Existing systems with NanoTDF infrastructure
- Extreme size constraints (< 500 bytes total overhead)
- Legacy compatibility requirements

---

## Migration Steps

### 1. Update Imports

NanoTDF uses low-level primitives scattered across files. TDF-CBOR uses a unified builder pattern.

```swift
// Old: NanoTDF
import OpenTDFKit
// Uses: NanoTDF, Header, Payload, KasMetadata, createNanoTDFv12()

// New: TDF-CBOR
import OpenTDFKit
// Uses: TDFCBORBuilder, TDFCBORContainer, TDFPolicy
```

### 2. Encryption

#### NanoTDF (Deprecated)

```swift
// Create KAS metadata
let kasMetadata = KasMetadata(
    url: URL(string: "https://kas.example.com")!,
    publicKey: kasPublicKey,
    curve: .secp256r1
)

// Create policy
var policy = Policy(
    type: .remote,
    body: .remote(RemotePolicyBody(url: policyUrl)),
    binding: nil  // Will be set during creation
)

// Encrypt
let nanoTDF = try await createNanoTDFv12(
    kas: kasMetadata,
    policy: &policy,
    plaintext: plaintextData
)

// Serialize
let encryptedData = nanoTDF.toData()
```

#### TDF-CBOR (Recommended)

```swift
// Create policy
let policy = TDFPolicy(
    uuid: UUID().uuidString,
    body: TDFPolicyBody(
        dataAttributes: [],
        dissem: ["user@example.com"]
    )
)

// Build and encrypt in one fluent chain
let result = try TDFCBORBuilder()
    .kasURL(URL(string: "https://kas.example.com")!)
    .kasPublicKey(kasPublicKeyPEM)
    .policy(policy)
    .mimeType("application/octet-stream")
    .encrypt(plaintext: plaintextData)

// Get the encrypted container and symmetric key
let container = result.container
let symmetricKey = result.symmetricKey  // Save for offline decryption

// Serialize to CBOR bytes
let encryptedData = try container.serializedData()
```

### 3. Decryption

#### NanoTDF (Deprecated)

```swift
// Parse the NanoTDF
let parser = BinaryParser(data: encryptedData)
let nanoTDF = try parser.parseNanoTDF()

// Method 1: Using KeyStore (offline)
let keyStore = KeyStore()
keyStore.addPrivateKey(privateKey, for: kasPublicKey)
let plaintext = try await nanoTDF.getPlaintext(using: keyStore)

// Method 2: Using KAS rewrap
let rewrapClient = KASRewrapClient(kasURL: kasURL, token: accessToken)
let unwrappedKey = try await rewrapClient.rewrap(header: nanoTDF.header)
let symmetricKey = try deriveSymmetricKey(from: unwrappedKey)
let plaintext = try await nanoTDF.getPayloadPlaintext(symmetricKey: symmetricKey)
```

#### TDF-CBOR (Recommended)

```swift
// Parse the TDF-CBOR
let envelope = try TDFCBOREnvelope.fromCBORData(encryptedData)
let container = TDFCBORContainer(envelope: envelope)

// Method 1: Offline decryption with symmetric key
let plaintext = try TDFCrypto.decryptPayload(
    ciphertext: container.payloadData,
    symmetricKey: symmetricKey
)

// Method 2: Using KAS rewrap (TBD - similar pattern to NanoTDF)
// The key access object contains all info needed for KAS rewrap
let keyAccess = container.encryptionInformation.keyAccess.first!
// Send rewrap request to keyAccess.url with wrapped key
```

### 4. Policy Handling

#### NanoTDF (Deprecated)

```swift
// Policies are binary-encoded and limited
let policy = Policy(
    type: .remote,
    body: .remote(RemotePolicyBody(url: policyUrl)),
    binding: nil
)
// Only supports remote policy URLs or embedded policy bytes
```

#### TDF-CBOR (Recommended)

```swift
// Full JSON policy with attributes and dissemination
let policy = TDFPolicy(
    uuid: UUID().uuidString,
    body: TDFPolicyBody(
        dataAttributes: [
            TDFAttribute(attribute: "https://example.com/attr/classification/value/secret")
        ],
        dissem: ["user@example.com", "team@example.com"]
    )
)

// Access policy from decrypted container
let encInfo = container.encryptionInformation
let policyJSON = encInfo.policy  // Base64-encoded JSON
```

### 5. File Operations

#### NanoTDF (Deprecated)

```swift
// Write NanoTDF to file
let nanoTDF = try await createNanoTDFv12(kas: kas, policy: &policy, plaintext: data)
try nanoTDF.toData().write(to: fileURL)

// Read NanoTDF from file
let data = try Data(contentsOf: fileURL)
let parser = BinaryParser(data: data)
let nanoTDF = try parser.parseNanoTDF()
```

#### TDF-CBOR (Recommended)

```swift
// Write TDF-CBOR to file
let result = try TDFCBORBuilder()
    .kasURL(kasURL)
    .kasPublicKey(kasPublicKeyPEM)
    .policy(policy)
    .encrypt(plaintext: data)
try result.container.serializedData().write(to: fileURL)

// Read TDF-CBOR from file
let data = try Data(contentsOf: fileURL)
let envelope = try TDFCBOREnvelope.fromCBORData(data)
let container = TDFCBORContainer(envelope: envelope)
```

---

## CLI Migration

### NanoTDF (Deprecated)

```bash
# Encrypt
OpenTDFKitCLI encrypt input.txt output.ntdf nano

# Decrypt
OpenTDFKitCLI decrypt output.ntdf recovered.txt nano
```

### TDF-CBOR (Recommended)

```bash
# Encrypt
export KASURL="https://kas.example.com"
export TDF_KAS_PUBLIC_KEY_PATH="/path/to/kas-public.pem"
OpenTDFKitCLI encrypt input.txt output.cbor cbor

# Decrypt
export TDF_SYMMETRIC_KEY_PATH="/path/to/key.txt"
OpenTDFKitCLI decrypt output.cbor recovered.txt cbor

# Verify structure
OpenTDFKitCLI verify output.cbor
```

---

## Error Handling Changes

### NanoTDF Errors

```swift
do {
    let nanoTDF = try await createNanoTDFv12(kas: kas, policy: &policy, plaintext: data)
} catch CryptoHelperError.keyDerivationFailed {
    // Handle key derivation failure
} catch CryptoHelperError.invalidKey {
    // Handle invalid key
}
```

### TDF-CBOR Errors

```swift
do {
    let result = try TDFCBORBuilder()
        .kasURL(kasURL)
        .kasPublicKey(pem)
        .policy(policy)
        .encrypt(plaintext: data)
} catch TDFCBORError.encryptionFailed(let message) {
    // Handle encryption failure with descriptive message
} catch TDFCBORError.missingField(let field) {
    // Handle missing required field
} catch TDFCBORError.cborEncodingFailed(let reason) {
    // Handle CBOR encoding issues
}
```

---

## Size Comparison

For a 100-byte payload:

| Format | Total Size | Overhead |
|--------|------------|----------|
| NanoTDF | ~350 bytes | ~250 bytes |
| TDF-CBOR | ~560 bytes | ~460 bytes |
| TDF-JSON | ~1,300 bytes | ~1,200 bytes |
| TDF Archive (ZIP) | ~1,500 bytes | ~1,400 bytes |

TDF-CBOR offers the best balance of features and size efficiency for most use cases.

---

## Interoperability

TDF-CBOR provides better cross-SDK interoperability:

```swift
// Swift SDK creates TDF-CBOR
let swiftCBOR = try TDFCBORBuilder()
    .kasURL(kasURL)
    .kasPublicKey(pem)
    .policy(policy)
    .encrypt(plaintext: data)

// Rust SDK can read it directly
// cargo run --example tdf_cbor_example --features cbor

// And vice versa - Swift can read Rust-created TDF-CBOR
let rustData = try Data(contentsOf: URL(fileURLWithPath: "rust_created.cbor"))
let envelope = try TDFCBOREnvelope.fromCBORData(rustData)
```

---

## Timeline

- **Now**: NanoTDF marked as deprecated
- **OpenTDFKit 2.x**: NanoTDF continues to work with deprecation warnings
- **OpenTDFKit 3.0**: NanoTDF removed

---

## Need Help?

- [OpenTDFKit GitHub Issues](https://github.com/opentdf/openTDFKit/issues)
- [TDF-CBOR Specification](../../specifications/tdf-cbor/draft-00.md)
