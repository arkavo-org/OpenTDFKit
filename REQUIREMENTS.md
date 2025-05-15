# OpenTDFKit Requirements

## Overview
OpenTDFKit is a Swift toolkit for implementing the OpenTDF (Trusted Data Format) specification with a focus on the NanoTDF format. It provides a secure framework for encrypting, decrypting, and managing protected data with policy-based access controls.

## Core Components

### NanoTDF
- Create and manage NanoTDF containers according to the [OpenTDF nanotdf specification](https://github.com/opentdf/spec/tree/main/schema/nanotdf)
- Support encryption and decryption of data with policy bindings
- Implement secure cryptographic operations for payload protection

### KeyStore
- Manage cryptographic keys with support for various elliptic curves
- Provide efficient key generation, storage, and retrieval
- Ensure thread-safe operations in concurrent environments
- Support serialization and deserialization of key data

### KASService
- Enable key access services for policy-based decryption
- Implement secure key exchange protocols
- Support policy binding verification

### CryptoHelper
- Provide cryptographic primitives for OpenTDF operations
- Support various elliptic curves (secp256r1, secp384r1, secp521r1)
- Implement symmetric encryption for payload protection

## Current API Requirements

### PublicKeyStore Class
```swift
/// A store containing only public keys to be shared with peers
public class PublicKeyStore {
    /// Initialize a PublicKeyStore with a specific curve
    /// - Parameter curve: The elliptic curve to use for the keys
    public init(curve: EllipticCurve)
    
    /// The collection of public keys in this store
    public var publicKeys: [Data] { get async }
    
    /// Deserialize a PublicKeyStore from binary data
    /// - Parameter data: The serialized PublicKeyStore data
    /// - Throws: Deserialization errors
    public func deserialize(from data: Data) async throws
    
    /// Serialize this PublicKeyStore to binary data
    /// - Returns: The serialized data
    public func serialize() async -> Data
    
    /// Get and remove a public key from the store
    /// - Returns: A public key, removing it from the store
    /// - Throws: Error if no keys are available
    public func getAndRemovePublicKey() async throws -> Data
    
    /// Create KAS metadata using one of the public keys
    /// - Parameter resourceLocator: The resource locator for the KAS
    /// - Returns: Key access metadata for TDF creation
    /// - Throws: Error if no keys are available
    public func createKasMetadata(resourceLocator: ResourceLocator) async throws -> KeyAccessMetadata
}
```

### KeyStore Extensions
```swift
extension KeyStore {
    /// Export a PublicKeyStore containing only the public keys from this KeyStore
    /// - Returns: A PublicKeyStore with the public keys from this KeyStore
    public func exportPublicKeyStore() async -> PublicKeyStore
    
    /// Identify and remove a specific key pair by ID
    /// - Parameter keyID: The unique identifier of the key pair to remove
    /// - Throws: Error if the key pair is not found
    public func removeKeyPair(keyID: UUID) async throws
    
    /// Check if the store contains a key pair matching the given public key
    /// - Parameter publicKey: The public key to check for
    /// - Returns: True if a matching key pair is found
    public func containsMatchingPublicKey(_ publicKey: Data) async -> Bool
}
```

### KASService Extensions
```swift
extension KASService {
    /// Process a key access request and report which key was used
    /// - Parameters:
    ///   - ephemeralPublicKey: The ephemeral public key from the requester
    ///   - encryptedKey: The encrypted session key that needs to be rewrapped
    ///   - kasPublicKey: The KAS public key
    /// - Returns: A tuple containing the rewrapped key data and the ID of the key that was used
    /// - Throws: KAS errors
    public func processKeyAccessWithKeyIdentifier(
        ephemeralPublicKey: Data,
        encryptedKey: Data,
        kasPublicKey: Data
    ) async throws -> (rewrappedKey: Data, keyID: UUID)
}
```

## Usage Examples

### Decryption After Rewrap
```swift
let decryptedData = try nanoTDF.getPayloadPlaintext(symmetricKey: symmetricKey)
```

### NanoTDF Creation
```swift
let kasRL = ResourceLocator(protocolEnum: .http, body: "kas.arkavo.net")
let kasMetadata = KasMetadata(resourceLocator: kasRL!, publicKey: publicKey, curve: .secp256r1)
let remotePolicy = ResourceLocator(protocolEnum: .sharedResourceDirectory, body: "5Cqk3ERPToSMuY8UoKJtcmo4fs1iVyQpq6ndzWzpzWezAF1W")
var policy = Policy(type: .remote, body: nil, remote: remotePolicy, binding: nil)
let nanoTDF = try createNanoTDF(kas: kasMetadata, policy: &policy, plaintext: "hello".data(using: .utf8)!)
```

## Performance Requirements

### KeyStore Performance
- Generate and store 8192 EC521 keys in ~23 seconds or less
- Key lookup in ~0.002ms per lookup (440,000+ ops/sec)
- Private key retrieval in ~0.003ms per retrieval (370,000+ ops/sec)
- Serialization throughput of 400+ MB/s

### NanoTDF Operations
- Encryption performance by curve type:
  - secp256r1: ~1.1ms per operation (900+ ops/sec)
  - secp384r1: ~2.9ms per operation (350+ ops/sec)
  - secp521r1: ~7.9ms per operation (125+ ops/sec)
- Decryption in ~0.003ms per operation (390,000+ ops/sec)
- Signature operation in ~1.6ms per operation (630+ ops/sec)

### Serialization Performance
- Payload size scaling:
  - 10 bytes: ~17 MB/s
  - 100 bytes: ~42 MB/s
  - 1,000 bytes: ~225 MB/s
  - 10,000 bytes: ~1.8 GB/s

### KAS Service Performance
- KAS metadata generation in ~0.4ms per operation (2,400+ ops/sec)
- Key access performance by curve type:
  - secp256r1: ~1.3ms per operation (750+ ops/sec)
  - secp384r1: ~3.4ms per operation (290+ ops/sec)
  - secp521r1: ~9.4ms per operation (105+ ops/sec)
- Policy binding verification in ~0.002ms (500,000+ verifications/sec)

## Detailed Requirements

### Perfect Forward Secrecy
- One-time use TDF implementation for enhanced security
- Atomic and permanent key removal operations
- Each key is used exactly once in the system

### Thread Safety
- All operations must be thread-safe
- Support for concurrent access in multi-peer environments
- Proper synchronization of shared resources

### Error Handling
- Clear error types for each possible failure condition
- Proper propagation of errors through the API stack
- Informative error messages for debugging

### Key Management
- Support for generating large batches of keys (8000+)
- Efficient storage and retrieval of key material
- Automatic replenishment mechanism when running low on keys
- Secure storage of sensitive key material

### Implementation Quality
- Clear documentation with examples
- Comprehensive unit tests covering all API functionality
- Integration tests demonstrating complete workflows
- Performance benchmarks for key operations
- Code adheres to Swift best practices and concurrency model
- Support for the latest Swift language features