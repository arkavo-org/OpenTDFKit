import CryptoKit
import Foundation

// MARK: - Key Types and Storage

public struct KeyPairIdentifier: Hashable, Sendable {
    // Store the public key bytes directly - already fixed size per curve
    private let bytes: Data

    public var publicKey: Data {
        bytes
    }

    public init(publicKey: Data) {
        bytes = publicKey
    }
}

public struct StoredKeyPair: Sendable {
    // Store all bytes contiguously
    private let bytes: ContiguousArray<UInt8>
    private let publicKeyLength: Int

    public var publicKey: Data {
        bytes.withUnsafeBufferPointer { buffer in
            Data(bytes: buffer.baseAddress!, count: publicKeyLength)
        }
    }

    var privateKey: Data {
        bytes.withUnsafeBufferPointer { buffer in
            let privateKeyStart = buffer.baseAddress!.advanced(by: publicKeyLength)
            let privateKeyLength = buffer.count - publicKeyLength
            return Data(bytes: privateKeyStart, count: privateKeyLength)
        }
    }

    init(publicKey: Data, privateKey: Data) {
        // Single allocation for both keys
        var bytes = ContiguousArray<UInt8>()
        bytes.reserveCapacity(publicKey.count + privateKey.count)

        // Copy bytes directly without intermediate buffers
        publicKey.withUnsafeBytes { pubBytes in
            bytes.append(contentsOf: pubBytes)
        }
        privateKey.withUnsafeBytes { privBytes in
            bytes.append(contentsOf: privBytes)
        }

        self.bytes = bytes
        publicKeyLength = publicKey.count
    }
}

// MARK: - KeyStore Implementation

public actor KeyStore {
    public let curve: Curve
    public var keyPairs: [KeyPairIdentifier: StoredKeyPair]
    // Track total memory used
    public var totalBytesStored: Int = 0

    public init(curve: Curve, capacity: Int = 1000) {
        self.curve = curve
        keyPairs = Dictionary(minimumCapacity: capacity)
        totalBytesStored = 0
    }

    public func getPrivateKey(forPublicKey publicKey: Data) -> Data? {
        let identifier = KeyPairIdentifier(publicKey: publicKey)
        return keyPairs[identifier]?.privateKey
    }

    public func store(keyPair: StoredKeyPair) {
        let identifier = KeyPairIdentifier(publicKey: keyPair.publicKey)
        keyPairs[identifier] = keyPair
        totalBytesStored += curve.publicKeyLength + curve.privateKeyLength
    }

    // Batch storage optimized for memory
    public func storeBatch(pairs: [(publicKey: Data, privateKey: Data)]) {
        // Pre-allocate for entire batch
        let totalNewBytes = pairs.count * (curve.publicKeyLength + curve.privateKeyLength)
        keyPairs.reserveCapacity(keyPairs.count + pairs.count)

        // Store all pairs
        for pair in pairs {
            let stored = StoredKeyPair(publicKey: pair.publicKey, privateKey: pair.privateKey)
            let identifier = KeyPairIdentifier(publicKey: pair.publicKey)
            keyPairs[identifier] = stored
        }

        totalBytesStored += totalNewBytes
    }

    // Batch generation method
    public func generateAndStoreKeyPairs(count: Int) async throws {
        // Pre-allocate space
        var tempPairs: [(KeyPairIdentifier, StoredKeyPair)] = []
        tempPairs.reserveCapacity(count)

        try await withThrowingTaskGroup(of: StoredKeyPair.self) { group in
            for _ in 0 ..< count {
                group.addTask {
                    try await self.generateKeyPair() // Now calling a throwing function
                }
            }

            for try await keyPair in group {
                let identifier = KeyPairIdentifier(publicKey: keyPair.publicKey)
                tempPairs.append((identifier, keyPair))
            }
        }

        // Batch insert
        for (identifier, keyPair) in tempPairs {
            keyPairs[identifier] = keyPair
            totalBytesStored += curve.publicKeyLength + curve.privateKeyLength
        }
    }

    public func generateKeyPair() throws -> StoredKeyPair { // Made throwing
        // Since curve is a stored property, no need for switch
        switch curve {
        case .secp521r1:
            let privateKey = P521.KeyAgreement.PrivateKey()
            return StoredKeyPair(
                publicKey: privateKey.publicKey.compressedRepresentation,
                privateKey: privateKey.rawRepresentation
            )
        case .secp384r1:
            let privateKey = P384.KeyAgreement.PrivateKey()
            return StoredKeyPair(
                publicKey: privateKey.publicKey.compressedRepresentation,
                privateKey: privateKey.rawRepresentation
            )
        case .secp256r1:
            let privateKey = P256.KeyAgreement.PrivateKey()
            return StoredKeyPair(
                publicKey: privateKey.publicKey.compressedRepresentation,
                privateKey: privateKey.rawRepresentation
            )
        case .xsecp256k1:
            throw KeyStoreError.unsupportedCurve // Throw error instead of fatalError
        }
    }

    /// Serializes the key store data into a Data object.
    /// - Returns: A Data object containing the serialized key store data.
    public func serialize() -> Data {
        let estimatedSize = keyPairs.count * (curve.publicKeyLength + curve.privateKeyLength) + 5
        // Create a Data object with an initial capacity based on the estimated size.
        // This can help improve performance by reducing the number of reallocations.
        var data = Data(capacity: estimatedSize)

        // Store curve type
        data.append(curve.rawValue)

        // Store count
        let count = UInt32(keyPairs.count)
        withUnsafeBytes(of: count.bigEndian) { data.append(contentsOf: $0) }
        // Append the big-endian representation of the key pair count to the data.

        // Store key pairs - no need for length prefixes since sizes are fixed per curve
        for keyPair in keyPairs.values {
            data.append(keyPair.publicKey)
            data.append(keyPair.privateKey)
        }

        return data
    }

    /// Deserializes key store data from a Data object.
    /// - Parameter data: The Data object containing the serialized key store data.
    /// - Throws: `KeyStoreError.invalidKeyData` if the data is invalid.
    public func deserialize(from data: Data) throws {
        guard data.count >= 5 else { throw KeyStoreError.invalidKeyData }

        // Read curve
        let curveValue = data[data.startIndex]
        guard let curve = Curve(rawValue: curveValue),
              curve == self.curve else { throw KeyStoreError.invalidKeyData }

        // Read count
        let countBytes = [UInt8](data[data.index(data.startIndex, offsetBy: 1) ... data.index(data.startIndex, offsetBy: 4)])
        let count = UInt32(countBytes[0]) << 24 | UInt32(countBytes[1]) << 16 | UInt32(countBytes[2]) << 8 | UInt32(countBytes[3])

        let pairSize = curve.publicKeyLength + curve.privateKeyLength
        let expectedSize = 5 + (Int(count) * pairSize)
        guard data.count == expectedSize else { throw KeyStoreError.invalidKeyData }

        // Clear existing data
        keyPairs.removeAll(keepingCapacity: true)

        var offset = 5

        // Pre-allocate capacity
        keyPairs.reserveCapacity(Int(count))

        // Read fixed-size pairs
        for _ in 0 ..< count {
            let pubKeyStart = data.index(data.startIndex, offsetBy: offset)
            let pubKeyEnd = data.index(pubKeyStart, offsetBy: curve.publicKeyLength)
            let publicKey = data[pubKeyStart ..< pubKeyEnd]

            let privKeyStart = pubKeyEnd
            let privKeyEnd = data.index(privKeyStart, offsetBy: curve.privateKeyLength)
            let privateKey = data[privKeyStart ..< privKeyEnd]

            let keyPair = StoredKeyPair(
                publicKey: Data(publicKey),
                privateKey: Data(privateKey)
            )

            let identifier = KeyPairIdentifier(publicKey: keyPair.publicKey)
            keyPairs[identifier] = keyPair

            offset += pairSize
        }
    }

    /// Derives the symmetric key for NanoTDF v13 payload decryption using ECDH.
    /// This function assumes the KeyStore holds the KAS's private key.
    ///
    /// - Parameters:
    ///   - kasPublicKeyForLookup: The public key of the KAS, used to retrieve its private key from this KeyStore.
    ///                            This corresponds to `header.payloadKeyAccess.kasPublicKey`.
    ///   - clientEphemeralPublicKey: The ephemeral public key from the NanoTDF Header's main ephemeral key field.
    ///                               This corresponds to `header.ephemeralPublicKey`.
    ///   - curve: The elliptic curve used for the key agreement (e.g., from `header.payloadKeyAccess.kasKeyCurve`).
    /// - Returns: The derived symmetric key for AES-256-GCM as Data.
    /// - Throws: KeyStoreError or other errors if key derivation fails.
    public func derivePayloadSymmetricKeyForV13(
        kasPublicKeyForLookup: Data,
        clientEphemeralPublicKey: Data,
        curve: Curve
    ) async throws -> Data {
        // 1. Get the KAS's private key from this KeyStore
        // The kasPublicKeyForLookup is the KAS's own public key, used to identify its private key.
        guard let kasPrivateKeyData = getPrivateKey(forPublicKey: kasPublicKeyForLookup) else {
            throw KeyStoreError.keyNotFound("Private key for KAS Public Key \(kasPublicKeyForLookup.hexString) not found in this KeyStore.")
        }

        // 2. Perform Elliptic Curve Diffie-Hellman (ECDH) Key Agreement
        let sharedSecret: SharedSecret
        do {
            switch curve {
            case .secp256r1:
                let kasPrivKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: kasPrivateKeyData)
                let clientPubKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: clientEphemeralPublicKey)
                sharedSecret = try kasPrivKey.sharedSecretFromKeyAgreement(with: clientPubKey)
            case .secp384r1:
                let kasPrivKey = try P384.KeyAgreement.PrivateKey(rawRepresentation: kasPrivateKeyData)
                let clientPubKey = try P384.KeyAgreement.PublicKey(compressedRepresentation: clientEphemeralPublicKey)
                sharedSecret = try kasPrivKey.sharedSecretFromKeyAgreement(with: clientPubKey)
            case .secp521r1:
                let kasPrivKey = try P521.KeyAgreement.PrivateKey(rawRepresentation: kasPrivateKeyData)
                let clientPubKey = try P521.KeyAgreement.PublicKey(compressedRepresentation: clientEphemeralPublicKey)
                sharedSecret = try kasPrivKey.sharedSecretFromKeyAgreement(with: clientPubKey)
            case .xsecp256k1:
                // CryptoKit does not natively support secp256k1 for key agreement.
                throw KeyStoreError.unsupportedCurve
            }
        } catch {
            throw KeyStoreError.keyAgreementFailed("ECDH key agreement failed: \(error.localizedDescription)")
        }

        // 3. Derive the symmetric key using HKDF (v13 specific)
        //    Salt: "L1M" for v13
        //    Info: "encryption" for payload symmetric key
        //    Output Byte Count: 32 (for AES-256)
        let symmetricKeyCryptoKit = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("L1M".utf8), // v13 salt
            sharedInfo: Data("encryption".utf8), // Standard info for payload encryption
            outputByteCount: 32 // For AES-256
        )

        // Convert SymmetricKey to Data
        return symmetricKeyCryptoKit.withUnsafeBytes { Data($0) }
    }

    // MARK: - One-Time TDF Extensions

    /// Export a PublicKeyStore containing only the public keys from this KeyStore
    /// - Returns: A PublicKeyStore with the public keys from this KeyStore
    public func exportPublicKeyStore() async -> PublicKeyStore {
        let publicKeyStore = PublicKeyStore(curve: curve)

        // Extract all public keys from keyPairs dictionary
        let allPublicKeys = keyPairs.values.map(\.publicKey)

        // Add all public keys to the new store
        await publicKeyStore.addPublicKeys(allPublicKeys)

        return publicKeyStore
    }

    /// Remove a key pair by KeyPairIdentifier
    /// - Parameter keyID: The KeyPairIdentifier of the key pair to remove
    /// - Throws: KeyStoreError.keyNotFound if the key pair is not found
    public func removeKeyPair(keyID: KeyPairIdentifier) async throws {
        guard let _ = keyPairs.removeValue(forKey: keyID) else {
            throw KeyStoreError.keyNotFound(keyID.publicKey.hexString)
        }

        // Update storage tracking
        totalBytesStored -= (curve.publicKeyLength + curve.privateKeyLength)
    }

    /// Check if the store contains a key pair matching the given public key
    /// - Parameter publicKey: The public key to check for
    /// - Returns: True if a matching key pair is found
    public func containsMatchingPublicKey(_ publicKey: Data) async -> Bool {
        let identifier = KeyPairIdentifier(publicKey: publicKey)
        return keyPairs[identifier] != nil
    }

    /// Get the current count of key pairs in the store
    /// - Returns: The number of key pairs in the store
    public func getKeyCount() async -> Int {
        keyPairs.count
    }
}

// Helper extension for testing
extension KeyStore {
    func getAllPublicKeys() -> [Data] {
        Array(keyPairs.values.map(\.publicKey))
    }
}

public enum KeyStoreError: Error, Equatable {
    case unsupportedCurve
    case invalidKeyData
    case keyNotFound(String? = nil) // Added optional message
    case invalidKeyFormat
    case encryptionFailed
    case keyGenerationFailed
    case signingFailed
    case decryptionFailed
    case unknownError
    case keyAgreementFailed(String? = nil)
    case keyDerivationFailed(String? = nil)

    // Equatable conformance
    public static func == (lhs: KeyStoreError, rhs: KeyStoreError) -> Bool {
        switch (lhs, rhs) {
        case (.unsupportedCurve, .unsupportedCurve):
            return true
        case (.invalidKeyData, .invalidKeyData):
            return true
        case (.keyNotFound(let lhsMsg), .keyNotFound(let rhsMsg)):
            return lhsMsg == rhsMsg
        case (.invalidKeyFormat, .invalidKeyFormat):
            return true
        case (.encryptionFailed, .encryptionFailed):
            return true
        case (.keyGenerationFailed, .keyGenerationFailed):
            return true
        case (.signingFailed, .signingFailed):
            return true
        case (.decryptionFailed, .decryptionFailed):
            return true
        case (.unknownError, .unknownError):
            return true
        case (.keyAgreementFailed(let lhsMsg), .keyAgreementFailed(let rhsMsg)):
            return lhsMsg == rhsMsg
        case (.keyDerivationFailed(let lhsMsg), .keyDerivationFailed(let rhsMsg)):
            return lhsMsg == rhsMsg
        default:
            return false
        }
    }
}

// Helper extension for Data to hex string (for debugging/errors)
public extension Data {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

// Helper extension
extension Curve {
    var publicKeyLength: Int {
        switch self {
        case .secp256r1: 33 // compressed format
        case .secp384r1: 49
        case .secp521r1: 67
        case .xsecp256k1: 33
        }
    }

    var privateKeyLength: Int {
        switch self {
        case .secp256r1: 32
        case .secp384r1: 48
        case .secp521r1: 66
        case .xsecp256k1: 32
        }
    }
}
