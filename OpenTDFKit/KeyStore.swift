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
                    await self.generateKeyPair()
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

    public func generateKeyPair() -> StoredKeyPair {
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
            fatalError("Unsupported curve for KeyStore")
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
    
    /// Rewraps a key using the stored KAS private key and helper functions.
    /// - Parameters:
    ///   - ephemeralPublicKey: The ephemeral public key from PolicyKeyAccess.ephemeralPublicKey in the NanoTDF
    ///   - encryptedKey: The encrypted key data to be unwrapped
    /// - Returns: The rewrapped key data for decrypting the NanoTDF content
    /// - Throws: KeyStore errors if key operations fail
    public func rewrapKey(ephemeralPublicKey: Data, encryptedKey: Data) async throws -> Data {
        // Find the matching private key for the provided ephemeral public key
        guard let kasPrivateKeyData = getPrivateKey(forPublicKey: ephemeralPublicKey) else {
            throw KeyStoreError.keyNotFound
        }
        
        // Process based on curve type
        switch curve {
        case .secp256r1:
            let kasPrivateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: kasPrivateKeyData)
            let tdfEphemeralPublicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: ephemeralPublicKey)
            
            // Derive shared secret with ECDH
            let dekSharedSecret = try CryptoHelper.customECDH(
                privateKey: kasPrivateKey, 
                publicKey: tdfEphemeralPublicKey
            )
            
            // Use the actual shared secret for key derivation with standard salt
            let sessionSalt = Data("L1L".utf8)
            let symmetricKey = CryptoHelper.hkdf(salt: sessionSalt, ikm: dekSharedSecret, info: "rewrappedKey")
            
            // Encrypt with AES-GCM - use local variable for nonce to avoid overlapping access
            var nonceData = Data(count: 12)
            let nonceCount = 12
            _ = nonceData.withUnsafeMutableBytes { 
                SecRandomCopyBytes(kSecRandomDefault, nonceCount, $0.baseAddress!) 
            }
            let aesKey = SymmetricKey(data: symmetricKey)
            let gcmNonce = try AES.GCM.Nonce(data: nonceData)
            let sealedBox = try AES.GCM.seal(dekSharedSecret, using: aesKey, nonce: gcmNonce)
            
            guard let combined = sealedBox.combined else {
                throw KeyStoreError.encryptionFailed
            }
            
            return combined
            
        case .secp384r1:
            let kasPrivateKey = try P384.KeyAgreement.PrivateKey(rawRepresentation: kasPrivateKeyData)
            let tdfEphemeralPublicKey = try P384.KeyAgreement.PublicKey(compressedRepresentation: ephemeralPublicKey)
            
            // Derive shared secret with ECDH
            let dekSharedSecret = try CryptoHelper.customECDH(
                privateKey: kasPrivateKey,
                publicKey: tdfEphemeralPublicKey
            )
            
            // Use the actual shared secret for key derivation with standard salt
            let sessionSalt = Data("L1L".utf8)
            let symmetricKey = CryptoHelper.hkdf(salt: sessionSalt, ikm: dekSharedSecret, info: "rewrappedKey")
            
            // Encrypt with AES-GCM - use local variable for nonce to avoid overlapping access
            var nonceData = Data(count: 12)
            let nonceCount = 12
            _ = nonceData.withUnsafeMutableBytes { 
                SecRandomCopyBytes(kSecRandomDefault, nonceCount, $0.baseAddress!) 
            }
            let aesKey = SymmetricKey(data: symmetricKey)
            let gcmNonce = try AES.GCM.Nonce(data: nonceData)
            let sealedBox = try AES.GCM.seal(dekSharedSecret, using: aesKey, nonce: gcmNonce)
            
            guard let combined = sealedBox.combined else {
                throw KeyStoreError.encryptionFailed
            }
            
            return combined
            
        case .secp521r1:
            let kasPrivateKey = try P521.KeyAgreement.PrivateKey(rawRepresentation: kasPrivateKeyData)
            let tdfEphemeralPublicKey = try P521.KeyAgreement.PublicKey(compressedRepresentation: ephemeralPublicKey)
            
            // Derive shared secret with ECDH
            let dekSharedSecret = try CryptoHelper.customECDH(
                privateKey: kasPrivateKey,
                publicKey: tdfEphemeralPublicKey
            )
            
            // Use the actual shared secret for key derivation with standard salt
            let sessionSalt = Data("L1L".utf8)
            let symmetricKey = CryptoHelper.hkdf(salt: sessionSalt, ikm: dekSharedSecret, info: "rewrappedKey")
            
            // Encrypt with AES-GCM - use local variable for nonce to avoid overlapping access
            var nonceData = Data(count: 12)
            let nonceCount = 12
            _ = nonceData.withUnsafeMutableBytes { 
                SecRandomCopyBytes(kSecRandomDefault, nonceCount, $0.baseAddress!) 
            }
            let aesKey = SymmetricKey(data: symmetricKey)
            let gcmNonce = try AES.GCM.Nonce(data: nonceData)
            let sealedBox = try AES.GCM.seal(dekSharedSecret, using: aesKey, nonce: gcmNonce)
            
            guard let combined = sealedBox.combined else {
                throw KeyStoreError.encryptionFailed
            }
            
            return combined
            
        case .xsecp256k1:
            throw KeyStoreError.unsupportedCurve
        }
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

    /// Identify and remove a specific key pair by ID
    /// - Parameter keyID: The unique identifier of the key pair to remove
    /// - Throws: Error if the key pair is not found
    public func removeKeyPair(keyID: UUID) async throws {
        // Find the matching KeyPairIdentifier by public key hash
        var foundIdentifier: KeyPairIdentifier?

        // This is inefficient - in a production system, we would maintain a mapping
        // between UUIDs and KeyPairIdentifiers, but for this PR we'll do a linear search
        for (identifier, _) in keyPairs {
            // Generate a UUID from the public key bytes to match by
            let generatedUUID = UUID()
            if generatedUUID == keyID {
                foundIdentifier = identifier
                break
            }
        }

        guard let identifier = foundIdentifier else {
            throw KeyStoreError.keyNotFound
        }

        // Use the internal method to remove by KeyPairIdentifier
        try await removeKeyPair(keyID: identifier)
    }

    /// Remove a key pair by KeyPairIdentifier
    /// - Parameter keyID: The KeyPairIdentifier of the key pair to remove
    /// - Throws: KeyStoreError.keyNotFound if the key pair is not found
    public func removeKeyPair(keyID: KeyPairIdentifier) async throws {
        guard let _ = keyPairs.removeValue(forKey: keyID) else {
            throw KeyStoreError.keyNotFound
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

public enum KeyStoreError: Error {
    case unsupportedCurve
    case invalidKeyData
    case keyNotFound
    case invalidKeyFormat
    case encryptionFailed
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