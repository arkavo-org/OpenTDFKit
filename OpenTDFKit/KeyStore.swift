import CryptoKit
import Darwin
import Foundation

// MARK: - Key Types and Storage

/// Reference-counted storage for key pair bytes that zeroes memory on deallocation.
private final class SecureKeyPairStorage: @unchecked Sendable {
    var bytes: ContiguousArray<UInt8>

    init(publicKey: Data, privateKey: Data) {
        var buffer = ContiguousArray<UInt8>()
        buffer.reserveCapacity(publicKey.count + privateKey.count)
        publicKey.withUnsafeBytes { buffer.append(contentsOf: $0) }
        privateKey.withUnsafeBytes { buffer.append(contentsOf: $0) }
        bytes = buffer
    }

    deinit {
        bytes.withUnsafeMutableBytes { buffer in
            guard let baseAddress = buffer.baseAddress else { return }
            memset_s(baseAddress, buffer.count, 0, buffer.count)
        }
    }
}

public struct KeyPairIdentifier: Hashable, Sendable {
    /// Store the public key bytes directly - already fixed size per curve
    private let bytes: Data

    public var publicKey: Data {
        bytes
    }

    public init(publicKey: Data) {
        bytes = publicKey
    }
}

public struct StoredKeyPair: Sendable {
    // Store all bytes contiguously in zero-on-deinit storage
    private let storage: SecureKeyPairStorage
    private let publicKeyLength: Int

    public var publicKey: Data {
        storage.bytes.withUnsafeBufferPointer { buffer in
            Data(buffer.prefix(publicKeyLength))
        }
    }

    var privateKey: Data {
        storage.bytes.withUnsafeBufferPointer { buffer in
            let privateKeyStart = buffer.index(buffer.startIndex, offsetBy: publicKeyLength)
            return Data(buffer.suffix(from: privateKeyStart))
        }
    }

    /// Appends `publicKey || privateKey` directly from contiguous zero-on-deinit storage
    /// without allocating intermediate `Data` copies of the private key.
    func appendSerializedBytes(to destination: inout Data) {
        storage.bytes.withUnsafeBytes { buffer in
            destination.append(contentsOf: buffer)
        }
    }

    init(publicKey: Data, privateKey: Data) {
        storage = SecureKeyPairStorage(publicKey: publicKey, privateKey: privateKey)
        publicKeyLength = publicKey.count
    }
}

// MARK: - Ephemeral Key Pair

/// Ephemeral key pair for temporary cryptographic operations
public struct EphemeralKeyPair: Sendable {
    public let privateKey: Data
    public let publicKey: Data
    public let curve: Curve

    public init(privateKey: Data, publicKey: Data, curve: Curve) {
        self.privateKey = privateKey
        self.publicKey = publicKey
        self.curve = curve
    }
}

// MARK: - KeyStore Implementation

public actor KeyStore {
    public let curve: Curve
    public private(set) var keyPairs: [KeyPairIdentifier: StoredKeyPair]
    /// Track total memory used
    public private(set) var totalBytesStored: Int = 0

    public init(curve: Curve, capacity: Int = 1000) {
        self.curve = curve
        keyPairs = Dictionary(minimumCapacity: capacity)
        totalBytesStored = 0
    }

    private func recalculateTotalBytesStored() {
        totalBytesStored = keyPairs.count * (curve.publicKeyLength + curve.privateKeyLength)
    }

    public func getPrivateKey(forPublicKey publicKey: Data) -> Data? {
        let identifier = KeyPairIdentifier(publicKey: publicKey)
        return keyPairs[identifier]?.privateKey
    }

    /// Atomically retrieves and removes the private key for `publicKey` in a single
    /// actor-isolated operation (prevents actor-reentrancy races for one-time keys).
    public func popPrivateKey(forPublicKey publicKey: Data) -> Data? {
        let identifier = KeyPairIdentifier(publicKey: publicKey)
        guard let removed = keyPairs.removeValue(forKey: identifier) else {
            return nil
        }
        recalculateTotalBytesStored()
        return removed.privateKey
    }

    public func store(keyPair: StoredKeyPair) {
        let identifier = KeyPairIdentifier(publicKey: keyPair.publicKey)
        keyPairs[identifier] = keyPair
        recalculateTotalBytesStored()
    }

    /// Batch storage optimized for memory
    public func storeBatch(pairs: [(publicKey: Data, privateKey: Data)]) {
        // Pre-allocate for entire batch
        keyPairs.reserveCapacity(keyPairs.count + pairs.count)

        // Store all pairs
        for pair in pairs {
            let stored = StoredKeyPair(publicKey: pair.publicKey, privateKey: pair.privateKey)
            let identifier = KeyPairIdentifier(publicKey: pair.publicKey)
            keyPairs[identifier] = stored
        }

        recalculateTotalBytesStored()
    }

    /// Batch generation method
    public func generateAndStoreKeyPairs(count: Int) async throws {
        guard count > 0 else { return }
        // Capture immutable state before leaving the actor context
        let curveSnapshot = curve

        // Chunk work across available CPU cores rather than spawning `count` individual tasks.
        let workerCount = min(count, max(1, ProcessInfo.processInfo.activeProcessorCount))
        let baseChunk = count / workerCount
        let remainder = count % workerCount

        var tempPairs: [(KeyPairIdentifier, StoredKeyPair)] = []
        tempPairs.reserveCapacity(count)

        try await withThrowingTaskGroup(of: [(KeyPairIdentifier, StoredKeyPair)].self) { group in
            for worker in 0 ..< workerCount {
                let batchSize = baseChunk + (worker < remainder ? 1 : 0)
                group.addTask {
                    var localPairs: [(KeyPairIdentifier, StoredKeyPair)] = []
                    localPairs.reserveCapacity(batchSize)
                    for _ in 0 ..< batchSize {
                        let keyPair = KeyStore.makeKeyPair(curve: curveSnapshot)
                        let identifier = KeyPairIdentifier(publicKey: keyPair.publicKey)
                        localPairs.append((identifier, keyPair))
                    }
                    return localPairs
                }
            }

            for try await batch in group {
                tempPairs.append(contentsOf: batch)
            }
        }

        // Batch insert all key pairs atomically
        keyPairs.reserveCapacity(keyPairs.count + tempPairs.count)

        for (identifier, keyPair) in tempPairs {
            keyPairs[identifier] = keyPair
        }

        recalculateTotalBytesStored()
    }

    /// Generates a new key pair using the store's configured curve.
    /// - Returns: A newly generated `StoredKeyPair`
    public func generateKeyPair() -> StoredKeyPair {
        KeyStore.makeKeyPair(curve: curve)
    }

    /// Static method to generate a key pair outside of the actor context.
    /// This enables true parallelism when generating multiple keys in batch operations.
    /// - Parameter curve: The elliptic curve to use for key generation
    /// - Returns: A newly generated `StoredKeyPair`
    private static func makeKeyPair(curve: Curve) -> StoredKeyPair {
        // Since curve is a stored property, no need for switch
        switch curve {
        case .secp521r1:
            let privateKey = P521.KeyAgreement.PrivateKey()
            return StoredKeyPair(
                publicKey: privateKey.publicKey.compressedRepresentation,
                privateKey: privateKey.rawRepresentation,
            )
        case .secp384r1:
            let privateKey = P384.KeyAgreement.PrivateKey()
            return StoredKeyPair(
                publicKey: privateKey.publicKey.compressedRepresentation,
                privateKey: privateKey.rawRepresentation,
            )
        case .secp256r1:
            let privateKey = P256.KeyAgreement.PrivateKey()
            return StoredKeyPair(
                publicKey: privateKey.publicKey.compressedRepresentation,
                privateKey: privateKey.rawRepresentation,
            )
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

        // Store key pairs directly from contiguous storage (no unzeroed intermediate copies)
        for keyPair in keyPairs.values {
            keyPair.appendSerializedBytes(to: &data)
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
        guard let countInt = Int(exactly: count) else { throw KeyStoreError.invalidKeyData }
        let (pairsBytes, multOverflow) = countInt.multipliedReportingOverflow(by: pairSize)
        guard !multOverflow else { throw KeyStoreError.invalidKeyData }
        let (expectedSize, addOverflow) = pairsBytes.addingReportingOverflow(5)
        guard !addOverflow, data.count == expectedSize else { throw KeyStoreError.invalidKeyData }

        var parsedPairs: [KeyPairIdentifier: StoredKeyPair] = Dictionary(minimumCapacity: countInt)
        var offset = 5

        // Read fixed-size pairs into a fresh dictionary before replacing state
        for _ in 0 ..< countInt {
            let pubKeyStart = data.index(data.startIndex, offsetBy: offset)
            let pubKeyEnd = data.index(pubKeyStart, offsetBy: curve.publicKeyLength)
            let publicKey = data[pubKeyStart ..< pubKeyEnd]

            let privKeyStart = pubKeyEnd
            let privKeyEnd = data.index(privKeyStart, offsetBy: curve.privateKeyLength)
            var privateKey = Data(data[privKeyStart ..< privKeyEnd])
            defer { privateKey.secureZero() }

            let keyPair = StoredKeyPair(
                publicKey: Data(publicKey),
                privateKey: privateKey,
            )

            let identifier = KeyPairIdentifier(publicKey: keyPair.publicKey)
            parsedPairs[identifier] = keyPair

            offset += pairSize
        }

        keyPairs = parsedPairs
        recalculateTotalBytesStored()
    }

    /// Resolves the key pair for a parsed v12 NanoTDF header (whose wire format omits `kasPublicKey`).
    /// Matches by optional `ResourceLocator.identifier` (exact public key, public key prefix, or SHA-256 prefix),
    /// or falls back to the sole stored key when the store contains exactly one key.
    private func resolveV12KeyPair(identifier: Data?) -> (publicKey: Data, privateKey: Data)? {
        if let identifier, !identifier.isEmpty {
            var matches: [StoredKeyPair] = []
            for (keyID, pair) in keyPairs {
                let pub = keyID.publicKey
                if pub == identifier ||
                    (identifier.count <= pub.count && pub.prefix(identifier.count) == identifier) ||
                    Data(SHA256.hash(data: pub)).prefix(identifier.count) == identifier
                {
                    matches.append(pair)
                    if matches.count > 1 {
                        return nil
                    }
                }
            }
            if let unique = matches.first {
                return (unique.publicKey, unique.privateKey)
            }
        }
        if keyPairs.count == 1, let sole = keyPairs.values.first {
            return (sole.publicKey, sole.privateKey)
        }
        return nil
    }

    /// Resolves the stored key pair for a NanoTDF header, handling both explicit KAS public keys
    /// and parsed v12 headers (whose wire format omits `kasPublicKey`).
    func resolveKeyPair(for header: Header, explicitPublicKey: Data? = nil) -> (publicKey: Data, privateKey: Data)? {
        let lookupKey = explicitPublicKey ?? header.payloadKeyAccess.kasPublicKey
        if !lookupKey.isEmpty {
            let identifier = KeyPairIdentifier(publicKey: lookupKey)
            guard let pair = keyPairs[identifier] else {
                return nil
            }
            return (pair.publicKey, pair.privateKey)
        }
        return resolveV12KeyPair(identifier: header.kas.identifier)
    }

    /// Derives the symmetric key for NanoTDF payload decryption using ECDH.
    /// This function assumes the KeyStore holds the KAS's private key.
    ///
    /// - Parameters:
    ///   - header: The NanoTDF header containing the necessary keys for decryption.
    /// - Returns: The derived symmetric key for AES-256-GCM as SymmetricKey.
    /// - Throws: KeyStoreError or other errors if key derivation fails.
    public nonisolated func derivePayloadSymmetricKey(header: Header) async throws -> SymmetricKey {
        let kasPublicKey = header.payloadKeyAccess.kasPublicKey
        let tdfEphemeralPublicKey = header.ephemeralPublicKey

        if !kasPublicKey.isEmpty {
            return try await derivePayloadSymmetricKey(kasPublicKey: kasPublicKey, tdfEphemeralPublicKey: tdfEphemeralPublicKey)
        }

        // v12 NanoTDF headers omit the KAS public key on the wire; resolve via identifier or sole key.
        guard let resolved = await resolveV12KeyPair(identifier: header.kas.identifier) else {
            throw KeyStoreError.keyNotFound("Private key for v12 NanoTDF header not found in this KeyStore.")
        }
        var kasPrivateKeyData = resolved.privateKey
        defer { kasPrivateKeyData.secureZero() }
        return try derivePayloadSymmetricKey(
            kasPrivateKeyData: kasPrivateKeyData,
            tdfEphemeralPublicKey: tdfEphemeralPublicKey,
        )
    }

    /// Derives the symmetric key for NanoTDF payload decryption using ECDH.
    /// This function assumes the KeyStore holds the KAS's private key.
    ///
    /// - Parameters:
    ///   - kasPublicKey: The public key of the KAS, used to retrieve its private key from this KeyStore.
    ///                   This corresponds to `header.payloadKeyAccess.kasPublicKey`.
    ///   - tdfEphemeralPublicKey: The ephemeral public key from the NanoTDF Header's main ephemeral key field.
    ///                            This corresponds to `header.ephemeralPublicKey`.
    /// - Returns: The derived symmetric key for AES-256-GCM as SymmetricKey.
    /// - Throws: KeyStoreError or other errors if key derivation fails.
    public nonisolated func derivePayloadSymmetricKey(
        kasPublicKey: Data,
        tdfEphemeralPublicKey: Data,
    ) async throws -> SymmetricKey {
        // 1. Get the KAS's private key from this KeyStore (the only actor-isolated step;
        //    the ECDH and HKDF below run on the caller's executor so concurrent
        //    decrypts are not serialized through the store).
        guard var kasPrivateKeyData = await getPrivateKey(forPublicKey: kasPublicKey) else {
            throw KeyStoreError.keyNotFound("Private key for KAS Public Key \(kasPublicKey.hexString) not found in this KeyStore.")
        }
        defer { kasPrivateKeyData.secureZero() }

        return try derivePayloadSymmetricKey(
            kasPrivateKeyData: kasPrivateKeyData,
            tdfEphemeralPublicKey: tdfEphemeralPublicKey,
        )
    }

    nonisolated func derivePayloadSymmetricKey(
        kasPrivateKeyData: Data,
        tdfEphemeralPublicKey: Data,
    ) throws -> SymmetricKey {
        // 2. Perform Elliptic Curve Diffie-Hellman (ECDH) Key Agreement
        let sharedSecret: SharedSecret
        do {
            switch curve {
            case .secp256r1:
                let kasPrivKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: kasPrivateKeyData)
                let clientPubKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: tdfEphemeralPublicKey)
                sharedSecret = try kasPrivKey.sharedSecretFromKeyAgreement(with: clientPubKey)
            case .secp384r1:
                let kasPrivKey = try P384.KeyAgreement.PrivateKey(rawRepresentation: kasPrivateKeyData)
                let clientPubKey = try P384.KeyAgreement.PublicKey(compressedRepresentation: tdfEphemeralPublicKey)
                sharedSecret = try kasPrivKey.sharedSecretFromKeyAgreement(with: clientPubKey)
            case .secp521r1:
                let kasPrivKey = try P521.KeyAgreement.PrivateKey(rawRepresentation: kasPrivateKeyData)
                let clientPubKey = try P521.KeyAgreement.PublicKey(compressedRepresentation: tdfEphemeralPublicKey)
                sharedSecret = try kasPrivKey.sharedSecretFromKeyAgreement(with: clientPubKey)
            }
        } catch {
            throw KeyStoreError.keyAgreementFailed("ECDH key agreement failed: \(error.localizedDescription)")
        }

        // 3. Derive the symmetric key using HKDF
        //    Salt: SHA256("L1" + VERSION) - use v12 for NanoTDF collection compatibility
        //    Info: empty per spec guidance
        //    Output Byte Count: 32 (for AES-256)
        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: CryptoConstants.hkdfSaltV12,
            sharedInfo: CryptoConstants.hkdfInfoEncryption,
            outputByteCount: CryptoConstants.symmetricKeyByteCount,
        )
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
        recalculateTotalBytesStored()
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

/// Helper extension for testing
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

    /// Equatable conformance
    public static func == (lhs: KeyStoreError, rhs: KeyStoreError) -> Bool {
        switch (lhs, rhs) {
        case (.unsupportedCurve, .unsupportedCurve):
            true
        case (.invalidKeyData, .invalidKeyData):
            true
        case let (.keyNotFound(lhsMsg), .keyNotFound(rhsMsg)):
            lhsMsg == rhsMsg
        case (.invalidKeyFormat, .invalidKeyFormat):
            true
        case (.encryptionFailed, .encryptionFailed):
            true
        case (.keyGenerationFailed, .keyGenerationFailed):
            true
        case (.signingFailed, .signingFailed):
            true
        case (.decryptionFailed, .decryptionFailed):
            true
        case (.unknownError, .unknownError):
            true
        case let (.keyAgreementFailed(lhsMsg), .keyAgreementFailed(rhsMsg)):
            lhsMsg == rhsMsg
        case let (.keyDerivationFailed(lhsMsg), .keyDerivationFailed(rhsMsg)):
            lhsMsg == rhsMsg
        default:
            false
        }
    }
}

/// Helper extension for Data to hex string (for debugging/errors)
public extension Data {
    var hexString: String {
        let hexDigits: [UInt8] = [
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        ]
        var utf8 = [UInt8]()
        utf8.reserveCapacity(count * 2)
        for byte in self {
            utf8.append(hexDigits[Int(byte >> 4)])
            utf8.append(hexDigits[Int(byte & 0x0F)])
        }
        return String(decoding: utf8, as: UTF8.self)
    }
}

/// Helper extension
extension Curve {
    var publicKeyLength: Int {
        switch self {
        case .secp256r1: 33 // compressed format
        case .secp384r1: 49
        case .secp521r1: 67
        }
    }

    var privateKeyLength: Int {
        switch self {
        case .secp256r1: 32
        case .secp384r1: 48
        case .secp521r1: 66
        }
    }
}
