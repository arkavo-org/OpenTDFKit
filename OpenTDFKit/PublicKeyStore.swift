import CryptoKit
import Foundation

/// A store containing only public keys to be shared with peers
@preconcurrency public final class PublicKeyStore: Sendable {
    private let curve: Curve
    private actor InternalStore {
        var keys: [Data] = []

        func addKey(_ key: Data) {
            keys.append(key)
        }

        func addKeys(_ newKeys: [Data]) {
            keys.append(contentsOf: newKeys)
        }

        func getAndRemoveKey() throws -> Data {
            guard !keys.isEmpty else {
                throw PublicKeyStoreError.noKeysAvailable
            }
            return keys.removeFirst()
        }

        func getKeys() -> [Data] {
            keys
        }

        func clear() {
            keys.removeAll()
        }
    }

    private let store = InternalStore()

    /// Initialize a PublicKeyStore with a specific curve
    /// - Parameter curve: The elliptic curve to use for the keys
    public init(curve: Curve) {
        self.curve = curve
    }

    /// The collection of public keys in this store
    public var publicKeys: [Data] {
        get async {
            await store.getKeys()
        }
    }

    /// Add a public key to the store
    /// - Parameter key: The public key to add
    public func addPublicKey(_ key: Data) async {
        await store.addKey(key)
    }

    /// Add multiple public keys to the store
    /// - Parameter keys: The public keys to add
    public func addPublicKeys(_ keys: [Data]) async {
        await store.addKeys(keys)
    }

    /// Deserialize a PublicKeyStore from binary data
    /// - Parameter data: The serialized PublicKeyStore data
    /// - Throws: Deserialization errors
    public func deserialize(from data: Data) async throws {
        guard data.count >= 5 else { throw PublicKeyStoreError.invalidData }

        // Read curve
        let curveValue = data[data.startIndex]
        guard let storedCurve = Curve(rawValue: curveValue),
              storedCurve == curve
        else {
            throw PublicKeyStoreError.curveTypeMismatch
        }

        // Read count
        let countBytes = [UInt8](data[data.index(data.startIndex, offsetBy: 1) ... data.index(data.startIndex, offsetBy: 4)])
        let count = UInt32(countBytes[0]) << 24 | UInt32(countBytes[1]) << 16 | UInt32(countBytes[2]) << 8 | UInt32(countBytes[3])

        let keySize = curve.publicKeyLength
        let expectedSize = 5 + (Int(count) * keySize)
        guard data.count == expectedSize else { throw PublicKeyStoreError.invalidData }

        // Clear existing keys
        await store.clear()

        var keys = [Data]()
        keys.reserveCapacity(Int(count))

        var offset = 5
        // Read each public key
        for _ in 0 ..< count {
            let keyStart = data.index(data.startIndex, offsetBy: offset)
            let keyEnd = data.index(keyStart, offsetBy: keySize)
            let publicKey = data[keyStart ..< keyEnd]

            keys.append(Data(publicKey))
            offset += keySize
        }

        await store.addKeys(keys)
    }

    /// Serialize this PublicKeyStore to binary data
    /// - Returns: The serialized data
    public func serialize() async -> Data {
        let keys = await store.getKeys()
        let estimatedSize = keys.count * curve.publicKeyLength + 5
        var data = Data(capacity: estimatedSize)

        // Store curve type
        data.append(curve.rawValue)

        // Store count
        let count = UInt32(keys.count)
        withUnsafeBytes(of: count.bigEndian) { data.append(contentsOf: $0) }

        // Store public keys
        for publicKey in keys {
            data.append(publicKey)
        }

        return data
    }

    /// Get and remove a public key from the store
    /// - Returns: A public key, removing it from the store
    /// - Throws: Error if no keys are available
    public func getAndRemovePublicKey() async throws -> Data {
        try await store.getAndRemoveKey()
    }

    /// Create KAS metadata using one of the public keys
    /// - Parameter resourceLocator: The resource locator for the KAS
    /// - Returns: Key access metadata for TDF creation
    /// - Throws: Error if no keys are available
    public func createKasMetadata(resourceLocator: ResourceLocator) async throws -> KasMetadata {
        let publicKeyData = try await getAndRemovePublicKey()

        switch curve {
        case .secp256r1:
            let publicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: publicKeyData)
            return try KasMetadata(resourceLocator: resourceLocator, publicKey: publicKey, curve: .secp256r1)
        case .secp384r1:
            let publicKey = try P384.KeyAgreement.PublicKey(compressedRepresentation: publicKeyData)
            return try KasMetadata(resourceLocator: resourceLocator, publicKey: publicKey, curve: .secp384r1)
        case .secp521r1:
            let publicKey = try P521.KeyAgreement.PublicKey(compressedRepresentation: publicKeyData)
            return try KasMetadata(resourceLocator: resourceLocator, publicKey: publicKey, curve: .secp521r1)
        case .xsecp256k1:
            throw PublicKeyStoreError.unsupportedCurve
        }
    }
}

/// Errors specific to PublicKeyStore operations
public enum PublicKeyStoreError: Error {
    case noKeysAvailable
    case invalidData
    case curveTypeMismatch
    case unsupportedCurve
}
