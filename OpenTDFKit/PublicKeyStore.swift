import CryptoKit
import Foundation

/// A store containing only public keys to be shared with peers
public final class PublicKeyStore: Sendable {
    public let curve: Curve
    private actor InternalStore {
        private var keys: [Data] = []
        private var head: Int = 0

        func addKey(_ key: Data) {
            keys.append(key)
        }

        func addKeys(_ newKeys: [Data]) {
            keys.append(contentsOf: newKeys)
        }

        func getAndRemoveKey() throws -> Data {
            guard head < keys.count else {
                throw PublicKeyStoreError.noKeysAvailable
            }
            let key = keys[head]
            head += 1
            // Amortized O(1) FIFO pop: compact only when at least half the buffer is consumed.
            if head >= keys.count {
                keys.removeAll(keepingCapacity: true)
                head = 0
            } else if head >= 64, head * 2 >= keys.count {
                keys.removeFirst(head)
                head = 0
            }
            return key
        }

        func getKeys() -> [Data] {
            head == 0 ? keys : Array(keys[head...])
        }

        func clear() {
            keys.removeAll()
            head = 0
        }

        func replaceAll(_ newKeys: [Data]) {
            keys = newKeys
            head = 0
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
        guard let countInt = Int(exactly: count) else { throw PublicKeyStoreError.invalidData }
        let (keysBytes, multOverflow) = countInt.multipliedReportingOverflow(by: keySize)
        guard !multOverflow else { throw PublicKeyStoreError.invalidData }
        let (expectedSize, addOverflow) = keysBytes.addingReportingOverflow(5)
        guard !addOverflow, data.count == expectedSize else { throw PublicKeyStoreError.invalidData }

        var keys = [Data]()
        keys.reserveCapacity(countInt)

        var offset = 5
        // Parse all keys locally before atomically replacing the store
        for _ in 0 ..< countInt {
            let keyStart = data.index(data.startIndex, offsetBy: offset)
            let keyEnd = data.index(keyStart, offsetBy: keySize)
            let publicKey = data[keyStart ..< keyEnd]

            keys.append(Data(publicKey))
            offset += keySize
        }

        await store.replaceAll(keys)
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

/// For testing purposes only
extension PublicKeyStore {
    var keys: [Data] {
        get async {
            await store.getKeys()
        }
    }
}
