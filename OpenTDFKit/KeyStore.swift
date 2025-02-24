import CryptoKit
import Foundation

// MARK: - Key Types and Storage

public struct KeyPairIdentifier: Hashable, Sendable {
    // Store the public key bytes directly - already fixed size per curve
    private let bytes: Data

    init(publicKey: Data) {
        bytes = publicKey
    }
}

public struct StoredKeyPair: Sendable {
    // Store all bytes contiguously
    private let bytes: ContiguousArray<UInt8>
    private let publicKeyLength: Int

    var publicKey: Data {
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
    let curve: Curve
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
            fatalError("Unsupported curve")
        }
    }

    public func serialize() -> Data {
        let estimatedSize = keyPairs.count * (curve.publicKeyLength + curve.privateKeyLength) + 5
        var data = Data(capacity: estimatedSize)

        // Store curve type
        data.append(curve.rawValue)

        // Store count
        let count = UInt32(keyPairs.count)
        withUnsafeBytes(of: count.bigEndian) { data.append(contentsOf: $0) }

        // Store key pairs - no need for length prefixes since sizes are fixed per curve
        for keyPair in keyPairs.values {
            data.append(keyPair.publicKey)
            data.append(keyPair.privateKey)
        }

        return data
    }

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
}

public enum KeyStoreError: Error {
    case unsupportedCurve
    case invalidKeyData
    case keyNotFound
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
