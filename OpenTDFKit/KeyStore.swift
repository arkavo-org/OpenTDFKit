import Foundation
import CryptoKit

// MARK: - Key Types and Storage

public struct KeyPairIdentifier: Hashable, Sendable {
    let publicKeyHash: String
    
    init(publicKey: Data) {
        self.publicKeyHash = SHA256.hash(data: publicKey).compactMap { String(format: "%02x", $0) }.joined()
    }
}

public struct StoredKeyPair: Sendable {
    let publicKey: Data
    let privateKey: Data
    let curve: Curve
    
    init(publicKey: Data, privateKey: Data, curve: Curve) {
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.curve = curve
    }
    
    // Binary format:
    // [curve: UInt8][pubKeyLength: UInt16][privKeyLength: UInt16][pubKey: Data][privKey: Data]
    func serialize() -> Data {
        var data = Data()
        data.append(curve.rawValue)
        
        let pubKeyLength = UInt16(publicKey.count)
        withUnsafeBytes(of: pubKeyLength.bigEndian) { data.append(contentsOf: $0) }
        
        let privKeyLength = UInt16(privateKey.count)
        withUnsafeBytes(of: privKeyLength.bigEndian) { data.append(contentsOf: $0) }
        
        data.append(publicKey)
        data.append(privateKey)
        
        return data
    }
    
    static func deserialize(from data: Data) throws -> StoredKeyPair {
        guard data.count >= 5 else { throw KeyStoreError.invalidKeyData } // Minimum size: curve + 2 lengths
        
        // Read curve
        let curveValue = data[data.startIndex]
        guard let curve = Curve(rawValue: curveValue) else { throw KeyStoreError.invalidKeyData }
        
        // Read public key length
        let pubKeyLengthBytes = [UInt8](data[data.index(data.startIndex, offsetBy: 1)...data.index(data.startIndex, offsetBy: 2)])
        let pubKeyLength = UInt16(pubKeyLengthBytes[0]) << 8 | UInt16(pubKeyLengthBytes[1])
        
        // Read private key length
        let privKeyLengthBytes = [UInt8](data[data.index(data.startIndex, offsetBy: 3)...data.index(data.startIndex, offsetBy: 4)])
        let privKeyLength = UInt16(privKeyLengthBytes[0]) << 8 | UInt16(privKeyLengthBytes[1])
        
        // Verify total length
        let expectedLength = 5 + Int(pubKeyLength) + Int(privKeyLength)
        guard data.count >= expectedLength else { throw KeyStoreError.invalidKeyData }
        
        // Extract keys
        let pubKeyStart = data.index(data.startIndex, offsetBy: 5)
        let pubKeyEnd = data.index(pubKeyStart, offsetBy: Int(pubKeyLength))
        let publicKey = data[pubKeyStart..<pubKeyEnd]
        
        let privKeyStart = pubKeyEnd
        let privKeyEnd = data.index(privKeyStart, offsetBy: Int(privKeyLength))
        let privateKey = data[privKeyStart..<privKeyEnd]
        
        return StoredKeyPair(
            publicKey: Data(publicKey),
            privateKey: Data(privateKey),
            curve: curve
        )
    }
}

// MARK: - KeyStore Implementation

public actor KeyStore {
    // Use a more efficient storage structure with pre-allocated capacity
    var keyPairs: [KeyPairIdentifier: StoredKeyPair]
    private let cache: NSCache<NSData, NSData>
    
    public init(capacity: Int = 1000) {
        self.keyPairs = Dictionary(minimumCapacity: capacity)
        self.cache = NSCache<NSData, NSData>()
        self.cache.countLimit = 1000
    }
    
    // Store a single key pair
    public func store(keyPair: StoredKeyPair) {
        let identifier = KeyPairIdentifier(publicKey: keyPair.publicKey)
        keyPairs[identifier] = keyPair
        cache.setObject(keyPair.privateKey as NSData, forKey: keyPair.publicKey as NSData)
    }
    
    // Batch generation method for better performance
    public func generateAndStoreKeyPairs(count: Int, curve: Curve) async throws {
        var tempPairs: [(KeyPairIdentifier, StoredKeyPair)] = []
        tempPairs.reserveCapacity(count)
        
        try await withThrowingTaskGroup(of: StoredKeyPair.self) { group in
            for _ in 0..<count {
                group.addTask { [curve] in
                    return await self.generateKeyPair(curve: curve)
                }
            }
            
            for try await keyPair in group {
                let identifier = KeyPairIdentifier(publicKey: keyPair.publicKey)
                tempPairs.append((identifier, keyPair))
            }
        }
        
        for (identifier, keyPair) in tempPairs {
            keyPairs[identifier] = keyPair
            cache.setObject(keyPair.privateKey as NSData, forKey: keyPair.publicKey as NSData)
        }
    }
    
    public func getPrivateKey(forPublicKey publicKey: Data) -> Data? {
        if let cachedPrivateKey = cache.object(forKey: publicKey as NSData) {
            return cachedPrivateKey as Data
        }
        
        let identifier = KeyPairIdentifier(publicKey: publicKey)
        guard let privateKey = keyPairs[identifier]?.privateKey else {
            return nil
        }
        
        cache.setObject(privateKey as NSData, forKey: publicKey as NSData)
        return privateKey
    }
    
    public func generateKeyPair(curve: Curve) -> StoredKeyPair {
        switch curve {
        case .secp521r1:
            let privateKey = P521.KeyAgreement.PrivateKey()
            return StoredKeyPair(
                publicKey: privateKey.publicKey.compressedRepresentation,
                privateKey: privateKey.rawRepresentation,
                curve: curve
            )
        case .secp384r1:
            let privateKey = P384.KeyAgreement.PrivateKey()
            return StoredKeyPair(
                publicKey: privateKey.publicKey.compressedRepresentation,
                privateKey: privateKey.rawRepresentation,
                curve: curve
            )
        case .secp256r1:
            let privateKey = P256.KeyAgreement.PrivateKey()
            return StoredKeyPair(
                publicKey: privateKey.publicKey.compressedRepresentation,
                privateKey: privateKey.rawRepresentation,
                curve: curve
            )
        case .xsecp256k1:
            fatalError("Unsupported curve")
        }
    }
    
    public func serialize() -> Data {
        let estimatedSize = keyPairs.count * 256
        var data = Data(capacity: estimatedSize)
        
        let count = UInt32(keyPairs.count)
        withUnsafeBytes(of: count.bigEndian) { data.append(contentsOf: $0) }
        
        for keyPair in keyPairs.values {
            data.append(keyPair.serialize())
        }
        
        return data
    }
    
    public func deserialize(from data: Data) throws {
        guard data.count >= 4 else { throw KeyStoreError.invalidKeyData }
        
        // Read count
        let countBytes = [UInt8](data.prefix(4))
        let count = UInt32(countBytes[0]) << 24 | UInt32(countBytes[1]) << 16 | UInt32(countBytes[2]) << 8 | UInt32(countBytes[3])
        
        var offset = 4
        var newKeyPairs: [KeyPairIdentifier: StoredKeyPair] = [:]
        
        for _ in 0..<count {
            let remainingData = data[data.index(data.startIndex, offsetBy: offset)...]
            let keyPair = try StoredKeyPair.deserialize(from: remainingData)
            let identifier = KeyPairIdentifier(publicKey: keyPair.publicKey)
            newKeyPairs[identifier] = keyPair
            
            // Move offset past this key pair
            offset += keyPair.serialize().count
            guard offset <= data.count else { throw KeyStoreError.invalidKeyData }
        }
        
        // Update storage and cache
        keyPairs = newKeyPairs
        cache.removeAllObjects() // Clear cache after deserialization
        
        // Populate cache with new key pairs
        for keyPair in newKeyPairs.values {
            cache.setObject(keyPair.privateKey as NSData, forKey: keyPair.publicKey as NSData)
        }
    }
    
    // Key exchange functionality
    public func performKeyExchange(publicKey: Data, curve: Curve) throws -> (sharedSecret: SharedSecret, ephemeralPublicKey: Data) {
        let ephemeralKeyPair = generateKeyPair(curve: curve)
        
        switch curve {
        case .secp521r1:
            let recipientKey = try P521.KeyAgreement.PublicKey(compressedRepresentation: publicKey)
            let privateKey = try P521.KeyAgreement.PrivateKey(rawRepresentation: ephemeralKeyPair.privateKey)
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: recipientKey)
            return (sharedSecret, ephemeralKeyPair.publicKey)
            
        case .secp384r1:
            let recipientKey = try P384.KeyAgreement.PublicKey(compressedRepresentation: publicKey)
            let privateKey = try P384.KeyAgreement.PrivateKey(rawRepresentation: ephemeralKeyPair.privateKey)
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: recipientKey)
            return (sharedSecret, ephemeralKeyPair.publicKey)
            
        case .secp256r1:
            let recipientKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: publicKey)
            let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: ephemeralKeyPair.privateKey)
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: recipientKey)
            return (sharedSecret, ephemeralKeyPair.publicKey)
            
        case .xsecp256k1:
            throw KeyStoreError.unsupportedCurve
        }
    }
}

public enum KeyStoreError: Error {
    case unsupportedCurve
    case invalidKeyData
    case keyNotFound
}
