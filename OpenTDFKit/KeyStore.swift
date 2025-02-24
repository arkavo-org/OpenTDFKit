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
    
    init(publicKey: Data, privateKey: Data) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }
}

// MARK: - KeyStore Implementation

public actor KeyStore {
    let curve: Curve
    var keyPairs: [KeyPairIdentifier: StoredKeyPair]
    // Just track public keys for fast existence checks
    private var publicKeySet: Set<KeyPairIdentifier>
    
    public init(curve: Curve, capacity: Int = 1000) {
        self.curve = curve
        self.keyPairs = Dictionary(minimumCapacity: capacity)
        self.publicKeySet = Set(minimumCapacity: capacity)
    }
    
    // Fast path - just checks existence
    public func hasKey(publicKey: Data) -> Bool {
        let identifier = KeyPairIdentifier(publicKey: publicKey)
        return publicKeySet.contains(identifier)
    }
    
    // Called only when needed for key exchange
    public func getPrivateKey(forPublicKey publicKey: Data) -> Data? {
        let identifier = KeyPairIdentifier(publicKey: publicKey)
        return keyPairs[identifier]?.privateKey
    }
    
    public func store(keyPair: StoredKeyPair) {
        let identifier = KeyPairIdentifier(publicKey: keyPair.publicKey)
        keyPairs[identifier] = keyPair
        publicKeySet.insert(identifier)
    }
    
    // Batch generation method
    public func generateAndStoreKeyPairs(count: Int) async throws {
        // Pre-allocate space
        var tempPairs: [(KeyPairIdentifier, StoredKeyPair)] = []
        tempPairs.reserveCapacity(count)
        
        try await withThrowingTaskGroup(of: StoredKeyPair.self) { group in
            for _ in 0..<count {
                group.addTask {
                    return await self.generateKeyPair()
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
            publicKeySet.insert(identifier)
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
        let countBytes = [UInt8](data[data.index(data.startIndex, offsetBy: 1)...data.index(data.startIndex, offsetBy: 4)])
        let count = UInt32(countBytes[0]) << 24 | UInt32(countBytes[1]) << 16 | UInt32(countBytes[2]) << 8 | UInt32(countBytes[3])
        
        let pairSize = curve.publicKeyLength + curve.privateKeyLength
        let expectedSize = 5 + (Int(count) * pairSize)
        guard data.count == expectedSize else { throw KeyStoreError.invalidKeyData }
        
        // Clear existing data
        keyPairs.removeAll(keepingCapacity: true)
        publicKeySet.removeAll(keepingCapacity: true)
        
        var offset = 5
        
        // Pre-allocate capacity
        keyPairs.reserveCapacity(Int(count))
        publicKeySet.reserveCapacity(Int(count))
        
        // Read fixed-size pairs
        for _ in 0..<count {
            let pubKeyStart = data.index(data.startIndex, offsetBy: offset)
            let pubKeyEnd = data.index(pubKeyStart, offsetBy: curve.publicKeyLength)
            let publicKey = data[pubKeyStart..<pubKeyEnd]
            
            let privKeyStart = pubKeyEnd
            let privKeyEnd = data.index(privKeyStart, offsetBy: curve.privateKeyLength)
            let privateKey = data[privKeyStart..<privKeyEnd]
            
            let keyPair = StoredKeyPair(
                publicKey: Data(publicKey),
                privateKey: Data(privateKey)
            )
            
            let identifier = KeyPairIdentifier(publicKey: keyPair.publicKey)
            keyPairs[identifier] = keyPair
            publicKeySet.insert(identifier)
            
            offset += pairSize
        }
    }
    
    // Key exchange functionality
    public func performKeyExchange(publicKey: Data) throws -> (sharedSecret: SharedSecret, ephemeralPublicKey: Data) {
        let ephemeralKeyPair = generateKeyPair()
        
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

// Helper extension
extension Curve {
    var publicKeyLength: Int {
        switch self {
        case .secp256r1: return 33  // compressed format
        case .secp384r1: return 49
        case .secp521r1: return 67
        case .xsecp256k1: return 33
        }
    }
    
    var privateKeyLength: Int {
        switch self {
        case .secp256r1: return 32
        case .secp384r1: return 48
        case .secp521r1: return 66
        case .xsecp256k1: return 32
        }
    }
}
