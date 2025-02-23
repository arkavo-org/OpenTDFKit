import XCTest
@preconcurrency import CryptoKit
@testable import OpenTDFKit

final class KeyStoreTests: XCTestCase {
    
    func testGenerateAndStoreSingleKey() async throws {
        let keyStore = KeyStore()
        let keyPair = await keyStore.generateKeyPair(curve: .secp256r1)
        await keyStore.store(keyPair: keyPair)
        
        // Test direct lookup
        let foundPrivateKey = await keyStore.getPrivateKey(forPublicKey: keyPair.publicKey)
        XCTAssertNotNil(foundPrivateKey)
        XCTAssertEqual(foundPrivateKey, keyPair.privateKey)
        
        // Test cached lookup
        let cachedPrivateKey = await keyStore.getPrivateKey(forPublicKey: keyPair.publicKey)
        XCTAssertNotNil(cachedPrivateKey)
        XCTAssertEqual(cachedPrivateKey, keyPair.privateKey)
    }
    
    func testSerializationAndDeserialization() async throws {
        let keyStore = KeyStore()
        
        // Generate multiple test key pairs with different curves
        let testPairs = [
            await keyStore.generateKeyPair(curve: .secp256r1),
            await keyStore.generateKeyPair(curve: .secp384r1),
            await keyStore.generateKeyPair(curve: .secp521r1)
        ]
        
        // Store and print key sizes for verification
        for (index, pair) in testPairs.enumerated() {
            await keyStore.store(keyPair: pair)
            print("Test pair \(index) - pub key size: \(pair.publicKey.count), priv key size: \(pair.privateKey.count)")
        }
        
        // Serialize all keys
        let serializedData = await keyStore.serialize()
        print("Total serialized size: \(serializedData.count) bytes")
        
        // Create new store and deserialize
        let restoredStore = KeyStore()
        try await restoredStore.deserialize(from: serializedData)
        
        // Verify all keys were restored correctly
        for pair in testPairs {
            let retrievedKey = await restoredStore.getPrivateKey(forPublicKey: pair.publicKey)
            XCTAssertNotNil(retrievedKey, "Failed to retrieve key after deserialization")
            XCTAssertEqual(retrievedKey, pair.privateKey, "Retrieved key doesn't match original")
            
            // Verify cache is working after deserialization
            let cachedKey = await restoredStore.getPrivateKey(forPublicKey: pair.publicKey)
            XCTAssertEqual(cachedKey, pair.privateKey, "Cache lookup failed after deserialization")
        }
    }
    
    func testKeyExchangeImplementation() async throws {
        let keyStore = KeyStore()
        
        // Test key exchange with different curves
        let curves: [Curve] = [.secp256r1, .secp384r1, .secp521r1]
        
        for curve in curves {
            print("Testing key exchange with curve: \(curve)")
            
            let recipientKeyPair = await keyStore.generateKeyPair(curve: curve)
            XCTAssertFalse(recipientKeyPair.publicKey.isEmpty)
            XCTAssertFalse(recipientKeyPair.privateKey.isEmpty)
            
            let (sharedSecret, ephemeralPublicKey) = try await keyStore.performKeyExchange(
                publicKey: recipientKeyPair.publicKey,
                curve: curve
            )
            
            XCTAssertNotNil(sharedSecret)
            XCTAssertFalse(ephemeralPublicKey.isEmpty)
            
            // Test key derivation and encryption
            let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data("test-salt".utf8),
                sharedInfo: Data("test-info".utf8),
                outputByteCount: 32
            )
            
            let testMessage = "Test message for curve \(curve)".data(using: .utf8)!
            let nonce = try AES.GCM.Nonce()
            let sealedBox = try AES.GCM.seal(testMessage, using: symmetricKey, nonce: nonce)
            let decryptedMessage = try AES.GCM.open(sealedBox, using: symmetricKey)
            
            XCTAssertEqual(testMessage, decryptedMessage)
        }
    }
    
    func testInvalidDeserialization() async {
        let keyStore = KeyStore()
        
        // Test empty data
        do {
            try await keyStore.deserialize(from: Data())
            XCTFail("Should fail with empty data")
        } catch let error {
            if case KeyStoreError.invalidKeyData = error {
                // Expected error
            } else {
                XCTFail("Unexpected error: \(error)")
            }
        }
        
        // Test truncated data
        let invalidData = Data([0x00, 0x01, 0x02])
        do {
            try await keyStore.deserialize(from: invalidData)
            XCTFail("Should fail with truncated data")
        } catch let error {
            if case KeyStoreError.invalidKeyData = error {
                // Expected error
            } else {
                XCTFail("Unexpected error: \(error)")
            }
        }
        
        // Test invalid count
        var data = Data()
        let invalidCount: UInt32 = UInt32.max
        withUnsafeBytes(of: invalidCount.bigEndian) { data.append(contentsOf: $0) }
        do {
            try await keyStore.deserialize(from: data)
            XCTFail("Should fail with invalid count")
        } catch let error {
            if case KeyStoreError.invalidKeyData = error {
                // Expected error
            } else {
                XCTFail("Unexpected error: \(error)")
            }
        }
    }
    
    func testCacheEffectiveness() async throws {
        let keyStore = KeyStore()
        let keyPair = await keyStore.generateKeyPair(curve: .secp256r1)
        await keyStore.store(keyPair: keyPair)
        
        // First lookup (uncached)
        let startTime1 = DispatchTime.now()
        let _ = await keyStore.getPrivateKey(forPublicKey: keyPair.publicKey)
        let endTime1 = DispatchTime.now()
        let uncachedTime = Double(endTime1.uptimeNanoseconds - startTime1.uptimeNanoseconds) / 1_000_000 // ms
        
        // Second lookup (should be cached)
        let startTime2 = DispatchTime.now()
        let _ = await keyStore.getPrivateKey(forPublicKey: keyPair.publicKey)
        let endTime2 = DispatchTime.now()
        let cachedTime = Double(endTime2.uptimeNanoseconds - startTime2.uptimeNanoseconds) / 1_000_000 // ms
        
        print("Uncached lookup time: \(uncachedTime) ms")
        print("Cached lookup time: \(cachedTime) ms")
        
        // Cached lookup should be faster
        XCTAssertLessThan(cachedTime, uncachedTime, "Cached lookup should be faster than uncached")
    }
}
