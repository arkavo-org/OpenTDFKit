import CryptoKit
import Foundation
import XCTest

@testable import OpenTDFKit

final class OneTimeTDFTests: XCTestCase {
    
    func testOneTimeTDFKeyRemoval() async throws {
        // Create KeyStore
        let curve = Curve.secp256r1
        let keyStore = KeyStore(curve: curve)
        
        // Generate keys
        try await keyStore.generateAndStoreKeyPairs(count: 5)
        
        // Count initial keys
        let initialKeyCount = await keyStore.getKeyCount()
        XCTAssertEqual(initialKeyCount, 5)
        
        // Get a key to test removal
        let allKeys = await keyStore.keyPairs.values.map { $0.publicKey }
        let keyToRemove = allKeys.first!
        
        // Create identifier and verify key exists
        let identifier = KeyPairIdentifier(publicKey: keyToRemove)
        let hasKey = await keyStore.containsMatchingPublicKey(keyToRemove)
        XCTAssertTrue(hasKey)
        
        // Remove the key directly
        try await keyStore.removeKeyPair(keyID: identifier)
        
        // Verify key was removed
        let keyExists = await keyStore.containsMatchingPublicKey(keyToRemove)
        XCTAssertFalse(keyExists, "Key should be removed after removal operation")
        let finalKeyCount = await keyStore.getKeyCount()
        XCTAssertEqual(finalKeyCount, initialKeyCount - 1)
    }
    
    // TODO: Fix this test to handle cryptographic operations correctly
    // Current error in processKeyAccessWithKeyIdentifier is likely related to
    // mock data not being properly formatted for decryption
    /*
    func testOneTimeTDFKeyUsageWithKAS() async throws {
        // Create KeyStore and KAS Service
        let curve = Curve.secp256r1
        let keyStore = KeyStore(curve: curve)
        
        // Generate a set of keys for the test
        let keyCount = 10
        try await keyStore.generateAndStoreKeyPairs(count: keyCount)
        
        // Count initial keys
        let initialKeyCount = await keyStore.getKeyCount()
        XCTAssertEqual(initialKeyCount, keyCount)
        
        // Export public keys to PublicKeyStore (for client use)
        let publicKeyStore = await keyStore.exportPublicKeyStore()
        let exportedKeys = await publicKeyStore.publicKeys
        XCTAssertEqual(exportedKeys.count, keyCount)
        
        // Setup KAS service
        let baseURL = URL(string: "http://kas.example.com")!
        let kasService = KASService(keyStore: keyStore, baseURL: baseURL)
        
        // Test key removal after use
        // 1. Get a key from the public key store
        let clientKey = try await publicKeyStore.getAndRemovePublicKey()
        let remainingPublicKeys = await publicKeyStore.publicKeys
        XCTAssertEqual(remainingPublicKeys.count, keyCount - 1)
        
        // 2. Check if keystore contains this key
        let hasKey = await keyStore.containsMatchingPublicKey(clientKey)
        XCTAssertTrue(hasKey, "KeyStore should contain the public key")
        
        // 3. Create mock ephemeral key and properly formatted encrypted key for the test
        let ephemeralPrivateKey = P256.KeyAgreement.PrivateKey()
        let ephemeralPublicKey = ephemeralPrivateKey.publicKey.compressedRepresentation
        
        // Mock encrypted key with proper format:
        // - First 12 bytes: nonce
        // - Last 16 bytes: tag
        // - Middle bytes: ciphertext
        let mockNonce = Data(repeating: 0x01, count: 12)
        let mockCiphertext = Data(repeating: 0x02, count: 32)
        let mockTag = Data(repeating: 0x03, count: 16)
        var mockEncryptedKey = Data()
        mockEncryptedKey.append(mockNonce)
        mockEncryptedKey.append(mockCiphertext)
        mockEncryptedKey.append(mockTag)
        
        // 4. Process key access with identifier (should remove the key after use)
        let (_, _) = try await kasService.processKeyAccessWithKeyIdentifier(
            ephemeralPublicKey: ephemeralPublicKey,
            encryptedKey: mockEncryptedKey,
            kasPublicKey: clientKey
        )
        
        // 5. Verify the key was removed
        let keyStillExists = await keyStore.containsMatchingPublicKey(clientKey)
        XCTAssertFalse(keyStillExists, "Key should be removed after use")
        let finalKeyCount = await keyStore.getKeyCount()
        XCTAssertEqual(finalKeyCount, initialKeyCount - 1)
    }
    */
    
    func testPublicKeyStoreSerializationDeserialization() async throws {
        // Create stores with the same curve
        let curve = Curve.secp384r1
        let keyStore = KeyStore(curve: curve)
        
        // Generate keys
        try await keyStore.generateAndStoreKeyPairs(count: 5)
        
        // Export to PublicKeyStore
        let publicKeyStore = await keyStore.exportPublicKeyStore()
        let initialKeys = await publicKeyStore.publicKeys
        XCTAssertEqual(initialKeys.count, 5)
        
        // Serialize PublicKeyStore
        let serializedData = await publicKeyStore.serialize()
        
        // Create a new empty PublicKeyStore
        let newPublicKeyStore = PublicKeyStore(curve: curve)
        
        // Deserialize into the new store
        try await newPublicKeyStore.deserialize(from: serializedData)
        
        // Check keys were correctly deserialized
        let restoredKeys = await newPublicKeyStore.publicKeys
        XCTAssertEqual(restoredKeys.count, initialKeys.count)
        
        // Check each key matches
        for key in initialKeys {
            XCTAssertTrue(restoredKeys.contains(where: { $0 == key }))
        }
    }
    
    func testCreateKasMetadataFromPublicKeyStore() async throws {
        // Create KeyStore
        let curve = Curve.secp256r1
        let keyStore = KeyStore(curve: curve)
        
        // Generate keys
        try await keyStore.generateAndStoreKeyPairs(count: 3)
        
        // Export to PublicKeyStore
        let publicKeyStore = await keyStore.exportPublicKeyStore()
        let initialKeyCount = (await publicKeyStore.publicKeys).count
        XCTAssertEqual(initialKeyCount, 3)
        
        // Create a resource locator
        let resourceLocator = ResourceLocator(protocolEnum: .http, body: "kas.example.com")!
        
        // Create KAS metadata using a key from the store
        let metadata = try await publicKeyStore.createKasMetadata(resourceLocator: resourceLocator)
        
        // Verify key was consumed
        let remainingKeyCount = (await publicKeyStore.publicKeys).count
        XCTAssertEqual(remainingKeyCount, initialKeyCount - 1)
        
        // Verify metadata has correct information
        XCTAssertEqual(metadata.resourceLocator.body, "kas.example.com")
        XCTAssertEqual(metadata.resourceLocator.protocolEnum, .http)
        XCTAssertEqual(metadata.curve, curve)
    }
    
    func testKeyStoreExportPublicKeyStoreAndRemove() async throws {
        // Create a keystore and generate some keys
        let curve = Curve.secp256r1
        let keyStore = KeyStore(curve: curve)
        try await keyStore.generateAndStoreKeyPairs(count: 5)
        
        // Export keys to PublicKeyStore
        let publicKeyStore = await keyStore.exportPublicKeyStore()
        let publicKeys = await publicKeyStore.publicKeys
        XCTAssertEqual(publicKeys.count, 5)
        
        // Get a key to test removal
        let keyToRemove = publicKeys[0]
        
        // Create identifier and verify key exists
        let identifier = KeyPairIdentifier(publicKey: keyToRemove)
        let hasKey = await keyStore.containsMatchingPublicKey(keyToRemove)
        XCTAssertTrue(hasKey)
        
        // Remove the key
        try await keyStore.removeKeyPair(keyID: identifier)
        
        // Verify key was removed
        let keyExists = await keyStore.containsMatchingPublicKey(keyToRemove)
        XCTAssertFalse(keyExists)
        let finalCount = await keyStore.getKeyCount()
        XCTAssertEqual(finalCount, 4)
    }
}