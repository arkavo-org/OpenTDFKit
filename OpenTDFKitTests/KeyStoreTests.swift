@preconcurrency import CryptoKit
@testable import OpenTDFKit
import XCTest

final class KeyStoreTests: XCTestCase {
    func testGenerateAndStoreSingleKey() async throws {
        let keyStore = KeyStore(curve: .secp256r1)
        let keyPair = await keyStore.generateKeyPair()
        await keyStore.store(keyPair: keyPair)

        // Test existence check
        let exists = await keyStore.getPrivateKey(forPublicKey: keyPair.publicKey)
        XCTAssertTrue(exists != nil)

        // Test private key retrieval
        let foundPrivateKey = await keyStore.getPrivateKey(forPublicKey: keyPair.publicKey)
        XCTAssertNotNil(foundPrivateKey)
        XCTAssertEqual(foundPrivateKey, keyPair.privateKey)
    }

    func testSerializationAndDeserialization() async throws {
        let keyStore = KeyStore(curve: .secp256r1)

        // Generate test key pairs
        try await keyStore.generateAndStoreKeyPairs(count: 10)

        // Serialize all keys
        let serializedData = await keyStore.serialize()
        print("Total serialized size: \(serializedData.count) bytes")

        // Create new store and deserialize
        let restoredStore = KeyStore(curve: .secp256r1)
        try await restoredStore.deserialize(from: serializedData)

        // Verify key counts match
        let originalKeys = await keyStore.getAllPublicKeys()
        let restoredKeys = await restoredStore.getAllPublicKeys()
        XCTAssertEqual(originalKeys.count, restoredKeys.count)

        // Verify all keys were restored correctly
        for publicKey in originalKeys {
            // Check existence
            let exists = await restoredStore.getPrivateKey(forPublicKey: publicKey)
            XCTAssertTrue(exists != nil, "Key existence check failed after deserialization")

            // Verify private key matches
            let originalPrivateKey = await keyStore.getPrivateKey(forPublicKey: publicKey)
            let restoredPrivateKey = await restoredStore.getPrivateKey(forPublicKey: publicKey)
            XCTAssertEqual(restoredPrivateKey, originalPrivateKey, "Private key mismatch after deserialization")
        }
    }

    func testInvalidDeserialization() async {
        let keyStore = KeyStore(curve: .secp256r1)

        // Test empty data
        do {
            try await keyStore.deserialize(from: Data())
            XCTFail("Should fail with empty data")
        } catch {
            XCTAssertEqual(error as? KeyStoreError, .invalidKeyData)
        }

        // Test truncated data
        let invalidData = Data([0x00, 0x01, 0x02])
        do {
            try await keyStore.deserialize(from: invalidData)
            XCTFail("Should fail with truncated data")
        } catch {
            XCTAssertEqual(error as? KeyStoreError, .invalidKeyData)
        }

        // Test wrong curve
        let wrongCurveStore = KeyStore(curve: .secp384r1)
        let originalData = await keyStore.serialize()
        do {
            try await wrongCurveStore.deserialize(from: originalData)
            XCTFail("Should fail with wrong curve")
        } catch {
            XCTAssertEqual(error as? KeyStoreError, .invalidKeyData)
        }

        // Test invalid count
        var data = Data()
        data.append(Curve.secp256r1.rawValue)
        let invalidCount = UInt32.max
        withUnsafeBytes(of: invalidCount.bigEndian) { data.append(contentsOf: $0) }
        do {
            try await keyStore.deserialize(from: data)
            XCTFail("Should fail with invalid count")
        } catch {
            XCTAssertEqual(error as? KeyStoreError, .invalidKeyData)
        }
    }

    // MARK: - Tests for derivePayloadSymmetricKey

    // Helper enum for test-specific errors
    enum TestError: Error {
        case keyGenerationFailed(String)
    }

    // Helper to generate client ephemeral key pair for tests
    private func generateClientEphemeralKeyPair(curve: Curve) async throws -> EphemeralKeyPair {
        let cryptoHelper = CryptoHelper()
        guard let keyPair = await cryptoHelper.generateEphemeralKeyPair(curveType: curve) else {
            throw TestError.keyGenerationFailed("Client ephemeral key pair generation failed for curve \(curve)")
        }
        return keyPair
    }

    func testDerivePayloadSymmetricKey_Secp256r1_Success() async throws {
        let curve = Curve.secp256r1
        let keyStore = KeyStore(curve: curve)

        // Setup KAS key in KeyStore
        let kasStoredKeyPair = await keyStore.generateKeyPair() // Not async, not throws per provided KeyStore.swift
        await keyStore.store(keyPair: kasStoredKeyPair)

        // Setup Client ephemeral key
        let clientEphemeralKeyPair = try await generateClientEphemeralKeyPair(curve: curve)

        // Action
        let derivedSymKey = try await keyStore.derivePayloadSymmetricKey(
            kasPublicKey: kasStoredKeyPair.publicKey,
            tdfEphemeralPublicKey: clientEphemeralKeyPair.publicKey
        )

        // Assertions
        // Can't check size of SymmetricKey directly, but we can verify it works for decryption
        XCTAssertNotNil(derivedSymKey, "Derived symmetric key should not be nil")

        // Manual derivation for comparison
        let kasPrivKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: kasStoredKeyPair.privateKey)
        let clientPubKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: clientEphemeralKeyPair.publicKey)
        let sharedSecret = try kasPrivKey.sharedSecretFromKeyAgreement(with: clientPubKey)
        let expectedSymKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("L1M".utf8),
            sharedInfo: Data("encryption".utf8),
            outputByteCount: 32
        )
        // Convert both to data for comparison
        let derivedSymKeyData = derivedSymKey.withUnsafeBytes { Data($0) }
        let expectedSymKeyData = expectedSymKey.withUnsafeBytes { Data($0) }
        XCTAssertEqual(derivedSymKeyData, expectedSymKeyData)
    }

    func testDerivePayloadSymmetricKey_Secp384r1_Success() async throws {
        let curve = Curve.secp384r1
        let keyStore = KeyStore(curve: curve)

        // Setup KAS key in KeyStore
        let kasStoredKeyPair = await keyStore.generateKeyPair()
        await keyStore.store(keyPair: kasStoredKeyPair)

        // Setup Client ephemeral key
        let clientEphemeralKeyPair = try await generateClientEphemeralKeyPair(curve: curve)

        // Action
        let derivedSymKey = try await keyStore.derivePayloadSymmetricKey(
            kasPublicKey: kasStoredKeyPair.publicKey,
            tdfEphemeralPublicKey: clientEphemeralKeyPair.publicKey
        )

        // Assertions
        XCTAssertNotNil(derivedSymKey, "Derived symmetric key should not be nil")

        // Manual derivation for comparison
        let kasPrivKey = try P384.KeyAgreement.PrivateKey(rawRepresentation: kasStoredKeyPair.privateKey)
        let clientPubKey = try P384.KeyAgreement.PublicKey(compressedRepresentation: clientEphemeralKeyPair.publicKey)
        let sharedSecret = try kasPrivKey.sharedSecretFromKeyAgreement(with: clientPubKey)
        let expectedSymKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("L1M".utf8),
            sharedInfo: Data("encryption".utf8),
            outputByteCount: 32
        )
        // Convert both to data for comparison
        let derivedSymKeyData = derivedSymKey.withUnsafeBytes { Data($0) }
        let expectedSymKeyData = expectedSymKey.withUnsafeBytes { Data($0) }
        XCTAssertEqual(derivedSymKeyData, expectedSymKeyData)
    }

    func testDerivePayloadSymmetricKey_Secp521r1_Success() async throws {
        let curve = Curve.secp521r1
        let keyStore = KeyStore(curve: curve)

        // Setup KAS key in KeyStore
        let kasStoredKeyPair = await keyStore.generateKeyPair()
        await keyStore.store(keyPair: kasStoredKeyPair)

        // Setup Client ephemeral key
        let clientEphemeralKeyPair = try await generateClientEphemeralKeyPair(curve: curve)

        // Action
        let derivedSymKey = try await keyStore.derivePayloadSymmetricKey(
            kasPublicKey: kasStoredKeyPair.publicKey,
            tdfEphemeralPublicKey: clientEphemeralKeyPair.publicKey
        )

        // Assertions
        XCTAssertNotNil(derivedSymKey, "Derived symmetric key should not be nil")

        // Manual derivation for comparison
        let kasPrivKey = try P521.KeyAgreement.PrivateKey(rawRepresentation: kasStoredKeyPair.privateKey)
        let clientPubKey = try P521.KeyAgreement.PublicKey(compressedRepresentation: clientEphemeralKeyPair.publicKey)
        let sharedSecret = try kasPrivKey.sharedSecretFromKeyAgreement(with: clientPubKey)
        let expectedSymKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("L1M".utf8),
            sharedInfo: Data("encryption".utf8),
            outputByteCount: 32
        )
        // Convert both to data for comparison
        let derivedSymKeyData = derivedSymKey.withUnsafeBytes { Data($0) }
        let expectedSymKeyData = expectedSymKey.withUnsafeBytes { Data($0) }
        XCTAssertEqual(derivedSymKeyData, expectedSymKeyData)
    }

    func testDerivePayloadSymmetricKey_KasKeyNotFound() async throws {
        let curve = Curve.secp256r1
        let keyStore = KeyStore(curve: curve)

        // Generate a KAS public key that is NOT in the store
        let cryptoHelper = CryptoHelper()
        guard let nonStoredKasKeyPair = await cryptoHelper.generateEphemeralKeyPair(curveType: curve) else {
            XCTFail("Failed to generate non-stored KAS key pair for test setup")
            return
        }
        let kasPublicKeyNotInStore = nonStoredKasKeyPair.publicKey

        // Client ephemeral key
        let clientEphemeralKeyPair = try await generateClientEphemeralKeyPair(curve: curve)

        do {
            _ = try await keyStore.derivePayloadSymmetricKey(
                kasPublicKey: kasPublicKeyNotInStore,
                tdfEphemeralPublicKey: clientEphemeralKeyPair.publicKey
            )
            XCTFail("Should have thrown KeyStoreError.keyNotFound")
        } catch {
            let expectedError = KeyStoreError.keyNotFound("Private key for KAS Public Key \(kasPublicKeyNotInStore.hexString) not found in this KeyStore.")
            XCTAssertEqual(error as? KeyStoreError, expectedError, "Incorrect error thrown or error message mismatch for keyNotFound.")
        }
    }

    func testPublicKeyStoreExportAndKeyLookup() async throws {
        // 1. Create KeyStore with 100 keys
        let keyStore = KeyStore(curve: .secp256r1, capacity: 100)
        try await keyStore.generateAndStoreKeyPairs(count: 100)
        let keyStoreCount = await keyStore.getKeyCount()
        XCTAssertEqual(keyStoreCount, 100)

        // 2. Create a PublicKeyStore
        let publicKeyStore = await keyStore.exportPublicKeyStore()
        let publicKeysFromStore = await publicKeyStore.publicKeys
        XCTAssertEqual(publicKeysFromStore.count, 100)

        let serialzed = await publicKeyStore.serialize()
        let dePublicKeyStore = PublicKeyStore(curve: .secp256r1)
        try await dePublicKeyStore.deserialize(from: serialzed)
        let deKeyStoreCount = await dePublicKeyStore.publicKeys
        XCTAssertEqual(deKeyStoreCount.count, 100)

        // 3. Get a public key from said PublicKeyStore.
        var aPublicKeyFromPublicKeyStore = try await dePublicKeyStore.getAndRemovePublicKey()

        // 4. Should be found in the original KeyStore
        let privateKey = await keyStore.getPrivateKey(forPublicKey: aPublicKeyFromPublicKeyStore)
        XCTAssertNotNil(privateKey, "The public key from PublicKeyStore should be found in the original KeyStore")

        aPublicKeyFromPublicKeyStore = try await publicKeyStore.getAndRemovePublicKey()
        let dummyTdfPrivateKey = P256.KeyAgreement.PrivateKey()
        let dummyTdfPublicKey = dummyTdfPrivateKey.publicKey.compressedRepresentation

        let symmetricKey = try await keyStore.derivePayloadSymmetricKey(kasPublicKey: aPublicKeyFromPublicKeyStore, tdfEphemeralPublicKey: dummyTdfPublicKey)
        XCTAssertNotNil(symmetricKey, "The symmetric key from KeyStore should be found derived")
    }
}

// Helper extension for testing
extension KeyStore {
    func getAllPublicKeys() -> [Data] {
        Array(keyPairs.values.map(\.publicKey))
    }
}

final class PublicKeyStoreTests: XCTestCase {
    func testPublicKeyStoreExportAndConsumption() async throws {
        // Create and populate a full KeyStore
        let keyStore = KeyStore(curve: .secp256r1)
        try await keyStore.generateAndStoreKeyPairs(count: 10)
        
        // Export just the public keys to a PublicKeyStore
        let publicKeyStore = await keyStore.exportPublicKeyStore()
        
        // Verify the count is correct
        let initialCount = await publicKeyStore.getCount()
        XCTAssertEqual(initialCount, 10)
        
        // Serialize and deserialize the PublicKeyStore (simulating sending to a peer)
        let serializedData = await publicKeyStore.serialize()
        print("PublicKeyStore serialized size: \(serializedData.count) bytes")
        
        let receivedStore = PublicKeyStore(curve: .secp256r1)
        try await receivedStore.deserialize(from: serializedData)
        
        // Verify count after deserialization
        let afterDeserializeCount = await receivedStore.getCount()
        XCTAssertEqual(afterDeserializeCount, 10)
        
        // Get and remove a public key
        let publicKey = await receivedStore.getAndRemovePublicKey()
        XCTAssertNotNil(publicKey)
        
        // Verify count decreased
        let afterRemoveCount = await receivedStore.getCount()
        XCTAssertEqual(afterRemoveCount, 9)
        
        // Create KasMetadata using the removed public key
        let resourceLocator = ResourceLocator(protocolEnum: .https, body: "peer://local")!
        let kasMetadata = try await receivedStore.createKasMetadata(resourceLocator: resourceLocator)
        
        // Verify we can extract the public key from KasMetadata
        let extractedPublicKey = try kasMetadata.getPublicKey()
        XCTAssertFalse(extractedPublicKey.isEmpty)
    }
    
    func testP2PEncryptionDecryption() async throws {
        // 1. Generate a KeyStore with key pairs for peer A
        let peerAKeyStore = KeyStore(curve: .secp256r1)
        try await peerAKeyStore.generateAndStoreKeyPairs(count: 10)
        
        // 2. Export just the public keys to share with peer B
        let peerAPublicKeys = await peerAKeyStore.exportPublicKeyStore()
        let serializedPublicKeys = await peerAPublicKeys.serialize()
        
        // 3. Peer B receives and deserializes peer A's public keys
        let receivedAPublicKeys = PublicKeyStore(curve: .secp256r1)
        try await receivedAPublicKeys.deserialize(from: serializedPublicKeys)
        
        // 4. Peer B encrypts data for peer A using one of A's public keys
        let plaintext = "Hello, secure P2P world!".data(using: .utf8)!
        let resourceLocator = ResourceLocator(protocolEnum: .https, body: "peer://local")!
        
        // Get a KasMetadata using peer A's public key
        let kasMetadata = try await receivedAPublicKeys.createKasMetadata(resourceLocator: resourceLocator)
        
        // Create a policy
        var policy = Policy(type: .remote, body: nil, remote: resourceLocator)
        
        // Create a NanoTDF encrypted with peer A's public key
        let nanoTDF = try await createNanoTDF(kas: kasMetadata, policy: &policy, plaintext: plaintext)
        let serializedTDF = nanoTDF.toData()
        
        // 5. Peer A receives the encrypted data and needs to decrypt it
        // First, extract the ephemeral public key from the header
        let ephemeralPublicKey = nanoTDF.header.ephemeralPublicKey
        
        // Look up the corresponding private key in peer A's KeyStore
        guard let privateKey = await peerAKeyStore.getPrivateKey(forPublicKey: try kasMetadata.getPublicKey()) else {
            XCTFail("Failed to find private key in KeyStore")
            return
        }
        
        // Create an ephemeral key pair for decryption
        let cryptoHelper = CryptoHelper()
        let ephemeralKeyPair = EphemeralKeyPair(
            privateKey: privateKey,
            publicKey: try kasMetadata.getPublicKey(),
            curve: .secp256r1
        )
        
        // Derive shared secret
        guard let sharedSecret = try await cryptoHelper.deriveSharedSecret(
            keyPair: ephemeralKeyPair,
            recipientPublicKey: ephemeralPublicKey
        ) else {
            XCTFail("Failed to derive shared secret")
            return
        }
        
        // Decrypt the payload using the shared secret
        let decryptedData = try await nanoTDF.getPayloadPlaintext(withSharedSecret: sharedSecret)
        
        // Verify decryption was successful
        let decryptedText = String(data: decryptedData, encoding: .utf8)
        XCTAssertEqual(decryptedText, "Hello, secure P2P world!")
    }
    
    func testComprehensiveP2PWorkflow() async throws {
        // This test demonstrates a complete bidirectional P2P workflow where two peers
        // exchange public keys and then send encrypted messages to each other
        
        // PART 1: Initialize both peers' KeyStores
        print("\n--- Initializing peer KeyStores ---")
        
        // Peer A generates their KeyStore
        let peerAKeyStore = KeyStore(curve: .secp256r1)
        try await peerAKeyStore.generateAndStoreKeyPairs(count: 50)
        let peerAKeyCount = await peerAKeyStore.keyPairs.count
        print("Peer A generated KeyStore with \(peerAKeyCount) key pairs")
        
        // Peer B generates their KeyStore
        let peerBKeyStore = KeyStore(curve: .secp256r1)
        try await peerBKeyStore.generateAndStoreKeyPairs(count: 50)
        let peerBKeyCount = await peerBKeyStore.keyPairs.count
        print("Peer B generated KeyStore with \(peerBKeyCount) key pairs")
        
        // Each peer exports only their public keys for exchange
        let peerAPublicKeyStore = await peerAKeyStore.exportPublicKeyStore()
        let serializedAPubKeys = await peerAPublicKeyStore.serialize()
        print("Peer A exported PublicKeyStore (size: \(serializedAPubKeys.count) bytes)")
        
        let peerBPublicKeyStore = await peerBKeyStore.exportPublicKeyStore()
        let serializedBPubKeys = await peerBPublicKeyStore.serialize()
        print("Peer B exported PublicKeyStore (size: \(serializedBPubKeys.count) bytes)")
        
        // PART 2: Exchange public keys (over a secure channel)
        print("\n--- Simulating exchange of public keys ---")
        
        // Peer A receives and imports Peer B's public keys
        let peerBPublicKeysForA = PublicKeyStore(curve: .secp256r1) // This is on Peer A's device
        try await peerBPublicKeysForA.deserialize(from: serializedBPubKeys)
        let receivedBKeyCount = await peerBPublicKeysForA.getCount()
        print("Peer A received \(receivedBKeyCount) public keys from Peer B")
        
        // Peer B receives and imports Peer A's public keys
        let peerAPublicKeysForB = PublicKeyStore(curve: .secp256r1) // This is on Peer B's device
        try await peerAPublicKeysForB.deserialize(from: serializedAPubKeys)
        let receivedAKeyCount = await peerAPublicKeysForB.getCount()
        print("Peer B received \(receivedAKeyCount) public keys from Peer A")
        
        // PART 3: Peer A encrypts a message for Peer B
        print("\n--- Peer A encrypts a message for Peer B ---")
        
        let messageFromA = "Hello Peer B, this is a secure message from Peer A!".data(using: .utf8)!
        
        // Peer A creates a ResourceLocator (can be a dummy for P2P)
        let resourceLocator = ResourceLocator(protocolEnum: .https, body: "peer://local")!
        
        // Peer A gets a public key from Peer B's PublicKeyStore and creates KasMetadata
        let kasBMetadata = try await peerBPublicKeysForA.createKasMetadata(resourceLocator: resourceLocator)
        print("Peer A consumed one of Peer B's public keys")
        
        // Create policy 
        var policyForB = Policy(type: .remote, body: nil, remote: resourceLocator)
        
        // Create NanoTDF
        let nanoTDFFromA = try await createNanoTDF(kas: kasBMetadata, policy: &policyForB, plaintext: messageFromA)
        let serializedTDFFromA = nanoTDFFromA.toData()
        print("Peer A created NanoTDF for Peer B (size: \(serializedTDFFromA.count) bytes)")
        
        // Verify consumption of one public key
        let remainingBKeysForA = await peerBPublicKeysForA.getCount()
        XCTAssertEqual(remainingBKeysForA, receivedBKeyCount - 1)
        print("Peer A now has \(remainingBKeysForA) of Peer B's public keys remaining")
        
        // PART 4: Peer B decrypts the message from Peer A
        print("\n--- Peer B decrypts the message from Peer A ---")
        
        // Extract the public key used for encryption
        let publicKeyFromB = try kasBMetadata.getPublicKey()
        
        // Peer B looks up their private key corresponding to the public key
        guard let privateKeyB = await peerBKeyStore.getPrivateKey(forPublicKey: publicKeyFromB) else {
            XCTFail("Failed to find Peer B's private key")
            return
        }
        print("Peer B found matching private key for decryption")
        
        // Create ephemeral key pair for decryption
        let ephemeralPublicKeyFromA = nanoTDFFromA.header.ephemeralPublicKey
        let cryptoHelper = CryptoHelper()
        let ephemeralKeyPairB = EphemeralKeyPair(
            privateKey: privateKeyB,
            publicKey: publicKeyFromB,
            curve: .secp256r1
        )
        
        // Derive shared secret
        guard let sharedSecretB = try await cryptoHelper.deriveSharedSecret(
            keyPair: ephemeralKeyPairB,
            recipientPublicKey: ephemeralPublicKeyFromA
        ) else {
            XCTFail("Failed to derive shared secret for Peer B")
            return
        }
        
        // Decrypt the message
        let decryptedDataB = try await nanoTDFFromA.getPayloadPlaintext(withSharedSecret: sharedSecretB)
        let decryptedMessageB = String(data: decryptedDataB, encoding: .utf8)!
        print("Peer B successfully decrypted message: \"\(decryptedMessageB)\"")
        XCTAssertEqual(decryptedMessageB, "Hello Peer B, this is a secure message from Peer A!")
        
        // PART 5: Peer B responds to Peer A with an encrypted message
        print("\n--- Peer B responds to Peer A with an encrypted message ---")
        
        let messageFromB = "Hello Peer A, this is a secure response from Peer B!".data(using: .utf8)!
        
        // Peer B gets a public key from Peer A's PublicKeyStore
        let kasAMetadata = try await peerAPublicKeysForB.createKasMetadata(resourceLocator: resourceLocator)
        print("Peer B consumed one of Peer A's public keys")
        
        // Create policy
        var policyForA = Policy(type: .remote, body: nil, remote: resourceLocator)
        
        // Create NanoTDF
        let nanoTDFFromB = try await createNanoTDF(kas: kasAMetadata, policy: &policyForA, plaintext: messageFromB)
        let serializedTDFFromB = nanoTDFFromB.toData()
        print("Peer B created NanoTDF for Peer A (size: \(serializedTDFFromB.count) bytes)")
        
        // Verify consumption of one public key
        let remainingAKeysForB = await peerAPublicKeysForB.getCount()
        XCTAssertEqual(remainingAKeysForB, receivedAKeyCount - 1)
        print("Peer B now has \(remainingAKeysForB) of Peer A's public keys remaining")
        
        // PART 6: Peer A decrypts the response from Peer B
        print("\n--- Peer A decrypts the response from Peer B ---")
        
        // Extract the public key used for encryption
        let publicKeyFromA = try kasAMetadata.getPublicKey()
        
        // Peer A looks up their private key corresponding to the public key
        guard let privateKeyA = await peerAKeyStore.getPrivateKey(forPublicKey: publicKeyFromA) else {
            XCTFail("Failed to find Peer A's private key")
            return
        }
        print("Peer A found matching private key for decryption")
        
        // Create ephemeral key pair for decryption
        let ephemeralPublicKeyFromB = nanoTDFFromB.header.ephemeralPublicKey
        let ephemeralKeyPairA = EphemeralKeyPair(
            privateKey: privateKeyA,
            publicKey: publicKeyFromA,
            curve: .secp256r1
        )
        
        // Derive shared secret
        guard let sharedSecretA = try await cryptoHelper.deriveSharedSecret(
            keyPair: ephemeralKeyPairA,
            recipientPublicKey: ephemeralPublicKeyFromB
        ) else {
            XCTFail("Failed to derive shared secret for Peer A")
            return
        }
        
        // Decrypt the message
        let decryptedDataA = try await nanoTDFFromB.getPayloadPlaintext(withSharedSecret: sharedSecretA)
        let decryptedMessageA = String(data: decryptedDataA, encoding: .utf8)!
        print("Peer A successfully decrypted message: \"\(decryptedMessageA)\"")
        XCTAssertEqual(decryptedMessageA, "Hello Peer A, this is a secure response from Peer B!")
        
        print("\n--- P2P Workflow Test Completed Successfully ---")
    }
}
