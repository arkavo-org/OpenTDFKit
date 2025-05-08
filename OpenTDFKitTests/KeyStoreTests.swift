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
        let derivedSymKeyData = try await keyStore.derivePayloadSymmetricKey(
            kasPublicKeyForLookup: kasStoredKeyPair.publicKey,
            clientEphemeralPublicKey: clientEphemeralKeyPair.publicKey,
            curve: curve
        )

        // Assertions
        XCTAssertEqual(derivedSymKeyData.count, 32, "Derived symmetric key should be 32 bytes for AES-256")

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
        XCTAssertEqual(derivedSymKeyData, expectedSymKey.withUnsafeBytes { Data($0) })
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
        let derivedSymKeyData = try await keyStore.derivePayloadSymmetricKey(
            kasPublicKeyForLookup: kasStoredKeyPair.publicKey,
            clientEphemeralPublicKey: clientEphemeralKeyPair.publicKey,
            curve: curve
        )

        // Assertions
        XCTAssertEqual(derivedSymKeyData.count, 32, "Derived symmetric key should be 32 bytes for AES-256")

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
        XCTAssertEqual(derivedSymKeyData, expectedSymKey.withUnsafeBytes { Data($0) })
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
        let derivedSymKeyData = try await keyStore.derivePayloadSymmetricKey(
            kasPublicKeyForLookup: kasStoredKeyPair.publicKey,
            clientEphemeralPublicKey: clientEphemeralKeyPair.publicKey,
            curve: curve
        )

        // Assertions
        XCTAssertEqual(derivedSymKeyData.count, 32, "Derived symmetric key should be 32 bytes for AES-256")

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
        XCTAssertEqual(derivedSymKeyData, expectedSymKey.withUnsafeBytes { Data($0) })
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
                kasPublicKeyForLookup: kasPublicKeyNotInStore,
                clientEphemeralPublicKey: clientEphemeralKeyPair.publicKey,
                curve: curve
            )
            XCTFail("Should have thrown KeyStoreError.keyNotFound")
        } catch {
            let expectedError = KeyStoreError.keyNotFound("Private key for KAS Public Key \(kasPublicKeyNotInStore.hexString) not found in this KeyStore.")
            XCTAssertEqual(error as? KeyStoreError, expectedError, "Incorrect error thrown or error message mismatch for keyNotFound.")
        }
    }

    func testDerivePayloadSymmetricKey_KeyAgreementFailure_MismatchedClientKeyCurve() async throws {
        let kasCurve = Curve.secp256r1
        let clientKeyCurve = Curve.secp384r1 // Different curve for client key

        let keyStore = KeyStore(curve: kasCurve)

        // Setup KAS key in KeyStore (secp256r1)
        let kasStoredKeyPair = await keyStore.generateKeyPair()
        await keyStore.store(keyPair: kasStoredKeyPair)

        // Setup Client ephemeral key (secp384r1)
        let clientEphemeralKeyPair = try await generateClientEphemeralKeyPair(curve: clientKeyCurve)

        do {
            _ = try await keyStore.derivePayloadSymmetricKey(
                kasPublicKeyForLookup: kasStoredKeyPair.publicKey,
                clientEphemeralPublicKey: clientEphemeralKeyPair.publicKey, // This is a P384 key
                curve: kasCurve // Expecting P256 operations internally based on this curve
            )
            XCTFail("Should have thrown KeyStoreError.keyAgreementFailed due to mismatched client key curve")
        } catch KeyStoreError.keyAgreementFailed {
            // This is the expected error because P256.KeyAgreement.PublicKey(compressedRepresentation:)
            // will fail if clientEphemeralKeyPair.publicKey is not a P256 key.
        } catch {
            XCTFail("Unexpected error type: \(error). Expected KeyStoreError.keyAgreementFailed.")
        }
    }
}

// Helper extension for testing
extension KeyStore {
    func getAllPublicKeys() -> [Data] {
        Array(keyPairs.values.map(\.publicKey))
    }
}
