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
}

// Helper extension for testing
extension KeyStore {
    func getAllPublicKeys() -> [Data] {
        Array(keyPairs.values.map(\.publicKey))
    }
}
