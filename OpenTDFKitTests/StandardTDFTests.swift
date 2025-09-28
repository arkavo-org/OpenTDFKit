import CryptoKit
import Foundation
@testable import OpenTDFKit
import XCTest

final class StandardTDFTests: XCTestCase {
    let testPlaintext = "Test data for Standard TDF".data(using: .utf8)!

    func testTDFEncryptionAndDecryption() throws {
        let symmetricKey = try StandardTDFCrypto.generateSymmetricKey()
        let (iv, ciphertext, tag) = try StandardTDFCrypto.encryptPayload(
            plaintext: testPlaintext,
            symmetricKey: symmetricKey,
        )

        XCTAssertEqual(iv.count, 12, "IV should be 12 bytes")
        XCTAssertEqual(tag.count, 16, "Tag should be 16 bytes")
        XCTAssertGreaterThan(ciphertext.count, 0, "Ciphertext should not be empty")

        let decrypted = try StandardTDFCrypto.decryptPayload(
            ciphertext: ciphertext,
            iv: iv,
            tag: tag,
            symmetricKey: symmetricKey,
        )

        XCTAssertEqual(decrypted, testPlaintext, "Decrypted data should match original")
    }

    func testPolicyBinding() throws {
        let symmetricKey = try StandardTDFCrypto.generateSymmetricKey()
        let policyJSON = """
        {
            "uuid": "test-uuid",
            "body": {
                "dataAttributes": [],
                "dissem": []
            }
        }
        """.data(using: .utf8)!

        let binding = StandardTDFCrypto.policyBinding(policy: policyJSON, symmetricKey: symmetricKey)

        XCTAssertFalse(binding.alg.isEmpty, "Policy binding algorithm should not be empty")
        XCTAssertFalse(binding.hash.isEmpty, "Policy binding hash should not be empty")
    }

    func testSegmentSignature() throws {
        let symmetricKey = try StandardTDFCrypto.generateSymmetricKey()
        let segmentData = "Segment data".data(using: .utf8)!

        let signature = StandardTDFCrypto.segmentSignature(
            segmentCiphertext: segmentData,
            symmetricKey: symmetricKey,
        )

        XCTAssertEqual(signature.count, 32, "Signature should be 32 bytes (HMAC-SHA256)")
    }

    func testRSAKeyWrapping() throws {
        let keyPair = try generateTestRSAKeyPair()
        let symmetricKey = try StandardTDFCrypto.generateSymmetricKey()

        let wrappedKey = try StandardTDFCrypto.wrapSymmetricKeyWithRSA(
            publicKeyPEM: keyPair.publicKeyPEM,
            symmetricKey: symmetricKey,
        )

        XCTAssertFalse(wrappedKey.isEmpty, "Wrapped key should not be empty")

        let unwrappedKey = try StandardTDFCrypto.unwrapSymmetricKeyWithRSA(
            privateKeyPEM: keyPair.privateKeyPEM,
            wrappedKey: wrappedKey,
        )

        let originalKeyData = symmetricKey.withUnsafeBytes { Data($0) }
        let unwrappedKeyData = unwrappedKey.withUnsafeBytes { Data($0) }

        XCTAssertEqual(originalKeyData, unwrappedKeyData, "Unwrapped key should match original")
    }

    func testTDFContainerCreation() throws {
        let manifest = createTestManifest()
        let payload = testPlaintext

        let container = StandardTDFContainer(manifest: manifest, payload: payload)

        XCTAssertEqual(container.manifest.schemaVersion, "1.0.0")
        XCTAssertEqual(container.payload, testPlaintext)
    }

    func testTDFContainerSerialization() throws {
        let manifest = createTestManifest()
        let container = StandardTDFContainer(manifest: manifest, payload: testPlaintext)

        let serialized = try container.serializedData()

        XCTAssertGreaterThan(serialized.count, 0, "Serialized data should not be empty")
        XCTAssertTrue(serialized.starts(with: [0x50, 0x4B]), "Should start with ZIP header")
    }

    func testTDFContainerDeserialization() throws {
        let manifest = createTestManifest()
        let container = StandardTDFContainer(manifest: manifest, payload: testPlaintext)
        let serialized = try container.serializedData()

        let loader = StandardTDFLoader()
        let loaded = try loader.load(from: serialized)

        XCTAssertEqual(loaded.manifest.schemaVersion, "1.0.0")
        XCTAssertEqual(loaded.payload, testPlaintext)
    }

    func testEndToEndEncryptionDecryption() throws {
        let keyPair = try generateTestRSAKeyPair()

        let kasInfo = StandardTDFKasInfo(
            url: URL(string: "http://localhost:8080/kas")!,
            publicKeyPEM: keyPair.publicKeyPEM,
            kid: "test-key-1",
        )

        let policy = StandardTDFPolicy(json: """
        {
            "uuid": "test-policy",
            "body": {
                "dataAttributes": [],
                "dissem": []
            }
        }
        """.data(using: .utf8)!)

        let config = StandardTDFEncryptionConfiguration(
            kas: kasInfo,
            policy: policy,
            mimeType: "text/plain",
        )

        let encryptor = StandardTDFEncryptor()
        let result = try encryptor.encrypt(plaintext: testPlaintext, configuration: config)

        XCTAssertNotNil(result.container)
        XCTAssertEqual(result.container.manifest.encryptionInformation.keyAccess.count, 1)

        let decryptor = StandardTDFDecryptor()
        let decrypted = try decryptor.decrypt(
            container: result.container,
            symmetricKey: result.symmetricKey,
        )

        XCTAssertEqual(decrypted, testPlaintext, "Decrypted data should match original")
    }

    func testManifestStructure() throws {
        let manifest = createTestManifest()

        XCTAssertEqual(manifest.schemaVersion, "1.0.0")
        XCTAssertEqual(manifest.payload.url, "0.payload")
        XCTAssertTrue(manifest.payload.isEncrypted)
        XCTAssertEqual(manifest.encryptionInformation.type, .split)
        XCTAssertEqual(manifest.encryptionInformation.method.algorithm, "AES-256-GCM")
    }

    private func createTestManifest() -> TDFManifest {
        let method = TDFMethodDescriptor(
            algorithm: "AES-256-GCM",
            iv: Data(count: 12).base64EncodedString(),
            isStreamable: false,
        )

        let segment = TDFSegment(
            hash: Data(count: 32).base64EncodedString(),
            segmentSize: Int64(testPlaintext.count),
            encryptedSegmentSize: Int64(testPlaintext.count + 28),
        )

        let integrity = TDFIntegrityInformation(
            rootSignature: TDFRootSignature(
                alg: "HS256",
                sig: Data(count: 32).base64EncodedString(),
            ),
            segmentHashAlg: "HS256",
            segmentSizeDefault: Int64(testPlaintext.count),
            encryptedSegmentSizeDefault: Int64(testPlaintext.count + 28),
            segments: [segment],
        )

        let kasObject = TDFKeyAccessObject(
            type: .wrapped,
            url: "http://localhost:8080/kas",
            protocolValue: .kas,
            wrappedKey: "test-wrapped-key",
            policyBinding: TDFPolicyBinding(alg: "HS256", hash: "test-binding-hash"),
            encryptedMetadata: nil,
            kid: "test-key",
            sid: nil,
            schemaVersion: nil,
            ephemeralPublicKey: nil,
        )

        let encryptionInfo = TDFEncryptionInformation(
            type: .split,
            keyAccess: [kasObject],
            method: method,
            integrityInformation: integrity,
            policy: "test-policy".data(using: .utf8)!.base64EncodedString(),
        )

        let payload = TDFPayloadDescriptor(
            type: .reference,
            url: "0.payload",
            protocolValue: .zip,
            isEncrypted: true,
            mimeType: "text/plain",
        )

        return TDFManifest(
            schemaVersion: "1.0.0",
            payload: payload,
            encryptionInformation: encryptionInfo,
            assertions: nil,
        )
    }

    private func generateTestRSAKeyPair() throws -> (publicKeyPEM: String, privateKeyPEM: String) {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        task.arguments = ["genrsa", "2048"]

        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()

        try task.run()
        task.waitUntilExit()

        let privateKeyPEM = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)!

        let pubTask = Process()
        pubTask.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        pubTask.arguments = ["rsa", "-pubout"]

        let pubPipe = Pipe()
        let inPipe = Pipe()
        pubTask.standardInput = inPipe
        pubTask.standardOutput = pubPipe
        pubTask.standardError = Pipe()

        try pubTask.run()
        inPipe.fileHandleForWriting.write(privateKeyPEM.data(using: .utf8)!)
        try inPipe.fileHandleForWriting.close()
        pubTask.waitUntilExit()

        let publicKeyPEM = String(data: pubPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)!

        return (publicKeyPEM, privateKeyPEM)
    }
}
