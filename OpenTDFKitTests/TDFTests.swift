import CryptoKit
import Foundation
@testable import OpenTDFKit
import XCTest
@preconcurrency import ZIPFoundation

final class StandardTDFTests: XCTestCase {
    let testPlaintext = "Test data for Standard TDF".data(using: .utf8)!

    func testTDFEncryptionAndDecryption() throws {
        let symmetricKey = try TDFCrypto.generateSymmetricKey()
        let (iv, ciphertext, tag) = try TDFCrypto.encryptPayload(
            plaintext: testPlaintext,
            symmetricKey: symmetricKey,
        )

        XCTAssertEqual(iv.count, 12, "IV should be 12 bytes")
        XCTAssertEqual(tag.count, 16, "Tag should be 16 bytes")
        XCTAssertGreaterThan(ciphertext.count, 0, "Ciphertext should not be empty")

        let decrypted = try TDFCrypto.decryptPayload(
            ciphertext: ciphertext,
            iv: iv,
            tag: tag,
            symmetricKey: symmetricKey,
        )

        XCTAssertEqual(decrypted, testPlaintext, "Decrypted data should match original")
    }

    func testPolicyBinding() throws {
        let symmetricKey = try TDFCrypto.generateSymmetricKey()
        let policyJSON = """
        {
            "uuid": "test-uuid",
            "body": {
                "dataAttributes": [],
                "dissem": []
            }
        }
        """.data(using: .utf8)!

        let binding = TDFCrypto.policyBinding(policy: policyJSON, symmetricKey: symmetricKey)

        XCTAssertFalse(binding.alg.isEmpty, "Policy binding algorithm should not be empty")
        XCTAssertFalse(binding.hash.isEmpty, "Policy binding hash should not be empty")
    }

    func testSegmentSignature() throws {
        let symmetricKey = try TDFCrypto.generateSymmetricKey()
        let segmentData = "Segment data".data(using: .utf8)!

        let signature = TDFCrypto.segmentSignature(
            segmentCiphertext: segmentData,
            symmetricKey: symmetricKey,
        )

        XCTAssertEqual(signature.count, 32, "Signature should be 32 bytes (HMAC-SHA256)")
    }

    func testRSAKeyWrapping() throws {
        let keyPair = try generateTestRSAKeyPair()
        let symmetricKey = try TDFCrypto.generateSymmetricKey()

        let wrappedKey = try TDFCrypto.wrapSymmetricKeyWithRSA(
            publicKeyPEM: keyPair.publicKeyPEM,
            symmetricKey: symmetricKey,
        )

        XCTAssertFalse(wrappedKey.isEmpty, "Wrapped key should not be empty")

        let unwrappedKey = try TDFCrypto.unwrapSymmetricKeyWithRSA(
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

        let container = TDFContainer(manifest: manifest, payload: payload)

        XCTAssertEqual(container.manifest.schemaVersion, "1.0.0")
        XCTAssertEqual(container.payload, testPlaintext)
    }

    func testTDFContainerSerialization() throws {
        let manifest = createTestManifest()
        let container = TDFContainer(manifest: manifest, payload: testPlaintext)

        let serialized = try container.serializedData()

        XCTAssertGreaterThan(serialized.count, 0, "Serialized data should not be empty")
        XCTAssertTrue(serialized.starts(with: [0x50, 0x4B]), "Should start with ZIP header")
    }

    func testTDFContainerDeserialization() throws {
        let manifest = createTestManifest()
        let container = TDFContainer(manifest: manifest, payload: testPlaintext)
        let serialized = try container.serializedData()

        let loader = TDFLoader()
        let loaded = try loader.load(from: serialized)

        XCTAssertEqual(loaded.manifest.schemaVersion, "1.0.0")
        XCTAssertEqual(loaded.payload, testPlaintext)
    }

    func testEndToEndEncryptionDecryption() throws {
        let keyPair = try generateTestRSAKeyPair()

        let kasInfo = TDFKasInfo(
            url: URL(string: "http://localhost:8080/kas")!,
            publicKeyPEM: keyPair.publicKeyPEM,
            kid: "test-key-1",
        )

        let policy = try TDFPolicy(json: """
        {
            "uuid": "test-policy",
            "body": {
                "dataAttributes": [],
                "dissem": []
            }
        }
        """.data(using: .utf8)!)

        let config = TDFEncryptionConfiguration(
            kas: kasInfo,
            policy: policy,
            mimeType: "text/plain",
        )

        let encryptor = TDFEncryptor()
        let result = try encryptor.encrypt(plaintext: testPlaintext, configuration: config)

        XCTAssertNotNil(result.container)
        XCTAssertEqual(result.container.manifest.encryptionInformation.keyAccess.count, 1)

        let decryptor = TDFDecryptor()
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

    func testMalformedZIPArchive() throws {
        let invalidZIPData = "This is not a ZIP archive".data(using: .utf8)!

        XCTAssertThrowsError(try TDFArchiveReader(data: invalidZIPData)) { error in
            guard let archiveError = error as? TDFArchiveError else {
                XCTFail("Expected TDFArchiveError, got \(type(of: error))")
                return
            }
            XCTAssertEqual(archiveError, TDFArchiveError.unreadableArchive)
        }
    }

    func testMissingManifestInArchive() throws {
        let writer = TDFArchiveWriter()
        let manifest = createTestManifest()
        let archiveData = try writer.buildArchive(manifest: manifest, payload: testPlaintext)

        guard var archive = try? ZIPFoundation.Archive(data: archiveData, accessMode: .update) else {
            XCTFail("Could not open test archive")
            return
        }

        try archive.remove(archive["0.manifest.json"]!)

        guard let corruptedData = archive.data else {
            XCTFail("Could not get corrupted archive data")
            return
        }

        let reader = try TDFArchiveReader(data: corruptedData)
        XCTAssertThrowsError(try reader.manifest()) { error in
            guard let archiveError = error as? TDFArchiveError else {
                XCTFail("Expected TDFArchiveError, got \(type(of: error))")
                return
            }
            XCTAssertEqual(archiveError, TDFArchiveError.missingManifest)
        }
    }

    func testMissingPayloadInArchive() throws {
        let writer = TDFArchiveWriter()
        let manifest = createTestManifest()
        let archiveData = try writer.buildArchive(manifest: manifest, payload: testPlaintext)

        guard var archive = try? ZIPFoundation.Archive(data: archiveData, accessMode: .update) else {
            XCTFail("Could not open test archive")
            return
        }

        try archive.remove(archive["0.payload"]!)

        guard let corruptedData = archive.data else {
            XCTFail("Could not get corrupted archive data")
            return
        }

        let reader = try TDFArchiveReader(data: corruptedData)
        XCTAssertThrowsError(try reader.payloadData()) { error in
            guard let archiveError = error as? TDFArchiveError else {
                XCTFail("Expected TDFArchiveError, got \(type(of: error))")
                return
            }
            XCTAssertEqual(archiveError, TDFArchiveError.missingPayload)
        }
    }

    func testTruncatedPayload() throws {
        let symmetricKey = try TDFCrypto.generateSymmetricKey()
        let tooShortPayload = Data([0x01, 0x02, 0x03])

        let manifest = createTestManifest()
        let container = TDFContainer(manifest: manifest, payload: tooShortPayload)

        let decryptor = TDFDecryptor()
        XCTAssertThrowsError(try decryptor.decrypt(container: container, symmetricKey: symmetricKey)) { error in
            guard let decryptError = error as? TDFDecryptError else {
                XCTFail("Expected TDFDecryptError, got \(type(of: error))")
                return
            }
            XCTAssertEqual(decryptError, TDFDecryptError.malformedPayload)
        }
    }

    func testWrongKeyDecryption() throws {
        let keyPair = try generateTestRSAKeyPair()

        let kasInfo = TDFKasInfo(
            url: URL(string: "http://localhost:8080/kas")!,
            publicKeyPEM: keyPair.publicKeyPEM,
            kid: "test-key",
        )

        let policy = try TDFPolicy(json: """
        {"uuid":"test","body":{"dataAttributes":[],"dissem":[]}}
        """.data(using: .utf8)!)

        let config = TDFEncryptionConfiguration(kas: kasInfo, policy: policy)

        let encryptor = TDFEncryptor()
        let result = try encryptor.encrypt(plaintext: testPlaintext, configuration: config)

        let wrongKey = try TDFCrypto.generateSymmetricKey()

        let decryptor = TDFDecryptor()
        XCTAssertThrowsError(try decryptor.decrypt(container: result.container, symmetricKey: wrongKey))
    }

    func testInvalidBase64InWrappedKey() throws {
        let decryptor = TDFDecryptor()
        let keyPair = try generateTestRSAKeyPair()

        let kasObject = TDFKeyAccessObject(
            type: .wrapped,
            url: "http://localhost:8080/kas",
            protocolValue: .kas,
            wrappedKey: "not-valid-base64!!!",
            policyBinding: TDFPolicyBinding(alg: "HS256", hash: "test"),
            kid: "test",
        )

        let method = TDFMethodDescriptor(algorithm: "AES-256-GCM", iv: Data(count: 12).base64EncodedString())
        let segment = TDFSegment(hash: Data(count: 32).base64EncodedString(), segmentSize: 100)
        let integrity = TDFIntegrityInformation(
            rootSignature: TDFRootSignature(alg: "HS256", sig: Data(count: 32).base64EncodedString()),
            segmentHashAlg: "HS256",
            segmentSizeDefault: 100,
            segments: [segment],
        )

        let encryptionInfo = TDFEncryptionInformation(
            type: .split,
            keyAccess: [kasObject],
            method: method,
            integrityInformation: integrity,
            policy: "test",
        )

        let payload = TDFPayloadDescriptor(
            type: .reference,
            url: "0.payload",
            protocolValue: .zip,
            isEncrypted: true,
        )

        let manifest = TDFManifest(
            schemaVersion: "1.0.0",
            payload: payload,
            encryptionInformation: encryptionInfo,
        )

        let container = TDFContainer(manifest: manifest, payload: Data(count: 100))

        XCTAssertThrowsError(try decryptor.decrypt(container: container, privateKeyPEM: keyPair.privateKeyPEM))
    }

    func testWeakRSAKeyRejection() throws {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        task.arguments = ["genrsa", "1024"]

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

        let weakPublicKeyPEM = String(data: pubPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)!

        XCTAssertThrowsError(try TDFCrypto.loadRSAPublicKey(fromPEM: weakPublicKeyPEM)) { error in
            guard let cryptoError = error as? TDFCryptoError,
                  case let .weakKey(keySize, minimum) = cryptoError
            else {
                XCTFail("Expected weakKey error, got \(error)")
                return
            }
            XCTAssertEqual(keySize, 1024)
            XCTAssertEqual(minimum, 2048)
        }
    }

    func testRSA3072KeyWrapping() throws {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        task.arguments = ["genrsa", "3072"]

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

        let symmetricKey = try TDFCrypto.generateSymmetricKey()
        let wrappedKey = try TDFCrypto.wrapSymmetricKeyWithRSA(
            publicKeyPEM: publicKeyPEM,
            symmetricKey: symmetricKey,
        )

        XCTAssertFalse(wrappedKey.isEmpty)

        let unwrappedKey = try TDFCrypto.unwrapSymmetricKeyWithRSA(
            privateKeyPEM: privateKeyPEM,
            wrappedKey: wrappedKey,
        )

        let originalKeyData = symmetricKey.withUnsafeBytes { Data($0) }
        let unwrappedKeyData = unwrappedKey.withUnsafeBytes { Data($0) }

        XCTAssertEqual(originalKeyData, unwrappedKeyData)
    }

    func testMultiKASKeyReconstruction() throws {
        let keyData1 = Data([0x01, 0x02, 0x03, 0x04])
        let keyData2 = Data([0x05, 0x06, 0x07, 0x08])
        let key1 = SymmetricKey(data: keyData1)
        let key2 = SymmetricKey(data: keyData2)

        let keyPair = try generateTestRSAKeyPair()

        let wrapped1 = try TDFCrypto.wrapSymmetricKeyWithRSA(
            publicKeyPEM: keyPair.publicKeyPEM,
            symmetricKey: key1,
        )

        let wrapped2 = try TDFCrypto.wrapSymmetricKeyWithRSA(
            publicKeyPEM: keyPair.publicKeyPEM,
            symmetricKey: key2,
        )

        let kasObject1 = TDFKeyAccessObject(
            type: .wrapped,
            url: "http://localhost:8080/kas",
            protocolValue: .kas,
            wrappedKey: wrapped1,
            policyBinding: TDFPolicyBinding(alg: "HS256", hash: "test"),
            kid: "kas-1",
        )

        let kasObject2 = TDFKeyAccessObject(
            type: .wrapped,
            url: "http://localhost:8080/kas",
            protocolValue: .kas,
            wrappedKey: wrapped2,
            policyBinding: TDFPolicyBinding(alg: "HS256", hash: "test"),
            kid: "kas-2",
        )

        let method = TDFMethodDescriptor(algorithm: "AES-256-GCM", iv: Data(count: 12).base64EncodedString())
        let segment = TDFSegment(hash: Data(count: 32).base64EncodedString(), segmentSize: 100)
        let integrity = TDFIntegrityInformation(
            rootSignature: TDFRootSignature(alg: "HS256", sig: Data(count: 32).base64EncodedString()),
            segmentHashAlg: "HS256",
            segmentSizeDefault: 100,
            segments: [segment],
        )

        let encryptionInfo = TDFEncryptionInformation(
            type: .split,
            keyAccess: [kasObject1, kasObject2],
            method: method,
            integrityInformation: integrity,
            policy: "test",
        )

        let payload = TDFPayloadDescriptor(
            type: .reference,
            url: "0.payload",
            protocolValue: .zip,
            isEncrypted: true,
        )

        let manifest = TDFManifest(
            schemaVersion: "1.0.0",
            payload: payload,
            encryptionInformation: encryptionInfo,
        )

        let expectedXOR = Data(zip(keyData1, keyData2).map { $0 ^ $1 })

        XCTAssertEqual(expectedXOR, Data([0x04, 0x04, 0x04, 0x0C]))
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

    func testPerformanceEncryption1KB() throws {
        let plaintext = Data(repeating: 0x41, count: 1024)
        let keyPair = try generateTestRSAKeyPair()
        let kasInfo = TDFKasInfo(url: URL(string: "http://localhost:8080/kas")!, publicKeyPEM: keyPair.publicKeyPEM, kid: "perf-test")
        let policy = try TDFPolicy(json: """
        {"uuid":"perf-test","body":{"dataAttributes":[],"dissem":[]}}
        """.data(using: .utf8)!)
        let config = TDFEncryptionConfiguration(kas: kasInfo, policy: policy)
        let encryptor = TDFEncryptor()

        measure {
            _ = try? encryptor.encrypt(plaintext: plaintext, configuration: config)
        }
    }

    func testPerformanceEncryption100KB() throws {
        let plaintext = Data(repeating: 0x41, count: 100 * 1024)
        let keyPair = try generateTestRSAKeyPair()
        let kasInfo = TDFKasInfo(url: URL(string: "http://localhost:8080/kas")!, publicKeyPEM: keyPair.publicKeyPEM, kid: "perf-test")
        let policy = try TDFPolicy(json: """
        {"uuid":"perf-test","body":{"dataAttributes":[],"dissem":[]}}
        """.data(using: .utf8)!)
        let config = TDFEncryptionConfiguration(kas: kasInfo, policy: policy)
        let encryptor = TDFEncryptor()

        measure {
            _ = try? encryptor.encrypt(plaintext: plaintext, configuration: config)
        }
    }

    func testPerformanceDecryption1KB() throws {
        let plaintext = Data(repeating: 0x41, count: 1024)
        let keyPair = try generateTestRSAKeyPair()
        let kasInfo = TDFKasInfo(url: URL(string: "http://localhost:8080/kas")!, publicKeyPEM: keyPair.publicKeyPEM, kid: "perf-test")
        let policy = try TDFPolicy(json: """
        {"uuid":"perf-test","body":{"dataAttributes":[],"dissem":[]}}
        """.data(using: .utf8)!)
        let config = TDFEncryptionConfiguration(kas: kasInfo, policy: policy)
        let encryptor = TDFEncryptor()
        let result = try encryptor.encrypt(plaintext: plaintext, configuration: config)
        let decryptor = TDFDecryptor()

        measure {
            _ = try? decryptor.decrypt(container: result.container, symmetricKey: result.symmetricKey)
        }
    }

    func testPerformanceDecryption100KB() throws {
        let plaintext = Data(repeating: 0x41, count: 100 * 1024)
        let keyPair = try generateTestRSAKeyPair()
        let kasInfo = TDFKasInfo(url: URL(string: "http://localhost:8080/kas")!, publicKeyPEM: keyPair.publicKeyPEM, kid: "perf-test")
        let policy = try TDFPolicy(json: """
        {"uuid":"perf-test","body":{"dataAttributes":[],"dissem":[]}}
        """.data(using: .utf8)!)
        let config = TDFEncryptionConfiguration(kas: kasInfo, policy: policy)
        let encryptor = TDFEncryptor()
        let result = try encryptor.encrypt(plaintext: plaintext, configuration: config)
        let decryptor = TDFDecryptor()

        measure {
            _ = try? decryptor.decrypt(container: result.container, symmetricKey: result.symmetricKey)
        }
    }
}
