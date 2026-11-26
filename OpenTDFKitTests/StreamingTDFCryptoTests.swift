import CryptoKit
import Foundation
@testable import OpenTDFKit
import XCTest

final class StreamingTDFCryptoTests: XCTestCase {
    func testEncryptRejectsNonPositiveChunkSize() throws {
        let inputURL = try temporaryFile(data: Data([1, 2, 3]))
        defer { try? FileManager.default.removeItem(at: inputURL) }
        let input = try FileHandle(forReadingFrom: inputURL)
        defer { try? input.close() }

        XCTAssertThrowsError(try StreamingTDFCrypto.encryptPayloadStreamingToMemory(
            inputHandle: input,
            symmetricKey: SymmetricKey(size: .bits256),
            chunkSize: 0,
        )) { error in
            guard case StreamingCryptoError.invalidChunkSize = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
    }

    func testSingleSegmentDecryptRejectsShortInput() throws {
        let inputURL = try temporaryFile(data: Data())
        defer { try? FileManager.default.removeItem(at: inputURL) }
        let input = try FileHandle(forReadingFrom: inputURL)
        defer { try? input.close() }

        XCTAssertThrowsError(try StreamingTDFCrypto.decryptPayloadStreaming(
            inputHandle: input,
            outputHandle: .nullDevice,
            iv: Data(count: 12),
            tag: Data(count: 16),
            symmetricKey: SymmetricKey(size: .bits256),
        )) { error in
            guard case StreamingCryptoError.malformedSegment(0) = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
    }

    func testMemoryDecryptRejectsInvalidSegmentSizesAndTrailingData() throws {
        let key = SymmetricKey(size: .bits256)
        let (iv, ciphertext, tag) = try TDFCrypto.encryptPayload(plaintext: Data([1, 2, 3]), symmetricKey: key)
        let encrypted = iv + ciphertext + tag
        let validSegment = StreamingTDFCrypto.EncryptedSegment(
            segmentIndex: 0,
            plaintextSize: 3,
            encryptedSize: Int64(encrypted.count),
            hash: tag.base64EncodedString(),
        )

        let rootSig = Data(HMAC<SHA256>.authenticationCode(for: tag, using: key)).base64EncodedString()

        for invalidSize in [-1, 27, Int64(encrypted.count + 1)] {
            let segment = StreamingTDFCrypto.EncryptedSegment(
                segmentIndex: 0,
                plaintextSize: 3,
                encryptedSize: invalidSize,
                hash: tag.base64EncodedString(),
            )
            XCTAssertThrowsError(try StreamingTDFCrypto.decryptPayloadMultiSegmentFromMemory(
                encryptedPayload: encrypted,
                segments: [segment],
                symmetricKey: key,
                rootSignature: rootSig,
            ))
        }

        XCTAssertThrowsError(try StreamingTDFCrypto.decryptPayloadMultiSegmentFromMemory(
            encryptedPayload: encrypted + Data([0]),
            segments: [validSegment],
            symmetricKey: key,
            rootSignature: rootSig,
        ))
        XCTAssertThrowsError(try StreamingTDFCrypto.decryptPayloadMultiSegmentFromMemory(
            encryptedPayload: encrypted,
            segments: [validSegment],
            symmetricKey: key,
            rootSignature: nil,
        ))
        XCTAssertEqual(try StreamingTDFCrypto.decryptPayloadMultiSegmentFromMemory(
            encryptedPayload: encrypted,
            segments: [validSegment],
            symmetricKey: key,
            rootSignature: rootSig,
        ), Data([1, 2, 3]))
    }

    func testStreamingRoundTripWithSmallChunks() throws {
        let plaintext = Data([1, 2, 3, 4, 5])
        let inputURL = try temporaryFile(data: plaintext)
        let encryptedURL = try temporaryFile(data: Data())
        let outputURL = try temporaryFile(data: Data())
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: encryptedURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        let key = SymmetricKey(size: .bits256)
        let input = try FileHandle(forReadingFrom: inputURL)
        let encryptedOutput = try FileHandle(forWritingTo: encryptedURL)
        let result = try StreamingTDFCrypto.encryptPayloadStreaming(
            inputHandle: input,
            outputHandle: encryptedOutput,
            symmetricKey: key,
            chunkSize: 2,
        )
        try input.close()
        try encryptedOutput.close()

        let encryptedInput = try FileHandle(forReadingFrom: encryptedURL)
        let plaintextOutput = try FileHandle(forWritingTo: outputURL)
        try StreamingTDFCrypto.decryptPayloadStreaming(
            inputHandle: encryptedInput,
            outputHandle: plaintextOutput,
            iv: result.iv,
            tag: result.tag,
            symmetricKey: key,
            chunkSize: 1,
        )
        try encryptedInput.close()
        try plaintextOutput.close()

        XCTAssertEqual(try Data(contentsOf: outputURL), plaintext)
    }

    func testEncryptFileStreamingAndDecryptFileRoundTrip() throws {
        let plaintext = Data((0 ..< 150_000).map { UInt8($0 & 0xFF) })
        let inputURL = try temporaryFile(data: plaintext)
        let archiveURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("streaming-tdf-\(UUID().uuidString).tdf")
        let outputURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("streaming-out-\(UUID().uuidString).bin")
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: archiveURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        let kasKey = P256.KeyAgreement.PrivateKey()
        let kas = TDFKasInfo(
            url: URL(string: "https://kas.example.com")!,
            publicKeyPEM: kasKey.publicKey.pemRepresentation,
            kid: "ec-kid-1",
            keyType: .ecP256,
        )
        let policy = try TDFPolicy(json: Data(#"{"uuid":"1234","body":{"dataAttributes":[]}}"#.utf8))
        let config = TDFEncryptionConfiguration(kas: kas, policy: policy)

        let result = try TDFEncryptor().encryptFileStreaming(
            inputURL: inputURL,
            outputURL: archiveURL,
            configuration: config,
            segmentSize: 32768,
        )
        XCTAssertEqual(result.manifest.encryptionInformation.integrityInformation?.segments.count, 5)

        try TDFDecryptor().decryptFile(
            inputURL: archiveURL,
            outputURL: outputURL,
            symmetricKey: result.symmetricKey,
            chunkSize: 8192,
        )
        XCTAssertEqual(try Data(contentsOf: outputURL), plaintext)
    }

    func testDecryptFileSinglePassDoesNotCreateOutputOnTamperedRoot() throws {
        let plaintext = Data(repeating: 0x42, count: 80000)
        let inputURL = try temporaryFile(data: plaintext)
        let archiveURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("streaming-tamper-\(UUID().uuidString).tdf")
        let tamperedArchiveURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("streaming-tamper-bad-\(UUID().uuidString).tdf")
        let outputURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("streaming-tamper-out-\(UUID().uuidString).bin")
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: archiveURL)
            try? FileManager.default.removeItem(at: tamperedArchiveURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        let kasKey = P256.KeyAgreement.PrivateKey()
        let kas = TDFKasInfo(
            url: URL(string: "https://kas.example.com")!,
            publicKeyPEM: kasKey.publicKey.pemRepresentation,
            kid: "ec-kid-1",
            keyType: .ecP256,
        )
        let policy = try TDFPolicy(json: Data(#"{"uuid":"1234","body":{"dataAttributes":[]}}"#.utf8))
        let config = TDFEncryptionConfiguration(kas: kas, policy: policy)

        let result = try TDFEncryptor().encryptFileStreaming(
            inputURL: inputURL,
            outputURL: archiveURL,
            configuration: config,
            segmentSize: 32768,
        )

        let loaded = try TDFLoader().load(from: archiveURL)
        var badManifest = loaded.manifest
        badManifest.encryptionInformation.integrityInformation?.rootSignature.sig = Data(repeating: 0, count: 32).base64EncodedString()
        try TDFArchiveWriter().buildArchiveToFile(manifest: badManifest, payload: loaded.payload, outputURL: tamperedArchiveURL)

        XCTAssertThrowsError(try TDFDecryptor().decryptFile(
            inputURL: tamperedArchiveURL,
            outputURL: outputURL,
            symmetricKey: result.symmetricKey,
            chunkSize: 4096,
        ))
        XCTAssertFalse(FileManager.default.fileExists(atPath: outputURL.path))
    }

    func testPublicKeyStoreFIFODrainWithCompaction() async throws {
        let store = PublicKeyStore(curve: .secp256r1)
        let keys = (0 ..< 200).map { i -> Data in
            var d = Data(count: 33)
            d[0] = 0x02
            d[32] = UInt8(i)
            return d
        }
        await store.addPublicKeys(keys)

        for expected in keys {
            let popped = try await store.getAndRemovePublicKey()
            XCTAssertEqual(popped, expected)
        }
        let remaining = await store.publicKeys
        XCTAssertTrue(remaining.isEmpty)
        do {
            _ = try await store.getAndRemovePublicKey()
            XCTFail("Expected noKeysAvailable")
        } catch PublicKeyStoreError.noKeysAvailable {
            // expected
        }
    }

    private func temporaryFile(data: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("streaming-crypto-\(UUID().uuidString)")
        try data.write(to: url)
        return url
    }
}
