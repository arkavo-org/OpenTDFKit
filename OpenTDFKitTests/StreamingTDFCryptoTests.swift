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

    func testDecryptFileHonorsMaxPayloadSizeAndManifestDeclaredBound() throws {
        let plaintext = Data((0 ..< 150_000).map { UInt8($0 & 0xFF) })
        let inputURL = try temporaryFile(data: plaintext)
        let archiveURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("streaming-cap-\(UUID().uuidString).tdf")
        let bloatedArchiveURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("streaming-bloated-\(UUID().uuidString).tdf")
        let outputURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("streaming-cap-out-\(UUID().uuidString).bin")
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: archiveURL)
            try? FileManager.default.removeItem(at: bloatedArchiveURL)
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

        // Smaller caller-provided maxPayloadSize rejects extraction before writing output
        XCTAssertThrowsError(try TDFDecryptor().decryptFile(
            inputURL: archiveURL,
            outputURL: outputURL,
            symmetricKey: result.symmetricKey,
            maxPayloadSize: 100_000,
        )) { error in
            XCTAssertEqual(error as? TDFArchiveError, .payloadTooLarge)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: outputURL.path))

        // Uncapped default (bounded by manifest's declared segment sum) succeeds
        try TDFDecryptor().decryptFile(
            inputURL: archiveURL,
            outputURL: outputURL,
            symmetricKey: result.symmetricKey,
            maxPayloadSize: nil,
        )
        XCTAssertEqual(try Data(contentsOf: outputURL), plaintext)
        try? FileManager.default.removeItem(at: outputURL)

        // Archive whose ZIP payload expands past the manifest's declared segment sum is aborted
        // during extraction with payloadTooLarge rather than filling disk.
        let loaded = try TDFLoader().load(from: archiveURL)
        var bloatedPayload = loaded.payload
        bloatedPayload.append(Data(repeating: 0xAA, count: 65536))
        try TDFArchiveWriter().buildArchiveToFile(
            manifest: loaded.manifest,
            payload: bloatedPayload,
            outputURL: bloatedArchiveURL,
        )
        XCTAssertThrowsError(try TDFDecryptor().decryptFile(
            inputURL: bloatedArchiveURL,
            outputURL: outputURL,
            symmetricKey: result.symmetricKey,
        )) { error in
            XCTAssertEqual(error as? TDFArchiveError, .payloadTooLarge)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: outputURL.path))
    }

    func testEncryptFileStreamingSupportsEmptyInput() throws {
        let inputURL = try temporaryFile(data: Data())
        let archiveURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("streaming-empty-\(UUID().uuidString).tdf")
        let outputURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("streaming-empty-out-\(UUID().uuidString).bin")
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: archiveURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        let kasKey = P256.KeyAgreement.PrivateKey()
        let kas = TDFKasInfo(
            url: URL(string: "https://kas.example.com")!,
            publicKeyPEM: kasKey.publicKey.pemRepresentation,
            kid: "ec-kid-empty",
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
        XCTAssertEqual(result.manifest.encryptionInformation.integrityInformation?.segments.count, 1)
        XCTAssertEqual(result.manifest.encryptionInformation.integrityInformation?.segments.first?.segmentSize, 0)

        try TDFDecryptor().decryptFile(
            inputURL: archiveURL,
            outputURL: outputURL,
            symmetricKey: result.symmetricKey,
        )
        XCTAssertEqual(try Data(contentsOf: outputURL), Data())
    }

    func testECContainerDecryptFallsBackAcrossSameSplitKAOs() throws {
        let kasKey = P256.KeyAgreement.PrivateKey()
        let policy = try TDFPolicy(json: Data(#"{"uuid":"fallback-test","body":{"dataAttributes":[]}}"#.utf8))
        let plaintext = Data("secret payload".utf8)
        let kasURL = URL(string: "https://kas.example.com")!

        // Build a valid TDF-JSON container, then prepend a decoy KAO wrapped to the same
        // recipient & policy with a different DEK (so unwrap + policyBinding succeed,
        // but payload decryption must fall through to the second KAO).
        let validResult = try TDFJSONBuilder()
            .kasURL(kasURL)
            .kasPublicKey(kasKey.publicKey.pemRepresentation)
            .policy(policy)
            .encrypt(plaintext: plaintext)

        let wrongDEK = SymmetricKey(size: .bits256)
        let decoyWrap = try TDFCrypto.wrapSymmetricKeyWithEC(
            publicKeyPEM: kasKey.publicKey.pemRepresentation,
            symmetricKey: wrongDEK,
        )
        let decoyKAO = TDFKeyAccessObject(
            type: .ecWrapped,
            url: kasURL.absoluteString,
            protocolValue: .kas,
            wrappedKey: decoyWrap.wrappedKey,
            policyBinding: TDFCrypto.policyBinding(policy: policy.json, symmetricKey: wrongDEK),
            kid: nil,
            sid: nil,
            schemaVersion: "1.0",
            ephemeralPublicKey: decoyWrap.ephemeralPublicKey,
        )

        var encInfo = validResult.container.encryptionInformation
        encInfo.keyAccess = [decoyKAO] + encInfo.keyAccess
        let modifiedEnvelope = TDFJSONEnvelope(
            tdf: validResult.container.envelope.tdf,
            version: validResult.container.envelope.version,
            created: validResult.container.envelope.created,
            manifest: TDFJSONManifest(encryptionInformation: encInfo, assertions: nil),
            payload: validResult.container.envelope.payload,
        )
        let modifiedContainer = TDFJSONContainer(
            envelope: modifiedEnvelope,
            payloadData: validResult.container.payloadData,
        )

        let recovered = try TDFJSONDecryptor().decrypt(
            container: modifiedContainer,
            privateKeyPEM: kasKey.pemRepresentation,
        )
        XCTAssertEqual(recovered, plaintext)
    }

    func testDecryptFileTamperedCiphertextThrowsIntegrityCheckFailedAndRejectsDirectoryOutput() throws {
        let plaintext = Data(repeating: 0x55, count: 40000)
        let inputURL = try temporaryFile(data: plaintext)
        let archiveURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("streaming-ct-src-\(UUID().uuidString).tdf")
        let tamperedArchiveURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("streaming-ct-bad-\(UUID().uuidString).tdf")
        let outputURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("streaming-ct-out-\(UUID().uuidString).bin")
        let existingDirURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("streaming-dir-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: existingDirURL, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: archiveURL)
            try? FileManager.default.removeItem(at: tamperedArchiveURL)
            try? FileManager.default.removeItem(at: outputURL)
            try? FileManager.default.removeItem(at: existingDirURL)
        }

        let kasKey = P256.KeyAgreement.PrivateKey()
        let kas = TDFKasInfo(
            url: URL(string: "https://kas.example.com")!,
            publicKeyPEM: kasKey.publicKey.pemRepresentation,
            kid: "ec-kid-ct",
            keyType: .ecP256,
        )
        let policy = try TDFPolicy(json: Data(#"{"uuid":"ct-tamper","body":{"dataAttributes":[]}}"#.utf8))
        let config = TDFEncryptionConfiguration(kas: kas, policy: policy)

        let result = try TDFEncryptor().encryptFileStreaming(
            inputURL: inputURL,
            outputURL: archiveURL,
            configuration: config,
            segmentSize: 16384,
        )

        // Flip a ciphertext byte (leaving GMAC tag intact so AES.GCM.open catches it)
        let loaded = try TDFLoader().load(from: archiveURL)
        var tamperedPayload = loaded.payload
        tamperedPayload[12] ^= 0x01
        try TDFArchiveWriter().buildArchiveToFile(
            manifest: loaded.manifest,
            payload: tamperedPayload,
            outputURL: tamperedArchiveURL,
        )

        XCTAssertThrowsError(try TDFDecryptor().decryptFile(
            inputURL: tamperedArchiveURL,
            outputURL: outputURL,
            symmetricKey: result.symmetricKey,
        )) { error in
            XCTAssertEqual(error as? TDFDecryptError, .integrityCheckFailed)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: outputURL.path))

        // Reject existing directory as outputURL without touching it
        XCTAssertThrowsError(try TDFDecryptor().decryptFile(
            inputURL: archiveURL,
            outputURL: existingDirURL,
            symmetricKey: result.symmetricKey,
        ))
        var isDir: ObjCBool = false
        XCTAssertTrue(FileManager.default.fileExists(atPath: existingDirURL.path, isDirectory: &isDir) && isDir.boolValue)
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
