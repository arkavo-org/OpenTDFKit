import CryptoKit
import Foundation
@testable import OpenTDFKit
import XCTest

/// In-memory multi-segment Standard TDF: `TDFEncryptor.encrypt(plaintext:configuration:segmentSize:)`
/// and `TDFDecryptor.decrypt(container:symmetricKey:)` over multi-segment payloads.
final class TDFSegmentedPayloadTests: XCTestCase {
    private static let segmentSize = 2 * 1024 * 1024
    private static let kasPublicKeyPEM: String? = try? makeRSAPublicKeyPEM()

    // MARK: - Encrypt

    func testSegmentedEncryptSplitsPayloadIntoSegments() throws {
        let plaintext = Self.deterministicBytes(count: 5 * 1024 * 1024 + 123)
        let result = try TDFEncryptor().encrypt(
            plaintext: plaintext,
            configuration: makeConfiguration(),
            segmentSize: Self.segmentSize,
        )

        let integrity = try XCTUnwrap(result.container.manifest.encryptionInformation.integrityInformation)
        XCTAssertEqual(integrity.segments.map(\.segmentSize), [2_097_152, 2_097_152, 1_048_699])
        XCTAssertEqual(integrity.segments.map(\.encryptedSegmentSize), [2_097_180, 2_097_180, 1_048_727])
        XCTAssertEqual(integrity.segmentSizeDefault, 2_097_152)
        XCTAssertEqual(integrity.encryptedSegmentSizeDefault, 2_097_180)
        XCTAssertEqual(integrity.segmentHashAlg, "GMAC")
        XCTAssertEqual(result.container.payload.count, 2_097_180 * 2 + 1_048_727)

        // Each segment hash is the GMAC (AES-GCM tag) of that segment; the root
        // signature is HMAC-SHA256(DEK, concat(tags)).
        var offset = result.container.payload.startIndex
        var tags: [Data] = []
        for segment in integrity.segments {
            let encryptedSize = try Int(XCTUnwrap(segment.encryptedSegmentSize))
            let segmentData = result.container.payload[offset ..< offset + encryptedSize]
            let tag = Data(segmentData.suffix(16))
            XCTAssertEqual(segment.hash, tag.base64EncodedString())
            tags.append(tag)
            offset += encryptedSize
        }
        XCTAssertEqual(
            integrity.rootSignature.sig,
            TDFCrypto.rootSignatureBase64(rawSegmentSignatures: tags, symmetricKey: result.symmetricKey),
        )
    }

    func testSegmentedEncryptExactMultipleHasNoEmptyTrailingSegment() throws {
        let plaintext = Self.deterministicBytes(count: 2 * Self.segmentSize)
        let result = try TDFEncryptor().encrypt(
            plaintext: plaintext,
            configuration: makeConfiguration(),
            segmentSize: Self.segmentSize,
        )

        let integrity = try XCTUnwrap(result.container.manifest.encryptionInformation.integrityInformation)
        XCTAssertEqual(integrity.segments.map(\.segmentSize), [2_097_152, 2_097_152])
    }

    func testSegmentedEncryptRejectsNonPositiveSegmentSize() throws {
        XCTAssertThrowsError(try TDFEncryptor().encrypt(
            plaintext: Data([1, 2, 3]),
            configuration: makeConfiguration(),
            segmentSize: 0,
        ))
    }

    // MARK: - Decrypt

    func testSegmentedRoundTripThroughArchive() throws {
        let plaintext = Self.deterministicBytes(count: 5 * 1024 * 1024 + 123)
        let result = try TDFEncryptor().encrypt(
            plaintext: plaintext,
            configuration: makeConfiguration(),
            segmentSize: Self.segmentSize,
        )

        let archive = try result.container.serializedData()
        let loaded = try TDFLoader().load(from: archive)
        let decrypted = try TDFDecryptor().decrypt(container: loaded, symmetricKey: result.symmetricKey)

        XCTAssertEqual(decrypted, plaintext)
    }

    func testSegmentedRoundTripEmptyPlaintext() throws {
        let result = try TDFEncryptor().encrypt(
            plaintext: Data(),
            configuration: makeConfiguration(),
            segmentSize: Self.segmentSize,
        )

        let integrity = try XCTUnwrap(result.container.manifest.encryptionInformation.integrityInformation)
        XCTAssertEqual(integrity.segments.count, 1)
        let decrypted = try TDFDecryptor().decrypt(container: result.container, symmetricKey: result.symmetricKey)
        XCTAssertEqual(decrypted, Data())
    }

    func testInMemoryDecryptHandlesFileMultiSegmentOutput() throws {
        let plaintext = Self.deterministicBytes(count: 2 * 1024 * 1024 + 512 * 1024)
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let inputURL = directory.appendingPathComponent("input.bin")
        let outputURL = directory.appendingPathComponent("output.tdf")
        try plaintext.write(to: inputURL)

        let result = try TDFEncryptor().encryptFileMultiSegment(
            inputURL: inputURL,
            outputURL: outputURL,
            configuration: makeConfiguration(),
            segmentSizes: [1024 * 1024, 1024 * 1024, 1024 * 1024],
        )

        let loaded = try TDFLoader().load(from: outputURL)
        XCTAssertEqual(loaded.manifest.encryptionInformation.integrityInformation?.segments.count, 3)
        let decrypted = try TDFDecryptor().decrypt(container: loaded, symmetricKey: result.symmetricKey)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testSegmentedDecryptRejectsTamperedSegment() throws {
        let plaintext = Self.deterministicBytes(count: 5 * 1024 * 1024)
        let result = try TDFEncryptor().encrypt(
            plaintext: plaintext,
            configuration: makeConfiguration(),
            segmentSize: Self.segmentSize,
        )

        var payload = result.container.payload
        let secondSegmentCiphertext = payload.startIndex + 2_097_180 + 12 + 100
        payload[secondSegmentCiphertext] ^= 0x01
        let tampered = TDFContainer(manifest: result.container.manifest, payload: payload)

        XCTAssertThrowsError(try TDFDecryptor().decrypt(container: tampered, symmetricKey: result.symmetricKey))
    }

    func testSegmentedDecryptRejectsPayloadSizeMismatch() throws {
        let plaintext = Self.deterministicBytes(count: 3 * 1024 * 1024)
        let result = try TDFEncryptor().encrypt(
            plaintext: plaintext,
            configuration: makeConfiguration(),
            segmentSize: Self.segmentSize,
        )

        let truncated = TDFContainer(
            manifest: result.container.manifest,
            payload: result.container.payload.dropLast(1),
        )

        XCTAssertThrowsError(try TDFDecryptor().decrypt(container: truncated, symmetricKey: result.symmetricKey))
    }

    // MARK: - Integrity

    func testDecryptRejectsReorderedSegments() throws {
        let result = try encryptThreeSegments()
        let payload = result.container.payload
        let segment = 2_097_180
        var swapped = Data()
        swapped.append(payload[payload.startIndex + segment ..< payload.startIndex + 2 * segment])
        swapped.append(payload[payload.startIndex ..< payload.startIndex + segment])
        swapped.append(payload[(payload.startIndex + 2 * segment)...])
        let reordered = TDFContainer(manifest: result.container.manifest, payload: swapped)

        assertIntegrityFailure(try TDFDecryptor().decrypt(container: reordered, symmetricKey: result.symmetricKey))
    }

    func testDecryptRejectsTruncationToSingleSegment() throws {
        let result = try encryptThreeSegments()
        var manifest = result.container.manifest
        var integrity = try XCTUnwrap(manifest.encryptionInformation.integrityInformation)
        integrity.segments = [integrity.segments[0]]
        manifest.encryptionInformation.integrityInformation = integrity
        let firstSegment = result.container.payload.prefix(2_097_180)
        let truncated = TDFContainer(manifest: manifest, payload: Data(firstSegment))

        assertIntegrityFailure(try TDFDecryptor().decrypt(container: truncated, symmetricKey: result.symmetricKey))
    }

    func testDecryptRejectsDroppedTrailingSegment() throws {
        let result = try encryptThreeSegments()
        var manifest = result.container.manifest
        var integrity = try XCTUnwrap(manifest.encryptionInformation.integrityInformation)
        integrity.segments.removeLast()
        manifest.encryptionInformation.integrityInformation = integrity
        let truncated = TDFContainer(manifest: manifest, payload: Data(result.container.payload.prefix(2 * 2_097_180)))

        assertIntegrityFailure(try TDFDecryptor().decrypt(container: truncated, symmetricKey: result.symmetricKey))
    }

    func testDecryptRejectsTamperedSegmentHash() throws {
        let result = try encryptThreeSegments()
        var manifest = result.container.manifest
        var integrity = try XCTUnwrap(manifest.encryptionInformation.integrityInformation)
        integrity.segments[1].hash = Data(count: 16).base64EncodedString()
        manifest.encryptionInformation.integrityInformation = integrity
        let tampered = TDFContainer(manifest: manifest, payload: result.container.payload)

        assertIntegrityFailure(try TDFDecryptor().decrypt(container: tampered, symmetricKey: result.symmetricKey))
    }

    func testDecryptRejectsKeylessRootSignatureDowngrade() throws {
        // A GMAC root is just the last segment's tag; accepting it would let a
        // truncated payload carry a forged root.
        let result = try encryptThreeSegments()
        var manifest = result.container.manifest
        var integrity = try XCTUnwrap(manifest.encryptionInformation.integrityInformation)
        integrity.segments.removeLast()
        let truncatedPayload = Data(result.container.payload.prefix(2 * 2_097_180))
        integrity.rootSignature = TDFRootSignature(alg: "GMAC", sig: Data(truncatedPayload.suffix(16)).base64EncodedString())
        manifest.encryptionInformation.integrityInformation = integrity
        let forged = TDFContainer(manifest: manifest, payload: truncatedPayload)

        XCTAssertThrowsError(try TDFDecryptor().decrypt(container: forged, symmetricKey: result.symmetricKey)) { error in
            XCTAssertEqual(error as? TDFDecryptError, .unsupportedIntegrityAlgorithm("GMAC"))
        }
    }

    func testDecryptRejectsMissingIntegrityInformation() throws {
        let result = try encryptThreeSegments()
        var manifest = result.container.manifest
        manifest.encryptionInformation.integrityInformation = nil
        let stripped = TDFContainer(manifest: manifest, payload: result.container.payload)

        XCTAssertThrowsError(try TDFDecryptor().decrypt(container: stripped, symmetricKey: result.symmetricKey)) { error in
            XCTAssertEqual(error as? TDFDecryptError, .missingIntegrityInformation)
        }
    }

    // MARK: - Helpers

    private func encryptThreeSegments() throws -> TDFEncryptionResult {
        try TDFEncryptor().encrypt(
            plaintext: Self.deterministicBytes(count: 5 * 1024 * 1024),
            configuration: makeConfiguration(),
            segmentSize: Self.segmentSize,
        )
    }

    private func assertIntegrityFailure(
        _ expression: @autoclosure () throws -> some Any,
        file: StaticString = #filePath,
        line: UInt = #line,
    ) {
        XCTAssertThrowsError(try expression(), file: file, line: line) { error in
            XCTAssertEqual(error as? TDFDecryptError, .integrityCheckFailed, file: file, line: line)
        }
    }

    private func makeConfiguration() throws -> TDFEncryptionConfiguration {
        let pem = try XCTUnwrap(Self.kasPublicKeyPEM, "openssl RSA key generation failed")
        let kasInfo = try TDFKasInfo(
            url: XCTUnwrap(URL(string: "https://kas.example.com/kas")),
            publicKeyPEM: pem,
            kid: "r1",
        )
        let policy = try TDFPolicy(json: Data(#"{"uuid":"segmented-test","body":{"dataAttributes":[],"dissem":[]}}"#.utf8))
        return TDFEncryptionConfiguration(kas: kasInfo, policy: policy)
    }

    /// Same deterministic pattern as the cross-SDK E2E benchmark: byte i = (i*131 + (i>>8)*17) & 255.
    static func deterministicBytes(count: Int) -> Data {
        Data((0 ..< count).map { UInt8(truncatingIfNeeded: $0 &* 131 &+ ($0 >> 8) &* 17) })
    }

    /// RSA-2048 SPKI public key PEM for tests that need a KAS wrapping key.
    static func makeRSAPublicKeyPEM() throws -> String {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
              let publicKey = SecKeyCopyPublicKey(privateKey),
              let pkcs1 = SecKeyCopyExternalRepresentation(publicKey, &error) as Data?
        else {
            throw error?.takeRetainedValue() ?? NSError(domain: "TDFSegmentedPayloadTests", code: 1)
        }
        // Wrap PKCS#1 RSAPublicKey in an SPKI header for rsaEncryption.
        let algorithmIdentifier: [UInt8] = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00]
        let bitString = derElement(tag: 0x03, content: Data([0x00]) + pkcs1)
        let spki = derElement(tag: 0x30, content: Data(algorithmIdentifier) + bitString)
        let base64 = spki.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN PUBLIC KEY-----\n\(base64)\n-----END PUBLIC KEY-----\n"
    }

    private static func derElement(tag: UInt8, content: Data) -> Data {
        var out = Data([tag])
        let length = content.count
        if length < 0x80 {
            out.append(UInt8(length))
        } else {
            let lengthBytes = withUnsafeBytes(of: UInt32(length).bigEndian) { Data($0) }.drop { $0 == 0 }
            out.append(0x80 | UInt8(lengthBytes.count))
            out.append(contentsOf: lengthBytes)
        }
        return out + content
    }
}
