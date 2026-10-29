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
            ))
        }

        XCTAssertThrowsError(try StreamingTDFCrypto.decryptPayloadMultiSegmentFromMemory(
            encryptedPayload: encrypted + Data([0]),
            segments: [validSegment],
            symmetricKey: key,
        ))
        XCTAssertEqual(try StreamingTDFCrypto.decryptPayloadMultiSegmentFromMemory(
            encryptedPayload: encrypted,
            segments: [validSegment],
            symmetricKey: key,
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

    private func temporaryFile(data: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("streaming-crypto-\(UUID().uuidString)")
        try data.write(to: url)
        return url
    }
}
