@preconcurrency import CryptoKit
@testable import OpenTDFKit
import XCTest

final class GCMEncryptionTests: XCTestCase {
    private let testPlaintext = "This is a test message for GCM encryption".data(using: .utf8)!
    private let testKey = SymmetricKey(size: .bits256)
    private let testIV = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C])

    func testEncryptDecryptWithGCM64() throws {
        try testEncryptDecryptRoundTrip(cipher: .aes256GCM64, expectedTagSize: 8)
    }

    func testEncryptDecryptWithGCM96() throws {
        try testEncryptDecryptRoundTrip(cipher: .aes256GCM96, expectedTagSize: 12)
    }

    func testEncryptDecryptWithGCM104() throws {
        try testEncryptDecryptRoundTrip(cipher: .aes256GCM104, expectedTagSize: 13)
    }

    func testEncryptDecryptWithGCM112() throws {
        try testEncryptDecryptRoundTrip(cipher: .aes256GCM112, expectedTagSize: 14)
    }

    func testEncryptDecryptWithGCM120() throws {
        try testEncryptDecryptRoundTrip(cipher: .aes256GCM120, expectedTagSize: 15)
    }

    func testEncryptDecryptWithGCM128() throws {
        try testEncryptDecryptRoundTrip(cipher: .aes256GCM128, expectedTagSize: 16)
    }

    private func testEncryptDecryptRoundTrip(cipher: Cipher, expectedTagSize: Int) throws {
        let (ciphertext, tag) = try CryptoHelper.encryptNanoTDF(
            cipher: cipher,
            key: testKey,
            iv: testIV,
            plaintext: testPlaintext,
        )

        XCTAssertEqual(tag.count, expectedTagSize, "Tag size should be \(expectedTagSize) bytes for \(cipher)")
        XCTAssertNotEqual(ciphertext, testPlaintext, "Ciphertext should differ from plaintext")

        let decrypted = try CryptoHelper.decryptNanoTDF(
            cipher: cipher,
            key: testKey,
            iv: testIV,
            ciphertext: ciphertext,
            tag: tag,
        )

        XCTAssertEqual(decrypted, testPlaintext, "Decrypted data should match original plaintext")
    }

    func testGCM128UsesCryptoKit() throws {
        let (ciphertext, tag) = try CryptoHelper.encryptNanoTDF(
            cipher: .aes256GCM128,
            key: testKey,
            iv: testIV,
            plaintext: testPlaintext,
        )

        XCTAssertEqual(tag.count, 16, "GCM128 should produce 16-byte tag")

        let nonce = try CryptoKit.AES.GCM.Nonce(data: testIV)
        let sealedBox = try CryptoKit.AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag,
        )

        let decrypted = try CryptoKit.AES.GCM.open(sealedBox, using: testKey)
        XCTAssertEqual(decrypted, testPlaintext, "CryptoKit should be able to decrypt GCM128")
    }

    func testInvalidKeySizeForEncryption() {
        let invalidKey = SymmetricKey(size: .bits128)

        XCTAssertThrowsError(
            try CryptoHelper.encryptNanoTDF(
                cipher: .aes256GCM128,
                key: invalidKey,
                iv: testIV,
                plaintext: testPlaintext,
            ),
        ) { error in
            guard case CryptoHelperError.keyDerivationFailed = error else {
                XCTFail("Expected keyDerivationFailed error for invalid key size")
                return
            }
        }
    }

    func testInvalidKeySizeForDecryption() {
        let invalidKey = SymmetricKey(size: .bits192)

        let (ciphertext, tag) = try! CryptoHelper.encryptNanoTDF(
            cipher: .aes256GCM128,
            key: testKey,
            iv: testIV,
            plaintext: testPlaintext,
        )

        XCTAssertThrowsError(
            try CryptoHelper.decryptNanoTDF(
                cipher: .aes256GCM128,
                key: invalidKey,
                iv: testIV,
                ciphertext: ciphertext,
                tag: tag,
            ),
        ) { error in
            guard case CryptoHelperError.keyDerivationFailed = error else {
                XCTFail("Expected keyDerivationFailed error for invalid key size")
                return
            }
        }
    }

    func testInvalidIVSizeForEncryption() {
        let invalidIV = Data([0x01, 0x02, 0x03, 0x04])

        XCTAssertThrowsError(
            try CryptoHelper.encryptNanoTDF(
                cipher: .aes256GCM128,
                key: testKey,
                iv: invalidIV,
                plaintext: testPlaintext,
            ),
        ) { error in
            guard case CryptoHelperError.keyDerivationFailed = error else {
                XCTFail("Expected keyDerivationFailed error for invalid IV size")
                return
            }
        }
    }

    func testInvalidIVSizeForDecryption() {
        let invalidIV = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])

        let (ciphertext, tag) = try! CryptoHelper.encryptNanoTDF(
            cipher: .aes256GCM128,
            key: testKey,
            iv: testIV,
            plaintext: testPlaintext,
        )

        XCTAssertThrowsError(
            try CryptoHelper.decryptNanoTDF(
                cipher: .aes256GCM128,
                key: testKey,
                iv: invalidIV,
                ciphertext: ciphertext,
                tag: tag,
            ),
        ) { error in
            guard case CryptoHelperError.keyDerivationFailed = error else {
                XCTFail("Expected keyDerivationFailed error for invalid IV size")
                return
            }
        }
    }

    func testTagSizeMismatchForDecryption() {
        let (ciphertext, tag) = try! CryptoHelper.encryptNanoTDF(
            cipher: .aes256GCM128,
            key: testKey,
            iv: testIV,
            plaintext: testPlaintext,
        )

        let truncatedTag = tag.prefix(8)

        XCTAssertThrowsError(
            try CryptoHelper.decryptNanoTDF(
                cipher: .aes256GCM128,
                key: testKey,
                iv: testIV,
                ciphertext: ciphertext,
                tag: truncatedTag,
            ),
        ) { error in
            guard case CryptoHelperError.keyDerivationFailed = error else {
                XCTFail("Expected keyDerivationFailed error for tag size mismatch")
                return
            }
        }
    }

    func testInvalidTagForDecryption() {
        let (ciphertext, _) = try! CryptoHelper.encryptNanoTDF(
            cipher: .aes256GCM128,
            key: testKey,
            iv: testIV,
            plaintext: testPlaintext,
        )

        let invalidTag = Data([UInt8](repeating: 0xFF, count: 16))

        XCTAssertThrowsError(
            try CryptoHelper.decryptNanoTDF(
                cipher: .aes256GCM128,
                key: testKey,
                iv: testIV,
                ciphertext: ciphertext,
                tag: invalidTag,
            ),
        ) { _ in
        }
    }

    func testModifiedCiphertextFailsDecryption() {
        let (ciphertext, tag) = try! CryptoHelper.encryptNanoTDF(
            cipher: .aes256GCM128,
            key: testKey,
            iv: testIV,
            plaintext: testPlaintext,
        )

        XCTAssertGreaterThan(ciphertext.count, 0, "Ciphertext should not be empty")

        var modifiedCiphertext = Data(ciphertext)
        modifiedCiphertext[0] ^= 0xFF

        XCTAssertThrowsError(
            try CryptoHelper.decryptNanoTDF(
                cipher: .aes256GCM128,
                key: testKey,
                iv: testIV,
                ciphertext: modifiedCiphertext,
                tag: tag,
            ),
        ) { error in
            XCTAssertNotNil(error, "Should throw an error for modified ciphertext")
        }
    }

    func testDifferentCipherModesProduceDifferentTags() throws {
        let (_, tag64) = try CryptoHelper.encryptNanoTDF(
            cipher: .aes256GCM64,
            key: testKey,
            iv: testIV,
            plaintext: testPlaintext,
        )

        let (_, tag96) = try CryptoHelper.encryptNanoTDF(
            cipher: .aes256GCM96,
            key: testKey,
            iv: testIV,
            plaintext: testPlaintext,
        )

        let (_, tag128) = try CryptoHelper.encryptNanoTDF(
            cipher: .aes256GCM128,
            key: testKey,
            iv: testIV,
            plaintext: testPlaintext,
        )

        XCTAssertNotEqual(tag64.count, tag96.count)
        XCTAssertNotEqual(tag96.count, tag128.count)
        XCTAssertNotEqual(tag64.count, tag128.count)
    }

    func testEmptyPlaintextEncryption() throws {
        let emptyPlaintext = Data()

        let (ciphertext, tag) = try CryptoHelper.encryptNanoTDF(
            cipher: .aes256GCM128,
            key: testKey,
            iv: testIV,
            plaintext: emptyPlaintext,
        )

        XCTAssertEqual(ciphertext.count, 0, "Ciphertext of empty plaintext should be empty")
        XCTAssertEqual(tag.count, 16, "Tag should still be 16 bytes for empty plaintext")

        let decrypted = try CryptoHelper.decryptNanoTDF(
            cipher: .aes256GCM128,
            key: testKey,
            iv: testIV,
            ciphertext: ciphertext,
            tag: tag,
        )

        XCTAssertEqual(decrypted, emptyPlaintext, "Decrypted empty ciphertext should be empty")
    }

    func testLargePlaintextEncryption() throws {
        let largePlaintext = Data([UInt8](repeating: 0x42, count: 1024 * 1024))

        let (ciphertext, tag) = try CryptoHelper.encryptNanoTDF(
            cipher: .aes256GCM128,
            key: testKey,
            iv: testIV,
            plaintext: largePlaintext,
        )

        XCTAssertEqual(ciphertext.count, largePlaintext.count)
        XCTAssertEqual(tag.count, 16)

        let decrypted = try CryptoHelper.decryptNanoTDF(
            cipher: .aes256GCM128,
            key: testKey,
            iv: testIV,
            ciphertext: ciphertext,
            tag: tag,
        )

        XCTAssertEqual(decrypted, largePlaintext, "Large plaintext should decrypt correctly")
    }

    func testDifferentIVsProduceDifferentCiphertexts() throws {
        let iv1 = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C])
        let iv2 = Data([0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4])

        let (ciphertext1, _) = try CryptoHelper.encryptNanoTDF(
            cipher: .aes256GCM128,
            key: testKey,
            iv: iv1,
            plaintext: testPlaintext,
        )

        let (ciphertext2, _) = try CryptoHelper.encryptNanoTDF(
            cipher: .aes256GCM128,
            key: testKey,
            iv: iv2,
            plaintext: testPlaintext,
        )

        XCTAssertNotEqual(ciphertext1, ciphertext2, "Different IVs should produce different ciphertexts")
    }

    func testDifferentKeysProduceDifferentCiphertexts() throws {
        let key1 = SymmetricKey(size: .bits256)
        let key2 = SymmetricKey(size: .bits256)

        let (ciphertext1, _) = try CryptoHelper.encryptNanoTDF(
            cipher: .aes256GCM128,
            key: key1,
            iv: testIV,
            plaintext: testPlaintext,
        )

        let (ciphertext2, _) = try CryptoHelper.encryptNanoTDF(
            cipher: .aes256GCM128,
            key: key2,
            iv: testIV,
            plaintext: testPlaintext,
        )

        XCTAssertNotEqual(ciphertext1, ciphertext2, "Different keys should produce different ciphertexts")
    }

    func testCipherModeConsistency() {
        let cipherModes: [Cipher] = [.aes256GCM64, .aes256GCM96, .aes256GCM104, .aes256GCM112, .aes256GCM120, .aes256GCM128]

        for cipher in cipherModes {
            XCTAssertNoThrow(
                try CryptoHelper.encryptNanoTDF(
                    cipher: cipher,
                    key: testKey,
                    iv: testIV,
                    plaintext: testPlaintext,
                ),
                "Cipher mode \(cipher) should support encryption",
            )
        }
    }

    func testCryptoSwiftBackedModes() throws {
        let cryptoSwiftModes: [Cipher] = [.aes256GCM64, .aes256GCM96, .aes256GCM104, .aes256GCM112, .aes256GCM120]

        for cipher in cryptoSwiftModes {
            let (ciphertext, tag) = try CryptoHelper.encryptNanoTDF(
                cipher: cipher,
                key: testKey,
                iv: testIV,
                plaintext: testPlaintext,
            )

            let decrypted = try CryptoHelper.decryptNanoTDF(
                cipher: cipher,
                key: testKey,
                iv: testIV,
                ciphertext: ciphertext,
                tag: tag,
            )

            XCTAssertEqual(decrypted, testPlaintext, "CryptoSwift-backed mode \(cipher) should work correctly")
        }
    }

    func testTagSizeForEachCipherMode() throws {
        let expectedTagSizes: [(Cipher, Int)] = [
            (.aes256GCM64, 8),
            (.aes256GCM96, 12),
            (.aes256GCM104, 13),
            (.aes256GCM112, 14),
            (.aes256GCM120, 15),
            (.aes256GCM128, 16),
        ]

        for (cipher, expectedSize) in expectedTagSizes {
            let (_, tag) = try CryptoHelper.encryptNanoTDF(
                cipher: cipher,
                key: testKey,
                iv: testIV,
                plaintext: testPlaintext,
            )

            XCTAssertEqual(tag.count, expectedSize, "Cipher \(cipher) should produce \(expectedSize)-byte tag")
        }
    }
}
