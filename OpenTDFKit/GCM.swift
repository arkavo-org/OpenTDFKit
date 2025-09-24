import CryptoKit
import CryptoSwift
import Foundation

/// GCM helper for NanoTDF - supports all 6 cipher modes defined in the spec
public enum GCM {

    public enum Error: Swift.Error, CustomStringConvertible {
        case invalidKeySize(Int)
        case invalidIVSize(Int)
        case unsupportedCipher

        public var description: String {
            switch self {
            case .invalidKeySize(let size):
                return "Invalid key size: \(size) bytes (expected 32 for AES-256)"
            case .invalidIVSize(let size):
                return "Invalid IV size: \(size) bytes (expected 12)"
            case .unsupportedCipher:
                return "Unsupported cipher mode"
            }
        }
    }

    /// Decrypt NanoTDF payload using the appropriate GCM implementation based on tag size
    /// - Parameters:
    ///   - cipher: The NanoTDF cipher mode
    ///   - key: The symmetric key (SymmetricKey for CryptoKit compatibility)
    ///   - iv: The IV/nonce (12 bytes)
    ///   - ciphertext: The encrypted payload
    ///   - tag: The authentication tag
    /// - Returns: Decrypted plaintext
    public static func decryptNanoTDF(
        cipher: Cipher,
        key: SymmetricKey,
        iv: Data,
        ciphertext: Data,
        tag: Data
    ) throws -> Data {
        // For 128-bit tags, use CryptoKit (it's faster)
        if cipher == .aes256GCM128 {
            let nonce = try AES.GCM.Nonce(data: iv)
            let sealedBox = try AES.GCM.SealedBox(
                nonce: nonce,
                ciphertext: ciphertext,
                tag: tag
            )
            return try AES.GCM.open(sealedBox, using: key)
        }

        // For all other tag sizes, use CryptoSwift
        let keyData = key.withUnsafeBytes { Data($0) }
        return try decryptWithCryptoSwift(
            key: keyData,
            iv: iv,
            ciphertext: ciphertext,
            tag: tag,
            tagLength: tagSize(for: cipher)
        )
    }

    /// Encrypt NanoTDF payload using the appropriate GCM implementation based on tag size
    /// - Parameters:
    ///   - cipher: The NanoTDF cipher mode
    ///   - key: The symmetric key
    ///   - iv: The IV/nonce (12 bytes)
    ///   - plaintext: The data to encrypt
    /// - Returns: Tuple of (ciphertext, tag)
    public static func encryptNanoTDF(
        cipher: Cipher,
        key: SymmetricKey,
        iv: Data,
        plaintext: Data
    ) throws -> (ciphertext: Data, tag: Data) {
        // For 128-bit tags, use CryptoKit
        if cipher == .aes256GCM128 {
            let nonce = try AES.GCM.Nonce(data: iv)
            let sealedBox = try AES.GCM.seal(plaintext, using: key, nonce: nonce)
            return (sealedBox.ciphertext, sealedBox.tag)
        }

        // For all other tag sizes, use CryptoSwift
        let keyData = key.withUnsafeBytes { Data($0) }
        return try encryptWithCryptoSwift(
            key: keyData,
            iv: iv,
            plaintext: plaintext,
            tagLength: tagSize(for: cipher)
        )
    }

    /// Get the tag size in bytes for a given NanoTDF cipher
    private static func tagSize(for cipher: Cipher) -> Int {
        switch cipher {
        case .aes256GCM64: return 8
        case .aes256GCM96: return 12
        case .aes256GCM104: return 13
        case .aes256GCM112: return 14
        case .aes256GCM120: return 15
        case .aes256GCM128: return 16
        }
    }

    // MARK: - CryptoSwift Implementation

    private static func decryptWithCryptoSwift(
        key: Data,
        iv: Data,
        ciphertext: Data,
        tag: Data,
        tagLength: Int
    ) throws -> Data {
        guard key.count == 32 else {
            throw Error.invalidKeySize(key.count)
        }
        guard iv.count == 12 else {
            throw Error.invalidIVSize(iv.count)
        }

        // Configure GCM with the specific tag length
        let gcm = CryptoSwift.GCM(
            iv: Array(iv),
            additionalAuthenticatedData: nil,
            tagLength: tagLength
        )

        // IMPORTANT: Set the authentication tag for decryption (detached tag model)
        gcm.authenticationTag = Array(tag)

        let aes = try CryptoSwift.AES(
            key: Array(key),
            blockMode: gcm,
            padding: .noPadding
        )

        // Decrypt just the ciphertext (NOT combined with tag)
        let plaintextBytes = try aes.decrypt(Array(ciphertext))
        return Data(plaintextBytes)
    }

    private static func encryptWithCryptoSwift(
        key: Data,
        iv: Data,
        plaintext: Data,
        tagLength: Int
    ) throws -> (ciphertext: Data, tag: Data) {
        guard key.count == 32 else {
            throw Error.invalidKeySize(key.count)
        }
        guard iv.count == 12 else {
            throw Error.invalidIVSize(iv.count)
        }

        // Configure GCM with the specific tag length
        let gcm = CryptoSwift.GCM(
            iv: Array(iv),
            additionalAuthenticatedData: nil,
            tagLength: tagLength
        )

        let aes = try CryptoSwift.AES(
            key: Array(key),
            blockMode: gcm,
            padding: .noPadding
        )

        // CryptoSwift returns just the ciphertext (same length as plaintext)
        let ciphertextBytes = try aes.encrypt(Array(plaintext))

        // Get the authentication tag separately (detached tag model)
        guard let tagBytes = gcm.authenticationTag else {
            throw Error.unsupportedCipher
        }

        return (Data(ciphertextBytes), Data(tagBytes))
    }
}