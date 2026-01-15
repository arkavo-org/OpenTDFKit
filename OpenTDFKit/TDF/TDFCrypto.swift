import CryptoKit
import CryptoSwift
import Foundation

/// Encryption mode for TDF payloads
public enum TDFEncryptionMode: String, Sendable {
    /// AES-GCM (authenticated encryption, default)
    case gcm = "GCM"
    /// AES-CBC with PKCS7 padding (FairPlay Streaming compatible)
    case cbc = "CBC"
}

/// Symmetric key size for TDF Archive encryption.
/// AES-128 is required for FairPlay Streaming compatibility.
public enum TDFKeySize: Sendable {
    /// 128-bit key (16 bytes) - FairPlay Streaming compatible
    case bits128
    /// 256-bit key (32 bytes) - default, higher security
    case bits256

    /// Number of bytes for this key size
    public var byteCount: Int {
        switch self {
        case .bits128: 16
        case .bits256: 32
        }
    }

    /// Algorithm string for TDF manifest (GCM mode, for backward compatibility)
    public var algorithm: String {
        algorithm(mode: .gcm)
    }

    /// Algorithm string for TDF manifest with specified mode
    public func algorithm(mode: TDFEncryptionMode) -> String {
        switch (self, mode) {
        case (.bits128, .gcm): "AES-128-GCM"
        case (.bits128, .cbc): "AES-128-CBC"
        case (.bits256, .gcm): "AES-256-GCM"
        case (.bits256, .cbc): "AES-256-CBC"
        }
    }
}

extension Data {
    mutating func secureZero() {
        withUnsafeMutableBytes { buffer in
            guard let baseAddress = buffer.baseAddress else { return }
            memset_s(baseAddress, buffer.count, 0, buffer.count)
        }
    }
}

public enum TDFCrypto {
    /// Generate a symmetric key for TDF encryption.
    /// - Parameter size: Key size (default: .bits256 for AES-256-GCM)
    /// - Returns: A new symmetric key of the specified size
    public static func generateSymmetricKey(size: TDFKeySize = .bits256) throws -> SymmetricKey {
        let keyData = try randomBytes(count: size.byteCount)
        return SymmetricKey(data: keyData)
    }

    public static func randomBytes(count: Int) throws -> Data {
        var generator = SystemRandomNumberGenerator()
        let randomBytes = (0 ..< count).map { _ in UInt8.random(in: UInt8.min ... UInt8.max, using: &generator) }
        return Data(randomBytes)
    }

    public static func encryptPayload(plaintext: Data, symmetricKey: SymmetricKey) throws -> (iv: Data, cipherText: Data, authenticationTag: Data) {
        let nonceData = try randomBytes(count: 12)
        let nonce = try CryptoKit.AES.GCM.Nonce(data: nonceData)
        let sealed = try CryptoKit.AES.GCM.seal(plaintext, using: symmetricKey, nonce: nonce)
        return (Data(nonce), sealed.ciphertext, Data(sealed.tag))
    }

    public static func decryptPayload(ciphertext: Data, iv: Data, tag: Data, symmetricKey: SymmetricKey) throws -> Data {
        let nonce = try CryptoKit.AES.GCM.Nonce(data: iv)
        let sealed = try CryptoKit.AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        return try CryptoKit.AES.GCM.open(sealed, using: symmetricKey)
    }

    // MARK: - AES-CBC Encryption (FairPlay Compatible)

    /// Encrypt payload using AES-CBC with PKCS7 padding.
    /// This mode is compatible with FairPlay Streaming.
    /// - Parameters:
    ///   - plaintext: Data to encrypt
    ///   - symmetricKey: Symmetric key (16 or 32 bytes)
    /// - Returns: Tuple of (iv, ciphertext)
    public static func encryptPayloadCBC(plaintext: Data, symmetricKey: SymmetricKey) throws -> (iv: Data, cipherText: Data) {
        let ivData = try randomBytes(count: 16) // CBC uses 16-byte IV
        let keyData = symmetricKey.withUnsafeBytes { Data($0) }

        let aes = try CryptoSwift.AES(
            key: Array(keyData),
            blockMode: CryptoSwift.CBC(iv: Array(ivData)),
            padding: .pkcs7,
        )

        let ciphertext = try aes.encrypt(Array(plaintext))
        return (ivData, Data(ciphertext))
    }

    /// Decrypt payload using AES-CBC with PKCS7 padding.
    /// - Parameters:
    ///   - ciphertext: Encrypted data
    ///   - iv: Initialization vector (16 bytes)
    ///   - symmetricKey: Symmetric key
    /// - Returns: Decrypted plaintext
    public static func decryptPayloadCBC(ciphertext: Data, iv: Data, symmetricKey: SymmetricKey) throws -> Data {
        guard iv.count == 16 else {
            throw TDFCryptoError.invalidIVSize(expected: 16, actual: iv.count)
        }

        let keyData = symmetricKey.withUnsafeBytes { Data($0) }

        let aes = try CryptoSwift.AES(
            key: Array(keyData),
            blockMode: CryptoSwift.CBC(iv: Array(iv)),
            padding: .pkcs7,
        )

        let plaintext = try aes.decrypt(Array(ciphertext))
        return Data(plaintext)
    }

    public static func policyBinding(policy: Data, symmetricKey: SymmetricKey) -> TDFPolicyBinding {
        let hmac = HMAC<SHA256>.authenticationCode(for: policy, using: symmetricKey)
        let hash = Data(hmac).base64EncodedString()
        return TDFPolicyBinding(alg: "HS256", hash: hash)
    }

    public static func data(from symmetricKey: SymmetricKey) -> Data {
        symmetricKey.withUnsafeBytes { Data($0) }
    }

    public static func segmentSignature(segmentCiphertext: Data, symmetricKey: SymmetricKey) -> Data {
        let hmac = HMAC<SHA256>.authenticationCode(for: segmentCiphertext, using: symmetricKey)
        return Data(hmac)
    }

    public static func segmentSignatureGMAC(segmentCiphertext: Data, symmetricKey: SymmetricKey) throws -> Data {
        let nonce = try AES.GCM.Nonce(data: Data(count: 12))
        let sealed = try AES.GCM.seal(Data(), using: symmetricKey, nonce: nonce, authenticating: segmentCiphertext)
        return Data(sealed.tag)
    }

    public static func wrapSymmetricKeyWithRSA(publicKeyPEM: String, symmetricKey: SymmetricKey) throws -> String {
        let keyData = symmetricKey.withUnsafeBytes { rawBuffer -> Data in
            Data(rawBuffer)
        }
        let publicKey = try loadRSAPublicKey(fromPEM: publicKeyPEM)
        var error: Unmanaged<CFError>?
        guard let encrypted = SecKeyCreateEncryptedData(
            publicKey,
            .rsaEncryptionOAEPSHA256,
            keyData as CFData,
            &error,
        ) as Data? else {
            throw TDFCryptoError.keyWrapFailed(error?.takeRetainedValue())
        }
        return encrypted.base64EncodedString()
    }

    public static func unwrapSymmetricKeyWithRSA(privateKeyPEM: String, wrappedKey: String) throws -> SymmetricKey {
        let privateKey = try loadRSAPrivateKey(fromPEM: privateKeyPEM)
        guard let wrappedData = Data(base64Encoded: wrappedKey) else {
            throw TDFCryptoError.invalidWrappedKey
        }
        var error: Unmanaged<CFError>?
        guard var decrypted = SecKeyCreateDecryptedData(
            privateKey,
            .rsaEncryptionOAEPSHA256,
            wrappedData as CFData,
            &error,
        ) as Data? else {
            throw TDFCryptoError.keyUnwrapFailed(error?.takeRetainedValue())
        }

        defer {
            decrypted.secureZero()
        }

        return SymmetricKey(data: decrypted)
    }

    public static func loadRSAPublicKey(fromPEM pem: String) throws -> SecKey {
        let stripped = pem
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard let data = Data(base64Encoded: stripped) else {
            throw TDFCryptoError.invalidPEM
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else {
            throw TDFCryptoError.invalidKeyData(error?.takeRetainedValue())
        }

        try validateRSAKeySize(key, minimumBits: 2048)
        return key
    }

    public static func loadRSAPrivateKey(fromPEM pem: String) throws -> SecKey {
        let stripped = pem
            .replacingOccurrences(of: "-----BEGIN RSA PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END RSA PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----BEGIN PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard let data = Data(base64Encoded: stripped) else {
            throw TDFCryptoError.invalidPEM
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else {
            throw TDFCryptoError.invalidKeyData(error?.takeRetainedValue())
        }

        try validateRSAKeySize(key, minimumBits: 2048)
        return key
    }

    private static func validateRSAKeySize(_ key: SecKey, minimumBits: Int) throws {
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              let keySize = attributes[kSecAttrKeySizeInBits as String] as? Int
        else {
            throw TDFCryptoError.cannotDetermineKeySize
        }

        guard keySize >= minimumBits else {
            throw TDFCryptoError.weakKey(keySize: keySize, minimum: minimumBits)
        }
    }
}

public enum TDFCryptoError: Error, CustomStringConvertible {
    case invalidPEM
    case invalidKeyData(CFError?)
    case keyWrapFailed(CFError?)
    case keyUnwrapFailed(CFError?)
    case invalidWrappedKey
    case weakKey(keySize: Int, minimum: Int)
    case cannotDetermineKeySize
    case invalidIVSize(expected: Int, actual: Int)
    case cbcEncryptionFailed(String)
    case cbcDecryptionFailed(String)

    public var description: String {
        switch self {
        case .invalidPEM:
            return "Invalid PEM format"
        case let .invalidKeyData(error):
            if let error {
                return "Invalid key data: \(error.localizedDescription)"
            }
            return "Invalid key data"
        case let .keyWrapFailed(error):
            if let error {
                return "Key wrapping failed: \(error.localizedDescription)"
            }
            return "Key wrapping failed"
        case let .keyUnwrapFailed(error):
            if let error {
                return "Key unwrapping failed: \(error.localizedDescription)"
            }
            return "Key unwrapping failed"
        case .invalidWrappedKey:
            return "Invalid wrapped key format"
        case let .weakKey(keySize, minimum):
            #if DEBUG
                return "RSA key size \(keySize) bits is too weak. Minimum required: \(minimum) bits"
            #else
                return "Cryptographic key does not meet security requirements"
            #endif
        case .cannotDetermineKeySize:
            return "Unable to validate key strength"
        case let .invalidIVSize(expected, actual):
            return "Invalid IV size: expected \(expected) bytes, got \(actual)"
        case let .cbcEncryptionFailed(reason):
            return "AES-CBC encryption failed: \(reason)"
        case let .cbcDecryptionFailed(reason):
            return "AES-CBC decryption failed: \(reason)"
        }
    }
}
