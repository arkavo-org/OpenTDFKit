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

    /// Decrypt AES-GCM payload with combined IV + ciphertext + tag format
    /// - Parameters:
    ///   - combinedPayload: Data containing IV (12 bytes) + ciphertext + tag (16 bytes)
    ///   - symmetricKey: The decryption key
    /// - Returns: Decrypted plaintext
    public static func decryptCombinedPayload(
        _ combinedPayload: Data,
        symmetricKey: SymmetricKey,
    ) throws -> Data {
        let ivSize = 12
        let tagSize = 16
        let minSize = ivSize + tagSize

        guard combinedPayload.count >= minSize else {
            throw TDFCryptoError.decryptionFailed("Malformed payload: insufficient data")
        }

        let iv = combinedPayload.prefix(ivSize)
        let ciphertext = combinedPayload.dropFirst(ivSize).dropLast(tagSize)
        let tag = combinedPayload.suffix(tagSize)

        return try decryptPayload(
            ciphertext: Data(ciphertext),
            iv: Data(iv),
            tag: Data(tag),
            symmetricKey: symmetricKey,
        )
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

    // MARK: - EC Key Wrapping (ECIES)

    /// Wrap a symmetric key using EC (ECIES: ECDH + HKDF + AES-GCM).
    /// This generates an ephemeral key pair and uses ECDH with the recipient's public key.
    /// - Parameters:
    ///   - publicKeyPEM: The recipient's EC public key in PEM format
    ///   - symmetricKey: The symmetric key to wrap
    ///   - curve: The EC curve to use (default: P-256)
    /// - Returns: ECWrappedKeyResult containing the wrapped key and ephemeral public key
    public static func wrapSymmetricKeyWithEC(
        publicKeyPEM: String,
        symmetricKey: SymmetricKey,
        curve: TDFECCurve = .p256,
    ) throws -> ECWrappedKeyResult {
        switch curve {
        case .p256:
            try wrapWithP256(publicKeyPEM: publicKeyPEM, symmetricKey: symmetricKey)
        case .p384:
            try wrapWithP384(publicKeyPEM: publicKeyPEM, symmetricKey: symmetricKey)
        case .p521:
            try wrapWithP521(publicKeyPEM: publicKeyPEM, symmetricKey: symmetricKey)
        }
    }

    /// Unwrap a symmetric key using EC (ECIES: ECDH + HKDF + AES-GCM).
    /// - Parameters:
    ///   - privateKey: The recipient's private key for ECDH
    ///   - wrappedKey: The wrapped key data (base64-encoded nonce + ciphertext + tag)
    ///   - ephemeralPublicKey: The sender's ephemeral public key (PEM or base64 SEC1 compressed)
    ///   - curve: The EC curve used
    /// - Returns: The unwrapped symmetric key
    public static func unwrapSymmetricKeyWithEC(
        privateKey: P256.KeyAgreement.PrivateKey,
        wrappedKey: String,
        ephemeralPublicKey ephemeralKeyString: String,
    ) throws -> SymmetricKey {
        guard let wrappedData = Data(base64Encoded: wrappedKey) else {
            throw TDFCryptoError.invalidWrappedKey
        }

        // Parse ephemeral public key - supports both PEM and base64 SEC1 (compressed/uncompressed)
        let ephemeralPublicKey: P256.KeyAgreement.PublicKey
        if ephemeralKeyString.contains("-----BEGIN") {
            // PEM format (legacy)
            ephemeralPublicKey = try loadECPublicKeyP256(fromPEM: ephemeralKeyString)
        } else {
            // Base64 SEC1 format (compressed or uncompressed)
            guard let keyData = Data(base64Encoded: ephemeralKeyString) else {
                throw TDFCryptoError.ecKeyAgreementFailed("Invalid ephemeral key encoding")
            }
            // Try compressed first (33 bytes), then uncompressed (65 bytes)
            if keyData.count == 33 {
                ephemeralPublicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: keyData)
            } else {
                ephemeralPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: keyData)
            }
        }

        // Perform ECDH to get shared secret
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)

        // Derive wrapping key using HKDF-SHA256 (empty salt and info for TDF compatibility)
        let wrapKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data(),
            outputByteCount: 32,
        )

        // Unwrap using AES-GCM (format: nonce[12] + ciphertext + tag[16])
        guard wrappedData.count > 28 else {
            throw TDFCryptoError.invalidWrappedKey
        }

        let sealedBox = try AES.GCM.SealedBox(combined: wrappedData)
        var decryptedKey = try AES.GCM.open(sealedBox, using: wrapKey)

        defer {
            decryptedKey.secureZero()
        }

        return SymmetricKey(data: decryptedKey)
    }

    // MARK: - P-256 EC Wrapping

    private static func wrapWithP256(publicKeyPEM: String, symmetricKey: SymmetricKey) throws -> ECWrappedKeyResult {
        // Load recipient's public key
        let recipientPublicKey = try loadECPublicKeyP256(fromPEM: publicKeyPEM)

        // Generate ephemeral key pair
        let ephemeralPrivateKey = P256.KeyAgreement.PrivateKey()
        let ephemeralPublicKey = ephemeralPrivateKey.publicKey

        // Perform ECDH to get shared secret
        let sharedSecret = try ephemeralPrivateKey.sharedSecretFromKeyAgreement(with: recipientPublicKey)

        // Derive wrapping key using HKDF-SHA256 (empty salt and info for TDF compatibility)
        let wrapKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data(),
            outputByteCount: 32,
        )

        // Extract key data
        let keyData = symmetricKey.withUnsafeBytes { Data($0) }

        // Wrap using AES-GCM
        let nonce = try AES.GCM.Nonce(data: randomBytes(count: 12))
        let sealed = try AES.GCM.seal(keyData, using: wrapKey, nonce: nonce)

        // Combined format: nonce + ciphertext + tag
        let wrappedKey = sealed.combined!.base64EncodedString()

        // Convert ephemeral public key to compressed SEC1 format (33 bytes for P-256)
        // Much smaller than PEM (~140 bytes) or uncompressed (65 bytes)
        let ephemeralCompressed = ephemeralPublicKey.compressedRepresentation.base64EncodedString()

        return ECWrappedKeyResult(wrappedKey: wrappedKey, ephemeralPublicKey: ephemeralCompressed)
    }

    // MARK: - P-384 EC Wrapping

    private static func wrapWithP384(publicKeyPEM: String, symmetricKey: SymmetricKey) throws -> ECWrappedKeyResult {
        let recipientPublicKey = try loadECPublicKeyP384(fromPEM: publicKeyPEM)

        let ephemeralPrivateKey = P384.KeyAgreement.PrivateKey()
        let ephemeralPublicKey = ephemeralPrivateKey.publicKey

        let sharedSecret = try ephemeralPrivateKey.sharedSecretFromKeyAgreement(with: recipientPublicKey)

        let wrapKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data(),
            outputByteCount: 32,
        )

        let keyData = symmetricKey.withUnsafeBytes { Data($0) }

        let nonce = try AES.GCM.Nonce(data: randomBytes(count: 12))
        let sealed = try AES.GCM.seal(keyData, using: wrapKey, nonce: nonce)

        let wrappedKey = sealed.combined!.base64EncodedString()
        // Compressed SEC1 format (49 bytes for P-384)
        let ephemeralCompressed = ephemeralPublicKey.compressedRepresentation.base64EncodedString()

        return ECWrappedKeyResult(wrappedKey: wrappedKey, ephemeralPublicKey: ephemeralCompressed)
    }

    // MARK: - P-521 EC Wrapping

    private static func wrapWithP521(publicKeyPEM: String, symmetricKey: SymmetricKey) throws -> ECWrappedKeyResult {
        let recipientPublicKey = try loadECPublicKeyP521(fromPEM: publicKeyPEM)

        let ephemeralPrivateKey = P521.KeyAgreement.PrivateKey()
        let ephemeralPublicKey = ephemeralPrivateKey.publicKey

        let sharedSecret = try ephemeralPrivateKey.sharedSecretFromKeyAgreement(with: recipientPublicKey)

        let wrapKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data(),
            outputByteCount: 32,
        )

        let keyData = symmetricKey.withUnsafeBytes { Data($0) }

        let nonce = try AES.GCM.Nonce(data: randomBytes(count: 12))
        let sealed = try AES.GCM.seal(keyData, using: wrapKey, nonce: nonce)

        let wrappedKey = sealed.combined!.base64EncodedString()
        // Compressed SEC1 format (67 bytes for P-521)
        let ephemeralCompressed = ephemeralPublicKey.compressedRepresentation.base64EncodedString()

        return ECWrappedKeyResult(wrappedKey: wrappedKey, ephemeralPublicKey: ephemeralCompressed)
    }

    // MARK: - EC Public Key Loading

    /// Load a P-256 EC public key from PEM format
    public static func loadECPublicKeyP256(fromPEM pem: String) throws -> P256.KeyAgreement.PublicKey {
        let stripped = pem
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard let data = Data(base64Encoded: stripped) else {
            throw TDFCryptoError.invalidPEM
        }

        do {
            return try P256.KeyAgreement.PublicKey(derRepresentation: data)
        } catch {
            throw TDFCryptoError.ecKeyAgreementFailed("Failed to parse P-256 public key: \(error.localizedDescription)")
        }
    }

    /// Load a P-384 EC public key from PEM format
    public static func loadECPublicKeyP384(fromPEM pem: String) throws -> P384.KeyAgreement.PublicKey {
        let stripped = pem
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard let data = Data(base64Encoded: stripped) else {
            throw TDFCryptoError.invalidPEM
        }

        do {
            return try P384.KeyAgreement.PublicKey(derRepresentation: data)
        } catch {
            throw TDFCryptoError.ecKeyAgreementFailed("Failed to parse P-384 public key: \(error.localizedDescription)")
        }
    }

    /// Load a P-521 EC public key from PEM format
    public static func loadECPublicKeyP521(fromPEM pem: String) throws -> P521.KeyAgreement.PublicKey {
        let stripped = pem
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard let data = Data(base64Encoded: stripped) else {
            throw TDFCryptoError.invalidPEM
        }

        do {
            return try P521.KeyAgreement.PublicKey(derRepresentation: data)
        } catch {
            throw TDFCryptoError.ecKeyAgreementFailed("Failed to parse P-521 public key: \(error.localizedDescription)")
        }
    }
}

/// Result of EC key wrapping containing wrapped key and ephemeral public key
public struct ECWrappedKeyResult: Sendable {
    /// The wrapped symmetric key (nonce + ciphertext + tag)
    public let wrappedKey: String
    /// The ephemeral public key in PEM format
    public let ephemeralPublicKey: String
}

/// Supported EC curves for TDF3 EC key wrapping
public enum TDFECCurve: String, Sendable {
    case p256 = "ec:secp256r1"
    case p384 = "ec:secp384r1"
    case p521 = "ec:secp521r1"

    /// The size of compressed public key in bytes
    public var compressedKeySize: Int {
        switch self {
        case .p256: 33
        case .p384: 49
        case .p521: 67
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
    case ecKeyAgreementFailed(String)
    case unsupportedCurve(String)
    case decryptionFailed(String)

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
        case let .ecKeyAgreementFailed(reason):
            return "EC key agreement failed: \(reason)"
        case let .unsupportedCurve(curve):
            return "Unsupported EC curve: \(curve)"
        case let .decryptionFailed(reason):
            return "Decryption failed: \(reason)"
        }
    }
}
