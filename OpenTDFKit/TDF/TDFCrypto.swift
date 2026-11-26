import CommonCrypto
import CryptoKit
import Foundation
import Security

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
        var keyData = try randomBytes(count: size.byteCount)
        defer { keyData.secureZero() }
        return SymmetricKey(data: keyData)
    }

    public static func randomBytes(count: Int) throws -> Data {
        var bytes = Data(count: count)
        let status = bytes.withUnsafeMutableBytes { buffer -> OSStatus in
            guard let baseAddress = buffer.baseAddress else {
                return errSecAllocate
            }
            return SecRandomCopyBytes(kSecRandomDefault, count, baseAddress)
        }
        guard status == errSecSuccess else {
            throw TDFCryptoError.randomGenerationFailed(status)
        }
        return bytes
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

    /// Encrypt payload using AES-CBC with PKCS7 padding via hardware-accelerated CommonCrypto.
    /// This mode is compatible with FairPlay Streaming.
    /// - Parameters:
    ///   - plaintext: Data to encrypt
    ///   - symmetricKey: Symmetric key (16 or 32 bytes)
    /// - Returns: Tuple of (iv, ciphertext)
    public static func encryptPayloadCBC(plaintext: Data, symmetricKey: SymmetricKey) throws -> (iv: Data, cipherText: Data) {
        let bitCount = symmetricKey.bitCount
        guard bitCount == 128 || bitCount == 192 || bitCount == 256 else {
            throw TDFCryptoError.cbcEncryptionFailed("Unsupported AES key size: \(bitCount) bits")
        }

        let ivData = try randomBytes(count: kCCBlockSizeAES128) // CBC uses 16-byte IV
        let ciphertext = try aesCBCTransform(
            operation: CCOperation(kCCEncrypt),
            input: plaintext,
            iv: ivData,
            symmetricKey: symmetricKey,
        )
        return (ivData, ciphertext)
    }

    /// Decrypt payload using AES-CBC with PKCS7 padding via hardware-accelerated CommonCrypto.
    /// - Parameters:
    ///   - ciphertext: Encrypted data
    ///   - iv: Initialization vector (16 bytes)
    ///   - symmetricKey: Symmetric key (16 or 32 bytes)
    /// - Returns: Decrypted plaintext
    public static func decryptPayloadCBC(ciphertext: Data, iv: Data, symmetricKey: SymmetricKey) throws -> Data {
        guard iv.count == kCCBlockSizeAES128 else {
            throw TDFCryptoError.invalidIVSize(expected: kCCBlockSizeAES128, actual: iv.count)
        }
        let bitCount = symmetricKey.bitCount
        guard bitCount == 128 || bitCount == 192 || bitCount == 256 else {
            throw TDFCryptoError.cbcDecryptionFailed("Unsupported AES key size: \(bitCount) bits")
        }
        guard !ciphertext.isEmpty, ciphertext.count % kCCBlockSizeAES128 == 0 else {
            throw TDFCryptoError.cbcDecryptionFailed("Ciphertext length must be a non-zero multiple of 16 bytes")
        }

        return try aesCBCTransform(
            operation: CCOperation(kCCDecrypt),
            input: ciphertext,
            iv: iv,
            symmetricKey: symmetricKey,
        )
    }

    private static func aesCBCTransform(
        operation: CCOperation,
        input: Data,
        iv: Data,
        symmetricKey: SymmetricKey,
    ) throws -> Data {
        let isEncrypt = operation == CCOperation(kCCEncrypt)
        // Use CommonCrypto PKCS7 padding on encrypt; on decrypt use raw CBC + constant-time
        // PKCS7 validation so malformed padding is deterministically rejected across all OS versions.
        let options: CCOptions = isEncrypt ? CCOptions(kCCOptionPKCS7Padding) : 0
        let outputCapacity = isEncrypt ? (input.count + kCCBlockSizeAES128) : input.count
        var output = Data(count: outputCapacity)
        var bytesMoved = 0

        let status: CCCryptorStatus = symmetricKey.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                input.withUnsafeBytes { inBytes in
                    output.withUnsafeMutableBytes { outBytes in
                        CCCrypt(
                            operation,
                            CCAlgorithm(kCCAlgorithmAES),
                            options,
                            keyBytes.baseAddress,
                            keyBytes.count,
                            ivBytes.baseAddress,
                            inBytes.baseAddress,
                            input.count,
                            outBytes.baseAddress,
                            outputCapacity,
                            &bytesMoved,
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            output.secureZero()
            if isEncrypt {
                throw TDFCryptoError.cbcEncryptionFailed("CommonCrypto status \(status)")
            } else {
                throw TDFCryptoError.cbcDecryptionFailed("CommonCrypto status \(status)")
            }
        }

        if isEncrypt {
            output.removeSubrange(bytesMoved ..< output.count)
            return output
        }

        guard bytesMoved == input.count, bytesMoved >= kCCBlockSizeAES128 else {
            output.secureZero()
            throw TDFCryptoError.cbcDecryptionFailed("Unexpected decrypted byte count")
        }

        // Constant-time PKCS7 padding verification over the final 16-byte block.
        let padByte = output[bytesMoved - 1]
        let padLen = Int(padByte)
        var bad: UInt8 = (padLen >= 1 && padLen <= kCCBlockSizeAES128) ? 0 : 1
        let clampedPadLen = min(max(padLen, 0), kCCBlockSizeAES128)
        for offset in 0 ..< kCCBlockSizeAES128 {
            let mask = UInt8(truncatingIfNeeded: (offset &- clampedPadLen) >> (Int.bitWidth - 1))
            let diff = output[bytesMoved - 1 - offset] ^ padByte
            bad |= diff & mask
        }
        guard bad == 0 else {
            output.secureZero()
            throw TDFCryptoError.cbcDecryptionFailed("Invalid PKCS7 padding")
        }

        output.removeSubrange((bytesMoved - padLen) ..< bytesMoved)
        return output
    }

    /// Compute the Standard TDF policy binding: `Base64(HMAC-SHA256(DEK, Base64(policyJSON)))`,
    /// 44 characters decoding to the raw 32-byte HMAC (OpenTDF spec
    /// `schema/OpenTDF/key_access_object.md`, `concepts/security.md`).
    ///
    /// The Go SDK's legacy `Base64(hex(HMAC))` form is not written. Rewrapping
    /// these TDFs needs a KAS that accepts the spec form (opentdf/platform#4081).
    public static func policyBinding(policy: Data, symmetricKey: SymmetricKey) -> TDFPolicyBinding {
        let policyBase64 = Data(policy.base64EncodedString().utf8)
        let hmac = HMAC<SHA256>.authenticationCode(for: policyBase64, using: symmetricKey)
        return TDFPolicyBinding(alg: "HS256", hash: Data(hmac).base64EncodedString())
    }

    /// Verifies a Standard TDF `policyBinding` against `policyBase64` (the manifest's
    /// base64-encoded policy string) and `symmetricKey` (the DEK or KAO key share).
    /// Accepts spec-form `Base64(raw HMAC-SHA256)` (32 bytes) and legacy Go SDK
    /// `Base64(hex(HMAC-SHA256))` (64 ASCII hex bytes), compared in constant time.
    public static func verifyPolicyBinding(
        _ binding: TDFPolicyBinding,
        policyBase64: String,
        symmetricKey: SymmetricKey,
    ) -> Bool {
        guard binding.alg.isEmpty || binding.alg.uppercased() == "HS256",
              !policyBase64.isEmpty,
              let decodedHash = Data(base64Encoded: binding.hash)
        else {
            return false
        }
        let expectedRaw = Data(HMAC<SHA256>.authenticationCode(
            for: Data(policyBase64.utf8),
            using: symmetricKey,
        ))
        if decodedHash.count == expectedRaw.count {
            return CryptoHelper.constantTimeEquals(decodedHash, expectedRaw)
        }
        if decodedHash.count == expectedRaw.count * 2 {
            let expectedHex = Data(expectedRaw.hexEncodedString().utf8)
            return CryptoHelper.constantTimeEquals(decodedHash, expectedHex)
        }
        return false
    }

    public static func data(from symmetricKey: SymmetricKey) -> Data {
        symmetricKey.withUnsafeBytes { Data($0) }
    }

    /// HS256 root/segment signature: raw HMAC-SHA256 digest (32 bytes).
    public static func segmentSignature(segmentCiphertext: Data, symmetricKey: SymmetricKey) -> Data {
        let hmac = HMAC<SHA256>.authenticationCode(for: segmentCiphertext, using: symmetricKey)
        return Data(hmac)
    }

    /// OpenTDF "GMAC" segment integrity for AES-GCM payloads is **not** a separate
    /// MAC — it is the last 16 bytes of the encrypted segment (the AES-GCM tag).
    /// Matches go SDK `calculateSignature` with GMAC + hexless (4.3.0).
    ///
    /// - Parameter encryptedSegment: IV (12) + ciphertext + tag (16)
    /// - Returns: 16-byte GCM tag
    public static func segmentSignatureGMAC(encryptedSegment: Data) throws -> Data {
        let tagSize = 16
        guard encryptedSegment.count >= tagSize else {
            throw TDFCryptoError.decryptionFailed(
                "Encrypted segment too short for GMAC (\(encryptedSegment.count) < \(tagSize))",
            )
        }
        return Data(encryptedSegment.suffix(tagSize))
    }

    /// Manifest segment hash string for hexless TDF 4.3.0: `base64(raw GMAC/tag)`.
    public static func segmentHashBase64GMAC(encryptedSegment: Data) throws -> String {
        try segmentSignatureGMAC(encryptedSegment: encryptedSegment).base64EncodedString()
    }

    /// Root signature for hexless TDF 4.3.0: `base64(HMAC-SHA256(DEK, concat(raw segment sigs)))`.
    public static func rootSignatureBase64(
        rawSegmentSignatures: [Data],
        symmetricKey: SymmetricKey,
    ) -> String {
        let aggregate = rawSegmentSignatures.reduce(into: Data()) { $0.append($1) }
        let hmac = HMAC<SHA256>.authenticationCode(for: aggregate, using: symmetricKey)
        return Data(hmac).base64EncodedString()
    }

    /// Legacy helper kept for call sites that previously computed a synthetic GMAC.
    /// Prefer `segmentSignatureGMAC(encryptedSegment:)` for OpenTDF interop.
    @available(*, deprecated, message: "Use segmentSignatureGMAC(encryptedSegment:) — OpenTDF GMAC is the AES-GCM tag")
    public static func segmentSignatureGMAC(segmentCiphertext: Data, symmetricKey _: SymmetricKey) throws -> Data {
        try segmentSignatureGMAC(encryptedSegment: segmentCiphertext)
    }

    /// Wrap the payload DEK with the KAS RSA public key.
    ///
    /// Uses RSA-OAEP with **SHA-1** to match the OpenTDF platform / go SDK
    /// (`rsa.EncryptOAEP(sha1.New(), …)`). SHA-256 OAEP is not interoperable
    /// with current KAS unwrap and surfaces as rewrap failures ("access denied"
    /// / "bad request" after DEK decrypt fails).
    public static func wrapSymmetricKeyWithRSA(publicKeyPEM: String, symmetricKey: SymmetricKey) throws -> String {
        var keyData = symmetricKey.withUnsafeBytes { rawBuffer -> Data in
            Data(rawBuffer)
        }
        defer { keyData.secureZero() }
        let publicKey = try loadRSAPublicKey(fromPEM: publicKeyPEM)
        var error: Unmanaged<CFError>?
        guard let encrypted = SecKeyCreateEncryptedData(
            publicKey,
            .rsaEncryptionOAEPSHA1,
            keyData as CFData,
            &error,
        ) as Data? else {
            throw TDFCryptoError.keyWrapFailed(error?.takeRetainedValue())
        }
        return encrypted.base64EncodedString()
    }

    /// Unwrap a KAS RSA-wrapped DEK (OAEP-SHA1, matching go platform).
    public static func unwrapSymmetricKeyWithRSA(privateKeyPEM: String, wrappedKey: String) throws -> SymmetricKey {
        let privateKey = try loadRSAPrivateKey(fromPEM: privateKeyPEM)
        guard let wrappedData = Data(base64Encoded: wrappedKey) else {
            throw TDFCryptoError.invalidWrappedKey
        }
        var error: Unmanaged<CFError>?
        guard var decrypted = SecKeyCreateDecryptedData(
            privateKey,
            .rsaEncryptionOAEPSHA1,
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
        let data = try decodePEMBody(pem, markers: [
            "-----BEGIN PUBLIC KEY-----",
            "-----END PUBLIC KEY-----",
        ])

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
        let data = try decodePEMBody(pem, markers: [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----END PRIVATE KEY-----",
        ])

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

    private static func decodePEMBody(_ pem: String, markers: [String]) throws -> Data {
        var stripped = pem
        for marker in markers {
            stripped = stripped.replacingOccurrences(of: marker, with: "")
        }
        stripped = stripped
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard let data = Data(base64Encoded: stripped) else {
            throw TDFCryptoError.invalidPEM
        }
        return data
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
    ///
    /// This is the TDF-JSON / TDF-CBOR draft scheme: an **empty** HKDF salt and a
    /// base64 compressed SEC1 ephemeral key. It is not the go SDK / opentdf-platform
    /// `ec-wrapped` scheme, which a platform KAS and `TDFKAS.rewrap` expect; use
    /// `wrapSymmetricKeyWithECForKAS` for that.
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

    /// Unwrap a symmetric key using EC (ECIES: ECDH + HKDF + AES-GCM), in the
    /// TDF-JSON / TDF-CBOR draft scheme (empty HKDF salt); supports P-256, P-384, and P-521.
    public static func unwrapSymmetricKeyWithEC(
        privateKeyPEM: String,
        wrappedKey: String,
        ephemeralPublicKey ephemeralKeyString: String,
    ) throws -> SymmetricKey {
        if let p256Key = try? P256.KeyAgreement.PrivateKey(pemRepresentation: privateKeyPEM) {
            return try unwrapSymmetricKeyWithEC(
                privateKey: p256Key,
                wrappedKey: wrappedKey,
                ephemeralPublicKey: ephemeralKeyString,
            )
        }
        if let p384Key = try? P384.KeyAgreement.PrivateKey(pemRepresentation: privateKeyPEM) {
            return try unwrapSymmetricKeyWithEC(
                privateKey: p384Key,
                wrappedKey: wrappedKey,
                ephemeralPublicKey: ephemeralKeyString,
            )
        }
        if let p521Key = try? P521.KeyAgreement.PrivateKey(pemRepresentation: privateKeyPEM) {
            return try unwrapSymmetricKeyWithEC(
                privateKey: p521Key,
                wrappedKey: wrappedKey,
                ephemeralPublicKey: ephemeralKeyString,
            )
        }
        throw TDFCryptoError.ecKeyAgreementFailed("Unsupported or invalid EC private key PEM")
    }

    /// Unwrap a symmetric key using P-256 EC (ECIES: ECDH + HKDF + AES-GCM).
    public static func unwrapSymmetricKeyWithEC(
        privateKey: P256.KeyAgreement.PrivateKey,
        wrappedKey: String,
        ephemeralPublicKey ephemeralKeyString: String,
    ) throws -> SymmetricKey {
        let ephemeralPublicKey: P256.KeyAgreement.PublicKey
        if ephemeralKeyString.contains("-----BEGIN") {
            ephemeralPublicKey = try loadECPublicKeyP256(fromPEM: ephemeralKeyString)
        } else {
            guard let keyData = Data(base64Encoded: ephemeralKeyString) else {
                throw TDFCryptoError.ecKeyAgreementFailed("Invalid ephemeral key encoding")
            }
            if keyData.count == 33 {
                ephemeralPublicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: keyData)
            } else {
                ephemeralPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: keyData)
            }
        }
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
        return try unwrapECKey(wrappedKey: wrappedKey, sharedSecret: sharedSecret)
    }

    /// Unwrap a symmetric key using P-384 EC (ECIES: ECDH + HKDF + AES-GCM).
    public static func unwrapSymmetricKeyWithEC(
        privateKey: P384.KeyAgreement.PrivateKey,
        wrappedKey: String,
        ephemeralPublicKey ephemeralKeyString: String,
    ) throws -> SymmetricKey {
        let ephemeralPublicKey: P384.KeyAgreement.PublicKey
        if ephemeralKeyString.contains("-----BEGIN") {
            ephemeralPublicKey = try loadECPublicKeyP384(fromPEM: ephemeralKeyString)
        } else {
            guard let keyData = Data(base64Encoded: ephemeralKeyString) else {
                throw TDFCryptoError.ecKeyAgreementFailed("Invalid ephemeral key encoding")
            }
            if keyData.count == 49 {
                ephemeralPublicKey = try P384.KeyAgreement.PublicKey(compressedRepresentation: keyData)
            } else {
                ephemeralPublicKey = try P384.KeyAgreement.PublicKey(x963Representation: keyData)
            }
        }
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
        return try unwrapECKey(wrappedKey: wrappedKey, sharedSecret: sharedSecret)
    }

    /// Unwrap a symmetric key using P-521 EC (ECIES: ECDH + HKDF + AES-GCM).
    public static func unwrapSymmetricKeyWithEC(
        privateKey: P521.KeyAgreement.PrivateKey,
        wrappedKey: String,
        ephemeralPublicKey ephemeralKeyString: String,
    ) throws -> SymmetricKey {
        let ephemeralPublicKey: P521.KeyAgreement.PublicKey
        if ephemeralKeyString.contains("-----BEGIN") {
            ephemeralPublicKey = try loadECPublicKeyP521(fromPEM: ephemeralKeyString)
        } else {
            guard let keyData = Data(base64Encoded: ephemeralKeyString) else {
                throw TDFCryptoError.ecKeyAgreementFailed("Invalid ephemeral key encoding")
            }
            if keyData.count == 67 {
                ephemeralPublicKey = try P521.KeyAgreement.PublicKey(compressedRepresentation: keyData)
            } else {
                ephemeralPublicKey = try P521.KeyAgreement.PublicKey(x963Representation: keyData)
            }
        }
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
        return try unwrapECKey(wrappedKey: wrappedKey, sharedSecret: sharedSecret)
    }

    private static func unwrapECKey(wrappedKey: String, sharedSecret: SharedSecret) throws -> SymmetricKey {
        guard let wrappedData = Data(base64Encoded: wrappedKey), wrappedData.count > 28 else {
            throw TDFCryptoError.invalidWrappedKey
        }
        let wrapKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data(),
            outputByteCount: 32,
        )
        let sealedBox = try AES.GCM.SealedBox(combined: wrappedData)
        var decryptedKey = try AES.GCM.open(sealedBox, using: wrapKey)
        defer { decryptedKey.secureZero() }
        return SymmetricKey(data: decryptedKey)
    }

    // MARK: - EC Key Wrapping for a KAS (`ec-wrapped`)

    /// Wraps a key share to a KAS P-256 public key in the go SDK / opentdf-platform
    /// `ec-wrapped` scheme (go SDK `generateWrapKeyWithEC`): a fresh ephemeral
    /// P-256 key, ECDH, HKDF-SHA256 with salt `SHA256("TDF")`, empty info and a
    /// 32-byte output, AES-256-GCM. A platform KAS with EC enabled, and `TDFKAS.rewrap`,
    /// can rewrap the result.
    ///
    /// This is not the scheme of `wrapSymmetricKeyWithEC`, which the TDF-JSON and
    /// TDF-CBOR containers use (empty salt, compressed SEC1 ephemeral key).
    /// - Parameters:
    ///   - publicKeyPEM: The KAS's P-256 public key, PEM SubjectPublicKeyInfo.
    ///   - symmetricKey: The key share to wrap (the DEK for a single-split TDF).
    /// - Returns: The base64 wrapped key and the PEM ephemeral public key.
    public static func wrapSymmetricKeyWithECForKAS(
        publicKeyPEM: String,
        symmetricKey: SymmetricKey,
    ) throws -> KASECWrappedKey {
        let kasPublicKey = try loadECPublicKeyP256(fromPEM: publicKeyPEM)
        let ephemeralPrivateKey = P256.KeyAgreement.PrivateKey()
        let wrapKey = try deriveKASWrapKey(ephemeralPrivateKey, kasPublicKey)
        // Seal straight from the key's own storage, so no copy of the share is left behind.
        let sealed = try symmetricKey.withUnsafeBytes { try AES.GCM.seal($0, using: wrapKey) }
        guard let combined = sealed.combined else {
            throw TDFCryptoError.keyWrapFailed(nil)
        }
        return KASECWrappedKey(
            wrappedKey: combined.base64EncodedString(),
            ephemeralPublicKeyPEM: ephemeralPrivateKey.publicKey.pemRepresentation,
        )
    }

    /// ECDH, then HKDF-SHA256 with salt `SHA256("TDF")`, empty info, 32 bytes:
    /// the go SDK's `tdfSalt()` scheme, used for the `ec-wrapped` key access
    /// object wrap and for the rewrap session alike (`TDFKAS`).
    static func deriveKASWrapKey(
        _ privateKey: P256.KeyAgreement.PrivateKey,
        _ publicKey: P256.KeyAgreement.PublicKey,
    ) throws -> SymmetricKey {
        try privateKey.sharedSecretFromKeyAgreement(with: publicKey).hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: KASRewrapClient.standardTDFSessionSalt,
            sharedInfo: Data(),
            outputByteCount: 32,
        )
    }

    // MARK: - EC Wrapping Helpers (TDF-JSON / TDF-CBOR draft scheme)

    private static func sealECWrappedKey(
        sharedSecret: SharedSecret,
        ephemeralCompressedPublicKey: Data,
        symmetricKey: SymmetricKey,
    ) throws -> ECWrappedKeyResult {
        // Derive wrapping key using HKDF-SHA256 (empty salt and info for TDF-JSON / TDF-CBOR compatibility)
        let wrapKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data(),
            outputByteCount: 32,
        )
        // Seal directly from symmetricKey storage so no unzeroed copy is left behind
        let nonce = try AES.GCM.Nonce(data: randomBytes(count: 12))
        let sealed = try symmetricKey.withUnsafeBytes { try AES.GCM.seal($0, using: wrapKey, nonce: nonce) }
        guard let combined = sealed.combined else {
            throw TDFCryptoError.keyWrapFailed(nil)
        }
        return ECWrappedKeyResult(
            wrappedKey: combined.base64EncodedString(),
            ephemeralPublicKey: ephemeralCompressedPublicKey.base64EncodedString(),
        )
    }

    private static func wrapWithP256(publicKeyPEM: String, symmetricKey: SymmetricKey) throws -> ECWrappedKeyResult {
        let recipientPublicKey = try loadECPublicKeyP256(fromPEM: publicKeyPEM)
        let ephemeralPrivateKey = P256.KeyAgreement.PrivateKey()
        let sharedSecret = try ephemeralPrivateKey.sharedSecretFromKeyAgreement(with: recipientPublicKey)
        return try sealECWrappedKey(
            sharedSecret: sharedSecret,
            ephemeralCompressedPublicKey: ephemeralPrivateKey.publicKey.compressedRepresentation,
            symmetricKey: symmetricKey,
        )
    }

    private static func wrapWithP384(publicKeyPEM: String, symmetricKey: SymmetricKey) throws -> ECWrappedKeyResult {
        let recipientPublicKey = try loadECPublicKeyP384(fromPEM: publicKeyPEM)
        let ephemeralPrivateKey = P384.KeyAgreement.PrivateKey()
        let sharedSecret = try ephemeralPrivateKey.sharedSecretFromKeyAgreement(with: recipientPublicKey)
        return try sealECWrappedKey(
            sharedSecret: sharedSecret,
            ephemeralCompressedPublicKey: ephemeralPrivateKey.publicKey.compressedRepresentation,
            symmetricKey: symmetricKey,
        )
    }

    private static func wrapWithP521(publicKeyPEM: String, symmetricKey: SymmetricKey) throws -> ECWrappedKeyResult {
        let recipientPublicKey = try loadECPublicKeyP521(fromPEM: publicKeyPEM)
        let ephemeralPrivateKey = P521.KeyAgreement.PrivateKey()
        let sharedSecret = try ephemeralPrivateKey.sharedSecretFromKeyAgreement(with: recipientPublicKey)
        return try sealECWrappedKey(
            sharedSecret: sharedSecret,
            ephemeralCompressedPublicKey: ephemeralPrivateKey.publicKey.compressedRepresentation,
            symmetricKey: symmetricKey,
        )
    }

    // MARK: - EC Public Key Loading

    private static let publicKeyPEMMarkers = [
        "-----BEGIN PUBLIC KEY-----",
        "-----END PUBLIC KEY-----",
    ]

    /// Load a P-256 EC public key from PEM format
    public static func loadECPublicKeyP256(fromPEM pem: String) throws -> P256.KeyAgreement.PublicKey {
        let data = try decodePEMBody(pem, markers: publicKeyPEMMarkers)
        do {
            return try P256.KeyAgreement.PublicKey(derRepresentation: data)
        } catch {
            throw TDFCryptoError.ecKeyAgreementFailed("Failed to parse P-256 public key: \(error.localizedDescription)")
        }
    }

    /// Load a P-384 EC public key from PEM format
    public static func loadECPublicKeyP384(fromPEM pem: String) throws -> P384.KeyAgreement.PublicKey {
        let data = try decodePEMBody(pem, markers: publicKeyPEMMarkers)
        do {
            return try P384.KeyAgreement.PublicKey(derRepresentation: data)
        } catch {
            throw TDFCryptoError.ecKeyAgreementFailed("Failed to parse P-384 public key: \(error.localizedDescription)")
        }
    }

    /// Load a P-521 EC public key from PEM format
    public static func loadECPublicKeyP521(fromPEM pem: String) throws -> P521.KeyAgreement.PublicKey {
        let data = try decodePEMBody(pem, markers: publicKeyPEMMarkers)
        do {
            return try P521.KeyAgreement.PublicKey(derRepresentation: data)
        } catch {
            throw TDFCryptoError.ecKeyAgreementFailed("Failed to parse P-521 public key: \(error.localizedDescription)")
        }
    }
}

/// Result of `TDFCrypto.wrapSymmetricKeyWithEC` (the TDF-JSON / TDF-CBOR draft
/// scheme): the wrapped key and the ephemeral public key
public struct ECWrappedKeyResult: Sendable {
    /// The wrapped symmetric key, base64 (nonce + ciphertext + tag)
    public let wrappedKey: String
    /// The ephemeral public key, base64 compressed SEC1 (not PEM)
    public let ephemeralPublicKey: String
}

/// A key share wrapped to a KAS by `TDFCrypto.wrapSymmetricKeyWithECForKAS`, in the
/// go SDK / opentdf-platform `ec-wrapped` scheme.
public struct KASECWrappedKey: Sendable {
    /// Base64 of nonce (12) ‖ ciphertext ‖ tag (16); the key access object's `wrappedKey`.
    public let wrappedKey: String
    /// The ephemeral P-256 public key, PEM SubjectPublicKeyInfo; the key access
    /// object's `ephemeralPublicKey`.
    public let ephemeralPublicKeyPEM: String
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
    case randomGenerationFailed(OSStatus?)

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
        case let .randomGenerationFailed(status):
            if let status {
                return "Random number generation failed with status \(status)"
            }
            return "Random number generation failed"
        }
    }
}
