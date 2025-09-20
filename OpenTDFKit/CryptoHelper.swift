import CryptoKit
import Foundation

/// Enum representing the KAS key curves supported for NanoTDF Payload Key Access.
/// These values align with the NanoTDF specification for KAS Key Curve Enum.
public enum KasKeyCurve: UInt8, Sendable, CaseIterable {
    /// NIST P-256 curve (secp256r1).
    case secp256r1 = 0x00
    /// NIST P-384 curve (secp384r1).
    case secp384r1 = 0x01
    /// NIST P-521 curve (secp521r1).
    case secp521r1 = 0x02
    // Note: secp256k1 (0x03) is specified in NanoTDF KAS Key Curve Enum but omitted here
    // as it's not directly supported by CryptoKit for key agreement and not in the proposal's enum example.
}

// Define a Sendable key pair struct
struct EphemeralKeyPair: Sendable {
    let privateKey: Data // Store as raw data
    let publicKey: Data
    let curve: Curve

    init(privateKey: Data, publicKey: Data, curve: Curve) {
        self.privateKey = privateKey
        self.publicKey = publicKey
        self.curve = curve
    }
}

/// Common error types for cryptographic operations within the CryptoHelper.
public enum CryptoHelperError: Error {
    /// Indicates that an unsupported elliptic curve was specified or encountered.
    case unsupportedCurve
    /// Indicates an invalid internal state, potentially related to session management (if used).
    case invalidState
    /// Indicates a failure during key derivation processes like ECDH or HKDF.
    case keyDerivationFailed
    /// Indicates a failure during key pair generation.
    case keyGenerationFailed
    /// Indicates that an expected session or key pair was not found (if session management is used).
    case sessionNotFound
}

/// Constants used within the CryptoHelper and related cryptographic operations.
enum CryptoConstants {
    /// HKDF salt for NanoTDF v12 ("L1L"), computed as SHA256(MAGIC_NUMBER + VERSION).
    static let hkdfSaltV12 = CryptoHelper.computeHKDFSalt(version: Header.versionV12)
    /// HKDF salt for NanoTDF v13 ("L1M"), computed as SHA256(MAGIC_NUMBER + VERSION).
    static let hkdfSaltV13 = CryptoHelper.computeHKDFSalt(version: Header.version)
    /// Default HKDF salt (prioritising v12 compatibility).
    static let hkdfSalt = hkdfSaltV12
    /// Standard info tag used for HKDF key derivation for encryption keys in NanoTDF context.
    static let hkdfInfoEncryption = Data()
    /// Standard output byte count for derived symmetric keys (AES-256).
    static let symmetricKeyByteCount = 32
    /// Standard nonce size for AES-GCM encryption in this implementation (12 bytes).
    static let aesGcmNonceSize = 12
    /// Standard nonce size specified in the NanoTDF header (3 bytes).
    static let nanoTDFNonceSize = 3
    /// Standard tag size for AES-GCM-128 authentication.
    static let aesGcmTagSize = 16
}

/// An actor providing helper functions for common cryptographic operations needed for NanoTDF.
/// Encapsulates key generation, key derivation (ECDH, HKDF), encryption/decryption (AES-GCM),
/// nonce handling, and signature generation.
actor CryptoHelper {
    /// Computes HKDF salt for a given NanoTDF version by hashing the magic number and version byte.
    /// - Parameter version: The NanoTDF version byte (e.g. 0x4C for v12, 0x4D for v13).
    /// - Returns: The resulting salt as Data.
    static func computeHKDFSalt(version: UInt8) -> Data {
        let magicAndVersion = Header.magicNumber + Data([version])
        return Data(SHA256.hash(data: magicAndVersion))
    }

    /// Performs ECDH (Elliptic Curve Diffie-Hellman) key agreement for P256 curve.
    /// - Parameters:
    ///   - privateKey: The P256 private key.
    ///   - publicKey: The corresponding P256 public key.
    /// - Returns: The raw shared secret as `Data`.
    /// - Throws: `CryptoKitError` if key agreement fails.
    public static func customECDH(privateKey: P256.KeyAgreement.PrivateKey, publicKey: P256.KeyAgreement.PublicKey) throws -> Data {
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        // Extract raw bytes from the SharedSecret object
        return sharedSecret.withUnsafeBytes { Data($0) }
    }

    /// Performs ECDH key agreement for P384 curve.
    /// - Parameters:
    ///   - privateKey: The P384 private key.
    ///   - publicKey: The corresponding P384 public key.
    /// - Returns: The raw shared secret as `Data`.
    /// - Throws: `CryptoKitError` if key agreement fails.
    public static func customECDH(privateKey: P384.KeyAgreement.PrivateKey, publicKey: P384.KeyAgreement.PublicKey) throws -> Data {
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        return sharedSecret.withUnsafeBytes { Data($0) }
    }

    /// Performs ECDH key agreement for P521 curve.
    /// - Parameters:
    ///   - privateKey: The P521 private key.
    ///   - publicKey: The corresponding P521 public key.
    /// - Returns: The raw shared secret as `Data`.
    /// - Throws: `CryptoKitError` if key agreement fails.
    public static func customECDH(privateKey: P521.KeyAgreement.PrivateKey, publicKey: P521.KeyAgreement.PublicKey) throws -> Data {
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        return sharedSecret.withUnsafeBytes { Data($0) }
    }

    /// Returns the byte representation for a given KAS key curve.
    /// - Parameter curve: The `KasKeyCurve` enum value.
    /// - Returns: The `UInt8` byte value for the curve.
    public static func kasKeyCurveByte(for curve: KasKeyCurve) -> UInt8 {
        curve.rawValue
    }

    /// Returns the `KasKeyCurve` enum value for a given byte.
    /// - Parameter byte: The `UInt8` byte value representing the curve.
    /// - Returns: An optional `KasKeyCurve` if the byte corresponds to a defined curve, otherwise `nil`.
    public static func curve(fromKasKeyCurveByte byte: UInt8) -> KasKeyCurve? {
        KasKeyCurve(rawValue: byte)
    }

    /// Returns the X9.62 compressed representation of a P256 public key.
    /// - Parameter publicKey: The `P256.KeyAgreement.PublicKey`.
    /// - Returns: The compressed public key as `Data`.
    public static func getCompressedRepresentation(for publicKey: P256.KeyAgreement.PublicKey) -> Data {
        publicKey.compressedRepresentation
    }

    /// Returns the X9.62 compressed representation of a P384 public key.
    /// - Parameter publicKey: The `P384.KeyAgreement.PublicKey`.
    /// - Returns: The compressed public key as `Data`.
    public static func getCompressedRepresentation(for publicKey: P384.KeyAgreement.PublicKey) -> Data {
        publicKey.compressedRepresentation
    }

    /// Returns the X9.62 compressed representation of a P521 public key.
    /// - Parameter publicKey: The `P521.KeyAgreement.PublicKey`.
    /// - Returns: The compressed public key as `Data`.
    public static func getCompressedRepresentation(for publicKey: P521.KeyAgreement.PublicKey) -> Data {
        publicKey.compressedRepresentation
    }

    // Note: `activeSessions` is declared but not currently used in the provided methods.
    // It might be intended for future stateful operations.
    private var activeSessions: [String: EphemeralKeyPair] = [:]

    /// Generates a new ephemeral key pair for the specified elliptic curve.
    /// - Parameter curveType: The `Curve` enum value specifying the desired curve (e.g., `.secp256r1`).
    /// - Returns: An `EphemeralKeyPair` containing the raw private key and compressed public key data, or `nil` if the curve is unsupported (`.xsecp256k1`).
    func generateEphemeralKeyPair(curveType: Curve) -> EphemeralKeyPair? {
        switch curveType {
        case .secp256r1:
            let privateKey = P256.KeyAgreement.PrivateKey()
            return EphemeralKeyPair(
                privateKey: privateKey.rawRepresentation,
                publicKey: privateKey.publicKey.compressedRepresentation,
                curve: curveType,
            )
        case .secp384r1:
            let privateKey = P384.KeyAgreement.PrivateKey()
            return EphemeralKeyPair(
                privateKey: privateKey.rawRepresentation,
                publicKey: privateKey.publicKey.compressedRepresentation,
                curve: curveType,
            )
        case .secp521r1:
            let privateKey = P521.KeyAgreement.PrivateKey()
            return EphemeralKeyPair(
                privateKey: privateKey.rawRepresentation,
                publicKey: privateKey.publicKey.compressedRepresentation,
                curve: curveType,
            )
        }
    }

    /// Derives a shared secret using ECDH between a local key pair and a recipient's public key.
    /// Handles key reconstruction from raw/compressed data based on the curve specified in `keyPair`.
    /// - Parameters:
    ///   - keyPair: The `EphemeralKeyPair` containing the local private key (raw) and curve info.
    ///   - recipientPublicKey: The recipient's public key (compressed representation as `Data`).
    /// - Returns: The derived `SharedSecret` object, or `nil` if the curve is unsupported.
    /// - Throws: `CryptoKitError` if key reconstruction or the key agreement process fails.
    func deriveSharedSecret(keyPair: EphemeralKeyPair, recipientPublicKey: Data) throws -> SharedSecret? {
        switch keyPair.curve {
        case .secp256r1:
            let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: keyPair.privateKey)
            let publicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: recipientPublicKey)
            return try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        case .secp384r1:
            let privateKey = try P384.KeyAgreement.PrivateKey(rawRepresentation: keyPair.privateKey)
            let publicKey = try P384.KeyAgreement.PublicKey(compressedRepresentation: recipientPublicKey)
            return try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        case .secp521r1:
            let privateKey = try P521.KeyAgreement.PrivateKey(rawRepresentation: keyPair.privateKey)
            let publicKey = try P521.KeyAgreement.PublicKey(compressedRepresentation: recipientPublicKey)
            return try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        }
    }

    /// Derives a symmetric key from a shared secret using HKDF with SHA256.
    /// Uses default salt, info, and output size consistent with NanoTDF practices if not provided.
    /// - Parameters:
    ///   - sharedSecret: The `SharedSecret` derived from ECDH.
    ///   - salt: Salt data for HKDF. Defaults to `CryptoConstants.hkdfSalt`.
    ///   - info: Info data for HKDF. Defaults to `CryptoConstants.hkdfInfoEncryption`.
    ///   - outputByteCount: Desired length of the derived key. Defaults to `CryptoConstants.symmetricKeyByteCount` (32 bytes for AES-256).
    /// - Returns: A `SymmetricKey` object.
    func deriveSymmetricKey(
        sharedSecret: SharedSecret,
        salt: Data = CryptoConstants.hkdfSalt,
        info: Data = CryptoConstants.hkdfInfoEncryption,
        outputByteCount: Int = CryptoConstants.symmetricKeyByteCount,
    ) -> SymmetricKey {
        // Use the hkdfDerivedSymmetricKey method on SharedSecret for efficient derivation.
        sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: info,
            outputByteCount: outputByteCount,
        )
    }

    /// Creates a GMAC (Galois/Message Authentication Code) binding tag for policy data.
    /// This is achieved by performing an AES-GCM seal operation with empty plaintext
    /// and the policy data as authenticated data (AAD). The resulting tag serves as the binding.
    /// Per NanoTDF spec section 3.3.1.3, the GMAC tag is truncated to 64 bits (8 bytes).
    /// - Parameters:
    ///   - policyBody: The policy data to bind.
    ///   - symmetricKey: The symmetric key (derived from ECDH/HKDF) to use for generating the tag.
    /// - Returns: The calculated GMAC tag truncated to 8 bytes as `Data`.
    /// - Throws: `CryptoKitError` if the AES-GCM seal operation fails.
    func createGMACBinding(policyBody: Data, symmetricKey: SymmetricKey) throws -> Data {
        // Seal empty data, authenticating the policyBody. The tag is the GMAC binding.
        let sealedBox = try AES.GCM.seal(Data(), using: symmetricKey, authenticating: policyBody)
        // Truncate to 64 bits (8 bytes) per spec section 3.3.1.3
        return Data(sealedBox.tag.prefix(8))
    }

    /// Generates a cryptographically secure random nonce (IV) of the specified length.
    /// - Parameter length: The desired length of the nonce in bytes. Defaults to `CryptoConstants.aesGcmNonceSize` (12 bytes).
    /// - Returns: The generated nonce as `Data`.
    func generateNonce(length: Int = CryptoConstants.aesGcmNonceSize) -> Data {
        var nonce = Data(count: length)
        // Use SecRandomCopyBytes for generating secure random data.
        _ = nonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, length, $0.baseAddress!) }
        return nonce
    }

    /// Adjusts a nonce to a specific length required by a cryptographic algorithm (e.g., AES-GCM typically needs 12 bytes).
    /// - If the input nonce is the correct length, it's returned unchanged.
    /// - If it's longer, it's truncated.
    /// - If it's shorter, it's padded with zero bytes at the end.
    /// - Parameters:
    ///   - nonce: The input nonce `Data`.
    ///   - length: The target length in bytes.
    /// - Returns: The adjusted nonce `Data`.
    func adjustNonce(_ nonce: Data, to length: Int) -> Data {
        if nonce.count == length {
            return nonce // Already correct length
        } else if nonce.count > length {
            return nonce.prefix(length) // Truncate if too long
        } else {
            // Pad with zeros if too short
            var paddedNonce = nonce
            paddedNonce.append(contentsOf: [UInt8](repeating: 0, count: length - nonce.count))
            return paddedNonce
        }
    }

    /// Encrypts plaintext data using AES-GCM.
    /// - Parameters:
    ///   - plaintext: The data to encrypt.
    ///   - symmetricKey: The `SymmetricKey` to use for encryption.
    ///   - nonce: The `AES.GCM.Nonce` to use. Must be unique for each encryption with the same key.
    /// - Returns: A tuple containing the `ciphertext` and the authentication `tag`.
    /// - Throws: `CryptoKitError` if encryption fails.
    func encryptPayload(plaintext: Data, symmetricKey: SymmetricKey, nonce: AES.GCM.Nonce) throws -> (ciphertext: Data, tag: Data) {
        let sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: nonce)
        return (sealedBox.ciphertext, sealedBox.tag)
    }

    /// Encrypts plaintext data using AES-GCM, taking nonce as `Data`.
    /// Note: Internally converts `Data` nonce to `AES.GCM.Nonce`. Ensure input nonce `Data` is the correct size (e.g., 12 bytes).
    /// - Parameters:
    ///   - plaintext: The data to encrypt.
    ///   - symmetricKey: The `SymmetricKey` to use for encryption.
    ///   - nonce: The nonce as `Data`. Must be unique for each encryption with the same key.
    /// - Returns: A tuple containing the `ciphertext` and the authentication `tag`.
    /// - Throws: `CryptoKitError` if encryption fails or if nonce data cannot be converted.
    func encryptPayload(plaintext: Data, symmetricKey: SymmetricKey, nonce: Data) throws -> (ciphertext: Data, tag: Data) {
        // Convert Data to AES.GCM.Nonce before sealing
        let aesNonce = try AES.GCM.Nonce(data: nonce)
        let sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: aesNonce)
        return (sealedBox.ciphertext, sealedBox.tag)
    }

    /// Decrypts ciphertext using AES-GCM.
    /// Reconstructs the `AES.GCM.SealedBox` from ciphertext, nonce, and tag before opening.
    /// - Parameters:
    ///   - ciphertext: The encrypted data.
    ///   - symmetricKey: The `SymmetricKey` used for encryption.
    ///   - nonce: The `AES.GCM.Nonce` used during encryption.
    ///   - tag: The authentication tag generated during encryption.
    /// - Returns: The original plaintext `Data`.
    /// - Throws: `CryptoKitError` if decryption fails (e.g., incorrect key, invalid tag, corrupted data).
    func decryptPayload(ciphertext: Data, symmetricKey: SymmetricKey, nonce: AES.GCM.Nonce, tag: Data) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        return try AES.GCM.open(sealedBox, using: symmetricKey)
    }

    /// Decrypts ciphertext using AES-GCM, taking nonce as `Data`.
    /// Note: Internally converts `Data` nonce to `AES.GCM.Nonce`. Ensure input nonce `Data` is the correct size (e.g., 12 bytes).
    /// - Parameters:
    ///   - ciphertext: The encrypted data.
    ///   - symmetricKey: The `SymmetricKey` used for encryption.
    ///   - nonce: The nonce as `Data` used during encryption.
    ///   - tag: The authentication tag generated during encryption.
    /// - Returns: The original plaintext `Data`.
    /// - Throws: `CryptoKitError` if decryption fails or if nonce data cannot be converted.
    func decryptPayload(ciphertext: Data, symmetricKey: SymmetricKey, nonce: Data, tag: Data) throws -> Data {
        // Convert Data nonce to AES.GCM.Nonce before constructing SealedBox
        let aesNonce = try AES.GCM.Nonce(data: nonce)
        let sealedBox = try AES.GCM.SealedBox(nonce: aesNonce, ciphertext: ciphertext, tag: tag)
        return try AES.GCM.open(sealedBox, using: symmetricKey)
    }

    /// Generates an ECDSA signature (specifically P256) for a given message.
    /// Extracts the raw R and S components from the DER-encoded signature provided by CryptoKit.
    /// - Parameters:
    ///   - privateKey: The `P256.Signing.PrivateKey` to use for signing.
    ///   - message: The `Data` to sign.
    /// - Returns: The raw signature as `Data` (concatenated R and S values, each 32 bytes), or `nil` if extraction fails.
    /// - Throws: `CryptoKitError` if the signing operation itself fails.
    func generateECDSASignature(privateKey: P256.Signing.PrivateKey, message: Data) throws -> Data? {
        // Generate the signature in DER format using CryptoKit
        let derSignature = try privateKey.signature(for: message).derRepresentation
        // Extract the raw R || S components from the DER structure
        return extractRawECDSASignature(from: derSignature)
    }

    /// Extracts the raw R and S components (each expected to be 32 bytes for P256) from a DER-encoded ECDSA signature.
    /// This function manually parses the ASN.1 structure of the DER signature.
    /// **Note:** This assumes a standard P256 ECDSA signature format. It might be fragile if the DER encoding varies.
    /// Consider using `rawRepresentation` on the `P256.Signing.ECDSASignature` object directly if available and suitable.
    /// - Parameter derSignature: The DER-encoded signature `Data`.
    /// - Returns: The concatenated 64-byte raw signature (R || S), or `nil` if parsing fails or lengths are incorrect.
    private func extractRawECDSASignature(from derSignature: Data) -> Data? {
        var r: Data?
        var s: Data?

        // Basic validation of DER structure (SEQUENCE tag, etc.)
        guard derSignature.count > 8 else { return nil } // Minimal length check

        var index = 0
        // Expect SEQUENCE tag (0x30)
        guard derSignature[index] == 0x30 else { return nil }
        index += 1

        // Skip length byte (we don't strictly need it here)
        // let sequenceLength = derSignature[index]
        index += 1

        // Expect INTEGER tag (0x02) for R
        guard derSignature[index] == 0x02 else { return nil }
        index += 1

        // Get length of R
        let rLength = Int(derSignature[index])
        index += 1

        // Extract R value bytes
        guard index + rLength <= derSignature.count else { return nil } // Bounds check
        r = derSignature[index ..< (index + rLength)]
        index += rLength

        // Expect INTEGER tag (0x02) for S
        guard derSignature[index] == 0x02 else { return nil }
        index += 1

        // Get length of S
        let sLength = Int(derSignature[index])
        index += 1

        // Extract S value bytes
        guard index + sLength <= derSignature.count else { return nil } // Bounds check
        s = derSignature[index ..< (index + sLength)]

        // Ensure R and S were extracted
        guard let rData = r, let sData = s else { return nil }

        // Handle potential leading zero byte in R or S if the value is positive
        // but the high bit is set. Trim to expected 32 bytes for P256.
        let rTrimmed = rData.count == 33 && rData.first == 0x00 ? rData.dropFirst() : rData
        let sTrimmed = sData.count == 33 && sData.first == 0x00 ? sData.dropFirst() : sData

        // Validate final lengths are exactly 32 bytes each for P256 raw signature
        guard rTrimmed.count == 32, sTrimmed.count == 32 else { return nil }

        // Concatenate R and S for the raw signature format
        return rTrimmed + sTrimmed
    }

    /// Performs HKDF (HMAC-based Key Derivation Function) using SHA256.
    /// Static utility function.
    /// - Parameters:
    ///   - salt: The salt `Data` for HKDF.
    ///   - ikm: The input keying material `Data` (e.g., a shared secret).
    ///   - info: Optional context/application-specific info string for HKDF.
    ///   - count: The desired output length in bytes (defaults to 32).
    /// - Returns: The derived key as `Data`.
    public static func hkdf(salt: Data, ikm: Data, info: String?, count: Int = 32) -> Data {
        // Convert SharedSecret (as ikm) to SymmetricKey for HKDF input
        let symmetricIkm = SymmetricKey(data: ikm)

        // Perform HKDF extraction (creates pseudorandom key)
        let prk = HKDF<SHA256>.extract(inputKeyMaterial: symmetricIkm, salt: salt)

        // Perform HKDF expansion to the desired output size
        let okm = HKDF<SHA256>.expand(pseudoRandomKey: prk, info: info?.data(using: .utf8) ?? Data(), outputByteCount: count)

        // Return the derived key data
        return okm.withUnsafeBytes { Data($0) }
    }
}
