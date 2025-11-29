import CryptoKit
import Foundation

// MARK: - Collection Decryptor

/// Decryptor for NanoTDF Collection items.
/// Supports both client-side decryption (with unwrapped DEK) and KAS-side decryption (with KeyStore).
///
/// ## Client-Side Usage
/// ```swift
/// // After KAS rewrap provides the symmetric key
/// let decryptor = NanoTDFCollectionDecryptor.withUnwrappedKey(
///     symmetricKey: unwrappedKey,
///     cipher: .aes256GCM128
/// )
/// let plaintext = try await decryptor.decryptItem(item)
/// ```
///
/// ## KAS-Side Usage
/// ```swift
/// // For server-side decryption with access to KAS private key
/// let decryptor = try await NanoTDFCollectionDecryptor.withKeyStore(
///     header: collectionHeader,
///     keyStore: kasKeyStore
/// )
/// let plaintext = try await decryptor.decryptItem(item)
/// ```
public actor NanoTDFCollectionDecryptor {
    /// The symmetric key for decryption
    private let symmetricKey: SymmetricKey

    /// The cipher used for encryption
    private let cipher: Cipher

    /// Pre-allocated 12-byte nonce buffer (reused for each decryption)
    private var nonceBuffer: ContiguousArray<UInt8>

    // MARK: - Factory Methods

    /// Creates a decryptor with an already-unwrapped symmetric key.
    /// Use this for client-side decryption after KAS rewrap.
    ///
    /// - Parameters:
    ///   - symmetricKey: The unwrapped symmetric key from KAS rewrap
    ///   - cipher: The cipher used for encryption (default: aes256GCM128)
    /// - Returns: A configured decryptor ready for use
    public static func withUnwrappedKey(
        symmetricKey: SymmetricKey,
        cipher: Cipher = .aes256GCM128,
    ) -> NanoTDFCollectionDecryptor {
        NanoTDFCollectionDecryptor(symmetricKey: symmetricKey, cipher: cipher)
    }

    /// Creates a decryptor using a KeyStore containing the KAS private key.
    /// Use this for server-side (KAS) decryption.
    ///
    /// - Parameters:
    ///   - header: The NanoTDF header from the collection
    ///   - keyStore: The KeyStore containing the KAS private key
    /// - Returns: A configured decryptor ready for use
    /// - Throws: `KeyStoreError` if the private key is not found or key derivation fails
    public static func withKeyStore(
        header: Header,
        keyStore: KeyStore,
    ) async throws -> NanoTDFCollectionDecryptor {
        // Derive symmetric key using KeyStore's ECDH + HKDF
        let symmetricKey = try await keyStore.derivePayloadSymmetricKey(header: header)
        let cipher = header.payloadSignatureConfig.payloadCipher ?? .aes256GCM128
        return NanoTDFCollectionDecryptor(symmetricKey: symmetricKey, cipher: cipher)
    }

    /// Creates a decryptor using raw key data from a KAS private key.
    /// Use this when you have the KAS private key data directly.
    ///
    /// - Parameters:
    ///   - header: The NanoTDF header from the collection
    ///   - kasPrivateKeyData: The raw private key data
    ///   - curve: The elliptic curve used
    /// - Returns: A configured decryptor ready for use
    /// - Throws: `NanoTDFCollectionError` if key derivation fails
    public static func withPrivateKey(
        header: Header,
        kasPrivateKeyData: Data,
        curve: Curve,
    ) async throws -> NanoTDFCollectionDecryptor {
        let cryptoHelper = NanoTDF.sharedCryptoHelper

        // Create ephemeral key pair from raw data for ECDH
        let keyPair = EphemeralKeyPair(
            privateKey: kasPrivateKeyData,
            publicKey: header.payloadKeyAccess.kasPublicKey,
            curve: curve,
        )

        // Perform ECDH with the TDF's ephemeral public key
        guard let sharedSecret = try await cryptoHelper.deriveSharedSecret(
            keyPair: keyPair,
            recipientPublicKey: header.ephemeralPublicKey,
        ) else {
            throw NanoTDFCollectionError.keyDerivationFailed("Failed to derive shared secret")
        }

        // Derive symmetric key via HKDF
        let salt = CryptoHelper.computeHKDFSalt(version: Header.version)
        let symmetricKey = await cryptoHelper.deriveSymmetricKey(
            sharedSecret: sharedSecret,
            salt: salt,
            info: Data(),
            outputByteCount: 32,
        )

        let cipher = header.payloadSignatureConfig.payloadCipher ?? .aes256GCM128
        return NanoTDFCollectionDecryptor(symmetricKey: symmetricKey, cipher: cipher)
    }

    // MARK: - Private Initializer

    private init(symmetricKey: SymmetricKey, cipher: Cipher) {
        self.symmetricKey = symmetricKey
        self.cipher = cipher
        nonceBuffer = ContiguousArray<UInt8>(repeating: 0, count: 12)
    }

    // MARK: - Decryption

    /// Decrypts a single collection item
    ///
    /// - Parameter item: The CollectionItem to decrypt
    /// - Returns: The decrypted plaintext data
    /// - Throws: `NanoTDFCollectionError.decryptionFailed` if decryption fails
    public func decryptItem(_ item: CollectionItem) throws -> Data {
        // Update nonce buffer with item's IV
        let iv = item.ivCounter
        nonceBuffer[9] = UInt8((iv >> 16) & 0xFF)
        nonceBuffer[10] = UInt8((iv >> 8) & 0xFF)
        nonceBuffer[11] = UInt8(iv & 0xFF)

        // Use CryptoKit for 128-bit tags (fastest path)
        if cipher == .aes256GCM128 {
            do {
                let nonce = try nonceBuffer.withUnsafeBufferPointer { buffer in
                    try AES.GCM.Nonce(data: Data(buffer))
                }
                let sealedBox = try AES.GCM.SealedBox(
                    nonce: nonce,
                    ciphertext: item.ciphertext,
                    tag: item.tag,
                )
                return try AES.GCM.open(sealedBox, using: symmetricKey)
            } catch {
                throw NanoTDFCollectionError.decryptionFailed("AES-GCM decryption failed: \(error)")
            }
        }

        // For other tag sizes, use CryptoHelper's CryptoSwift path
        do {
            return try CryptoHelper.decryptNanoTDF(
                cipher: cipher,
                key: symmetricKey,
                iv: Data(nonceBuffer),
                ciphertext: item.ciphertext,
                tag: item.tag,
            )
        } catch {
            throw NanoTDFCollectionError.decryptionFailed("Decryption failed: \(error)")
        }
    }

    /// Decrypts multiple collection items efficiently
    ///
    /// - Parameter items: Array of CollectionItems to decrypt
    /// - Returns: Array of decrypted plaintext data in the same order as input
    /// - Throws: `NanoTDFCollectionError.decryptionFailed` if any decryption fails
    public func decryptBatch(_ items: [CollectionItem]) throws -> [Data] {
        var results = [Data]()
        results.reserveCapacity(items.count)

        for item in items {
            try results.append(decryptItem(item))
        }

        return results
    }

    /// Decrypts a collection item and returns nil on failure instead of throwing
    ///
    /// - Parameter item: The CollectionItem to decrypt
    /// - Returns: The decrypted plaintext data, or nil if decryption fails
    public func tryDecryptItem(_ item: CollectionItem) -> Data? {
        try? decryptItem(item)
    }
}
