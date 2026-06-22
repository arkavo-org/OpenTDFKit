import CryptoKit
import Foundation
@testable import OpenTDFKit

extension CryptoHelper {
    /// Combined operation that keeps sensitive types within the actor
    struct EncryptionResult {
        let gmacTag: Data
        let nonce: Data
        let ciphertext: Data
        let tag: Data
    }

    func deriveKeysAndEncrypt(
        keyPair: EphemeralKeyPair,
        recipientPublicKey: Data,
        plaintext: Data,
        policyBody: Data,
    ) throws -> EncryptionResult {
        // Derive shared secret
        guard let sharedSecret = try deriveSharedSecret(
            keyPair: keyPair,
            recipientPublicKey: recipientPublicKey,
        ) else {
            throw CryptoHelperError.keyDerivationFailed
        }

        // Derive symmetric key
        let symmetricKey = deriveSymmetricKey(
            sharedSecret: sharedSecret,
            salt: CryptoConstants.hkdfSalt,
            info: CryptoConstants.hkdfInfoEncryption,
            outputByteCount: CryptoConstants.symmetricKeyByteCount,
        )

        // Create GMAC binding
        let gmacTag = try createGMACBinding(
            policyBody: policyBody,
            symmetricKey: symmetricKey,
        )

        // Generate nonce
        let nonce = try generateNonce()

        // Encrypt payload
        let (ciphertext, tag) = try encryptPayload(
            plaintext: plaintext,
            symmetricKey: symmetricKey,
            nonce: nonce,
        )

        return EncryptionResult(
            gmacTag: gmacTag,
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag,
        )
    }

    func decryptWithDerivedKeys(
        keyPair: EphemeralKeyPair,
        recipientPublicKey: Data,
        ciphertext: Data,
        nonce: Data,
        tag: Data,
    ) throws -> Data {
        // Derive shared secret
        guard let sharedSecret = try deriveSharedSecret(
            keyPair: keyPair,
            recipientPublicKey: recipientPublicKey,
        ) else {
            throw CryptoHelperError.keyDerivationFailed
        }

        // Derive symmetric key
        let symmetricKey = deriveSymmetricKey(
            sharedSecret: sharedSecret,
            salt: CryptoConstants.hkdfSalt,
            info: CryptoConstants.hkdfInfoEncryption,
            outputByteCount: CryptoConstants.symmetricKeyByteCount,
        )

        // Decrypt
        return try decryptPayload(
            ciphertext: ciphertext,
            symmetricKey: symmetricKey,
            nonce: nonce,
            tag: tag,
        )
    }
}
