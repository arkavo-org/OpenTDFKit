import CryptoKit
import Foundation

enum CryptoHelperError: Error {
    case unsupportedCurve
}

enum CryptoHelper {
    // Step 3: Generate Ephemeral Keypair based on curve
    static func generateEphemeralKeyPair(curveType: Curve) -> (privateKey: Any, publicKey: Any)? {
        switch curveType {
        case .secp256r1:
            let privateKey = P256.KeyAgreement.PrivateKey()
            let publicKey = privateKey.publicKey
            return (privateKey, publicKey)
        case .secp384r1:
            let privateKey = P384.KeyAgreement.PrivateKey()
            let publicKey = privateKey.publicKey
            return (privateKey, publicKey)
        case .secp521r1:
            let privateKey = P521.KeyAgreement.PrivateKey()
            let publicKey = privateKey.publicKey
            return (privateKey, publicKey)
        case .xsecp256k1:
            return nil
        }
    }

    // Step 3: Derive shared secret using ECDH
    static func deriveSharedSecret(curveType: Curve, ephemeralPrivateKey: Any, recipientPublicKey: Any) throws -> SharedSecret? {
        switch curveType {
        case .secp256r1:
            let privateKey = ephemeralPrivateKey as! P256.KeyAgreement.PrivateKey
            let publicKey = recipientPublicKey as! P256.KeyAgreement.PublicKey
            return try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        case .secp384r1:
            let privateKey = ephemeralPrivateKey as! P384.KeyAgreement.PrivateKey
            let publicKey = recipientPublicKey as! P384.KeyAgreement.PublicKey
            return try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        case .secp521r1:
            let privateKey = ephemeralPrivateKey as! P521.KeyAgreement.PrivateKey
            let publicKey = recipientPublicKey as! P521.KeyAgreement.PublicKey
            return try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        case .xsecp256k1:
            return nil
        }
    }

    // Step 4: Derive symmetric key using HKDF
    static func deriveSymmetricKey(sharedSecret: SharedSecret, salt: Data = Data(), info: Data = Data(), outputByteCount: Int = 32) -> SymmetricKey {
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: outputByteCount)
        return symmetricKey
    }

    // Step 5: Generate nonce (IV)
    static func generateNonce(length: Int = 12) -> Data {
        var nonce = Data(count: length)
        _ = nonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, length, $0.baseAddress!) }
        return nonce
    }

    // Step 6: Encrypt payload using symmetric key and nonce (IV)
    static func encryptPayload(plaintext: Data, symmetricKey: SymmetricKey, nonce: Data) throws -> (ciphertext: Data, tag: Data) {
        let sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: AES.GCM.Nonce(data: nonce))
        return (sealedBox.ciphertext, sealedBox.tag)
    }
}
