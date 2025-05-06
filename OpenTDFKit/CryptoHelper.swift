import CryptoKit
import Foundation

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

public enum CryptoHelperError: Error {
    case unsupportedCurve
    case invalidState
    case keyDerivationFailed
    case sessionNotFound
}

actor CryptoHelper {
    /// Performs ECDH (Elliptic Curve Diffie-Hellman) key agreement.
    ///
    /// - Parameters:
    ///   - privateKey: The private key for the key agreement.
    ///   - publicKey: The public key for the key agreement.
    /// - Returns: The shared secret as `Data`.
    /// - Throws: An error if the key agreement fails.
    public static func customECDH(privateKey: P256.KeyAgreement.PrivateKey, publicKey: P256.KeyAgreement.PublicKey) throws -> Data {
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        return sharedSecret.withUnsafeBytes { Data($0) }
    }

    /// Performs ECDH (Elliptic Curve Diffie-Hellman) key agreement.
    ///
    /// - Parameters:
    ///   - privateKey: The private key for the key agreement.
    ///   - publicKey: The public key for the key agreement.
    /// - Returns: The shared secret as `Data`.
    /// - Throws: An error if the key agreement fails.
    public static func customECDH(privateKey: P384.KeyAgreement.PrivateKey, publicKey: P384.KeyAgreement.PublicKey) throws -> Data {
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        return sharedSecret.withUnsafeBytes { Data($0) }
    }

    /// Performs ECDH (Elliptic Curve Diffie-Hellman) key agreement.
    ///
    /// - Parameters:
    ///   - privateKey: The private key for the key agreement.
    ///   - publicKey: The public key for the key agreement.
    /// - Returns: The shared secret as `Data`.
    /// - Throws: An error if the key agreement fails.
    public static func customECDH(privateKey: P521.KeyAgreement.PrivateKey, publicKey: P521.KeyAgreement.PublicKey) throws -> Data {
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        return sharedSecret.withUnsafeBytes { Data($0) }
    }

    /// Performs HKDF (HMAC-based Key Derivation Function) key derivation.
    ///
    /// - Parameters:
    ///   - salt: The salt for the HKDF.
    ///   - ikm: The input keying material.
    ///   - info: The info parameter for HKDF.
    /// - Returns: The derived key as `Data`.
    public static func hkdf(salt: Data, ikm: Data, info: String) -> Data {
        let symmetricKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: salt,
            info: Data(info.utf8),
            outputByteCount: 32
        )
        return symmetricKey.withUnsafeBytes { Data($0) }
    }

    private var activeSessions: [String: EphemeralKeyPair] = [:]

    func generateEphemeralKeyPair(curveType: Curve) -> EphemeralKeyPair? {
        switch curveType {
        case .secp256r1:
            let privateKey = P256.KeyAgreement.PrivateKey()
            return EphemeralKeyPair(
                privateKey: privateKey.rawRepresentation,
                publicKey: privateKey.publicKey.compressedRepresentation,
                curve: curveType
            )
        case .secp384r1:
            let privateKey = P384.KeyAgreement.PrivateKey()
            return EphemeralKeyPair(
                privateKey: privateKey.rawRepresentation,
                publicKey: privateKey.publicKey.compressedRepresentation,
                curve: curveType
            )
        case .secp521r1:
            let privateKey = P521.KeyAgreement.PrivateKey()
            return EphemeralKeyPair(
                privateKey: privateKey.rawRepresentation,
                publicKey: privateKey.publicKey.compressedRepresentation,
                curve: curveType
            )
        case .xsecp256k1:
            return nil
        }
    }

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
        case .xsecp256k1:
            return nil
        }
    }

    func deriveSymmetricKey(sharedSecret: SharedSecret, salt: Data = Data(), info: Data = Data(), outputByteCount: Int = 32) -> SymmetricKey {
        sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: info,
            outputByteCount: outputByteCount
        )
    }

    func createGMACBinding(policyBody: Data, symmetricKey: SymmetricKey) throws -> Data {
        let gmac = try AES.GCM.seal(policyBody, using: symmetricKey)
        return gmac.tag
    }

    func generateNonce(length: Int = 12) -> Data {
        var nonce = Data(count: length)
        _ = nonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, length, $0.baseAddress!) }
        return nonce
    }

    func adjustNonce(_ nonce: Data, to length: Int) -> Data {
        if nonce.count == length {
            return nonce
        } else if nonce.count > length {
            return nonce.prefix(length)
        } else {
            var paddedNonce = nonce
            paddedNonce.append(contentsOf: [UInt8](repeating: 0, count: length - nonce.count))
            return paddedNonce
        }
    }

    func encryptPayload(plaintext: Data, symmetricKey: SymmetricKey, nonce: Data) throws -> (ciphertext: Data, tag: Data) {
        let sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: AES.GCM.Nonce(data: nonce))
        return (sealedBox.ciphertext, sealedBox.tag)
    }

    func decryptPayload(ciphertext: Data, symmetricKey: SymmetricKey, nonce: Data, tag: Data) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: nonce),
            ciphertext: ciphertext,
            tag: tag
        )
        return try AES.GCM.open(sealedBox, using: symmetricKey)
    }

    func generateECDSASignature(privateKey: P256.Signing.PrivateKey, message: Data) throws -> Data? {
        let derSignature = try privateKey.signature(for: message).derRepresentation
        return extractRawECDSASignature(from: derSignature)
    }

    private func extractRawECDSASignature(from derSignature: Data) -> Data? {
        var r: Data?
        var s: Data?

        guard derSignature.count > 8 else { return nil }

        var index = 0
        guard derSignature[index] == 0x30 else { return nil }
        index += 1

        _ = derSignature[index]
        index += 1

        guard derSignature[index] == 0x02 else { return nil }
        index += 1

        let rLength = Int(derSignature[index])
        index += 1

        r = derSignature[index ..< (index + rLength)]
        index += rLength

        guard derSignature[index] == 0x02 else { return nil }
        index += 1

        let sLength = Int(derSignature[index])
        index += 1

        s = derSignature[index ..< (index + sLength)]

        guard let rData = r, let sData = s else { return nil }

        let rTrimmed = rData.count == 33 ? rData.dropFirst() : rData
        let sTrimmed = sData.count == 33 ? sData.dropFirst() : sData

        guard rTrimmed.count == 32, sTrimmed.count == 32 else { return nil }

        return rTrimmed + sTrimmed
    }
}
