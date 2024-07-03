import CryptoKit
import Foundation

public enum CryptoHelperError: Error {
    case unsupportedCurve
}

public enum CryptoHelper {
    // Step 3: Generate Ephemeral Keypair based on curve
    public static func generateEphemeralKeyPair(curveType: Curve) -> (privateKey: Any, publicKey: Any)? {
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
    public static func deriveSharedSecret(curveType: Curve, ephemeralPrivateKey: Any, recipientPublicKey: Any) throws -> SharedSecret? {
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
    public static func deriveSymmetricKey(sharedSecret: SharedSecret, salt: Data = Data(), info: Data = Data(), outputByteCount: Int = 32) -> SymmetricKey {
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: outputByteCount)
//        if info.count < 12 {
//            print("dek_shared_secret \(symmetricKey.withUnsafeBytes { Data($0).hexEncodedString() })")
//        }
        return symmetricKey
    }

    public static func deriveSymmetricKey(sharedSecretKey: SymmetricKey, salt: Data = Data(), info: Data = Data(), outputByteCount: Int = 32) -> SymmetricKey {
        let symmetricKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: sharedSecretKey, salt: salt, info: info, outputByteCount: outputByteCount)
//        if info.count < 12 {
//            print("Derived key (first 8 bytes): \(symmetricKey.withUnsafeBytes { Data($0.prefix(8)).hexEncodedString() })")
//            print("dek_shared_secret \(symmetricKey.withUnsafeBytes { Data($0).hexEncodedString() })")
//        }
        return symmetricKey
    }

    // Generate GMAC tag for the policy body
    public static func createGMACBinding(policyBody: Data, symmetricKey: SymmetricKey) throws -> Data {
        let gmac = try AES.GCM.seal(policyBody, using: symmetricKey)
        return gmac.tag
    }

    // Step 5: Generate nonce (IV)
    public static func generateNonce(length: Int = 12) -> Data {
        var nonce = Data(count: length)
        _ = nonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, length, $0.baseAddress!) }
        return nonce
    }

    // Pad or trim nonce (IV) to the required length
    public static func adjustNonce(_ nonce: Data, to length: Int) -> Data {
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

    // Step 6: Encrypt payload using symmetric key and nonce (IV)
    public static func encryptPayload(plaintext: Data, symmetricKey: SymmetricKey, nonce: Data) throws -> (ciphertext: Data, tag: Data) {
//        print("Symmetric key: \(symmetricKey.withUnsafeBytes { Data($0).hexEncodedString() })")
//        print("Padded IV: \(nonce.hexEncodedString())")
        let sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: AES.GCM.Nonce(data: nonce))
        return (sealedBox.ciphertext, sealedBox.tag)
    }

    // Helper function to generate ECDSA signature
    public static func generateECDSASignature(privateKey: P256.Signing.PrivateKey, message: Data) throws -> Data? {
        let derSignature = try privateKey.signature(for: message).derRepresentation
        return extractRawECDSASignature(from: derSignature)
    }

    // Helper function to extract r and s values from DER-encoded ECDSA signature
    public static func extractRawECDSASignature(from derSignature: Data) -> Data? {
        var r: Data?
        var s: Data?

        // Decode DER signature
        // DER structure: 0x30 (SEQUENCE) + length + 0x02 (INTEGER) + r length + r + 0x02 (INTEGER) + s length + s
        guard derSignature.count > 8 else { return nil }

        var index = 0
        guard derSignature[index] == 0x30 else { return nil }
        index += 1

        _ = derSignature[index] // length of the sequence
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

        // Ensure r and s are present and have correct lengths
        guard let rData = r, let sData = s else { return nil }

        // Remove leading zero if present
        let rTrimmed = rData.count == 33 ? rData.dropFirst() : rData
        let sTrimmed = sData.count == 33 ? sData.dropFirst() : sData

        // Ensure r and s have correct lengths
        guard rTrimmed.count == 32, sTrimmed.count == 32 else { return nil }

        return rTrimmed + sTrimmed
    }
}
