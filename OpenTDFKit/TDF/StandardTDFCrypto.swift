import CryptoKit
import Foundation

public enum StandardTDFCrypto {
    public static func generateSymmetricKey() throws -> SymmetricKey {
        let keyData = try randomBytes(count: 32)
        return SymmetricKey(data: keyData)
    }

    public static func randomBytes(count: Int) throws -> Data {
        var generator = SystemRandomNumberGenerator()
        let randomBytes = (0 ..< count).map { _ in UInt8.random(in: UInt8.min ... UInt8.max, using: &generator) }
        return Data(randomBytes)
    }

    public static func encryptPayload(plaintext: Data, symmetricKey: SymmetricKey) throws -> (iv: Data, cipherText: Data, authenticationTag: Data) {
        let nonceData = try randomBytes(count: 12)
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let sealed = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: nonce)
        return (Data(nonce), sealed.ciphertext, Data(sealed.tag))
    }

    public static func decryptPayload(ciphertext: Data, iv: Data, tag: Data, symmetricKey: SymmetricKey) throws -> Data {
        let nonce = try AES.GCM.Nonce(data: iv)
        let sealed = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        return try AES.GCM.open(sealed, using: symmetricKey)
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
            throw StandardTDFCryptoError.keyWrapFailed(error?.takeRetainedValue())
        }
        return encrypted.base64EncodedString()
    }

    public static func unwrapSymmetricKeyWithRSA(privateKeyPEM: String, wrappedKey: String) throws -> SymmetricKey {
        let privateKey = try loadRSAPrivateKey(fromPEM: privateKeyPEM)
        guard let wrappedData = Data(base64Encoded: wrappedKey) else {
            throw StandardTDFCryptoError.invalidWrappedKey
        }
        var error: Unmanaged<CFError>?
        guard let decrypted = SecKeyCreateDecryptedData(
            privateKey,
            .rsaEncryptionOAEPSHA256,
            wrappedData as CFData,
            &error,
        ) as Data? else {
            throw StandardTDFCryptoError.keyUnwrapFailed(error?.takeRetainedValue())
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
            throw StandardTDFCryptoError.invalidPEM
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else {
            throw StandardTDFCryptoError.invalidKeyData(error?.takeRetainedValue())
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
            throw StandardTDFCryptoError.invalidPEM
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else {
            throw StandardTDFCryptoError.invalidKeyData(error?.takeRetainedValue())
        }

        try validateRSAKeySize(key, minimumBits: 2048)
        return key
    }

    private static func validateRSAKeySize(_ key: SecKey, minimumBits: Int) throws {
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              let keySize = attributes[kSecAttrKeySizeInBits as String] as? Int else {
            throw StandardTDFCryptoError.cannotDetermineKeySize
        }

        guard keySize >= minimumBits else {
            throw StandardTDFCryptoError.weakKey(keySize: keySize, minimum: minimumBits)
        }
    }
}

public enum StandardTDFCryptoError: Error, CustomStringConvertible {
    case invalidPEM
    case invalidKeyData(CFError?)
    case keyWrapFailed(CFError?)
    case keyUnwrapFailed(CFError?)
    case invalidWrappedKey
    case weakKey(keySize: Int, minimum: Int)
    case cannotDetermineKeySize

    public var description: String {
        switch self {
        case .invalidPEM:
            return "Invalid PEM format: unable to decode base64 content"
        case let .invalidKeyData(error):
            if let error {
                return "Invalid key data: \(error.localizedDescription)"
            }
            return "Invalid key data: unable to create SecKey from provided data"
        case let .keyWrapFailed(error):
            if let error {
                return "RSA key wrapping failed: \(error.localizedDescription)"
            }
            return "RSA key wrapping failed"
        case let .keyUnwrapFailed(error):
            if let error {
                return "RSA key unwrapping failed: \(error.localizedDescription)"
            }
            return "RSA key unwrapping failed"
        case .invalidWrappedKey:
            return "Invalid wrapped key: unable to decode base64 content"
        case let .weakKey(keySize, minimum):
            return "RSA key size \(keySize) bits is too weak. Minimum required: \(minimum) bits"
        case .cannotDetermineKeySize:
            return "Unable to determine RSA key size from key attributes"
        }
    }
}
