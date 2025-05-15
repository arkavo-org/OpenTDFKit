@preconcurrency import CryptoKit
import Foundation

public struct NanoTDF: Sendable {
    public var header: Header
    public let payload: Payload
    public var signature: Signature?

    public init(header: Header, payload: Payload, signature: Signature? = nil) {
        self.header = header
        self.payload = payload
        self.signature = signature
    }

    public func toData() -> Data {
        var data = Data()
        data.append(header.toData())
        data.append(payload.toData())
        if let signature {
            data.append(signature.toData())
        }
        return data
    }

    // Original method maintained for backward compatibility
    public func getPayloadPlaintext(symmetricKey: SymmetricKey) async throws -> Data {
        let cryptoHelper = CryptoHelper()
        let paddedIV = await cryptoHelper.adjustNonce(payload.iv, to: 12)
        return try await cryptoHelper.decryptPayload(
            ciphertext: payload.ciphertext,
            symmetricKey: symmetricKey,
            nonce: paddedIV,
            tag: payload.mac
        )
    }
    
    // New method that handles salt-based key derivation
    public func getPayloadPlaintext(withSharedSecret sharedSecret: SharedSecret) async throws -> Data {
        let cryptoHelper = CryptoHelper()
        
        // Extract salt from policy (or use default if not available for backward compatibility)
        let salt = header.policy.salt ?? Data("L1L".utf8)
        
        // Derive symmetric key using the same salt that was used for encryption
        let symmetricKey = await cryptoHelper.deriveSymmetricKey(
            sharedSecret: sharedSecret,
            salt: salt,
            info: Data("encryption".utf8),
            outputByteCount: 32
        )
        
        return try await getPayloadPlaintext(symmetricKey: symmetricKey)
    }
}

public func createNanoTDF(kas: KasMetadata, policy: inout Policy, plaintext: Data) async throws -> NanoTDF {
    let cryptoHelper = CryptoHelper()

    // Step 1: Generate an ephemeral key pair
    guard let keyPair = await cryptoHelper.generateEphemeralKeyPair(curveType: kas.curve) else {
        throw CryptoHelperError.keyDerivationFailed
    }

    // Step 2: Derive shared secret
    let kasPublicKey = try kas.getPublicKey()

    guard let sharedSecret = try await cryptoHelper.deriveSharedSecret(
        keyPair: keyPair,
        recipientPublicKey: kasPublicKey
    ) else {
        throw CryptoHelperError.keyDerivationFailed
    }

    // Step 3: Generate random salt and derive symmetric key
    let salt = await cryptoHelper.generateNonce(length: 16)
    let tdfSymmetricKey = await cryptoHelper.deriveSymmetricKey(
        sharedSecret: sharedSecret,
        salt: salt,
        info: Data("encryption".utf8),
        outputByteCount: 32
    )
    
    // Store salt in policy for use during decryption
    policy.salt = salt

    // Policy
    let policyBody: Data = switch policy.type {
    case .remote:
        policy.remote!.toData()
    case .embeddedPlaintext, .embeddedEncrypted, .embeddedEncryptedWithPolicyKeyAccess:
        policy.body!.toData()
    }

    // Create GMAC binding
    let gmacTag = try await cryptoHelper.createGMACBinding(
        policyBody: policyBody,
        symmetricKey: tdfSymmetricKey
    )
    policy.binding = gmacTag

    // Step 4: Generate nonce
    let nonce = await cryptoHelper.generateNonce(length: 3)
    let nonce12 = await cryptoHelper.adjustNonce(nonce, to: 12)

    // Step 5: Encrypt payload
    let (ciphertext, tag) = try await cryptoHelper.encryptPayload(
        plaintext: plaintext,
        symmetricKey: tdfSymmetricKey,
        nonce: nonce12
    )

    let payloadLength = ciphertext.count + tag.count + nonce.count
    let payload = Payload(
        length: UInt32(payloadLength),
        iv: nonce,
        ciphertext: ciphertext,
        mac: tag
    )

    let header = Header(
        kas: kas.resourceLocator,
        policyBindingConfig: PolicyBindingConfig(ecdsaBinding: false, curve: kas.curve),
        payloadSignatureConfig: SignatureAndPayloadConfig(
            signed: false,
            signatureCurve: kas.curve,
            payloadCipher: .aes256GCM128
        ),
        policy: policy,
        ephemeralPublicKey: keyPair.publicKey
    )

    return NanoTDF(header: header, payload: payload, signature: nil)
}

// Update the addSignatureToNanoTDF function:
public func addSignatureToNanoTDF(nanoTDF: inout NanoTDF, privateKey: P256.Signing.PrivateKey, config: SignatureAndPayloadConfig) async throws {
    let cryptoHelper = CryptoHelper()
    let message = nanoTDF.header.toData() + nanoTDF.payload.toData()

    guard let signatureData = try await cryptoHelper.generateECDSASignature(
        privateKey: privateKey,
        message: message
    ) else {
        throw SignatureError.invalidSigning
    }

    let publicKeyData = privateKey.publicKey.compressedRepresentation
    let signature = Signature(publicKey: publicKeyData, signature: signatureData)

    nanoTDF.signature = signature
    nanoTDF.header.payloadSignatureConfig.signed = true
    nanoTDF.header.payloadSignatureConfig.signatureCurve = config.signatureCurve
}

public struct Header: Sendable {
    public static let magicNumber = Data([0x4C, 0x31]) // 0x4C31 (L1L) - first 18 bits
    public static let version: UInt8 = 0x4D // "M" (upgraded from 0x4C "L")
    public let kas: ResourceLocator
    public let policyBindingConfig: PolicyBindingConfig
    public var payloadSignatureConfig: SignatureAndPayloadConfig
    public let policy: Policy
    public let ephemeralPublicKey: Data

    public init(kas: ResourceLocator, policyBindingConfig: PolicyBindingConfig, payloadSignatureConfig: SignatureAndPayloadConfig, policy: Policy, ephemeralPublicKey: Data) {
        self.kas = kas
        self.policyBindingConfig = policyBindingConfig
        self.payloadSignatureConfig = payloadSignatureConfig
        self.policy = policy
        self.ephemeralPublicKey = ephemeralPublicKey
    }

    public func toData() -> Data {
        var data = Data()
        data.append(Header.magicNumber)
        data.append(Header.version)
        data.append(kas.toData())
        data.append(policyBindingConfig.toData())
        data.append(payloadSignatureConfig.toData())
        data.append(policy.toData())
        data.append(ephemeralPublicKey)
        return data
    }
}

public struct Payload: Sendable {
    public let length: UInt32
    public let iv: Data
    public let ciphertext: Data
    public let mac: Data

    public init(length: UInt32, iv: Data, ciphertext: Data, mac: Data) {
        self.length = length
        self.iv = iv
        self.ciphertext = ciphertext
        self.mac = mac
    }

    public func toData() -> Data {
        var data = Data()
        data.append(UInt8((length >> 16) & 0xFF))
        data.append(UInt8((length >> 8) & 0xFF))
        data.append(UInt8(length & 0xFF))
        data.append(iv)
        data.append(ciphertext)
        data.append(mac)
        return data
    }
}

public struct Signature: Sendable {
    let publicKey: Data
    let signature: Data

    func toData() -> Data {
        var data = Data()
        data.append(publicKey)
        data.append(signature)
        return data
    }
}

public struct PolicyBindingConfig: Sendable {
    // true ECDSA using creator key.  The signature is used as the binding
    // false GMAC tag is computed over the policy body using the derived symmetric key.
    var ecdsaBinding: Bool
    var curve: Curve

    func toData() -> Data {
        var byte: UInt8 = 0
        if ecdsaBinding {
            byte |= 0b1000_0000 // Set the USE_ECDSA_BINDING bit (bit 7)
        }
        byte |= (curve.rawValue & 0b0000_0111) // Set the Ephemeral ECC Params Enum bits (bits 0-2)
        return Data([byte])
    }
}

public struct SignatureAndPayloadConfig: Sendable {
    var signed: Bool
    var signatureCurve: Curve?
    let payloadCipher: Cipher?

    func toData() -> Data {
        var byte: UInt8 = 0
        if signed {
            byte |= 0b1000_0000 // Set the HAS_SIGNATURE bit (bit 7)
        }
        if let signatureECCMode = signatureCurve {
            byte |= (signatureECCMode.rawValue & 0b0000_0111) << 4 // Set the Signature ECC Mode bits (bits 4-6)
        }
        if let symmetricCipherEnum = payloadCipher {
            byte |= (symmetricCipherEnum.rawValue & 0b0000_1111) // Set the Symmetric Cipher Enum bits (bits 0-3)
        }
        // print("SymmetricAndPayloadConfig write serialized data:", Data([byte]).map { String($0, radix: 16) })
        return Data([byte])
    }
}

public enum ProtocolEnum: UInt8, Sendable {
    case http = 0x00
    case https = 0x01
    // BEGIN out-of-spec
    case ws = 0x02
    case wss = 0x03
    // END out-of-spec
    case sharedResourceDirectory = 0xFF
}

public struct ResourceLocator: Sendable {
    public let protocolEnum: ProtocolEnum
    public let body: String

    public init?(protocolEnum: ProtocolEnum, body: String) {
        guard body.utf8.count >= 1, body.utf8.count <= 255 else {
            print(body.utf8.count)
            return nil
        }
        self.protocolEnum = protocolEnum
        self.body = body
    }

    public func toData() -> Data {
        var data = Data()
        data.append(protocolEnum.rawValue)
        if let bodyData = body.data(using: .utf8) {
            data.append(UInt8(bodyData.count))
            data.append(bodyData)
        }
        return data
    }
}

public struct Policy: Sendable {
    public enum PolicyType: UInt8, Sendable {
        case remote = 0x00
        case embeddedPlaintext = 0x01
        case embeddedEncrypted = 0x02
        // IV value 00 00 00 is reserved for use with an encrypted policy.
        case embeddedEncryptedWithPolicyKeyAccess = 0x03
    }

    public let type: PolicyType
    public let body: EmbeddedPolicyBody?
    public let remote: ResourceLocator?
    public var binding: Data?
    public var salt: Data?

    public init(type: PolicyType, body: EmbeddedPolicyBody?, remote: ResourceLocator?, binding: Data? = nil, salt: Data? = nil) {
        self.type = type
        self.body = body
        self.remote = remote
        self.binding = binding
        self.salt = salt
    }

    public func toData() -> Data {
        var data = Data()
        data.append(type.rawValue)
        switch type {
        case .remote:
            if let remote {
                data.append(remote.toData())
            }
        case .embeddedPlaintext, .embeddedEncrypted, .embeddedEncryptedWithPolicyKeyAccess:
            if let body {
                data.append(body.toData())
            }
        }
        if let salt {
            // Add salt length byte followed by salt
            data.append(UInt8(salt.count))
            data.append(salt)
        } else {
            // No salt, add 0 length
            data.append(UInt8(0))
        }
        if let binding {
            data.append(binding)
        }
        return data
    }
}

public struct EmbeddedPolicyBody: Sendable {
    public let body: Data
    public let keyAccess: PolicyKeyAccess?

    public init(body: Data, keyAccess: PolicyKeyAccess? = nil) {
        self.body = body
        self.keyAccess = keyAccess
    }

    public func toData() -> Data {
        var data = Data()
        let bodyLength = UInt16(body.count)
        data.append(UInt8((bodyLength >> 8) & 0xFF)) // length high byte
        data.append(UInt8(bodyLength & 0xFF)) // length low byte
        data.append(body)
        if let keyAccess {
            data.append(keyAccess.toData())
        }
        return data
    }
}

public struct PolicyKeyAccess: Sendable {
    public let resourceLocator: ResourceLocator
    public let ephemeralPublicKey: Data

    func toData() -> Data {
        var data = Data()
        data.append(resourceLocator.toData())
        data.append(ephemeralPublicKey)
        return data
    }
}

public enum Curve: UInt8, Sendable {
    case secp256r1 = 0x00
    case secp384r1 = 0x01
    case secp521r1 = 0x02
    // BEGIN in-spec unsupported
    case xsecp256k1 = 0x03
    // END in-spec unsupported
}

public enum Cipher: UInt8, Sendable {
    case aes256GCM64 = 0x00
    case aes256GCM96 = 0x01
    case aes256GCM104 = 0x02
    case aes256GCM112 = 0x03
    case aes256GCM120 = 0x04
    // CryptoKit’s AES.GCM uses a 128-bit authentication tag by default,
    // and you don't need to (nor can you) specify different tag lengths.
    case aes256GCM128 = 0x05
}

public enum SignatureError: Error {
    case invalidSigning
    case invalidKey
    case invalidMessage
    case invalidSignatureLength
    case invalidPublicKeyLength
    case invalidCurve
}

// Initialize a NanoTDF small
public func initializeSmallNanoTDF(kasResourceLocator: ResourceLocator) -> NanoTDF {
    let curve: Curve = .secp256r1
    let header = Header(
        kas: kasResourceLocator,
        policyBindingConfig: PolicyBindingConfig(ecdsaBinding: false, curve: curve),
        payloadSignatureConfig: SignatureAndPayloadConfig(signed: false, signatureCurve: curve, payloadCipher: .aes256GCM128),
        policy: Policy(type: .remote, body: nil, remote: kasResourceLocator, binding: nil),
        ephemeralPublicKey: Data([0x04, 0x05, 0x06])
    )

    let payload = Payload(
        length: 7,
        iv: Data([0x07, 0x08, 0x09]),
        ciphertext: Data([0x00]),
        mac: Data([0x13, 0x14, 0x15])
    )

    return NanoTDF(header: header,
                   payload: payload,
                   signature: nil)
}

public enum PublicKeyType: Sendable {
    case p256(Data) // Stores compressed representation
    case p384(Data)
    case p521(Data)
}

public struct KasMetadata: Sendable {
    public let resourceLocator: ResourceLocator
    private let publicKeyType: PublicKeyType
    public let curve: Curve

    public init(resourceLocator: ResourceLocator, publicKey: Any, curve: Curve) throws {
        self.resourceLocator = resourceLocator
        self.curve = curve

        // Store compressed representation instead of key objects
        switch curve {
        case .secp256r1:
            guard let key = publicKey as? P256.KeyAgreement.PublicKey else {
                throw CryptoHelperError.unsupportedCurve
            }
            publicKeyType = .p256(key.compressedRepresentation)
        case .secp384r1:
            guard let key = publicKey as? P384.KeyAgreement.PublicKey else {
                throw CryptoHelperError.unsupportedCurve
            }
            publicKeyType = .p384(key.compressedRepresentation)
        case .secp521r1:
            guard let key = publicKey as? P521.KeyAgreement.PublicKey else {
                throw CryptoHelperError.unsupportedCurve
            }
            publicKeyType = .p521(key.compressedRepresentation)
        case .xsecp256k1:
            throw CryptoHelperError.unsupportedCurve
        }
    }

    public func getPublicKey() throws -> Data {
        // Return the compressed representation directly
        switch publicKeyType {
        case let .p256(data):
            data
        case let .p384(data):
            data
        case let .p521(data):
            data
        }
    }
}
