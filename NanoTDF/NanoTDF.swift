import CryptoKit
import Foundation

struct NanoTDF {
    var header: Header
    var payload: Payload
    var signature: Signature?

    func toData() -> Data {
        var data = Data()
        data.append(header.toData())
        data.append(payload.toData())
        if let signature = signature {
            data.append(signature.toData())
        }
        return data
    }
}

protocol NanoTDFDecorator {
    func compressNanoTDF() -> NanoTDF
    func encryptNanoTDF() -> NanoTDF
    func signAndBindNanoTDF() -> NanoTDF
}

struct Header {
    let magicNumber: Data
    let version: Data
    let kas: ResourceLocator
    let policyBindingConfig: PolicyBindingConfig
    var payloadSignatureConfig: SignatureAndPayloadConfig
    let policy: Policy
    let ephemeralPublicKey: Data

    init?(magicNumber: Data, version: Data, kas: ResourceLocator, eccMode: PolicyBindingConfig, payloadSigMode: SignatureAndPayloadConfig, policy: Policy, ephemeralKey: Data) {
        // Validate magicNumber
        let expectedMagicNumber = Data([0x4C, 0x31]) // 0x4C31 (L1L) - first 18 bits
        guard magicNumber.prefix(2) == expectedMagicNumber else {
            print("Header.init magicNumber", magicNumber)
            return nil
        }
        self.magicNumber = magicNumber
        self.version = version
        self.kas = kas
        policyBindingConfig = eccMode
        payloadSignatureConfig = payloadSigMode
        self.policy = policy
        ephemeralPublicKey = ephemeralKey
    }

    func toData() -> Data {
        var data = Data()
        data.append(magicNumber)
        data.append(version)
        data.append(kas.toData())
        data.append(policyBindingConfig.toData())
        data.append(payloadSignatureConfig.toData())
        data.append(policy.toData())
        data.append(ephemeralPublicKey)
        return data
    }
}

struct Payload {
    let length: UInt32
    let iv: Data
    let ciphertext: Data
    let mac: Data

    func toData() -> Data {
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

struct Signature {
    let publicKey: Data
    let signature: Data

    func toData() -> Data {
        var data = Data()
        data.append(publicKey)
        data.append(signature)
        return data
    }
}

struct PolicyBindingConfig {
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

struct SignatureAndPayloadConfig {
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
        print("SymmetricAndPayloadConfig write serialized data:", Data([byte]).map { String($0, radix: 16) })
        return Data([byte])
    }
}

enum ProtocolEnum: UInt8 {
    case http = 0x00
    case https = 0x01
    // BEGIN out-of-spec
    case ws = 0x02
    case wss = 0x03
    // END out-of-spec
    case sharedResourceDirectory = 0xFF
}

struct ResourceLocator {
    let protocolEnum: ProtocolEnum
    let body: String

    init?(protocolEnum: ProtocolEnum, body: String) {
        guard body.utf8.count >= 1, body.utf8.count <= 255 else {
            print(body.utf8.count)
            return nil
        }
        self.protocolEnum = protocolEnum
        self.body = body
    }

    func toData() -> Data {
        var data = Data()
        data.append(protocolEnum.rawValue)
        if let bodyData = body.data(using: .utf8) {
            data.append(UInt8(bodyData.count))
            data.append(bodyData)
        }
        return data
    }
}

struct Policy {
    enum PolicyType: UInt8 {
        case remote = 0x00
        case embeddedPlaintext = 0x01
        case embeddedEncrypted = 0x02
        // IV value 00 00 00 is reserved for use with an encrypted policy.
        case embeddedEncryptedWithPolicyKeyAccess = 0x03
    }

    let type: PolicyType
    let body: EmbeddedPolicyBody?
    let remote: ResourceLocator?
    var binding: Data?

    func toData() -> Data {
        var data = Data()
        data.append(type.rawValue)
        switch type {
        case .remote:
            if let remote = remote {
                data.append(remote.toData())
            }
        case .embeddedPlaintext, .embeddedEncrypted, .embeddedEncryptedWithPolicyKeyAccess:
            if let body = body {
                data.append(body.toData())
            }
        }
        if let binding = binding {
            data.append(binding)
        }
        return data
    }
}

struct EmbeddedPolicyBody {
    let length: Int
    let body: Data
    let keyAccess: PolicyKeyAccess?
    
    func toData() -> Data {
        var data = Data()
        data.append(UInt8(body.count)) // length
        data.append(body)
        if let keyAccess = keyAccess {
            data.append(keyAccess.toData())
        }
        return data
    }
}

struct PolicyKeyAccess {
    let resourceLocator: ResourceLocator
    let ephemeralPublicKey: Data

    func toData() -> Data {
        var data = Data()
        data.append(resourceLocator.toData())
        data.append(ephemeralPublicKey)
        return data
    }
}

enum Curve: UInt8 {
    case secp256r1 = 0x00
    case secp384r1 = 0x01
    case secp521r1 = 0x02
    // BEGIN in-spec unsupported
    case xsecp256k1 = 0x03
    // END in-spec unsupported
}

enum Cipher: UInt8 {
    case aes256GCM64 = 0x00
    case aes256GCM96 = 0x01
    case aes256GCM104 = 0x02
    case aes256GCM112 = 0x03
    case aes256GCM120 = 0x04
    // CryptoKit’s AES.GCM uses a 128-bit authentication tag by default,
    // and you don't need to (nor can you) specify different tag lengths.
    case aes256GCM128 = 0x05
}

// Function to add a signature to a NanoTDF
func addSignatureToNanoTDF(nanoTDF: inout NanoTDF, privateKey: P256.Signing.PrivateKey, config: SignatureAndPayloadConfig) throws {
    let message = nanoTDF.header.toData() + nanoTDF.payload.toData()
    guard let signatureData = try CryptoHelper.generateECDSASignature(privateKey: privateKey, message: message) else {
        throw ParsingError.invalidSigning
    }
    print("signatureData", signatureData.count)
    let publicKeyData = privateKey.publicKey.compressedRepresentation // Using compressedRepresentation for the compressed key format
    print("publicKeyData", publicKeyData.count)
    // Determine lengths based on ECC mode
    let publicKeyLength: Int
    let signatureLength: Int

    print("config.signatureECCMode", config.signatureCurve as Any)
    switch config.signatureCurve {
    case .secp256r1, .xsecp256k1:
        publicKeyLength = 33
        signatureLength = 64
    case .secp384r1:
        publicKeyLength = 49
        signatureLength = 96
    case .secp521r1:
        publicKeyLength = 67
        signatureLength = 132
    case .none:
        print("signatureECCMode not found")
        throw ParsingError.invalidFormat
    }

    // Check lengths
    guard publicKeyData.count == publicKeyLength else {
        throw ParsingError.invalidPublicKeyLength
    }
    guard signatureData.count == signatureLength else {
        throw ParsingError.invalidSignatureLength
    }

    let signature = Signature(publicKey: publicKeyData, signature: signatureData)
    nanoTDF.signature = signature
    nanoTDF.header.payloadSignatureConfig.signed = true
    nanoTDF.header.payloadSignatureConfig.signatureCurve = config.signatureCurve // Use the provided config
}

// Initialize a NanoTDF small
func initializeSmallNanoTDF(kasResourceLocator: ResourceLocator) -> NanoTDF {
    let magicNumber = Data([0x4C, 0x31]) // 0x4C31 (L1L) - first 18 bits
    let version = Data([0x0C]) // version[0] & 0x3F (12) last 6 bits for version
    let curve: Curve = .secp256r1
    let header = Header(magicNumber: magicNumber,
                        version: version,
                        kas: kasResourceLocator,
                        eccMode: PolicyBindingConfig(ecdsaBinding: false,
                                                     curve: curve),
                        payloadSigMode: SignatureAndPayloadConfig(signed: false,
                                                                  signatureCurve: nil,
                                                                  payloadCipher: .aes256GCM128),
                        policy: Policy(type: .embeddedPlaintext,
                                       body: nil,
                                       remote: nil,
                                       binding: nil),
                        ephemeralKey: Data([0x04, 0x05, 0x06]))

    let payload = Payload(length: 7,
                          iv: Data([0x07, 0x08, 0x09]),
                          ciphertext: Data([0x00]),
                          mac: Data([0x13, 0x14, 0x15]))

    return NanoTDF(header: header!,
                   payload: payload,
                   signature: nil)
}

struct KasMetadata {
    let resourceLocator: ResourceLocator
    let publicKey: Any
    let curve: Curve
}

func createNanoTDF(kas: KasMetadata, policy: inout Policy, plaintext: Data) throws -> NanoTDF {
    // Step 1: Generate an ephemeral key pair
    guard let (ephemeralPrivateKey, ephemeralPublicKey) = CryptoHelper.generateEphemeralKeyPair(curveType: kas.curve) else {
        throw NSError(domain: "CryptoError", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to generate ephemeral key pair"])
    }
    
    // Step 2: Derive shared secret
    guard let sharedSecret = try CryptoHelper.deriveSharedSecret(curveType: kas.curve, ephemeralPrivateKey: ephemeralPrivateKey, recipientPublicKey: kas.publicKey) else {
        throw NSError(domain: "CryptoError", code: 2, userInfo: [NSLocalizedDescriptionKey: "Failed to derive shared secret"])
    }
    
    // Step 3: Derive symmetric key
    let symmetricKey = CryptoHelper.deriveSymmetricKey(sharedSecret: sharedSecret)
    var policyBody: Data
    switch policy.type {
    case .remote:
        policyBody = policy.remote!.toData()
    case .embeddedPlaintext, .embeddedEncrypted, .embeddedEncryptedWithPolicyKeyAccess:
        policyBody = policy.body!.toData()
    }
    let gmacTag = try CryptoHelper.createGMACBinding(policyBody: policyBody, symmetricKey: symmetricKey)
    policy.binding = gmacTag
    // Step 4: Generate nonce (IV)
    // 3.3.2.2 IV + Ciphertext + MAClength 3
    let nonce3 = CryptoHelper.adjustNonce(CryptoHelper.generateNonce(), to: 3)
    let nonce12 = CryptoHelper.adjustNonce(nonce3, to: 12)
    
    // Step 5: Encrypt payload
    let (ciphertext, tag) = try CryptoHelper.encryptPayload(plaintext: plaintext, symmetricKey: symmetricKey, nonce: nonce12)
    
    // Step 6: Create Policy Key Access structure
//    let policyKeyAccessEphemeralKeyPair = CryptoHelper.generateEphemeralKeyPair(curveType: kas.curve)!
//    let policyKeyAccess = PolicyKeyAccess(
//        resourceLocator: kas.resourceLocator,
//        ephemeralPublicKey: policyKeyAccessEphemeralKeyPair.publicKey
//    )

    // If including nonce in payload, add its length
    let payloadLength = ciphertext.count + tag.count + nonce3.count
    print("createNanoTDF payloadLength", payloadLength)
    // Payload
    let payload = Payload(length: UInt32(payloadLength),
                          iv: nonce3,
                          ciphertext: ciphertext,
                          mac: tag)
    // Header
    let magicNumber = Data([0x4C, 0x31]) // 0x4C31 (L1L) - first 18 bits
    let version = Data([0x4C]) // version[0] & 0x3F (12) last 6 bits for version
    let curve: Curve = .secp256r1
    var ephemeralPublicKeyData: Data = Data()
    if let ephemeralPublicKey = ephemeralPublicKey as? P256.KeyAgreement.PublicKey {
        ephemeralPublicKeyData = ephemeralPublicKey.compressedRepresentation
    }
    print("ephemeralPublicKeyData.count", ephemeralPublicKeyData.count)
    let header = Header(magicNumber: magicNumber,
                        version: version,
                        kas: kas.resourceLocator,
                        eccMode: PolicyBindingConfig(ecdsaBinding: false,
                                                     curve: curve),
                        payloadSigMode: SignatureAndPayloadConfig(signed: false,
                                                                  signatureCurve: .secp256r1,
                                                                  payloadCipher: .aes256GCM128),
                        policy: policy,
                        ephemeralKey: ephemeralPublicKeyData)
    return NanoTDF(header: header!,
                   payload: payload,
                   signature: nil)
}
