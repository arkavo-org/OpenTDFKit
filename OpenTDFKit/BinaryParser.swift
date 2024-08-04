import Foundation

public class BinaryParser {
    var data: Data
    var cursor: Int = 0

    public init(data: Data) {
        self.data = data
    }

    func read(length: Int) -> Data? {
        guard cursor >= 0 else { return nil }
        guard !data.isEmpty else { return nil }
        guard cursor + length <= data.count else { return nil }
        let range = cursor ..< (cursor + length)
        cursor += length
        return data.subdata(in: range)
    }

    private func readResourceLocator() -> ResourceLocator? {
        guard let protocolData = read(length: 1),
              let protocolEnum = protocolData.first,
              let protocolEnumValue = ProtocolEnum(rawValue: protocolEnum),
              let bodyLengthData = read(length: 1),
              let bodyLength = bodyLengthData.first,
              let body = read(length: Int(bodyLength)),
              let bodyString = String(data: body, encoding: .utf8)
        else {
            return nil
        }
//        let bodyLengthlHex = String(format: "%02x", bodyLength)
//        print("Body Length Hex:", bodyLengthlHex)
//        let bodyHexString = body.map { String(format: "%02x", $0) }.joined(separator: " ")
//        print("Body Hex:", bodyHexString)
//        print("bodyString: \(bodyString)")
        return ResourceLocator(protocolEnum: protocolEnumValue, body: bodyString)
    }

    private func readPolicyField(bindingMode: PolicyBindingConfig) -> Policy? {
        guard let policyTypeData = read(length: 1),
              let policyType = Policy.PolicyType(rawValue: policyTypeData[0])
        else {
            return nil
        }

        switch policyType {
        case .remote:
            guard let resourceLocator = readResourceLocator() else {
                print("Failed to read Remote Policy resource locator")
                return nil
            }
            // Binding
            guard let binding = readPolicyBinding(bindingMode: bindingMode) else {
                print("Failed to read Remote Policy binding")
                return nil
            }
            return Policy(type: .remote, body: nil, remote: resourceLocator, binding: binding)
        case .embeddedPlaintext, .embeddedEncrypted, .embeddedEncryptedWithPolicyKeyAccess:
            let policyData = readEmbeddedPolicyBody(policyType: policyType, bindingMode: bindingMode)
            // Binding
            guard let binding = readPolicyBinding(bindingMode: bindingMode) else {
                print("Failed to read Remote Policy binding")
                return nil
            }
            return Policy(type: .embeddedPlaintext, body: policyData, remote: nil, binding: binding)
        }
    }

    private func readEmbeddedPolicyBody(policyType: Policy.PolicyType, bindingMode: PolicyBindingConfig) -> EmbeddedPolicyBody? {
        guard let contentLengthData = read(length: 2)
        else {
            print("Failed to read Embedded Policy content length")
            return nil
        }
        let plaintextCiphertextLengthData = contentLengthData.prefix(2) // contentLengthData.first

        let contentLength = plaintextCiphertextLengthData.withUnsafeBytes {
            $0.load(as: UInt16.self)
        }
        print("Policy Body Length: \(contentLength)")

        // if no policy added then no read
        // Note 3.4.2.3.2 Body for Embedded Policy states Minimum Length is 1
        if contentLength == 0 {
            return EmbeddedPolicyBody(length: 1, body: Data([0x00]), keyAccess: nil)
        }

        guard let plaintextCiphertext = read(length: Int(contentLength)) else {
            print("Failed to read Embedded Policy plaintext / ciphertext")
            return nil
        }
        // Policy Key Access
        let keyAccess = policyType == .embeddedEncryptedWithPolicyKeyAccess ? readPolicyKeyAccess(bindingMode: bindingMode) : nil

        return EmbeddedPolicyBody(length: plaintextCiphertext.count, body: plaintextCiphertext, keyAccess: keyAccess)
    }

    func readEccAndBindingMode() -> PolicyBindingConfig? {
        guard let eccAndBindingModeData = read(length: 1),
              let eccAndBindingMode = eccAndBindingModeData.first
        else {
            print("Failed to read BindingMode")
            return nil
        }
//        let eccModeHex = String(format: "%02x", eccAndBindingMode)
//        print("ECC Mode Hex:", eccModeHex)
        let ecdsaBinding = (eccAndBindingMode & (1 << 7)) != 0
        let ephemeralECCParamsEnumValue = Curve(rawValue: eccAndBindingMode & 0x7)

        guard let ephemeralECCParamsEnum = ephemeralECCParamsEnumValue else {
            print("Unsupported Ephemeral ECC Params Enum value")
            return nil
        }

//        print("ecdsaBinding: \(ecdsaBinding)")
//        print("ephemeralECCParamsEnum: \(ephemeralECCParamsEnum)")

        return PolicyBindingConfig(ecdsaBinding: ecdsaBinding, curve: ephemeralECCParamsEnum)
    }

    func readSymmetricAndPayloadConfig() -> SignatureAndPayloadConfig? {
        guard let data = read(length: 1)
        else {
            return nil
        }
        // print("SymmetricAndPayloadConfig read serialized data:", data.map { String($0, radix: 16) })
        guard data.count == 1 else { return nil }
        let byte = data[0]
        let signed = (byte & 0b1000_0000) != 0
        let signatureECCMode = Curve(rawValue: (byte & 0b0111_0000) >> 4)
        let cipher = Cipher(rawValue: byte & 0b0000_1111)

        guard let signatureMode = signatureECCMode, let symmetricCipher = cipher else {
            return nil
        }

        return SignatureAndPayloadConfig(signed: signed, signatureCurve: signatureMode, payloadCipher: symmetricCipher)
    }

    func readPolicyBinding(bindingMode: PolicyBindingConfig) -> Data? {
        var bindingSize: Int
//        print("bindingMode", bindingMode)
        if bindingMode.ecdsaBinding {
            switch bindingMode.curve {
            case .secp256r1, .xsecp256k1:
                bindingSize = 64
            case .secp384r1:
                bindingSize = 96
            case .secp521r1:
                bindingSize = 132
            }
        } else {
            // GMAC Tag Binding
            bindingSize = 16
        }
//        print("bindingSize", bindingSize)
        return read(length: bindingSize)
    }

    func readPolicyKeyAccess(bindingMode: PolicyBindingConfig) -> PolicyKeyAccess? {
        let keySize = switch bindingMode.curve {
        case .secp256r1:
            65
        case .secp384r1:
            97
        case .secp521r1:
            133
        case .xsecp256k1:
            65
        }

        guard let resourceLocator = readResourceLocator(),
              let ephemeralPublicKey = read(length: keySize)
        else {
            return nil
        }

        return PolicyKeyAccess(resourceLocator: resourceLocator, ephemeralPublicKey: ephemeralPublicKey)
    }

    public func parseHeader() throws -> Header {
//        print("Starting to parse header")
        
        guard let magicNumber = read(length: FieldSize.magicNumberSize) else {
            throw ParsingError.invalidFormat
        }
//        print("Read Magic Number: \(magicNumber), Expected: \(Header.magicNumber)")
        guard magicNumber == Header.magicNumber else {
            throw ParsingError.invalidMagicNumber
        }
        
        guard let versionData = read(length: FieldSize.versionSize) else {
            throw ParsingError.invalidFormat
        }
        let versionDataInt = Int(versionData[0])
        guard versionDataInt == Header.version else {
            throw ParsingError.invalidVersion
        }
//        let version = versionData[0]
//        print("Version: \(String(format: "%02X", version))")
        guard let kas = readResourceLocator(),
              let policyBindingConfig = readEccAndBindingMode(),
              let payloadSignatureConfig = readSymmetricAndPayloadConfig(),
              let policy = readPolicyField(bindingMode: policyBindingConfig)
        else {
            throw ParsingError.invalidFormat
        }

        let ephemeralPublicKeySize = switch policyBindingConfig.curve {
        case .secp256r1:
            33
        case .secp384r1:
            49
        case .secp521r1:
            67
        case .xsecp256k1:
            33
        }
        guard let ephemeralPublicKey = read(length: ephemeralPublicKeySize) else {
            throw ParsingError.invalidFormat
        }

        return Header(
            kas: kas,
            policyBindingConfig: policyBindingConfig,
            payloadSignatureConfig: payloadSignatureConfig,
            policy: policy,
            ephemeralPublicKey: ephemeralPublicKey
        )
    }

    public func parsePayload(config: SignatureAndPayloadConfig) throws -> Payload {
        guard let lengthData = read(length: FieldSize.payloadLengthSize)
        else {
            throw ParsingError.invalidFormat
        }
        let byte1 = UInt32(lengthData[0]) << 16
        let byte2 = UInt32(lengthData[1]) << 8
        let byte3 = UInt32(lengthData[2])
        let length: UInt32 = byte1 | byte2 | byte3
//        print("parsePayload length", length)
        // IV nonce
        guard let iv = read(length: FieldSize.payloadIvSize)
        else {
            throw ParsingError.invalidFormat
        }
        // MAC Auth tag
        let payloadMACSize: Int
        switch config.payloadCipher {
        case .aes256GCM64:
            payloadMACSize = 8
        case .aes256GCM96:
            payloadMACSize = 12
        case .aes256GCM104:
            payloadMACSize = 13
        case .aes256GCM112:
            payloadMACSize = 14
        case .aes256GCM120:
            payloadMACSize = 15
        case .aes256GCM128:
            payloadMACSize = 16
        case .none:
            throw ParsingError.invalidFormat
        }
        // cipherText
        let cipherTextLength = Int(length) - payloadMACSize - FieldSize.payloadIvSize
//        print("cipherTextLength", cipherTextLength)
        guard let ciphertext = read(length: cipherTextLength),
              let payloadMAC = read(length: payloadMACSize)
        else {
            throw ParsingError.invalidPayload
        }
        let payload = Payload(length: length, iv: iv, ciphertext: ciphertext, mac: payloadMAC)
        return payload
    }

    public func parseSignature(config: SignatureAndPayloadConfig) throws -> Signature? {
        if !config.signed {
            return nil
        }
        let publicKeyLength: Int
        let signatureLength: Int
//        print("config.signatureECCMode", config)
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
//        print("publicKeyLength", publicKeyLength)
//        print("signatureLength", signatureLength)
        guard let publicKey = read(length: publicKeyLength),
              let signature = read(length: signatureLength)
        else {
            print("publicKey or signatureLength read error")
            throw ParsingError.invalidFormat
        }
        return Signature(publicKey: publicKey, signature: signature)
    }
}

// see https://github.com/opentdf/spec/tree/main/schema/nanotdf
enum FieldSize {
    static let magicNumberSize = 2
    static let versionSize = 1
    static let minKASSize = 3
    static let maxKASSize = 257
    static let eccModeSize = 1
    static let payloadSigModeSize = 1
    static let minPolicySize = 3
    static let maxPolicySize = 257
    static let minEphemeralKeySize = 33
    static let maxEphemeralKeySize = 133
    static let payloadLengthSize = 3
    static let payloadIvSize = 3
    static let minPayloadMacSize = 8
    static let maxPayloadMacSize = 32
}

public enum ParsingError: Error {
    case invalidFormat
    case invalidMagicNumber
    case invalidVersion
    case invalidKAS
    case invalidECCMode
    case invalidPayloadSigMode
    case invalidPolicy
    case invalidEphemeralKey
    case invalidPayload
    case invalidPublicKeyLength
    case invalidSignatureLength
    case invalidSigning
}
