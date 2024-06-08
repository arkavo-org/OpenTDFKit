import CryptoKit
import Foundation

struct NanoTDF {
    let header: Header
    let payload: Payload
    let signature: Signature?

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

struct Header {
    let magicNumber: Data
    let version: Data
    let kas: ResourceLocator
    let eccMode: ECCAndBindingMode
    let payloadSigMode: SymmetricAndPayloadConfig
    let policy: Policy
    let ephemeralKey: Data

    func toData() -> Data {
        var data = Data()
        data.append(magicNumber)
        data.append(version)
        data.append(kas.toData())
        data.append(eccMode.toData())
        data.append(payloadSigMode.toData())
        data.append(policy.toData())
        data.append(ephemeralKey)
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
        let lengthBytes = withUnsafeBytes(of: length.bigEndian) { Array($0) }
        data.append(contentsOf: lengthBytes[1...3]) // Append the last 3 bytes to represent a 3-byte length
        data.append(iv)
        data.append(ciphertext)
        data.append(mac)
        return data
    }
}

struct ECCAndBindingMode {
    var useECDSABinding: Bool
    var ephemeralECCParamsEnum: ECDSAParams
    
    func toData() -> Data {
        var byte: UInt8 = 0
        if useECDSABinding {
            byte |= 0b10000000 // Set the USE_ECDSA_BINDING bit (bit 7)
        }
        byte |= (ephemeralECCParamsEnum.rawValue & 0b00000111) // Set the Ephemeral ECC Params Enum bits (bits 0-2)
        return Data([byte])
    }
}

struct SymmetricAndPayloadConfig {
    let hasSignature: Bool
    let signatureECCMode: ECDSAParams?
    let symmetricCipherEnum: SymmetricCiphers?
    
    func toData() -> Data {
        var byte: UInt8 = 0
        if hasSignature {
            byte |= 0b10000000 // Set the HAS_SIGNATURE bit (bit 7)
        }
        if let signatureECCMode = signatureECCMode {
            byte |= (signatureECCMode.rawValue & 0b00000111) << 4 // Set the Signature ECC Mode bits (bits 4-6)
        }
        if let symmetricCipherEnum = symmetricCipherEnum {
            byte |= (symmetricCipherEnum.rawValue & 0b00001111) // Set the Symmetric Cipher Enum bits (bits 0-3)
        }
        return Data([byte])
    }
}

enum ProtocolEnum: UInt8, Codable {
    case http = 0x00
    case https = 0x01
    case unreserved = 0x02
    case sharedResourceDirectory = 0xFF
}

struct ResourceLocator: Codable {
    let protocolEnum: ProtocolEnum
    let body: String
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
        case embeddedEncryptedWithPolicyKeyAccess = 0x03
    }

    let type: PolicyType
    let body: Data?
    let remote: ResourceLocator?
    let binding: Data?
    
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
                data.append(body)
            }
        }
        if let binding = binding {
            data.append(binding)
        }
        return data
    }
}

struct EmbeddedPolicyBody {
    let contentLength: UInt16
    let plaintextCiphertext: Data?
    let policyKeyAccess: Data?
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

enum ECDSAParams: UInt8 {
    case secp256r1 = 0x00
    case secp384r1 = 0x01
    case secp521r1 = 0x02
    case secp256k1 = 0x03
}

enum SymmetricCiphers: UInt8 {
    case GCM_64 = 0x00
    case GCM_96 = 0x01
    case GCM_104 = 0x02
    case GCM_112 = 0x03
    case GCM_120 = 0x04
    case GCM_128 = 0x05
}

class BinaryParser {
    var data: Data
    var cursor: Int = 0

    init(data: Data) {
        self.data = data
    }

    func read(length: Int) -> Data? {
        print("Length: \(length)")
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
        let protocolHex = String(format: "%02x", protocolEnum)
        print("Protocol Hex:", protocolHex)
        let bodyLengthlHex = String(format: "%02x", bodyLength)
        print("Body Length Hex:", bodyLengthlHex)
        let bodyHexString = body.map { String(format: "%02x", $0) }.joined(separator: " ")
        print("Body Hex:", bodyHexString)
        print("bodyString: \(bodyString)")
        return ResourceLocator(protocolEnum: protocolEnumValue, body: bodyString)
    }

    private func readPolicyField() -> Policy? {
        print("readPolicyField")
        guard let typeEnum = read(length: 1),
              let type = typeEnum.first
        else {
            print("Failed to read Type Enum")
            return nil
        }

        switch type {
        case 0x00:
            // Remote Policy
            print("Remote Policy")
            guard let resourceLocator = readResourceLocator() else {
                print("Failed to read Remote Policy resource locator")
                return nil
            }
            // Binding
            guard let binding = readPolicyBinding() else {
                print("Failed to read Remote Policy binding")
                return nil
            }
            return Policy(type: .remote, body: nil, remote: resourceLocator, binding: binding)

        case 0x01, 0x02, 0x03:
            // Embedded Policy (Plaintext or Encrypted)
            let policyData = readEmbeddedPolicyBody()
            // Binding
            guard let binding = readPolicyBinding() else {
                print("Failed to read Remote Policy binding")
                return nil
            }
            return Policy(type: .embeddedPlaintext, body: policyData?.plaintextCiphertext, remote: nil, binding: binding)
        default:
            print("Unknown Policy Type Enum value")
            return nil
        }
    }

    private func readEmbeddedPolicyBody() -> EmbeddedPolicyBody? {
        print("readEmbeddedPolicyBody")
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
            return EmbeddedPolicyBody(contentLength: contentLength, plaintextCiphertext: nil, policyKeyAccess: nil)
        }

        guard let plaintextCiphertext = read(length: Int(contentLength)) else {
            print("Failed to read Embedded Policy plaintext / ciphertext")
            return nil
        }

        var policyKeyAccess: Data?
        if cursor < data.count {
            policyKeyAccess = read(length: data.count - cursor)
        }

        return EmbeddedPolicyBody(contentLength: contentLength, plaintextCiphertext: plaintextCiphertext, policyKeyAccess: policyKeyAccess)
    }

    func readEccAndBindingMode() -> ECCAndBindingMode? {
        print("readEccAndBindingMode")
        guard let eccAndBindingModeData = read(length: 1),
              let eccAndBindingMode = eccAndBindingModeData.first
        else {
            print("Failed to read BindingMode")
            return nil
        }
        let eccModeHex = String(format: "%02x", eccAndBindingMode)
        print("ECC Mode Hex:", eccModeHex)
        let useECDSABinding = (eccAndBindingMode & (1 << 7)) != 0
        let ephemeralECCParamsEnumValue = ECDSAParams(rawValue: eccAndBindingMode & 0x7)

        guard let ephemeralECCParamsEnum = ephemeralECCParamsEnumValue else {
            print("Unsupported Ephemeral ECC Params Enum value")
            return nil
        }

        print("useECDSABinding: \(useECDSABinding)")
        print("ephemeralECCParamsEnum: \(ephemeralECCParamsEnum)")

        return ECCAndBindingMode(useECDSABinding: useECDSABinding, ephemeralECCParamsEnum: ephemeralECCParamsEnum)
    }

    func readSymmetricAndPayloadConfig() -> SymmetricAndPayloadConfig? {
        print("readSymmetricAndPayloadConfig")
        guard let symmetricAndPayloadConfigData = read(length: 1),
              let symmetricAndPayloadConfig = symmetricAndPayloadConfigData.first
        else {
            print("Failed to read Symmetric and Payload Config")
            return nil
        }
        let symmetricAndPayloadConfigHex = String(format: "%02x", symmetricAndPayloadConfig)
        print("Symmetric And Payload Config Hex:", symmetricAndPayloadConfigHex)
        let hasSignature = (symmetricAndPayloadConfig & 0x80) >> 7 != 0
        let signatureECCModeEnum = ECDSAParams(rawValue: (symmetricAndPayloadConfig & 0x70) >> 4)
        let symmetricCipherEnum = SymmetricCiphers(rawValue: symmetricAndPayloadConfig & 0x0F)

        print("hasSignature: \(hasSignature)")
        print("signatureECCModeEnum: \(String(describing: signatureECCModeEnum))")
        print("symmetricCipherEnum: \(String(describing: symmetricCipherEnum))")

        return SymmetricAndPayloadConfig(hasSignature: hasSignature,
                                         signatureECCMode: signatureECCModeEnum,
                                         symmetricCipherEnum: symmetricCipherEnum)
    }

    func readPolicyBinding() -> Data? {
        // The length should be determined based on the ECC and Binding Mode described
        let bindingLength = determinePolicyBindingLength() // This function needs to be implemented based on ECC and Binding Mode
        return read(length: bindingLength)
    }

    private func determinePolicyBindingLength() -> Int {
        // This should return the correct length based on ECC and Binding Mode
        // Placeholder: returning a typical length for an ECDSA signature
        return 64 // Example length, adjust based on actual application requirements
    }

    func parseHeader() throws -> Header {
        guard let magicNumber = read(length: FieldSize.magicNumberSize),
              let version = read(length: FieldSize.versionSize),
              let kas = readResourceLocator(),
              let eccMode = readEccAndBindingMode(),
              let payloadSigMode = readSymmetricAndPayloadConfig(),
              let policy = readPolicyField()
        else {
            throw ParsingError.invalidFormat
        }

        let ephemeralKeySize: Int
        switch eccMode.ephemeralECCParamsEnum {
        case .secp256r1:
            ephemeralKeySize = 33
        case .secp384r1:
            ephemeralKeySize = 49
        case .secp521r1:
            ephemeralKeySize = 67
        case .secp256k1:
            ephemeralKeySize = 33
        }
        guard let ephemeralKey = read(length: ephemeralKeySize) else {
            throw ParsingError.invalidFormat
        }
        
        return Header(magicNumber: magicNumber, version: version, kas: kas, eccMode: eccMode, payloadSigMode: payloadSigMode, policy: policy, ephemeralKey: ephemeralKey)
    }

    func parsePayload(config: SymmetricAndPayloadConfig) throws -> Payload {
        guard let lengthData = read(length: FieldSize.payloadCipherTextSize)
        else {
            throw ParsingError.invalidFormat
        }
        var length: UInt32 = 0
        let count = lengthData.count
        for i in 0..<count {
            length += UInt32(lengthData[i]) << (8 * (count - 1 - i))
        }
        // IV nonce
        guard let iv = read(length: FieldSize.payloadIvSize)
        else {
            throw ParsingError.invalidFormat
        }
        // MAC Auth tag
        let payloadMACSize: Int
        switch config.symmetricCipherEnum {
        case .GCM_64:
            payloadMACSize = 8
        case .GCM_96:
            payloadMACSize = 12
        case .GCM_104:
            payloadMACSize = 13
        case .GCM_112:
            payloadMACSize = 14
        case .GCM_120:
            payloadMACSize = 15
        case .GCM_128:
            payloadMACSize = 16
        case .none:
            throw ParsingError.invalidFormat
        }
        // cipherText
        let cipherTextLength = Int(length) - payloadMACSize - FieldSize.payloadIvSize
        print("cipherTextLength", cipherTextLength)
        guard let ciphertext = read(length: cipherTextLength),
            let payloadMAC = read(length: FieldSize.minPayloadMacSize)
        else {
            throw ParsingError.invalidFormat
        }
        let payload = Payload(length: length, iv: iv, ciphertext: ciphertext, mac: payloadMAC)
        return payload
    }
    
    func parseSignature(config: SymmetricAndPayloadConfig) throws -> Signature? {
        if !config.hasSignature {
            return nil
        }
        let publicKeyLength: Int
        let signatureLength: Int
        print("config.signatureECCMode", config)
        switch config.signatureECCMode {
        case .secp256r1, .secp256k1:
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
        print("publicKeyLength", publicKeyLength)
        print("signatureLength", signatureLength)
        guard let publicKey = read(length: publicKeyLength),
              let signature = read(length: signatureLength) else {
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
    static let payloadCipherTextSize = 3
    static let payloadIvSize = 3
    static let minPayloadMacSize = 8
    static let maxPayloadMacSize = 32
}

enum ParsingError: Error {
    case invalidFormat
    case invalidMagicNumber
    case invalidVersion
    case invalidKAS
    case invalidECCMode
    case invalidPayloadSigMode
    case invalidPolicy
    case invalidEphemeralKey
    case invalidPayload
}
