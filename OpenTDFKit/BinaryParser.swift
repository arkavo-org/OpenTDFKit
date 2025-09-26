import Foundation

public class BinaryParser {
    var data: Data
    var cursor: Int = 0

    public init(data: Data) {
        self.data = data
    }

    func read(length: Int) -> Data? {
        guard length > 0 else { return nil }
        guard cursor >= 0 else { return nil }
        guard !data.isEmpty else { return nil }
        guard cursor + length <= data.count else { return nil }
        let range = cursor ..< (cursor + length)
        cursor += length
        // Use zero-copy slicing instead of subdata to avoid allocations
        return data[range]
    }

    @inline(__always)
    private func readByte() -> UInt8? {
        guard let d = read(length: 1) else { return nil }
        return d.first
    }

    private func readResourceLocator() -> ResourceLocator? {
        guard let protocolByte = readByte() else {
            return nil
        }

        // Extract protocol (bits 3-0) and identifier type (bits 7-4)
        let protocolValue = protocolByte & 0x0F
        let identifierType = (protocolByte >> 4) & 0x0F

        // Get the protocol enum
        guard let protocolEnumValue = ProtocolEnum(rawValue: protocolValue) else {
            return nil
        }

        // Read body length and body
        guard let bodyLength = readByte(),
              let body = read(length: Int(bodyLength)),
              let bodyString = String(data: body, encoding: .utf8)
        else {
            return nil
        }

        // Read identifier if present
        let identifierSizes: [UInt8: Int] = [0: 0, 1: 2, 2: 8, 3: 32]
        let identifierSize = identifierSizes[identifierType] ?? 0

        var identifier: Data? = nil
        if identifierSize > 0 {
            guard let identifierData = read(length: identifierSize) else {
                return nil
            }
            identifier = identifierData
        }

        return ResourceLocator(protocolEnum: protocolEnumValue, body: bodyString, identifier: identifier)
    }

    private func readPolicyField(bindingMode: PolicyBindingConfig) -> Policy? {
        guard let policyTypeByte = readByte(),
              let policyType = Policy.PolicyType(rawValue: policyTypeByte)
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
            return Policy(type: policyType, body: policyData, remote: nil, binding: binding)
        }
    }

    private func readEmbeddedPolicyBody(policyType: Policy.PolicyType, bindingMode: PolicyBindingConfig) -> EmbeddedPolicyBody? {
        guard let contentLengthData = read(length: 2)
        else {
            print("Failed to read Embedded Policy content length")
            return nil
        }
        let plaintextCiphertextLengthData = contentLengthData.prefix(2)

        let bytes = Array(plaintextCiphertextLengthData)
        let contentLength = (UInt16(bytes[0]) << 8) | UInt16(bytes[1])

        // if no policy added then no read
        // Note 3.4.2.3.2 Body for Embedded Policy states Minimum Length is 1
        if contentLength == 0 {
            return EmbeddedPolicyBody(body: Data([0x00]), keyAccess: nil)
        }

        guard let plaintextCiphertext = read(length: Int(contentLength)) else {
            print("Failed to read Embedded Policy plaintext / ciphertext")
            return nil
        }
        // Policy Key Access
        let keyAccess = policyType == .embeddedEncryptedWithPolicyKeyAccess ? readPolicyKeyAccess(bindingMode: bindingMode) : nil

        return EmbeddedPolicyBody(body: plaintextCiphertext, keyAccess: keyAccess)
    }

    func readEccAndBindingMode() -> PolicyBindingConfig? {
        guard let eccAndBindingMode = readByte() else {
            print("Failed to read BindingMode")
            return nil
        }
        let ecdsaBinding = (eccAndBindingMode & (1 << 7)) != 0
        let ephemeralECCParamsEnumValue = Curve(rawValue: eccAndBindingMode & 0x7)

        guard let ephemeralECCParamsEnum = ephemeralECCParamsEnumValue else {
            print("Unsupported Ephemeral ECC Params Enum value")
            return nil
        }

        return PolicyBindingConfig(ecdsaBinding: ecdsaBinding, curve: ephemeralECCParamsEnum)
    }

    func readSymmetricAndPayloadConfig() -> SignatureAndPayloadConfig? {
        guard let byte = readByte() else {
            return nil
        }
        let signed = (byte & 0b1000_0000) != 0
        let signatureECCMode = Curve(rawValue: (byte & 0b0111_0000) >> 4)
        let cipher = Cipher(rawValue: byte & 0b0000_1111)

        // FIXME: signatureECCMode can be nil if curve is not supported by SDK - secp256k1 0x03
        guard let symmetricCipher = cipher else {
            return nil
        }

        return SignatureAndPayloadConfig(signed: signed, signatureCurve: signatureECCMode, payloadCipher: symmetricCipher)
    }

    func readPolicyBinding(bindingMode: PolicyBindingConfig) -> Data? {
        let bindingSize = if bindingMode.ecdsaBinding {
            switch bindingMode.curve {
            case .secp256r1:
                64
            case .secp384r1:
                96
            case .secp521r1:
                132
            }
        } else {
            // GMAC Tag Binding - 64 bits (8 bytes) per spec section 3.3.1.3
            8
        }
        return read(length: bindingSize)
    }

    func readPolicyKeyAccess(bindingMode: PolicyBindingConfig) -> PolicyKeyAccess? {
        let keySize = bindingMode.curve.publicKeyLength // Use compressed key length

        guard let resourceLocator = readResourceLocator(),
              let ephemeralPublicKey = read(length: keySize)
        else {
            return nil
        }

        return PolicyKeyAccess(resourceLocator: resourceLocator, ephemeralPublicKey: ephemeralPublicKey)
    }

    /// Reads a PayloadKeyAccess structure and advances the cursor.
    /// - Parameter version: The version of the NanoTDF format (v12 or v13)
    /// - Returns: An initialized `PayloadKeyAccess` object if parsing is successful, otherwise `nil`.
    func readPayloadKeyAccess(version: UInt8? = nil) -> PayloadKeyAccess? {
        // 1. Parse KAS Endpoint Locator (ResourceLocator)
        guard let kasEndpointLocator = readResourceLocator() else {
            return nil
        }

        // 2. Read the curve byte
        guard let curveRaw = readByte(),
              let curve = Curve(rawValue: curveRaw)
        else {
            return nil
        }

        // For v12 format, we don't have a public key
        if version == 0x4C { // v12 "L1L"
            return PayloadKeyAccess(kasEndpointLocator: kasEndpointLocator, kasPublicKey: Data())
        }

        // For v13 format, read the key based on the curve size
        let expectedPublicKeyLength = curve.publicKeyLength
        guard expectedPublicKeyLength > 0 else { return nil }

        // Read the public key
        guard let kasPublicKey = read(length: expectedPublicKeyLength) else {
            return nil
        }

        return PayloadKeyAccess(kasEndpointLocator: kasEndpointLocator, kasPublicKey: kasPublicKey)
    }

    public func parseHeader() throws -> Header {
        // Read the Magic Number first
        guard let magicNumber = read(length: FieldSize.magicNumberSize) else {
            throw ParsingError.invalidFormat
        }
        guard magicNumber == Header.magicNumber else {
            throw ParsingError.invalidMagicNumber
        }

        // Read the Version
        guard let version = readByte() else {
            throw ParsingError.invalidFormat
        }

        // Branch based on version
        switch version {
        case 0x4C: // v12 "L1L"
            return try parseHeaderV12()
        case 0x4D: // v13 "L1M"
            return try parseHeaderV13()
        default:
            throw ParsingError.invalidVersion
        }
    }

    private func parseHeaderV12() throws -> Header {
        // Parse the legacy single-field ResourceLocator KAS for v12
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
        }
        guard let ephemeralPublicKey = read(length: ephemeralPublicKeySize) else {
            throw ParsingError.invalidFormat
        }

        // Create a PayloadKeyAccess from the legacy KAS ResourceLocator
        // For v12 format, the KAS public key is not present in the header.
        // We represent this with an empty Data object for kasPublicKey.
        let payloadKeyAccess = PayloadKeyAccess(
            kasEndpointLocator: kas,
            kasPublicKey: Data(), // For v12, KAS public key is empty.
        )

        return Header(
            payloadKeyAccess: payloadKeyAccess,
            policyBindingConfig: policyBindingConfig,
            payloadSignatureConfig: payloadSignatureConfig,
            policy: policy,
            ephemeralPublicKey: ephemeralPublicKey,
        )
    }

    private func parseHeaderV13() throws -> Header {
        // Parse the new three-field PayloadKeyAccess structure for v13
        guard let payloadKeyAccess = readPayloadKeyAccess(version: 0x4D) else {
            throw ParsingError.invalidKAS
        }

        guard let policyBindingConfig = readEccAndBindingMode(),
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
        }
        guard let ephemeralPublicKey = read(length: ephemeralPublicKeySize) else {
            throw ParsingError.invalidFormat
        }

        return Header(
            payloadKeyAccess: payloadKeyAccess,
            policyBindingConfig: policyBindingConfig,
            payloadSignatureConfig: payloadSignatureConfig,
            policy: policy,
            ephemeralPublicKey: ephemeralPublicKey,
        )
    }

    public func parsePayload(config: SignatureAndPayloadConfig) throws -> Payload {
        guard let lengthData = read(length: FieldSize.payloadLengthSize)
        else {
            throw ParsingError.invalidFormat
        }
        guard lengthData.count == FieldSize.payloadLengthSize else {
            throw ParsingError.invalidFormat
        }
        let b = Array(lengthData)
        let byte1 = UInt32(b[0]) << 16
        let byte2 = UInt32(b[1]) << 8
        let byte3 = UInt32(b[2])
        let length: UInt32 = byte1 | byte2 | byte3

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
        guard cipherTextLength >= 0 else {
            throw ParsingError.invalidPayload("Calculated ciphertext length is negative")
        }

        guard let ciphertext = read(length: cipherTextLength),
              let payloadMAC = read(length: payloadMACSize)
        else {
            throw ParsingError.invalidPayload("Failed to read ciphertext or payload MAC")
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
        switch config.signatureCurve {
        case .secp256r1:
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
    case invalidPayload(String = "Invalid payload")
    case invalidPublicKeyLength
    case invalidSignatureLength
    case invalidSigning
}
