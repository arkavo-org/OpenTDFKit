import Foundation

public class BinaryParser {
    var data: Data
    var cursor: Int = 0

    public init(data: Data) {
        self.data = data
    }

    func read(length: Int) -> Data? {
        guard length >= 0, cursor >= 0, cursor <= data.count, length <= data.count - cursor else {
            return nil
        }
        let start = data.startIndex + cursor
        let end = start + length
        cursor += length
        // Use zero-copy slicing instead of subdata to avoid allocations
        return data[start ..< end]
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

        // Get the protocol enum (0x0F maps to sharedResourceDirectory, which has rawValue 0xFF)
        let protocolEnumValue: ProtocolEnum
        if protocolValue == 0x0F {
            protocolEnumValue = .sharedResourceDirectory
        } else if let parsedProtocol = ProtocolEnum(rawValue: protocolValue) {
            protocolEnumValue = parsedProtocol
        } else {
            return nil
        }

        // Read body length and body
        guard let bodyLength = readByte(),
              let body = read(length: Int(bodyLength)),
              let bodyString = String(data: body, encoding: .utf8)
        else {
            return nil
        }

        // Read identifier if present (only identifier types 0...3 are valid per spec 3.4.1.1)
        let identifierSize: Int
        switch identifierType {
        case 0: identifierSize = 0
        case 1: identifierSize = 2
        case 2: identifierSize = 8
        case 3: identifierSize = 32
        default:
            return nil
        }

        var identifier: Data? = nil
        if identifierSize > 0 {
            guard let identifierData = read(length: identifierSize) else {
                return nil
            }
            identifier = identifierData
        }

        return ResourceLocator(protocolEnum: protocolEnumValue, body: bodyString, identifier: identifier)
    }

    private func readPolicyField(bindingMode: PolicyBindingConfig) throws -> Policy? {
        guard let policyTypeByte = readByte(),
              let policyType = Policy.PolicyType(rawValue: policyTypeByte)
        else {
            return nil
        }

        switch policyType {
        case .remote:
            guard let resourceLocator = readResourceLocator() else {
                throw ParsingError.invalidPolicy
            }
            // Binding
            guard let binding = readPolicyBinding(bindingMode: bindingMode) else {
                throw ParsingError.invalidPolicy
            }
            return Policy(type: .remote, body: nil, remote: resourceLocator, binding: binding)
        case .embeddedPlaintext, .embeddedEncrypted, .embeddedEncryptedWithPolicyKeyAccess:
            let policyData = try readEmbeddedPolicyBody(policyType: policyType, bindingMode: bindingMode)
            // Binding
            guard let binding = readPolicyBinding(bindingMode: bindingMode) else {
                throw ParsingError.invalidPolicy
            }
            return Policy(type: policyType, body: policyData, remote: nil, binding: binding)
        }
    }

    private func readEmbeddedPolicyBody(policyType: Policy.PolicyType, bindingMode: PolicyBindingConfig) throws -> EmbeddedPolicyBody? {
        guard let contentLengthData = read(length: 2)
        else {
            throw ParsingError.invalidPolicy
        }
        let i0 = contentLengthData.startIndex
        let contentLength = (UInt16(contentLengthData[i0]) << 8) | UInt16(contentLengthData[contentLengthData.index(after: i0)])

        // Note 3.4.2.3.2 Body for Embedded Policy states Minimum Length is 1
        if contentLength == 0 {
            throw ParsingError.invalidPolicy
        }

        guard let plaintextCiphertext = read(length: Int(contentLength)) else {
            throw ParsingError.invalidPolicy
        }
        // Policy Key Access (required when policyType is .embeddedEncryptedWithPolicyKeyAccess)
        let keyAccess: PolicyKeyAccess?
        if policyType == .embeddedEncryptedWithPolicyKeyAccess {
            guard let parsedKeyAccess = readPolicyKeyAccess(bindingMode: bindingMode) else {
                throw ParsingError.invalidPolicy
            }
            keyAccess = parsedKeyAccess
        } else {
            keyAccess = nil
        }

        return EmbeddedPolicyBody(body: plaintextCiphertext, keyAccess: keyAccess)
    }

    func readEccAndBindingMode() -> PolicyBindingConfig? {
        guard let eccAndBindingMode = readByte() else {
            return nil
        }
        let ecdsaBinding = (eccAndBindingMode & (1 << 7)) != 0
        let ephemeralECCParamsEnumValue = Curve(rawValue: eccAndBindingMode & 0x7)

        guard let ephemeralECCParamsEnum = ephemeralECCParamsEnumValue else {
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

    /// Parses a NanoTDF header and advances the cursor.
    /// Only v12 ("L1L") headers are accepted; v13 ("L1M") headers are rejected.
    /// - Returns: An initialized `Header` object.
    /// - Throws: `ParsingError` if the header is malformed or uses an unsupported version.
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

        // Branch based on version. v13 ("L1M") creation and rewrap support has been
        // removed; only v12 ("L1L") NanoTDFs are supported.
        switch version {
        case 0x4C: // v12 "L1L"
            return try parseHeaderV12()
        case 0x4D: // v13 "L1M" — no longer supported
            throw ParsingError.invalidVersion
        default:
            throw ParsingError.invalidVersion
        }
    }

    private func parseHeaderV12() throws -> Header {
        // Parse the legacy single-field ResourceLocator KAS for v12
        guard let kas = readResourceLocator(),
              let policyBindingConfig = readEccAndBindingMode(),
              let payloadSignatureConfig = readSymmetricAndPayloadConfig(),
              let policy = try readPolicyField(bindingMode: policyBindingConfig)
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

    public func parsePayload(config: SignatureAndPayloadConfig) throws -> Payload {
        guard let lengthData = read(length: FieldSize.payloadLengthSize), lengthData.count == FieldSize.payloadLengthSize else {
            throw ParsingError.invalidFormat
        }
        let i0 = lengthData.startIndex
        let i1 = lengthData.index(after: i0)
        let i2 = lengthData.index(after: i1)
        let length: UInt32 = (UInt32(lengthData[i0]) << 16) | (UInt32(lengthData[i1]) << 8) | UInt32(lengthData[i2])

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
        return Payload(length: length, iv: iv, ciphertext: ciphertext, mac: payloadMAC)
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
            throw ParsingError.invalidFormat
        }

        guard let publicKey = read(length: publicKeyLength),
              let signature = read(length: signatureLength)
        else {
            throw ParsingError.invalidFormat
        }
        return Signature(publicKey: publicKey, signature: signature)
    }
}

/// see https://github.com/opentdf/spec/tree/main/schema/nanotdf
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
