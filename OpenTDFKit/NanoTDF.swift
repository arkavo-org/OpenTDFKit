@preconcurrency import CryptoKit
import Foundation

/// Represents a NanoTDF (Nano Trusted Data Format) object, containing a header, payload, and optional signature.
/// Conforms to `Sendable` for safe use in concurrent contexts.
public struct NanoTDF: Sendable {
    /// The header section of the NanoTDF, containing metadata like KAS info, policy, and ephemeral key.
    public var header: Header
    /// The encrypted payload section of the NanoTDF.
    public let payload: Payload
    /// An optional signature section for verifying the integrity and authenticity of the header and payload.
    public var signature: Signature?

    /// Initializes a NanoTDF object.
    /// - Parameters:
    ///   - header: The `Header` struct.
    ///   - payload: The `Payload` struct.
    ///   - signature: An optional `Signature` struct.
    public init(header: Header, payload: Payload, signature: Signature? = nil) {
        self.header = header
        self.payload = payload
        self.signature = signature
    }

    /// Serializes the entire NanoTDF object (header, payload, and optional signature) into a single `Data` object.
    /// - Returns: A `Data` object representing the serialized NanoTDF.
    public func toData() -> Data {
        var data = Data()
        data.append(header.toData())
        data.append(payload.toData())
        if let signature {
            data.append(signature.toData())
        }
        return data
    }

    /// Decrypts the payload ciphertext using the provided symmetric key.
    /// Handles nonce padding/adjusting internally.
    /// - Parameter symmetricKey: The `SymmetricKey` derived during the TDF creation or key access process.
    /// - Returns: The original plaintext `Data`.
    /// - Throws: Errors from `CryptoHelper` or `CryptoKit` if decryption fails (e.g., incorrect key, corrupted data).
    public func getPayloadPlaintext(symmetricKey: SymmetricKey) async throws -> Data {
        let cryptoHelper = CryptoHelper()
        // The NanoTDF spec uses a 3-byte IV, but AES-GCM typically requires a 12-byte nonce.
        // Adjust the IV to 12 bytes (e.g., by padding). The CryptoHelper handles this.
        let paddedIV = await cryptoHelper.adjustNonce(payload.iv, to: 12)
        return try await cryptoHelper.decryptPayload(
            ciphertext: payload.ciphertext,
            symmetricKey: symmetricKey,
            nonce: paddedIV,
            tag: payload.mac
        )
    }
}

/// Creates a NanoTDF object by encrypting the provided plaintext.
/// Follows the NanoTDF creation workflow: ephemeral key generation, key derivation, policy binding, and payload encryption.
/// - Parameters:
///   - kas: The `KasMetadata` containing the KAS URL and public key information.
///   - policy: An `inout` `Policy` struct. The function will calculate and set the `binding` property on this policy object.
///   - plaintext: The `Data` to be encrypted and included in the NanoTDF payload.
/// - Returns: A newly created `NanoTDF` object.
/// - Throws: `CryptoHelperError` if key generation or derivation fails, or errors from `CryptoKit` during cryptographic operations (e.g., binding calculation, encryption).
public func createNanoTDF(kas: KasMetadata, policy: inout Policy, plaintext: Data) async throws -> NanoTDF {
    let cryptoHelper = CryptoHelper()

    // Step 1: Generate an ephemeral key pair based on the KAS curve
    guard let keyPair = await cryptoHelper.generateEphemeralKeyPair(curveType: kas.curve) else {
        throw CryptoHelperError.keyDerivationFailed // Or a more specific error
    }

    // Step 2: Derive the shared secret using ECDH between the ephemeral key pair and the KAS public key
    let kasPublicKey = try kas.getPublicKey() // Get the KAS public key data

    guard let sharedSecret = try await cryptoHelper.deriveSharedSecret(
        keyPair: keyPair,
        recipientPublicKey: kasPublicKey
    ) else {
        throw CryptoHelperError.keyDerivationFailed
    }

    // Step 3: Derive the symmetric TDF key from the shared secret using HKDF
    // NOTE: For NanoTDF v13 ("L1M"), the salt should be SHA256("L1M"). This needs to be updated.
    let tdfSymmetricKey = await cryptoHelper.deriveSymmetricKey(
        sharedSecret: sharedSecret,
        salt: Data("L1L".utf8), // Standard salt for NanoTDF v12. Needs update for v13.
        info: Data("encryption".utf8), // Standard info for NanoTDF
        outputByteCount: 32 // AES-256 key size
    )

    // Extract and potentially encrypt the policy body based on the policy type
    let policyBody: Data
    switch policy.type {
    case .remote:
        guard let remote = policy.remote else {
            // Handle error: Remote policy type must have a remote locator
            throw PolicyError.missingRemoteLocator
        }
        policyBody = remote.toData()
    case .embeddedPlaintext:
        guard let body = policy.body else {
            // Handle error: Embedded policy type must have a body
            throw PolicyError.missingEmbeddedBody
        }
        policyBody = body.toData()
    case .embeddedEncrypted, .embeddedEncryptedWithPolicyKeyAccess:
        guard let body = policy.body else {
            throw PolicyError.missingEmbeddedBody
        }

        if policy.type == .embeddedEncryptedWithPolicyKeyAccess {
            guard let keyAccess = body.keyAccess else {
                throw PolicyError.missingPolicyKeyAccess
            }

            // CRITICAL: For embedded encrypted policies with key access:
            // 1. Generate a new ephemeral key pair specifically for policy encryption
            // 2. Get the Policy KAS public key (which would be provided separately)
            // 3. Create a new PolicyKeyAccess with our newly generated ephemeral public key
            // 4. Encrypt policy with the shared secret derived from our ephemeral private key and Policy KAS public key

            // Get the original Policy KAS public key
            // Note: In a real implementation, we would look up this key from a keystore based on
            // the keyAccess.resourceLocator, but for now we'll use the provided key
            let policyKasPublicKey = keyAccess.ephemeralPublicKey

            // Generate a new ephemeral key pair specifically for policy encryption
            guard let policyEphemeralKeyPair = await cryptoHelper.generateEphemeralKeyPair(curveType: kas.curve) else {
                throw CryptoHelperError.keyGenerationFailed
            }

            // Create a new PolicyKeyAccess with our generated ephemeral public key
            // This is the public key that will be included in the TDF for the Policy KAS to use
            let updatedPolicyKeyAccess = PolicyKeyAccess(
                resourceLocator: keyAccess.resourceLocator,
                ephemeralPublicKey: policyEphemeralKeyPair.publicKey
            )

            // Derive a shared secret between our ephemeral private key and the Policy KAS public key
            guard let policySharedSecret = try await cryptoHelper.deriveSharedSecret(
                keyPair: policyEphemeralKeyPair,
                recipientPublicKey: policyKasPublicKey
            ) else {
                throw CryptoHelperError.keyDerivationFailed
            }

            // Derive symmetric key for policy encryption
            // NOTE: For NanoTDF v13 ("L1M"), the salt should be SHA256("L1M"). This needs to be updated.
            let policySymmetricKey = await cryptoHelper.deriveSymmetricKey(
                sharedSecret: policySharedSecret,
                salt: Data("L1L".utf8), // Use standard NanoTDF salt for consistency. Needs update for v13.
                info: Data("policy_encryption".utf8), // Specific context for policy encryption
                outputByteCount: 32
            )

            // NanoTDF spec requires IV of 0x000000 for policy encryption
            let policyIV = Data([0, 0, 0])
            let adjustedIV = await cryptoHelper.adjustNonce(policyIV, to: 12)

            // Encrypt the policy data
            let (encryptedPolicyData, _) = try await cryptoHelper.encryptPayload(
                plaintext: body.body,
                symmetricKey: policySymmetricKey,
                nonce: adjustedIV
            )

            // Create new encrypted policy body with the encrypted data and updated key access
            let encryptedBody = EmbeddedPolicyBody(
                body: encryptedPolicyData,
                keyAccess: updatedPolicyKeyAccess
            )

            // Update policy with encrypted body
            policy.body = encryptedBody
            policyBody = encryptedBody.toData()

        } else if policy.type == .embeddedEncrypted {
            // For embedded encrypted policy without PolicyKeyAccess
            // The policy should be encrypted with the main TDF symmetric key

            // NanoTDF spec requires IV of 0x000000 for policy encryption
            let policyIV = Data([0, 0, 0])
            let adjustedIV = await cryptoHelper.adjustNonce(policyIV, to: 12)

            // Encrypt the policy data using the main TDF symmetric key
            let (encryptedPolicyData, _) = try await cryptoHelper.encryptPayload(
                plaintext: body.body,
                symmetricKey: tdfSymmetricKey, // Use the main TDF symmetric key
                nonce: adjustedIV
            )

            // Create new encrypted policy body with the encrypted data
            let encryptedBody = EmbeddedPolicyBody(
                body: encryptedPolicyData,
                keyAccess: nil // No key access for .embeddedEncrypted
            )

            // Update policy with encrypted body
            policy.body = encryptedBody
            policyBody = encryptedBody.toData()

        } else {
            // For plaintext policies, just use the body as is
            policyBody = body.toData()
        }
    }

    // Create the GMAC policy binding using the derived TDF symmetric key
    let gmacTag = try await cryptoHelper.createGMACBinding(
        policyBody: policyBody,
        symmetricKey: tdfSymmetricKey
    )
    // Update the input policy struct with the calculated binding
    policy.binding = gmacTag

    // Step 4: Generate a 3-byte nonce/IV for the payload encryption
    let nonce = await cryptoHelper.generateNonce(length: 3)
    // Adjust the 3-byte nonce to 12 bytes for AES-GCM compatibility
    let nonce12 = await cryptoHelper.adjustNonce(nonce, to: 12)

    // Step 5: Encrypt the plaintext payload using AES-GCM with the derived TDF key and adjusted nonce
    let (ciphertext, tag) = try await cryptoHelper.encryptPayload(
        plaintext: plaintext,
        symmetricKey: tdfSymmetricKey,
        nonce: nonce12
    )

    // Calculate the total payload length (IV + Ciphertext + Auth Tag)
    // The payload length field uses UInt24 (3 bytes) in the spec.
    let payloadLength = UInt32(nonce.count + ciphertext.count + tag.count)

    // Create the Payload struct
    let payload = Payload(
        length: payloadLength,
        iv: nonce, // Store the original 3-byte IV
        ciphertext: ciphertext,
        mac: tag // Store the 16-byte authentication tag
    )

    // Create the Header struct
    // THIS INITIALIZATION WILL BE BROKEN BY Header.init SIGNATURE CHANGE
    // AND THE `kas` PARAMETER NEEDS TO BE REPLACED WITH A `PayloadKeyAccess` INSTANCE.
    let header = Header(
        kas: kas.resourceLocator, // OLD FIELD: This will cause a compile error. Replace with `payloadKeyAccess`.
        policyBindingConfig: PolicyBindingConfig(ecdsaBinding: false, curve: kas.curve), // Assuming GMAC binding for now
        payloadSignatureConfig: SignatureAndPayloadConfig(
            signed: false, // Signature is added separately
            signatureCurve: kas.curve, // Default to KAS curve, can be overridden if signing
            payloadCipher: .aes256GCM128 // Using AES-256-GCM with 128-bit tag
        ),
        policy: policy, // Use the policy object (now with binding)
        ephemeralPublicKey: keyPair.publicKey // The compressed ephemeral public key
    )

    // Construct and return the final NanoTDF object (without signature initially)
    return NanoTDF(header: header, payload: payload, signature: nil)
}

/// Adds an ECDSA signature to an existing NanoTDF object.
/// Calculates the signature over the header and payload data, then updates the NanoTDF's signature field and header configuration.
/// - Parameters:
///   - nanoTDF: The `inout` `NanoTDF` object to modify.
///   - privateKey: The `P256.Signing.PrivateKey` used to generate the signature.
///   - config: The `SignatureAndPayloadConfig` indicating the desired signature settings (especially the curve).
/// - Throws: `SignatureError.invalidSigning` if signature generation fails, or errors from `CryptoKit`.
public func addSignatureToNanoTDF(nanoTDF: inout NanoTDF, privateKey: P256.Signing.PrivateKey, config: SignatureAndPayloadConfig) async throws {
    let cryptoHelper = CryptoHelper()
    // The message to be signed is the concatenation of the serialized header and payload.
    let message = nanoTDF.header.toData() + nanoTDF.payload.toData()

    // Generate the ECDSA signature using the provided private key.
    // The helper function abstracts away DER encoding details if necessary.
    guard let signatureData = try await cryptoHelper.generateECDSASignature(
        privateKey: privateKey,
        message: message
    ) else {
        // Throw an error if signature generation unexpectedly returns nil
        throw SignatureError.invalidSigning
    }

    // Get the compressed public key corresponding to the private signing key.
    let publicKeyData = privateKey.publicKey.compressedRepresentation
    // Create the Signature struct.
    let signature = Signature(publicKey: publicKeyData, signature: signatureData)

    // Update the NanoTDF object:
    // 1. Set the signature field.
    nanoTDF.signature = signature
    // 2. Update the header's signature configuration to indicate it's signed and specify the curve used.
    nanoTDF.header.payloadSignatureConfig.signed = true
    nanoTDF.header.payloadSignatureConfig.signatureCurve = config.signatureCurve
}

/// Represents the KAS (Key Access Service) information structure in the NanoTDF header,
/// as per NanoTDF Spec v13 ("L1M").
public struct PayloadKeyAccess: Sendable {
    /// Locator for the KAS endpoint.
    public let kasEndpointLocator: ResourceLocator
    /// The elliptic curve of the KAS Public Key.
    public let kasKeyCurve: Curve
    /// The compressed public key of the KAS.
    public let kasPublicKey: Data

    public init(kasEndpointLocator: ResourceLocator, kasKeyCurve: Curve, kasPublicKey: Data) {
        self.kasEndpointLocator = kasEndpointLocator
        self.kasKeyCurve = kasKeyCurve
        self.kasPublicKey = kasPublicKey
    }

    /// Serializes the PayloadKeyAccess into its binary `Data` representation.
    /// Format: KAS Endpoint Locator || KAS Key Curve Enum || KAS Public Key
    public func toData() -> Data {
        var data = Data()
        data.append(kasEndpointLocator.toData())
        data.append(kasKeyCurve.rawValue)
        data.append(kasPublicKey)
        return data
    }

    /// Parses a PayloadKeyAccess structure from the given data at the current index.
    /// Advances the `currentIndex` past the parsed bytes.
    /// - Parameters:
    ///   - data: The `Data` object containing the NanoTDF header bytes.
    ///   - currentIndex: An `inout` `Data.Index` pointing to the start of the PayloadKeyAccess structure.
    /// - Returns: An initialized `PayloadKeyAccess` object if parsing is successful, otherwise `nil`.
    public static func parse(from data: Data, currentIndex: inout Data.Index) -> PayloadKeyAccess? {
        // 1. Parse KAS Endpoint Locator (ResourceLocator)
        // 1.1. Protocol Enum (1 byte)
        guard currentIndex < data.endIndex else { return nil }
        let protocolByte = data[currentIndex]
        guard let protocolEnum = ProtocolEnum(rawValue: protocolByte) else { return nil }
        data.formIndex(after: &currentIndex)

        // 1.2. Body Length (1 byte)
        guard currentIndex < data.endIndex else { return nil }
        let bodyLength = Int(data[currentIndex])
        // As per spec 3.4.1, Body Length is 1 byte, Body is 1-255 bytes.
        // ResourceLocator.init? validates body.utf8.count (1 to 255).
        // If bodyLength is 0, ResourceLocator.init? will return nil.
        guard bodyLength >= 0 && bodyLength <= 255 else { return nil } // bodyLength itself is UInt8
        data.formIndex(after: &currentIndex)

        // 1.3. Body (variable length: bodyLength bytes)
        let bodyEndIndex = data.index(currentIndex, offsetBy: bodyLength, limitedBy: data.endIndex)
        guard let actualBodyEndIndex = bodyEndIndex, currentIndex <= actualBodyEndIndex else { return nil }
        let bodyData = data[currentIndex..<actualBodyEndIndex]
        guard let bodyString = String(data: bodyData, encoding: .utf8) else { return nil }
        currentIndex = actualBodyEndIndex

        guard let kasEndpointLocator = ResourceLocator(protocolEnum: protocolEnum, body: bodyString) else {
            return nil
        }

        // 2. Parse KAS Key Curve Enum (1 byte)
        guard currentIndex < data.endIndex else { return nil }
        let curveByte = data[currentIndex]
        guard let kasKeyCurve = Curve(rawValue: curveByte) else { return nil }
        data.formIndex(after: &currentIndex)

        // 3. Parse KAS Public Key (length determined by kasKeyCurve)
        let expectedPublicKeyLength = kasKeyCurve.publicKeyLength
        // Ensure publicKeyLength is valid (e.g., not 0 if a curve was invalidly defined, though current ones are fine)
        guard expectedPublicKeyLength > 0 else { return nil }

        let publicKeyEndIndex = data.index(currentIndex, offsetBy: expectedPublicKeyLength, limitedBy: data.endIndex)
        guard let actualPublicKeyEndIndex = publicKeyEndIndex, currentIndex <= actualPublicKeyEndIndex else { return nil }
        let kasPublicKey = data[currentIndex..<actualPublicKeyEndIndex]
        currentIndex = actualPublicKeyEndIndex
        
        // Final check that we read the correct amount of data for the public key
        guard kasPublicKey.count == expectedPublicKeyLength else { return nil }


        return PayloadKeyAccess(kasEndpointLocator: kasEndpointLocator,
                                kasKeyCurve: kasKeyCurve,
                                kasPublicKey: kasPublicKey)
    }
}

/// Represents the header section of a NanoTDF object.
/// Contains metadata necessary for processing and decrypting the TDF.
public struct Header: Sendable {
    /// Magic number "L1" identifying the format.
    public static let magicNumber = Data([0x4C, 0x31]) // "L1"
    /// Version identifier for the NanoTDF specification (0x4D for v13 "L1M").
    public static let version: UInt8 = 0x4D
    /// Key Access Service information, as per NanoTDF Spec v13.
    public let payloadKeyAccess: PayloadKeyAccess
    /// Configuration for the policy binding (e.g., curve used, binding type).
    public let policyBindingConfig: PolicyBindingConfig
    /// Configuration for the payload and its optional signature (e.g., cipher used, signature presence/curve).
    public var payloadSignatureConfig: SignatureAndPayloadConfig // Mutable if signature is added later
    /// The policy associated with the TDF (can be remote or embedded).
    public let policy: Policy
    /// The ephemeral public key generated by the TDF creator, used for key agreement.
    public let ephemeralPublicKey: Data

    /// Initializes a Header object.
    public init(payloadKeyAccess: PayloadKeyAccess, policyBindingConfig: PolicyBindingConfig, payloadSignatureConfig: SignatureAndPayloadConfig, policy: Policy, ephemeralPublicKey: Data) {
        self.payloadKeyAccess = payloadKeyAccess
        self.policyBindingConfig = policyBindingConfig
        self.payloadSignatureConfig = payloadSignatureConfig
        self.policy = policy
        self.ephemeralPublicKey = ephemeralPublicKey
    }

    /// Serializes the Header into its binary `Data` representation according to the NanoTDF specification.
    /// - Returns: A `Data` object representing the serialized header.
    public func toData() -> Data {
        var data = Data()
        data.append(Header.magicNumber)
        data.append(Header.version)
        data.append(payloadKeyAccess.toData())
        data.append(policyBindingConfig.toData())
        data.append(payloadSignatureConfig.toData())
        data.append(policy.toData())
        data.append(ephemeralPublicKey)
        return data
    }
}

/// Represents the encrypted payload section of a NanoTDF object.
public struct Payload: Sendable {
    /// The length of the payload components (IV + Ciphertext + Auth Tag) represented as UInt24 (stored as UInt32).
    public let length: UInt32
    /// The Initialization Vector (Nonce) used for encryption (typically 3 bytes in NanoTDF spec).
    public let iv: Data
    /// The encrypted content.
    public let ciphertext: Data
    /// The authentication tag generated during encryption (e.g., 16 bytes for AES-GCM-128).
    public let mac: Data

    /// Initializes a Payload object.
    public init(length: UInt32, iv: Data, ciphertext: Data, mac: Data) {
        self.length = length
        self.iv = iv
        self.ciphertext = ciphertext
        self.mac = mac
    }

    /// Serializes the Payload into its binary `Data` representation according to the NanoTDF specification.
    /// Note: Length is serialized as 3 bytes (UInt24).
    /// - Returns: A `Data` object representing the serialized payload.
    public func toData() -> Data {
        var data = Data()
        // Serialize length as UInt24 (3 bytes)
        data.append(UInt8((length >> 16) & 0xFF))
        data.append(UInt8((length >> 8) & 0xFF))
        data.append(UInt8(length & 0xFF))
        // Append IV, Ciphertext, and MAC tag
        data.append(iv)
        data.append(ciphertext)
        data.append(mac)
        return data
    }
}

/// Represents the optional signature section of a NanoTDF object.
public struct Signature: Sendable {
    /// The public key corresponding to the private key used for signing (compressed format).
    let publicKey: Data
    /// The raw signature data (e.g., concatenated R and S values for ECDSA).
    let signature: Data

    /// Serializes the Signature into its binary `Data` representation (PublicKey || Signature).
    /// - Returns: A `Data` object representing the serialized signature.
    func toData() -> Data {
        var data = Data()
        data.append(publicKey)
        data.append(signature)
        return data
    }
}

/// Configuration flags for the policy binding within the NanoTDF header.
public struct PolicyBindingConfig: Sendable {
    /// Specifies the type of binding: `true` for ECDSA signature, `false` for GMAC tag.
    var ecdsaBinding: Bool
    /// The elliptic curve used for the ephemeral key agreement (and potentially ECDSA binding if `ecdsaBinding` is true).
    var curve: Curve

    /// Serializes the PolicyBindingConfig into its 1-byte binary representation.
    /// - Bit 7: USE_ECDSA_BINDING
    /// - Bits 0-2: Ephemeral ECC Params Enum (`Curve` raw value)
    /// - Returns: A `Data` object containing the single configuration byte.
    func toData() -> Data {
        var byte: UInt8 = 0
        if ecdsaBinding {
            byte |= 0b1000_0000 // Set bit 7 if ECDSA binding is used
        }
        byte |= (curve.rawValue & 0b0000_0111) // Mask and set bits 0-2 for the curve
        return Data([byte])
    }
}

/// Configuration flags for the payload encryption and optional signature within the NanoTDF header.
public struct SignatureAndPayloadConfig: Sendable {
    /// Indicates whether the NanoTDF includes a signature (`true`) or not (`false`).
    var signed: Bool
    /// The elliptic curve used for the signature, if present.
    var signatureCurve: Curve?
    /// The symmetric cipher used for payload encryption.
    let payloadCipher: Cipher?

    /// Serializes the SignatureAndPayloadConfig into its 1-byte binary representation.
    /// - Bit 7: HAS_SIGNATURE
    /// - Bits 4-6: Signature ECC Mode (`Curve` raw value)
    /// - Bits 0-3: Symmetric Cipher Enum (`Cipher` raw value)
    /// - Returns: A `Data` object containing the single configuration byte.
    func toData() -> Data {
        var byte: UInt8 = 0
        if signed {
            byte |= 0b1000_0000 // Set bit 7 if signature is present
        }
        if let signatureECCMode = signatureCurve {
            // Shift the curve raw value (masked) to bits 4-6
            byte |= (signatureECCMode.rawValue & 0b0000_0111) << 4
        }
        if let symmetricCipherEnum = payloadCipher {
            // Mask and set bits 0-3 for the cipher
            byte |= (symmetricCipherEnum.rawValue & 0b0000_1111)
        }
        return Data([byte])
    }
}

/// Enumeration of network protocols supported for Resource Locators.
public enum ProtocolEnum: UInt8, Sendable {
    case http = 0x00
    case https = 0x01
    // NOTE: WS/WSS are included here but marked as out-of-spec relative to the base NanoTDF standard.
    // Their inclusion might be for specific application needs.
    // BEGIN out-of-spec
    case ws = 0x02
    case wss = 0x03
    // END out-of-spec
    case sharedResourceDirectory = 0xFF // Likely for non-network resources
}

/// Represents a locator for a resource, typically a URL for KAS or policy information.
public struct ResourceLocator: Sendable {
    /// The protocol used to access the resource.
    public let protocolEnum: ProtocolEnum
    /// The body of the locator (e.g., hostname and path for HTTP/HTTPS).
    public let body: String

    /// Initializes a ResourceLocator, validating the body length.
    /// The body length must be between 1 and 255 bytes (UTF-8 encoded).
    /// - Parameters:
    ///   - protocolEnum: The `ProtocolEnum` value.
    ///   - body: The string representation of the locator body.
    /// - Returns: An initialized `ResourceLocator` or `nil` if the body length is invalid.
    public init?(protocolEnum: ProtocolEnum, body: String) {
        // Validate body length (1 to 255 bytes as per spec for body content)
        // ResourceLocator body itself can be 0 length if Identifier is "None" (0x0) as per KAS Endpoint Locator spec.
        // However, the general ResourceLocator spec (3.4.1) says Body is 1-255.
        // The current implementation of ResourceLocator.toData() uses body.data(using: .utf8)
        // and then UInt8(bodyData.count). If body is empty, bodyData.count is 0.
        // This is consistent with KAS Endpoint Locator Identifier "None" (0x0) if body is empty.
        // For now, stick to current validation which requires non-empty body.
        // If an empty body is needed for "None" identifier, this init needs adjustment.
        guard !body.isEmpty, body.utf8.count <= 255 else {
            // Allow empty body if protocol is http/https and it's for KAS "None" identifier.
            // The spec for KAS Endpoint Locator says: "The `Identifier` part of this `ResourceLocator` will likely be "None" (`0x0`)."
            // "None" (0x0) for ResourceLocator body means length 0.
            // Let's adjust to allow empty body, as ResourceLocator.toData() handles it.
            if body.isEmpty && body.utf8.count == 0 {
                // Allow empty body
            } else if body.utf8.count > 255 {
                 return nil
            }
            // If body is not empty, it must be <= 255.
            // If body is empty, it's allowed.
        }
        self.protocolEnum = protocolEnum
        self.body = body
    }

    /// Serializes the ResourceLocator into its binary `Data` representation.
    /// Format: Protocol (1 byte) || Body Length (1 byte) || Body (variable length).
    /// - Returns: A `Data` object representing the serialized resource locator.
    public func toData() -> Data {
        var data = Data()
        data.append(protocolEnum.rawValue)
        // Ensure body can be encoded to UTF-8
        if let bodyData = body.data(using: .utf8) {
            // Append length (UInt8) and the body data itself
            data.append(UInt8(bodyData.count))
            data.append(bodyData)
        } else {
            // Handle the unlikely case where UTF-8 encoding fails.
            // Appending length 0 might be one way, or logging an error.
            // Currently, it results in a locator with just the protocol byte.
            data.append(UInt8(0)) // Should not happen with valid Swift strings
        }
        return data
    }
}

/// Represents the policy associated with a NanoTDF object.
public struct Policy: Sendable {
    /// Defines the type of policy storage/retrieval.
    public enum PolicyType: UInt8, Sendable {
        /// Policy information is located remotely, specified by `remote` locator.
        case remote = 0x00
        /// Policy is embedded directly within the TDF header in plaintext.
        case embeddedPlaintext = 0x01
        /// Policy is embedded and encrypted (details depend on specific implementation/standard extension).
        case embeddedEncrypted = 0x02
        /// Policy is embedded, encrypted, and requires a specific key access mechanism (details depend on extension).
        case embeddedEncryptedWithPolicyKeyAccess = 0x03
    }

    /// The type of the policy.
    public let type: PolicyType
    /// The body of the policy if it's embedded (`embeddedPlaintext`, `embeddedEncrypted`, etc.).
    public var body: EmbeddedPolicyBody? // Mutable to allow encrypted policy updates
    /// The resource locator if the policy is remote (`remote`).
    public let remote: ResourceLocator?
    /// The policy binding (GMAC tag or ECDSA signature) calculated over the policy body/locator.
    public var binding: Data? // Mutable because it's calculated during TDF creation

    /// Initializes a Policy object.
    public init(type: PolicyType, body: EmbeddedPolicyBody?, remote: ResourceLocator?, binding: Data? = nil) {
        self.type = type
        self.body = body
        self.remote = remote
        self.binding = binding
        // Add validation? e.g., ensure 'remote' is non-nil if type is .remote
    }

    /// Serializes the Policy into its binary `Data` representation.
    /// Format varies based on `PolicyType`:
    /// - Remote: Type (1 byte) || Remote Locator Data || Binding Data
    /// - Embedded: Type (1 byte) || Embedded Body Data || Binding Data
    /// - Returns: A `Data` object representing the serialized policy.
    public func toData() -> Data {
        var data = Data()
        data.append(type.rawValue)

        // Append policy data based on type
        switch type {
        case .remote:
            if let remote {
                data.append(remote.toData())
            }
        // Else: Potentially invalid state if type is remote but remote is nil.
        case .embeddedPlaintext:
            if let body {
                data.append(body.toData())
            }
        // Else: Potentially invalid state if type is embedded but body is nil.
        case .embeddedEncrypted:
            if let body {
                data.append(body.toData())
            }
        // Else: Potentially invalid state if type is embedded but body is nil.
        case .embeddedEncryptedWithPolicyKeyAccess:
            if let body {
                data.append(body.toData())
            }
            // Else: Potentially invalid state if type is embedded but body is nil.
        }

        // Append the policy binding if it exists
        if let binding {
            data.append(binding)
        }
        return data
    }
}

/// Represents the body of an embedded policy.
public struct EmbeddedPolicyBody: Sendable {
    /// The actual policy content (e.g., plaintext claims, encrypted policy data).
    public let body: Data
    /// Optional key access information if the policy itself requires key access (e.g., for decryption).
    public let keyAccess: PolicyKeyAccess?

    /// Initializes an EmbeddedPolicyBody.
    public init(body: Data, keyAccess: PolicyKeyAccess? = nil) {
        self.body = body
        self.keyAccess = keyAccess
    }

    /// Serializes the EmbeddedPolicyBody into its binary `Data` representation.
    /// Format: Body Length (2 bytes) || Body Data || Optional Key Access Data.
    /// - Returns: A `Data` object representing the serialized embedded policy body.
    public func toData() -> Data {
        var data = Data()
        // Serialize body length as UInt16 (2 bytes, big-endian)
        let bodyLength = UInt16(body.count)
        data.append(UInt8((bodyLength >> 8) & 0xFF)) // High byte
        data.append(UInt8(bodyLength & 0xFF)) // Low byte
        // Append the policy body data
        data.append(body)
        // Append key access information if present
        if let keyAccess {
            data.append(keyAccess.toData())
        }
        return data
    }
}

/// Represents key access information associated with an embedded policy (if the policy itself is protected).
public struct PolicyKeyAccess: Sendable {
    /// Locator for the service/key needed to access the policy content.
    public let resourceLocator: ResourceLocator
    /// Ephemeral public key potentially needed for key agreement to decrypt the policy.
    public let ephemeralPublicKey: Data

    /// Serializes the PolicyKeyAccess into its binary `Data` representation.
    /// Format: Resource Locator Data || Ephemeral Public Key Data.
    /// - Returns: A `Data` object representing the serialized policy key access info.
    func toData() -> Data {
        var data = Data()
        data.append(resourceLocator.toData())
        data.append(ephemeralPublicKey)
        return data
    }

    /// Gets the public key for key agreement
    /// - Returns: The public key data
    func getPublicKey() -> Data {
        ephemeralPublicKey
    }
}

/// Enumeration of supported Elliptic Curves.
public enum Curve: UInt8, Sendable {
    /// NIST P-256 curve (secp256r1).
    case secp256r1 = 0x00
    /// NIST P-384 curve (secp384r1).
    case secp384r1 = 0x01
    /// NIST P-521 curve (secp521r1).
    case secp521r1 = 0x02
    // BEGIN in-spec unsupported
    /// SECG secp256k1 curve (commonly used in Bitcoin). Marked as unsupported in this implementation context.
    case xsecp256k1 = 0x03
    // END in-spec unsupported

    // publicKeyLength is defined as an extension in KeyStore.swift
}

/// Enumeration of supported Symmetric Ciphers for payload encryption.
public enum Cipher: UInt8, Sendable {
    /// AES-256-GCM with a 64-bit authentication tag.
    case aes256GCM64 = 0x00
    /// AES-256-GCM with a 96-bit authentication tag.
    case aes256GCM96 = 0x01
    /// AES-256-GCM with a 104-bit authentication tag.
    case aes256GCM104 = 0x02
    /// AES-256-GCM with a 112-bit authentication tag.
    case aes256GCM112 = 0x03
    /// AES-256-GCM with a 120-bit authentication tag.
    case aes256GCM120 = 0x04
    /// AES-256-GCM with a 128-bit authentication tag (default for Apple's CryptoKit).
    case aes256GCM128 = 0x05
}

/// Errors related to signature generation or verification.
public enum SignatureError: Error {
    /// General failure during the signing process.
    case invalidSigning
    /// An invalid key was provided or used.
    case invalidKey
    /// The message data to be signed/verified is invalid.
    case invalidMessage
    /// The signature data has an unexpected or invalid length.
    case invalidSignatureLength
    /// The public key data has an unexpected or invalid length.
    case invalidPublicKeyLength
    /// An unsupported or invalid curve was specified or used.
    case invalidCurve
}

/// Custom error type for policy-related issues.
public enum PolicyError: Error {
    case missingRemoteLocator
    case missingEmbeddedBody
    case missingPolicyKeyAccess
    case invalidPolicyEncryption
    // Add other policy-related error cases as needed
}

/// Initializes a basic, small NanoTDF object, primarily useful for testing or simple examples.
/// Uses placeholder values for ephemeral keys and payload.
/// - Parameter kasResourceLocator: The `ResourceLocator` for the KAS.
/// - Returns: A minimally initialized `NanoTDF` object.
public func initializeSmallNanoTDF(kasResourceLocator: ResourceLocator) -> NanoTDF {
    let curve: Curve = .secp256r1 // Default curve for this example
    // Create a placeholder header
    // THIS INITIALIZATION WILL BE BROKEN BY Header.init SIGNATURE CHANGE
    // AND THE `kas` PARAMETER NEEDS TO BE REPLACED WITH A `PayloadKeyAccess` INSTANCE.
    let header = Header(
        kas: kasResourceLocator, // OLD FIELD: This will cause a compile error. Replace with `payloadKeyAccess`.
        policyBindingConfig: PolicyBindingConfig(ecdsaBinding: false, curve: curve), // GMAC binding
        payloadSignatureConfig: SignatureAndPayloadConfig(signed: false, signatureCurve: curve, payloadCipher: .aes256GCM128), // Not signed, AES-256-GCM-128
        policy: Policy(type: .remote, body: nil, remote: kasResourceLocator, binding: nil), // Remote policy pointing to KAS URL, no binding yet
        ephemeralPublicKey: Data([0x04, 0x05, 0x06]) // Placeholder ephemeral public key
    )

    // Create a placeholder payload
    let payload = Payload(
        length: 7, // Minimal length (3 IV + 1 Ciphertext + 3 Placeholder MAC)
        iv: Data([0x07, 0x08, 0x09]), // Placeholder IV
        ciphertext: Data([0x00]), // Placeholder ciphertext
        mac: Data([0x13, 0x14, 0x15]) // Placeholder MAC tag (incorrect size for AES-GCM-128)
    )

    // Return the NanoTDF object
    return NanoTDF(header: header,
                   payload: payload,
                   signature: nil) // No signature
}

/// Represents the type of a public key, storing its compressed data representation.
/// This avoids holding onto specific CryptoKit key objects directly, aiding `Sendable` conformance.
public enum PublicKeyType: Sendable {
    /// P-256 public key data (compressed).
    case p256(Data)
    /// P-384 public key data (compressed).
    case p384(Data)
    /// P-521 public key data (compressed).
    case p521(Data)
}

/// Metadata associated with a Key Access Service (KAS), including its location and public key.
public struct KasMetadata: Sendable {
    /// Locator for the KAS endpoint.
    public let resourceLocator: ResourceLocator
    /// The type and compressed data of the KAS public key.
    private let publicKeyType: PublicKeyType
    /// The elliptic curve associated with the KAS public key.
    public let curve: Curve

    /// Initializes KAS Metadata.
    /// Takes a generic `Any` public key and attempts to cast it to the expected CryptoKit type based on the curve.
    /// Stores the compressed representation of the key internally.
    /// - Parameters:
    ///   - resourceLocator: The `ResourceLocator` for the KAS.
    ///   - publicKey: The KAS public key object (e.g., `P256.KeyAgreement.PublicKey`). Must match the `curve`.
    ///   - curve: The `Curve` enum value corresponding to the `publicKey` type.
    /// - Throws: `CryptoHelperError.unsupportedCurve` if the provided `publicKey` type doesn't match the `curve` or if the curve is `xsecp256k1`.
    public init(resourceLocator: ResourceLocator, publicKey: Any, curve: Curve) throws {
        self.resourceLocator = resourceLocator
        self.curve = curve

        // Store the compressed key representation based on the curve
        switch curve {
        case .secp256r1:
            guard let key = publicKey as? P256.KeyAgreement.PublicKey else {
                throw CryptoHelperError.unsupportedCurve // Type mismatch
            }
            publicKeyType = .p256(key.compressedRepresentation)
        case .secp384r1:
            guard let key = publicKey as? P384.KeyAgreement.PublicKey else {
                throw CryptoHelperError.unsupportedCurve // Type mismatch
            }
            publicKeyType = .p384(key.compressedRepresentation)
        case .secp521r1:
            guard let key = publicKey as? P521.KeyAgreement.PublicKey else {
                throw CryptoHelperError.unsupportedCurve // Type mismatch
            }
            publicKeyType = .p521(key.compressedRepresentation)
        case .xsecp256k1:
            // Explicitly disallow xsecp256k1 as it's marked unsupported
            throw CryptoHelperError.unsupportedCurve
        }
    }

    /// Retrieves the KAS public key as compressed `Data`.
    /// - Returns: The compressed public key data.
    /// - Throws: Currently does not throw, but signature could be added if internal state could be invalid.
    public func getPublicKey() throws -> Data {
        // Return the stored compressed representation directly.
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
