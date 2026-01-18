import CryptoKit
import Foundation

// MARK: - TDF-JSON Container

/// Container for TDF-JSON format that conforms to TrustedDataContainer.
public struct TDFJSONContainer: TrustedDataContainer, Sendable {
    /// The TDF-JSON envelope
    public let envelope: TDFJSONEnvelope

    /// Raw payload data (encrypted ciphertext)
    public let payloadData: Data

    public var formatKind: TrustedDataFormatKind { .json }

    public init(envelope: TDFJSONEnvelope, payloadData: Data) {
        self.envelope = envelope
        self.payloadData = payloadData
    }

    /// Serialize the container to JSON data
    public func serializedData() throws -> Data {
        try envelope.toJSONData()
    }

    /// Get the manifest from the envelope
    public var manifest: TDFJSONManifest {
        envelope.manifest
    }

    /// Get the encryption information
    public var encryptionInformation: TDFEncryptionInformation {
        envelope.manifest.encryptionInformation
    }

    /// Get the MIME type of the payload
    public var mimeType: String? {
        envelope.payload.mimeType
    }
}

// MARK: - TDF-JSON Builder

/// Builder for creating TDF-JSON containers with encryption.
public struct TDFJSONBuilder: Sendable {
    private var kasURL: URL?
    private var kasPublicKeyPEM: String?
    private var kasKid: String?
    private var mimeType: String?
    private var includeCreated: Bool = true
    private var policy: TDFPolicy?

    public init() {}

    /// Set the KAS URL
    public func kasURL(_ url: URL) -> TDFJSONBuilder {
        var copy = self
        copy.kasURL = url
        return copy
    }

    /// Set the KAS public key PEM
    public func kasPublicKey(_ pem: String) -> TDFJSONBuilder {
        var copy = self
        copy.kasPublicKeyPEM = pem
        return copy
    }

    /// Set the KAS key ID
    public func kasKid(_ kid: String) -> TDFJSONBuilder {
        var copy = self
        copy.kasKid = kid
        return copy
    }

    /// Set the MIME type of the plaintext
    public func mimeType(_ type: String) -> TDFJSONBuilder {
        var copy = self
        copy.mimeType = type
        return copy
    }

    /// Whether to include the created timestamp
    public func includeCreated(_ include: Bool) -> TDFJSONBuilder {
        var copy = self
        copy.includeCreated = include
        return copy
    }

    /// Set the policy
    public func policy(_ policy: TDFPolicy) -> TDFJSONBuilder {
        var copy = self
        copy.policy = policy
        return copy
    }

    /// Build a TDF-JSON container by encrypting the provided plaintext
    public func encrypt(plaintext: Data) throws -> TDFJSONEncryptionResult {
        guard let kasURL = kasURL else {
            throw TDFJSONError.encryptionFailed("KAS URL is required")
        }
        guard let kasPublicKeyPEM = kasPublicKeyPEM else {
            throw TDFJSONError.encryptionFailed("KAS public key is required")
        }
        guard let policy = policy else {
            throw TDFJSONError.encryptionFailed("Policy is required")
        }

        // Generate symmetric key
        let symmetricKey = SymmetricKey(size: .bits256)

        // Encrypt the plaintext
        let (iv, ciphertext, tag) = try TDFCrypto.encryptPayload(
            plaintext: plaintext,
            symmetricKey: symmetricKey
        )

        // Combine IV + ciphertext + tag for the payload
        let payloadData = iv + ciphertext + tag

        // Wrap the symmetric key using EC (ECDH + HKDF + AES-GCM)
        let ecWrapped = try TDFCrypto.wrapSymmetricKeyWithEC(
            publicKeyPEM: kasPublicKeyPEM,
            symmetricKey: symmetricKey
        )

        // Create policy binding
        let policyBinding = TDFCrypto.policyBinding(
            policy: policy.json,
            symmetricKey: symmetricKey
        )

        // Calculate segment signature (GMAC)
        let segmentSignature = try TDFCrypto.segmentSignatureGMAC(
            segmentCiphertext: payloadData,
            symmetricKey: symmetricKey
        )

        // Calculate root signature
        let rootSignature = TDFCrypto.segmentSignature(
            segmentCiphertext: segmentSignature,
            symmetricKey: symmetricKey
        )

        // Create key access object with EC ephemeral public key
        let keyAccessObject = TDFKeyAccessObject(
            type: .wrapped,
            url: kasURL.absoluteString,
            protocolValue: .kas,
            wrappedKey: ecWrapped.wrappedKey,
            policyBinding: policyBinding,
            encryptedMetadata: nil,
            kid: kasKid,
            sid: nil,
            schemaVersion: "1.0",
            ephemeralPublicKey: ecWrapped.ephemeralPublicKey
        )

        // Create integrity information
        let integrityInfo = TDFIntegrityInformation(
            rootSignature: TDFRootSignature(alg: "HS256", sig: rootSignature.base64EncodedString()),
            segmentHashAlg: "GMAC",
            segmentSizeDefault: Int64(plaintext.count),
            encryptedSegmentSizeDefault: Int64(payloadData.count),
            segments: [
                TDFSegment(
                    hash: segmentSignature.base64EncodedString(),
                    segmentSize: Int64(plaintext.count),
                    encryptedSegmentSize: Int64(payloadData.count)
                ),
            ]
        )

        // Create method descriptor
        let method = TDFMethodDescriptor(
            algorithm: "AES-256-GCM",
            iv: iv.base64EncodedString(),
            isStreamable: true
        )

        // Create encryption information
        let encryptionInfo = TDFEncryptionInformation(
            type: .split,
            keyAccess: [keyAccessObject],
            method: method,
            integrityInformation: integrityInfo,
            policy: policy.base64String
        )

        // Create manifest
        let manifest = TDFJSONManifest(
            encryptionInformation: encryptionInfo,
            assertions: nil
        )

        // Create payload
        let payload = TDFInlinePayload(
            type: "inline",
            protocol: "base64",
            mimeType: mimeType,
            isEncrypted: true,
            length: UInt64(payloadData.count),
            value: payloadData.base64EncodedString()
        )

        // Create envelope
        let created = includeCreated ? ISO8601DateFormatter().string(from: Date()) : nil
        let envelope = TDFJSONEnvelope(
            tdf: "json",
            version: "1.0.0",
            created: created,
            manifest: manifest,
            payload: payload
        )

        let container = TDFJSONContainer(envelope: envelope, payloadData: payloadData)

        return TDFJSONEncryptionResult(
            container: container,
            symmetricKey: symmetricKey,
            iv: iv,
            tag: tag
        )
    }
}

// MARK: - TDF-JSON Encryption Result

/// Result of TDF-JSON encryption containing the container and key material
public struct TDFJSONEncryptionResult: Sendable {
    /// The encrypted TDF-JSON container
    public let container: TDFJSONContainer

    /// The symmetric key used for encryption (save for later decryption)
    public let symmetricKey: SymmetricKey

    /// The IV used for encryption
    public let iv: Data

    /// The authentication tag
    public let tag: Data

    public init(container: TDFJSONContainer, symmetricKey: SymmetricKey, iv: Data, tag: Data) {
        self.container = container
        self.symmetricKey = symmetricKey
        self.iv = iv
        self.tag = tag
    }
}

// MARK: - TDF-JSON Loader

/// Loader for parsing TDF-JSON from data or files
public struct TDFJSONLoader: Sendable {
    public init() {}

    /// Load a TDF-JSON container from data
    public func load(from data: Data) throws -> TDFJSONContainer {
        let envelope = try TDFJSONEnvelope.parse(from: data)
        let payloadData = try envelope.decodePayloadValue()
        return TDFJSONContainer(envelope: envelope, payloadData: payloadData)
    }

    /// Load a TDF-JSON container from a URL
    public func load(from url: URL) throws -> TDFJSONContainer {
        let data = try Data(contentsOf: url)
        return try load(from: data)
    }

    /// Load a TDF-JSON container from a JSON string
    public func load(from jsonString: String) throws -> TDFJSONContainer {
        guard let data = jsonString.data(using: .utf8) else {
            throw TDFJSONError.payloadDecodeError("Invalid UTF-8 string")
        }
        return try load(from: data)
    }
}

// MARK: - TDF-JSON Decryptor

/// Decryptor for TDF-JSON containers
public struct TDFJSONDecryptor: Sendable {
    public init() {}

    /// Decrypt a TDF-JSON container with a symmetric key
    public func decrypt(container: TDFJSONContainer, symmetricKey: SymmetricKey) throws -> Data {
        let payloadData = container.payloadData

        let ivSize = 12
        let tagSize = 16
        let minSize = ivSize + tagSize

        guard payloadData.count >= minSize else {
            throw TDFJSONError.decryptionFailed("Malformed payload: insufficient data")
        }

        let iv = payloadData.prefix(ivSize)
        let ciphertext = payloadData.dropFirst(ivSize).dropLast(tagSize)
        let tag = payloadData.suffix(tagSize)

        return try TDFCrypto.decryptPayload(
            ciphertext: Data(ciphertext),
            iv: Data(iv),
            tag: Data(tag),
            symmetricKey: symmetricKey
        )
    }

    /// Decrypt a TDF-JSON container with a private key (unwraps the symmetric key first)
    public func decrypt(container: TDFJSONContainer, privateKeyPEM: String) throws -> Data {
        let keyAccess = container.encryptionInformation.keyAccess
        guard !keyAccess.isEmpty else {
            throw TDFJSONError.decryptionFailed("No key access objects found")
        }

        let symmetricKey = try TDFCrypto.unwrapSymmetricKeyWithRSA(
            privateKeyPEM: privateKeyPEM,
            wrappedKey: keyAccess[0].wrappedKey
        )

        return try decrypt(container: container, symmetricKey: symmetricKey)
    }
}
