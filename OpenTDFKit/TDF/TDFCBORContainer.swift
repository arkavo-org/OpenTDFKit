import CryptoKit
import Foundation

// MARK: - TDF-CBOR Container

/// Container for TDF-CBOR format that conforms to TrustedDataContainer.
public struct TDFCBORContainer: TrustedDataContainer, Sendable {
    /// The TDF-CBOR envelope
    public let envelope: TDFCBOREnvelope

    public var formatKind: TrustedDataFormatKind { .cbor }

    public init(envelope: TDFCBOREnvelope) {
        self.envelope = envelope
    }

    /// Serialize the container to CBOR data
    public func serializedData() throws -> Data {
        try envelope.toCBORData()
    }

    /// Get the manifest from the envelope
    public var manifest: TDFCBORManifest {
        envelope.manifest
    }

    /// Get the encryption information
    public var encryptionInformation: TDFEncryptionInformation {
        envelope.manifest.encryptionInformation
    }

    /// Get the raw payload data
    public var payloadData: Data {
        envelope.payload.value
    }

    /// Get the MIME type of the payload
    public var mimeType: String? {
        envelope.payload.mimeType
    }
}

// MARK: - TDF-CBOR Builder

/// Builder for creating TDF-CBOR containers with encryption.
public struct TDFCBORBuilder: Sendable {
    private var kasURL: URL?
    private var kasPublicKeyPEM: String?
    private var kasKid: String?
    private var mimeType: String?
    private var includeCreated: Bool = true
    private var policy: TDFPolicy?

    public init() {}

    /// Set the KAS URL
    public func kasURL(_ url: URL) -> TDFCBORBuilder {
        var copy = self
        copy.kasURL = url
        return copy
    }

    /// Set the KAS public key PEM
    public func kasPublicKey(_ pem: String) -> TDFCBORBuilder {
        var copy = self
        copy.kasPublicKeyPEM = pem
        return copy
    }

    /// Set the KAS key ID
    public func kasKid(_ kid: String) -> TDFCBORBuilder {
        var copy = self
        copy.kasKid = kid
        return copy
    }

    /// Set the MIME type of the plaintext
    public func mimeType(_ type: String) -> TDFCBORBuilder {
        var copy = self
        copy.mimeType = type
        return copy
    }

    /// Whether to include the created timestamp
    public func includeCreated(_ include: Bool) -> TDFCBORBuilder {
        var copy = self
        copy.includeCreated = include
        return copy
    }

    /// Set the policy
    public func policy(_ policy: TDFPolicy) -> TDFCBORBuilder {
        var copy = self
        copy.policy = policy
        return copy
    }

    /// Build a TDF-CBOR container by encrypting the provided plaintext
    public func encrypt(plaintext: Data) throws -> TDFCBOREncryptionResult {
        guard let kasURL else {
            throw TDFCBORError.encryptionFailed("KAS URL is required")
        }
        guard let kasPublicKeyPEM else {
            throw TDFCBORError.encryptionFailed("KAS public key is required")
        }
        guard let policy else {
            throw TDFCBORError.encryptionFailed("Policy is required")
        }

        // Generate symmetric key
        let symmetricKey = SymmetricKey(size: .bits256)

        // Encrypt the plaintext
        let (iv, ciphertext, tag) = try TDFCrypto.encryptPayload(
            plaintext: plaintext,
            symmetricKey: symmetricKey,
        )

        // Combine IV + ciphertext + tag for the payload (as raw bytes)
        let payloadData = iv + ciphertext + tag

        // Wrap the symmetric key using EC (ECDH + HKDF + AES-GCM)
        let ecWrapped = try TDFCrypto.wrapSymmetricKeyWithEC(
            publicKeyPEM: kasPublicKeyPEM,
            symmetricKey: symmetricKey,
        )

        // Create policy binding
        let policyBinding = TDFCrypto.policyBinding(
            policy: policy.json,
            symmetricKey: symmetricKey,
        )

        // Calculate segment signature (GMAC)
        let segmentSignature = try TDFCrypto.segmentSignatureGMAC(
            segmentCiphertext: payloadData,
            symmetricKey: symmetricKey,
        )

        // Calculate root signature
        let rootSignature = TDFCrypto.segmentSignature(
            segmentCiphertext: segmentSignature,
            symmetricKey: symmetricKey,
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
            ephemeralPublicKey: ecWrapped.ephemeralPublicKey,
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
                    encryptedSegmentSize: Int64(payloadData.count),
                ),
            ],
        )

        // Create method descriptor
        let method = TDFMethodDescriptor(
            algorithm: "AES-256-GCM",
            iv: iv.base64EncodedString(),
            isStreamable: true,
        )

        // Create encryption information
        let encryptionInfo = TDFEncryptionInformation(
            type: .split,
            keyAccess: [keyAccessObject],
            method: method,
            integrityInformation: integrityInfo,
            policy: policy.base64String,
        )

        // Create manifest
        let manifest = TDFCBORManifest(
            encryptionInformation: encryptionInfo,
            assertions: nil,
        )

        // Create binary payload (not base64)
        let payload = TDFBinaryPayload(
            type: "inline",
            protocol: "binary",
            mimeType: mimeType,
            isEncrypted: true,
            value: payloadData,
        )

        // Create timestamp
        let created: UInt64? = includeCreated ? UInt64(Date().timeIntervalSince1970) : nil

        // Create envelope
        let envelope = TDFCBOREnvelope(
            tdf: "cbor",
            version: [1, 0, 0],
            created: created,
            manifest: manifest,
            payload: payload,
        )

        let container = TDFCBORContainer(envelope: envelope)

        return TDFCBOREncryptionResult(
            container: container,
            symmetricKey: symmetricKey,
            iv: iv,
            tag: tag,
        )
    }
}

// MARK: - TDF-CBOR Encryption Result

/// Result of TDF-CBOR encryption containing the container and key material
public struct TDFCBOREncryptionResult: Sendable {
    /// The encrypted TDF-CBOR container
    public let container: TDFCBORContainer

    /// The symmetric key used for encryption (save for later decryption)
    public let symmetricKey: SymmetricKey

    /// The IV used for encryption
    public let iv: Data

    /// The authentication tag
    public let tag: Data

    public init(container: TDFCBORContainer, symmetricKey: SymmetricKey, iv: Data, tag: Data) {
        self.container = container
        self.symmetricKey = symmetricKey
        self.iv = iv
        self.tag = tag
    }
}

// MARK: - TDF-CBOR Loader

/// Loader for parsing TDF-CBOR from data or files
public struct TDFCBORLoader: Sendable {
    public init() {}

    /// Load a TDF-CBOR container from data
    public func load(from data: Data) throws -> TDFCBORContainer {
        let envelope = try TDFCBOREnvelope.fromCBORData(data)
        return TDFCBORContainer(envelope: envelope)
    }

    /// Load a TDF-CBOR container from a URL
    public func load(from url: URL) throws -> TDFCBORContainer {
        let data = try Data(contentsOf: url)
        return try load(from: data)
    }
}

// MARK: - TDF-CBOR Decryptor

/// Decryptor for TDF-CBOR containers
public struct TDFCBORDecryptor: Sendable {
    public init() {}

    /// Decrypt a TDF-CBOR container with a symmetric key
    public func decrypt(container: TDFCBORContainer, symmetricKey: SymmetricKey) throws -> Data {
        try TDFCrypto.decryptCombinedPayload(container.payloadData, symmetricKey: symmetricKey)
    }

    /// Decrypt a TDF-CBOR container with a private key (unwraps the symmetric key first)
    public func decrypt(container: TDFCBORContainer, privateKeyPEM: String) throws -> Data {
        let keyAccess = container.encryptionInformation.keyAccess
        guard !keyAccess.isEmpty else {
            throw TDFCBORError.decryptionFailed("No key access objects found")
        }

        let symmetricKey = try TDFCrypto.unwrapSymmetricKeyWithRSA(
            privateKeyPEM: privateKeyPEM,
            wrappedKey: keyAccess[0].wrappedKey,
        )

        return try decrypt(container: container, symmetricKey: symmetricKey)
    }
}
