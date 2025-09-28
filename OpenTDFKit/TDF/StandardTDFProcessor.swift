import CryptoKit
import Foundation

public struct StandardTDFKasInfo: Sendable {
    public let url: URL
    public let publicKeyPEM: String
    public let kid: String?
    public let schemaVersion: String?

    public init(url: URL, publicKeyPEM: String, kid: String? = nil, schemaVersion: String? = nil) {
        self.url = url
        self.publicKeyPEM = publicKeyPEM
        self.kid = kid
        self.schemaVersion = schemaVersion
    }
}

public struct StandardTDFPolicy: Sendable {
    public let json: Data

    public init(json: Data) {
        self.json = json
    }

    public var base64String: String {
        json.base64EncodedString()
    }
}

public struct StandardTDFEncryptionConfiguration: Sendable {
    public let kas: StandardTDFKasInfo
    public let policy: StandardTDFPolicy
    public let mimeType: String?
    public let tdfSpecVersion: String

    public init(kas: StandardTDFKasInfo, policy: StandardTDFPolicy, mimeType: String? = nil, tdfSpecVersion: String = "4.3.0") {
        self.kas = kas
        self.policy = policy
        self.mimeType = mimeType
        self.tdfSpecVersion = tdfSpecVersion
    }
}

public struct StandardTDFEncryptor {
    public init() {}

    public func encrypt(plaintext: Data, configuration: StandardTDFEncryptionConfiguration) throws -> StandardTDFEncryptionResult {
        let symmetricKey = try StandardTDFCrypto.generateSymmetricKey()
        let (iv, ciphertext, tag) = try StandardTDFCrypto.encryptPayload(plaintext: plaintext, symmetricKey: symmetricKey)

        let payloadData = iv + ciphertext + tag

        let policyBinding = StandardTDFCrypto.policyBinding(policy: configuration.policy.json, symmetricKey: symmetricKey)
        let wrappedKey = try StandardTDFCrypto.wrapSymmetricKeyWithRSA(publicKeyPEM: configuration.kas.publicKeyPEM, symmetricKey: symmetricKey)

        let segmentSignature = try StandardTDFCrypto.segmentSignatureGMAC(segmentCiphertext: payloadData, symmetricKey: symmetricKey)
        let segmentSignatureBase64 = segmentSignature.base64EncodedString()

        let rootSignature = try StandardTDFCrypto.segmentSignatureGMAC(segmentCiphertext: segmentSignature, symmetricKey: symmetricKey).base64EncodedString()

        let method = TDFMethodDescriptor(
            algorithm: "AES-256-GCM",
            iv: iv.base64EncodedString(),
            isStreamable: false,
        )

        let segment = TDFSegment(
            hash: segmentSignatureBase64,
            segmentSize: Int64(plaintext.count),
            encryptedSegmentSize: Int64(payloadData.count),
        )

        let integrity = TDFIntegrityInformation(
            rootSignature: TDFRootSignature(alg: "GMAC", sig: rootSignature),
            segmentHashAlg: "GMAC",
            segmentSizeDefault: Int64(plaintext.count),
            encryptedSegmentSizeDefault: Int64(payloadData.count),
            segments: [segment],
        )

        let kasObject = TDFKeyAccessObject(
            type: .wrapped,
            url: configuration.kas.url.absoluteString,
            protocolValue: .kas,
            wrappedKey: wrappedKey,
            policyBinding: policyBinding,
            encryptedMetadata: nil,
            kid: configuration.kas.kid,
            sid: nil,
            schemaVersion: configuration.kas.schemaVersion ?? "1.0",
            ephemeralPublicKey: nil,
        )

        let encryptionInformation = TDFEncryptionInformation(
            type: .split,
            keyAccess: [kasObject],
            method: method,
            integrityInformation: integrity,
            policy: configuration.policy.base64String,
        )

        let payloadDescriptor = TDFPayloadDescriptor(
            type: .reference,
            url: "0.payload",
            protocolValue: .zip,
            isEncrypted: true,
            mimeType: configuration.mimeType,
        )

        let manifest = TDFManifest(
            schemaVersion: configuration.tdfSpecVersion,
            payload: payloadDescriptor,
            encryptionInformation: encryptionInformation,
            assertions: nil,
        )

        let container = StandardTDFContainer(
            manifest: manifest,
            payload: payloadData,
        )

        return StandardTDFEncryptionResult(container: container, symmetricKey: symmetricKey, iv: iv, tag: tag)
    }
}

public struct StandardTDFEncryptionResult: Sendable {
    public let container: StandardTDFContainer
    public let symmetricKey: SymmetricKey
    public let iv: Data
    public let tag: Data

    public init(container: StandardTDFContainer, symmetricKey: SymmetricKey, iv: Data, tag: Data) {
        self.container = container
        self.symmetricKey = symmetricKey
        self.iv = iv
        self.tag = tag
    }
}

public struct StandardTDFDecryptor {
    public init() {}

    public func decrypt(container: StandardTDFContainer, privateKeyPEM: String) throws -> Data {
        let keyAccess = container.manifest.encryptionInformation.keyAccess
        guard !keyAccess.isEmpty else {
            throw StandardTDFDecryptError.missingKeyAccess
        }

        if keyAccess.count == 1 {
            let symmetricKey = try StandardTDFCrypto.unwrapSymmetricKeyWithRSA(
                privateKeyPEM: privateKeyPEM,
                wrappedKey: keyAccess[0].wrappedKey,
            )
            return try decrypt(container: container, symmetricKey: symmetricKey)
        }

        var combinedKeyData: Data?
        for kasObject in keyAccess.sorted(by: { ($0.kid ?? "") < ($1.kid ?? "") }) {
            let symmetricKeyPart = try StandardTDFCrypto.unwrapSymmetricKeyWithRSA(
                privateKeyPEM: privateKeyPEM,
                wrappedKey: kasObject.wrappedKey,
            )
            let keyData = StandardTDFCrypto.data(from: symmetricKeyPart)

            if let existing = combinedKeyData {
                guard existing.count == keyData.count else {
                    throw StandardTDFDecryptError.keyShareSizeMismatch
                }
                combinedKeyData = xorKeyData(existing, keyData)
            } else {
                combinedKeyData = keyData
            }
        }

        guard let finalKeyData = combinedKeyData else {
            throw StandardTDFDecryptError.missingKeyAccess
        }

        let finalSymmetricKey = SymmetricKey(data: finalKeyData)
        return try decrypt(container: container, symmetricKey: finalSymmetricKey)
    }

    private func xorKeyData(_ lhs: Data, _ rhs: Data) -> Data {
        Data(zip(lhs, rhs).map { $0 ^ $1 })
    }

    public func decrypt(container: StandardTDFContainer, symmetricKey: SymmetricKey) throws -> Data {
        let payloadData = container.payload
        let ivSize = 12
        let tagSize = 16
        let minSize = ivSize + tagSize
        guard payloadData.count >= minSize else {
            throw StandardTDFDecryptError.malformedPayload
        }

        let iv = payloadData.prefix(ivSize)
        let ciphertext = payloadData.dropFirst(ivSize).dropLast(tagSize)
        let tag = payloadData.suffix(tagSize)

        return try StandardTDFCrypto.decryptPayload(ciphertext: Data(ciphertext), iv: Data(iv), tag: Data(tag), symmetricKey: symmetricKey)
    }
}

public enum StandardTDFDecryptError: Error, CustomStringConvertible, Equatable {
    case missingKeyAccess
    case malformedPayload
    case keyShareSizeMismatch

    public var description: String {
        switch self {
        case .missingKeyAccess:
            "No key access objects found in manifest"
        case .malformedPayload:
            "Malformed encrypted payload: insufficient data for IV and authentication tag"
        case .keyShareSizeMismatch:
            "Key share size mismatch: all key shares must have the same length for XOR reconstruction"
        }
    }
}
