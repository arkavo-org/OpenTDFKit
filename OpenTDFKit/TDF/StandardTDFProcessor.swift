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

    public init(kas: StandardTDFKasInfo, policy: StandardTDFPolicy, mimeType: String? = nil, tdfSpecVersion: String = "1.0.0") {
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

        let segmentSignature = StandardTDFCrypto.segmentSignature(segmentCiphertext: payloadData, symmetricKey: symmetricKey)
        let segmentSignatureBase64 = segmentSignature.base64EncodedString()

        let rootSignature = StandardTDFCrypto.segmentSignature(segmentCiphertext: segmentSignature, symmetricKey: symmetricKey).base64EncodedString()

        let method = TDFMethodDescriptor(
            algorithm: "AES-256-GCM",
            iv: iv.base64EncodedString(),
            isStreamable: false
        )

        let segment = TDFSegment(
            hash: segmentSignatureBase64,
            segmentSize: Int64(plaintext.count),
            encryptedSegmentSize: Int64(payloadData.count)
        )

        let integrity = TDFIntegrityInformation(
            rootSignature: TDFRootSignature(alg: "HS256", sig: rootSignature),
            segmentHashAlg: "HS256",
            segmentSizeDefault: Int64(plaintext.count),
            encryptedSegmentSizeDefault: Int64(payloadData.count),
            segments: [segment]
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
            schemaVersion: configuration.kas.schemaVersion,
            ephemeralPublicKey: nil
        )

        let encryptionInformation = TDFEncryptionInformation(
            type: .split,
            keyAccess: [kasObject],
            method: method,
            integrityInformation: integrity,
            policy: configuration.policy.base64String
        )

        let payloadDescriptor = TDFPayloadDescriptor(
            type: .reference,
            url: "0.payload",
            protocolValue: .zip,
            isEncrypted: true,
            mimeType: configuration.mimeType
        )

        let manifest = TDFManifest(
            schemaVersion: configuration.tdfSpecVersion,
            payload: payloadDescriptor,
            encryptionInformation: encryptionInformation,
            assertions: nil
        )

        let container = StandardTDFContainer(
            manifest: manifest,
            payload: StandardTDFContainer.PayloadStorage.inMemory(payloadData)
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
        guard let kasObject = container.manifest.encryptionInformation.keyAccess.first else {
            throw StandardTDFDecryptError.missingKeyAccess
        }

        let symmetricKey = try StandardTDFCrypto.unwrapSymmetricKeyWithRSA(
            privateKeyPEM: privateKeyPEM,
            wrappedKey: kasObject.wrappedKey
        )

        return try decrypt(container: container, symmetricKey: symmetricKey)
    }

    public func decrypt(container: StandardTDFContainer, symmetricKey: SymmetricKey) throws -> Data {
        guard case let .inMemory(payloadData) = container.payload else {
            throw StandardTDFDecryptError.unsupportedPayloadStorage
        }
        guard payloadData.count >= 12 + 16 else {
            throw StandardTDFDecryptError.malformedPayload
        }

        let iv = payloadData.prefix(12)
        let ciphertext = payloadData.dropFirst(12).dropLast(16)
        let tag = payloadData.suffix(16)

        return try StandardTDFCrypto.decryptPayload(ciphertext: Data(ciphertext), iv: Data(iv), tag: Data(tag), symmetricKey: symmetricKey)
    }
}

public enum StandardTDFDecryptError: Error {
    case missingKeyAccess
    case unsupportedPayloadStorage
    case malformedPayload
}
