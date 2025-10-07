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

    public init(json: Data) throws {
        try Self.validate(json)
        self.json = json
    }

    public var base64String: String {
        json.base64EncodedString()
    }

    private static func validate(_ policyJSON: Data) throws {
        guard let policyObject = try? JSONSerialization.jsonObject(with: policyJSON) as? [String: Any] else {
            throw StandardTDFPolicyError.invalidJSON
        }

        guard policyObject["uuid"] != nil else {
            throw StandardTDFPolicyError.missingUUID
        }

        guard let body = policyObject["body"] as? [String: Any] else {
            throw StandardTDFPolicyError.missingBody
        }

        if body["dataAttributes"] == nil, body["dissem"] == nil {
            throw StandardTDFPolicyError.emptyPolicy
        }
    }
}

public enum StandardTDFPolicyError: Error, CustomStringConvertible {
    case invalidJSON
    case missingUUID
    case missingBody
    case emptyPolicy

    public var description: String {
        switch self {
        case .invalidJSON:
            "Policy must be valid JSON object"
        case .missingUUID:
            "Policy must contain 'uuid' field"
        case .missingBody:
            "Policy must contain 'body' field"
        case .emptyPolicy:
            "Policy body must contain 'dataAttributes' or 'dissem' fields"
        }
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

    public func encryptFile(
        inputURL: URL,
        outputURL: URL,
        configuration: StandardTDFEncryptionConfiguration,
        chunkSize: Int = StreamingStandardTDFCrypto.defaultChunkSize,
    ) throws -> StandardTDFEncryptionResult {
        let symmetricKey = try StandardTDFCrypto.generateSymmetricKey()
        let payloadData: Data
        let streamingResult: StreamingStandardTDFCrypto.StreamingEncryptionResult

        do {
            let inputHandle = try FileHandle(forReadingFrom: inputURL)
            defer { try? inputHandle.close() }

            (payloadData, streamingResult) = try StreamingStandardTDFCrypto.encryptPayloadStreamingToMemory(
                inputHandle: inputHandle,
                symmetricKey: symmetricKey,
                chunkSize: chunkSize,
            )
        }

        let policyBinding = StandardTDFCrypto.policyBinding(policy: configuration.policy.json, symmetricKey: symmetricKey)
        let wrappedKey = try StandardTDFCrypto.wrapSymmetricKeyWithRSA(
            publicKeyPEM: configuration.kas.publicKeyPEM,
            symmetricKey: symmetricKey,
        )

        let method = TDFMethodDescriptor(
            algorithm: "AES-256-GCM",
            iv: "",
            isStreamable: true,
        )

        let segments = streamingResult.segments.map { seg in
            TDFSegment(
                hash: seg.hash,
                segmentSize: seg.plaintextSize,
                encryptedSegmentSize: seg.encryptedSize,
            )
        }

        let segmentSignatureBase64 = segments.first!.hash
        let rootSignature = StandardTDFCrypto.segmentSignature(
            segmentCiphertext: Data(base64Encoded: segmentSignatureBase64)!,
            symmetricKey: symmetricKey,
        ).base64EncodedString()

        let integrity = TDFIntegrityInformation(
            rootSignature: TDFRootSignature(alg: "HS256", sig: rootSignature),
            segmentHashAlg: "GMAC",
            segmentSizeDefault: Int64(chunkSize),
            encryptedSegmentSizeDefault: Int64(chunkSize + 28),
            segments: segments,
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

        let archiveData = try container.serializedData()
        try archiveData.write(to: outputURL)

        return StandardTDFEncryptionResult(
            container: container,
            symmetricKey: symmetricKey,
            iv: streamingResult.iv,
            tag: streamingResult.tag,
        )
    }

    public func encryptFileMultiSegment(
        inputURL: URL,
        outputURL: URL,
        configuration: StandardTDFEncryptionConfiguration,
        segmentSizes: [Int],
    ) throws -> StandardTDFEncryptionResult {
        guard !segmentSizes.isEmpty else {
            throw StreamingCryptoError.invalidSegmentSize
        }

        let symmetricKey = try StandardTDFCrypto.generateSymmetricKey()
        let payloadData: Data
        let streamingResult: StreamingStandardTDFCrypto.StreamingEncryptionResult

        do {
            let inputHandle = try FileHandle(forReadingFrom: inputURL)
            defer { try? inputHandle.close() }

            (payloadData, streamingResult) = try StreamingStandardTDFCrypto.encryptPayloadStreamingMultiSegmentToMemory(
                inputHandle: inputHandle,
                symmetricKey: symmetricKey,
                segmentSizes: segmentSizes,
            )
        }

        let policyBinding = StandardTDFCrypto.policyBinding(policy: configuration.policy.json, symmetricKey: symmetricKey)
        let wrappedKey = try StandardTDFCrypto.wrapSymmetricKeyWithRSA(
            publicKeyPEM: configuration.kas.publicKeyPEM,
            symmetricKey: symmetricKey,
        )

        let method = TDFMethodDescriptor(
            algorithm: "AES-256-GCM",
            iv: "",
            isStreamable: true,
        )

        let segments = streamingResult.segments.map { seg in
            TDFSegment(
                hash: seg.hash,
                segmentSize: seg.plaintextSize,
                encryptedSegmentSize: seg.encryptedSize,
            )
        }

        let segmentHashes = segments.map { Data(base64Encoded: $0.hash)! }
        let concatenatedHashes = segmentHashes.reduce(Data(), +)
        let rootSignature = StandardTDFCrypto.segmentSignature(
            segmentCiphertext: concatenatedHashes,
            symmetricKey: symmetricKey,
        ).base64EncodedString()

        let defaultSegmentSize = segmentSizes.first ?? StreamingStandardTDFCrypto.defaultChunkSize
        let integrity = TDFIntegrityInformation(
            rootSignature: TDFRootSignature(alg: "HS256", sig: rootSignature),
            segmentHashAlg: "GMAC",
            segmentSizeDefault: Int64(defaultSegmentSize),
            encryptedSegmentSizeDefault: Int64(defaultSegmentSize + 28),
            segments: segments,
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

        let archiveData = try container.serializedData()
        try archiveData.write(to: outputURL)

        return StandardTDFEncryptionResult(
            container: container,
            symmetricKey: symmetricKey,
            iv: streamingResult.iv,
            tag: streamingResult.tag,
        )
    }

    public func encrypt(plaintext: Data, configuration: StandardTDFEncryptionConfiguration) throws -> StandardTDFEncryptionResult {
        let symmetricKey = try StandardTDFCrypto.generateSymmetricKey()
        let (iv, ciphertext, tag) = try StandardTDFCrypto.encryptPayload(plaintext: plaintext, symmetricKey: symmetricKey)

        let payloadData = iv + ciphertext + tag

        let policyBinding = StandardTDFCrypto.policyBinding(policy: configuration.policy.json, symmetricKey: symmetricKey)
        let wrappedKey = try StandardTDFCrypto.wrapSymmetricKeyWithRSA(publicKeyPEM: configuration.kas.publicKeyPEM, symmetricKey: symmetricKey)

        let segmentSignature = try StandardTDFCrypto.segmentSignatureGMAC(segmentCiphertext: payloadData, symmetricKey: symmetricKey)
        let segmentSignatureBase64 = segmentSignature.base64EncodedString()

        let rootSignature = StandardTDFCrypto.segmentSignature(segmentCiphertext: segmentSignature, symmetricKey: symmetricKey).base64EncodedString()

        let method = TDFMethodDescriptor(
            algorithm: "AES-256-GCM",
            iv: "",
            isStreamable: true,
        )

        let segment = TDFSegment(
            hash: segmentSignatureBase64,
            segmentSize: Int64(plaintext.count),
            encryptedSegmentSize: Int64(payloadData.count),
        )

        let integrity = TDFIntegrityInformation(
            rootSignature: TDFRootSignature(alg: "HS256", sig: rootSignature),
            segmentHashAlg: "GMAC",
            segmentSizeDefault: 2_097_152,
            encryptedSegmentSizeDefault: 2_097_180,
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

    public func decryptFile(
        inputURL: URL,
        outputURL: URL,
        symmetricKey: SymmetricKey,
        chunkSize _: Int = StreamingStandardTDFCrypto.defaultChunkSize,
    ) throws {
        let loader = StandardTDFLoader()
        let container = try loader.load(from: inputURL)

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

        let plaintext = try StandardTDFCrypto.decryptPayload(
            ciphertext: Data(ciphertext),
            iv: Data(iv),
            tag: Data(tag),
            symmetricKey: symmetricKey,
        )

        try plaintext.write(to: outputURL)
    }

    public func decryptFile(
        inputURL: URL,
        outputURL: URL,
        privateKeyPEM: String,
        chunkSize: Int = StreamingStandardTDFCrypto.defaultChunkSize,
    ) throws {
        let loader = StandardTDFLoader()
        let container = try loader.load(from: inputURL)

        let keyAccess = container.manifest.encryptionInformation.keyAccess
        guard !keyAccess.isEmpty else {
            throw StandardTDFDecryptError.missingKeyAccess
        }

        let symmetricKey: SymmetricKey
        if keyAccess.count == 1 {
            symmetricKey = try StandardTDFCrypto.unwrapSymmetricKeyWithRSA(
                privateKeyPEM: privateKeyPEM,
                wrappedKey: keyAccess[0].wrappedKey,
            )
        } else {
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
            symmetricKey = SymmetricKey(data: finalKeyData)
        }

        try decryptFile(inputURL: inputURL, outputURL: outputURL, symmetricKey: symmetricKey, chunkSize: chunkSize)
    }

    public func decryptFileMultiSegment(
        inputURL: URL,
        outputURL: URL,
        symmetricKey: SymmetricKey,
        chunkSize _: Int = StreamingStandardTDFCrypto.defaultChunkSize,
    ) throws {
        let loader = StandardTDFLoader()
        let container = try loader.load(from: inputURL)

        guard let integrityInfo = container.manifest.encryptionInformation.integrityInformation else {
            throw StandardTDFDecryptError.missingIntegrityInformation
        }

        let segments = integrityInfo.segments.enumerated().map { index, seg in
            StreamingStandardTDFCrypto.EncryptedSegment(
                segmentIndex: index,
                plaintextSize: seg.segmentSize,
                encryptedSize: seg.encryptedSegmentSize ?? (seg.segmentSize + 28),
                hash: seg.hash,
            )
        }

        let plaintext = try StreamingStandardTDFCrypto.decryptPayloadMultiSegmentFromMemory(
            encryptedPayload: container.payload,
            segments: segments,
            symmetricKey: symmetricKey,
        )

        try plaintext.write(to: outputURL)
    }

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
    case missingIntegrityInformation

    public var description: String {
        switch self {
        case .missingKeyAccess:
            "No key access objects found in manifest"
        case .malformedPayload:
            "Malformed encrypted payload: insufficient data for IV and authentication tag"
        case .keyShareSizeMismatch:
            "Key share size mismatch: all key shares must have the same length for XOR reconstruction"
        case .missingIntegrityInformation:
            "Multi-segment decryption requires integrity information with segment metadata"
        }
    }
}
