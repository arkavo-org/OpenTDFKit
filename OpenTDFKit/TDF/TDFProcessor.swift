import CryptoKit
import Foundation

public struct TDFKasInfo: Sendable {
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

public struct TDFPolicy: Sendable {
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
            throw TDFPolicyError.invalidJSON
        }

        guard policyObject["uuid"] != nil else {
            throw TDFPolicyError.missingUUID
        }

        guard let body = policyObject["body"] as? [String: Any] else {
            throw TDFPolicyError.missingBody
        }

        if body["dataAttributes"] == nil, body["dissem"] == nil {
            throw TDFPolicyError.emptyPolicy
        }
    }
}

public enum TDFPolicyError: Error, CustomStringConvertible {
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

public struct TDFEncryptionConfiguration: Sendable {
    /// The only TDF spec version OpenTDFKit writes (manifest `schemaVersion`).
    public static let specVersion = "4.3.0"

    public let kas: TDFKasInfo
    public let policy: TDFPolicy
    public let mimeType: String?
    public let keySize: TDFKeySize

    /// Always `TDFEncryptionConfiguration.specVersion`.
    public var tdfSpecVersion: String {
        Self.specVersion
    }

    public init(kas: TDFKasInfo, policy: TDFPolicy, mimeType: String? = nil, keySize: TDFKeySize = .bits256) {
        self.kas = kas
        self.policy = policy
        self.mimeType = mimeType
        self.keySize = keySize
    }
}

public struct TDFEncryptor {
    public init() {}

    public func encryptFile(
        inputURL: URL,
        outputURL: URL,
        configuration: TDFEncryptionConfiguration,
        chunkSize: Int = StreamingTDFCrypto.defaultChunkSize,
    ) throws -> TDFEncryptionResult {
        let symmetricKey = try TDFCrypto.generateSymmetricKey(size: configuration.keySize)
        let payloadData: Data
        let streamingResult: StreamingTDFCrypto.StreamingEncryptionResult

        do {
            let inputHandle = try FileHandle(forReadingFrom: inputURL)
            defer { try? inputHandle.close() }

            (payloadData, streamingResult) = try StreamingTDFCrypto.encryptPayloadStreamingToMemory(
                inputHandle: inputHandle,
                symmetricKey: symmetricKey,
                chunkSize: chunkSize,
            )
        }

        let policyBinding = TDFCrypto.policyBinding(policy: configuration.policy.json, symmetricKey: symmetricKey)
        let wrappedKey = try TDFCrypto.wrapSymmetricKeyWithRSA(
            publicKeyPEM: configuration.kas.publicKeyPEM,
            symmetricKey: symmetricKey,
        )

        let method = TDFMethodDescriptor(
            algorithm: configuration.keySize.algorithm,
            iv: streamingResult.iv.base64EncodedString(),
            isStreamable: true,
        )

        let segments = streamingResult.segments.map { seg in
            TDFSegment(
                hash: seg.hash,
                segmentSize: seg.plaintextSize,
                encryptedSegmentSize: seg.encryptedSize,
            )
        }

        // Hexless 4.3.0: root = base64(HMAC-SHA256(DEK, concat(raw GMAC tags))).
        let rawSegmentSigs = segments.compactMap { Data(base64Encoded: $0.hash) }
        let rootSignature = TDFCrypto.rootSignatureBase64(
            rawSegmentSignatures: rawSegmentSigs,
            symmetricKey: symmetricKey,
        )

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
            url: TDFArchiveEntryNames.payload,
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

        let container = TDFContainer(
            manifest: manifest,
            payload: payloadData,
        )

        let archiveData = try container.serializedData()
        try archiveData.write(to: outputURL)

        return TDFEncryptionResult(
            container: container,
            symmetricKey: symmetricKey,
            iv: streamingResult.iv,
            tag: streamingResult.tag,
        )
    }

    public func encryptFileMultiSegment(
        inputURL: URL,
        outputURL: URL,
        configuration: TDFEncryptionConfiguration,
        segmentSizes: [Int],
    ) throws -> TDFEncryptionResult {
        guard !segmentSizes.isEmpty else {
            throw StreamingCryptoError.invalidSegmentSize
        }

        let symmetricKey = try TDFCrypto.generateSymmetricKey(size: configuration.keySize)
        let payloadData: Data
        let streamingResult: StreamingTDFCrypto.StreamingEncryptionResult

        do {
            let inputHandle = try FileHandle(forReadingFrom: inputURL)
            defer { try? inputHandle.close() }

            (payloadData, streamingResult) = try StreamingTDFCrypto.encryptPayloadStreamingMultiSegmentToMemory(
                inputHandle: inputHandle,
                symmetricKey: symmetricKey,
                segmentSizes: segmentSizes,
            )
        }

        let policyBinding = TDFCrypto.policyBinding(policy: configuration.policy.json, symmetricKey: symmetricKey)
        let wrappedKey = try TDFCrypto.wrapSymmetricKeyWithRSA(
            publicKeyPEM: configuration.kas.publicKeyPEM,
            symmetricKey: symmetricKey,
        )

        let method = TDFMethodDescriptor(
            algorithm: configuration.keySize.algorithm,
            iv: streamingResult.iv.base64EncodedString(),
            isStreamable: true,
        )

        let segments = streamingResult.segments.map { seg in
            TDFSegment(
                hash: seg.hash,
                segmentSize: seg.plaintextSize,
                encryptedSegmentSize: seg.encryptedSize,
            )
        }

        let rawSegmentSigs = segments.compactMap { Data(base64Encoded: $0.hash) }
        let rootSignature = TDFCrypto.rootSignatureBase64(
            rawSegmentSignatures: rawSegmentSigs,
            symmetricKey: symmetricKey,
        )

        let defaultSegmentSize = segmentSizes.first ?? StreamingTDFCrypto.defaultChunkSize
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
            url: TDFArchiveEntryNames.payload,
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

        let container = TDFContainer(
            manifest: manifest,
            payload: payloadData,
        )

        let archiveData = try container.serializedData()
        try archiveData.write(to: outputURL)

        return TDFEncryptionResult(
            container: container,
            symmetricKey: symmetricKey,
            iv: streamingResult.iv,
            tag: streamingResult.tag,
        )
    }

    public func encrypt(plaintext: Data, configuration: TDFEncryptionConfiguration) throws -> TDFEncryptionResult {
        let symmetricKey = try TDFCrypto.generateSymmetricKey(size: configuration.keySize)
        let (iv, ciphertext, tag) = try TDFCrypto.encryptPayload(plaintext: plaintext, symmetricKey: symmetricKey)

        let payloadData = iv + ciphertext + tag

        let segmentSignature = try TDFCrypto.segmentSignatureGMAC(encryptedSegment: payloadData)
        let segment = TDFSegment(
            hash: segmentSignature.base64EncodedString(),
            segmentSize: Int64(plaintext.count),
            encryptedSegmentSize: Int64(payloadData.count),
        )

        return try makeResult(
            payloadData: payloadData,
            segments: [segment],
            rawSegmentSignatures: [segmentSignature],
            segmentSizeDefault: 2_097_152,
            symmetricKey: symmetricKey,
            configuration: configuration,
            iv: iv,
            tag: tag,
        )
    }

    /// Encrypt in memory into `segmentSize`-byte segments (the last may be shorter),
    /// each sealed with its own AES-GCM nonce and recorded in the manifest with its
    /// GMAC. This is the layout other OpenTDF SDKs produce by default (2 MiB segments).
    /// - Parameters:
    ///   - plaintext: Data to protect.
    ///   - configuration: KAS, policy and format settings.
    ///   - segmentSize: Plaintext bytes per segment; must be positive.
    /// - Returns: The container plus the generated DEK, first segment IV and last segment tag.
    public func encrypt(
        plaintext: Data,
        configuration: TDFEncryptionConfiguration,
        segmentSize: Int,
    ) throws -> TDFEncryptionResult {
        guard segmentSize > 0 else {
            throw StreamingCryptoError.invalidSegmentSize
        }

        let symmetricKey = try TDFCrypto.generateSymmetricKey(size: configuration.keySize)
        let segmentCount = max(1, (plaintext.count + segmentSize - 1) / segmentSize)

        var payloadData = Data()
        payloadData.reserveCapacity(plaintext.count + segmentCount * 28)
        var segments: [TDFSegment] = []
        segments.reserveCapacity(segmentCount)
        var tags: [Data] = []
        tags.reserveCapacity(segmentCount)
        var firstIV = Data()

        var offset = plaintext.startIndex
        repeat {
            let end = min(offset + segmentSize, plaintext.endIndex)
            let nonce = AES.GCM.Nonce()
            let sealed = try AES.GCM.seal(plaintext[offset ..< end], using: symmetricKey, nonce: nonce)
            let segmentStart = payloadData.count
            payloadData.append(contentsOf: nonce)
            payloadData.append(sealed.ciphertext)
            payloadData.append(sealed.tag)

            if firstIV.isEmpty {
                firstIV = Data(nonce)
            }
            tags.append(sealed.tag)
            segments.append(TDFSegment(
                hash: sealed.tag.base64EncodedString(),
                segmentSize: Int64(end - offset),
                encryptedSegmentSize: Int64(payloadData.count - segmentStart),
            ))
            offset = end
        } while offset < plaintext.endIndex

        return try makeResult(
            payloadData: payloadData,
            segments: segments,
            rawSegmentSignatures: tags,
            segmentSizeDefault: Int64(segmentSize),
            symmetricKey: symmetricKey,
            configuration: configuration,
            iv: firstIV,
            tag: tags[tags.count - 1],
        )
    }

    /// Wrap the DEK, bind the policy and assemble the manifest around an encrypted payload.
    private func makeResult(
        payloadData: Data,
        segments: [TDFSegment],
        rawSegmentSignatures: [Data],
        segmentSizeDefault: Int64,
        symmetricKey: SymmetricKey,
        configuration: TDFEncryptionConfiguration,
        iv: Data,
        tag: Data,
    ) throws -> TDFEncryptionResult {
        let policyBinding = TDFCrypto.policyBinding(policy: configuration.policy.json, symmetricKey: symmetricKey)
        let wrappedKey = try TDFCrypto.wrapSymmetricKeyWithRSA(publicKeyPEM: configuration.kas.publicKeyPEM, symmetricKey: symmetricKey)

        let rootSignature = TDFCrypto.rootSignatureBase64(
            rawSegmentSignatures: rawSegmentSignatures,
            symmetricKey: symmetricKey,
        )

        // Spec method.md: `iv` is required; record the first segment's nonce
        // (each segment carries its own nonce inline, which is what readers use).
        let method = TDFMethodDescriptor(
            algorithm: configuration.keySize.algorithm,
            iv: iv.base64EncodedString(),
            isStreamable: true,
        )

        let integrity = TDFIntegrityInformation(
            rootSignature: TDFRootSignature(alg: "HS256", sig: rootSignature),
            segmentHashAlg: "GMAC",
            segmentSizeDefault: segmentSizeDefault,
            encryptedSegmentSizeDefault: segmentSizeDefault + 28,
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
            url: TDFArchiveEntryNames.payload,
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

        let container = TDFContainer(
            manifest: manifest,
            payload: payloadData,
        )

        return TDFEncryptionResult(container: container, symmetricKey: symmetricKey, iv: iv, tag: tag)
    }
}

public struct TDFEncryptionResult: Sendable {
    public let container: TDFContainer
    public let symmetricKey: SymmetricKey
    public let iv: Data
    public let tag: Data

    public init(container: TDFContainer, symmetricKey: SymmetricKey, iv: Data, tag: Data) {
        self.container = container
        self.symmetricKey = symmetricKey
        self.iv = iv
        self.tag = tag
    }
}

public struct TDFDecryptor {
    public init() {}

    public func decryptFile(
        inputURL: URL,
        outputURL: URL,
        symmetricKey: SymmetricKey,
        chunkSize _: Int = StreamingTDFCrypto.defaultChunkSize,
    ) throws {
        let container = try TDFLoader().load(from: inputURL)
        try decrypt(container: container, symmetricKey: symmetricKey).write(to: outputURL)
    }

    public func decryptFile(
        inputURL: URL,
        outputURL: URL,
        privateKeyPEM: String,
        chunkSize _: Int = StreamingTDFCrypto.defaultChunkSize,
    ) throws {
        let loader = TDFLoader()
        let container = try loader.load(from: inputURL)

        let symmetricKey = try unwrapDEK(
            keyAccess: container.manifest.encryptionInformation.keyAccess,
            privateKeyPEM: privateKeyPEM,
        )
        try decrypt(container: container, symmetricKey: symmetricKey).write(to: outputURL)
    }

    public func decryptFileMultiSegment(
        inputURL: URL,
        outputURL: URL,
        symmetricKey: SymmetricKey,
        chunkSize _: Int = StreamingTDFCrypto.defaultChunkSize,
    ) throws {
        let container = try TDFLoader().load(from: inputURL)
        try decrypt(container: container, symmetricKey: symmetricKey).write(to: outputURL)
    }

    public func decrypt(container: TDFContainer, privateKeyPEM: String) throws -> Data {
        let symmetricKey = try unwrapDEK(
            keyAccess: container.manifest.encryptionInformation.keyAccess,
            privateKeyPEM: privateKeyPEM,
        )
        return try decrypt(container: container, symmetricKey: symmetricKey)
    }

    /// Payload algorithms `decrypt` accepts. AES-128-GCM is only written by
    /// OpenTDFKit (`TDFKeySize.bits128`); other SDKs write AES-256-GCM.
    static let supportedPayloadAlgorithms: Set<String> = ["AES-256-GCM", "AES-128-GCM"]

    /// Reconstructs a DEK from key access objects per OpenTDF split semantics
    /// (spec concepts/security.md; Go SDK): objects that share a split ID (`sid`,
    /// absent treated as "") are alternatives for one share and the first that
    /// unwraps is used; the shares of distinct splits are XORed together. Every
    /// split must yield a share.
    /// - Parameter candidates: Each key access object's split ID and a closure
    ///   that unwraps its share; closures are only called until their split has a share.
    /// - Returns: The combined key bytes.
    /// - Throws: The last unwrap error of a split with no share, or
    ///   `TDFDecryptError.keyShareSizeMismatch` / `.missingKeyAccess`.
    public static func combineKeyShares(_ candidates: [(sid: String?, unwrap: () throws -> Data)]) throws -> Data {
        var shares: [String: Data] = [:]
        var failures: [String: Error] = [:]
        var splitOrder: [String] = []
        for candidate in candidates {
            let sid = candidate.sid ?? ""
            if !splitOrder.contains(sid) {
                splitOrder.append(sid)
            }
            guard shares[sid] == nil else { continue }
            do {
                shares[sid] = try candidate.unwrap()
            } catch {
                failures[sid] = error
            }
        }

        var combined: Data?
        for sid in splitOrder {
            guard let share = shares[sid] else {
                throw failures[sid] ?? TDFDecryptError.missingKeyAccess
            }
            if let current = combined {
                guard current.count == share.count else {
                    throw TDFDecryptError.keyShareSizeMismatch
                }
                combined = Data(zip(current, share).map { $0 ^ $1 })
            } else {
                combined = share
            }
        }
        guard let combined else {
            throw TDFDecryptError.missingKeyAccess
        }
        return combined
    }

    /// Unwraps every key access object with the RSA private key and combines the
    /// shares per split ID (see `combineKeyShares`).
    private func unwrapDEK(keyAccess: [TDFKeyAccessObject], privateKeyPEM: String) throws -> SymmetricKey {
        let dek = try Self.combineKeyShares(keyAccess.map { kasObject in
            (sid: kasObject.sid, unwrap: {
                try TDFCrypto.data(from: TDFCrypto.unwrapSymmetricKeyWithRSA(
                    privateKeyPEM: privateKeyPEM,
                    wrappedKey: kasObject.wrappedKey,
                ))
            })
        })
        return SymmetricKey(data: dek)
    }

    /// Decrypt a Standard TDF payload with its DEK.
    ///
    /// Every segment is opened with AES-GCM, and the manifest's segment hashes and
    /// root signature are checked against the payload so dropped, reordered or
    /// substituted segments are rejected.
    /// - Throws: `TDFDecryptError.missingIntegrityInformation` when the manifest has
    ///   no segments, `.malformedPayload` when segment sizes do not tile the payload,
    ///   `.integrityCheckFailed` when a hash or the root signature does not match,
    ///   or a CryptoKit error when a segment fails authentication.
    public func decrypt(container: TDFContainer, symmetricKey: SymmetricKey) throws -> Data {
        let algorithm = container.manifest.encryptionInformation.method.algorithm
        guard Self.supportedPayloadAlgorithms.contains(algorithm.uppercased()) else {
            throw TDFDecryptError.unsupportedPayloadAlgorithm(algorithm)
        }
        guard let integrity = container.manifest.encryptionInformation.integrityInformation,
              !integrity.segments.isEmpty
        else {
            throw TDFDecryptError.missingIntegrityInformation
        }
        return try decryptSegments(payload: container.payload, integrity: integrity, symmetricKey: symmetricKey)
    }

    /// Open each `IV || ciphertext || tag` segment laid out back to back in `payload`,
    /// using the manifest's per-segment encrypted sizes (the last segment defaults to
    /// the remaining bytes). The segments must cover the payload exactly.
    private func decryptSegments(
        payload: Data,
        integrity: TDFIntegrityInformation,
        symmetricKey: SymmetricKey,
    ) throws -> Data {
        let ivSize = 12
        let tagSize = 16

        var plaintext = Data()
        plaintext.reserveCapacity(payload.count)
        var signatures: [Data] = []
        signatures.reserveCapacity(integrity.segments.count)
        var offset = payload.startIndex

        for (index, segment) in integrity.segments.enumerated() {
            let remaining = payload.endIndex - offset
            let isLast = index == integrity.segments.count - 1
            guard let encryptedSize = segment.encryptedSegmentSize
                ?? (isLast ? Int64(remaining) : integrity.encryptedSegmentSizeDefault),
                encryptedSize >= ivSize + tagSize,
                encryptedSize <= remaining
            else {
                throw TDFDecryptError.malformedPayload
            }
            let segmentEnd = offset + Int(encryptedSize)
            let encryptedSegment = payload[offset ..< segmentEnd]
            try signatures.append(segmentSignature(
                encryptedSegment,
                algorithm: integrity.segmentHashAlg,
                symmetricKey: symmetricKey,
            ))

            let nonce = try AES.GCM.Nonce(data: payload[offset ..< offset + ivSize])
            let sealed = try AES.GCM.SealedBox(
                nonce: nonce,
                ciphertext: payload[offset + ivSize ..< segmentEnd - tagSize],
                tag: payload[segmentEnd - tagSize ..< segmentEnd],
            )
            try plaintext.append(AES.GCM.open(sealed, using: symmetricKey))
            offset = segmentEnd
        }

        guard offset == payload.endIndex else {
            throw TDFDecryptError.malformedPayload
        }
        try verifyIntegrity(signatures: signatures, integrity: integrity, symmetricKey: symmetricKey)
        return plaintext
    }

    // MARK: - Integrity verification

    /// Check the manifest's per-segment hashes and root signature against the
    /// signatures recomputed from the payload, in the hexless TDF 4.3.0+ encoding
    /// (`base64(raw signature)`).
    ///
    /// The root must be HS256: HMAC-SHA256 with the DEK over the segment signatures
    /// in order, which binds segment order and count. A keyless root (e.g. GMAC,
    /// which is just the last segment's tag) is rejected so a manifest cannot
    /// downgrade the check.
    private func verifyIntegrity(
        signatures: [Data],
        integrity: TDFIntegrityInformation,
        symmetricKey: SymmetricKey,
    ) throws {
        let rootAlgorithm = integrity.rootSignature.alg
        guard rootAlgorithm.isEmpty || rootAlgorithm.uppercased() == "HS256" else {
            throw TDFDecryptError.unsupportedIntegrityAlgorithm(integrity.rootSignature.alg)
        }
        let root = Data(HMAC<SHA256>.authenticationCode(for: Data(signatures.joined()), using: symmetricKey))
        guard let manifestRoot = Data(base64Encoded: integrity.rootSignature.sig),
              constantTimeEquals(manifestRoot, root)
        else {
            throw TDFDecryptError.integrityCheckFailed
        }

        for (segment, signature) in zip(integrity.segments, signatures) {
            guard let manifestHash = Data(base64Encoded: segment.hash),
                  constantTimeEquals(manifestHash, signature)
            else {
                throw TDFDecryptError.integrityCheckFailed
            }
        }
    }

    /// Segment signature per OpenTDF: GMAC is the segment's AES-GCM tag (its last
    /// 16 bytes); HS256 is HMAC-SHA256 over the encrypted segment with the DEK.
    private func segmentSignature(_ encryptedSegment: Data, algorithm: String, symmetricKey: SymmetricKey) throws -> Data {
        switch algorithm.uppercased() {
        case "GMAC":
            return Data(encryptedSegment.suffix(16))
        case "HS256":
            return Data(HMAC<SHA256>.authenticationCode(for: encryptedSegment, using: symmetricKey))
        default:
            throw TDFDecryptError.unsupportedIntegrityAlgorithm(algorithm)
        }
    }

    /// Length is public; only the contents are compared in constant time.
    private func constantTimeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for (a, b) in zip(lhs, rhs) {
            difference |= a ^ b
        }
        return difference == 0
    }
}

public enum TDFDecryptError: Error, CustomStringConvertible, Equatable {
    case missingKeyAccess
    case malformedPayload
    case keyShareSizeMismatch
    case missingIntegrityInformation
    case integrityCheckFailed
    case unsupportedIntegrityAlgorithm(String)
    case unsupportedPayloadAlgorithm(String)

    public var description: String {
        switch self {
        case .missingKeyAccess:
            "No key access objects found in manifest"
        case .malformedPayload:
            "Malformed encrypted payload: insufficient data for IV and authentication tag"
        case .keyShareSizeMismatch:
            "Key share size mismatch: all key shares must have the same length for XOR reconstruction"
        case .missingIntegrityInformation:
            "Decryption requires integrity information with segment metadata"
        case .integrityCheckFailed:
            "Integrity check failed: segment hashes or root signature do not match the payload"
        case let .unsupportedIntegrityAlgorithm(algorithm):
            "Unsupported integrity algorithm: \(algorithm)"
        case let .unsupportedPayloadAlgorithm(algorithm):
            "Unsupported payload encryption algorithm: \(algorithm)"
        }
    }
}
