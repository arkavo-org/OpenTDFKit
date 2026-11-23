import CryptoKit
import Foundation

public struct TDFKasInfo: Sendable {
    /// The kind of key the KAS holds, which decides how the DEK is wrapped.
    public enum KeyType: Sendable, Equatable {
        /// RSA (2048 bits or more): a `wrapped` key access object, RSA-OAEP.
        case rsa
        /// EC P-256: an `ec-wrapped` key access object in the go SDK /
        /// opentdf-platform scheme. Needs a `kid` and AES-256.
        case ecP256
    }

    public let url: URL
    /// The KAS public key, PEM SubjectPublicKeyInfo, of the kind `keyType` names.
    public let publicKeyPEM: String
    public let kid: String?
    public let schemaVersion: String?
    public let keyType: KeyType

    public init(
        url: URL,
        publicKeyPEM: String,
        kid: String? = nil,
        schemaVersion: String? = nil,
        keyType: KeyType = .rsa,
    ) {
        self.url = url
        self.publicKeyPEM = publicKeyPEM
        self.kid = kid
        self.schemaVersion = schemaVersion
        self.keyType = keyType
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
        try validate(configuration)
        guard chunkSize > 0, Int64(chunkSize) <= Int64.max - 28 else {
            throw StreamingCryptoError.invalidChunkSize
        }
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

        let kasObject = try makeKeyAccessObject(kas: configuration.kas, policy: configuration.policy, symmetricKey: symmetricKey)

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
            encryptedSegmentSizeDefault: Int64(chunkSize) + 28,
            segments: segments,
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

        try TDFArchiveWriter(compressionMethod: container.compression)
            .buildArchiveToFile(manifest: container.manifest, payload: container.payload, outputURL: outputURL)

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
        try validate(configuration)
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

        let kasObject = try makeKeyAccessObject(kas: configuration.kas, policy: configuration.policy, symmetricKey: symmetricKey)

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
        guard defaultSegmentSize > 0, Int64(defaultSegmentSize) <= Int64.max - 28 else {
            throw StreamingCryptoError.invalidSegmentSize
        }
        let integrity = TDFIntegrityInformation(
            rootSignature: TDFRootSignature(alg: "HS256", sig: rootSignature),
            segmentHashAlg: "GMAC",
            segmentSizeDefault: Int64(defaultSegmentSize),
            encryptedSegmentSizeDefault: Int64(defaultSegmentSize) + 28,
            segments: segments,
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

        try TDFArchiveWriter(compressionMethod: container.compression)
            .buildArchiveToFile(manifest: container.manifest, payload: container.payload, outputURL: outputURL)

        return TDFEncryptionResult(
            container: container,
            symmetricKey: symmetricKey,
            iv: streamingResult.iv,
            tag: streamingResult.tag,
        )
    }

    public func encrypt(plaintext: Data, configuration: TDFEncryptionConfiguration) throws -> TDFEncryptionResult {
        try validate(configuration)
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
        try validate(configuration)
        guard segmentSize > 0, Int64(segmentSize) <= Int64.max - 28 else {
            throw StreamingCryptoError.invalidSegmentSize
        }

        let symmetricKey = try TDFCrypto.generateSymmetricKey(size: configuration.keySize)
        // Overflow-safe ceiling division for any segmentSize > 0
        let segmentCount = plaintext.isEmpty ? 1 : ((plaintext.count - 1) / segmentSize) + 1

        var payloadData = Data()
        let (overhead, mulOverflow) = segmentCount.multipliedReportingOverflow(by: 28)
        if !mulOverflow {
            let (totalCap, addOverflow) = plaintext.count.addingReportingOverflow(overhead)
            if !addOverflow {
                payloadData.reserveCapacity(totalCap)
            }
        }
        var segments: [TDFSegment] = []
        segments.reserveCapacity(segmentCount)
        var tags: [Data] = []
        tags.reserveCapacity(segmentCount)
        var firstIV = Data()

        var offset = plaintext.startIndex
        repeat {
            let remaining = plaintext.endIndex - offset
            let end = offset + min(remaining, segmentSize)
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

    /// Refuses a configuration no KAS could rewrap, before the input is read or
    /// anything is written: the KAS public key must load as its declared
    /// `keyType` (a `TDFCryptoError` otherwise), and an `.ecP256` KAS needs a
    /// `kid` (the platform finds EC keys by `kid` alone) and AES-256 (the go SDK
    /// only reconstructs a 32-byte key, and `TDFKAS.rewrap` only accepts
    /// 32-byte shares).
    private func validate(_ configuration: TDFEncryptionConfiguration) throws {
        let kas = configuration.kas
        switch kas.keyType {
        case .rsa:
            _ = try TDFCrypto.loadRSAPublicKey(fromPEM: kas.publicKeyPEM)
        case .ecP256:
            _ = try TDFCrypto.loadECPublicKeyP256(fromPEM: kas.publicKeyPEM)
            guard let kid = kas.kid, !kid.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw TDFEncryptError.ecKasRequiresKeyID
            }
            guard configuration.keySize == .bits256 else {
                throw TDFEncryptError.ecKasRequiresAES256
            }
        }
    }

    /// Wraps the DEK to the KAS and binds the policy (spec form) into one key
    /// access object: `wrapped` (RSA-OAEP) or `ec-wrapped` (the go SDK scheme,
    /// PEM ephemeral key) by `kas.keyType`.
    private func makeKeyAccessObject(
        kas: TDFKasInfo,
        policy: TDFPolicy,
        symmetricKey: SymmetricKey,
    ) throws -> TDFKeyAccessObject {
        let policyBinding = TDFCrypto.policyBinding(policy: policy.json, symmetricKey: symmetricKey)
        let type: TDFKeyAccessObject.AccessType
        let wrappedKey: String
        let ephemeralPublicKey: String?
        switch kas.keyType {
        case .rsa:
            type = .wrapped
            wrappedKey = try TDFCrypto.wrapSymmetricKeyWithRSA(publicKeyPEM: kas.publicKeyPEM, symmetricKey: symmetricKey)
            ephemeralPublicKey = nil
        case .ecP256:
            let wrapped = try TDFCrypto.wrapSymmetricKeyWithECForKAS(publicKeyPEM: kas.publicKeyPEM, symmetricKey: symmetricKey)
            type = .ecWrapped
            wrappedKey = wrapped.wrappedKey
            ephemeralPublicKey = wrapped.ephemeralPublicKeyPEM
        }
        return TDFKeyAccessObject(
            type: type,
            url: kas.url.absoluteString,
            protocolValue: .kas,
            wrappedKey: wrappedKey,
            policyBinding: policyBinding,
            encryptedMetadata: nil,
            kid: kas.kid,
            sid: nil,
            schemaVersion: kas.schemaVersion ?? "1.0",
            ephemeralPublicKey: ephemeralPublicKey,
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
        let kasObject = try makeKeyAccessObject(kas: configuration.kas, policy: configuration.policy, symmetricKey: symmetricKey)

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

        let encryptedDefault: Int64? = segmentSizeDefault <= Int64.max - 28 ? segmentSizeDefault + 28 : nil
        let integrity = TDFIntegrityInformation(
            rootSignature: TDFRootSignature(alg: "HS256", sig: rootSignature),
            segmentHashAlg: "GMAC",
            segmentSizeDefault: segmentSizeDefault,
            encryptedSegmentSizeDefault: encryptedDefault,
            segments: segments,
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
            encryptionInformation: container.manifest.encryptionInformation,
            privateKeyPEM: privateKeyPEM,
        )
        try decryptEncryptionInfo(
            container.manifest.encryptionInformation,
            payload: container.payload,
            symmetricKey: symmetricKey,
            policyBindingAlreadyVerified: true,
        ).write(to: outputURL)
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
            encryptionInformation: container.manifest.encryptionInformation,
            privateKeyPEM: privateKeyPEM,
        )
        return try decryptEncryptionInfo(
            container.manifest.encryptionInformation,
            payload: container.payload,
            symmetricKey: symmetricKey,
            policyBindingAlreadyVerified: true,
        )
    }

    /// Decrypts a Standard TDF (single- or multi-split) using unwrapped per-split key shares.
    /// Verifies each split's `policyBinding` against its matching key access object(s) in the
    /// manifest, requires every manifest split to be satisfied, XOR-combines the verified shares
    /// into the DEK, and verifies payload integrity before returning plaintext.
    public func decrypt(container: TDFContainer, keyShares: [TDFKeyShare]) throws -> Data {
        let encryptionInfo = container.manifest.encryptionInformation
        let keyAccess = encryptionInfo.keyAccess
        guard !keyAccess.isEmpty else {
            throw TDFDecryptError.policyBindingFailed
        }

        let policyBase64 = encryptionInfo.policy
        var kaBySplit: [String: [TDFKeyAccessObject]] = [:]
        var splitOrder: [String] = []
        for kao in keyAccess {
            let sid = kao.sid ?? ""
            if kaBySplit[sid] == nil {
                splitOrder.append(sid)
            }
            kaBySplit[sid, default: []].append(kao)
        }

        var verifiedShares: [String: Data] = [:]
        defer {
            for sid in verifiedShares.keys {
                verifiedShares[sid]?.secureZero()
            }
        }

        for share in keyShares {
            let sid = share.sid ?? ""
            guard verifiedShares[sid] == nil, let candidates = kaBySplit[sid] else {
                continue
            }
            let bindingValid = candidates.contains { kao in
                TDFCrypto.verifyPolicyBinding(
                    kao.policyBinding,
                    policyBase64: policyBase64,
                    symmetricKey: share.key,
                )
            }
            // Skip a bad replica share so another valid replica for the same split can still succeed.
            guard bindingValid else {
                continue
            }
            verifiedShares[sid] = TDFCrypto.data(from: share.key)
        }

        guard verifiedShares.count == splitOrder.count else {
            throw TDFDecryptError.policyBindingFailed
        }

        var dek = try Self.combineKeyShares(splitOrder.map { sid in
            (sid: sid, unwrap: {
                guard let share = verifiedShares[sid] else {
                    throw TDFDecryptError.missingKeyAccess
                }
                return share
            })
        })
        defer { dek.secureZero() }

        return try decryptEncryptionInfo(
            encryptionInfo,
            payload: container.payload,
            symmetricKey: SymmetricKey(data: dek),
            policyBindingAlreadyVerified: true,
        )
    }

    /// Payload algorithms `decrypt` accepts. AES-128-GCM is only written by
    /// OpenTDFKit (`TDFKeySize.bits128`); other SDKs write AES-256-GCM.
    static let supportedPayloadAlgorithms: Set<String> = ["AES-256-GCM", "AES-128-GCM"]

    static func expectedKeyBitCount(for algorithm: String) throws -> Int {
        switch algorithm.uppercased() {
        case "AES-256-GCM": 256
        case "AES-128-GCM": 128
        default: throw TDFDecryptError.unsupportedPayloadAlgorithm(algorithm)
        }
    }

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
        defer {
            for key in shares.keys {
                shares[key]?.secureZero()
            }
        }
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
                combined?.secureZero()
                throw failures[sid] ?? TDFDecryptError.missingKeyAccess
            }
            if var current = combined {
                guard current.count == share.count else {
                    current.secureZero()
                    throw TDFDecryptError.keyShareSizeMismatch
                }
                let next = Data(zip(current, share).map { $0 ^ $1 })
                current.secureZero()
                combined = next
            } else {
                combined = share
            }
        }
        guard let combined else {
            throw TDFDecryptError.missingKeyAccess
        }
        return combined
    }

    /// Unwraps every key access object with the RSA private key, verifies each
    /// KAO's `policyBinding` against its unwrapped share, and combines shares per split ID.
    private func unwrapDEK(
        encryptionInformation: TDFEncryptionInformation,
        privateKeyPEM: String,
    ) throws -> SymmetricKey {
        let policyBase64 = encryptionInformation.policy
        var dek = try Self.combineKeyShares(encryptionInformation.keyAccess.map { kasObject in
            (sid: kasObject.sid, unwrap: {
                let shareKey = try TDFCrypto.unwrapSymmetricKeyWithRSA(
                    privateKeyPEM: privateKeyPEM,
                    wrappedKey: kasObject.wrappedKey,
                )
                guard TDFCrypto.verifyPolicyBinding(
                    kasObject.policyBinding,
                    policyBase64: policyBase64,
                    symmetricKey: shareKey,
                ) else {
                    throw TDFDecryptError.policyBindingFailed
                }
                return TDFCrypto.data(from: shareKey)
            })
        })
        defer { dek.secureZero() }
        return SymmetricKey(data: dek)
    }

    /// Decrypt a single-split Standard TDF payload with its DEK.
    ///
    /// Checks payload algorithm and key size, verifies segment/root integrity and
    /// policy binding, and opens every AES-GCM segment. For multi-split manifests,
    /// use `decrypt(container:keyShares:)` or `decrypt(container:privateKeyPEM:)`
    /// so every split's share binding is verified before XOR combination.
    public func decrypt(container: TDFContainer, symmetricKey: SymmetricKey) throws -> Data {
        try decryptEncryptionInfo(
            container.manifest.encryptionInformation,
            payload: container.payload,
            symmetricKey: symmetricKey,
        )
    }

    /// Shared decryption + integrity + policy-binding verification used by ZIP, JSON, and CBOR decryptors.
    func decryptEncryptionInfo(
        _ encryptionInformation: TDFEncryptionInformation,
        payload: Data,
        symmetricKey: SymmetricKey,
        policyBindingAlreadyVerified: Bool = false,
    ) throws -> Data {
        let expectedBits = try Self.expectedKeyBitCount(for: encryptionInformation.method.algorithm)
        guard symmetricKey.bitCount == expectedBits else {
            throw TDFDecryptError.keySizeMismatch(expected: expectedBits, actual: symmetricKey.bitCount)
        }
        guard let integrity = encryptionInformation.integrityInformation,
              !integrity.segments.isEmpty
        else {
            throw TDFDecryptError.missingIntegrityInformation
        }

        // Decrypt and verify all segments + root signature before verifying policy binding and returning
        var plaintext = try decryptSegments(payload: payload, integrity: integrity, symmetricKey: symmetricKey)

        if !policyBindingAlreadyVerified {
            // Bare-DEK decryption must fail closed if KAOs are absent or multi-split
            // (in multi-split manifests each KAO binds its own share, so callers must
            // use `decrypt(container:privateKeyPEM:)` or `decrypt(container:keyShares:)`).
            let keyAccess = encryptionInformation.keyAccess
            let distinctSplits = Set(keyAccess.map { $0.sid ?? "" })
            guard !keyAccess.isEmpty, distinctSplits.count == 1 else {
                plaintext.secureZero()
                throw TDFDecryptError.policyBindingFailed
            }
            let bindingValid = keyAccess.contains { kao in
                TDFCrypto.verifyPolicyBinding(
                    kao.policyBinding,
                    policyBase64: encryptionInformation.policy,
                    symmetricKey: symmetricKey,
                )
            }
            guard bindingValid else {
                plaintext.secureZero()
                throw TDFDecryptError.policyBindingFailed
            }
        }

        return plaintext
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
            Data(encryptedSegment.suffix(16))
        case "HS256":
            Data(HMAC<SHA256>.authenticationCode(for: encryptedSegment, using: symmetricKey))
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

/// A configuration `TDFEncryptor` refuses before encrypting.
public enum TDFEncryptError: Error, CustomStringConvertible, Equatable {
    /// An `.ecP256` KAS has no `kid`; no platform KAS could find its key.
    case ecKasRequiresKeyID
    /// An `.ecP256` KAS with a key size other than AES-256.
    case ecKasRequiresAES256

    public var description: String {
        switch self {
        case .ecKasRequiresKeyID:
            "An EC P-256 KAS needs a key ID (kid); a KAS finds EC keys by kid"
        case .ecKasRequiresAES256:
            "An EC P-256 KAS needs AES-256; other OpenTDF SDKs only read a 32-byte key"
        }
    }
}

public enum TDFDecryptError: Error, CustomStringConvertible, Equatable {
    case missingKeyAccess
    case malformedPayload
    case keyShareSizeMismatch
    case missingIntegrityInformation
    case integrityCheckFailed
    case policyBindingFailed
    case keySizeMismatch(expected: Int, actual: Int)
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
        case .policyBindingFailed:
            "Policy binding verification failed: manifest policy does not match key access binding"
        case let .keySizeMismatch(expected, actual):
            "Symmetric key size \(actual) bits does not match manifest algorithm requirement (\(expected) bits)"
        case let .unsupportedIntegrityAlgorithm(algorithm):
            "Unsupported integrity algorithm: \(algorithm)"
        case let .unsupportedPayloadAlgorithm(algorithm):
            "Unsupported payload encryption algorithm: \(algorithm)"
        }
    }
}
