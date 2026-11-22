import Foundation
import SwiftCBOR

// MARK: - TDF-CBOR Magic Bytes

/// Self-describe CBOR tag (55799)
/// D9 D9F7 = tag(55799)
public let TDF_CBOR_MAGIC: [UInt8] = [0xD9, 0xD9, 0xF7]

/// Integer key mappings per TDF-CBOR spec section 3.1
public enum TDFCBORKey: Int, CodingKey {
    case tdf = 1
    case version = 2
    case created = 3
    case manifest = 4
    case payload = 5

    public var intValue: Int? {
        rawValue
    }

    public var stringValue: String {
        String(rawValue)
    }

    public init?(intValue: Int) {
        self.init(rawValue: intValue)
    }

    public init?(stringValue: String) {
        guard let intVal = Int(stringValue) else { return nil }
        self.init(rawValue: intVal)
    }
}

/// Payload integer key mappings per TDF-CBOR spec section 3.1
public enum TDFCBORPayloadKey: Int {
    case type = 1
    case `protocol` = 2
    case mimeType = 3
    case isEncrypted = 4
    case length = 5
    case value = 6
}

/// Enumerated values per TDF-CBOR spec section 1.5
public enum TDFCBOREnums {
    // Payload type: 0=inline, 1=reference
    public static let payloadTypeInline: UInt64 = 0
    public static let payloadTypeReference: UInt64 = 1

    // Payload protocol: 0=binary, 1=binary-chunked
    public static let payloadProtocolBinary: UInt64 = 0
    public static let payloadProtocolBinaryChunked: UInt64 = 1

    // Encryption type: 0=split, 1=remote
    public static let encryptionTypeSplit: UInt64 = 0
    public static let encryptionTypeRemote: UInt64 = 1

    // Key access type: 0=wrapped, 1=remote, 2=remoteWrapped, 3=ecWrapped
    public static let keyAccessTypeWrapped: UInt64 = 0
    public static let keyAccessTypeRemote: UInt64 = 1
    public static let keyAccessTypeRemoteWrapped: UInt64 = 2
    public static let keyAccessTypeEcWrapped: UInt64 = 3

    /// Key protocol: 0=kas
    public static let keyProtocolKas: UInt64 = 0

    /// Symmetric algorithm: 0=AES-256-GCM, 1=AES-128-GCM, 2=AES-256-CBC, 3=AES-128-CBC
    public static let symmetricAlgAes256Gcm: UInt64 = 0
    public static let symmetricAlgAes128Gcm: UInt64 = 1
    public static let symmetricAlgAes256Cbc: UInt64 = 2
    public static let symmetricAlgAes128Cbc: UInt64 = 3

    // Hash/Signature algorithm
    public static let hashAlgHS256: UInt64 = 0
    public static let hashAlgHS384: UInt64 = 1
    public static let hashAlgHS512: UInt64 = 2
    public static let hashAlgGMAC: UInt64 = 3
    public static let hashAlgSHA256: UInt64 = 4
    public static let hashAlgES256: UInt64 = 5
    public static let hashAlgES384: UInt64 = 6
    public static let hashAlgES512: UInt64 = 7
}

/// Manifest integer key mappings per TDF-CBOR spec section 3.1
public enum TDFCBORManifestKey: Int {
    case encryptionInformation = 1
    case assertions = 2
}

/// EncryptionInformation integer key mappings
public enum TDFCBOREncInfoKey: Int {
    case type = 1
    case keyAccess = 2
    case method = 3
    case integrityInformation = 4
    case policy = 5
}

/// KeyAccess integer key mappings
public enum TDFCBORKeyAccessKey: Int {
    case type = 1
    case url = 2
    case `protocol` = 3
    case wrappedKey = 4
    case policyBinding = 5
    case encryptedMetadata = 6
    case kid = 7
    case ephemeralPublicKey = 8
    case schemaVersion = 9
    case sid = 10
}

/// PolicyBinding integer key mappings
public enum TDFCBORPolicyBindingKey: Int {
    case alg = 1
    case hash = 2
}

/// Method integer key mappings
public enum TDFCBORMethodKey: Int {
    case algorithm = 1
    case iv = 2
    case isStreamable = 3
}

/// IntegrityInformation integer key mappings
public enum TDFCBORIntegrityKey: Int {
    case rootSignature = 1
    case segmentHashAlg = 2
    case segments = 3
    case segmentSizeDefault = 4
    case encryptedSegmentSizeDefault = 5
}

/// RootSignature integer key mappings
public enum TDFCBORRootSigKey: Int {
    case alg = 1
    case sig = 2
}

/// Segment integer key mappings
public enum TDFCBORSegmentKey: Int {
    case hash = 1
    case segmentSize = 2
    case encryptedSegmentSize = 3
}

// MARK: - TDF-CBOR Envelope

/// TDF-CBOR envelope for binary payload transmission (spec-compliant)
///
/// This structure represents a complete TDF-CBOR package per the TDF-CBOR
/// specification draft-00. The format uses integer keys and binary payloads
/// for optimal size and parsing efficiency.
///
/// ## Integer Key Mapping
///
/// | Key | Field    | Type                |
/// |-----|----------|---------------------|
/// | 1   | tdf      | string "cbor"       |
/// | 2   | version  | [UInt8] semver      |
/// | 3   | created  | UInt64 Unix timestamp |
/// | 4   | manifest | TDFCBORManifest     |
/// | 5   | payload  | TDFBinaryPayload    |
public struct TDFCBOREnvelope: Sendable {
    /// Format identifier. MUST be "cbor" for TDF-CBOR documents.
    public let tdf: String

    /// Semantic version as [major, minor, patch] array
    public let version: [UInt8]

    /// Unix timestamp of document creation (optional)
    public var created: UInt64?

    /// TDF manifest containing encryption and policy information
    public let manifest: TDFCBORManifest

    /// Binary encrypted payload container
    public let payload: TDFBinaryPayload

    public init(
        tdf: String = "cbor",
        version: [UInt8] = [1, 0, 0],
        created: UInt64? = nil,
        manifest: TDFCBORManifest,
        payload: TDFBinaryPayload,
    ) {
        self.tdf = tdf
        self.version = version
        self.created = created
        self.manifest = manifest
        self.payload = payload
    }

    /// Format identifier (always "cbor")
    public var formatId: String {
        tdf
    }
}

// MARK: - TDF-CBOR Manifest

/// TDF manifest for TDF-CBOR format.
///
/// Contains encryption information serialized as JSON string within CBOR.
public struct TDFCBORManifest: Sendable {
    /// Encryption information including key access and policy
    public let encryptionInformation: TDFEncryptionInformation

    /// Optional assertions for additional metadata
    public var assertions: [TDFAssertion]?

    public init(
        encryptionInformation: TDFEncryptionInformation,
        assertions: [TDFAssertion]? = nil,
    ) {
        self.encryptionInformation = encryptionInformation
        self.assertions = assertions
    }
}

// MARK: - TDF Binary Payload

/// Binary payload for TDF-CBOR transport.
///
/// Contains the encrypted data directly as binary bytes (no base64 encoding).
public struct TDFBinaryPayload: Sendable {
    /// Payload type. MUST be "inline" for TDF-CBOR
    public let type: String

    /// Protocol. MUST be "binary" for TDF-CBOR (not "base64")
    public let `protocol`: String

    /// MIME type of the original (unencrypted) data
    public var mimeType: String?

    /// Whether the payload is encrypted. MUST be true
    public let isEncrypted: Bool

    /// Raw encrypted bytes (not base64 encoded)
    public let value: Data

    public init(
        type: String = "inline",
        protocol: String = "binary",
        mimeType: String? = nil,
        isEncrypted: Bool = true,
        value: Data,
    ) {
        self.type = type
        self.protocol = `protocol`
        self.mimeType = mimeType
        self.isEncrypted = isEncrypted
        self.value = value
    }
}

// MARK: - TDF-CBOR Error Types

/// Errors specific to TDF-CBOR parsing and validation.
public enum TDFCBORError: Error, CustomStringConvertible, Sendable {
    case invalidMagicBytes
    case invalidTdfIdentifier(String)
    case unexpectedKey(expected: Int, got: Int)
    case cborDecodingFailed(String)
    case cborEncodingFailed(String)
    case binaryPayloadExpected
    case missingField(String)
    case encryptionFailed(String)
    case decryptionFailed(String)

    public var description: String {
        switch self {
        case .invalidMagicBytes:
            "Invalid or missing CBOR magic bytes"
        case let .invalidTdfIdentifier(id):
            "Invalid tdf identifier: expected 'cbor', got '\(id)'"
        case let .unexpectedKey(expected, got):
            "Expected integer key \(expected), got \(got)"
        case let .cborDecodingFailed(e):
            "CBOR decoding failed: \(e)"
        case let .cborEncodingFailed(e):
            "CBOR encoding failed: \(e)"
        case .binaryPayloadExpected:
            "Binary payload expected but got base64"
        case let .missingField(field):
            "Missing required field: \(field)"
        case let .encryptionFailed(e):
            "Encryption failed: \(e)"
        case let .decryptionFailed(e):
            "Decryption failed: \(e)"
        }
    }
}

// MARK: - TDF-CBOR Extensions

public extension TDFCBOREnvelope {
    /// Check if data starts with CBOR self-describe tag (slice-safe for startIndex > 0)
    static func hasMagicBytes(_ data: Data) -> Bool {
        guard data.count >= 3 else { return false }
        let i0 = data.startIndex
        let i1 = data.index(after: i0)
        let i2 = data.index(after: i1)
        return data[i0] == 0xD9 && data[i1] == 0xD9 && data[i2] == 0xF7
    }

    /// Convert to standard TDF manifest format (for KAS integration)
    func toStandardManifest() -> TDFManifest {
        TDFManifest(
            schemaVersion: "1.0.0",
            payload: TDFPayloadDescriptor(
                type: .reference,
                url: "inline",
                protocolValue: .zip,
                isEncrypted: true,
                mimeType: payload.mimeType,
            ),
            encryptionInformation: manifest.encryptionInformation,
            assertions: manifest.assertions,
        )
    }
}

// MARK: - CBOR Coding

extension TDFCBOREnvelope {
    /// Encode to CBOR bytes with self-describe tag
    public func toCBORData() throws -> Data {
        // Build manifest as native CBOR with integer keys and enums
        let manifestCBOR = try encodeManifestToCBOR()

        // Build payload map with integer keys and enum values per spec section 1.5
        let payloadTypeEnum: UInt64 = payload.type == "inline" ? TDFCBOREnums.payloadTypeInline : TDFCBOREnums.payloadTypeReference
        let protocolEnum: UInt64 = payload.protocol == "binary" ? TDFCBOREnums.payloadProtocolBinary : TDFCBOREnums.payloadProtocolBinaryChunked

        var payloadMap: [CBOR: CBOR] = [
            CBOR.unsignedInt(UInt64(TDFCBORPayloadKey.type.rawValue)): .unsignedInt(payloadTypeEnum),
            CBOR.unsignedInt(UInt64(TDFCBORPayloadKey.protocol.rawValue)): .unsignedInt(protocolEnum),
            CBOR.unsignedInt(UInt64(TDFCBORPayloadKey.isEncrypted.rawValue)): .boolean(payload.isEncrypted),
            CBOR.unsignedInt(UInt64(TDFCBORPayloadKey.value.rawValue)): .byteString(Array(payload.value)),
        ]
        if let mimeType = payload.mimeType {
            payloadMap[CBOR.unsignedInt(UInt64(TDFCBORPayloadKey.mimeType.rawValue))] = .utf8String(mimeType)
        }

        // Build main map with integer keys
        var mainMap: [CBOR: CBOR] = [
            CBOR.unsignedInt(UInt64(TDFCBORKey.tdf.rawValue)): .utf8String(tdf),
            CBOR.unsignedInt(UInt64(TDFCBORKey.version.rawValue)): .array(version.map { .unsignedInt(UInt64($0)) }),
            CBOR.unsignedInt(UInt64(TDFCBORKey.manifest.rawValue)): manifestCBOR,
            CBOR.unsignedInt(UInt64(TDFCBORKey.payload.rawValue)): .map(payloadMap),
        ]

        if let created {
            mainMap[CBOR.unsignedInt(UInt64(TDFCBORKey.created.rawValue))] = .unsignedInt(created)
        }

        let cborValue = CBOR.map(mainMap)
        let encoded = cborValue.encode()

        // Prepend self-describe tag
        var result = Data(TDF_CBOR_MAGIC)
        result.append(contentsOf: encoded)
        return result
    }

    /// Encode manifest to native CBOR with integer keys and enums
    private func encodeManifestToCBOR() throws -> CBOR {
        let encInfo = manifest.encryptionInformation

        // Decode policy from base64 to raw bytes
        guard let policyData = Data(base64Encoded: encInfo.policy) else {
            throw TDFCBORError.cborEncodingFailed("Invalid policy base64")
        }

        // Encode key access array
        let keyAccessArray: [CBOR] = try encInfo.keyAccess.map { try encodeKeyAccessToCBOR($0) }

        // Encode method
        let methodCBOR = try encodeMethodToCBOR(encInfo.method)

        // Encode integrity information (if present)
        guard let integrityInfo = encInfo.integrityInformation else {
            throw TDFCBORError.missingField("integrityInformation")
        }
        let integrityCBOR = try encodeIntegrityToCBOR(integrityInfo)

        // Encryption type enum: "split" -> 0, "remote" -> 1
        let encTypeEnum: UInt64 = encInfo.type == .split ? TDFCBOREnums.encryptionTypeSplit : TDFCBOREnums.encryptionTypeRemote

        // Build encryptionInformation map
        let encInfoMap: [CBOR: CBOR] = [
            .unsignedInt(UInt64(TDFCBOREncInfoKey.type.rawValue)): .unsignedInt(encTypeEnum),
            .unsignedInt(UInt64(TDFCBOREncInfoKey.keyAccess.rawValue)): .array(keyAccessArray),
            .unsignedInt(UInt64(TDFCBOREncInfoKey.method.rawValue)): methodCBOR,
            .unsignedInt(UInt64(TDFCBOREncInfoKey.integrityInformation.rawValue)): integrityCBOR,
            .unsignedInt(UInt64(TDFCBOREncInfoKey.policy.rawValue)): .byteString(Array(policyData)),
        ]

        // Build manifest map
        var manifestMap: [CBOR: CBOR] = [
            .unsignedInt(UInt64(TDFCBORManifestKey.encryptionInformation.rawValue)): .map(encInfoMap),
        ]

        // Add assertions if present
        if let assertions = manifest.assertions, !assertions.isEmpty {
            let assertionsArray = try encodeAssertionsToCBOR(assertions)
            manifestMap[.unsignedInt(UInt64(TDFCBORManifestKey.assertions.rawValue))] = .array(assertionsArray)
        }

        return .map(manifestMap)
    }

    /// Encode a single key access object to CBOR
    private func encodeKeyAccessToCBOR(_ ka: TDFKeyAccessObject) throws -> CBOR {
        // Key access type enum
        let kaTypeEnum: UInt64
        switch ka.type {
        case .wrapped: kaTypeEnum = TDFCBOREnums.keyAccessTypeWrapped
        case .remote: kaTypeEnum = TDFCBOREnums.keyAccessTypeRemote
        case .remoteWrapped: kaTypeEnum = TDFCBOREnums.keyAccessTypeRemoteWrapped
        case .ecWrapped: kaTypeEnum = TDFCBOREnums.keyAccessTypeEcWrapped
        case .hybridWrapped, .mlkemWrapped:
            throw TDFCBORError.cborEncodingFailed("Key access type \(ka.type.rawValue) has no TDF-CBOR encoding")
        }

        // Protocol enum: "kas" -> 0 (currently only kas is supported)
        let protocolEnum: UInt64 = TDFCBOREnums.keyProtocolKas

        // Decode wrapped key from base64 to raw bytes
        guard let wrappedKeyData = Data(base64Encoded: ka.wrappedKey) else {
            throw TDFCBORError.cborEncodingFailed("Invalid wrappedKey base64")
        }

        // Encode policy binding
        let bindingAlgEnum = try hashAlgToEnum(ka.policyBinding.alg)
        guard let bindingHashData = Data(base64Encoded: ka.policyBinding.hash) else {
            throw TDFCBORError.cborEncodingFailed("Invalid policy binding hash base64")
        }

        let policyBindingMap: [CBOR: CBOR] = [
            .unsignedInt(UInt64(TDFCBORPolicyBindingKey.alg.rawValue)): .unsignedInt(bindingAlgEnum),
            .unsignedInt(UInt64(TDFCBORPolicyBindingKey.hash.rawValue)): .byteString(Array(bindingHashData)),
        ]

        var kaMap: [CBOR: CBOR] = [
            .unsignedInt(UInt64(TDFCBORKeyAccessKey.type.rawValue)): .unsignedInt(kaTypeEnum),
            .unsignedInt(UInt64(TDFCBORKeyAccessKey.url.rawValue)): .utf8String(ka.url),
            .unsignedInt(UInt64(TDFCBORKeyAccessKey.protocol.rawValue)): .unsignedInt(protocolEnum),
            .unsignedInt(UInt64(TDFCBORKeyAccessKey.wrappedKey.rawValue)): .byteString(Array(wrappedKeyData)),
            .unsignedInt(UInt64(TDFCBORKeyAccessKey.policyBinding.rawValue)): .map(policyBindingMap),
        ]

        // Add optional fields without silently dropping values
        if let encryptedMetadata = ka.encryptedMetadata {
            if let metaData = Data(base64Encoded: encryptedMetadata) {
                kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.encryptedMetadata.rawValue))] = .byteString(Array(metaData))
            } else {
                kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.encryptedMetadata.rawValue))] = .utf8String(encryptedMetadata)
            }
        }

        if let kid = ka.kid {
            kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.kid.rawValue))] = .utf8String(kid)
        }

        if let epk = ka.ephemeralPublicKey {
            if epk.contains("-----BEGIN") {
                kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.ephemeralPublicKey.rawValue))] = .utf8String(epk)
            } else if let epkData = Data(base64Encoded: epk) {
                kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.ephemeralPublicKey.rawValue))] = .byteString(Array(epkData))
            } else {
                throw TDFCBORError.cborEncodingFailed("Invalid ephemeralPublicKey encoding")
            }
        }

        if let sv = ka.schemaVersion {
            kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.schemaVersion.rawValue))] = .utf8String(sv)
        }

        if let sid = ka.sid {
            kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.sid.rawValue))] = .utf8String(sid)
        }

        return .map(kaMap)
    }

    /// Encode method to CBOR
    private func encodeMethodToCBOR(_ method: TDFMethodDescriptor) throws -> CBOR {
        // Algorithm enum mapping
        let algEnum: UInt64 = switch method.algorithm {
        case "AES-256-GCM": TDFCBOREnums.symmetricAlgAes256Gcm
        case "AES-128-GCM": TDFCBOREnums.symmetricAlgAes128Gcm
        case "AES-256-CBC": TDFCBOREnums.symmetricAlgAes256Cbc
        case "AES-128-CBC": TDFCBOREnums.symmetricAlgAes128Cbc
        default:
            throw TDFCBORError.cborEncodingFailed("Unsupported symmetric algorithm: \(method.algorithm)")
        }

        // Decode IV from base64 to raw bytes
        guard let ivData = Data(base64Encoded: method.iv) else {
            throw TDFCBORError.cborEncodingFailed("Invalid IV base64")
        }

        let methodMap: [CBOR: CBOR] = [
            .unsignedInt(UInt64(TDFCBORMethodKey.algorithm.rawValue)): .unsignedInt(algEnum),
            .unsignedInt(UInt64(TDFCBORMethodKey.iv.rawValue)): .byteString(Array(ivData)),
            .unsignedInt(UInt64(TDFCBORMethodKey.isStreamable.rawValue)): .boolean(method.isStreamable ?? true),
        ]

        return .map(methodMap)
    }

    /// Encode integrity information to CBOR
    private func encodeIntegrityToCBOR(_ integrity: TDFIntegrityInformation) throws -> CBOR {
        // Encode root signature
        let rootAlgEnum = try hashAlgToEnum(integrity.rootSignature.alg)
        guard let rootSigData = Data(base64Encoded: integrity.rootSignature.sig) else {
            throw TDFCBORError.cborEncodingFailed("Invalid root signature base64")
        }

        let rootSigMap: [CBOR: CBOR] = [
            .unsignedInt(UInt64(TDFCBORRootSigKey.alg.rawValue)): .unsignedInt(rootAlgEnum),
            .unsignedInt(UInt64(TDFCBORRootSigKey.sig.rawValue)): .byteString(Array(rootSigData)),
        ]

        // Segment hash algorithm enum
        let segHashAlgEnum = try hashAlgToEnum(integrity.segmentHashAlg)

        let segmentsArray: [CBOR] = try integrity.segments.map { seg in
            guard let hashData = Data(base64Encoded: seg.hash) else {
                throw TDFCBORError.cborEncodingFailed("Invalid segment hash base64")
            }
            guard seg.segmentSize >= 0 else {
                throw TDFCBORError.cborEncodingFailed("Segment size must not be negative")
            }

            var segMap: [CBOR: CBOR] = [
                .unsignedInt(UInt64(TDFCBORSegmentKey.hash.rawValue)): .byteString(Array(hashData)),
                .unsignedInt(UInt64(TDFCBORSegmentKey.segmentSize.rawValue)): .unsignedInt(UInt64(seg.segmentSize)),
            ]

            if let size = seg.encryptedSegmentSize {
                guard size >= 0 else {
                    throw TDFCBORError.cborEncodingFailed("Encrypted segment size must not be negative")
                }
                segMap[.unsignedInt(UInt64(TDFCBORSegmentKey.encryptedSegmentSize.rawValue))] = .unsignedInt(UInt64(size))
            }

            return .map(segMap)
        }

        guard integrity.segmentSizeDefault >= 0 else {
            throw TDFCBORError.cborEncodingFailed("Segment size default must not be negative")
        }
        var integrityMap: [CBOR: CBOR] = [
            .unsignedInt(UInt64(TDFCBORIntegrityKey.rootSignature.rawValue)): .map(rootSigMap),
            .unsignedInt(UInt64(TDFCBORIntegrityKey.segmentHashAlg.rawValue)): .unsignedInt(segHashAlgEnum),
            .unsignedInt(UInt64(TDFCBORIntegrityKey.segments.rawValue)): .array(segmentsArray),
            .unsignedInt(UInt64(TDFCBORIntegrityKey.segmentSizeDefault.rawValue)): .unsignedInt(UInt64(integrity.segmentSizeDefault)),
        ]

        if let encSize = integrity.encryptedSegmentSizeDefault {
            guard encSize >= 0 else {
                throw TDFCBORError.cborEncodingFailed("Encrypted segment size default must not be negative")
            }
            integrityMap[.unsignedInt(UInt64(TDFCBORIntegrityKey.encryptedSegmentSizeDefault.rawValue))] = .unsignedInt(UInt64(encSize))
        }

        return .map(integrityMap)
    }

    /// Convert hash algorithm string to enum value
    private func hashAlgToEnum(_ alg: String) throws -> UInt64 {
        switch alg {
        case "HS256": TDFCBOREnums.hashAlgHS256
        case "HS384": TDFCBOREnums.hashAlgHS384
        case "HS512": TDFCBOREnums.hashAlgHS512
        case "GMAC": TDFCBOREnums.hashAlgGMAC
        case "SHA256": TDFCBOREnums.hashAlgSHA256
        case "ES256": TDFCBOREnums.hashAlgES256
        case "ES384": TDFCBOREnums.hashAlgES384
        case "ES512": TDFCBOREnums.hashAlgES512
        default:
            throw TDFCBORError.cborEncodingFailed("Unsupported hash algorithm: \(alg)")
        }
    }

    /// Convert enum value to hash algorithm string
    private static func enumToHashAlg(_ val: UInt64) throws -> String {
        switch val {
        case TDFCBOREnums.hashAlgHS256: "HS256"
        case TDFCBOREnums.hashAlgHS384: "HS384"
        case TDFCBOREnums.hashAlgHS512: "HS512"
        case TDFCBOREnums.hashAlgGMAC: "GMAC"
        case TDFCBOREnums.hashAlgSHA256: "SHA256"
        case TDFCBOREnums.hashAlgES256: "ES256"
        case TDFCBOREnums.hashAlgES384: "ES384"
        case TDFCBOREnums.hashAlgES512: "ES512"
        default:
            throw TDFCBORError.cborDecodingFailed("Unsupported hash algorithm enum: \(val)")
        }
    }

    /// Iterative structural pre-validator for raw CBOR bytes.
    /// Enforces bounded nesting depth, total item count, and declared byte/element lengths
    /// against remaining input bytes BEFORE handing off to SwiftCBOR (which otherwise uses
    /// unbounded recursion and allocates declared lengths eagerly in `readN`).
    private static func validateCBORStructure(
        _ bytes: [UInt8],
        maxDepth: Int = 32,
        maxItems: Int = 100_000,
    ) throws {
        enum Frame {
            case definite(remaining: Int)
            case indefiniteContainer
            case indefiniteString(major: UInt8)
        }

        var offset = 0
        var itemCount = 0
        var stack: [Frame] = [.definite(remaining: 1)]

        func readArgument(ai: UInt8) throws -> UInt64 {
            switch ai {
            case 0 ... 23:
                return UInt64(ai)
            case 24:
                guard offset < bytes.count else {
                    throw TDFCBORError.cborDecodingFailed("Unexpected end of CBOR input")
                }
                let val = UInt64(bytes[offset])
                offset += 1
                return val
            case 25:
                guard bytes.count - offset >= 2 else {
                    throw TDFCBORError.cborDecodingFailed("Unexpected end of CBOR input")
                }
                let val = (UInt64(bytes[offset]) << 8) | UInt64(bytes[offset + 1])
                offset += 2
                return val
            case 26:
                guard bytes.count - offset >= 4 else {
                    throw TDFCBORError.cborDecodingFailed("Unexpected end of CBOR input")
                }
                let val = (UInt64(bytes[offset]) << 24)
                    | (UInt64(bytes[offset + 1]) << 16)
                    | (UInt64(bytes[offset + 2]) << 8)
                    | UInt64(bytes[offset + 3])
                offset += 4
                return val
            case 27:
                guard bytes.count - offset >= 8 else {
                    throw TDFCBORError.cborDecodingFailed("Unexpected end of CBOR input")
                }
                var val: UInt64 = 0
                for i in 0 ..< 8 {
                    val = (val << 8) | UInt64(bytes[offset + i])
                }
                offset += 8
                return val
            default:
                throw TDFCBORError.cborDecodingFailed("Invalid CBOR additional info \(ai)")
            }
        }

        while let frame = stack.popLast() {
            guard offset < bytes.count else {
                throw TDFCBORError.cborDecodingFailed("Truncated CBOR input")
            }

            switch frame {
            case let .definite(remaining):
                if remaining > 1 {
                    stack.append(.definite(remaining: remaining - 1))
                }
            case .indefiniteContainer:
                if bytes[offset] == 0xFF {
                    offset += 1
                    continue
                }
                stack.append(.indefiniteContainer)
            case let .indefiniteString(expectedMajor):
                if bytes[offset] == 0xFF {
                    offset += 1
                    continue
                }
                let initial = bytes[offset]
                offset += 1
                let major = initial >> 5
                let ai = initial & 0x1F
                guard major == expectedMajor, ai != 31 else {
                    throw TDFCBORError.cborDecodingFailed("Invalid chunk inside indefinite-length CBOR string")
                }
                let chunkLen = try readArgument(ai: ai)
                guard chunkLen <= UInt64(bytes.count - offset) else {
                    throw TDFCBORError.cborDecodingFailed("CBOR string chunk length exceeds remaining input")
                }
                offset += Int(chunkLen)
                stack.append(.indefiniteString(major: expectedMajor))
                continue
            }

            itemCount += 1
            guard itemCount <= maxItems else {
                throw TDFCBORError.cborDecodingFailed("CBOR item count exceeds safety limit")
            }

            let initial = bytes[offset]
            offset += 1
            let major = initial >> 5
            let ai = initial & 0x1F

            switch major {
            case 0, 1:
                guard ai != 31 else {
                    throw TDFCBORError.cborDecodingFailed("Invalid indefinite length for integer")
                }
                _ = try readArgument(ai: ai)
            case 2, 3:
                if ai == 31 {
                    guard stack.count < maxDepth else {
                        throw TDFCBORError.cborDecodingFailed("CBOR nesting depth exceeds limit")
                    }
                    stack.append(.indefiniteString(major: major))
                } else {
                    let length = try readArgument(ai: ai)
                    guard length <= UInt64(bytes.count - offset) else {
                        throw TDFCBORError.cborDecodingFailed("CBOR string length \(length) exceeds remaining input")
                    }
                    offset += Int(length)
                }
            case 4:
                if ai == 31 {
                    guard stack.count < maxDepth else {
                        throw TDFCBORError.cborDecodingFailed("CBOR nesting depth exceeds limit")
                    }
                    stack.append(.indefiniteContainer)
                } else {
                    let count = try readArgument(ai: ai)
                    guard count <= UInt64(bytes.count - offset) else {
                        throw TDFCBORError.cborDecodingFailed("CBOR array length \(count) exceeds remaining input")
                    }
                    if count > 0 {
                        guard stack.count < maxDepth else {
                            throw TDFCBORError.cborDecodingFailed("CBOR nesting depth exceeds limit")
                        }
                        stack.append(.definite(remaining: Int(count)))
                    }
                }
            case 5:
                if ai == 31 {
                    guard stack.count < maxDepth else {
                        throw TDFCBORError.cborDecodingFailed("CBOR nesting depth exceeds limit")
                    }
                    stack.append(.indefiniteContainer)
                } else {
                    let pairs = try readArgument(ai: ai)
                    guard pairs <= UInt64((bytes.count - offset) / 2) else {
                        throw TDFCBORError.cborDecodingFailed("CBOR map length \(pairs) exceeds remaining input")
                    }
                    if pairs > 0 {
                        guard stack.count < maxDepth else {
                            throw TDFCBORError.cborDecodingFailed("CBOR nesting depth exceeds limit")
                        }
                        stack.append(.definite(remaining: Int(pairs) * 2))
                    }
                }
            case 6:
                guard ai != 31 else {
                    throw TDFCBORError.cborDecodingFailed("Invalid indefinite length for CBOR tag")
                }
                _ = try readArgument(ai: ai)
                guard stack.count < maxDepth else {
                    throw TDFCBORError.cborDecodingFailed("CBOR nesting depth exceeds limit")
                }
                stack.append(.definite(remaining: 1))
            case 7:
                guard ai != 31 else {
                    throw TDFCBORError.cborDecodingFailed("Unexpected CBOR break byte")
                }
                _ = try readArgument(ai: ai)
            default:
                throw TDFCBORError.cborDecodingFailed("Invalid CBOR major type \(major)")
            }
        }

        guard offset == bytes.count else {
            throw TDFCBORError.cborDecodingFailed("Trailing bytes after CBOR root object")
        }
    }

    /// Decode from CBOR bytes
    public static func fromCBORData(_ data: Data) throws -> TDFCBOREnvelope {
        // Verify magic bytes
        guard hasMagicBytes(data) else {
            throw TDFCBORError.invalidMagicBytes
        }

        // Skip self-describe tag, validate CBOR structure iteratively, then decode
        let cborBytes = Array(data.dropFirst(3))
        try validateCBORStructure(cborBytes)
        guard let decoded = try? CBOR.decode(cborBytes) else {
            throw TDFCBORError.cborDecodingFailed("Failed to decode CBOR")
        }

        guard case let .map(mainMap) = decoded else {
            throw TDFCBORError.cborDecodingFailed("Expected CBOR map at root")
        }

        // Extract tdf field
        guard let tdfValue = mainMap[CBOR.unsignedInt(UInt64(TDFCBORKey.tdf.rawValue))],
              case let .utf8String(tdf) = tdfValue
        else {
            throw TDFCBORError.missingField("tdf")
        }
        guard tdf == "cbor" else {
            throw TDFCBORError.invalidTdfIdentifier(tdf)
        }

        // Extract version
        guard let versionValue = mainMap[CBOR.unsignedInt(UInt64(TDFCBORKey.version.rawValue))],
              case let .array(versionArray) = versionValue
        else {
            throw TDFCBORError.missingField("version")
        }
        let version: [UInt8] = try versionArray.map { cbor in
            guard case let .unsignedInt(value) = cbor, let byte = UInt8(exactly: value) else {
                throw TDFCBORError.cborDecodingFailed("Version elements must be unsigned 8-bit integers")
            }
            return byte
        }

        // Extract created (optional)
        var created: UInt64?
        if let createdValue = mainMap[CBOR.unsignedInt(UInt64(TDFCBORKey.created.rawValue))],
           case let .unsignedInt(ts) = createdValue
        {
            created = ts
        }

        // Extract manifest - support both native CBOR map (new) and JSON string (legacy)
        guard let manifestValue = mainMap[CBOR.unsignedInt(UInt64(TDFCBORKey.manifest.rawValue))] else {
            throw TDFCBORError.missingField("manifest")
        }

        let manifest: TDFCBORManifest
        switch manifestValue {
        case let .map(manifestMap):
            // Native CBOR manifest with integer keys
            manifest = try decodeManifestFromCBOR(manifestMap)
        case let .utf8String(manifestJSON):
            // Legacy JSON string format
            guard let manifestData = manifestJSON.data(using: .utf8) else {
                throw TDFCBORError.cborDecodingFailed("Invalid manifest JSON encoding")
            }
            let manifestWrapper = try JSONDecoder().decode(ManifestWrapper.self, from: manifestData)
            manifest = manifestWrapper.toManifest()
        default:
            throw TDFCBORError.cborDecodingFailed("Expected manifest as map or string")
        }

        // Extract payload
        guard let payloadValue = mainMap[CBOR.unsignedInt(UInt64(TDFCBORKey.payload.rawValue))],
              case let .map(payloadMap) = payloadValue
        else {
            throw TDFCBORError.missingField("payload")
        }

        // Support both integer keys (new spec) and string keys (legacy), rejecting unknown/mistyped values
        let payloadType: String
        if let v = payloadMap[CBOR.unsignedInt(UInt64(TDFCBORPayloadKey.type.rawValue))] {
            switch v {
            case .unsignedInt(TDFCBOREnums.payloadTypeInline):
                payloadType = "inline"
            case .unsignedInt(TDFCBOREnums.payloadTypeReference):
                payloadType = "reference"
            case let .utf8String(s):
                payloadType = s
            default:
                throw TDFCBORError.cborDecodingFailed("Invalid payload type value")
            }
        } else if let v = payloadMap["type"] {
            guard case let .utf8String(s) = v else {
                throw TDFCBORError.cborDecodingFailed("Invalid payload type string")
            }
            payloadType = s
        } else {
            throw TDFCBORError.missingField("payload.type")
        }

        let payloadProtocol: String
        if let v = payloadMap[CBOR.unsignedInt(UInt64(TDFCBORPayloadKey.protocol.rawValue))] {
            switch v {
            case .unsignedInt(TDFCBOREnums.payloadProtocolBinary):
                payloadProtocol = "binary"
            case .unsignedInt(TDFCBOREnums.payloadProtocolBinaryChunked):
                payloadProtocol = "binary-chunked"
            case let .utf8String(s):
                payloadProtocol = s
            default:
                throw TDFCBORError.cborDecodingFailed("Invalid payload protocol value")
            }
        } else if let v = payloadMap["protocol"] {
            guard case let .utf8String(s) = v else {
                throw TDFCBORError.cborDecodingFailed("Invalid payload protocol string")
            }
            payloadProtocol = s
        } else {
            throw TDFCBORError.missingField("payload.protocol")
        }

        let payloadMimeType: String?
        if let v = payloadMap[CBOR.unsignedInt(UInt64(TDFCBORPayloadKey.mimeType.rawValue))] {
            guard case let .utf8String(s) = v else {
                throw TDFCBORError.cborDecodingFailed("Invalid payload mimeType")
            }
            payloadMimeType = s
        } else if let v = payloadMap["mimeType"] {
            guard case let .utf8String(s) = v else {
                throw TDFCBORError.cborDecodingFailed("Invalid payload mimeType")
            }
            payloadMimeType = s
        } else {
            payloadMimeType = nil
        }

        let payloadIsEncrypted: Bool
        if let v = payloadMap[CBOR.unsignedInt(UInt64(TDFCBORPayloadKey.isEncrypted.rawValue))] {
            guard case let .boolean(b) = v else {
                throw TDFCBORError.cborDecodingFailed("Invalid payload isEncrypted value")
            }
            payloadIsEncrypted = b
        } else if let v = payloadMap["isEncrypted"] {
            guard case let .boolean(b) = v else {
                throw TDFCBORError.cborDecodingFailed("Invalid payload isEncrypted value")
            }
            payloadIsEncrypted = b
        } else {
            throw TDFCBORError.missingField("payload.isEncrypted")
        }

        // Try integer key first (new spec), then string key (legacy)
        let bytes: [UInt8]
        if let valueField = payloadMap[CBOR.unsignedInt(UInt64(TDFCBORPayloadKey.value.rawValue))],
           case let .byteString(b) = valueField
        {
            bytes = b
        } else if let valueField = payloadMap["value"],
                  case let .byteString(b) = valueField
        {
            bytes = b
        } else {
            throw TDFCBORError.binaryPayloadExpected
        }

        // Validate optional payload length if present
        if let lenField = payloadMap[CBOR.unsignedInt(UInt64(TDFCBORPayloadKey.length.rawValue))] ?? payloadMap["length"] {
            guard case let .unsignedInt(declaredLen) = lenField,
                  declaredLen == UInt64(bytes.count)
            else {
                throw TDFCBORError.cborDecodingFailed("Payload length mismatch")
            }
        }

        let payload = TDFBinaryPayload(
            type: payloadType,
            protocol: payloadProtocol,
            mimeType: payloadMimeType,
            isEncrypted: payloadIsEncrypted,
            value: Data(bytes),
        )

        return TDFCBOREnvelope(
            tdf: tdf,
            version: version,
            created: created,
            manifest: manifest,
            payload: payload,
        )
    }

    /// Decode manifest from native CBOR map
    private static func decodeManifestFromCBOR(_ manifestMap: [CBOR: CBOR]) throws -> TDFCBORManifest {
        guard let encInfoValue = manifestMap[.unsignedInt(UInt64(TDFCBORManifestKey.encryptionInformation.rawValue))],
              case let .map(encInfoMap) = encInfoValue
        else {
            throw TDFCBORError.missingField("encryptionInformation")
        }

        let encInfo = try decodeEncryptionInfo(encInfoMap)

        // Decode assertions if present
        var assertions: [TDFAssertion]?
        if let assertionsValue = manifestMap[.unsignedInt(UInt64(TDFCBORManifestKey.assertions.rawValue))],
           case let .array(assertionsArray) = assertionsValue
        {
            assertions = try decodeAssertionsFromCBOR(assertionsArray)
        }

        return TDFCBORManifest(
            encryptionInformation: encInfo,
            assertions: assertions,
        )
    }

    /// Decode encryption information from CBOR
    private static func decodeEncryptionInfo(_ encMap: [CBOR: CBOR]) throws -> TDFEncryptionInformation {
        // Encryption type (required, strict enum)
        guard let typeValue = encMap[.unsignedInt(UInt64(TDFCBOREncInfoKey.type.rawValue))],
              case let .unsignedInt(typeEnum) = typeValue
        else {
            throw TDFCBORError.missingField("encryptionInformation.type")
        }
        let encType: TDFEncryptionInformation.KeyAccessType
        switch typeEnum {
        case TDFCBOREnums.encryptionTypeSplit: encType = .split
        case TDFCBOREnums.encryptionTypeRemote: encType = .remote
        default:
            throw TDFCBORError.cborDecodingFailed("Unsupported encryption type enum: \(typeEnum)")
        }

        // Key access (required array of maps)
        guard let kaValue = encMap[.unsignedInt(UInt64(TDFCBOREncInfoKey.keyAccess.rawValue))],
              case let .array(kaArray) = kaValue
        else {
            throw TDFCBORError.missingField("keyAccess")
        }
        var keyAccess: [TDFKeyAccessObject] = []
        keyAccess.reserveCapacity(kaArray.count)
        for kaItem in kaArray {
            guard case let .map(kaMap) = kaItem else {
                throw TDFCBORError.cborDecodingFailed("Expected CBOR map for keyAccess entry")
            }
            try keyAccess.append(decodeKeyAccess(kaMap))
        }

        // Method
        guard let methodValue = encMap[.unsignedInt(UInt64(TDFCBOREncInfoKey.method.rawValue))],
              case let .map(methodMap) = methodValue
        else {
            throw TDFCBORError.missingField("method")
        }
        let method = try decodeMethod(methodMap)

        // Integrity information
        guard let integrityValue = encMap[.unsignedInt(UInt64(TDFCBOREncInfoKey.integrityInformation.rawValue))],
              case let .map(integrityMap) = integrityValue
        else {
            throw TDFCBORError.missingField("integrityInformation")
        }
        let integrity = try decodeIntegrity(integrityMap)

        // Policy (required byteString)
        guard let policyValue = encMap[.unsignedInt(UInt64(TDFCBOREncInfoKey.policy.rawValue))],
              case let .byteString(policyBytes) = policyValue
        else {
            throw TDFCBORError.missingField("policy")
        }
        let policy = Data(policyBytes).base64EncodedString()

        return TDFEncryptionInformation(
            type: encType,
            keyAccess: keyAccess,
            method: method,
            integrityInformation: integrity,
            policy: policy,
        )
    }

    /// Decode key access from CBOR
    private static func decodeKeyAccess(_ kaMap: [CBOR: CBOR]) throws -> TDFKeyAccessObject {
        // Type (required, strict enum)
        guard let typeValue = kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.type.rawValue))],
              case let .unsignedInt(typeEnum) = typeValue
        else {
            throw TDFCBORError.missingField("keyAccess.type")
        }
        let accessType: TDFKeyAccessObject.AccessType
        switch typeEnum {
        case TDFCBOREnums.keyAccessTypeWrapped: accessType = .wrapped
        case TDFCBOREnums.keyAccessTypeRemote: accessType = .remote
        case TDFCBOREnums.keyAccessTypeRemoteWrapped: accessType = .remoteWrapped
        case TDFCBOREnums.keyAccessTypeEcWrapped: accessType = .ecWrapped
        default:
            throw TDFCBORError.cborDecodingFailed("Unsupported keyAccess type enum: \(typeEnum)")
        }

        // URL (required non-empty string)
        guard let urlValue = kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.url.rawValue))],
              case let .utf8String(url) = urlValue, !url.isEmpty
        else {
            throw TDFCBORError.missingField("keyAccess.url")
        }

        // Protocol (required, only kas == 0 is supported)
        if let protoValue = kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.protocol.rawValue))] {
            guard case .unsignedInt(TDFCBOREnums.keyProtocolKas) = protoValue else {
                throw TDFCBORError.cborDecodingFailed("Unsupported keyAccess protocol")
            }
        }

        // Wrapped key (required byteString)
        guard let wkValue = kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.wrappedKey.rawValue))],
              case let .byteString(wkBytes) = wkValue
        else {
            throw TDFCBORError.missingField("keyAccess.wrappedKey")
        }
        let wrappedKey = Data(wkBytes).base64EncodedString()

        // Policy binding
        guard let pbValue = kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.policyBinding.rawValue))],
              case let .map(pbMap) = pbValue
        else {
            throw TDFCBORError.missingField("policyBinding")
        }
        let policyBinding = try decodePolicyBinding(pbMap)

        // Optional fields (strict type checks)
        var encryptedMetadata: String?
        if let metaValue = kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.encryptedMetadata.rawValue))] {
            switch metaValue {
            case let .byteString(metaBytes):
                encryptedMetadata = Data(metaBytes).base64EncodedString()
            case let .utf8String(metaStr):
                encryptedMetadata = metaStr
            default:
                throw TDFCBORError.cborDecodingFailed("Invalid keyAccess.encryptedMetadata")
            }
        }

        var kid: String?
        if let kidValue = kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.kid.rawValue))] {
            guard case let .utf8String(kidStr) = kidValue else {
                throw TDFCBORError.cborDecodingFailed("Invalid keyAccess.kid")
            }
            kid = kidStr
        }

        var ephemeralPublicKey: String?
        if let epkValue = kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.ephemeralPublicKey.rawValue))] {
            switch epkValue {
            case let .byteString(epkBytes):
                ephemeralPublicKey = Data(epkBytes).base64EncodedString()
            case let .utf8String(epkStr):
                ephemeralPublicKey = epkStr
            default:
                throw TDFCBORError.cborDecodingFailed("Invalid keyAccess.ephemeralPublicKey")
            }
        }

        var schemaVersion: String?
        if let svValue = kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.schemaVersion.rawValue))] {
            guard case let .utf8String(svStr) = svValue else {
                throw TDFCBORError.cborDecodingFailed("Invalid keyAccess.schemaVersion")
            }
            schemaVersion = svStr
        }

        var sid: String?
        if let sidValue = kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.sid.rawValue))] {
            guard case let .utf8String(sidStr) = sidValue else {
                throw TDFCBORError.cborDecodingFailed("Invalid keyAccess.sid")
            }
            sid = sidStr
        }

        return TDFKeyAccessObject(
            type: accessType,
            url: url,
            protocolValue: .kas,
            wrappedKey: wrappedKey,
            policyBinding: policyBinding,
            encryptedMetadata: encryptedMetadata,
            kid: kid,
            sid: sid,
            schemaVersion: schemaVersion,
            ephemeralPublicKey: ephemeralPublicKey,
        )
    }

    /// Decode policy binding from CBOR
    private static func decodePolicyBinding(_ pbMap: [CBOR: CBOR]) throws -> TDFPolicyBinding {
        let alg: String
        if let algValue = pbMap[.unsignedInt(UInt64(TDFCBORPolicyBindingKey.alg.rawValue))] {
            guard case let .unsignedInt(algEnum) = algValue else {
                throw TDFCBORError.cborDecodingFailed("Invalid policyBinding.alg")
            }
            alg = try enumToHashAlg(algEnum)
        } else {
            alg = "HS256"
        }

        guard let hashValue = pbMap[.unsignedInt(UInt64(TDFCBORPolicyBindingKey.hash.rawValue))],
              case let .byteString(hashBytes) = hashValue
        else {
            throw TDFCBORError.missingField("policyBinding.hash")
        }
        let hash = Data(hashBytes).base64EncodedString()

        return TDFPolicyBinding(alg: alg, hash: hash)
    }

    /// Decode method from CBOR
    private static func decodeMethod(_ methodMap: [CBOR: CBOR]) throws -> TDFMethodDescriptor {
        guard let algValue = methodMap[.unsignedInt(UInt64(TDFCBORMethodKey.algorithm.rawValue))],
              case let .unsignedInt(algEnum) = algValue
        else {
            throw TDFCBORError.missingField("method.algorithm")
        }
        let algorithm: String = switch algEnum {
        case TDFCBOREnums.symmetricAlgAes256Gcm: "AES-256-GCM"
        case TDFCBOREnums.symmetricAlgAes128Gcm: "AES-128-GCM"
        case TDFCBOREnums.symmetricAlgAes256Cbc: "AES-256-CBC"
        case TDFCBOREnums.symmetricAlgAes128Cbc: "AES-128-CBC"
        default:
            throw TDFCBORError.cborDecodingFailed("Unsupported symmetric algorithm enum: \(algEnum)")
        }

        guard let ivValue = methodMap[.unsignedInt(UInt64(TDFCBORMethodKey.iv.rawValue))],
              case let .byteString(ivBytes) = ivValue
        else {
            throw TDFCBORError.missingField("method.iv")
        }
        let iv = Data(ivBytes).base64EncodedString()

        var isStreamable: Bool? = true
        if let streamValue = methodMap[.unsignedInt(UInt64(TDFCBORMethodKey.isStreamable.rawValue))] {
            guard case let .boolean(streamBool) = streamValue else {
                throw TDFCBORError.cborDecodingFailed("Invalid method.isStreamable")
            }
            isStreamable = streamBool
        }

        return TDFMethodDescriptor(algorithm: algorithm, iv: iv, isStreamable: isStreamable)
    }

    /// Decode integrity information from CBOR
    private static func decodeIntegrity(_ intMap: [CBOR: CBOR]) throws -> TDFIntegrityInformation {
        // Root signature
        guard let rootSigValue = intMap[.unsignedInt(UInt64(TDFCBORIntegrityKey.rootSignature.rawValue))],
              case let .map(rootSigMap) = rootSigValue
        else {
            throw TDFCBORError.missingField("rootSignature")
        }
        let rootSig = try decodeRootSignature(rootSigMap)

        // Segment hash algorithm
        guard let segAlgValue = intMap[.unsignedInt(UInt64(TDFCBORIntegrityKey.segmentHashAlg.rawValue))],
              case let .unsignedInt(segAlgEnum) = segAlgValue
        else {
            throw TDFCBORError.missingField("segmentHashAlg")
        }
        let segmentHashAlg = try enumToHashAlg(segAlgEnum)

        // Segments
        guard let segsValue = intMap[.unsignedInt(UInt64(TDFCBORIntegrityKey.segments.rawValue))],
              case let .array(segsArray) = segsValue
        else {
            throw TDFCBORError.missingField("segments")
        }
        var segments: [TDFSegment] = []
        segments.reserveCapacity(segsArray.count)
        for segItem in segsArray {
            guard case let .map(segMap) = segItem else {
                throw TDFCBORError.cborDecodingFailed("Expected CBOR map for segment")
            }
            try segments.append(decodeSegment(segMap))
        }

        guard let ssdValue = intMap[.unsignedInt(UInt64(TDFCBORIntegrityKey.segmentSizeDefault.rawValue))],
              case let .unsignedInt(ssd) = ssdValue,
              let segmentSizeDefault = Int64(exactly: ssd)
        else {
            throw TDFCBORError.cborDecodingFailed("Missing or invalid segmentSizeDefault")
        }

        var encryptedSegmentSizeDefault: Int64?
        if let essdValue = intMap[.unsignedInt(UInt64(TDFCBORIntegrityKey.encryptedSegmentSizeDefault.rawValue))] {
            guard case let .unsignedInt(essd) = essdValue,
                  let size = Int64(exactly: essd)
            else {
                throw TDFCBORError.cborDecodingFailed("Encrypted segment size default must be a valid Int64")
            }
            encryptedSegmentSizeDefault = size
        }

        return TDFIntegrityInformation(
            rootSignature: rootSig,
            segmentHashAlg: segmentHashAlg,
            segmentSizeDefault: segmentSizeDefault,
            encryptedSegmentSizeDefault: encryptedSegmentSizeDefault,
            segments: segments,
        )
    }

    /// Decode root signature from CBOR
    private static func decodeRootSignature(_ sigMap: [CBOR: CBOR]) throws -> TDFRootSignature {
        let alg: String
        if let algValue = sigMap[.unsignedInt(UInt64(TDFCBORRootSigKey.alg.rawValue))] {
            guard case let .unsignedInt(algEnum) = algValue else {
                throw TDFCBORError.cborDecodingFailed("Invalid rootSignature.alg")
            }
            alg = try enumToHashAlg(algEnum)
        } else {
            alg = "HS256"
        }

        guard let sigValue = sigMap[.unsignedInt(UInt64(TDFCBORRootSigKey.sig.rawValue))],
              case let .byteString(sigBytes) = sigValue
        else {
            throw TDFCBORError.missingField("rootSignature.sig")
        }
        let sig = Data(sigBytes).base64EncodedString()

        return TDFRootSignature(alg: alg, sig: sig)
    }

    /// Decode segment from CBOR
    private static func decodeSegment(_ segMap: [CBOR: CBOR]) throws -> TDFSegment {
        guard let hashValue = segMap[.unsignedInt(UInt64(TDFCBORSegmentKey.hash.rawValue))],
              case let .byteString(hashBytes) = hashValue
        else {
            throw TDFCBORError.missingField("segment.hash")
        }
        let hash = Data(hashBytes).base64EncodedString()

        guard let ssValue = segMap[.unsignedInt(UInt64(TDFCBORSegmentKey.segmentSize.rawValue))],
              case let .unsignedInt(ss) = ssValue,
              let segmentSize = Int64(exactly: ss)
        else {
            throw TDFCBORError.cborDecodingFailed("Missing or invalid segment.segmentSize")
        }

        var encryptedSegmentSize: Int64?
        if let essValue = segMap[.unsignedInt(UInt64(TDFCBORSegmentKey.encryptedSegmentSize.rawValue))] {
            guard case let .unsignedInt(ess) = essValue,
                  let size = Int64(exactly: ess)
            else {
                throw TDFCBORError.cborDecodingFailed("Encrypted segment size must be a valid Int64")
            }
            encryptedSegmentSize = size
        }

        return TDFSegment(hash: hash, segmentSize: segmentSize, encryptedSegmentSize: encryptedSegmentSize)
    }

    // MARK: - Assertions Encoding/Decoding

    /// Encode assertions to CBOR array using JSON as intermediate format
    private func encodeAssertionsToCBOR(_ assertions: [TDFAssertion]) throws -> [CBOR] {
        // Use JSON encoder to serialize assertions, then convert to CBOR byte strings
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]

        var cborArray: [CBOR] = []
        for assertion in assertions {
            let jsonData = try encoder.encode(assertion)
            cborArray.append(.byteString(Array(jsonData)))
        }
        return cborArray
    }

    /// Decode assertions from CBOR array using JSON as intermediate format
    private static func decodeAssertionsFromCBOR(_ cborArray: [CBOR]) throws -> [TDFAssertion] {
        let decoder = JSONDecoder()

        var assertions: [TDFAssertion] = []
        for item in cborArray {
            switch item {
            case let .byteString(bytes):
                let jsonData = Data(bytes)
                let assertion = try decoder.decode(TDFAssertion.self, from: jsonData)
                assertions.append(assertion)
            case let .utf8String(jsonString):
                // Support legacy string format
                guard let jsonData = jsonString.data(using: .utf8) else {
                    throw TDFCBORError.cborDecodingFailed("Invalid assertion JSON encoding")
                }
                let assertion = try decoder.decode(TDFAssertion.self, from: jsonData)
                assertions.append(assertion)
            default:
                throw TDFCBORError.cborDecodingFailed("Expected assertion as byte string or UTF-8 string")
            }
        }
        return assertions
    }
}

// MARK: - Helper Types

/// Wrapper for manifest encoding
private struct ManifestWrapper: Codable {
    let encryptionInformation: TDFEncryptionInformation
    let assertions: [TDFAssertion]?

    init(manifest: TDFCBORManifest) {
        encryptionInformation = manifest.encryptionInformation
        assertions = manifest.assertions
    }

    func toManifest() -> TDFCBORManifest {
        TDFCBORManifest(
            encryptionInformation: encryptionInformation,
            assertions: assertions,
        )
    }
}
