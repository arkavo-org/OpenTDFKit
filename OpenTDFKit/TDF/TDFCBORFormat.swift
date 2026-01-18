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

    public var intValue: Int? { rawValue }
    public var stringValue: String { String(rawValue) }

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

    // Encryption type: 0=split
    public static let encryptionTypeSplit: UInt64 = 0

    // Key access type: 0=wrapped, 1=remote
    public static let keyAccessTypeWrapped: UInt64 = 0
    public static let keyAccessTypeRemote: UInt64 = 1

    // Key protocol: 0=kas
    public static let keyProtocolKas: UInt64 = 0

    // Symmetric algorithm: 0=AES-256-GCM
    public static let symmetricAlgAes256Gcm: UInt64 = 0

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
        payload: TDFBinaryPayload
    ) {
        self.tdf = tdf
        self.version = version
        self.created = created
        self.manifest = manifest
        self.payload = payload
    }

    /// Format identifier (always "cbor")
    public var formatId: String { tdf }
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
        assertions: [TDFAssertion]? = nil
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
        value: Data
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
            return "Invalid or missing CBOR magic bytes"
        case let .invalidTdfIdentifier(id):
            return "Invalid tdf identifier: expected 'cbor', got '\(id)'"
        case let .unexpectedKey(expected, got):
            return "Expected integer key \(expected), got \(got)"
        case let .cborDecodingFailed(e):
            return "CBOR decoding failed: \(e)"
        case let .cborEncodingFailed(e):
            return "CBOR encoding failed: \(e)"
        case .binaryPayloadExpected:
            return "Binary payload expected but got base64"
        case let .missingField(field):
            return "Missing required field: \(field)"
        case let .encryptionFailed(e):
            return "Encryption failed: \(e)"
        case let .decryptionFailed(e):
            return "Decryption failed: \(e)"
        }
    }
}

// MARK: - TDF-CBOR Extensions

extension TDFCBOREnvelope {
    /// Check if data starts with CBOR self-describe tag
    public static func hasMagicBytes(_ data: Data) -> Bool {
        guard data.count >= 3 else { return false }
        return data[0] == 0xD9 && data[1] == 0xD9 && data[2] == 0xF7
    }

    /// Convert to standard TDF manifest format (for KAS integration)
    public func toStandardManifest() -> TDFManifest {
        TDFManifest(
            schemaVersion: "1.0.0",
            payload: TDFPayloadDescriptor(
                type: .reference,
                url: "inline",
                protocolValue: .zip,
                isEncrypted: true,
                mimeType: payload.mimeType
            ),
            encryptionInformation: manifest.encryptionInformation,
            assertions: manifest.assertions
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

        if let created = created {
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

        // Encryption type enum: "split" -> 0
        let encTypeEnum: UInt64 = encInfo.type == .split ? TDFCBOREnums.encryptionTypeSplit : TDFCBOREnums.encryptionTypeSplit

        // Build encryptionInformation map
        let encInfoMap: [CBOR: CBOR] = [
            .unsignedInt(UInt64(TDFCBOREncInfoKey.type.rawValue)): .unsignedInt(encTypeEnum),
            .unsignedInt(UInt64(TDFCBOREncInfoKey.keyAccess.rawValue)): .array(keyAccessArray),
            .unsignedInt(UInt64(TDFCBOREncInfoKey.method.rawValue)): methodCBOR,
            .unsignedInt(UInt64(TDFCBOREncInfoKey.integrityInformation.rawValue)): integrityCBOR,
            .unsignedInt(UInt64(TDFCBOREncInfoKey.policy.rawValue)): .byteString(Array(policyData)),
        ]

        // Build manifest map
        let manifestMap: [CBOR: CBOR] = [
            .unsignedInt(UInt64(TDFCBORManifestKey.encryptionInformation.rawValue)): .map(encInfoMap),
        ]

        return .map(manifestMap)
    }

    /// Encode a single key access object to CBOR
    private func encodeKeyAccessToCBOR(_ ka: TDFKeyAccessObject) throws -> CBOR {
        // Key access type enum
        let kaTypeEnum: UInt64 = ka.type == .wrapped ? TDFCBOREnums.keyAccessTypeWrapped : TDFCBOREnums.keyAccessTypeRemote

        // Protocol enum: "kas" -> 0
        let protocolEnum: UInt64 = ka.protocolValue.rawValue == "kas" ? TDFCBOREnums.keyProtocolKas : TDFCBOREnums.keyProtocolKas

        // Decode wrapped key from base64 to raw bytes
        guard let wrappedKeyData = Data(base64Encoded: ka.wrappedKey) else {
            throw TDFCBORError.cborEncodingFailed("Invalid wrappedKey base64")
        }

        // Encode policy binding
        let bindingAlgEnum = hashAlgToEnum(ka.policyBinding.alg)
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

        // Add optional fields
        if let kid = ka.kid {
            kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.kid.rawValue))] = .utf8String(kid)
        }

        if let epk = ka.ephemeralPublicKey, let epkData = Data(base64Encoded: epk) {
            kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.ephemeralPublicKey.rawValue))] = .byteString(Array(epkData))
        }

        if let sv = ka.schemaVersion {
            kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.schemaVersion.rawValue))] = .utf8String(sv)
        }

        return .map(kaMap)
    }

    /// Encode method to CBOR
    private func encodeMethodToCBOR(_ method: TDFMethodDescriptor) throws -> CBOR {
        // Algorithm enum: "AES-256-GCM" -> 0
        let algEnum: UInt64 = method.algorithm == "AES-256-GCM" ? TDFCBOREnums.symmetricAlgAes256Gcm : TDFCBOREnums.symmetricAlgAes256Gcm

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
        let rootAlgEnum = hashAlgToEnum(integrity.rootSignature.alg)
        guard let rootSigData = Data(base64Encoded: integrity.rootSignature.sig) else {
            throw TDFCBORError.cborEncodingFailed("Invalid root signature base64")
        }

        let rootSigMap: [CBOR: CBOR] = [
            .unsignedInt(UInt64(TDFCBORRootSigKey.alg.rawValue)): .unsignedInt(rootAlgEnum),
            .unsignedInt(UInt64(TDFCBORRootSigKey.sig.rawValue)): .byteString(Array(rootSigData)),
        ]

        // Segment hash algorithm enum
        let segHashAlgEnum = hashAlgToEnum(integrity.segmentHashAlg)

        // Encode segments
        let segmentsArray: [CBOR] = try integrity.segments.map { seg in
            guard let hashData = Data(base64Encoded: seg.hash) else {
                throw TDFCBORError.cborEncodingFailed("Invalid segment hash base64")
            }

            var segMap: [CBOR: CBOR] = [
                .unsignedInt(UInt64(TDFCBORSegmentKey.hash.rawValue)): .byteString(Array(hashData)),
                .unsignedInt(UInt64(TDFCBORSegmentKey.segmentSize.rawValue)): .unsignedInt(UInt64(seg.segmentSize)),
            ]

            if let size = seg.encryptedSegmentSize {
                segMap[.unsignedInt(UInt64(TDFCBORSegmentKey.encryptedSegmentSize.rawValue))] = .unsignedInt(UInt64(size))
            }

            return .map(segMap)
        }

        var integrityMap: [CBOR: CBOR] = [
            .unsignedInt(UInt64(TDFCBORIntegrityKey.rootSignature.rawValue)): .map(rootSigMap),
            .unsignedInt(UInt64(TDFCBORIntegrityKey.segmentHashAlg.rawValue)): .unsignedInt(segHashAlgEnum),
            .unsignedInt(UInt64(TDFCBORIntegrityKey.segments.rawValue)): .array(segmentsArray),
            .unsignedInt(UInt64(TDFCBORIntegrityKey.segmentSizeDefault.rawValue)): .unsignedInt(UInt64(integrity.segmentSizeDefault)),
        ]

        // Add optional encryptedSegmentSizeDefault if present
        if let encSize = integrity.encryptedSegmentSizeDefault {
            integrityMap[.unsignedInt(UInt64(TDFCBORIntegrityKey.encryptedSegmentSizeDefault.rawValue))] = .unsignedInt(UInt64(encSize))
        }

        return .map(integrityMap)
    }

    /// Convert hash algorithm string to enum value
    private func hashAlgToEnum(_ alg: String) -> UInt64 {
        switch alg {
        case "HS256": return TDFCBOREnums.hashAlgHS256
        case "HS384": return TDFCBOREnums.hashAlgHS384
        case "HS512": return TDFCBOREnums.hashAlgHS512
        case "GMAC": return TDFCBOREnums.hashAlgGMAC
        case "SHA256": return TDFCBOREnums.hashAlgSHA256
        case "ES256": return TDFCBOREnums.hashAlgES256
        case "ES384": return TDFCBOREnums.hashAlgES384
        case "ES512": return TDFCBOREnums.hashAlgES512
        default: return TDFCBOREnums.hashAlgHS256
        }
    }

    /// Convert enum value to hash algorithm string
    private static func enumToHashAlg(_ val: UInt64) -> String {
        switch val {
        case TDFCBOREnums.hashAlgHS256: return "HS256"
        case TDFCBOREnums.hashAlgHS384: return "HS384"
        case TDFCBOREnums.hashAlgHS512: return "HS512"
        case TDFCBOREnums.hashAlgGMAC: return "GMAC"
        case TDFCBOREnums.hashAlgSHA256: return "SHA256"
        case TDFCBOREnums.hashAlgES256: return "ES256"
        case TDFCBOREnums.hashAlgES384: return "ES384"
        case TDFCBOREnums.hashAlgES512: return "ES512"
        default: return "HS256"
        }
    }

    /// Decode from CBOR bytes
    public static func fromCBORData(_ data: Data) throws -> TDFCBOREnvelope {
        // Verify magic bytes
        guard hasMagicBytes(data) else {
            throw TDFCBORError.invalidMagicBytes
        }

        // Skip self-describe tag and decode
        let cborBytes = Array(data.dropFirst(3))
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
        let version: [UInt8] = versionArray.compactMap { cbor -> UInt8? in
            if case let .unsignedInt(v) = cbor { return UInt8(v) }
            return nil
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

        // Support both integer keys (new spec) and string keys (legacy)
        let payloadType: String = {
            // Try integer key first (new spec)
            if let v = payloadMap[CBOR.unsignedInt(UInt64(TDFCBORPayloadKey.type.rawValue))] {
                // Support both integer enum (new) and string (legacy)
                switch v {
                case let .unsignedInt(i):
                    return i == TDFCBOREnums.payloadTypeInline ? "inline" : "reference"
                case let .utf8String(s):
                    return s
                default:
                    break
                }
            }
            // Fall back to string key (legacy)
            if let v = payloadMap["type"], case let .utf8String(s) = v { return s }
            return "inline"
        }()

        let payloadProtocol: String = {
            // Try integer key first (new spec)
            if let v = payloadMap[CBOR.unsignedInt(UInt64(TDFCBORPayloadKey.protocol.rawValue))] {
                // Support both integer enum (new) and string (legacy)
                switch v {
                case let .unsignedInt(i):
                    return i == TDFCBOREnums.payloadProtocolBinary ? "binary" : "binary-chunked"
                case let .utf8String(s):
                    return s
                default:
                    break
                }
            }
            // Fall back to string key (legacy)
            if let v = payloadMap["protocol"], case let .utf8String(s) = v { return s }
            return "binary"
        }()

        let payloadMimeType: String? = {
            // Try integer key first (new spec)
            if let v = payloadMap[CBOR.unsignedInt(UInt64(TDFCBORPayloadKey.mimeType.rawValue))],
               case let .utf8String(s) = v
            {
                return s
            }
            // Fall back to string key (legacy)
            if let v = payloadMap["mimeType"], case let .utf8String(s) = v { return s }
            return nil
        }()

        let payloadIsEncrypted: Bool = {
            // Try integer key first (new spec)
            if let v = payloadMap[CBOR.unsignedInt(UInt64(TDFCBORPayloadKey.isEncrypted.rawValue))],
               case let .boolean(b) = v
            {
                return b
            }
            // Fall back to string key (legacy)
            if let v = payloadMap["isEncrypted"], case let .boolean(b) = v { return b }
            return true
        }()

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

        let payload = TDFBinaryPayload(
            type: payloadType,
            protocol: payloadProtocol,
            mimeType: payloadMimeType,
            isEncrypted: payloadIsEncrypted,
            value: Data(bytes)
        )

        return TDFCBOREnvelope(
            tdf: tdf,
            version: version,
            created: created,
            manifest: manifest,
            payload: payload
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

        return TDFCBORManifest(
            encryptionInformation: encInfo,
            assertions: nil // TODO: decode assertions if present
        )
    }

    /// Decode encryption information from CBOR
    private static func decodeEncryptionInfo(_ encMap: [CBOR: CBOR]) throws -> TDFEncryptionInformation {
        // Encryption type
        var encType: TDFEncryptionInformation.KeyAccessType = .split
        if let typeValue = encMap[.unsignedInt(UInt64(TDFCBOREncInfoKey.type.rawValue))],
           case let .unsignedInt(typeEnum) = typeValue
        {
            encType = typeEnum == TDFCBOREnums.encryptionTypeSplit ? .split : .remote
        }

        // Key access
        var keyAccess: [TDFKeyAccessObject] = []
        if let kaValue = encMap[.unsignedInt(UInt64(TDFCBOREncInfoKey.keyAccess.rawValue))],
           case let .array(kaArray) = kaValue
        {
            for kaItem in kaArray {
                if case let .map(kaMap) = kaItem {
                    keyAccess.append(try decodeKeyAccess(kaMap))
                }
            }
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

        // Policy
        var policy = ""
        if let policyValue = encMap[.unsignedInt(UInt64(TDFCBOREncInfoKey.policy.rawValue))],
           case let .byteString(policyBytes) = policyValue
        {
            policy = Data(policyBytes).base64EncodedString()
        }

        return TDFEncryptionInformation(
            type: encType,
            keyAccess: keyAccess,
            method: method,
            integrityInformation: integrity,
            policy: policy
        )
    }

    /// Decode key access from CBOR
    private static func decodeKeyAccess(_ kaMap: [CBOR: CBOR]) throws -> TDFKeyAccessObject {
        // Type
        var accessType: TDFKeyAccessObject.AccessType = .wrapped
        if let typeValue = kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.type.rawValue))],
           case let .unsignedInt(typeEnum) = typeValue
        {
            accessType = typeEnum == TDFCBOREnums.keyAccessTypeWrapped ? .wrapped : .remote
        }

        // URL
        var url = ""
        if let urlValue = kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.url.rawValue))],
           case let .utf8String(urlStr) = urlValue
        {
            url = urlStr
        }

        // Protocol
        var protocolStr = "kas"
        if let protocolValue = kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.protocol.rawValue))],
           case let .unsignedInt(protocolEnum) = protocolValue
        {
            protocolStr = protocolEnum == TDFCBOREnums.keyProtocolKas ? "kas" : "kas"
        }

        // Wrapped key
        var wrappedKey = ""
        if let wkValue = kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.wrappedKey.rawValue))],
           case let .byteString(wkBytes) = wkValue
        {
            wrappedKey = Data(wkBytes).base64EncodedString()
        }

        // Policy binding
        guard let pbValue = kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.policyBinding.rawValue))],
              case let .map(pbMap) = pbValue
        else {
            throw TDFCBORError.missingField("policyBinding")
        }
        let policyBinding = try decodePolicyBinding(pbMap)

        // Optional fields
        var kid: String?
        if let kidValue = kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.kid.rawValue))],
           case let .utf8String(kidStr) = kidValue
        {
            kid = kidStr
        }

        var ephemeralPublicKey: String?
        if let epkValue = kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.ephemeralPublicKey.rawValue))],
           case let .byteString(epkBytes) = epkValue
        {
            ephemeralPublicKey = Data(epkBytes).base64EncodedString()
        }

        var schemaVersion: String?
        if let svValue = kaMap[.unsignedInt(UInt64(TDFCBORKeyAccessKey.schemaVersion.rawValue))],
           case let .utf8String(svStr) = svValue
        {
            schemaVersion = svStr
        }

        return TDFKeyAccessObject(
            type: accessType,
            url: url,
            protocolValue: TDFKeyAccessObject.AccessProtocol(rawValue: protocolStr) ?? .kas,
            wrappedKey: wrappedKey,
            policyBinding: policyBinding,
            encryptedMetadata: nil,
            kid: kid,
            sid: nil,
            schemaVersion: schemaVersion,
            ephemeralPublicKey: ephemeralPublicKey
        )
    }

    /// Decode policy binding from CBOR
    private static func decodePolicyBinding(_ pbMap: [CBOR: CBOR]) throws -> TDFPolicyBinding {
        var alg = "HS256"
        if let algValue = pbMap[.unsignedInt(UInt64(TDFCBORPolicyBindingKey.alg.rawValue))],
           case let .unsignedInt(algEnum) = algValue
        {
            alg = enumToHashAlg(algEnum)
        }

        var hash = ""
        if let hashValue = pbMap[.unsignedInt(UInt64(TDFCBORPolicyBindingKey.hash.rawValue))],
           case let .byteString(hashBytes) = hashValue
        {
            hash = Data(hashBytes).base64EncodedString()
        }

        return TDFPolicyBinding(alg: alg, hash: hash)
    }

    /// Decode method from CBOR
    private static func decodeMethod(_ methodMap: [CBOR: CBOR]) throws -> TDFMethodDescriptor {
        var algorithm = "AES-256-GCM"
        if let algValue = methodMap[.unsignedInt(UInt64(TDFCBORMethodKey.algorithm.rawValue))],
           case let .unsignedInt(algEnum) = algValue
        {
            algorithm = algEnum == TDFCBOREnums.symmetricAlgAes256Gcm ? "AES-256-GCM" : "AES-256-GCM"
        }

        var iv = ""
        if let ivValue = methodMap[.unsignedInt(UInt64(TDFCBORMethodKey.iv.rawValue))],
           case let .byteString(ivBytes) = ivValue
        {
            iv = Data(ivBytes).base64EncodedString()
        }

        var isStreamable: Bool? = true
        if let streamValue = methodMap[.unsignedInt(UInt64(TDFCBORMethodKey.isStreamable.rawValue))],
           case let .boolean(streamBool) = streamValue
        {
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
        var segmentHashAlg = "GMAC"
        if let segAlgValue = intMap[.unsignedInt(UInt64(TDFCBORIntegrityKey.segmentHashAlg.rawValue))],
           case let .unsignedInt(segAlgEnum) = segAlgValue
        {
            segmentHashAlg = enumToHashAlg(segAlgEnum)
        }

        // Segments
        var segments: [TDFSegment] = []
        if let segsValue = intMap[.unsignedInt(UInt64(TDFCBORIntegrityKey.segments.rawValue))],
           case let .array(segsArray) = segsValue
        {
            for segItem in segsArray {
                if case let .map(segMap) = segItem {
                    segments.append(try decodeSegment(segMap))
                }
            }
        }

        // Segment size defaults
        var segmentSizeDefault: Int = 0
        if let ssdValue = intMap[.unsignedInt(UInt64(TDFCBORIntegrityKey.segmentSizeDefault.rawValue))],
           case let .unsignedInt(ssd) = ssdValue
        {
            segmentSizeDefault = Int(ssd)
        }

        var encryptedSegmentSizeDefault: Int = 0
        if let essdValue = intMap[.unsignedInt(UInt64(TDFCBORIntegrityKey.encryptedSegmentSizeDefault.rawValue))],
           case let .unsignedInt(essd) = essdValue
        {
            encryptedSegmentSizeDefault = Int(essd)
        }

        return TDFIntegrityInformation(
            rootSignature: rootSig,
            segmentHashAlg: segmentHashAlg,
            segmentSizeDefault: Int64(segmentSizeDefault),
            encryptedSegmentSizeDefault: Int64(encryptedSegmentSizeDefault),
            segments: segments
        )
    }

    /// Decode root signature from CBOR
    private static func decodeRootSignature(_ sigMap: [CBOR: CBOR]) throws -> TDFRootSignature {
        var alg = "HS256"
        if let algValue = sigMap[.unsignedInt(UInt64(TDFCBORRootSigKey.alg.rawValue))],
           case let .unsignedInt(algEnum) = algValue
        {
            alg = enumToHashAlg(algEnum)
        }

        var sig = ""
        if let sigValue = sigMap[.unsignedInt(UInt64(TDFCBORRootSigKey.sig.rawValue))],
           case let .byteString(sigBytes) = sigValue
        {
            sig = Data(sigBytes).base64EncodedString()
        }

        return TDFRootSignature(alg: alg, sig: sig)
    }

    /// Decode segment from CBOR
    private static func decodeSegment(_ segMap: [CBOR: CBOR]) throws -> TDFSegment {
        var hash = ""
        if let hashValue = segMap[.unsignedInt(UInt64(TDFCBORSegmentKey.hash.rawValue))],
           case let .byteString(hashBytes) = hashValue
        {
            hash = Data(hashBytes).base64EncodedString()
        }

        var segmentSize: Int64 = 0
        if let ssValue = segMap[.unsignedInt(UInt64(TDFCBORSegmentKey.segmentSize.rawValue))],
           case let .unsignedInt(ss) = ssValue
        {
            segmentSize = Int64(ss)
        }

        var encryptedSegmentSize: Int64?
        if let essValue = segMap[.unsignedInt(UInt64(TDFCBORSegmentKey.encryptedSegmentSize.rawValue))],
           case let .unsignedInt(ess) = essValue
        {
            encryptedSegmentSize = Int64(ess)
        }

        return TDFSegment(hash: hash, segmentSize: segmentSize, encryptedSegmentSize: encryptedSegmentSize)
    }
}

// MARK: - Helper Types

/// Wrapper for manifest encoding
private struct ManifestWrapper: Codable {
    let encryptionInformation: TDFEncryptionInformation
    let assertions: [TDFAssertion]?

    init(manifest: TDFCBORManifest) {
        self.encryptionInformation = manifest.encryptionInformation
        self.assertions = manifest.assertions
    }

    func toManifest() -> TDFCBORManifest {
        TDFCBORManifest(
            encryptionInformation: encryptionInformation,
            assertions: assertions
        )
    }
}
