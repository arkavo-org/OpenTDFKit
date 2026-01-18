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
        // Encode manifest as JSON string
        let manifestEncoder = JSONEncoder()
        manifestEncoder.outputFormatting = [.sortedKeys]
        let manifestData = try manifestEncoder.encode(ManifestWrapper(manifest: manifest))
        guard let manifestJSON = String(data: manifestData, encoding: .utf8) else {
            throw TDFCBORError.cborEncodingFailed("Failed to encode manifest as JSON")
        }

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
            CBOR.unsignedInt(UInt64(TDFCBORKey.manifest.rawValue)): .utf8String(manifestJSON),
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

        // Extract manifest (JSON string)
        guard let manifestValue = mainMap[CBOR.unsignedInt(UInt64(TDFCBORKey.manifest.rawValue))],
              case let .utf8String(manifestJSON) = manifestValue,
              let manifestData = manifestJSON.data(using: .utf8)
        else {
            throw TDFCBORError.missingField("manifest")
        }
        let manifestWrapper = try JSONDecoder().decode(ManifestWrapper.self, from: manifestData)
        let manifest = manifestWrapper.toManifest()

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
