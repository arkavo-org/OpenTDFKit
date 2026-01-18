import Foundation

// MARK: - TDF-JSON Envelope (per TDF-JSON specification draft-00)

/// TDF-JSON envelope for inline payload transmission.
///
/// This structure represents a complete TDF-JSON package per the TDF-JSON
/// specification draft-00. The format is optimized for JSON-RPC protocols,
/// REST APIs, and streaming scenarios.
///
/// ## Structure
/// ```json
/// {
///   "tdf": "json",
///   "version": "1.0.0",
///   "created": "2026-01-17T12:00:00Z",
///   "manifest": { ... },
///   "payload": { ... }
/// }
/// ```
public struct TDFJSONEnvelope: Codable, Sendable {
    /// Format identifier. MUST be "json" for TDF-JSON documents.
    public let tdf: String

    /// Semantic version of the TDF-JSON specification (e.g., "1.0.0")
    public let version: String

    /// ISO 8601 timestamp of document creation (optional)
    public var created: String?

    /// TDF manifest containing encryption and policy information
    public let manifest: TDFJSONManifest

    /// Inline encrypted payload container
    public let payload: TDFInlinePayload

    public init(
        tdf: String = "json",
        version: String = "1.0.0",
        created: String? = nil,
        manifest: TDFJSONManifest,
        payload: TDFInlinePayload
    ) {
        self.tdf = tdf
        self.version = version
        self.created = created
        self.manifest = manifest
        self.payload = payload
    }

    /// Format identifier (always "json")
    public var formatId: String { tdf }
}

// MARK: - TDF-JSON Manifest

/// TDF manifest for TDF-JSON format.
///
/// Contains encryption information and optional assertions, but NOT the payload
/// (which is at the top level in TDF-JSON per the specification).
public struct TDFJSONManifest: Codable, Sendable {
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

// MARK: - TDF-JSON Payload

/// JSON payload for TDF-JSON transport.
///
/// Contains the encrypted data inline as a base64-encoded string.
/// Per the TDF-JSON spec, the payload is at the top level (not nested in manifest).
public struct TDFInlinePayload: Codable, Sendable {
    /// Payload type. MUST be "inline" for TDF-JSON
    public let type: String

    /// Encoding protocol. MUST be "base64" for TDF-JSON
    public let `protocol`: String

    /// MIME type of the original (unencrypted) data
    public var mimeType: String?

    /// Whether the payload is encrypted. MUST be true
    public let isEncrypted: Bool

    /// Length of ciphertext in bytes (before base64)
    public var length: UInt64?

    /// Base64-encoded ciphertext
    public let value: String

    public init(
        type: String = "inline",
        protocol: String = "base64",
        mimeType: String? = nil,
        isEncrypted: Bool = true,
        length: UInt64? = nil,
        value: String
    ) {
        self.type = type
        self.protocol = `protocol`
        self.mimeType = mimeType
        self.isEncrypted = isEncrypted
        self.length = length
        self.value = value
    }
}

// MARK: - TDF-JSON Error Types

/// Errors specific to TDF-JSON parsing and validation.
public enum TDFJSONError: Error, CustomStringConvertible, Sendable {
    case missingTdfField
    case invalidTdfIdentifier(String)
    case unsupportedVersion(String)
    case payloadDecodeError(String)
    case manifestParsingFailed(String)
    case encryptionFailed(String)
    case decryptionFailed(String)

    public var description: String {
        switch self {
        case .missingTdfField:
            return "Missing 'tdf' field in envelope"
        case let .invalidTdfIdentifier(id):
            return "Invalid tdf identifier: expected 'json', got '\(id)'"
        case let .unsupportedVersion(v):
            return "Unsupported version: \(v)"
        case let .payloadDecodeError(e):
            return "Payload decode error: \(e)"
        case let .manifestParsingFailed(e):
            return "Manifest parsing failed: \(e)"
        case let .encryptionFailed(e):
            return "Encryption failed: \(e)"
        case let .decryptionFailed(e):
            return "Decryption failed: \(e)"
        }
    }
}

// MARK: - TDF-JSON Extensions

extension TDFJSONEnvelope {
    /// Parse a TDF-JSON envelope from JSON data
    public static func parse(from data: Data) throws -> TDFJSONEnvelope {
        let decoder = JSONDecoder()
        let envelope = try decoder.decode(TDFJSONEnvelope.self, from: data)

        // Validate tdf field
        guard envelope.tdf == "json" else {
            throw TDFJSONError.invalidTdfIdentifier(envelope.tdf)
        }

        return envelope
    }

    /// Parse a TDF-JSON envelope from a JSON string
    public static func parse(from jsonString: String) throws -> TDFJSONEnvelope {
        guard let data = jsonString.data(using: .utf8) else {
            throw TDFJSONError.payloadDecodeError("Invalid UTF-8 string")
        }
        return try parse(from: data)
    }

    /// Serialize to JSON data
    public func toJSONData(prettyPrinted: Bool = false) throws -> Data {
        let encoder = JSONEncoder()
        if prettyPrinted {
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        } else {
            encoder.outputFormatting = [.sortedKeys]
        }
        return try encoder.encode(self)
    }

    /// Serialize to JSON string
    public func toJSONString(prettyPrinted: Bool = false) throws -> String {
        let data = try toJSONData(prettyPrinted: prettyPrinted)
        guard let string = String(data: data, encoding: .utf8) else {
            throw TDFJSONError.payloadDecodeError("Failed to encode as UTF-8")
        }
        return string
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

    /// Decode the base64 payload value to raw bytes
    public func decodePayloadValue() throws -> Data {
        guard let data = Data(base64Encoded: payload.value) else {
            throw TDFJSONError.payloadDecodeError("Invalid base64 encoding")
        }
        return data
    }
}

// MARK: - Conversion from Standard Manifest

extension TDFJSONManifest {
    /// Create a TDF-JSON manifest from a standard TDF manifest
    public init(from manifest: TDFManifest) {
        self.encryptionInformation = manifest.encryptionInformation
        self.assertions = manifest.assertions
    }
}
