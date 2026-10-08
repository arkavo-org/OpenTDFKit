import Foundation

/// Trusted Data Format manifest representation aligned with OpenTDF schema.
public struct TDFManifest: Codable, Sendable {
    /// Root version key every SDK writes. Optional on decode so peer manifests
    /// carrying only `tdf_spec_version` still load.
    public var schemaVersion: String?
    public var payload: TDFPayloadDescriptor
    public var encryptionInformation: TDFEncryptionInformation
    public var assertions: [TDFAssertion]?
    /// Spec prose places `tdf_spec_version` at the root. Decode-only; never encoded.
    public var tdfSpecVersion: String?

    enum CodingKeys: String, CodingKey {
        case schemaVersion
        case payload
        case encryptionInformation
        case assertions
        case tdfSpecVersion = "tdf_spec_version"
    }

    public init(
        schemaVersion: String,
        payload: TDFPayloadDescriptor,
        encryptionInformation: TDFEncryptionInformation,
        assertions: [TDFAssertion]? = nil,
    ) {
        self.schemaVersion = schemaVersion
        self.payload = payload
        self.encryptionInformation = encryptionInformation
        self.assertions = assertions
        tdfSpecVersion = nil
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try c.decodeIfPresent(String.self, forKey: .schemaVersion)
        payload = try c.decode(TDFPayloadDescriptor.self, forKey: .payload)
        encryptionInformation = try c.decode(TDFEncryptionInformation.self, forKey: .encryptionInformation)
        assertions = try c.decodeIfPresent([TDFAssertion].self, forKey: .assertions)
        tdfSpecVersion = try c.decodeIfPresent(String.self, forKey: .tdfSpecVersion)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeIfPresent(schemaVersion, forKey: .schemaVersion)
        try c.encode(payload, forKey: .payload)
        try c.encode(encryptionInformation, forKey: .encryptionInformation)
        try c.encodeIfPresent(assertions, forKey: .assertions)
        // tdfSpecVersion intentionally not encoded.
    }

    /// Resolve the spec version: `schemaVersion`, then root `tdf_spec_version`,
    /// then `payload.tdf_spec_version`. First non-empty wins.
    public var effectiveSpecVersion: String? {
        for candidate in [schemaVersion, tdfSpecVersion, payload.tdfSpecVersion] {
            if let v = candidate, !v.isEmpty {
                return v
            }
        }
        return nil
    }
}

public struct TDFPayloadDescriptor: Codable, Sendable {
    public enum PayloadType: String, Codable, Sendable {
        case reference
        case embedded
    }

    public enum PayloadProtocol: String, Codable, Sendable {
        case zip
        case zipstream
        case file
        case http
        case https
    }

    public var type: PayloadType
    public var url: String
    public var protocolValue: PayloadProtocol
    public var isEncrypted: Bool
    public var mimeType: String?
    /// Spec JSON schema places `tdf_spec_version` under payload. Decode-only.
    public var tdfSpecVersion: String?

    enum CodingKeys: String, CodingKey {
        case type
        case url
        case protocolValue = "protocol"
        case isEncrypted
        case mimeType
        case tdfSpecVersion = "tdf_spec_version"
    }

    public init(
        type: PayloadType,
        url: String,
        protocolValue: PayloadProtocol,
        isEncrypted: Bool,
        mimeType: String? = nil,
    ) {
        self.type = type
        self.url = url
        self.protocolValue = protocolValue
        self.isEncrypted = isEncrypted
        self.mimeType = mimeType
        tdfSpecVersion = nil
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        type = try c.decode(PayloadType.self, forKey: .type)
        url = try c.decode(String.self, forKey: .url)
        protocolValue = try c.decode(PayloadProtocol.self, forKey: .protocolValue)
        isEncrypted = try c.decode(Bool.self, forKey: .isEncrypted)
        mimeType = try c.decodeIfPresent(String.self, forKey: .mimeType)
        tdfSpecVersion = try c.decodeIfPresent(String.self, forKey: .tdfSpecVersion)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(type, forKey: .type)
        try c.encode(url, forKey: .url)
        try c.encode(protocolValue, forKey: .protocolValue)
        try c.encode(isEncrypted, forKey: .isEncrypted)
        try c.encodeIfPresent(mimeType, forKey: .mimeType)
    }
}

public struct TDFEncryptionInformation: Codable, Sendable {
    public enum KeyAccessType: String, Codable, Sendable {
        case split
        case remote
    }

    public var type: KeyAccessType
    public var keyAccess: [TDFKeyAccessObject]
    public var method: TDFMethodDescriptor
    public var integrityInformation: TDFIntegrityInformation?
    public var policy: String

    public init(
        type: KeyAccessType,
        keyAccess: [TDFKeyAccessObject],
        method: TDFMethodDescriptor,
        integrityInformation: TDFIntegrityInformation? = nil,
        policy: String,
    ) {
        self.type = type
        self.keyAccess = keyAccess
        self.method = method
        self.integrityInformation = integrityInformation
        self.policy = policy
    }
}

public struct TDFKeyAccessObject: Codable, Sendable {
    public enum AccessType: String, Codable, Sendable {
        case wrapped
        case remote
        case remoteWrapped
        case ecWrapped = "ec-wrapped"
        /// Wrapped to a KAS hybrid (classical + ML-KEM) key; the KAS unwraps it.
        case hybridWrapped = "hybrid-wrapped"
        /// Wrapped to a KAS ML-KEM key; the KAS unwraps it.
        case mlkemWrapped = "mlkem-wrapped"
    }

    public enum AccessProtocol: String, Codable, Sendable {
        case kas
    }

    public var type: AccessType
    public var url: String
    public var protocolValue: AccessProtocol
    public var wrappedKey: String
    public var policyBinding: TDFPolicyBinding
    public var encryptedMetadata: String?
    public var kid: String?
    public var sid: String?
    public var schemaVersion: String?
    public var ephemeralPublicKey: String?

    enum CodingKeys: String, CodingKey {
        case type
        case url
        case protocolValue = "protocol"
        case wrappedKey
        case policyBinding
        case encryptedMetadata
        case kid
        case sid
        case schemaVersion
        case ephemeralPublicKey
    }

    public init(
        type: AccessType,
        url: String,
        protocolValue: AccessProtocol,
        wrappedKey: String,
        policyBinding: TDFPolicyBinding,
        encryptedMetadata: String? = nil,
        kid: String? = nil,
        sid: String? = nil,
        schemaVersion: String? = nil,
        ephemeralPublicKey: String? = nil,
    ) {
        self.type = type
        self.url = url
        self.protocolValue = protocolValue
        self.wrappedKey = wrappedKey
        self.policyBinding = policyBinding
        self.encryptedMetadata = encryptedMetadata
        self.kid = kid
        self.sid = sid
        self.schemaVersion = schemaVersion
        self.ephemeralPublicKey = ephemeralPublicKey
    }
}

public struct TDFPolicyBinding: Codable, Sendable {
    public var alg: String
    public var hash: String

    public init(alg: String, hash: String) {
        self.alg = alg
        self.hash = hash
    }

    private enum CodingKeys: String, CodingKey {
        case alg
        case hash
    }

    /// Accepts the `{alg, hash}` object and the bare-string form some writers
    /// emit. An absent or empty `alg` means HS256 (OpenTDF spec PR #70, Go SDK).
    public init(from decoder: Decoder) throws {
        if let hash = try? decoder.singleValueContainer().decode(String.self) {
            alg = "HS256"
            self.hash = hash
            return
        }
        let c = try decoder.container(keyedBy: CodingKeys.self)
        hash = try c.decode(String.self, forKey: .hash)
        let decodedAlg = try c.decodeIfPresent(String.self, forKey: .alg) ?? ""
        alg = decodedAlg.isEmpty ? "HS256" : decodedAlg
    }
}

public struct TDFMethodDescriptor: Codable, Sendable {
    public var algorithm: String
    public var iv: String
    public var isStreamable: Bool?

    public init(algorithm: String, iv: String, isStreamable: Bool? = nil) {
        self.algorithm = algorithm
        self.iv = iv
        self.isStreamable = isStreamable
    }
}

public struct TDFIntegrityInformation: Codable, Sendable {
    public var rootSignature: TDFRootSignature
    public var segmentHashAlg: String
    public var segmentSizeDefault: Int64
    public var encryptedSegmentSizeDefault: Int64?
    public var segments: [TDFSegment]

    public init(
        rootSignature: TDFRootSignature,
        segmentHashAlg: String,
        segmentSizeDefault: Int64,
        encryptedSegmentSizeDefault: Int64? = nil,
        segments: [TDFSegment],
    ) {
        self.rootSignature = rootSignature
        self.segmentHashAlg = segmentHashAlg
        self.segmentSizeDefault = segmentSizeDefault
        self.encryptedSegmentSizeDefault = encryptedSegmentSizeDefault
        self.segments = segments
    }

    private enum CodingKeys: String, CodingKey {
        case rootSignature
        case segmentHashAlg
        case segmentSizeDefault
        case encryptedSegmentSizeDefault
        case segments
    }

    /// Segment entry as written on the wire: `segmentSize` is optional (spec
    /// integrity_information.md) and some writers emit `encryptedSegmentSize: 0`
    /// for "use the default".
    private struct WireSegment: Decodable {
        let hash: String
        let segmentSize: Int64?
        let encryptedSegmentSize: Int64?
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        rootSignature = try c.decode(TDFRootSignature.self, forKey: .rootSignature)
        segmentHashAlg = try c.decode(String.self, forKey: .segmentHashAlg)
        segmentSizeDefault = try c.decode(Int64.self, forKey: .segmentSizeDefault)
        encryptedSegmentSizeDefault = try c.decodeIfPresent(Int64.self, forKey: .encryptedSegmentSizeDefault)
        let defaultSize = segmentSizeDefault
        segments = try c.decode([WireSegment].self, forKey: .segments).map { segment in
            TDFSegment(
                hash: segment.hash,
                segmentSize: segment.segmentSize ?? defaultSize,
                encryptedSegmentSize: segment.encryptedSegmentSize.flatMap { $0 > 0 ? $0 : nil },
            )
        }
    }

    /// Minimal integrity information for simple use cases without segment hashing
    public static var minimal: TDFIntegrityInformation {
        TDFIntegrityInformation(
            rootSignature: TDFRootSignature(alg: "HS256", sig: ""),
            segmentHashAlg: "GMAC",
            segmentSizeDefault: 0,
            encryptedSegmentSizeDefault: nil,
            segments: [],
        )
    }
}

public struct TDFRootSignature: Codable, Sendable {
    public var alg: String
    public var sig: String

    public init(alg: String, sig: String) {
        self.alg = alg
        self.sig = sig
    }

    private enum CodingKeys: String, CodingKey {
        case alg
        case sig
    }

    /// An absent or empty `alg` means HS256 (OpenTDF spec PR #70, Go SDK).
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        sig = try c.decode(String.self, forKey: .sig)
        let decodedAlg = try c.decodeIfPresent(String.self, forKey: .alg) ?? ""
        alg = decodedAlg.isEmpty ? "HS256" : decodedAlg
    }
}

public struct TDFSegment: Codable, Sendable {
    public var hash: String
    public var segmentSize: Int64
    public var encryptedSegmentSize: Int64?

    public init(hash: String, segmentSize: Int64, encryptedSegmentSize: Int64? = nil) {
        self.hash = hash
        self.segmentSize = segmentSize
        self.encryptedSegmentSize = encryptedSegmentSize
    }
}

public struct TDFAssertion: Codable, Sendable {
    public var id: String?
    public var type: String
    public var scope: String?
    public var appliesToState: String?
    public var statement: TDFAssertionStatement
    public var binding: TDFAssertionBinding?

    public init(
        id: String? = nil,
        type: String,
        scope: String? = nil,
        appliesToState: String? = nil,
        statement: TDFAssertionStatement,
        binding: TDFAssertionBinding? = nil,
    ) {
        self.id = id
        self.type = type
        self.scope = scope
        self.appliesToState = appliesToState
        self.statement = statement
        self.binding = binding
    }
}

public struct TDFAssertionStatement: Codable, Sendable {
    /// Statement format. The spec lists `json-structured`, `base64binary` and
    /// `string`, and writers use others (the Go SDK's system-metadata assertion
    /// writes `json`), so any value round-trips.
    public struct StatementFormat: RawRepresentable, Codable, Hashable, Sendable {
        public let rawValue: String

        public init(rawValue: String) {
            self.rawValue = rawValue
        }

        public static let jsonStructured = StatementFormat(rawValue: "json-structured")
        public static let string = StatementFormat(rawValue: "string")
        public static let binary = StatementFormat(rawValue: "binary")
        public static let base64Binary = StatementFormat(rawValue: "base64binary")
    }

    public var format: StatementFormat
    public var schema: String?
    public var value: CodableValue

    public init(format: StatementFormat, schema: String? = nil, value: CodableValue) {
        self.format = format
        self.schema = schema
        self.value = value
    }

    private enum CodingKeys: String, CodingKey {
        case format
        case schema
        case value
    }

    /// `format` may be omitted (the Go SDK writes it `omitempty`).
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        format = try c.decodeIfPresent(StatementFormat.self, forKey: .format) ?? StatementFormat(rawValue: "")
        schema = try c.decodeIfPresent(String.self, forKey: .schema)
        value = try c.decode(CodableValue.self, forKey: .value)
    }
}

public struct TDFAssertionBinding: Codable, Sendable {
    public var method: String
    public var signature: String

    public init(method: String, signature: String) {
        self.method = method
        self.signature = signature
    }
}

/// Wrapper that preserves arbitrary JSON content for assertion statements.
public enum CodableValue: Codable, Sendable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case object([String: CodableValue])
    case array([CodableValue])
    case null

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([String: CodableValue].self) {
            self = .object(value)
        } else if let value = try? container.decode([CodableValue].self) {
            self = .array(value)
        } else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(codingPath: container.codingPath, debugDescription: "Unsupported JSON value"),
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case let .string(value):
            try container.encode(value)
        case let .number(value):
            try container.encode(value)
        case let .bool(value):
            try container.encode(value)
        case let .object(value):
            try container.encode(value)
        case let .array(value):
            try container.encode(value)
        case .null:
            try container.encodeNil()
        }
    }
}
