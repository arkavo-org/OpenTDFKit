import Foundation

/// Trusted Data Format manifest representation aligned with OpenTDF schema.
public struct TDFManifest: Codable, Sendable {
    public var schemaVersion: String
    public var payload: TDFPayloadDescriptor
    public var encryptionInformation: TDFEncryptionInformation
    public var assertions: [TDFAssertion]?

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
    }
}

public struct TDFPayloadDescriptor: Codable, Sendable {
    public enum PayloadType: String, Codable, Sendable {
        case reference
        case embedded
    }

    public enum PayloadProtocol: String, Codable, Sendable {
        case zip
        case file
        case http
        case https
    }

    public var type: PayloadType
    public var url: String
    public var protocolValue: PayloadProtocol
    public var isEncrypted: Bool
    public var mimeType: String?

    enum CodingKeys: String, CodingKey {
        case type
        case url
        case protocolValue = "protocol"
        case isEncrypted
        case mimeType
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
    public var integrityInformation: TDFIntegrityInformation
    public var policy: String

    public init(
        type: KeyAccessType,
        keyAccess: [TDFKeyAccessObject],
        method: TDFMethodDescriptor,
        integrityInformation: TDFIntegrityInformation,
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
}

public struct TDFRootSignature: Codable, Sendable {
    public var alg: String
    public var sig: String

    public init(alg: String, sig: String) {
        self.alg = alg
        self.sig = sig
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
    public enum StatementFormat: String, Codable, Sendable {
        case jsonStructured = "json-structured"
        case string
        case binary
    }

    public var format: StatementFormat
    public var schema: String?
    public var value: CodableValue

    public init(format: StatementFormat, schema: String? = nil, value: CodableValue) {
        self.format = format
        self.schema = schema
        self.value = value
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
