import CryptoKit
import Darwin
import Foundation

/// URLSession task delegate that refuses HTTP redirects. The KAS rewrap target
/// is an RPC endpoint that must never redirect; following a 3xx could re-issue
/// the bearer-carrying request to an unvalidated host.
final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_: URLSession, task _: URLSessionTask,
                    willPerformHTTPRedirection _: HTTPURLResponse, newRequest _: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void)
    {
        completionHandler(nil)
    }
}

/// Protocol for KAS rewrap client operations, enabling testability through dependency injection
public protocol KASRewrapClientProtocol {
    /// Perform NanoTDF rewrap request to KAS
    /// - Parameters:
    ///   - header: Raw NanoTDF header bytes
    ///   - parsedHeader: Parsed header structure to extract policy
    ///   - clientKeyPair: Client's ephemeral key pair for this request
    /// - Returns: Tuple containing the wrapped key data and session public key
    func rewrapNanoTDF(header: Data, parsedHeader: Header, clientKeyPair: EphemeralKeyPair) async throws -> (wrappedKey: Data, sessionPublicKey: Data)
}

/// Client for interacting with KAS rewrap endpoint for NanoTDF
public class KASRewrapClient: KASRewrapClientProtocol {
    // MARK: - Request/Response Structures

    /// Key Access Object for NanoTDF rewrap
    public struct KeyAccessObject: Codable {
        let header: String // Base64-encoded raw NanoTDF header bytes
        let type: String
        let url: String
        let `protocol`: String

        init(header: String, url: String) {
            self.header = header
            type = "remote"
            self.url = url
            self.protocol = "kas"
        }

        private enum CodingKeys: String, CodingKey {
            case header, type, url, `protocol`
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            header = try container.decode(String.self, forKey: .header)
            type = try container.decodeIfPresent(String.self, forKey: .type) ?? "remote"
            url = try container.decode(String.self, forKey: .url)
            `protocol` = try container.decodeIfPresent(String.self, forKey: .protocol) ?? "kas"
        }
    }

    /// Key Access Object wrapper for v2 API
    public struct KeyAccessObjectWrapper: Codable {
        let keyAccessObjectId: String
        let keyAccessObject: KeyAccessObject
    }

    // MARK: - Standard TDF Request Types

    public struct StandardPolicyBinding: Codable {
        let hash: String
        let alg: String?

        enum CodingKeys: String, CodingKey {
            case hash
            case alg
        }
    }

    public struct StandardKeyAccessObject: Codable {
        let keyType: String?
        let kasUrl: String
        let `protocol`: String
        let wrappedKey: String // Base64-encoded RSA-wrapped DEK for Standard TDF
        let policyBinding: StandardPolicyBinding?
        let encryptedMetadata: String?
        let kid: String?
        let splitId: String?
        let ephemeralPublicKey: String?

        enum CodingKeys: String, CodingKey {
            case keyType = "type"
            case kasUrl = "url"
            case `protocol`
            case wrappedKey
            case policyBinding
            case encryptedMetadata
            case kid
            case splitId = "sid"
            case ephemeralPublicKey
        }
    }

    public struct StandardKeyAccessObjectWrapper: Codable {
        let keyAccessObjectId: String
        let keyAccessObject: StandardKeyAccessObject
    }

    /// Algorithm type for KAS rewrap requests
    public enum RewrapAlgorithm: String, Sendable {
        case rsa2048 = "rsa:2048"
        case ecP256 = "ec:secp256r1"
        case ecP384 = "ec:secp384r1"
        case ecP521 = "ec:secp521r1"

        /// Detect algorithm from key access type
        public static func from(accessType: TDFKeyAccessObject.AccessType) -> RewrapAlgorithm {
            switch accessType {
            case .ecWrapped:
                .ecP256 // Default to P-256 for EC
            case .wrapped, .remote, .remoteWrapped:
                .rsa2048
            }
        }
    }

    public struct StandardPolicyRequest: Codable {
        let keyAccessObjects: [StandardKeyAccessObjectWrapper]
        let policy: Policy
        let algorithm: String?

        init(
            keyAccessObjects: [StandardKeyAccessObjectWrapper],
            policy: Policy,
            algorithm: String?,
        ) {
            self.keyAccessObjects = keyAccessObjects
            self.policy = policy
            self.algorithm = algorithm
        }
    }

    public struct StandardUnsignedRewrapRequest: Codable {
        let clientPublicKey: String
        let requests: [StandardPolicyRequest]
    }

    /// Policy structure
    public struct Policy: Codable {
        let id: String
        let body: String // Base64-encoded policy

        init(body: String) {
            id = "policy"
            self.body = body
        }

        private enum CodingKeys: String, CodingKey {
            case id, body
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            id = try container.decodeIfPresent(String.self, forKey: .id) ?? "policy"
            body = try container.decode(String.self, forKey: .body)
        }
    }

    /// Individual rewrap request entry
    public struct RewrapRequestEntry: Codable {
        let algorithm: String
        let policy: Policy
        let keyAccessObjects: [KeyAccessObjectWrapper]

        init(policy: Policy, keyAccessObjects: [KeyAccessObjectWrapper]) {
            algorithm = "ec:secp256r1"
            self.policy = policy
            self.keyAccessObjects = keyAccessObjects
        }

        private enum CodingKeys: String, CodingKey {
            case algorithm, policy, keyAccessObjects
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            algorithm = try container.decodeIfPresent(String.self, forKey: .algorithm) ?? "ec:secp256r1"
            policy = try container.decode(Policy.self, forKey: .policy)
            keyAccessObjects = try container.decode([KeyAccessObjectWrapper].self, forKey: .keyAccessObjects)
        }
    }

    /// Unsigned rewrap request structure
    public struct UnsignedRewrapRequest: Codable {
        let clientPublicKey: String // Top-level field as per proto
        let requests: [RewrapRequestEntry]
    }

    /// Signed request wrapper
    public struct SignedRewrapRequest: Codable {
        let signed_request_token: String
    }

    /// Individual KAS result
    public struct KASResult: Codable {
        let keyAccessObjectId: String
        let status: String // "permit" or "fail"
        let kasWrappedKey: String?
        let entityWrappedKey: String? // Legacy field
        let metadata: [String: String]?
    }

    /// Response policy entry
    public struct ResponsePolicyEntry: Codable {
        let policyId: String
        let results: [KASResult]
    }

    /// Rewrap response structure
    public struct RewrapResponse: Codable {
        let responses: [ResponsePolicyEntry]
        let sessionPublicKey: String?
        let entityWrappedKey: String? // Legacy field at top level
        let metadata: [String: String]?
        let schemaVersion: String?
    }

    // MARK: - KAS Public Key Response

    /// Response structure for KAS EC public key endpoint
    /// Handles both snake_case (public_key) and camelCase (publicKey) field names
    public struct KasEcPublicKeyResponse: Decodable {
        /// The PEM-encoded EC public key
        public let publicKey: String

        /// Key ID (optional, may be returned by some KAS implementations)
        public let kid: String?

        private enum CodingKeys: String, CodingKey {
            case publicKey
            case publicKeySnake = "public_key"
            case kid
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)

            // Try camelCase first, then snake_case
            if let key = try container.decodeIfPresent(String.self, forKey: .publicKey) {
                publicKey = key
            } else if let key = try container.decodeIfPresent(String.self, forKey: .publicKeySnake) {
                publicKey = key
            } else {
                throw DecodingError.keyNotFound(
                    CodingKeys.publicKey,
                    DecodingError.Context(
                        codingPath: container.codingPath,
                        debugDescription: "Neither 'publicKey' nor 'public_key' found in response",
                    ),
                )
            }

            kid = try container.decodeIfPresent(String.self, forKey: .kid)
        }

        /// Initialize directly (for testing)
        public init(publicKey: String, kid: String? = nil) {
            self.publicKey = publicKey
            self.kid = kid
        }
    }

    /// Result of fetching and validating a KAS EC public key
    public struct KasEcPublicKeyResult {
        /// Compressed P-256 public key (33 bytes)
        public let compressedKey: Data

        /// The original PEM string from the KAS
        public let pem: String

        /// Key ID if provided by the KAS
        public let kid: String?

        /// The parsed CryptoKit public key
        public let cryptoKitKey: P256.KeyAgreement.PublicKey
    }

    // MARK: - Properties

    private let endpoints: KasEndpoints
    /// KAS identity url for the request-body KeyAccessObject when the NanoTDF
    /// header locator is unavailable (fallback only).
    private let kasIdentityURL: String
    private let oauthToken: String
    private let urlSession: URLSession
    private let signingKey: P256.Signing.PrivateKey
    private let noRedirect = NoRedirectDelegate()

    // MARK: - Initialization

    /// Initialize from a resolved configuration document (preferred).
    /// - Parameters:
    ///   - configuration: Resolved config; obtain via `fetchWellKnown(...)` or
    ///     `OpenTDFConfiguration.forKasConnect(_:)`. Both resolved KAS URLs are
    ///     validated (HTTPS / scheme / SSRF) here.
    ///   - oauthToken: Bearer token (opaque: a JWT or base64url-encoded CWT).
    public init(configuration: OpenTDFConfiguration, oauthToken: String,
                urlSession: URLSession = .shared,
                signingKey: P256.Signing.PrivateKey? = nil) throws
    {
        endpoints = try KasEndpoints.from(configuration)
        kasIdentityURL = configuration.kas?.uri ?? ""
        self.oauthToken = oauthToken
        self.urlSession = urlSession
        self.signingKey = signingKey ?? P256.Signing.PrivateKey()
    }

    /// Legacy initializer: treats `kasURL` as a `{base}/kas` REST endpoint and
    /// builds `{kasURL}/v2/*` endpoints, preserving prior behavior.
    /// Transitional bridge — prefer `init(configuration:)`. (Removed in a later task.)
    public init(kasURL: URL, oauthToken: String, urlSession: URLSession = .shared,
                signingKey: P256.Signing.PrivateKey? = nil)
    {
        endpoints = KasEndpoints(
            rewrapURL: kasURL.appendingPathComponent("v2/rewrap").absoluteString,
            publicKeyURL: kasURL.appendingPathComponent("v2/kas_public_key").absoluteString,
            transport: .legacyRest,
        )
        kasIdentityURL = kasURL.absoluteString
        self.oauthToken = oauthToken
        self.urlSession = urlSession
        self.signingKey = signingKey ?? P256.Signing.PrivateKey()
    }

    // MARK: - Public Methods

    /// Perform NanoTDF rewrap request to KAS
    /// - Parameters:
    ///   - header: Raw NanoTDF header bytes
    ///   - parsedHeader: Parsed header structure to extract policy
    ///   - clientKeyPair: Client's ephemeral key pair for this request
    /// - Returns: Tuple containing the wrapped key data and session public key
    public func rewrapNanoTDF(header: Data, parsedHeader: Header, clientKeyPair: EphemeralKeyPair) async throws -> (wrappedKey: Data, sessionPublicKey: Data) {
        // Build the Key Access Object
        let keyAccess = KeyAccessObject(
            header: header.base64EncodedString(),
            url: resolveNanoKasURL(parsedHeader),
        )

        // Build the Key Access Object wrapper for v2 API
        let keyAccessWrapper = KeyAccessObjectWrapper(
            keyAccessObjectId: "kao-0",
            keyAccessObject: keyAccess,
        )

        // Build the policy from the parsed header
        let policyBody: String
        if let policyBodyData = parsedHeader.policy.body?.body {
            // All policy types are base64-encoded for KAS
            policyBody = policyBodyData.base64EncodedString()
        } else {
            // Send empty JSON object for embedded plaintext policies
            let emptyJSON = "{}".data(using: .utf8)!
            policyBody = emptyJSON.base64EncodedString()
        }
        let policy = Policy(body: policyBody)

        // Build the rewrap request entry
        let requestEntry = RewrapRequestEntry(
            policy: policy,
            keyAccessObjects: [keyAccessWrapper],
        )

        // Build the unsigned request with clientPublicKey at top level
        let clientPublicKeyPEM = String(data: clientKeyPair.publicKey, encoding: .utf8) ?? ""
        let unsignedRequest = UnsignedRewrapRequest(
            clientPublicKey: clientPublicKeyPEM,
            requests: [requestEntry],
        )

        // Encode to JSON
        let requestBodyJSON = try JSONEncoder().encode(unsignedRequest)

        // The KAS expects a signed JWT wrapper around the request body
        let signedToken = try createSignedJWT(requestBody: requestBodyJSON, signingKey: signingKey)
        let signedRequest = SignedRewrapRequest(signed_request_token: signedToken)

        // Create HTTP request
        guard let rewrapEndpoint = URL(string: endpoints.rewrapURL) else {
            throw KASRewrapError.invalidTDFRequest("Invalid rewrap URL: \(endpoints.rewrapURL)")
        }
        var request = URLRequest(url: rewrapEndpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = 30

        request.addValue("Bearer \(oauthToken)", forHTTPHeaderField: "Authorization")
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.addValue("1", forHTTPHeaderField: "Connect-Protocol-Version")
        request.httpBody = try JSONEncoder().encode(signedRequest)

        // Perform request (no redirects for the bearer-carrying call)
        let (data, response) = try await urlSession.data(for: request, delegate: noRedirect)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw KASRewrapError.invalidResponse
        }

        switch httpResponse.statusCode {
        case 200:
            // Parse response
            let rewrapResponse = try JSONDecoder().decode(RewrapResponse.self, from: data)

            guard let firstPolicy = rewrapResponse.responses.first,
                  let firstResult = firstPolicy.results.first
            else {
                throw KASRewrapError.emptyResponse
            }

            guard firstResult.status == "permit" else {
                let reason = firstResult.metadata?["error"] ?? "Access denied by policy"
                throw KASRewrapError.accessDenied(reason)
            }

            // Extract wrapped key (try kasWrappedKey first, then entityWrappedKey for legacy)
            guard let wrappedKeyBase64 = firstResult.kasWrappedKey ?? firstResult.entityWrappedKey,
                  let wrappedKey = Data(base64Encoded: wrappedKeyBase64)
            else {
                throw KASRewrapError.missingWrappedKey
            }

            // Extract session public key from PEM format
            guard let sessionKeyPEM = rewrapResponse.sessionPublicKey else {
                throw KASRewrapError.missingSessionKey
            }

            // Extract the compressed key from PEM
            let sessionKey = try extractCompressedKeyFromPEM(sessionKeyPEM)

            return (wrappedKey, sessionKey)
        default:
            throw mapRewrapHTTPError(status: httpResponse.statusCode, data: data)
        }
    }

    /// Perform Standard TDF rewrap request to KAS.
    /// - Parameters:
    ///   - manifest: The parsed TDF manifest containing key access entries.
    ///   - clientPrivateKey: Client's P-256 private key for ECDH. Its public key is sent in the request
    ///                       and the same key is used to sign the JWT (converted to signing key).
    /// - Returns: Mapping of KeyAccessObjectId to wrapped key data and optional session public key when EC wrapping is used.
    public func rewrapTDF(
        manifest: TDFManifest,
        clientPrivateKey: P256.KeyAgreement.PrivateKey,
    ) async throws -> TDFKASRewrapResult {
        // Convert KeyAgreement key to Signing key (same underlying P-256 key)
        let signingKey = try P256.Signing.PrivateKey(rawRepresentation: clientPrivateKey.rawRepresentation)
        let clientPublicKeyPEM = clientPrivateKey.publicKey.pemRepresentation

        let policyBody = manifest.encryptionInformation.policy
        let keyAccessEntries = manifest.encryptionInformation.keyAccess.filter { matchesKasURL($0.url) }

        guard !keyAccessEntries.isEmpty else {
            throw KASRewrapError.invalidTDFRequest("No key access entries for KAS \(kasIdentityURL)")
        }

        var wrappers: [StandardKeyAccessObjectWrapper] = []
        wrappers.reserveCapacity(keyAccessEntries.count)

        for (index, kao) in keyAccessEntries.enumerated() {
            // Validate the wrapped key is valid base64
            guard Data(base64Encoded: kao.wrappedKey) != nil else {
                throw KASRewrapError.invalidWrappedKeyFormat
            }

            let binding = StandardPolicyBinding(
                hash: kao.policyBinding.hash,
                alg: kao.policyBinding.alg,
            )

            // Standard TDF uses wrappedKey field with base64-encoded RSA-wrapped DEK
            let accessObject = StandardKeyAccessObject(
                keyType: kao.type.rawValue,
                kasUrl: kao.url,
                protocol: kao.protocolValue.rawValue,
                wrappedKey: kao.wrappedKey, // Base64-encoded DEK encrypted with KAS public key
                policyBinding: binding,
                encryptedMetadata: kao.encryptedMetadata,
                kid: kao.kid,
                splitId: kao.sid,
                ephemeralPublicKey: kao.ephemeralPublicKey,
            )

            let wrapper = StandardKeyAccessObjectWrapper(
                keyAccessObjectId: String(format: "kao-%d", index),
                keyAccessObject: accessObject,
            )
            wrappers.append(wrapper)
        }

        // Detect algorithm from first key access entry (all should use same algorithm)
        let algorithm: RewrapAlgorithm = keyAccessEntries.first
            .map { RewrapAlgorithm.from(accessType: $0.type) } ?? .rsa2048

        let policy = Policy(body: policyBody)
        let policyRequest = StandardPolicyRequest(
            keyAccessObjects: wrappers,
            policy: policy,
            algorithm: algorithm.rawValue,
        )

        let unsignedRequest = StandardUnsignedRewrapRequest(
            clientPublicKey: clientPublicKeyPEM,
            requests: [policyRequest],
        )

        let requestBodyJSON = try JSONEncoder().encode(unsignedRequest)
        let signedToken = try createSignedJWT(requestBody: requestBodyJSON, signingKey: signingKey)
        let signedRequest = SignedRewrapRequest(signed_request_token: signedToken)

        guard let rewrapEndpoint = URL(string: endpoints.rewrapURL) else {
            throw KASRewrapError.invalidTDFRequest("Invalid rewrap URL: \(endpoints.rewrapURL)")
        }
        var request = URLRequest(url: rewrapEndpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = 30
        request.addValue("Bearer \(oauthToken)", forHTTPHeaderField: "Authorization")
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.addValue("1", forHTTPHeaderField: "Connect-Protocol-Version")
        request.httpBody = try JSONEncoder().encode(signedRequest)

        let (data, response) = try await urlSession.data(for: request, delegate: noRedirect)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw KASRewrapError.invalidResponse
        }

        switch httpResponse.statusCode {
        case 200:
            let rewrapResponse = try JSONDecoder().decode(RewrapResponse.self, from: data)
            var wrappedKeys: [String: Data] = [:]

            for policyEntry in rewrapResponse.responses {
                for result in policyEntry.results {
                    guard result.status == "permit" else {
                        let reason = result.metadata?["error"] ?? "Access denied by policy"
                        throw KASRewrapError.accessDenied(reason)
                    }

                    guard let wrappedKeyBase64 = result.kasWrappedKey ?? result.entityWrappedKey,
                          let wrappedKeyData = Data(base64Encoded: wrappedKeyBase64)
                    else {
                        throw KASRewrapError.missingWrappedKey
                    }

                    wrappedKeys[result.keyAccessObjectId] = wrappedKeyData
                }
            }

            guard !wrappedKeys.isEmpty else {
                throw KASRewrapError.emptyResponse
            }

            return TDFKASRewrapResult(
                wrappedKeys: wrappedKeys,
                sessionPublicKeyPEM: rewrapResponse.sessionPublicKey,
            )
        default:
            throw mapRewrapHTTPError(status: httpResponse.statusCode, data: data)
        }
    }

    // MARK: - KAS Public Key Fetching

    /// Fetch the KAS EC public key for NanoTDF encryption
    /// - Parameter algorithm: The EC algorithm to request (defaults to P-256/secp256r1)
    /// - Returns: KasEcPublicKeyResult containing the validated compressed key and metadata
    /// - Throws: KASRewrapError if fetching or validation fails
    public func fetchKasEcPublicKey(
        algorithm: RewrapAlgorithm = .ecP256,
    ) async throws -> KasEcPublicKeyResult {
        // Validate algorithm is EC-based
        guard algorithm == .ecP256 || algorithm == .ecP384 || algorithm == .ecP521 else {
            throw KASRewrapError.unsupportedKeyAlgorithm(algorithm.rawValue)
        }

        var request: URLRequest
        switch endpoints.transport {
        case .connect:
            // ConnectRPC PublicKey RPC: POST the PublicKeyRequest message as JSON.
            // `algorithm` is a request-message field (Go opentdf/platform proto).
            guard let url = URL(string: endpoints.publicKeyURL) else {
                throw KASRewrapError.keyFetchFailed("Invalid public key URL: \(endpoints.publicKeyURL)")
            }
            request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.timeoutInterval = 30
            request.addValue("Bearer \(oauthToken)", forHTTPHeaderField: "Authorization")
            request.addValue("application/json", forHTTPHeaderField: "Content-Type")
            request.addValue("application/json", forHTTPHeaderField: "Accept")
            request.addValue("1", forHTTPHeaderField: "Connect-Protocol-Version")
            request.httpBody = try JSONEncoder().encode(["algorithm": algorithm.rawValue])
        case .legacyRest:
            guard var components = URLComponents(string: endpoints.publicKeyURL) else {
                throw KASRewrapError.keyFetchFailed("Invalid public key URL: \(endpoints.publicKeyURL)")
            }
            components.queryItems = [URLQueryItem(name: "algorithm", value: algorithm.rawValue)]
            guard let requestURL = components.url else {
                throw KASRewrapError.keyFetchFailed("Failed to construct KAS public key URL")
            }
            request = URLRequest(url: requestURL)
            request.httpMethod = "GET"
            request.timeoutInterval = 30
            request.addValue("Bearer \(oauthToken)", forHTTPHeaderField: "Authorization")
            request.addValue("application/json", forHTTPHeaderField: "Accept")
        }

        let (data, response) = try await urlSession.data(for: request, delegate: noRedirect)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw KASRewrapError.invalidResponse
        }

        switch httpResponse.statusCode {
        case 200:
            // Parse the JSON response
            let keyResponse: KasEcPublicKeyResponse
            do {
                keyResponse = try JSONDecoder().decode(KasEcPublicKeyResponse.self, from: data)
            } catch {
                throw KASRewrapError.keyFetchFailed("Failed to parse response: \(error.localizedDescription)")
            }

            // Validate and parse the PEM
            let result = try Self.validateEcPublicKeyPEM(keyResponse.publicKey, expectedAlgorithm: algorithm)

            return KasEcPublicKeyResult(
                compressedKey: result.compressedKey,
                pem: keyResponse.publicKey,
                kid: keyResponse.kid,
                cryptoKitKey: result.cryptoKitKey,
            )
        case 401:
            let message = String(data: data, encoding: .utf8)
            throw KASRewrapError.authenticationFailed(message)
        case 403:
            let message = String(data: data, encoding: .utf8)
            throw KASRewrapError.accessDenied(message ?? "Forbidden")
        case 404:
            throw KASRewrapError.keyFetchFailed("KAS public key endpoint not found")
        default:
            let message = String(data: data, encoding: .utf8)
            throw KASRewrapError.httpError(httpResponse.statusCode, message)
        }
    }

    /// Validate a PEM-encoded EC public key and extract the compressed representation
    /// - Parameters:
    ///   - pem: PEM-encoded public key string
    ///   - expectedAlgorithm: The expected EC algorithm (for validation)
    /// - Returns: Tuple containing compressed key data and CryptoKit public key
    /// - Throws: KASRewrapError if validation fails
    public static func validateEcPublicKeyPEM(
        _ pem: String,
        expectedAlgorithm: RewrapAlgorithm = .ecP256,
    ) throws -> (compressedKey: Data, cryptoKitKey: P256.KeyAgreement.PublicKey) {
        // Currently only P-256 is supported for validation
        guard expectedAlgorithm == .ecP256 else {
            throw KASRewrapError.unsupportedKeyAlgorithm(
                "Validation only supports P-256, got: \(expectedAlgorithm.rawValue)",
            )
        }

        // Normalize line endings and trim whitespace
        let normalizedPEM = pem
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        // Support multiple PEM header formats
        let beginMarkers = [
            "-----BEGIN PUBLIC KEY-----",
            "-----BEGIN EC PUBLIC KEY-----",
            "-----BEGIN ECDSA PUBLIC KEY-----",
        ]
        let endMarkers = [
            "-----END PUBLIC KEY-----",
            "-----END EC PUBLIC KEY-----",
            "-----END ECDSA PUBLIC KEY-----",
        ]

        // Extract base64 content by removing all markers
        var base64Content = normalizedPEM
        for marker in beginMarkers + endMarkers {
            base64Content = base64Content.replacingOccurrences(of: marker, with: "")
        }

        // Remove all whitespace and newlines
        base64Content = base64Content.components(separatedBy: .whitespacesAndNewlines).joined()

        // Validate we have content
        guard !base64Content.isEmpty else {
            throw KASRewrapError.invalidEcPublicKey("Empty PEM content")
        }

        // Decode base64
        guard let keyData = Data(base64Encoded: base64Content) else {
            throw KASRewrapError.invalidEcPublicKey("Invalid base64 encoding")
        }

        // Parse public key - support multiple formats
        // KAS server may return SEC1 bytes wrapped in SPKI PEM, or standard SPKI DER
        let publicKey: P256.KeyAgreement.PublicKey

        do {
            if keyData.count == 65, keyData[0] == 0x04 {
                // Raw uncompressed SEC1 point (0x04 || x || y) - 65 bytes
                // This is the format some KAS servers return inside the PEM wrapper
                publicKey = try P256.KeyAgreement.PublicKey(x963Representation: keyData)
            } else if keyData.count == 33, keyData[0] == 0x02 || keyData[0] == 0x03 {
                // Compressed SEC1 point (0x02/0x03 || x) - 33 bytes
                publicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: keyData)
            } else if keyData.count >= 59, keyData.count <= 91 {
                // SPKI DER format (typically 91 bytes for P-256 with uncompressed point,
                // or ~59 bytes with compressed point)
                publicKey = try P256.KeyAgreement.PublicKey(derRepresentation: keyData)
            } else {
                throw KASRewrapError.invalidEcPublicKey(
                    "Unrecognized key format: \(keyData.count) bytes",
                )
            }
        } catch let error as KASRewrapError {
            throw error
        } catch {
            throw KASRewrapError.invalidEcPublicKey("Failed to parse key: \(error.localizedDescription)")
        }

        // Get compressed representation
        let compressedKey = publicKey.compressedRepresentation

        // Validate compressed key size (33 bytes for P-256)
        guard compressedKey.count == 33 else {
            throw KASRewrapError.invalidEcPublicKey("Invalid compressed key size: \(compressedKey.count), expected 33")
        }

        // Validate first byte is valid compressed point prefix
        guard compressedKey[0] == 0x02 || compressedKey[0] == 0x03 else {
            throw KASRewrapError.invalidEcPublicKey(
                "Invalid compressed point prefix: 0x\(String(format: "%02x", compressedKey[0]))",
            )
        }

        return (compressedKey, publicKey)
    }

    // MARK: - Private Helpers

    /// Resolve the request-body KAS url for a NanoTDF rewrap from the parsed
    /// header's resource locator, falling back to the configured identity.
    private func resolveNanoKasURL(_ parsedHeader: Header) -> String {
        let locator = parsedHeader.kas
        let scheme: String? = switch locator.protocolEnum {
        case .http: "http"
        case .https: "https"
        default: nil
        }
        if let scheme, !locator.body.isEmpty {
            return "\(scheme)://\(locator.body)"
        }
        return kasIdentityURL
    }

    /// Map a non-2xx rewrap response to a KASRewrapError, enriching the message
    /// from a Connect error envelope when present.
    private func mapRewrapHTTPError(status: Int, data: Data) -> KASRewrapError {
        let body = String(data: data, encoding: .utf8) ?? ""
        let detail = parseConnectError(body).map { "\($0.code): \($0.message)" }
            ?? (body.isEmpty ? "HTTP \(status)" : body)
        switch status {
        case 401: return .authenticationFailed(detail)
        case 403: return .accessDenied(detail)
        default: return .httpError(status, detail)
        }
    }

    private func matchesKasURL(_ otherURLString: String) -> Bool {
        guard let otherURL = URL(string: otherURLString) else { return false }
        guard let kasURL = URL(string: kasIdentityURL) else { return false }
        guard let baseScheme = kasURL.scheme?.lowercased(),
              let otherScheme = otherURL.scheme?.lowercased(),
              let baseHost = kasURL.host?.lowercased(),
              let otherHost = otherURL.host?.lowercased()
        else {
            return false
        }
        guard baseScheme == otherScheme, baseHost == otherHost else {
            return false
        }
        return effectivePort(for: kasURL) == effectivePort(for: otherURL)
    }

    private func effectivePort(for url: URL) -> Int {
        if let explicitPort = url.port {
            return explicitPort
        }
        switch url.scheme?.lowercased() {
        case "https":
            return 443
        case "http":
            return 80
        default:
            return 0
        }
    }

    /// Decrypt the wrapped key using ECDH and the session key
    /// - Parameters:
    ///   - wrappedKey: The wrapped key from KAS response
    ///   - sessionPublicKey: The session public key from KAS response
    ///   - clientPrivateKey: The client's ephemeral private key
    ///   - salt: HKDF salt for session key derivation. Pass `nil` to use the default
    ///           NanoTDF v12 salt (matching KAS behavior). Pass empty `Data()` for Standard TDF.
    /// - Returns: The decrypted symmetric key
    public static func unwrapKey(
        wrappedKey: Data,
        sessionPublicKey: Data,
        clientPrivateKey: Data,
        salt: Data? = nil,
    ) throws -> SymmetricKey {
        // Perform ECDH with session public key
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: clientPrivateKey)
        let publicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: sessionPublicKey)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)

        // Derive symmetric key using HKDF
        // Default to NanoTDF v12 salt (matches KAS rewrap_dek session key derivation)
        let hkdfSalt = salt ?? CryptoConstants.hkdfSalt
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: hkdfSalt,
            sharedInfo: Data(),
            outputByteCount: 32,
        )

        // Decrypt the wrapped key
        // The wrapped key format from platform is: nonce (12 bytes) + ciphertext + tag (16 bytes)
        // The platform KAS always uses 128-bit (16-byte) tags, so CryptoKit works here
        guard wrappedKey.count > 28 else { // 12 nonce + at least 16 tag
            throw KASRewrapError.invalidWrappedKeyFormat
        }

        // Use the SealedBox combined initializer which expects nonce+ciphertext+tag
        let sealedBox = try AES.GCM.SealedBox(combined: wrappedKey)
        let decryptedKey = try AES.GCM.open(sealedBox, using: symmetricKey)
        return SymmetricKey(data: decryptedKey)
    }

    /// Extract compressed P256 public key from PEM format
    /// - Parameter pem: PEM-encoded public key (supports various formats)
    /// - Returns: Compressed P-256 public key data (33 bytes)
    /// - Throws: KASRewrapError.invalidWrappedKeyFormat if PEM parsing fails
    private func extractCompressedKeyFromPEM(_ pem: String) throws -> Data {
        // Normalize line endings and trim whitespace
        let normalizedPEM = pem
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        // Support multiple PEM header formats
        let beginMarkers = [
            "-----BEGIN PUBLIC KEY-----",
            "-----BEGIN EC PUBLIC KEY-----",
            "-----BEGIN ECDSA PUBLIC KEY-----",
        ]
        let endMarkers = [
            "-----END PUBLIC KEY-----",
            "-----END EC PUBLIC KEY-----",
            "-----END ECDSA PUBLIC KEY-----",
        ]

        // Extract base64 content by removing all markers
        var base64Content = normalizedPEM
        for marker in beginMarkers + endMarkers {
            base64Content = base64Content.replacingOccurrences(of: marker, with: "")
        }

        // Remove all whitespace and newlines
        base64Content = base64Content.components(separatedBy: .whitespacesAndNewlines).joined()

        // Validate we have content
        guard !base64Content.isEmpty else {
            throw KASRewrapError.pemParsingFailed("Empty PEM content")
        }

        // Decode base64
        guard let keyData = Data(base64Encoded: base64Content) else {
            throw KASRewrapError.pemParsingFailed("Invalid base64 encoding")
        }

        // Parse public key - support multiple formats
        do {
            let publicKey: P256.KeyAgreement.PublicKey

            if keyData.count == 65, keyData[0] == 0x04 {
                // Raw uncompressed SEC1 point (0x04 || x || y)
                publicKey = try P256.KeyAgreement.PublicKey(x963Representation: keyData)
            } else if keyData.count == 33, keyData[0] == 0x02 || keyData[0] == 0x03 {
                // Compressed SEC1 point (0x02/0x03 || x)
                publicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: keyData)
            } else if keyData.count >= 70 {
                // SPKI DER format (91 bytes typical for P-256)
                publicKey = try P256.KeyAgreement.PublicKey(derRepresentation: keyData)
            } else {
                throw KASRewrapError.pemParsingFailed("Unrecognized key format: \(keyData.count) bytes")
            }

            let compressedKey = publicKey.compressedRepresentation

            // Validate compressed key size
            guard compressedKey.count == 33 else {
                throw KASRewrapError.pemParsingFailed("Invalid compressed key size: \(compressedKey.count)")
            }

            return compressedKey
        } catch let error as KASRewrapError {
            throw error
        } catch {
            throw KASRewrapError.pemParsingFailed("Failed to parse key: \(error.localizedDescription)")
        }
    }

    /// Create a signed JWT using ES256 algorithm
    /// - Parameters:
    ///   - requestBody: The request body data to include in claims
    ///   - signingKey: P256 private key for signing
    /// - Returns: Signed JWT string in format header.payload.signature
    private func createSignedJWT(requestBody: Data, signingKey: P256.Signing.PrivateKey) throws -> String {
        // Create header with ES256 algorithm
        let header = ["alg": "ES256", "typ": "JWT"]
        let headerJSON = try JSONSerialization.data(withJSONObject: header)
        let headerBase64 = headerJSON.base64URLEncodedString()

        // Create claims with the request body and required timestamps
        let now = Int(Date().timeIntervalSince1970)
        let requestBodyString = String(data: requestBody, encoding: .utf8) ?? ""
        let claims: [String: Any] = [
            "requestBody": requestBodyString,
            "iat": now,
            "exp": now + 60,
        ]
        let claimsJSON = try JSONSerialization.data(withJSONObject: claims)
        let claimsBase64 = claimsJSON.base64URLEncodedString()

        // Create signature over header.payload
        let signingInput = "\(headerBase64).\(claimsBase64)".data(using: .utf8)!
        let signature = try signingKey.signature(for: signingInput)
        let signatureBase64 = signature.rawRepresentation.base64URLEncodedString()

        return "\(headerBase64).\(claimsBase64).\(signatureBase64)"
    }
}

public struct TDFKASRewrapResult {
    public let wrappedKeys: [String: Data]
    public let sessionPublicKeyPEM: String?
}

/// Errors specific to KAS rewrap operations
public enum KASRewrapError: Error, CustomStringConvertible {
    case invalidResponse
    case emptyResponse
    case accessDenied(String)
    case authenticationFailed(String?)
    case missingWrappedKey
    case missingSessionKey
    case invalidWrappedKeyFormat
    case pemParsingFailed(String)
    case jwtSigningFailed(Error)
    case httpError(Int, String?)
    case invalidTDFRequest(String)
    case keyFetchFailed(String)
    case invalidEcPublicKey(String)
    case unsupportedKeyAlgorithm(String)

    public var description: String {
        switch self {
        case .invalidResponse:
            "Invalid response from KAS server"
        case .emptyResponse:
            "Empty response from KAS server"
        case let .accessDenied(reason):
            "Access denied: \(reason)"
        case let .authenticationFailed(reason):
            "Authentication failed - check OAuth token" + (reason.map { ": \($0)" } ?? "")
        case .missingWrappedKey:
            "KAS response missing wrapped key"
        case .missingSessionKey:
            "KAS response missing session public key"
        case .invalidWrappedKeyFormat:
            "Invalid wrapped key format"
        case let .pemParsingFailed(reason):
            "PEM parsing failed: \(reason)"
        case let .jwtSigningFailed(error):
            "JWT signing failed: \(error.localizedDescription)"
        case let .httpError(code, message):
            "HTTP error \(code)" + (message.map { ": \($0)" } ?? "")
        case let .invalidTDFRequest(reason):
            "Invalid standard TDF rewrap request: \(reason)"
        case let .keyFetchFailed(reason):
            "Failed to fetch KAS public key: \(reason)"
        case let .invalidEcPublicKey(reason):
            "Invalid EC public key: \(reason)"
        case let .unsupportedKeyAlgorithm(algorithm):
            "Unsupported key algorithm: \(algorithm)"
        }
    }
}

// Use the existing EphemeralKeyPair from KeyStore

/// Extension for base64URL encoding
extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    func hexEncodedString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}
