import CryptoKit
import Darwin
import Foundation

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
        let wrappedKey: String  // Base64-encoded RSA-wrapped DEK for Standard TDF
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

    // MARK: - Properties

    private let kasURL: URL
    private let oauthToken: String
    private let urlSession: URLSession
    private let signingKey: P256.Signing.PrivateKey

    // MARK: - Initialization

    /// Initialize KAS rewrap client with required parameters
    /// - Parameters:
    ///   - kasURL: The KAS endpoint URL
    ///   - oauthToken: OAuth bearer token for authentication
    ///   - urlSession: URLSession for network requests (defaults to .shared)
    ///   - signingKey: Optional P256 private key for JWT signing (generates new key if not provided)
    public init(kasURL: URL, oauthToken: String, urlSession: URLSession = .shared, signingKey: P256.Signing.PrivateKey? = nil) {
        self.kasURL = kasURL
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
            url: kasURL.absoluteString,
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
        let rewrapEndpoint = kasURL.appendingPathComponent("v2/rewrap")
        var request = URLRequest(url: rewrapEndpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = 30 // 30 second timeout

        let authHeader = "Bearer \(oauthToken)"
        request.addValue(authHeader, forHTTPHeaderField: "Authorization")
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(signedRequest)

        // Perform request
        let (data, response) = try await urlSession.data(for: request)

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
        case 400:
            let errorMessage = String(data: data, encoding: .utf8) ?? "Bad request"
            throw KASRewrapError.httpError(400, errorMessage)
        case 401:
            throw KASRewrapError.authenticationFailed
        case 403:
            let errorMessage = String(data: data, encoding: .utf8)
            throw KASRewrapError.accessDenied(errorMessage ?? "Forbidden")
        case 404:
            throw KASRewrapError.httpError(404, "KAS endpoint not found")
        case 500:
            throw KASRewrapError.httpError(500, "Internal server error")
        case 502:
            throw KASRewrapError.httpError(502, "Bad gateway - KAS service unavailable")
        case 503:
            throw KASRewrapError.httpError(503, "Service unavailable - try again later")
        case 504:
            throw KASRewrapError.httpError(504, "Gateway timeout")
        default:
            let errorMessage = String(data: data, encoding: .utf8)
            throw KASRewrapError.httpError(httpResponse.statusCode, errorMessage)
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
            throw KASRewrapError.invalidTDFRequest("No key access entries for KAS \(kasURL.absoluteString)")
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
                wrappedKey: kao.wrappedKey,  // Base64-encoded DEK encrypted with KAS public key
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

        let policy = Policy(body: policyBody)
        let policyRequest = StandardPolicyRequest(
            keyAccessObjects: wrappers,
            policy: policy,
            algorithm: "rsa:2048",  // Specify RSA algorithm for KAS
        )

        let unsignedRequest = StandardUnsignedRewrapRequest(
            clientPublicKey: clientPublicKeyPEM,
            requests: [policyRequest],
        )

        let requestBodyJSON = try JSONEncoder().encode(unsignedRequest)
        let signedToken = try createSignedJWT(requestBody: requestBodyJSON, signingKey: signingKey)
        let signedRequest = SignedRewrapRequest(signed_request_token: signedToken)

        let rewrapEndpoint = kasURL.appendingPathComponent("v2/rewrap")
        var request = URLRequest(url: rewrapEndpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = 30
        request.addValue("Bearer \(oauthToken)", forHTTPHeaderField: "Authorization")
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(signedRequest)

        let (data, response) = try await urlSession.data(for: request)

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
        case 400:
            let message = String(data: data, encoding: .utf8)
            throw KASRewrapError.httpError(400, message)
        case 401:
            throw KASRewrapError.authenticationFailed
        case 403:
            let message = String(data: data, encoding: .utf8)
            throw KASRewrapError.accessDenied(message ?? "Forbidden")
        case 404:
            throw KASRewrapError.httpError(404, "KAS endpoint not found")
        case 500:
            throw KASRewrapError.httpError(500, "Internal server error")
        case 502:
            throw KASRewrapError.httpError(502, "Bad gateway - KAS service unavailable")
        case 503:
            throw KASRewrapError.httpError(503, "Service unavailable - try again later")
        case 504:
            throw KASRewrapError.httpError(504, "Gateway timeout")
        default:
            let message = String(data: data, encoding: .utf8)
            throw KASRewrapError.httpError(httpResponse.statusCode, message)
        }
    }

    private func matchesKasURL(_ otherURLString: String) -> Bool {
        guard let otherURL = URL(string: otherURLString) else { return false }
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
    /// - Returns: The decrypted symmetric key
    public static func unwrapKey(
        wrappedKey: Data,
        sessionPublicKey: Data,
        clientPrivateKey: Data,
    ) throws -> SymmetricKey {
        // Perform ECDH with session public key
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: clientPrivateKey)
        let publicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: sessionPublicKey)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)

        // Derive symmetric key using HKDF
        // For Standard TDF rewrap: empty salt, empty info (matches KAS implementation)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
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
    case authenticationFailed
    case missingWrappedKey
    case missingSessionKey
    case invalidWrappedKeyFormat
    case pemParsingFailed(String)
    case jwtSigningFailed(Error)
    case httpError(Int, String?)
    case invalidTDFRequest(String)

    public var description: String {
        switch self {
        case .invalidResponse:
            "Invalid response from KAS server"
        case .emptyResponse:
            "Empty response from KAS server"
        case let .accessDenied(reason):
            "Access denied: \(reason)"
        case .authenticationFailed:
            "Authentication failed - check OAuth token"
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
        }
    }
}

// Use the existing EphemeralKeyPair from KeyStore

// Extension for base64URL encoding
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
