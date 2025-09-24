import Foundation
import CryptoKit
import Darwin

/// Client for interacting with KAS rewrap endpoint for NanoTDF
public class KASRewrapClient {

    // MARK: - Request/Response Structures

    /// Key Access Object for NanoTDF rewrap
    public struct KeyAccessObject: Codable {
        let header: String  // Base64-encoded raw NanoTDF header bytes
        let type: String
        let url: String
        let `protocol`: String

        init(header: String, url: String) {
            self.header = header
            self.type = "remote"
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

    /// Policy structure
    public struct Policy: Codable {
        let id: String
        let body: String  // Base64-encoded policy

        init(body: String) {
            self.id = "policy"
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
            self.algorithm = "ec:secp256r1"
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
        let clientPublicKey: String  // Top-level field as per proto
        let requests: [RewrapRequestEntry]
    }

    /// Signed request wrapper
    public struct SignedRewrapRequest: Codable {
        let signed_request_token: String
    }

    /// Individual KAS result
    public struct KASResult: Codable {
        let keyAccessObjectId: String
        let status: String  // "permit" or "fail"
        let kasWrappedKey: String?
        let entityWrappedKey: String?  // Legacy field
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
        let entityWrappedKey: String?  // Legacy field at top level
        let metadata: [String: String]?
        let schemaVersion: String?
    }

    // MARK: - Properties

    private let kasURL: URL
    private let oauthToken: String
    private let urlSession: URLSession

    // MARK: - Initialization

    public init(kasURL: URL, oauthToken: String, urlSession: URLSession = .shared) {
        self.kasURL = kasURL
        self.oauthToken = oauthToken
        self.urlSession = urlSession
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
            url: kasURL.absoluteString
        )

        // Build the Key Access Object wrapper for v2 API
        let keyAccessWrapper = KeyAccessObjectWrapper(
            keyAccessObjectId: "kao-0",
            keyAccessObject: keyAccess
        )

        // Build the policy from the parsed header
        let policyBody: String
        if let policyBodyData = parsedHeader.policy.body?.body {
            fputs("DEBUG: Policy body data exists, length: \(policyBodyData.count)\n", stderr)
            if parsedHeader.policy.type == .embeddedPlaintext {
                // For plaintext policies, send the actual JSON content
                if let jsonString = String(data: policyBodyData, encoding: .utf8) {
                    fputs("DEBUG: Plaintext policy: \(jsonString)\n", stderr)
                    policyBody = policyBodyData.base64EncodedString()
                } else {
                    fputs("DEBUG: Failed to decode policy as UTF-8, sending as-is\n", stderr)
                    policyBody = policyBodyData.base64EncodedString()
                }
            } else {
                fputs("DEBUG: Encrypted policy, sending as base64\n", stderr)
                policyBody = policyBodyData.base64EncodedString()
            }
        } else {
            // Send empty JSON object for embedded plaintext policies
            fputs("DEBUG: No policy body, sending empty JSON\n", stderr)
            let emptyJSON = "{}".data(using: .utf8)!
            policyBody = emptyJSON.base64EncodedString()
        }
        let policy = Policy(body: policyBody)

        // Build the rewrap request entry
        let requestEntry = RewrapRequestEntry(
            policy: policy,
            keyAccessObjects: [keyAccessWrapper]
        )

        // Build the unsigned request with clientPublicKey at top level
        let clientPublicKeyPEM = String(data: clientKeyPair.publicKey, encoding: .utf8) ?? ""
        let unsignedRequest = UnsignedRewrapRequest(
            clientPublicKey: clientPublicKeyPEM,
            requests: [requestEntry]
        )

        // Encode to JSON
        let requestBodyJSON = try JSONEncoder().encode(unsignedRequest)


        // The KAS expects a signed JWT wrapper around the request body
        // For now, we'll create a simple unsigned JWT (alg: "none") for testing
        let signedToken = try createUnsignedJWT(requestBody: requestBodyJSON)
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
        fputs("DEBUG: Sending HTTP request to \(rewrapEndpoint.absoluteString)\n", stderr)
        let (data, response) = try await urlSession.data(for: request)
        fputs("DEBUG: Received HTTP response\n", stderr)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw KASRewrapError.invalidResponse
        }

        fputs("DEBUG: HTTP Status: \(httpResponse.statusCode)\n", stderr)

        switch httpResponse.statusCode {
        case 200:
            // Parse response
            fputs("DEBUG: Parsing JSON response...\n", stderr)
            let rewrapResponse = try JSONDecoder().decode(RewrapResponse.self, from: data)
            fputs("DEBUG: Parsed response successfully\n", stderr)

            fputs("DEBUG: Checking response structure...\n", stderr)
            guard let firstPolicy = rewrapResponse.responses.first,
                  let firstResult = firstPolicy.results.first else {
                fputs("DEBUG: Empty response\n", stderr)
                throw KASRewrapError.emptyResponse
            }

            fputs("DEBUG: Status: \(firstResult.status)\n", stderr)

            // Print full result for debugging
            if let jsonData = try? JSONEncoder().encode(firstResult),
               let jsonString = String(data: jsonData, encoding: .utf8) {
                fputs("DEBUG: Full result: \(jsonString)\n", stderr)
            }

            guard firstResult.status == "permit" else {
                throw KASRewrapError.accessDenied("Access denied")
            }

            // Extract wrapped key (try kasWrappedKey first, then entityWrappedKey for legacy)
            fputs("DEBUG: Extracting wrapped key...\n", stderr)
            guard let wrappedKeyBase64 = firstResult.kasWrappedKey ?? firstResult.entityWrappedKey,
                  let wrappedKey = Data(base64Encoded: wrappedKeyBase64) else {
                throw KASRewrapError.missingWrappedKey
            }

            // Extract session public key from PEM format
            fputs("DEBUG: Extracting session key...\n", stderr)
            guard let sessionKeyPEM = rewrapResponse.sessionPublicKey else {
                throw KASRewrapError.missingSessionKey
            }

            // Extract the compressed key from PEM
            fputs("DEBUG: Converting PEM to compressed key...\n", stderr)
            let sessionKey = try extractCompressedKeyFromPEM(sessionKeyPEM)
            fputs("DEBUG: Returning wrapped key and session key\n", stderr)

            return (wrappedKey, sessionKey)

        case 401:
            throw KASRewrapError.authenticationFailed
        case 403:
            throw KASRewrapError.accessDenied("Forbidden")
        default:
            throw KASRewrapError.httpError(httpResponse.statusCode)
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
        clientPrivateKey: Data
    ) throws -> SymmetricKey {
        fputs("DEBUG unwrapKey: Starting key unwrap\n", stderr)
        fputs("DEBUG unwrapKey: wrappedKey = \(wrappedKey.hexEncodedString())\n", stderr)

        // Perform ECDH with session public key
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: clientPrivateKey)
        let publicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: sessionPublicKey)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        fputs("DEBUG unwrapKey: ECDH completed\n", stderr)

        // Derive symmetric key using HKDF
        // Use the same salt as NanoTDF encryption (SHA256 of magic + version)
        let salt = CryptoConstants.hkdfSalt // This is SHA256("L1L") for v12 compatibility

        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: Data(),
            outputByteCount: 32
        )
        fputs("DEBUG unwrapKey: Derived symmetric key\n", stderr)

        // Decrypt the wrapped key
        // The wrapped key format from platform is: nonce (12 bytes) + ciphertext + tag (16 bytes)
        // The platform KAS always uses 128-bit (16-byte) tags, so CryptoKit works here
        guard wrappedKey.count > 28 else { // 12 nonce + at least 16 tag
            throw KASRewrapError.invalidWrappedKeyFormat
        }

        // Use the SealedBox combined initializer which expects nonce+ciphertext+tag
        fputs("DEBUG unwrapKey: Using combined format (nonce+ciphertext+tag)\n", stderr)
        let sealedBox = try AES.GCM.SealedBox(combined: wrappedKey)
        fputs("DEBUG unwrapKey: Created sealed box, attempting decrypt\n", stderr)

        let decryptedKey = try AES.GCM.open(sealedBox, using: symmetricKey)
        fputs("DEBUG unwrapKey: Decryption successful, key size: \(decryptedKey.count) bytes\n", stderr)

        return SymmetricKey(data: decryptedKey)
    }

    /// Extract compressed P256 public key from PEM format
    private func extractCompressedKeyFromPEM(_ pem: String) throws -> Data {
        fputs("DEBUG: PEM key received: \(pem.prefix(100))...\n", stderr)

        // Remove PEM headers and decode base64
        let pemLines = pem
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")

        guard let spkiData = Data(base64Encoded: pemLines) else {
            fputs("DEBUG: Failed to decode base64\n", stderr)
            throw KASRewrapError.invalidWrappedKeyFormat
        }

        fputs("DEBUG: SPKI data size: \(spkiData.count)\n", stderr)

        // For P-256 SPKI format, the uncompressed key is at the end
        // The structure is typically ~91 bytes total
        guard spkiData.count >= 91 else {
            fputs("DEBUG: SPKI data too short\n", stderr)
            throw KASRewrapError.invalidWrappedKeyFormat
        }

        // Use CryptoKit to parse the SPKI format directly
        do {
            // Try to create a P256 key from the SPKI data
            let publicKey = try P256.KeyAgreement.PublicKey(derRepresentation: spkiData)
            // Get the compressed representation
            let compressedKey = publicKey.compressedRepresentation
            fputs("DEBUG: Successfully extracted compressed key: \(compressedKey.count) bytes\n", stderr)
            return compressedKey
        } catch {
            fputs("DEBUG: CryptoKit parsing failed: \(error)\n", stderr)
            throw KASRewrapError.invalidWrappedKeyFormat
        }
    }

    /// Create an unsigned JWT for testing (alg: "none")
    private func createUnsignedJWT(requestBody: Data) throws -> String {
        // Create header with alg: "none"
        let header = ["alg": "none", "typ": "JWT"]
        let headerJSON = try JSONSerialization.data(withJSONObject: header)
        let headerBase64 = headerJSON.base64URLEncodedString()

        // Create claims with the request body and required timestamps
        let now = Int(Date().timeIntervalSince1970)
        let requestBodyString = String(data: requestBody, encoding: .utf8) ?? ""
        let claims: [String: Any] = [
            "requestBody": requestBodyString,
            "iat": now,
            "exp": now + 60  // SDK uses +60 seconds
        ]
        let claimsJSON = try JSONSerialization.data(withJSONObject: claims)
        let claimsBase64 = claimsJSON.base64URLEncodedString()

        // For unsigned JWT, signature is empty
        return "\(headerBase64).\(claimsBase64)."
    }
}

/// Errors specific to KAS rewrap operations
public enum KASRewrapError: Error {
    case invalidResponse
    case emptyResponse
    case accessDenied(String)
    case authenticationFailed
    case missingWrappedKey
    case missingSessionKey
    case invalidWrappedKeyFormat
    case httpError(Int)
}

// Use the existing EphemeralKeyPair from KeyStore

// Extension for base64URL encoding
extension Data {
    func base64URLEncodedString() -> String {
        return self.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    func hexEncodedString() -> String {
        return map { String(format: "%02x", $0) }.joined()
    }
}