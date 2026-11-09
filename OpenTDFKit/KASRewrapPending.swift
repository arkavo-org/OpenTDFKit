@preconcurrency import CryptoKit
import Foundation

// MARK: - Rewrap at a KAS that may answer later

/// A Rewrap path for a KAS that may answer with `202` and a `Location` to poll,
/// such as an owner KAS behind a relay, as well as a platform KAS that answers
/// at once. Unlike `rewrapTDF`, it signs with the client's init `signingKey`,
/// lets the caller set the signed request token's `exp` and add one extension
/// member, and returns every result (a denial is a result, not an error).
public extension KASRewrapClient {
    /// Options for `prepareRewrap`.
    struct RewrapOptions: Sendable {
        /// The signed request token's `exp`; `nil` means 60 seconds from now. An
        /// owner KAS needs it equal to the bearer token's `exp`.
        public var expiresAt: Date?
        /// One extra top-level `requestBody` member, covered by the signature.
        public var requestBodyExtension: RequestBodyExtension?

        public init(expiresAt: Date? = nil, requestBodyExtension: RequestBodyExtension? = nil) {
            self.expiresAt = expiresAt
            self.requestBodyExtension = requestBodyExtension
        }
    }

    /// A top-level `requestBody` member: its name, which must not be a standard
    /// member's, and its JSON value.
    struct RequestBodyExtension: Sendable {
        public let name: String
        public let json: Data

        public init(name: String, json: Data) {
            self.name = name
            self.json = json
        }
    }

    /// A signed Rewrap request as bytes. Submitting the same value again sends
    /// identical bytes, so a resend after a network failure is the same request.
    struct PreparedRewrap: Sendable {
        /// The HTTP body, `{"signed_request_token": "<JWT>"}`.
        public let body: Data
        public let requestToken: String
        /// `TDFKAS.requestTokenDigest(requestToken)`.
        public let requestTokenDigest: Data
        public let expiresAt: Date
        /// The key access objects sent, in `kao-<i>` order.
        let keyAccessObjects: [TDFKeyAccessObject]
    }

    /// Builds and signs a Rewrap request for this KAS's key access objects in
    /// `manifest`, without sending it. The policy is sent as the manifest's
    /// `encryptionInformation.policy` string, unchanged.
    /// - Parameters:
    ///   - manifest: The TDF's manifest.
    ///   - clientPrivateKey: The key the KAS rewraps to; its public key is sent.
    ///   - options: The token's `exp` and an optional extension member.
    /// - Throws: `KASRewrapError.invalidTDFRequest` when no key access object is
    ///   this KAS's, `.invalidRewrapOptions` for a past `exp` or a bad extension.
    func prepareRewrap(
        manifest: TDFManifest,
        clientPrivateKey: P256.KeyAgreement.PrivateKey,
        options: RewrapOptions = .init(),
    ) throws -> PreparedRewrap {
        let entries = keyAccessObjects(in: manifest)
        guard !entries.isEmpty else {
            throw KASRewrapError.invalidTDFRequest("No key access entries for this KAS")
        }
        let unsigned = try StandardUnsignedRewrapRequest(
            clientPublicKey: clientPrivateKey.publicKey.pemRepresentation,
            requests: [standardPolicyRequest(manifest: manifest, keyAccessEntries: entries)],
        )
        var requestBody = try JSONEncoder().encode(unsigned)

        if let member = options.requestBodyExtension {
            guard !TDFKAS.standardRequestBodyMembers.contains(member.name) else {
                throw KASRewrapError.invalidRewrapOptions("extension name '\(member.name)' is a standard member")
            }
            guard let value = try? JSONSerialization.jsonObject(with: member.json, options: [.fragmentsAllowed]),
                  var object = try JSONSerialization.jsonObject(with: requestBody) as? [String: Any]
            else {
                throw KASRewrapError.invalidRewrapOptions("extension '\(member.name)' is not JSON")
            }
            object[member.name] = value
            requestBody = try JSONSerialization.data(withJSONObject: object)
        }

        let issuedAt = Int(Date().timeIntervalSince1970)
        let expiresAt = options.expiresAt.map { Int($0.timeIntervalSince1970) } ?? issuedAt + 60
        guard expiresAt > issuedAt else {
            throw KASRewrapError.invalidRewrapOptions("expiresAt must be in the future")
        }
        let token = try createSignedJWT(
            requestBody: requestBody, signingKey: signingKey, issuedAt: issuedAt, expiresAt: expiresAt,
        )
        return try PreparedRewrap(
            body: JSONEncoder().encode(SignedRewrapRequest(signed_request_token: token)),
            requestToken: token,
            requestTokenDigest: TDFKAS.requestTokenDigest(token),
            expiresAt: Date(timeIntervalSince1970: TimeInterval(expiresAt)),
            keyAccessObjects: entries,
        )
    }
}
