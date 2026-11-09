@preconcurrency import CryptoKit
import Foundation

// MARK: - Verify a received Rewrap (KAS side)

public extension TDFKAS {
    /// Largest Rewrap body `verifyRewrapRequest` reads: 64 KiB, the owner-KAS relay's limit.
    static let maxRewrapRequestBytes = 65536

    /// `requestBody` members that are part of the Rewrap request itself; every
    /// other top-level member is an extension.
    internal static let standardRequestBodyMembers: Set<String> = [
        "clientPublicKey", "requests", "keyAccess", "policy", "algorithm", "schemaVersion",
    ]

    /// A Rewrap request whose signed request token verified.
    struct RewrapRequest: Sendable {
        /// The compact JWT as received.
        public let requestToken: String
        /// `TDFKAS.requestTokenDigest(requestToken)`.
        public let requestTokenDigest: Data
        public let issuedAt: Date?
        /// The token's `exp`, returned and not enforced: a KAS decides with its
        /// own clock, and can still answer an expired request with a signed denial.
        public let expiresAt: Date
        /// The key the KAS rewraps each permitted share to.
        public let clientPublicKey: P256.KeyAgreement.PublicKey
        public let policies: [Policy]
        /// Top-level `requestBody` members other than the standard ones, by name,
        /// each re-serialized as JSON with sorted keys and unescaped slashes:
        /// equal to the member as JSON, not byte-identical to how it was sent.
        /// They are covered by the signature.
        public let extensions: [String: Data]

        public struct Policy: Sendable {
            public let policyId: String
            /// The policy body as sent; the binding `TDFKAS.rewrap` checks is over
            /// this text.
            public let policyBase64: String
            public let keyAccessObjects: [KeyAccessEntry]
        }

        public struct KeyAccessEntry: Sendable {
            public let id: String
            public let keyAccessObject: TDFKeyAccessObject
        }
    }

    /// Verifies a received Rewrap body, `{"signed_request_token": "<JWT>"}`,
    /// under `signingPublicKey` (for an owner KAS, the bearer token's `cnf` key)
    /// and parses its `requestBody`.
    ///
    /// Checks, in order: the body is at most 64 KiB; it holds a string
    /// `signed_request_token` of three canonical (unpadded) base64url parts; the
    /// header's `alg` is `ES256` and it has no `crit`; the raw 64-byte signature
    /// verifies over `header.payload` as received; the claims hold a string
    /// `requestBody`, a numeric `exp` and, if present, a numeric `iat`; no JSON
    /// object anywhere repeats a member name; and `requestBody` holds a PEM P-256
    /// `clientPublicKey` and a non-empty `requests` array, each with
    /// `policy.id`, a base64 `policy.body` and non-empty key access objects.
    /// The token's `exp` is returned, not enforced.
    /// - Throws: `TDFKASError.requestTooLarge`, `.malformedRewrapRequest`,
    ///   `.unsupportedRequestAlgorithm` or `.requestSignatureInvalid`.
    static func verifyRewrapRequest(
        body: Data,
        signingPublicKey: P256.Signing.PublicKey,
    ) throws -> RewrapRequest {
        guard body.count <= maxRewrapRequestBytes else {
            throw TDFKASError.requestTooLarge
        }
        guard let envelope = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              !StrictJSON.hasDuplicateMembers(body),
              let token = envelope["signed_request_token"] as? String
        else {
            throw TDFKASError.malformedRewrapRequest("signed_request_token")
        }
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
              let headerData = canonicalBase64URL(parts[0]),
              let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any],
              !StrictJSON.hasDuplicateMembers(headerData)
        else {
            throw TDFKASError.malformedRewrapRequest("header")
        }
        guard header["crit"] == nil else {
            throw TDFKASError.malformedRewrapRequest("crit")
        }
        guard let alg = header["alg"] as? String else {
            throw TDFKASError.malformedRewrapRequest("alg")
        }
        guard alg == "ES256" else {
            throw TDFKASError.unsupportedRequestAlgorithm(alg)
        }
        guard let signatureData = canonicalBase64URL(parts[2]) else {
            throw TDFKASError.malformedRewrapRequest("signature")
        }
        guard signatureData.count == 64,
              let signature = try? P256.Signing.ECDSASignature(rawRepresentation: signatureData),
              signingPublicKey.isValidSignature(signature, for: Data("\(parts[0]).\(parts[1])".utf8))
        else {
            throw TDFKASError.requestSignatureInvalid
        }
        guard let claimsData = canonicalBase64URL(parts[1]),
              !StrictJSON.hasDuplicateMembers(claimsData),
              let claims = try? JSONDecoder().decode(TokenClaims.self, from: claimsData)
        else {
            throw TDFKASError.malformedRewrapRequest("claims")
        }

        let requestBodyData = Data(claims.requestBody.utf8)
        guard let requestBody = try? JSONSerialization.jsonObject(with: requestBodyData) as? [String: Any],
              !StrictJSON.hasDuplicateMembers(requestBodyData)
        else {
            throw TDFKASError.malformedRewrapRequest("requestBody")
        }
        guard let clientPEM = requestBody["clientPublicKey"] as? String,
              let clientPublicKey = try? parseEphemeralPublicKey(clientPEM)
        else {
            throw TDFKASError.malformedRewrapRequest("clientPublicKey")
        }
        guard let standard = try? JSONDecoder().decode(StandardBody.self, from: requestBodyData),
              !standard.requests.isEmpty
        else {
            throw TDFKASError.malformedRewrapRequest("requests")
        }
        let policies = try standard.requests.map { request in
            guard Data(base64Encoded: request.policy.body) != nil else {
                throw TDFKASError.malformedRewrapRequest("policy.body")
            }
            guard !request.keyAccessObjects.isEmpty else {
                throw TDFKASError.malformedRewrapRequest("keyAccessObjects")
            }
            return RewrapRequest.Policy(
                policyId: request.policy.id,
                policyBase64: request.policy.body,
                keyAccessObjects: request.keyAccessObjects.map {
                    RewrapRequest.KeyAccessEntry(id: $0.keyAccessObjectId, keyAccessObject: $0.keyAccessObject)
                },
            )
        }

        var extensions: [String: Data] = [:]
        for (name, value) in requestBody where !standardRequestBodyMembers.contains(name) {
            guard let json = try? JSONSerialization.data(
                withJSONObject: value, options: [.fragmentsAllowed, .sortedKeys, .withoutEscapingSlashes],
            ) else {
                throw TDFKASError.malformedRewrapRequest("extension")
            }
            extensions[name] = json
        }

        return RewrapRequest(
            requestToken: token,
            requestTokenDigest: requestTokenDigest(token),
            issuedAt: claims.iat.map { Date(timeIntervalSince1970: $0) },
            expiresAt: Date(timeIntervalSince1970: claims.exp),
            clientPublicKey: clientPublicKey,
            policies: policies,
            extensions: extensions,
        )
    }
}

// MARK: - Wire types

/// A JWS part decoded only if it is canonical base64url: no padding and no
/// stray bits, so one token has exactly one spelling and one digest.
private func canonicalBase64URL(_ part: Substring) -> Data? {
    guard let data = Data(base64URLEncoded: part), data.base64URLEncodedString() == part else {
        return nil
    }
    return data
}

private struct TokenClaims: Decodable {
    let requestBody: String
    let exp: Double
    let iat: Double?

    private enum CodingKeys: String, CodingKey {
        case requestBody
        case exp
        case iat
    }

    /// `iat` may be absent, but if present it must be a number (not `null`).
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        requestBody = try container.decode(String.self, forKey: .requestBody)
        exp = try container.decode(Double.self, forKey: .exp)
        iat = container.contains(.iat) ? try container.decode(Double.self, forKey: .iat) : nil
    }
}

private struct StandardBody: Decodable {
    struct Request: Decodable {
        struct Policy: Decodable {
            let id: String
            let body: String
        }

        struct Wrapper: Decodable {
            let keyAccessObjectId: String
            let keyAccessObject: TDFKeyAccessObject
        }

        let policy: Policy
        let keyAccessObjects: [Wrapper]
    }

    let requests: [Request]
}
