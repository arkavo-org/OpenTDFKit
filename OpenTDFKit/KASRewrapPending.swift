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

        let issuedAt = Int(now().timeIntervalSince1970)
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

// MARK: - Submit and poll

public extension KASRewrapClient {
    /// A Rewrap the KAS accepted but has not answered yet: poll `location` after
    /// `retryAfter` seconds. Holds no key; keep it to resume after an interruption.
    struct PendingRewrap: Sendable {
        /// Where to poll; always on the KAS's origin.
        public let location: URL
        public let retryAfter: TimeInterval
        public let requestTokenDigest: Data
        /// The signed request token's `exp`, which is the KAS's deadline.
        public let expiresAt: Date
        let keyAccessObjects: [TDFKeyAccessObject]
    }

    /// What `submitRewrap` got back.
    enum RewrapSubmission: Sendable {
        case answered(RewrapAnswer)
        case pending(PendingRewrap)
    }

    /// What `pollRewrap` ended with. `expired` and `deadlineReached` are never a
    /// denial: the KAS gave no answer.
    enum RewrapPollOutcome: Sendable {
        case answered(RewrapAnswer)
        /// The KAS's deadline passed (`410`, or `404` after `expiresAt`).
        case expired
        /// The caller's deadline came first; poll the handle again to resume.
        case deadlineReached(PendingRewrap)
    }

    /// `rewrap`'s outcome. `answered` carries the unwrapped share of every
    /// permitted result.
    enum RewrapOutcome: Sendable {
        case answered(RewrapAnswer, shares: [TDFKeyShare])
        case expired
        case deadlineReached(PendingRewrap)
    }

    /// A KAS's Rewrap response, every result kept: a denial is a result here,
    /// so the caller can verify what the KAS sent (for example an owner KAS's
    /// signed decision in `metadata`) before using any key.
    struct RewrapAnswer: Sendable {
        /// The digest of the signed request token this answers.
        public let requestTokenDigest: Data
        /// `nil` when the KAS permitted nothing.
        public let sessionPublicKey: P256.KeyAgreement.PublicKey?
        public let results: [KeyAccessResult]

        public struct KeyAccessResult: Sendable {
            public let keyAccessObjectId: String
            /// The split ID of the key access object `kao-<i>` this answers.
            public let sid: String?
            /// `permit`, `fail`, or whatever the KAS sent.
            public let status: String
            /// The share wrapped to the client's key, decoded from base64.
            public let kasWrappedKey: Data?
            public let error: String?
            public let metadata: [String: RewrapMetadataValue]
        }

        /// Unwraps one permitted result with `TDFKAS.unwrap` (TDF session salt).
        /// - Throws: `KASRewrapError.accessDenied` for a result that is not
        ///   `permit`, `.missingWrappedKey` / `.missingSessionKey` when the KAS
        ///   left them out, or `TDFKASError.keyUnwrapFailed`.
        public func share(
            for result: KeyAccessResult,
            clientPrivateKey: P256.KeyAgreement.PrivateKey,
        ) throws -> TDFKeyShare {
            guard result.status == "permit" else {
                throw KASRewrapError.accessDenied(result.error ?? "status=\(result.status)")
            }
            guard let wrappedKey = result.kasWrappedKey else {
                throw KASRewrapError.missingWrappedKey
            }
            guard let sessionPublicKey else {
                throw KASRewrapError.missingSessionKey
            }
            let key = try TDFKAS.unwrap(
                wrappedKey: wrappedKey,
                sessionPublicKey: sessionPublicKey,
                receiverPrivateKey: clientPrivateKey,
            )
            return TDFKeyShare(sid: result.sid, key: key)
        }
    }

    /// Sends a prepared Rewrap once. `200` is answered; `202` is pending, with
    /// its `Location` resolved against the Rewrap URL and refused unless it is
    /// on the same scheme, host and port. Never retries; resending the same
    /// `PreparedRewrap` is safe.
    /// - Throws: `KASRewrapError.pendingWithoutLocation`, `.unsafeLocation`, or
    ///   the error for any other HTTP status.
    func submitRewrap(_ prepared: PreparedRewrap) async throws -> RewrapSubmission {
        let (data, response) = try await transport.send(rewrapURLRequest(body: prepared.body))
        switch response.statusCode {
        case 200:
            return try .answered(answer(from: data, digest: prepared.requestTokenDigest,
                                        keyAccessObjects: prepared.keyAccessObjects))
        case 202:
            guard let location = response.value(forHTTPHeaderField: "Location"), !location.isEmpty else {
                throw KASRewrapError.pendingWithoutLocation
            }
            return try .pending(PendingRewrap(
                location: sameOriginLocation(location),
                retryAfter: Self.retryAfterSeconds(response.value(forHTTPHeaderField: "Retry-After")),
                requestTokenDigest: prepared.requestTokenDigest,
                expiresAt: prepared.expiresAt,
                keyAccessObjects: prepared.keyAccessObjects,
            ))
        default:
            throw mapRewrapHTTPError(status: response.statusCode, data: data)
        }
    }

    /// Polls a pending Rewrap with the same bearer, waiting `Retry-After` between
    /// polls, until it is answered (`200`), expires (`410`, or `404` at or after
    /// `expiresAt`), or the next wait would pass `deadline`.
    /// - Throws: `KASRewrapError.httpError` for any other status, including a
    ///   `404` before `expiresAt` (an unknown request: show the KAS as unavailable).
    func pollRewrap(_ pending: PendingRewrap, until deadline: Date) async throws -> RewrapPollOutcome {
        var current = pending
        while true {
            if now().addingTimeInterval(current.retryAfter) > deadline {
                return .deadlineReached(current)
            }
            try await sleeper(current.retryAfter)

            var request = URLRequest(url: current.location)
            request.httpMethod = "GET"
            request.timeoutInterval = 30
            request.addValue("Bearer \(oauthToken)", forHTTPHeaderField: "Authorization")
            let (data, response) = try await transport.send(request)

            switch response.statusCode {
            case 200:
                return try .answered(answer(from: data, digest: current.requestTokenDigest,
                                            keyAccessObjects: current.keyAccessObjects))
            case 202:
                current = PendingRewrap(
                    location: current.location,
                    retryAfter: Self.retryAfterSeconds(response.value(forHTTPHeaderField: "Retry-After")),
                    requestTokenDigest: current.requestTokenDigest,
                    expiresAt: current.expiresAt,
                    keyAccessObjects: current.keyAccessObjects,
                )
            case 410:
                return .expired
            case 404 where now() >= current.expiresAt:
                return .expired
            default:
                throw mapRewrapHTTPError(status: response.statusCode, data: data)
            }
        }
    }

    /// Prepares, submits and polls a Rewrap, and unwraps every permitted share.
    /// `deadline` defaults to the request token's `exp`. A cancelled task throws
    /// and loses the pending handle; a caller that must resume after an
    /// interruption calls the three steps itself.
    func rewrap(
        manifest: TDFManifest,
        clientPrivateKey: P256.KeyAgreement.PrivateKey,
        options: RewrapOptions = .init(),
        deadline: Date? = nil,
    ) async throws -> RewrapOutcome {
        let prepared = try prepareRewrap(manifest: manifest, clientPrivateKey: clientPrivateKey, options: options)
        let answer: RewrapAnswer
        switch try await submitRewrap(prepared) {
        case let .answered(immediate):
            answer = immediate
        case let .pending(pending):
            switch try await pollRewrap(pending, until: deadline ?? prepared.expiresAt) {
            case let .answered(polled):
                answer = polled
            case .expired:
                return .expired
            case let .deadlineReached(handle):
                return .deadlineReached(handle)
            }
        }
        let shares = try answer.results.filter { $0.status == "permit" }.map {
            try answer.share(for: $0, clientPrivateKey: clientPrivateKey)
        }
        return .answered(answer, shares: shares)
    }

    /// `Retry-After` as delta-seconds, clamped to 1–60; anything else (an
    /// HTTP-date, a negative value, nothing) is the default of 2 seconds.
    internal static func retryAfterSeconds(_ value: String?) -> TimeInterval {
        guard let value, let seconds = Int(value.trimmingCharacters(in: .whitespaces)), seconds >= 0 else {
            return 2
        }
        return TimeInterval(min(max(seconds, 1), 60))
    }
}

// MARK: - Helpers

extension KASRewrapClient {
    /// `location` resolved against the Rewrap URL, refused unless it keeps the
    /// Rewrap URL's scheme, host and effective port: the bearer token goes there.
    func sameOriginLocation(_ location: String) throws -> URL {
        guard let rewrapURL = URL(string: endpoints.rewrapURL),
              let resolved = URL(string: location, relativeTo: rewrapURL)?.absoluteURL,
              resolved.scheme?.lowercased() == rewrapURL.scheme?.lowercased(),
              resolved.host?.lowercased() == rewrapURL.host?.lowercased(),
              effectivePort(for: resolved) == effectivePort(for: rewrapURL)
        else {
            throw KASRewrapError.unsafeLocation(location)
        }
        return resolved
    }

    /// Maps a `200` Rewrap response body to a `RewrapAnswer`, keeping every
    /// result. Result `kao-<i>` takes the split ID of `keyAccessObjects[i]`.
    func answer(from data: Data, digest: Data, keyAccessObjects: [TDFKeyAccessObject]) throws -> RewrapAnswer {
        let response = try JSONDecoder().decode(RewrapResponse.self, from: data)
        let sessionPublicKey: P256.KeyAgreement.PublicKey?
        if let pem = response.sessionPublicKey, !pem.isEmpty {
            do {
                sessionPublicKey = try TDFKAS.parseEphemeralPublicKey(pem)
            } catch {
                throw KASRewrapError.invalidEcPublicKey("session public key is not a PEM P-256 key")
            }
        } else {
            sessionPublicKey = nil
        }
        let results = try response.responses.flatMap { policy in
            try policy.results.map { result in
                let wrapped = try (result.kasWrappedKey ?? result.entityWrappedKey).map { base64 in
                    guard let data = Data(base64Encoded: base64) else {
                        throw KASRewrapError.invalidWrappedKeyFormat
                    }
                    return data
                }
                let index = result.keyAccessObjectId.hasPrefix("kao-")
                    ? Int(result.keyAccessObjectId.dropFirst("kao-".count)) : nil
                let sid = index.flatMap { keyAccessObjects.indices.contains($0) ? keyAccessObjects[$0].sid : nil }
                return RewrapAnswer.KeyAccessResult(
                    keyAccessObjectId: result.keyAccessObjectId,
                    sid: sid,
                    status: result.status,
                    kasWrappedKey: wrapped,
                    error: result.error,
                    metadata: result.metadata ?? [:],
                )
            }
        }
        return RewrapAnswer(requestTokenDigest: digest, sessionPublicKey: sessionPublicKey, results: results)
    }
}
