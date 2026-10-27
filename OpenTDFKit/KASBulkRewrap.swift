import CryptoKit
import Foundation

// MARK: - Public Types

/// The result of rewrapping one standard TDF in a bulk call.
public enum BulkRewrapOutcome: Sendable {
    /// The KAS permitted access; the value is the TDF's data encryption key.
    case permitted(SymmetricKey)
    /// The access decision denied this TDF's policy.
    case denied
    /// This TDF could not be rewrapped.
    case failed(BulkRewrapFailure)
}

/// Why one TDF in a bulk rewrap failed. Carries no server text.
public enum BulkRewrapFailure: String, Sendable, Equatable, CustomStringConvertible {
    /// The manifest has no key access object for this client's KAS.
    case noKeyAccess
    /// The manifest splits its key across more than one split ID, so this KAS
    /// alone cannot yield the DEK. Use `rewrapAndUnwrapTDFShares` at each KAS.
    case splitKey
    /// The manifest's policy or a wrapped key is not valid base64.
    case invalidManifest
    /// The KAS returned no result for this TDF.
    case noResult
    /// The KAS answered with its generic "bad request": a policy binding or
    /// wrapped key that does not verify, which may indicate tampering.
    case tamperSuspected
    /// The KAS rejected the key access object for a stated, non-tamper reason
    /// (for example an unsupported key type or a malformed ephemeral key).
    case rejected
    /// The KAS permitted access but the returned key did not open with the
    /// session key.
    case unwrapFailed

    public var description: String {
        rawValue
    }
}

/// Limits for the single Rewrap call a bulk rewrap makes.
public struct BulkRewrapOptions: Sendable {
    /// The KAS evaluates one call's policies in a single access decision
    /// capped at 1,000 resources; going over fails every key access object.
    public static let policyLimit = 1000
    /// Below the KAS's 4 MiB default request limit, with headroom.
    public static let defaultMaxRequestBodyBytes = 3 * 1024 * 1024

    /// Largest signed HTTP body to send, in bytes. Lower it when a front
    /// proxy limits request size more tightly than the KAS.
    public let maxRequestBodyBytes: Int

    /// - Parameter maxRequestBodyBytes: Measured on the signed body that would be sent.
    public init(maxRequestBodyBytes: Int = BulkRewrapOptions.defaultMaxRequestBodyBytes) {
        self.maxRequestBodyBytes = maxRequestBodyBytes
    }
}

/// A bulk rewrap failed as a whole, so no TDF has an outcome; the call can be
/// retried. Carries no server text, so it is safe to log.
public enum BulkRewrapError: Error, Sendable, Equatable, CustomStringConvertible, LocalizedError {
    /// The KAS rejected the bearer token (HTTP 401).
    case authenticationFailed
    /// The KAS refused the call before evaluating any policy (HTTP 403).
    case forbidden
    /// Any other non-200 status, such as an unverifiable signed request (400)
    /// or a proxy's size limit (413).
    case httpError(Int)
    /// Every key access object failed with "could not perform access": the
    /// KAS could not reach its access decision service.
    case accessCheckUnavailable
    /// Every key access object failed with "invalid request": the KAS has EC
    /// rewrap disabled or could not use the client key.
    case requestRejected
    /// The KAS permitted keys but sent no session public key to open them.
    case missingSessionKey
    /// The response is not a rewrap response this client can read, or holds
    /// no result at all.
    case malformedResponse
    /// The configured rewrap URL is not a valid URL.
    case invalidEndpoint
    /// More TDFs to send than `BulkRewrapOptions.policyLimit`; nothing was
    /// sent. Split the list and call once per part.
    case tooManyPolicies(Int)
    /// The signed request (its size in bytes) exceeds
    /// `BulkRewrapOptions.maxRequestBodyBytes`; nothing was sent. Split the
    /// list and call once per part.
    case requestTooLarge(Int)

    public var description: String {
        switch self {
        case .authenticationFailed: "Bulk rewrap: authentication failed (HTTP 401)"
        case .forbidden: "Bulk rewrap: call refused (HTTP 403)"
        case let .httpError(status): "Bulk rewrap: HTTP \(status)"
        case .accessCheckUnavailable: "Bulk rewrap: KAS could not perform the access check"
        case .requestRejected: "Bulk rewrap: KAS rejected the request for every key access object"
        case .missingSessionKey: "Bulk rewrap: KAS response missing session public key"
        case .malformedResponse: "Bulk rewrap: unreadable or empty KAS response"
        case .invalidEndpoint: "Bulk rewrap: invalid rewrap URL"
        case let .tooManyPolicies(count): "Bulk rewrap: \(count) TDFs exceed the \(BulkRewrapOptions.policyLimit)-policy limit"
        case let .requestTooLarge(bytes): "Bulk rewrap: \(bytes)-byte request exceeds the size limit"
        }
    }

    public var errorDescription: String? {
        description
    }
}

// MARK: - Bulk Rewrap

public extension KASRewrapClient {
    /// Rewraps many standard TDFs at this client's KAS in one Rewrap call
    /// and unwraps each permitted DEK.
    ///
    /// Each manifest is one policy request with its own id; its key access
    /// objects for this KAS are alternatives for one DEK (a split-key manifest
    /// fails with `.splitKey`). Manifests this KAS cannot answer fail locally
    /// and are not sent. The rest go in one request, so the outcome is
    /// all-or-nothing: more than `BulkRewrapOptions.policyLimit` of them, or
    /// a signed body over `options.maxRequestBodyBytes`, is refused before
    /// anything is sent, and the caller splits the list.
    ///
    /// Results are matched by policy and key access object id, not position.
    /// The response's one session key is derived once and opens every result.
    /// The client key exists only for the duration of the call.
    ///
    /// - Parameters:
    ///   - manifests: The TDFs to rewrap.
    ///   - options: Request size limit.
    /// - Returns: One outcome per manifest, in input order.
    /// - Throws: `BulkRewrapError` when the request is over a limit, or when
    ///   the call fails as a whole (HTTP error, access check unavailable,
    ///   unreadable response), so the caller can retry rather than read it as
    ///   denials; errors from the transport (including cancellation)
    ///   propagate unchanged.
    func rewrapAndUnwrapTDFs(
        _ manifests: [TDFManifest],
        options: BulkRewrapOptions = BulkRewrapOptions(),
    ) async throws -> [BulkRewrapOutcome] {
        var outcomes = [BulkRewrapOutcome?](repeating: nil, count: manifests.count)
        var entries: [BulkEntry] = []
        for (index, manifest) in manifests.enumerated() {
            switch bulkEntry(for: manifest, index: index) {
            case let .ready(entry): entries.append(entry)
            case let .unsendable(reason): outcomes[index] = .failed(reason)
            }
        }

        if !entries.isEmpty {
            guard entries.count <= BulkRewrapOptions.policyLimit else {
                throw BulkRewrapError.tooManyPolicies(entries.count)
            }
            let clientKey = P256.KeyAgreement.PrivateKey()
            let body = try BulkSigner(client: self, clientKey: clientKey).body(for: entries)
            guard body.count <= options.maxRequestBodyBytes else {
                throw BulkRewrapError.requestTooLarge(body.count)
            }
            for (index, outcome) in try await sendBulkRewrap(body: body, batch: entries, clientKey: clientKey) {
                outcomes[index] = outcome
            }
        }
        return outcomes.map { $0 ?? .failed(.noResult) }
    }
}

/// A manifest's policy request, or why it cannot be sent.
enum BulkEntryPreparation {
    case ready(BulkEntry)
    case unsendable(BulkRewrapFailure)
}

/// One manifest's policy request, ready to send.
struct BulkEntry {
    /// Position in the caller's input.
    let index: Int
    let request: KASRewrapClient.StandardPolicyRequest

    var policyID: String {
        request.policy.id
    }
}

/// Signs bulk request bodies for one call with one client key.
private struct BulkSigner {
    let client: KASRewrapClient
    let clientPublicKeyPEM: String
    let signingKey: P256.Signing.PrivateKey

    init(client: KASRewrapClient, clientKey: P256.KeyAgreement.PrivateKey) throws {
        self.client = client
        clientPublicKeyPEM = clientKey.publicKey.pemRepresentation
        signingKey = try P256.Signing.PrivateKey(rawRepresentation: clientKey.rawRepresentation)
    }

    func body(for entries: some Collection<BulkEntry>) throws -> Data {
        let unsigned = KASRewrapClient.StandardUnsignedRewrapRequest(
            clientPublicKey: clientPublicKeyPEM,
            requests: entries.map(\.request),
        )
        return try client.signedRewrapBody(requestBody: bulkEncoder.encode(unsigned), signingKey: signingKey)
    }
}

private let bulkEncoder: JSONEncoder = {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.withoutEscapingSlashes]
    return encoder
}()

/// The Rewrap response shape, tolerating the empty fields Connect JSON omits.
private struct BulkRewrapResponse: Decodable {
    struct PolicyResults: Decodable {
        let policyId: String
        let results: [KASRewrapClient.KASResult]

        private enum CodingKeys: String, CodingKey {
            case policyId, results
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            policyId = try container.decodeIfPresent(String.self, forKey: .policyId) ?? ""
            results = try container.decodeIfPresent([KASRewrapClient.KASResult].self, forKey: .results) ?? []
        }
    }

    let responses: [PolicyResults]
    let sessionPublicKey: String?

    private enum CodingKeys: String, CodingKey {
        case responses, sessionPublicKey
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        responses = try container.decodeIfPresent([PolicyResults].self, forKey: .responses) ?? []
        sessionPublicKey = try container.decodeIfPresent(String.self, forKey: .sessionPublicKey)
    }
}

/// Substrings of the platform's serialized per-KAO errors
/// (`connect.NewError(code, status.Error(code, desc)).Error()`), anchored on
/// the gRPC code or description as the Go SDK does.
private enum KASResultError {
    static let permissionDenied = "PermissionDenied"
    static let genericBadRequest = "desc = bad request"
    static let accessCheckFailed = "desc = could not perform access"
    static let invalidRequest = "desc = invalid request"
}

extension KASRewrapClient {
    /// Builds a manifest's policy request (id `policy-<index>`), or the reason
    /// it cannot be sent to this KAS.
    func bulkEntry(for manifest: TDFManifest, index: Int) -> BulkEntryPreparation {
        let keyAccessEntries = keyAccessObjects(in: manifest)
        guard !keyAccessEntries.isEmpty else {
            return .unsendable(.noKeyAccess)
        }
        guard Set(manifest.encryptionInformation.keyAccess.map { $0.sid ?? "" }).count <= 1 else {
            return .unsendable(.splitKey)
        }
        guard let request = try? standardPolicyRequest(
            manifest: manifest,
            keyAccessEntries: keyAccessEntries,
            policyID: "policy-\(index)",
        ) else {
            return .unsendable(.invalidManifest)
        }
        return .ready(BulkEntry(index: index, request: request))
    }

    /// Sends the Rewrap call and maps its results to input positions.
    private func sendBulkRewrap(
        body: Data,
        batch: [BulkEntry],
        clientKey: P256.KeyAgreement.PrivateKey,
    ) async throws -> [(Int, BulkRewrapOutcome)] {
        let request: URLRequest
        do {
            request = try rewrapURLRequest(body: body)
        } catch {
            throw BulkRewrapError.invalidEndpoint
        }
        let (data, httpResponse) = try await transport.send(request)
        switch httpResponse.statusCode {
        case 200: break
        case 401: throw BulkRewrapError.authenticationFailed
        case 403: throw BulkRewrapError.forbidden
        default: throw BulkRewrapError.httpError(httpResponse.statusCode)
        }
        guard let response = try? JSONDecoder().decode(BulkRewrapResponse.self, from: data) else {
            throw BulkRewrapError.malformedResponse
        }

        let allResults = response.responses.flatMap(\.results)
        guard !allResults.isEmpty else {
            throw BulkRewrapError.malformedResponse
        }
        // The KAS fails every KAO alike (`failAllKaos`) when the call as a whole cannot proceed.
        if allResults.allSatisfy({ $0.status != "permit" && $0.error?.contains(KASResultError.accessCheckFailed) == true }) {
            throw BulkRewrapError.accessCheckUnavailable
        }
        if allResults.allSatisfy({ $0.status != "permit" && $0.error?.contains(KASResultError.invalidRequest) == true }) {
            throw BulkRewrapError.requestRejected
        }

        var sessionKEK: SymmetricKey?
        if allResults.contains(where: { $0.status == "permit" }) {
            guard let pem = response.sessionPublicKey, !pem.isEmpty else {
                throw BulkRewrapError.missingSessionKey
            }
            guard case let .p256(sessionPublicKey)? = try? Self.validateEcPublicKeyPEM(pem).key,
                  let shared = try? clientKey.sharedSecretFromKeyAgreement(with: sessionPublicKey)
            else {
                throw BulkRewrapError.malformedResponse
            }
            sessionKEK = shared.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Self.standardTDFSessionSalt,
                sharedInfo: Data(),
                outputByteCount: 32,
            )
        }

        var resultsByPolicy: [String: [KASResult]] = [:]
        for policy in response.responses {
            resultsByPolicy[policy.policyId, default: []].append(contentsOf: policy.results)
        }
        return batch.map { entry in
            let sentIDs = Set(entry.request.keyAccessObjects.map(\.keyAccessObjectId))
            let results = (resultsByPolicy[entry.policyID] ?? []).filter { sentIDs.contains($0.keyAccessObjectId) }
            return (entry.index, Self.bulkOutcome(results, sessionKEK: sessionKEK))
        }
    }

    /// One TDF's outcome from its KAOs' results, which are alternatives for
    /// one DEK: any that opens is the DEK; tamper outranks a denial.
    private static func bulkOutcome(_ results: [KASResult], sessionKEK: SymmetricKey?) -> BulkRewrapOutcome {
        guard !results.isEmpty else {
            return .failed(.noResult)
        }
        var tamper = false
        var denied = false
        var unwrapFailed = false
        for result in results {
            if result.status == "permit" {
                if let sessionKEK,
                   let wrappedBase64 = result.kasWrappedKey ?? result.entityWrappedKey,
                   let wrapped = Data(base64Encoded: wrappedBase64),
                   let sealed = try? AES.GCM.SealedBox(combined: wrapped),
                   let dek = try? AES.GCM.open(sealed, using: sessionKEK)
                {
                    return .permitted(SymmetricKey(data: dek))
                }
                unwrapFailed = true
                continue
            }
            let error = result.error ?? ""
            if error.contains(KASResultError.genericBadRequest) {
                tamper = true
            } else if error.contains(KASResultError.permissionDenied) {
                denied = true
            }
        }
        if tamper {
            return .failed(.tamperSuspected)
        }
        if denied {
            return .denied
        }
        return .failed(unwrapFailed ? .unwrapFailed : .rejected)
    }
}
