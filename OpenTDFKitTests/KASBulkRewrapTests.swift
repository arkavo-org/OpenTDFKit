@preconcurrency import CryptoKit
@testable import OpenTDFKit
import XCTest

/// `KASRewrapClient.rewrapAndUnwrapTDFs(_:options:)` against a fake KAS built
/// from the platform's wire behaviour (`service/kas/access/rewrap.go`), not
/// from the library: per-policy results in arbitrary order, one session key
/// per response, per-KAO errors serialized as Connect error strings, entries
/// with an empty policy id dropped. It also refuses duplicate policy ids with
/// a 400, which is stricter than the platform (a repeat overwrites results).
final class KASBulkRewrapTests: XCTestCase {
    private static let kasBaseURL = "https://kas.example.com"

    // Batch-wide per-KAO error strings exactly as the platform serializes them
    // (`connect.NewError(code, errors.Join(ErrUser|ErrInternal, status.Error(...))).Error()`).
    private static let accessCheckError = "internal: internal error\nrpc error: code = Internal desc = could not perform access"
    private static let invalidRequestError = "invalid_argument: request error\nrpc error: code = InvalidArgument desc = invalid request"

    // MARK: - Per-entry outcomes

    /// Permits and denials in one call come back per TDF, in input order,
    /// even though the fake KAS answers policies in reverse order.
    func testMixedPermitAndDenyReturnInInputOrder() async throws {
        let kas = FakeBulkKAS()
        let outcomes = try await makeClient(kas).rewrapAndUnwrapTDFs([
            makeManifest(dek: 1),
            makeManifest(dek: 2, mode: "deny"),
            makeManifest(dek: 3),
        ])

        XCTAssertEqual(outcomes.map(Self.describe), ["permitted:01", "denied", "permitted:03"])
        let requestCount = await kas.requests.count
        XCTAssertEqual(requestCount, 1, "three policies fit in one Rewrap call")
    }

    /// A policy the KAS returns nothing for is a per-entry failure, not a
    /// denial and not a batch error.
    func testMissingResultIsFailed() async throws {
        let outcomes = try await makeClient(FakeBulkKAS()).rewrapAndUnwrapTDFs([
            makeManifest(dek: 1),
            makeManifest(dek: 2, mode: "omit"),
        ])
        XCTAssertEqual(outcomes.map(Self.describe), ["permitted:01", "failed:noResult"])
    }

    /// A generic "bad request" marks possible tamper (binding or DEK failure)
    /// and is reported as a failure distinct from a denial.
    func testBadRequestIsTamperSuspected() async throws {
        let outcomes = try await makeClient(FakeBulkKAS()).rewrapAndUnwrapTDFs([
            makeManifest(dek: 1, mode: "tamper"),
            makeManifest(dek: 2),
        ])
        XCTAssertEqual(outcomes.map(Self.describe), ["failed:tamperSuspected", "permitted:02"])
    }

    /// Every entry denied is N denials, not a batch failure: denials are the
    /// answer, not an outage.
    func testAllDeniedIsPerEntryNotBatchFailure() async throws {
        let outcomes = try await makeClient(FakeBulkKAS()).rewrapAndUnwrapTDFs([
            makeManifest(dek: 1, mode: "deny"),
            makeManifest(dek: 2, mode: "deny"),
        ])
        XCTAssertEqual(outcomes.map(Self.describe), ["denied", "denied"])
    }

    /// The KAS sends one `sessionPublicKey` per response; every result in it
    /// must open with the KEK derived from that one key.
    func testOneSessionKeyOpensEveryResult() async throws {
        let kas = FakeBulkKAS()
        let outcomes = try await makeClient(kas).rewrapAndUnwrapTDFs((1 ... 40).map { makeManifest(dek: UInt8($0)) })

        XCTAssertEqual(outcomes.map(Self.describe), (1 ... 40).map { String(format: "permitted:%02x", $0) })
        let sessionKeys = await kas.sessionKeysIssued
        XCTAssertEqual(sessionKeys, 1, "the fake issued a single session key for the whole response")
    }

    /// Manifests that cannot be answered by this KAS fail locally and are
    /// never sent.
    func testManifestsThisKASCannotAnswerFailWithoutBeingSent() async throws {
        let kas = FakeBulkKAS()
        let outcomes = try await makeClient(kas).rewrapAndUnwrapTDFs([
            makeManifest(dek: 1, kasURLs: ["https://other.example.com/kas"]),
            makeManifest(dek: 2, sids: ["split-a", "split-b"]),
            makeManifest(dek: 3, policyBody: "not base64!"),
            makeManifest(dek: 4),
        ])

        XCTAssertEqual(outcomes.map(Self.describe), [
            "failed:noKeyAccess", "failed:splitKey", "failed:invalidManifest", "permitted:04",
        ])
        let sentPolicies = await kas.requests.flatMap(\.policyIDs)
        XCTAssertEqual(sentPolicies.count, 1, "only the answerable manifest reaches the KAS")
    }

    /// A result for a KAO id this client never sent is ignored, even a permit.
    func testResultForUnsentKAOIsIgnored() async throws {
        let outcomes = try await makeClient(FakeBulkKAS()).rewrapAndUnwrapTDFs([
            makeManifest(dek: 1, mode: "foreign"),
        ])
        XCTAssertEqual(outcomes.map(Self.describe), ["permitted:01"])
    }

    /// A wrapped key that will not open fails only its own TDF.
    func testCorruptWrappedKeyFailsOnlyItsEntry() async throws {
        let outcomes = try await makeClient(FakeBulkKAS()).rewrapAndUnwrapTDFs([
            makeManifest(dek: 1, mode: "corrupt"),
            makeManifest(dek: 2),
        ])
        XCTAssertEqual(outcomes.map(Self.describe), ["failed:unwrapFailed", "permitted:02"])
    }

    /// Several KAOs for one split at this KAS are alternatives for one DEK.
    func testAlternativeKAOsInOneSplitYieldOneKey() async throws {
        let outcomes = try await makeClient(FakeBulkKAS()).rewrapAndUnwrapTDFs([
            makeManifest(dek: 7, sids: ["s", "s"]),
        ])
        XCTAssertEqual(outcomes.map(Self.describe), ["permitted:07"])
    }

    func testEmptyInputSendsNothing() async throws {
        let kas = FakeBulkKAS()
        let outcomes = try await makeClient(kas).rewrapAndUnwrapTDFs([])
        XCTAssertTrue(outcomes.isEmpty)
        let requestCount = await kas.requests.count
        XCTAssertEqual(requestCount, 0)
    }

    // MARK: - Request shape

    /// The KAS drops entries with an empty policy id and keys results by id,
    /// so a repeated id loses an entry's results: each needs its own id.
    func testPolicyIDsAreUniqueAndNonEmpty() async throws {
        let kas = FakeBulkKAS()
        _ = try await makeClient(kas).rewrapAndUnwrapTDFs((1 ... 5).map { makeManifest(dek: UInt8($0)) })

        let ids = await kas.requests.flatMap(\.policyIDs)
        XCTAssertEqual(ids.count, 5)
        XCTAssertEqual(Set(ids).count, 5, "policy ids must not repeat: \(ids)")
        XCTAssertFalse(ids.contains(""), "policy ids must not be empty")
    }

    /// The call goes to the Connect Rewrap RPC with the bearer token.
    func testSendsConnectRewrapWithBearerToken() async throws {
        let kas = FakeBulkKAS()
        _ = try await makeClient(kas).rewrapAndUnwrapTDFs([makeManifest(dek: 1)])

        let first = await kas.requests.first
        let request = try XCTUnwrap(first)
        XCTAssertEqual(request.path, "/kas.AccessService/Rewrap")
        XCTAssertEqual(request.authorization, "Bearer test-token")
        XCTAssertEqual(request.connectProtocolVersion, "1")
    }

    // MARK: - Batching

    /// The KAS evaluates a call's policies in one decision request capped at
    /// 1,000 resources; a larger configured cap is clamped to it.
    func testSplitsAtOneThousandPolicies() async throws {
        let kas = FakeBulkKAS()
        let manifests = (0 ..< 1001).map { makeManifest(dek: UInt8($0 % 256)) }
        let outcomes = try await makeClient(kas).rewrapAndUnwrapTDFs(
            manifests,
            options: BulkRewrapOptions(maxPoliciesPerRequest: 5000),
        )

        let perRequest = await kas.requests.map(\.policyIDs.count)
        XCTAssertEqual(perRequest, [1000, 1])
        XCTAssertEqual(outcomes.map(Self.describe), (0 ..< 1001).map { String(format: "permitted:%02x", $0 % 256) })
    }

    func testSplitsAtConfiguredPolicyCount() async throws {
        let kas = FakeBulkKAS()
        let outcomes = try await makeClient(kas).rewrapAndUnwrapTDFs(
            (1 ... 5).map { makeManifest(dek: UInt8($0)) },
            options: BulkRewrapOptions(maxPoliciesPerRequest: 2),
        )

        let perRequest = await kas.requests.map(\.policyIDs.count)
        XCTAssertEqual(perRequest, [2, 2, 1])
        XCTAssertEqual(outcomes.map(Self.describe), ["permitted:01", "permitted:02", "permitted:03", "permitted:04", "permitted:05"])
    }

    /// Requests split by their measured encoded size, and no request sent
    /// exceeds the limit.
    func testSplitsByMeasuredBodySize() async throws {
        let kas = FakeBulkKAS()
        let limit = 8 * 1024
        let manifests = (1 ... 12).map { makeManifest(dek: UInt8($0), padding: 1000) }
        let outcomes = try await makeClient(kas).rewrapAndUnwrapTDFs(
            manifests,
            options: BulkRewrapOptions(maxRequestBodyBytes: limit),
        )

        let sizes = await kas.requests.map(\.bodySize)
        XCTAssertGreaterThan(sizes.count, 1, "twelve ~1 KB policies (~1.5 KB once signed) cannot fit in 8 KiB")
        for size in sizes {
            XCTAssertLessThanOrEqual(size, limit)
        }
        let sentPolicies = await kas.requests.flatMap(\.policyIDs)
        XCTAssertEqual(sentPolicies.count, 12, "each policy is sent exactly once")
        XCTAssertEqual(outcomes.map(Self.describe), (1 ... 12).map { String(format: "permitted:%02x", $0) })
    }

    /// An entry that cannot fit in any request under the limit fails alone.
    func testEntryLargerThanLimitFailsAlone() async throws {
        let kas = FakeBulkKAS()
        let outcomes = try await makeClient(kas).rewrapAndUnwrapTDFs(
            [makeManifest(dek: 1), makeManifest(dek: 2, padding: 8000), makeManifest(dek: 3)],
            options: BulkRewrapOptions(maxRequestBodyBytes: 4 * 1024),
        )
        XCTAssertEqual(outcomes.map(Self.describe), ["permitted:01", "failed:requestTooLarge", "permitted:03"])
        let sentPolicies = await kas.requests.flatMap(\.policyIDs)
        XCTAssertEqual(sentPolicies.count, 2)
    }

    // MARK: - Whole-batch failures

    /// The KAS fails every KAO with "could not perform access" when the
    /// access decision service is unreachable; that is an outage to retry,
    /// not N denials.
    func testAccessCheckUnavailableThrows() async {
        let kas = FakeBulkKAS(batchError: Self.accessCheckError)
        await assertThrows(.accessCheckUnavailable) {
            _ = try await self.makeClient(kas).rewrapAndUnwrapTDFs([self.makeManifest(dek: 1), self.makeManifest(dek: 2)])
        }
    }

    /// EC rewrap disabled or an unusable client key fails every KAO with
    /// "invalid request".
    func testInvalidRequestOnEveryKAOThrows() async {
        let kas = FakeBulkKAS(batchError: Self.invalidRequestError)
        await assertThrows(.requestRejected) {
            _ = try await self.makeClient(kas).rewrapAndUnwrapTDFs([self.makeManifest(dek: 1)])
        }
    }

    func testPermitWithoutSessionKeyThrows() async {
        let kas = FakeBulkKAS(includeSessionPublicKey: false)
        await assertThrows(.missingSessionKey) {
            _ = try await self.makeClient(kas).rewrapAndUnwrapTDFs([self.makeManifest(dek: 1)])
        }
    }

    func testUnauthenticatedThrows() async {
        let kas = FakeBulkKAS(httpStatus: 401, httpBody: #"{"code":"unauthenticated","message":"token expired"}"#)
        await assertThrows(.authenticationFailed) {
            _ = try await self.makeClient(kas).rewrapAndUnwrapTDFs([self.makeManifest(dek: 1)])
        }
    }

    /// Apps must not log server bodies, so the error carries the status only.
    func testHTTPErrorCarriesNoServerText() async throws {
        let kas = FakeBulkKAS(httpStatus: 500, httpBody: "stack trace with secret-server-detail")
        do {
            _ = try await makeClient(kas).rewrapAndUnwrapTDFs([makeManifest(dek: 1)])
            XCTFail("expected throw")
        } catch let error as BulkRewrapError {
            XCTAssertEqual(error, .httpError(500))
            XCTAssertFalse(String(describing: error).contains("secret-server-detail"))
            XCTAssertFalse(error.localizedDescription.contains("secret-server-detail"))
        }
    }

    // MARK: - Transport

    /// An injected transport carries every client request, not only bulk.
    func testInjectedTransportCarriesPublicKeyFetch() async throws {
        let kasKey = P256.KeyAgreement.PrivateKey().publicKey
        let transport = RecordingTransport(responseBody: Data(
            #"{"publicKey":"\#(kasKey.pemRepresentation.replacingOccurrences(of: "\n", with: "\\n"))"}"#.utf8,
        ))
        let client = try KASRewrapClient(
            configuration: OpenTDFConfiguration.forKasConnect(Self.kasBaseURL),
            oauthToken: "test-token",
            transport: transport,
        )

        let result = try await client.fetchKasEcPublicKey()

        XCTAssertEqual(result.compressedKey, kasKey.compressedRepresentation)
        let paths = await transport.paths
        XCTAssertEqual(paths, ["/kas.AccessService/PublicKey"])
    }

    /// The default transport returns a redirect instead of re-sending the
    /// bearer-carrying request to the redirect target.
    func testDefaultTransportDoesNotFollowRedirects() async throws {
        RedirectingURLProtocol.reset()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [RedirectingURLProtocol.self]
        let transport = URLSessionKASTransport(session: URLSession(configuration: configuration))
        var request = URLRequest(url: URL(string: "\(Self.kasBaseURL)/kas.AccessService/Rewrap")!)
        request.addValue("Bearer test-token", forHTTPHeaderField: "Authorization")

        let (_, response) = try await transport.send(request)

        XCTAssertEqual(response.statusCode, 307)
        XCTAssertEqual(RedirectingURLProtocol.requestedHosts, ["kas.example.com"])
    }

    // MARK: - Fixtures

    private func makeClient(_ transport: some KASRewrapTransport) throws -> KASRewrapClient {
        try KASRewrapClient(
            configuration: OpenTDFConfiguration.forKasConnect(Self.kasBaseURL),
            oauthToken: "test-token",
            transport: transport,
        )
    }

    /// A manifest whose KAO `wrappedKey` is the DEK itself (the fake KAS
    /// "unwraps" by base64-decoding), so each result is traceable to its TDF.
    /// `mode` in the policy JSON tells the fake KAS how to answer.
    private func makeManifest(
        dek: UInt8,
        mode: String = "permit",
        kasURLs: [String] = ["\(kasBaseURL)/kas"],
        sids: [String]? = nil,
        padding: Int = 0,
        policyBody: String? = nil,
    ) -> TDFManifest {
        let policyJSON = #"{"uuid":"u","body":{"dataAttributes":[],"dissem":[]},"mode":"\#(mode)","pad":"\#(String(repeating: "x", count: padding))"}"#
        let sidList = sids ?? kasURLs.map { _ in "split" }
        let urls = sids.map { Array(repeating: kasURLs[0], count: $0.count) } ?? kasURLs
        let keyAccess = zip(urls, sidList).map { url, sid in
            TDFKeyAccessObject(
                type: .ecWrapped,
                url: url,
                protocolValue: .kas,
                wrappedKey: Data(repeating: dek, count: 32).base64EncodedString(),
                policyBinding: TDFPolicyBinding(alg: "HS256", hash: "binding"),
                kid: "e1",
                sid: sid,
                ephemeralPublicKey: P256.KeyAgreement.PrivateKey().publicKey.pemRepresentation,
            )
        }
        return TDFManifest(
            schemaVersion: "4.3.0",
            payload: TDFPayloadDescriptor(type: .reference, url: "0.payload", protocolValue: .zip, isEncrypted: true),
            encryptionInformation: TDFEncryptionInformation(
                type: .split,
                keyAccess: keyAccess,
                method: TDFMethodDescriptor(algorithm: "AES-256-GCM", iv: "", isStreamable: true),
                policy: policyBody ?? Data(policyJSON.utf8).base64EncodedString(),
            ),
        )
    }

    /// `permitted:<first DEK byte>`, `denied`, or `failed:<reason>`.
    private static func describe(_ outcome: BulkRewrapOutcome) -> String {
        switch outcome {
        case let .permitted(key):
            let bytes = key.withUnsafeBytes { Data($0) }
            guard bytes.count == 32, Set(bytes).count == 1 else { return "permitted:corrupt" }
            return String(format: "permitted:%02x", bytes[0])
        case .denied:
            return "denied"
        case let .failed(reason):
            return "failed:\(reason)"
        }
    }

    private func assertThrows(
        _ expected: BulkRewrapError,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ body: () async throws -> Void,
    ) async {
        do {
            try await body()
            XCTFail("expected \(expected)", file: file, line: line)
        } catch let error as BulkRewrapError {
            XCTAssertEqual(error, expected, file: file, line: line)
        } catch {
            XCTFail("expected BulkRewrapError.\(expected), got \(type(of: error)): \(error)", file: file, line: line)
        }
    }
}

// MARK: - Fake KAS

/// What the fake KAS saw of one Rewrap call.
struct CapturedRewrap: Sendable {
    let path: String?
    let authorization: String?
    let connectProtocolVersion: String?
    let bodySize: Int
    let policyIDs: [String]
}

/// Fake KAS `Rewrap` transport. Per policy it reads `mode` from the policy
/// JSON: `permit` seals the KAO's DEK (its `wrappedKey`, base64) under the
/// session KEK (ECDH → HKDF-SHA256 with salt `SHA256("TDF")`, empty info →
/// AES-256-GCM `nonce || ct || tag`), `deny` fails with forbidden, `tamper`
/// with the generic bad request, `omit` returns no entry for the policy,
/// `corrupt` permits with a ciphertext that will not open, and `foreign`
/// adds a permit for a KAO id the client never sent.
/// `batchError` fails every KAO the same way, as the KAS's `failAllKaos` does.
actor FakeBulkKAS: KASRewrapTransport {
    private let batchError: String?
    private let includeSessionPublicKey: Bool
    private let httpStatus: Int
    private let httpBody: String
    private(set) var requests: [CapturedRewrap] = []
    private(set) var sessionKeysIssued = 0

    init(batchError: String? = nil, includeSessionPublicKey: Bool = true, httpStatus: Int = 200, httpBody: String = "") {
        self.batchError = batchError
        self.includeSessionPublicKey = includeSessionPublicKey
        self.httpStatus = httpStatus
        self.httpBody = httpBody
    }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let body = try XCTUnwrap(request.httpBody)
        let (clientPublicKey, policyRequests) = try Self.parse(body)
        let ids = try policyRequests.map { try XCTUnwrap(($0["policy"] as? [String: Any])?["id"] as? String) }
        requests.append(CapturedRewrap(
            path: request.url?.path,
            authorization: request.value(forHTTPHeaderField: "Authorization"),
            connectProtocolVersion: request.value(forHTTPHeaderField: "Connect-Protocol-Version"),
            bodySize: body.count,
            policyIDs: ids,
        ))

        guard httpStatus == 200 else {
            return (Data(httpBody.utf8), Self.response(request, status: httpStatus))
        }
        // Stricter than the platform, which lets a repeated policy id
        // overwrite the earlier entry's results: refuse it outright.
        guard Set(ids).count == ids.count else {
            return (Data(#"{"code":"invalid_argument","message":"duplicate policy id"}"#.utf8), Self.response(request, status: 400))
        }

        let sessionKey = P256.KeyAgreement.PrivateKey()
        sessionKeysIssued += 1
        let kek = try sessionKey.sharedSecretFromKeyAgreement(with: clientPublicKey).hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Data(SHA256.hash(data: Data("TDF".utf8))), sharedInfo: Data(), outputByteCount: 32,
        )

        var responses: [[String: Any]] = []
        // Answer in reverse so clients must match by id, not position.
        for policyRequest in policyRequests.reversed() {
            let policy = try XCTUnwrap(policyRequest["policy"] as? [String: Any])
            let id = try XCTUnwrap(policy["id"] as? String)
            guard !id.isEmpty else { continue } // the KAS drops these silently
            let mode = try Self.mode(ofPolicyBody: XCTUnwrap(policy["body"] as? String))
            if mode == "omit" {
                continue
            }
            let kaos = try XCTUnwrap(policyRequest["keyAccessObjects"] as? [[String: Any]])
            let results: [[String: Any]] = try kaos.map { kao in
                let kaoID = try XCTUnwrap(kao["keyAccessObjectId"] as? String)
                if let batchError {
                    return ["keyAccessObjectId": kaoID, "status": "fail", "error": batchError]
                }
                switch mode {
                case "deny":
                    return ["keyAccessObjectId": kaoID, "status": "fail", "error": Self.forbidden]
                case "tamper":
                    return ["keyAccessObjectId": kaoID, "status": "fail", "error": Self.tamper]
                default:
                    let object = try XCTUnwrap(kao["keyAccessObject"] as? [String: Any])
                    let dek = try XCTUnwrap(Data(base64Encoded: XCTUnwrap(object["wrappedKey"] as? String)))
                    var sealed = try XCTUnwrap(AES.GCM.seal(dek, using: kek).combined)
                    if mode == "corrupt" {
                        sealed[sealed.count - 1] ^= 0x01
                    }
                    return ["keyAccessObjectId": kaoID, "status": "permit", "kasWrappedKey": sealed.base64EncodedString()]
                }
            }
            var policyResults = results
            if mode == "foreign" {
                // A permit for a KAO id the client never sent, ahead of the real one.
                let sealed = try XCTUnwrap(AES.GCM.seal(Data(repeating: 0xEE, count: 32), using: kek).combined)
                policyResults.insert(
                    ["keyAccessObjectId": "kao-foreign", "status": "permit", "kasWrappedKey": sealed.base64EncodedString()],
                    at: 0,
                )
            }
            responses.append(["policyId": id, "results": policyResults])
        }

        var json: [String: Any] = ["responses": responses]
        if includeSessionPublicKey, batchError == nil {
            json["sessionPublicKey"] = sessionKey.publicKey.pemRepresentation
        }
        return try (JSONSerialization.data(withJSONObject: json), Self.response(request, status: 200))
    }

    private static let forbidden = "permission_denied: request error\nrpc error: code = PermissionDenied desc = forbidden"
    private static let tamper = "invalid_argument: request error\nrpc error: code = InvalidArgument desc = bad request"

    private static func response(_ request: URLRequest, status: Int) -> HTTPURLResponse {
        HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil,
                        headerFields: ["Content-Type": "application/json"])!
    }

    private static func mode(ofPolicyBody body: String) throws -> String {
        let json = try XCTUnwrap(Data(base64Encoded: body))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: json) as? [String: Any])
        return object["mode"] as? String ?? "permit"
    }

    /// `signed_request_token` → JWT claims → `requestBody` → client key and policy requests.
    private static func parse(_ body: Data) throws -> (P256.KeyAgreement.PublicKey, [[String: Any]]) {
        let envelope = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        let jwt = try XCTUnwrap(envelope["signed_request_token"] as? String)
        let parts = jwt.split(separator: ".")
        XCTAssertEqual(parts.count, 3, "ES256 JWT must have three segments")
        let claimsData = try XCTUnwrap(Data(base64URLDecoded: String(parts[1])))
        let claims = try XCTUnwrap(JSONSerialization.jsonObject(with: claimsData) as? [String: Any])
        let requestBody = try XCTUnwrap(claims["requestBody"] as? String)
        let unsigned = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(requestBody.utf8)) as? [String: Any])
        let clientPEM = try XCTUnwrap(unsigned["clientPublicKey"] as? String)
        let requests = try XCTUnwrap(unsigned["requests"] as? [[String: Any]])
        return try (P256.KeyAgreement.PublicKey(pemRepresentation: clientPEM), requests)
    }
}

/// Transport that answers every request with 200 and a fixed body, recording paths.
actor RecordingTransport: KASRewrapTransport {
    private let responseBody: Data
    private(set) var paths: [String] = []

    init(responseBody: Data) {
        self.responseBody = responseBody
    }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        paths.append(request.url?.path ?? "")
        let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                                       headerFields: ["Content-Type": "application/json"])!
        return (responseBody, response)
    }
}

/// Answers requests to kas.example.com with a 307 to another host, and every
/// other request with 200, recording the hosts it saw.
final class RedirectingURLProtocol: URLProtocol {
    private static let lock = NSLock()
    private nonisolated(unsafe) static var hosts: [String] = []

    static var requestedHosts: [String] {
        lock.withLock { hosts }
    }

    static func reset() {
        lock.withLock { hosts = [] }
    }

    override class func canInit(with _: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        let url = request.url!
        Self.lock.withLock { Self.hosts.append(url.host ?? "") }
        if url.host == "kas.example.com" {
            let target = URL(string: "https://collector.example.net/rewrap")!
            let response = HTTPURLResponse(url: url, statusCode: 307, httpVersion: nil,
                                           headerFields: ["Location": target.absoluteString])!
            client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: target), redirectResponse: response)
        }
        let response = HTTPURLResponse(url: url, statusCode: url.host == "kas.example.com" ? 307 : 200,
                                       httpVersion: nil, headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data())
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
