@preconcurrency import CryptoKit
import Foundation
@testable import OpenTDFKit
import XCTest

/// `KASRewrapClient`'s path for a KAS that may answer later (an owner KAS):
/// prepare a signed request, submit it, and poll a pending answer.
final class KASRewrapPendingTests: XCTestCase {
    static let ownerURL = "https://platform.arkavo.net/owner-kas/v1/routes/01HZXK3Q8R4M5N6P7Q8R9S0T1V"
    let signingKey = P256.Signing.PrivateKey()
    let clientKey = P256.KeyAgreement.PrivateKey()
    let kasKey = P256.KeyAgreement.PrivateKey()

    // MARK: - prepareRewrap

    func testPreparedRequestVerifiesOnThePhone() throws {
        let expiresAt = Date().addingTimeInterval(900)
        let prepared = try makeClient().prepareRewrap(
            manifest: makeManifest(), clientPrivateKey: clientKey, options: .init(expiresAt: expiresAt),
        )
        let request = try TDFKAS.verifyRewrapRequest(body: prepared.body, signingPublicKey: signingKey.publicKey)
        XCTAssertEqual(request.requestTokenDigest, prepared.requestTokenDigest)
        XCTAssertEqual(request.requestToken, prepared.requestToken)
        XCTAssertEqual(request.expiresAt, prepared.expiresAt)
        XCTAssertEqual(Int(prepared.expiresAt.timeIntervalSince1970), Int(expiresAt.timeIntervalSince1970))
        XCTAssertEqual(request.clientPublicKey.x963Representation, clientKey.publicKey.x963Representation)
    }

    func testPolicyForwardedVerbatim() throws {
        let manifest = try makeManifest()
        let prepared = try makeClient().prepareRewrap(manifest: manifest, clientPrivateKey: clientKey)
        let request = try TDFKAS.verifyRewrapRequest(body: prepared.body, signingPublicKey: signingKey.publicKey)
        XCTAssertEqual(request.policies.first?.policyBase64, manifest.encryptionInformation.policy)
    }

    /// Signed with the init `signingKey` (an owner KAS's `cnf` key), not the
    /// client's ECDH key as `rewrapTDF` does.
    func testSignedWithInitSigningKeyNotClientKey() throws {
        let prepared = try makeClient().prepareRewrap(manifest: makeManifest(), clientPrivateKey: clientKey)
        let clientSigningKey = try P256.Signing.PrivateKey(rawRepresentation: clientKey.rawRepresentation)
        XCTAssertThrowsError(try TDFKAS.verifyRewrapRequest(
            body: prepared.body, signingPublicKey: clientSigningKey.publicKey,
        )) {
            XCTAssertEqual($0 as? TDFKASError, .requestSignatureInvalid)
        }
    }

    func testDefaultExpIsSixtySeconds() throws {
        let prepared = try makeClient().prepareRewrap(manifest: makeManifest(), clientPrivateKey: clientKey)
        let request = try TDFKAS.verifyRewrapRequest(body: prepared.body, signingPublicKey: signingKey.publicKey)
        let issuedAt = try XCTUnwrap(request.issuedAt)
        XCTAssertEqual(request.expiresAt.timeIntervalSince(issuedAt), 60)
    }

    func testCallerExp() throws {
        let expiresAt = Date(timeIntervalSince1970: (Date().timeIntervalSince1970 + 900).rounded(.down))
        let prepared = try makeClient().prepareRewrap(
            manifest: makeManifest(), clientPrivateKey: clientKey, options: .init(expiresAt: expiresAt),
        )
        let request = try TDFKAS.verifyRewrapRequest(body: prepared.body, signingPublicKey: signingKey.publicKey)
        XCTAssertEqual(request.expiresAt, expiresAt)
    }

    func testPastExpRefused() throws {
        XCTAssertThrowsError(try makeClient().prepareRewrap(
            manifest: makeManifest(), clientPrivateKey: clientKey,
            options: .init(expiresAt: Date().addingTimeInterval(-1)),
        )) { assertInvalidOptions($0) }
    }

    func testExtensionCoveredBySignature() throws {
        let json = Data(#"{"v":1,"attempt_id":"QUJD","nonce":"REVG","tdf_digest":"R0hJ"}"#.utf8)
        let prepared = try makeClient().prepareRewrap(
            manifest: makeManifest(), clientPrivateKey: clientKey,
            options: .init(requestBodyExtension: .init(name: "arkavo", json: json)),
        )
        let request = try TDFKAS.verifyRewrapRequest(body: prepared.body, signingPublicKey: signingKey.publicKey)
        let sent = try XCTUnwrap(JSONSerialization.jsonObject(with: json) as? NSDictionary)
        let received = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(request.extensions["arkavo"]))
            as? NSDictionary)
        XCTAssertEqual(received, sent)
    }

    func testExtensionNameCollisionRefused() throws {
        for name in ["clientPublicKey", "requests", "keyAccess", "policy", "algorithm", "schemaVersion"] {
            XCTAssertThrowsError(try makeClient().prepareRewrap(
                manifest: makeManifest(), clientPrivateKey: clientKey,
                options: .init(requestBodyExtension: .init(name: name, json: Data("{}".utf8))),
            )) { assertInvalidOptions($0) }
        }
    }

    func testExtensionMustBeJSON() throws {
        XCTAssertThrowsError(try makeClient().prepareRewrap(
            manifest: makeManifest(), clientPrivateKey: clientKey,
            options: .init(requestBodyExtension: .init(name: "arkavo", json: Data("not json".utf8))),
        )) { assertInvalidOptions($0) }
    }

    func testOnlyThisKASKAOsSent() throws {
        var manifest = try makeManifest()
        var platformKAO = manifest.encryptionInformation.keyAccess[0]
        platformKAO.url = "https://platform.arkavo.net/kas"
        manifest.encryptionInformation.keyAccess.insert(platformKAO, at: 0)
        let prepared = try makeClient().prepareRewrap(manifest: manifest, clientPrivateKey: clientKey)
        let request = try TDFKAS.verifyRewrapRequest(body: prepared.body, signingPublicKey: signingKey.publicKey)
        XCTAssertEqual(request.policies.first?.keyAccessObjects.map(\.keyAccessObject.url), [Self.ownerURL])
    }

    // MARK: - submitRewrap / pollRewrap

    func testImmediate200IsAnswered() async throws {
        let encryption = try makeEncryption()
        let transport = try ScriptedTransport([.init(200, body: permitBody(for: encryption, plusFail: true))])
        let client = try makeClient(transport: transport)
        let prepared = try client.prepareRewrap(manifest: encryption.container.manifest, clientPrivateKey: clientKey)
        guard case let .answered(answer) = try await client.submitRewrap(prepared) else {
            return XCTFail("expected answered")
        }
        XCTAssertEqual(answer.requestTokenDigest, prepared.requestTokenDigest)
        XCTAssertEqual(answer.results.map(\.status), ["permit", "fail"])
        XCTAssertEqual(answer.results[1].error, "ACCESS_DENIED")
        XCTAssertNotNil(answer.sessionPublicKey)
    }

    func testDenyOnlyAnswerParses() async throws {
        let deny = try TDFKAS.rewrapResponseBody(sessionPublicKey: nil, responses: [
            .init(policyId: "policy", results: [
                .init(keyAccessObjectId: "kao-0", status: .fail, kasWrappedKey: nil, error: "ACCESS_REVOKED",
                      metadata: ["arkavo.decision": .string("c2lnbmVk")]),
            ]),
        ])
        let client = try makeClient(transport: ScriptedTransport([.init(200, body: deny)]))
        let prepared = try client.prepareRewrap(manifest: makeManifest(), clientPrivateKey: clientKey)
        guard case let .answered(answer) = try await client.submitRewrap(prepared) else {
            return XCTFail("expected answered")
        }
        XCTAssertNil(answer.sessionPublicKey)
        XCTAssertEqual(answer.results.first?.metadata["arkavo.decision"], .string("c2lnbmVk"))
        XCTAssertEqual(answer.results.first?.sid, nil)
    }

    func testPendingThenAnswered() async throws {
        let encryption = try makeEncryption()
        let transport = try ScriptedTransport([
            .init(202, headers: ["Location": "/owner-kas/v1/requests/abc", "Retry-After": "3"]),
            .init(202, headers: ["Retry-After": "5"]),
            .init(200, body: permitBody(for: encryption)),
        ])
        let clock = TestClock()
        let client = try makeClient(transport: transport, clock: clock)
        let prepared = try client.prepareRewrap(manifest: encryption.container.manifest, clientPrivateKey: clientKey)
        guard case let .pending(pending) = try await client.submitRewrap(prepared) else {
            return XCTFail("expected pending")
        }
        XCTAssertEqual(pending.location.absoluteString, "https://platform.arkavo.net/owner-kas/v1/requests/abc")
        XCTAssertEqual(pending.retryAfter, 3)
        guard case .answered = try await client.pollRewrap(pending, until: clock.start.addingTimeInterval(600)) else {
            return XCTFail("expected answered")
        }
        XCTAssertEqual(clock.sleeps, [3, 5])
        let requests = await transport.requests
        XCTAssertEqual(requests.map(\.method), ["POST", "GET", "GET"])
        for poll in requests.dropFirst() {
            XCTAssertEqual(poll.url, "https://platform.arkavo.net/owner-kas/v1/requests/abc")
            XCTAssertEqual(poll.authorization, "Bearer owner-kas-token")
            XCTAssertNil(poll.body)
        }
    }

    func testGoneIsExpired() async throws {
        let outcome = try await pollOutcome(after: [.init(410)])
        guard case .expired = outcome else { return XCTFail("expected expired, got \(outcome)") }
    }

    func test404AfterExpIsExpired() async throws {
        let outcome = try await pollOutcome(after: [.init(404)], retryAfter: "60", expiresIn: 60)
        guard case .expired = outcome else { return XCTFail("expected expired, got \(outcome)") }
    }

    func test404BeforeExpThrows() async throws {
        do {
            let outcome = try await pollOutcome(after: [.init(404)], retryAfter: "30", expiresIn: 900)
            XCTFail("expected a throw, got \(outcome)")
        } catch let KASRewrapError.httpError(status, _) {
            XCTAssertEqual(status, 404)
        }
    }

    /// When the next wait would pass the deadline, the client sleeps to the
    /// deadline and polls once more, then hands back the handle.
    func testDeadlineReachedReturnsHandleAndResumes() async throws {
        let encryption = try makeEncryption()
        let transport = try ScriptedTransport([
            .init(202, headers: ["Location": "/owner-kas/v1/requests/abc", "Retry-After": "10"]),
            .init(202, headers: ["Retry-After": "10"]),
            .init(200, body: permitBody(for: encryption)),
        ])
        let clock = TestClock()
        let client = try makeClient(transport: transport, clock: clock)
        let prepared = try client.prepareRewrap(manifest: encryption.container.manifest, clientPrivateKey: clientKey)
        guard case let .pending(pending) = try await client.submitRewrap(prepared) else {
            return XCTFail("expected pending")
        }
        guard case let .deadlineReached(handle) = try await client.pollRewrap(
            pending, until: clock.start.addingTimeInterval(5),
        ) else {
            return XCTFail("expected deadlineReached")
        }
        XCTAssertEqual(clock.sleeps, [5], "slept only to the deadline")
        let methods = await transport.requests.map(\.method)
        XCTAssertEqual(methods, ["POST", "GET"], "one last poll at the deadline")
        guard case .answered = try await client.pollRewrap(handle, until: clock.start.addingTimeInterval(100)) else {
            return XCTFail("expected answered after resuming")
        }
        XCTAssertEqual(clock.sleeps, [5, 10])
    }

    /// An iPhone suspended mid-wait wakes after the deadline: no poll is sent.
    func testOversleepPastDeadlineDoesNotPoll() async throws {
        let transport = ScriptedTransport([
            .init(202, headers: ["Location": "/owner-kas/v1/requests/abc", "Retry-After": "2"]),
        ])
        let clock = TestClock(oversleep: 3)
        let client = try makeClient(transport: transport, clock: clock)
        let prepared = try client.prepareRewrap(manifest: makeManifest(), clientPrivateKey: clientKey)
        guard case let .pending(pending) = try await client.submitRewrap(prepared) else {
            return XCTFail("expected pending")
        }
        guard case .deadlineReached = try await client.pollRewrap(pending, until: clock.start.addingTimeInterval(5))
        else {
            return XCTFail("expected deadlineReached")
        }
        let count = await transport.requests.count
        XCTAssertEqual(count, 1, "only the POST; no poll after the deadline")
    }

    func testPollTimeoutClampedToDeadline() async throws {
        let transport = ScriptedTransport([
            .init(202, headers: ["Location": "/owner-kas/v1/requests/abc", "Retry-After": "2"]),
            .init(202, headers: ["Retry-After": "60"]),
            .init(202, headers: ["Retry-After": "60"]),
        ])
        let clock = TestClock()
        let client = try makeClient(transport: transport, clock: clock)
        let prepared = try client.prepareRewrap(manifest: makeManifest(), clientPrivateKey: clientKey)
        guard case let .pending(pending) = try await client.submitRewrap(prepared) else {
            return XCTFail("expected pending")
        }
        _ = try await client.pollRewrap(pending, until: clock.start.addingTimeInterval(10))
        let timeouts = await transport.requests.dropFirst().map(\.timeout)
        XCTAssertEqual(timeouts, [8, 1], "8 s left at the first poll; the floor of 1 s at the deadline")
    }

    func testRewrapDefaultDeadlineIsExpired() async throws {
        let clock = TestClock()
        let transport = ScriptedTransport([
            .init(202, headers: ["Location": "/owner-kas/v1/requests/abc", "Retry-After": "60"]),
            .init(202, headers: ["Retry-After": "60"]),
        ])
        let outcome = try await makeClient(transport: transport, clock: clock).rewrap(
            manifest: makeManifest(), clientPrivateKey: clientKey,
            options: .init(expiresAt: clock.start.addingTimeInterval(30)),
        )
        guard case .expired = outcome else { return XCTFail("expected expired, got \(outcome)") }
    }

    func testPollRefusesHandleFromAnotherClient() async throws {
        let ownerTransport = ScriptedTransport([.init(202, headers: ["Location": "/owner-kas/v1/requests/abc"])])
        let owner = try makeClient(transport: ownerTransport)
        let prepared = try owner.prepareRewrap(manifest: makeManifest(), clientPrivateKey: clientKey)
        guard case let .pending(pending) = try await owner.submitRewrap(prepared) else {
            return XCTFail("expected pending")
        }
        let otherTransport = ScriptedTransport([.init(200)])
        let other = try KASRewrapClient(
            configuration: .forKasConnect("https://other.example/owner-kas/v1/routes/01HZXK3Q8R4M5N6P7Q8R9S0T1V"),
            oauthToken: "other-token", transport: otherTransport, signingKey: signingKey,
            sleeper: { _ in }, now: { Date() },
        )
        do {
            _ = try await other.pollRewrap(pending, until: Date().addingTimeInterval(600))
            XCTFail("expected unsafeLocation")
        } catch KASRewrapError.unsafeLocation {
            let count = await otherTransport.requests.count
            XCTAssertEqual(count, 0, "the other client's bearer goes nowhere")
        }
    }

    func testPoll202WithNewLocationIgnored() async throws {
        let encryption = try makeEncryption()
        let transport = try ScriptedTransport([
            .init(202, headers: ["Location": "/owner-kas/v1/requests/abc", "Retry-After": "1"]),
            .init(202, headers: ["Location": "https://evil.example/x", "Retry-After": "1"]),
            .init(200, body: permitBody(for: encryption)),
        ])
        let client = try makeClient(transport: transport)
        let prepared = try client.prepareRewrap(manifest: encryption.container.manifest, clientPrivateKey: clientKey)
        guard case let .pending(pending) = try await client.submitRewrap(prepared) else {
            return XCTFail("expected pending")
        }
        guard case .answered = try await client.pollRewrap(pending, until: Date().addingTimeInterval(600)) else {
            return XCTFail("expected answered")
        }
        let urls = await transport.requests.dropFirst().map(\.url)
        XCTAssertEqual(urls, Array(repeating: "https://platform.arkavo.net/owner-kas/v1/requests/abc", count: 2))
    }

    func test403IsHTTPErrorNotDenial() async throws {
        let client = try makeClient(transport: ScriptedTransport([.init(403, body: Data("blocked".utf8))]))
        let prepared = try client.prepareRewrap(manifest: makeManifest(), clientPrivateKey: clientKey)
        do {
            _ = try await client.submitRewrap(prepared)
            XCTFail("expected a throw")
        } catch let KASRewrapError.httpError(status, _) {
            XCTAssertEqual(status, 403)
        }
        do {
            _ = try await pollOutcome(after: [.init(403)])
            XCTFail("expected a throw")
        } catch let KASRewrapError.httpError(status, _) {
            XCTAssertEqual(status, 403)
        }
    }

    func testEmptyAnswerThrows() async throws {
        for body in [#"{"responses":[]}"#,
                     #"{"responses":[{"policyId":"policy","results":[{"keyAccessObjectId":"kao-7","status":"fail"}]}]}"#]
        {
            let client = try makeClient(transport: ScriptedTransport([.init(200, body: Data(body.utf8))]))
            let prepared = try client.prepareRewrap(manifest: makeManifest(), clientPrivateKey: clientKey)
            do {
                _ = try await client.submitRewrap(prepared)
                XCTFail("expected emptyResponse for \(body)")
            } catch KASRewrapError.emptyResponse {}
        }
    }

    func testMalformedWrappedKeyKeepsResult() async throws {
        let session = P256.KeyAgreement.PrivateKey().publicKey.pemRepresentation
        let object: [String: Any] = [
            "sessionPublicKey": session,
            "responses": [["policyId": "policy", "results": [
                ["keyAccessObjectId": "kao-0", "status": "permit", "kasWrappedKey": "!!!",
                 "metadata": ["arkavo.decision": "ZGVj"]],
            ]]],
        ]
        let client = try makeClient(transport: ScriptedTransport([
            .init(200, body: JSONSerialization.data(withJSONObject: object)),
        ]))
        let prepared = try client.prepareRewrap(manifest: makeManifest(), clientPrivateKey: clientKey)
        guard case let .answered(answer) = try await client.submitRewrap(prepared) else {
            return XCTFail("expected answered")
        }
        XCTAssertNil(answer.results.first?.kasWrappedKey)
        XCTAssertEqual(answer.results.first?.metadata["arkavo.decision"], .string("ZGVj"))
        XCTAssertThrowsError(try answer.share(for: answer.results[0], clientPrivateKey: clientKey))
    }

    func testOutOfRangeExpiresAtRefused() throws {
        for seconds in [Double.infinity, 1e300, Double.nan, -1e300, -Double.infinity] {
            XCTAssertThrowsError(try makeClient().prepareRewrap(
                manifest: makeManifest(), clientPrivateKey: clientKey,
                options: .init(expiresAt: Date(timeIntervalSince1970: seconds)),
            )) { assertInvalidOptions($0) }
        }
    }

    func testRetryAfterIsClamped() {
        XCTAssertEqual(KASRewrapClient.retryAfterSeconds("7"), 7)
        XCTAssertEqual(KASRewrapClient.retryAfterSeconds("0"), 1)
        XCTAssertEqual(KASRewrapClient.retryAfterSeconds("-5"), 2)
        XCTAssertEqual(KASRewrapClient.retryAfterSeconds("999"), 60)
        XCTAssertEqual(KASRewrapClient.retryAfterSeconds("Wed, 21 Oct 2015 07:28:00 GMT"), 2)
        XCTAssertEqual(KASRewrapClient.retryAfterSeconds(nil), 2)
        XCTAssertEqual(KASRewrapClient.retryAfterSeconds(" 4 "), 4)
        XCTAssertEqual(KASRewrapClient.retryAfterSeconds("99999999999999999999"), 60, "overflow clamps to the cap")
        XCTAssertEqual(KASRewrapClient.retryAfterSeconds("+5"), 2, "delta-seconds is digits only")
        XCTAssertEqual(KASRewrapClient.retryAfterSeconds("٣"), 2, "ASCII digits only")
    }

    func testLocationOriginRules() async throws {
        let allowed = [
            "/owner-kas/v1/requests/a": "https://platform.arkavo.net/owner-kas/v1/requests/a",
            "https://platform.arkavo.net/owner-kas/v1/requests/a": "https://platform.arkavo.net/owner-kas/v1/requests/a",
            "https://PLATFORM.arkavo.net:443/owner-kas/v1/requests/a":
                "https://PLATFORM.arkavo.net:443/owner-kas/v1/requests/a",
        ]
        for (location, resolved) in allowed {
            let client = try makeClient(transport: ScriptedTransport([.init(202, headers: ["Location": location])]))
            let prepared = try client.prepareRewrap(manifest: makeManifest(), clientPrivateKey: clientKey)
            guard case let .pending(pending) = try await client.submitRewrap(prepared) else {
                return XCTFail("expected pending for \(location)")
            }
            XCTAssertEqual(pending.location.absoluteString, resolved)
        }
        for location in ["https://evil.example/x", "//evil.example/x", "http://platform.arkavo.net/x",
                         "https://platform.arkavo.net:8443/x", "https://evil@platform.arkavo.net/x",
                         "https://u:p@platform.arkavo.net/x", "https://platform.arkavo.net\\@evil.example/x"]
        {
            let transport = ScriptedTransport([.init(202, headers: ["Location": location])])
            let client = try makeClient(transport: transport)
            let prepared = try client.prepareRewrap(manifest: makeManifest(), clientPrivateKey: clientKey)
            do {
                _ = try await client.submitRewrap(prepared)
                XCTFail("expected unsafeLocation for \(location)")
            } catch KASRewrapError.unsafeLocation {
                let count = await transport.requests.count
                XCTAssertEqual(count, 1, "nothing is sent to \(location)")
            }
        }
    }

    func testPendingWithoutLocationThrows() async throws {
        let client = try makeClient(transport: ScriptedTransport([.init(202, headers: ["Retry-After": "2"])]))
        let prepared = try client.prepareRewrap(manifest: makeManifest(), clientPrivateKey: clientKey)
        do {
            _ = try await client.submitRewrap(prepared)
            XCTFail("expected pendingWithoutLocation")
        } catch KASRewrapError.pendingWithoutLocation {}
    }

    func testResubmitSendsIdenticalBytes() async throws {
        let pending = ScriptedTransport.Reply(202, headers: ["Location": "/owner-kas/v1/requests/a"])
        let transport = ScriptedTransport([pending, pending])
        let client = try makeClient(transport: transport)
        let prepared = try client.prepareRewrap(manifest: makeManifest(), clientPrivateKey: clientKey)
        _ = try await client.submitRewrap(prepared)
        _ = try await client.submitRewrap(prepared)
        let bodies = await transport.requests.map(\.body)
        XCTAssertEqual(bodies.count, 2)
        XCTAssertEqual(bodies[0], bodies[1])
        XCTAssertEqual(bodies[0], prepared.body)
    }

    func testRewrapUnwrapsPermittedShares() async throws {
        let encryption = try makeEncryption()
        let client = try makeClient(transport: ScriptedTransport([.init(200, body: permitBody(for: encryption))]))
        guard case let .answered(answer, shares) = try await client.rewrap(
            manifest: encryption.container.manifest, clientPrivateKey: clientKey,
        ) else {
            return XCTFail("expected answered")
        }
        XCTAssertEqual(answer.results.count, 1)
        XCTAssertEqual(shares.count, 1)
        XCTAssertEqual(shares.first.map { Self.bytes($0.key) }, Self.bytes(encryption.symmetricKey))
    }

    func testAnswerShareRefusesFailResult() async throws {
        let encryption = try makeEncryption()
        let client = try makeClient(transport: ScriptedTransport([
            .init(200, body: permitBody(for: encryption, plusFail: true)),
        ]))
        let prepared = try client.prepareRewrap(manifest: encryption.container.manifest, clientPrivateKey: clientKey)
        guard case let .answered(answer) = try await client.submitRewrap(prepared) else {
            return XCTFail("expected answered")
        }
        XCTAssertThrowsError(try answer.share(for: answer.results[1], clientPrivateKey: clientKey))
        XCTAssertEqual(
            try Self.bytes(answer.share(for: answer.results[0], clientPrivateKey: clientKey).key),
            Self.bytes(encryption.symmetricKey),
        )
    }

    // MARK: - Helpers

    func makeClient(
        transport: any KASRewrapTransport = URLSessionKASTransport(),
        clock: TestClock = TestClock(),
    ) throws -> KASRewrapClient {
        try KASRewrapClient(
            configuration: .forKasConnect(Self.ownerURL),
            oauthToken: "owner-kas-token",
            transport: transport,
            signingKey: signingKey,
            sleeper: { clock.sleep($0) },
            now: { clock.now },
        )
    }

    /// Submits a request that is answered 202, then polls once into `replies`.
    func pollOutcome(
        after replies: [ScriptedTransport.Reply],
        retryAfter: String = "2",
        expiresIn: TimeInterval = 900,
    ) async throws -> KASRewrapClient.RewrapPollOutcome {
        let clock = TestClock()
        let transport = ScriptedTransport(
            [.init(202, headers: ["Location": "/owner-kas/v1/requests/abc", "Retry-After": retryAfter])] + replies,
        )
        let client = try makeClient(transport: transport, clock: clock)
        let prepared = try client.prepareRewrap(
            manifest: makeManifest(), clientPrivateKey: clientKey,
            options: .init(expiresAt: clock.start.addingTimeInterval(expiresIn)),
        )
        guard case let .pending(pending) = try await client.submitRewrap(prepared) else {
            throw KASRewrapError.invalidResponse
        }
        return try await client.pollRewrap(pending, until: clock.start.addingTimeInterval(expiresIn + 600))
    }

    /// A Rewrap response permitting the encryption's key access object, rewrapped
    /// by `TDFKAS` to `clientKey`, and optionally a second, failed result.
    func permitBody(for encryption: TDFEncryptionResult, plusFail: Bool = false) throws -> Data {
        let manifest = encryption.container.manifest
        let rewrapped = try TDFKAS.rewrap(
            keyAccessObject: manifest.encryptionInformation.keyAccess[0],
            policyBase64: manifest.encryptionInformation.policy,
            kasPrivateKey: kasKey,
            receiverPublicKey: clientKey.publicKey,
        )
        var results = [TDFKAS.KeyAccessResult(keyAccessObjectId: "kao-0", status: .permit,
                                              kasWrappedKey: rewrapped.wrappedKey, error: nil,
                                              metadata: ["arkavo.decision": .string("YWxsb3c")])]
        if plusFail {
            results.append(.init(keyAccessObjectId: "kao-1", status: .fail, kasWrappedKey: nil,
                                 error: "ACCESS_DENIED", metadata: [:]))
        }
        return try TDFKAS.rewrapResponseBody(
            sessionPublicKey: rewrapped.sessionPublicKey,
            responses: [.init(policyId: "policy", results: results)],
        )
    }

    static func bytes(_ key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }

    /// A TDF with one `ec-wrapped` key access object for the owner KAS.
    func makeManifest() throws -> TDFManifest {
        try makeEncryption().container.manifest
    }

    func makeEncryption(plaintext: Data = Data("owner-held".utf8)) throws -> TDFEncryptionResult {
        let kas = try TDFKasInfo(
            url: XCTUnwrap(URL(string: Self.ownerURL)),
            publicKeyPEM: kasKey.publicKey.pemRepresentation,
            kid: "e1",
            keyType: .ecP256,
        )
        let policy = try TDFPolicy(json: Data(
            #"{"uuid":"a1","body":{"dataAttributes":[],"dissem":[],"arkavo.owner-held":{"v":1}}}"#.utf8,
        ))
        return try TDFEncryptor().encrypt(plaintext: plaintext, configuration: TDFEncryptionConfiguration(kas: kas, policy: policy))
    }

    func assertInvalidOptions(_ error: Error, line: UInt = #line) {
        guard case .invalidRewrapOptions = error as? KASRewrapError else {
            return XCTFail("expected invalidRewrapOptions, got \(error)", line: line)
        }
    }
}

/// Replays scripted HTTP replies in order and records each request.
actor ScriptedTransport: KASRewrapTransport {
    struct Reply: Sendable {
        let status: Int
        let headers: [String: String]
        let body: Data

        init(_ status: Int, headers: [String: String] = [:], body: Data = Data()) {
            self.status = status
            self.headers = headers
            self.body = body
        }
    }

    struct Recorded: Sendable {
        let method: String
        let url: String
        let authorization: String?
        let body: Data?
        let timeout: TimeInterval
    }

    private var replies: [Reply]
    private(set) var requests: [Recorded] = []

    init(_ replies: [Reply]) {
        self.replies = replies
    }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        requests.append(Recorded(
            method: request.httpMethod ?? "GET",
            url: request.url?.absoluteString ?? "",
            authorization: request.value(forHTTPHeaderField: "Authorization"),
            body: request.httpBody,
            timeout: request.timeoutInterval,
        ))
        guard !replies.isEmpty else {
            throw URLError(.badServerResponse)
        }
        let reply = replies.removeFirst()
        let response = HTTPURLResponse(url: request.url!, statusCode: reply.status, httpVersion: "HTTP/1.1",
                                       headerFields: reply.headers)!
        return (reply.body, response)
    }
}

/// A clock that only moves when the client sleeps, recording each sleep. With
/// `oversleep` above 1 it wakes late, like an app suspended mid-wait.
final class TestClock: @unchecked Sendable {
    let start = Date()
    private let oversleep: Double

    init(oversleep: Double = 1) {
        self.oversleep = oversleep
    }

    private let lock = NSLock()
    private var elapsed: TimeInterval = 0
    private var recorded: [TimeInterval] = []

    var now: Date {
        lock.withLock { start.addingTimeInterval(elapsed) }
    }

    var sleeps: [TimeInterval] {
        lock.withLock { recorded }
    }

    func sleep(_ duration: TimeInterval) {
        lock.withLock {
            elapsed += duration * oversleep
            recorded.append(duration)
        }
    }
}
