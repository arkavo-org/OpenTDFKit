@preconcurrency import CryptoKit
import Foundation
@testable import OpenTDFKit
import XCTest

/// The receiver's `KASRewrapClient` against an owner KAS: a fake relay that
/// queues the Rewrap and, on a later poll, lets the "phone" answer it with
/// `TDFKAS.verifyRewrapRequest`, `TDFKAS.rewrap` and `TDFKAS.rewrapResponseBody`.
final class OwnerKASEndToEndTests: XCTestCase {
    static let ownerURL = "https://platform.arkavo.net/owner-kas/v1/routes/01HZXK3Q8R4M5N6P7Q8R9S0T1V"
    let kasKey = P256.KeyAgreement.PrivateKey()
    let cnfKey = P256.Signing.PrivateKey()
    let clientKey = P256.KeyAgreement.PrivateKey()
    let plaintext = Data("a photo, say".utf8)

    func testOwnerAllowEndToEnd() async throws {
        let encryption = try encrypt()
        let manifestKAO = encryption.container.manifest.encryptionInformation.keyAccess[0]
        let relay = FakeOwnerKAS(kasKey: kasKey, cnfKey: cnfKey.publicKey,
                                 expectedKAODigest: TDFKAS.keyAccessObjectDigest(manifestKAO), allow: true)
        let clock = TestClock()
        let extensionJSON = Data(#"{"v":1,"attempt_id":"QUJD","nonce":"REVG","tdf_digest":"R0hJ"}"#.utf8)

        let outcome = try await makeClient(transport: relay, clock: clock).rewrap(
            manifest: encryption.container.manifest,
            clientPrivateKey: clientKey,
            options: .init(expiresAt: clock.start.addingTimeInterval(900),
                           requestBodyExtension: .init(name: "arkavo", json: extensionJSON)),
        )

        guard case let .answered(answer, shares) = outcome else {
            return XCTFail("expected answered, got \(outcome)")
        }
        let phone = await relay.phoneSaw
        XCTAssertEqual(answer.requestTokenDigest, phone?.requestTokenDigest, "both sides report one digest")
        XCTAssertEqual(phone?.extensionNames, ["arkavo"])
        XCTAssertEqual(phone?.kaoDigestMatched, true)
        XCTAssertEqual(answer.results.first?.metadata["arkavo.decision"], .string("YWxsb3c"))
        XCTAssertEqual(shares.count, 1)
        let dek = try XCTUnwrap(shares.first?.key)
        XCTAssertEqual(try TDFDecryptor().decrypt(container: encryption.container, symmetricKey: dek), plaintext)
        XCTAssertEqual(clock.sleeps, [1, 1], "a 202 on submit and one on the first poll")
    }

    func testOwnerDenyEndToEnd() async throws {
        let encryption = try encrypt()
        let manifestKAO = encryption.container.manifest.encryptionInformation.keyAccess[0]
        let relay = FakeOwnerKAS(kasKey: kasKey, cnfKey: cnfKey.publicKey,
                                 expectedKAODigest: TDFKAS.keyAccessObjectDigest(manifestKAO), allow: false)
        let clock = TestClock()
        let outcome = try await makeClient(transport: relay, clock: clock).rewrap(
            manifest: encryption.container.manifest,
            clientPrivateKey: clientKey,
            options: .init(expiresAt: clock.start.addingTimeInterval(900)),
        )
        guard case let .answered(answer, shares) = outcome else {
            return XCTFail("expected answered, got \(outcome)")
        }
        XCTAssertTrue(shares.isEmpty)
        XCTAssertNil(answer.sessionPublicKey)
        XCTAssertEqual(answer.results.map(\.status), ["fail"])
        XCTAssertEqual(answer.results.first?.error, "ACCESS_DENIED")
        XCTAssertEqual(answer.results.first?.metadata["arkavo.decision"], .string("ZGVueQ"))
    }

    // MARK: - Helpers

    func makeClient(transport: any KASRewrapTransport, clock: TestClock) throws -> KASRewrapClient {
        try KASRewrapClient(
            configuration: .forKasConnect(Self.ownerURL),
            oauthToken: "owner-kas-token",
            transport: transport,
            signingKey: cnfKey,
            sleeper: { clock.sleep($0) },
            now: { clock.now },
        )
    }

    func encrypt() throws -> TDFEncryptionResult {
        let kas = try TDFKasInfo(
            url: XCTUnwrap(URL(string: Self.ownerURL)),
            publicKeyPEM: kasKey.publicKey.pemRepresentation,
            kid: "e1",
            keyType: .ecP256,
        )
        let policy = try TDFPolicy(json: Data(
            #"{"uuid":"asset-1","body":{"dataAttributes":[],"dissem":[],"arkavo.owner-held":{"v":1}}}"#.utf8,
        ))
        return try TDFEncryptor().encrypt(
            plaintext: plaintext,
            configuration: TDFEncryptionConfiguration(kas: kas, policy: policy, mimeType: "image/heic"),
        )
    }
}

/// A relay plus owner phone in one fake transport. The relay answers the Rewrap
/// POST with 202 and the first poll with 202; on the second poll the phone
/// verifies the queued request, checks the key access object against the
/// digest recorded at protect time, and answers.
actor FakeOwnerKAS: KASRewrapTransport {
    struct PhoneView: Sendable {
        let requestTokenDigest: Data
        let extensionNames: [String]
        let kaoDigestMatched: Bool
    }

    private let kasKey: P256.KeyAgreement.PrivateKey
    private let cnfKey: P256.Signing.PublicKey
    private let expectedKAODigest: Data
    private let allow: Bool
    private var queued: Data?
    private var polls = 0
    private(set) var phoneSaw: PhoneView?

    init(kasKey: P256.KeyAgreement.PrivateKey, cnfKey: P256.Signing.PublicKey, expectedKAODigest: Data, allow: Bool) {
        self.kasKey = kasKey
        self.cnfKey = cnfKey
        self.expectedKAODigest = expectedKAODigest
        self.allow = allow
    }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let url = try XCTUnwrap(request.url)
        if request.httpMethod == "POST" {
            XCTAssertTrue(url.path.hasSuffix("/owner-kas/v1/routes/01HZXK3Q8R4M5N6P7Q8R9S0T1V/kas.AccessService/Rewrap"))
            queued = request.httpBody
            return reply(url, 202, ["Location": "/owner-kas/v1/requests/r1", "Retry-After": "1"])
        }
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer owner-kas-token")
        polls += 1
        if polls == 1 {
            return reply(url, 202, ["Retry-After": "1"])
        }
        return try reply(url, 200, [:], body: answer())
    }

    private func answer() throws -> Data {
        let request = try TDFKAS.verifyRewrapRequest(body: XCTUnwrap(queued), signingPublicKey: cnfKey)
        let policy = try XCTUnwrap(request.policies.first)
        let entry = try XCTUnwrap(policy.keyAccessObjects.first)
        let matched = TDFKAS.keyAccessObjectDigest(entry.keyAccessObject) == expectedKAODigest
        phoneSaw = PhoneView(requestTokenDigest: request.requestTokenDigest,
                             extensionNames: request.extensions.keys.sorted(), kaoDigestMatched: matched)

        guard allow, matched else {
            return try TDFKAS.rewrapResponseBody(sessionPublicKey: nil, responses: [
                .init(policyId: policy.policyId, results: [
                    .init(keyAccessObjectId: entry.id, status: .fail, kasWrappedKey: nil,
                          error: matched ? "ACCESS_DENIED" : "BINDING_MISMATCH",
                          metadata: ["arkavo.decision": .string("ZGVueQ")]),
                ]),
            ])
        }
        let rewrapped = try TDFKAS.rewrap(
            keyAccessObject: entry.keyAccessObject,
            policyBase64: policy.policyBase64,
            kasPrivateKey: kasKey,
            receiverPublicKey: request.clientPublicKey,
        )
        return try TDFKAS.rewrapResponseBody(sessionPublicKey: rewrapped.sessionPublicKey, responses: [
            .init(policyId: policy.policyId, results: [
                .init(keyAccessObjectId: entry.id, status: .permit, kasWrappedKey: rewrapped.wrappedKey,
                      error: nil, metadata: ["arkavo.decision": .string("YWxsb3c")]),
            ]),
        ])
    }

    private func reply(_ url: URL, _ status: Int, _ headers: [String: String],
                       body: Data = Data()) -> (Data, HTTPURLResponse)
    {
        (body, HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!)
    }
}
