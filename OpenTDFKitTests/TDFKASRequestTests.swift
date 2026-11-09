@preconcurrency import CryptoKit
import Foundation
@testable import OpenTDFKit
import XCTest

/// `TDFKAS.verifyRewrapRequest`: the owner KAS verifies a received Rewrap
/// under the bearer token's `cnf` key and parses it. Requests here are built
/// by hand, independently of `KASRewrapClient`.
final class TDFKASRequestTests: XCTestCase {
    private let signingKey = P256.Signing.PrivateKey()
    private let clientKey = P256.KeyAgreement.PrivateKey()
    private let now = Int(Date().timeIntervalSince1970)

    func testValidRequestVerifies() throws {
        let kao = TDFKASDigestTests.fullKAO()
        let (body, token) = try signedRequest(requestBody: requestBody(kao: kao), exp: now + 900, iat: now)
        let request = try TDFKAS.verifyRewrapRequest(body: body, signingPublicKey: signingKey.publicKey)

        XCTAssertEqual(request.requestToken, token)
        XCTAssertEqual(request.requestTokenDigest, TDFKAS.requestTokenDigest(token))
        XCTAssertEqual(request.expiresAt, Date(timeIntervalSince1970: TimeInterval(now + 900)))
        XCTAssertEqual(request.issuedAt, Date(timeIntervalSince1970: TimeInterval(now)))
        XCTAssertEqual(request.clientPublicKey.x963Representation, clientKey.publicKey.x963Representation)
        XCTAssertEqual(request.policies.count, 1)
        let policy = try XCTUnwrap(request.policies.first)
        XCTAssertEqual(policy.policyId, "policy")
        XCTAssertEqual(policy.policyBase64, Self.policyBase64)
        XCTAssertEqual(policy.keyAccessObjects.map(\.id), ["kao-0"])
        XCTAssertEqual(
            TDFKAS.keyAccessObjectDigest(policy.keyAccessObjects[0].keyAccessObject),
            TDFKAS.keyAccessObjectDigest(kao),
        )
        XCTAssertEqual(Array(request.extensions.keys), ["arkavo"])
        try assertJSONEqual(request.extensions["arkavo"], Self.arkavoExtension)
    }

    func testExtensionRoundTripsUnicodeAndSlashes() throws {
        let note: [String: Any] = ["v": 1, "note": "é/ü \u{1F512}"]
        var bodyObject = try requestBody(kao: TDFKASDigestTests.fullKAO())
        bodyObject["arkavo"] = note
        let (body, _) = try signedRequest(requestBody: bodyObject, exp: now + 60, iat: now)
        let request = try TDFKAS.verifyRewrapRequest(body: body, signingPublicKey: signingKey.publicKey)
        try assertJSONEqual(request.extensions["arkavo"], note)
    }

    func testOtherSigningKeyRefused() throws {
        let (body, _) = try signedRequest(requestBody: requestBody(), exp: now + 60, iat: now)
        assertRefused(body, key: P256.Signing.PrivateKey().publicKey, .requestSignatureInvalid)
    }

    func testPayloadChangedAfterSigningRefused() throws {
        let (_, token) = try signedRequest(requestBody: requestBody(), exp: now + 60, iat: now)
        var parts = token.split(separator: ".").map(String.init)
        var claims = try XCTUnwrap(JSONSerialization.jsonObject(with: Self.base64URLDecode(parts[1])) as? [String: Any])
        claims["exp"] = now + 61
        parts[1] = try Self.base64URL(JSONSerialization.data(withJSONObject: claims))
        try assertRefused(Self.wrap(parts.joined(separator: ".")), key: signingKey.publicKey, .requestSignatureInvalid)
    }

    func testSignatureChangedRefused() throws {
        let (_, token) = try signedRequest(requestBody: requestBody(), exp: now + 60, iat: now)
        var parts = token.split(separator: ".").map(String.init)
        var signature = Self.base64URLDecode(parts[2])
        signature[10] ^= 0x01
        parts[2] = Self.base64URL(signature)
        try assertRefused(Self.wrap(parts.joined(separator: ".")), key: signingKey.publicKey, .requestSignatureInvalid)
    }

    func testAlgNoneAndHS256Refused() throws {
        for alg in ["none", "HS256"] {
            let (body, _) = try signedRequest(requestBody: requestBody(), header: ["alg": alg, "typ": "JWT"],
                                              exp: now + 60, iat: now)
            assertRefused(body, key: signingKey.publicKey, .unsupportedRequestAlgorithm(alg))
        }
    }

    func testOversizedBodyRefused() {
        assertRefused(Data(repeating: 0x20, count: 65537), key: signingKey.publicKey, .requestTooLarge)
    }

    func testMalformedShapesRefused() throws {
        var badClientKey = try requestBody()
        badClientKey["clientPublicKey"] = "not a key"
        var noRequests = try requestBody()
        noRequests["requests"] = [Any]()
        var badPolicy = try requestBody()
        badPolicy["requests"] = try [["policy": ["id": "policy", "body": "!!!"],
                                      "keyAccessObjects": Self.kaoWrappers(TDFKASDigestTests.fullKAO())]]
        var noWrappedKey = try Self.jsonObject(TDFKASDigestTests.fullKAO())
        noWrappedKey.removeValue(forKey: "wrappedKey")
        var badKAO = try requestBody()
        badKAO["requests"] = [["policy": ["id": "policy", "body": Self.policyBase64],
                               "keyAccessObjects": [["keyAccessObjectId": "kao-0", "keyAccessObject": noWrappedKey]]]]
        var noKAOs = try requestBody()
        noKAOs["requests"] = [["policy": ["id": "policy", "body": Self.policyBase64], "keyAccessObjects": [Any]()]]

        for requestBody in [badClientKey, noRequests, badPolicy, badKAO, noKAOs] {
            let (body, _) = try signedRequest(requestBody: requestBody, exp: now + 60, iat: now)
            assertMalformed(body)
        }
        assertMalformed(Data(#"{"other":"x"}"#.utf8))
        try assertMalformed(Self.wrap("only.two"))
        assertMalformed(Data("not json".utf8))
    }

    /// The phone must parse an expired request so it can sign REQUEST_EXPIRED.
    func testExpiredTokenStillParses() throws {
        let (body, _) = try signedRequest(requestBody: requestBody(), exp: now - 3600, iat: now - 4500)
        let request = try TDFKAS.verifyRewrapRequest(body: body, signingPublicKey: signingKey.publicKey)
        XCTAssertEqual(request.expiresAt, Date(timeIntervalSince1970: TimeInterval(now - 3600)))
    }

    func testStandardMembersAreNotExtensions() throws {
        var bodyObject = try requestBody()
        bodyObject["algorithm"] = "ec:secp256r1"
        bodyObject["keyAccess"] = ["url": "https://h"]
        bodyObject["policy"] = "e30="
        bodyObject["schemaVersion"] = "1.0.0"
        let (body, _) = try signedRequest(requestBody: bodyObject, exp: now + 60, iat: nil)
        let request = try TDFKAS.verifyRewrapRequest(body: body, signingPublicKey: signingKey.publicKey)
        XCTAssertEqual(Array(request.extensions.keys), ["arkavo"])
        XCTAssertNil(request.issuedAt)
    }

    // MARK: - Strict JOSE / JSON (RFC 7515 §4.1.11, §10.12; RFC 7519 §4)

    func testDuplicateHeaderMemberRefused() throws {
        let (body, _) = try signedRaw(header: #"{"alg":"ES256","alg":"none"}"#, claims: claimsJSON())
        assertMalformed(body)
    }

    func testDuplicateClaimRefused() throws {
        let claims = try claimsJSON().replacingOccurrences(of: #""exp":"#, with: #""exp":1,"exp":"#)
        let (body, _) = try signedRaw(header: #"{"alg":"ES256"}"#, claims: claims)
        assertMalformed(body)
    }

    func testDuplicateRequestBodyMemberRefused() throws {
        let pem = clientKey.publicKey.pemRepresentation
        let duplicated = try XCTUnwrap(String(data: JSONSerialization.data(withJSONObject: requestBody()), encoding: .utf8))
            .replacingOccurrences(of: "{", with: "{\"clientPublicKey\":\(Self.jsonString(pem)),", options: [], range: nil)
        let (body, _) = try signedRaw(header: #"{"alg":"ES256"}"#, claims: claimsJSON(requestBody: duplicated))
        assertMalformed(body)
    }

    func testDuplicateEnvelopeMemberRefused() throws {
        let (_, token) = try signedRequest(requestBody: requestBody(), exp: now + 60, iat: now)
        let body = Data("{\"signed_request_token\":\(Self.jsonString(token)),\"signed_request_token\":\"x.y.z\"}".utf8)
        assertMalformed(body)
    }

    func testCritHeaderRefused() throws {
        let (body, _) = try signedRaw(header: #"{"alg":"ES256","crit":["x"],"x":true}"#, claims: claimsJSON())
        assertMalformed(body)
    }

    func testNonCanonicalBase64URLRefused() throws {
        let (_, token) = try signedRequest(requestBody: requestBody(), exp: now + 60, iat: now)
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        let last = try XCTUnwrap(token.last)
        let index = try XCTUnwrap(alphabet.firstIndex(of: last))
        let slack = String(token.dropLast()) + String(alphabet[index ^ 0x01])
        XCTAssertEqual(Self.base64URLDecode(String(slack.split(separator: ".")[2])),
                       Self.base64URLDecode(String(token.split(separator: ".")[2])),
                       "the slack bits do not change the decoded signature")
        for variant in [token + "=", slack] {
            try assertMalformed(Self.wrap(variant))
        }
    }

    func testNullIatRefused() throws {
        let claims = try claimsJSON().replacingOccurrences(of: #""exp":"#, with: #""iat":null,"exp":"#)
        let (body, _) = try signedRaw(header: #"{"alg":"ES256"}"#, claims: claims)
        assertMalformed(body)
    }

    func testExtensionBytesAreSortedWithoutEscapedSlashes() throws {
        var bodyObject = try requestBody()
        bodyObject["arkavo"] = ["b": "x/y", "a": 1]
        let (body, _) = try signedRequest(requestBody: bodyObject, exp: now + 60, iat: now)
        let request = try TDFKAS.verifyRewrapRequest(body: body, signingPublicKey: signingKey.publicKey)
        XCTAssertEqual(request.extensions["arkavo"].map { String(decoding: $0, as: UTF8.self) }, #"{"a":1,"b":"x/y"}"#)
    }

    // MARK: - Helpers

    static let policyBase64 = Data(#"{"uuid":"u","body":{"dataAttributes":[],"dissem":[]}}"#.utf8).base64EncodedString()
    static var arkavoExtension: [String: Any] {
        ["v": 1, "attempt_id": "QUJD", "nonce": "REVG", "tdf_digest": "R0hJ"]
    }

    func requestBody(kao: TDFKeyAccessObject = TDFKASDigestTests.fullKAO()) throws -> [String: Any] {
        try [
            "clientPublicKey": clientKey.publicKey.pemRepresentation,
            "requests": [["policy": ["id": "policy", "body": Self.policyBase64],
                          "keyAccessObjects": Self.kaoWrappers(kao)]],
            "arkavo": Self.arkavoExtension,
        ]
    }

    static func kaoWrappers(_ kao: TDFKeyAccessObject) throws -> [[String: Any]] {
        try [["keyAccessObjectId": "kao-0", "keyAccessObject": jsonObject(kao)]]
    }

    static func jsonObject(_ kao: TDFKeyAccessObject) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(kao)) as? [String: Any])
    }

    /// `{"signed_request_token": <ES256 JWT>}` signed with `signingKey`.
    func signedRequest(
        requestBody: [String: Any],
        header: [String: Any] = ["alg": "ES256", "typ": "JWT"],
        exp: Int,
        iat: Int?,
    ) throws -> (body: Data, token: String) {
        let requestBodyString = try XCTUnwrap(String(
            data: JSONSerialization.data(withJSONObject: requestBody),
            encoding: .utf8,
        ))
        var claims: [String: Any] = ["requestBody": requestBodyString, "exp": exp]
        if let iat {
            claims["iat"] = iat
        }
        let signingInput = try Self.base64URL(JSONSerialization.data(withJSONObject: header)) + "."
            + Self.base64URL(JSONSerialization.data(withJSONObject: claims))
        let signature = try signingKey.signature(for: Data(signingInput.utf8)).rawRepresentation
        let token = signingInput + "." + Self.base64URL(signature)
        return try (Self.wrap(token), token)
    }

    /// Claims JSON written by hand: `requestBody` (as a JSON string) and `exp`.
    func claimsJSON(requestBody: String? = nil) throws -> String {
        let bodyText = try requestBody
            ?? XCTUnwrap(String(data: JSONSerialization.data(withJSONObject: self.requestBody()), encoding: .utf8))
        return "{\"requestBody\":\(Self.jsonString(bodyText)),\"exp\":\(now + 60)}"
    }

    /// A token over a hand-written header and claims, signed with `signingKey`.
    func signedRaw(header: String, claims: String) throws -> (body: Data, token: String) {
        let signingInput = Self.base64URL(Data(header.utf8)) + "." + Self.base64URL(Data(claims.utf8))
        let signature = try signingKey.signature(for: Data(signingInput.utf8)).rawRepresentation
        let token = signingInput + "." + Self.base64URL(signature)
        return try (Self.wrap(token), token)
    }

    static func jsonString(_ text: String) -> String {
        String(decoding: try! JSONEncoder().encode(text), as: UTF8.self)
    }

    static func wrap(_ token: String) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["signed_request_token": token])
    }

    static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func base64URLDecode(_ text: String) -> Data {
        var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        return Data(base64Encoded: base64)!
    }

    func assertJSONEqual(_ json: Data?, _ expected: [String: Any], line: UInt = #line) throws {
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(json, line: line)) as? NSDictionary,
                                   line: line)
        XCTAssertEqual(object, expected as NSDictionary, line: line)
    }

    func assertRefused(_ body: Data, key: P256.Signing.PublicKey, _ expected: TDFKASError, line: UInt = #line) {
        XCTAssertThrowsError(try TDFKAS.verifyRewrapRequest(body: body, signingPublicKey: key), line: line) {
            XCTAssertEqual($0 as? TDFKASError, expected, line: line)
        }
    }

    func assertMalformed(_ body: Data, line: UInt = #line) {
        XCTAssertThrowsError(try TDFKAS.verifyRewrapRequest(body: body, signingPublicKey: signingKey.publicKey),
                             line: line)
        { error in
            guard case .malformedRewrapRequest = error as? TDFKASError else {
                return XCTFail("expected malformedRewrapRequest, got \(error)", line: line)
            }
        }
    }
}
