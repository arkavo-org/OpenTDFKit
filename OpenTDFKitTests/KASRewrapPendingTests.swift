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

    // MARK: - Helpers

    func makeClient(transport: any KASRewrapTransport = URLSessionKASTransport()) throws -> KASRewrapClient {
        try KASRewrapClient(
            configuration: .forKasConnect(Self.ownerURL),
            oauthToken: "owner-kas-token",
            transport: transport,
            signingKey: signingKey,
        )
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
