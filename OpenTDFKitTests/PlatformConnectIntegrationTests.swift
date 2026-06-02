@preconcurrency import CryptoKit
@testable import OpenTDFKit
import XCTest

/// Live tests against the real Arkavo platform. Opt in with
/// `KAS_INTEGRATION_TESTS=1`. They document the Connect transport milestone.
final class PlatformConnectIntegrationTests: XCTestCase {
    private static let platform = "https://platform.arkavo.net"

    private func requireOptIn() throws {
        guard ProcessInfo.processInfo.environment["KAS_INTEGRATION_TESTS"] == "1" else {
            throw XCTSkip("Set KAS_INTEGRATION_TESTS=1 to run live platform tests")
        }
    }

    func testWellKnownReturnsKasConfig() async throws {
        try requireOptIn()
        let cfg = try await fetchWellKnown(platformURL: Self.platform)
        let kas = try XCTUnwrap(cfg.kas)
        XCTAssertNotNil(kas.connectRewrapURL, "platform should advertise connect_rewrap_url")
        XCTAssertNotNil(kas.connectPublicKeyURL, "platform should advertise connect_public_key_url")
        XCTAssertNotNil(kas.rewrapURL, "platform also exposes legacy REST rewrap_url")
    }

    func testConnectPublicKeyReturnsPEM() async throws {
        try requireOptIn()
        let cfg = try await fetchWellKnown(platformURL: Self.platform)
        let client = try KASRewrapClient(configuration: cfg, oauthToken: "")
        let result = try await client.fetchKasEcPublicKey(algorithm: .ecP256)
        XCTAssertTrue(result.pem.contains("BEGIN PUBLIC KEY"))
        XCTAssertEqual(result.compressedKey.count, 33)
    }

    func testConnectRewrapFakeBearerReturns401() async throws {
        try requireOptIn()
        let cfg = try await fetchWellKnown(platformURL: Self.platform)
        let client = try KASRewrapClient(configuration: cfg,
                                         oauthToken: "eyJhbGciOiJub25lIn0.e30.")
        let kas = try XCTUnwrap(ResourceLocator(protocolEnum: .https, body: "platform.arkavo.net/kas"))
        let header = makeMinimalHeader(kas: kas)
        let kp = EphemeralKeyPair(
            privateKey: P256.KeyAgreement.PrivateKey().rawRepresentation,
            publicKey: P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation,
            curve: .secp256r1,
        )
        do {
            _ = try await client.rewrapNanoTDF(header: Data([0, 0, 0]), parsedHeader: header,
                                               clientKeyPair: kp)
            XCTFail("rewrap should fail without valid auth")
        } catch KASRewrapError.authenticationFailed(_) {
            // expected
        } catch let KASRewrapError.accessDenied(reason) {
            print("AccessDenied: \(reason)")
        } catch let KASRewrapError.httpError(status, message) {
            XCTAssertNotEqual(status, 404, "404 means Connect rewrap path missing: \(message ?? "")")
            XCTAssertTrue((400 ..< 600).contains(status), "expected 4xx/5xx, got \(status)")
        }
    }

    private func makeMinimalHeader(kas: ResourceLocator) -> Header {
        let policy = Policy(type: .embeddedPlaintext,
                            body: EmbeddedPolicyBody(body: Data("{}".utf8)),
                            remote: nil, binding: nil)
        return Header(
            kas: kas,
            policyBindingConfig: PolicyBindingConfig(ecdsaBinding: false, curve: .secp256r1),
            payloadSignatureConfig: SignatureAndPayloadConfig(
                signed: false, signatureCurve: nil, payloadCipher: .aes256GCM128,
            ),
            policy: policy,
            ephemeralPublicKey: P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation,
        )
    }
}
