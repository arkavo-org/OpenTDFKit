@preconcurrency import CryptoKit
@testable import OpenTDFKit
import XCTest

final class KASConnectTransportTests: XCTestCase {
    override func tearDown() {
        MockURLProtocol.handler = nil
        super.tearDown()
    }

    /// EC public-key fetch over Connect POSTs to /kas.AccessService/PublicKey
    /// and parses the PEM + kid.
    func testConnectECPublicKeyFetch() async throws {
        // Generate a real P-256 key so the PEM round-trips correctly.
        let realKey = P256.KeyAgreement.PrivateKey()
        let derData = realKey.publicKey.derRepresentation
        let base64Lines = derData.base64EncodedString()
        let pem = "-----BEGIN PUBLIC KEY-----\n\(base64Lines)\n-----END PUBLIC KEY-----"

        MockURLProtocol.handler = { req in
            XCTAssertEqual(req.httpMethod, "POST")
            XCTAssertEqual(req.url?.path, "/kas.AccessService/PublicKey")
            XCTAssertEqual(req.value(forHTTPHeaderField: "Connect-Protocol-Version"), "1")
            let resp = HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: nil,
                                       headerFields: ["Content-Type": "application/json"])!
            let escapedPem = pem.replacingOccurrences(of: "\n", with: "\\n")
            let json = "{\"publicKey\":\"\(escapedPem)\",\"kid\":\"ec:secp256r1\"}"
            return (resp, Data(json.utf8))
        }
        let session = MockURLProtocol.makeSession()
        let cfg = OpenTDFConfiguration.forKasConnect("https://platform.arkavo.net")
        let client = try KASRewrapClient(configuration: cfg, oauthToken: "t", urlSession: session)
        let result = try await client.fetchKasEcPublicKey(algorithm: .ecP256)
        XCTAssertEqual(result.kid, "ec:secp256r1")
        XCTAssertEqual(result.compressedKey.count, 33)
        XCTAssertEqual(result.compressedKey, realKey.publicKey.compressedRepresentation)
    }

    /// A Connect 401 envelope surfaces as authenticationFailed with the code in
    /// the reason string.
    func testConnectRewrapErrorEnvelopeSurfacesReason() async throws {
        MockURLProtocol.handler = { req in
            XCTAssertEqual(req.url?.path, "/kas.AccessService/Rewrap")
            let resp = HTTPURLResponse(url: req.url!, statusCode: 401, httpVersion: nil,
                                       headerFields: nil)!
            return (resp, Data(#"{"code":"unauthenticated","message":"missing bearer"}"#.utf8))
        }
        let session = MockURLProtocol.makeSession()
        let cfg = OpenTDFConfiguration.forKasConnect("https://platform.arkavo.net")
        let client = try KASRewrapClient(configuration: cfg, oauthToken: "t", urlSession: session)

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
            XCTFail("expected throw")
        } catch let KASRewrapError.authenticationFailed(reason) {
            XCTAssertEqual(reason, "unauthenticated: missing bearer")
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
