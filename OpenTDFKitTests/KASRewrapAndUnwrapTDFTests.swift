@preconcurrency import CryptoKit
@testable import OpenTDFKit
import XCTest

/// `KASRewrapClient.rewrapAndUnwrapTDF(manifest:)` against a fake KAS built
/// from the wire definition (not from the library): the fake reads the client
/// public key out of the signed rewrap request, performs ECDH with a fresh
/// session key, derives the KEK with HKDF-SHA256, and AES-GCM-wraps the DEK.
final class KASRewrapAndUnwrapTDFTests: XCTestCase {
    private let kasBaseURL = "https://kas.example.com"

    override func tearDown() {
        MockURLProtocol.handler = nil
        super.tearDown()
    }

    // MARK: - Tests

    /// Standard TDF: the KAS derives the session KEK with `SHA256("TDF")` as the
    /// HKDF salt (go SDK `tdfSalt()`), so the one-call API must recover the DEK.
    func testRewrapAndUnwrapTDFReturnsDEKWithStandardSalt() async throws {
        let dek = SymmetricKey(size: .bits256)
        let fakeKAS = FakeKAS(salt: Self.standardTDFSalt, dek: dek)
        MockURLProtocol.handler = fakeKAS.handler

        let client = try makeClient()
        let recovered = try await client.rewrapAndUnwrapTDF(manifest: makeManifest(kaoCount: 1))

        XCTAssertEqual(Self.data(recovered), Self.data(dek), "Unwrapped key should equal the DEK the fake KAS wrapped")
        XCTAssertEqual(fakeKAS.requestCount, 1)
    }

    /// Regression guard: a KAS wrapping with the NanoTDF v12 salt
    /// (`SHA256(0x4C 0x31 0x4C)`, the `unwrapKey` default) must not unwrap.
    /// The failure must surface as a `KASRewrapError`, not a CryptoKit error.
    func testRewrapAndUnwrapTDFRejectsNanoTDFSaltWrappedKey() async throws {
        let nanoSalt = Data(SHA256.hash(data: Data([0x4C, 0x31, 0x4C])))
        XCTAssertEqual(nanoSalt, CryptoConstants.hkdfSalt, "fixture must be the NanoTDF v12 salt")
        let fakeKAS = FakeKAS(salt: nanoSalt, dek: SymmetricKey(size: .bits256))
        MockURLProtocol.handler = fakeKAS.handler

        let client = try makeClient()
        do {
            _ = try await client.rewrapAndUnwrapTDF(manifest: makeManifest(kaoCount: 1))
            XCTFail("expected unwrap to fail when the KAS used the NanoTDF salt")
        } catch let error as KASRewrapError {
            guard case .keyUnwrapFailed = error else {
                return XCTFail("expected keyUnwrapFailed, got \(error)")
            }
        } catch {
            XCTFail("expected KASRewrapError, got \(type(of: error)): \(error)")
        }
    }

    /// A manifest with no key access object for this KAS is rejected before
    /// any request is sent.
    func testRewrapAndUnwrapTDFThrowsWhenManifestHasNoKAOForKAS() async throws {
        let fakeKAS = FakeKAS(salt: Self.standardTDFSalt, dek: SymmetricKey(size: .bits256))
        MockURLProtocol.handler = fakeKAS.handler

        let client = try makeClient()
        do {
            _ = try await client.rewrapAndUnwrapTDF(manifest: makeManifest(kaoCount: 0))
            XCTFail("expected throw for a manifest without a KAO")
        } catch let error as KASRewrapError {
            guard case .invalidTDFRequest = error else {
                return XCTFail("expected invalidTDFRequest, got \(error)")
            }
        }
        XCTAssertEqual(fakeKAS.requestCount, 0, "no request should reach the KAS")
    }

    /// Several permitted key access objects at one KAS are split-key shares,
    /// not a DEK; the one-call API refuses rather than guessing.
    func testRewrapAndUnwrapTDFThrowsOnMultipleWrappedKeys() async throws {
        let fakeKAS = FakeKAS(salt: Self.standardTDFSalt, dek: SymmetricKey(size: .bits256))
        MockURLProtocol.handler = fakeKAS.handler

        let client = try makeClient()
        do {
            _ = try await client.rewrapAndUnwrapTDF(manifest: makeManifest(kaoCount: 2))
            XCTFail("expected throw for two wrapped keys")
        } catch let KASRewrapError.multipleWrappedKeys(count) {
            XCTAssertEqual(count, 2)
        }
    }

    /// A permit without `sessionPublicKey` cannot be unwrapped with ECDH.
    func testRewrapAndUnwrapTDFThrowsWhenSessionKeyMissing() async throws {
        let fakeKAS = FakeKAS(salt: Self.standardTDFSalt, dek: SymmetricKey(size: .bits256),
                              includeSessionPublicKey: false)
        MockURLProtocol.handler = fakeKAS.handler

        let client = try makeClient()
        do {
            _ = try await client.rewrapAndUnwrapTDF(manifest: makeManifest(kaoCount: 1))
            XCTFail("expected throw when sessionPublicKey is absent")
        } catch let error as KASRewrapError {
            guard case .missingSessionKey = error else {
                return XCTFail("expected missingSessionKey, got \(error)")
            }
        }
    }

    // MARK: - Fixtures

    private static var standardTDFSalt: Data {
        Data(SHA256.hash(data: Data("TDF".utf8)))
    }

    private static func data(_ key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }

    private func makeClient() throws -> KASRewrapClient {
        try KASRewrapClient(
            configuration: OpenTDFConfiguration.forKasConnect(kasBaseURL),
            oauthToken: "test-token",
            urlSession: MockURLProtocol.makeSession(),
        )
    }

    private func makeManifest(kaoCount: Int) -> TDFManifest {
        let keyAccess = (0 ..< kaoCount).map { index in
            TDFKeyAccessObject(
                type: .ecWrapped,
                url: "\(kasBaseURL)/kas",
                protocolValue: .kas,
                wrappedKey: Data(repeating: UInt8(index), count: 48).base64EncodedString(),
                policyBinding: TDFPolicyBinding(alg: "HS256", hash: "binding"),
                kid: "kid-\(index)",
                sid: "split-\(index)",
            )
        }
        return TDFManifest(
            schemaVersion: "4.3.0",
            payload: TDFPayloadDescriptor(type: .reference, url: "0.payload", protocolValue: .zip, isEncrypted: true),
            encryptionInformation: TDFEncryptionInformation(
                type: .split,
                keyAccess: keyAccess,
                method: TDFMethodDescriptor(algorithm: "AES-256-GCM", iv: "", isStreamable: true),
                policy: Data("{}".utf8).base64EncodedString(),
            ),
        )
    }

    /// Fake KAS `Rewrap` handler. Implements the platform's EC session wrap
    /// from the definition: ECDH(session, client) → HKDF-SHA256(salt, empty
    /// info, 32 bytes) → AES-256-GCM seal of the DEK → `nonce || ct || tag`.
    private final class FakeKAS: @unchecked Sendable {
        private let salt: Data
        private let dek: Data
        private let includeSessionPublicKey: Bool
        private(set) var requestCount = 0

        init(salt: Data, dek: SymmetricKey, includeSessionPublicKey: Bool = true) {
            self.salt = salt
            self.dek = KASRewrapAndUnwrapTDFTests.data(dek)
            self.includeSessionPublicKey = includeSessionPublicKey
        }

        var handler: (URLRequest) throws -> (HTTPURLResponse, Data) {
            { [self] request in
                requestCount += 1
                XCTAssertEqual(request.url?.path, "/kas.AccessService/Rewrap")

                let (clientPublicKey, kaoIDs) = try Self.parseRewrapRequest(request)

                let sessionKey = P256.KeyAgreement.PrivateKey()
                let shared = try sessionKey.sharedSecretFromKeyAgreement(with: clientPublicKey)
                let kek = shared.hkdfDerivedSymmetricKey(
                    using: SHA256.self, salt: salt, sharedInfo: Data(), outputByteCount: 32,
                )

                let results: [[String: Any]] = try kaoIDs.map { id in
                    let sealed = try AES.GCM.seal(dek, using: kek)
                    guard let combined = sealed.combined else {
                        throw NSError(domain: "FakeKAS", code: 1)
                    }
                    return [
                        "keyAccessObjectId": id,
                        "status": "permit",
                        "kasWrappedKey": combined.base64EncodedString(),
                    ]
                }
                var body: [String: Any] = [
                    "responses": [["policyId": "policy", "results": results]],
                ]
                if includeSessionPublicKey {
                    body["sessionPublicKey"] = sessionKey.publicKey.pemRepresentation
                }
                let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                                               headerFields: ["Content-Type": "application/json"])!
                return try (response, JSONSerialization.data(withJSONObject: body))
            }
        }

        /// Reads `signed_request_token`, decodes the JWT payload's `requestBody`,
        /// and returns the client's P-256 public key plus the KAO ids requested.
        private static func parseRewrapRequest(_ request: URLRequest) throws -> (P256.KeyAgreement.PublicKey, [String]) {
            let body = try XCTUnwrap(readBody(of: request))
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
            let kaos = try XCTUnwrap(requests.first?["keyAccessObjects"] as? [[String: Any]])
            let ids = try kaos.map { try XCTUnwrap($0["keyAccessObjectId"] as? String) }
            return try (P256.KeyAgreement.PublicKey(pemRepresentation: clientPEM), ids)
        }

        /// URLSession hands `URLProtocol` the body as a stream, not `httpBody`.
        private static func readBody(of request: URLRequest) -> Data? {
            if let body = request.httpBody {
                return body
            }
            guard let stream = request.httpBodyStream else { return nil }
            stream.open()
            defer { stream.close() }
            var data = Data()
            var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let read = stream.read(&buffer, maxLength: buffer.count)
                if read <= 0 {
                    break
                }
                data.append(buffer, count: read)
            }
            return data
        }
    }
}
