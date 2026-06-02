@testable import OpenTDFKit
import XCTest

final class KASDiscoveryTests: XCTestCase {
    /// Captured from https://platform.arkavo.net/.well-known/opentdf-configuration on 2026-05-28
    static let platformWellKnown = """
    {
        "health": { "endpoint": "/healthz" },
        "idp": {
            "access_token_format": "application/cwt",
            "authorization_endpoint": "https://identity.arkavo.net/oauth/authorize",
            "cose_keys_uri": "https://identity.arkavo.net/.well-known/cose-keys",
            "id_token_signing_alg_values_supported": ["ES256"],
            "issuer": "https://identity.arkavo.net",
            "jwks_uri": "https://identity.arkavo.net/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "token_endpoint": "https://identity.arkavo.net/oauth/token",
            "userinfo_endpoint": "https://identity.arkavo.net/oauth/userinfo"
        },
        "kas": {
            "algorithms": ["ec:secp256r1", "rsa:2048"],
            "connect_public_key_url": "https://platform.arkavo.net/kas.AccessService/PublicKey",
            "connect_rewrap_url": "https://platform.arkavo.net/kas.AccessService/Rewrap",
            "public_key_url": "https://platform.arkavo.net/kas/v2/kas_public_key",
            "rewrap_url": "https://platform.arkavo.net/kas/v2/rewrap",
            "uri": "https://platform.arkavo.net"
        },
        "platform_issuer": "https://identity.arkavo.net"
    }
    """

    func testDecodesPlatformWellKnown() throws {
        let cfg = try JSONDecoder().decode(OpenTDFConfiguration.self,
                                           from: Data(Self.platformWellKnown.utf8))
        let kas = try XCTUnwrap(cfg.kas)
        XCTAssertEqual(kas.uri, "https://platform.arkavo.net")
        XCTAssertEqual(kas.algorithms, ["ec:secp256r1", "rsa:2048"])
        XCTAssertEqual(kas.connectRewrapURL, "https://platform.arkavo.net/kas.AccessService/Rewrap")
        XCTAssertEqual(kas.rewrapURL, "https://platform.arkavo.net/kas/v2/rewrap")
        let idp = try XCTUnwrap(cfg.idp)
        XCTAssertEqual(idp.issuer, "https://identity.arkavo.net")
        XCTAssertEqual(idp.accessTokenFormat, "application/cwt")
        XCTAssertEqual(cfg.platformIssuer, "https://identity.arkavo.net")
    }

    func testDecodesMinimalKasOnly() throws {
        let json = """
        {"kas":{"uri":"https://k.example.com","algorithms":[],
        "rewrap_url":"https://k.example.com/kas/v2/rewrap",
        "public_key_url":"https://k.example.com/kas/v2/kas_public_key"}}
        """
        let cfg = try JSONDecoder().decode(OpenTDFConfiguration.self, from: Data(json.utf8))
        let kas = try XCTUnwrap(cfg.kas)
        XCTAssertNil(kas.connectRewrapURL)
        XCTAssertEqual(kas.rewrapURL, "https://k.example.com/kas/v2/rewrap")
        XCTAssertNil(cfg.idp)
    }

    func testForKasConnectConstructsURLs() {
        let cfg = OpenTDFConfiguration.forKasConnect("https://kas.example.com")
        XCTAssertEqual(cfg.kas?.connectRewrapURL, "https://kas.example.com/kas.AccessService/Rewrap")
        XCTAssertEqual(cfg.kas?.connectPublicKeyURL, "https://kas.example.com/kas.AccessService/PublicKey")
        XCTAssertEqual(cfg.kas?.uri, "https://kas.example.com")
    }

    func testForKasConnectHandlesTrailingSlash() {
        let cfg = OpenTDFConfiguration.forKasConnect("https://kas.example.com/")
        XCTAssertEqual(cfg.kas?.connectRewrapURL, "https://kas.example.com/kas.AccessService/Rewrap")
    }

    func testForKasLegacyRestConstructsURLs() {
        let cfg = OpenTDFConfiguration.forKasLegacyRest("https://kas.example.com")
        XCTAssertEqual(cfg.kas?.rewrapURL, "https://kas.example.com/kas/v2/rewrap")
        XCTAssertEqual(cfg.kas?.publicKeyURL, "https://kas.example.com/kas/v2/kas_public_key")
    }

    func testValidateAcceptsHTTPSAndLoopbackHTTP() {
        XCTAssertNoThrow(try validateKasURL("https://kas.example.com/kas.AccessService/Rewrap"))
        XCTAssertNoThrow(try validateKasURL("http://localhost:8080/x"))
        XCTAssertNoThrow(try validateKasURL("http://127.0.0.1:8080/x"))
        XCTAssertNoThrow(try validateKasURL("http://[::1]:8080/x"))
    }

    func testValidateRejectsNonLoopbackHTTPAndBadScheme() {
        XCTAssertThrowsError(try validateKasURL("http://evil.com/x"))
        XCTAssertThrowsError(try validateKasURL("ftp://kas.example.com/x"))
    }

    func testValidateRejectsIPv4PrivateAndLinkLocal() {
        for url in ["https://10.0.0.1/x", "https://172.16.0.1/x",
                    "https://192.168.1.1/x", "https://169.254.169.254/x"]
        {
            XCTAssertThrowsError(try validateKasURL(url), "\(url) should be rejected")
        }
    }

    func testValidateRejectsIPv6ULAAndLinkLocal() {
        for url in ["https://[fd00::1]/x", "https://[fc00::1]/x", "https://[fe80::1]/x"] {
            XCTAssertThrowsError(try validateKasURL(url), "\(url) should be rejected")
        }
    }

    func testValidateRejectsUnspecifiedAddresses() {
        XCTAssertThrowsError(try validateKasURL("https://0.0.0.0/x"))
        XCTAssertThrowsError(try validateKasURL("https://[::]/x"))
    }

    func testValidateRejectsIPv4MappedMetadataAddress() {
        XCTAssertThrowsError(try validateKasURL("https://[::ffff:169.254.169.254]/x"))
        XCTAssertThrowsError(try validateKasURL("https://[::ffff:10.0.0.1]/x"))
    }

    func testFromConfigPicksConnectWhenPresent() throws {
        let cfg = try JSONDecoder().decode(OpenTDFConfiguration.self,
                                           from: Data(Self.platformWellKnown.utf8))
        let ep = try KasEndpoints.from(cfg)
        XCTAssertEqual(ep.rewrapURL, "https://platform.arkavo.net/kas.AccessService/Rewrap")
        XCTAssertEqual(ep.publicKeyURL, "https://platform.arkavo.net/kas.AccessService/PublicKey")
        XCTAssertEqual(ep.transport, .connect)
    }

    func testFromConfigFallsBackToRest() throws {
        let cfg = OpenTDFConfiguration.forKasLegacyRest("https://k.example.com")
        let ep = try KasEndpoints.from(cfg)
        XCTAssertEqual(ep.rewrapURL, "https://k.example.com/kas/v2/rewrap")
        XCTAssertEqual(ep.transport, .legacyRest)
    }

    func testFromConfigThrowsWhenKasMissing() {
        let cfg = OpenTDFConfiguration(kas: nil, idp: nil, platformIssuer: "https://x.com")
        XCTAssertThrowsError(try KasEndpoints.from(cfg))
    }

    func testFromConfigThrowsWhenUriEmpty() {
        let cfg = OpenTDFConfiguration(
            kas: KasConfig(uri: "", algorithms: [],
                           publicKeyURL: "https://k.example.com/kas/v2/kas_public_key",
                           rewrapURL: "https://k.example.com/kas/v2/rewrap",
                           connectPublicKeyURL: nil, connectRewrapURL: nil),
            idp: nil, platformIssuer: nil,
        )
        XCTAssertThrowsError(try KasEndpoints.from(cfg))
    }

    func testFromConfigThrowsWhenURLsMissing() {
        let cfg = OpenTDFConfiguration(
            kas: KasConfig(uri: "https://k.example.com", algorithms: [], publicKeyURL: nil,
                           rewrapURL: nil, connectPublicKeyURL: nil, connectRewrapURL: nil),
            idp: nil, platformIssuer: nil,
        )
        XCTAssertThrowsError(try KasEndpoints.from(cfg))
    }

    func testFromConfigRejectsHostileConnectURL() {
        let cfg = OpenTDFConfiguration(
            kas: KasConfig(uri: "https://platform.example.com", algorithms: [],
                           publicKeyURL: nil, rewrapURL: nil,
                           connectPublicKeyURL: "https://platform.example.com/kas.AccessService/PublicKey",
                           connectRewrapURL: "https://169.254.169.254/kas.AccessService/Rewrap"),
            idp: nil, platformIssuer: nil,
        )
        XCTAssertThrowsError(try KasEndpoints.from(cfg))
    }

    func testFetchWellKnownReturnsParsedConfig() async throws {
        MockURLProtocol.handler = { req in
            XCTAssertEqual(req.url?.path, "/.well-known/opentdf-configuration")
            let resp = HTTPURLResponse(url: req.url!, statusCode: 200,
                                       httpVersion: nil, headerFields: nil)!
            return (resp, Data(Self.platformWellKnown.utf8))
        }
        defer { MockURLProtocol.handler = nil }
        let session = MockURLProtocol.makeSession()
        let cfg = try await fetchWellKnown(platformURL: "https://platform.arkavo.net",
                                           urlSession: session)
        XCTAssertNotNil(cfg.kas)
        XCTAssertEqual(cfg.platformIssuer, "https://identity.arkavo.net")
    }

    func testFetchWellKnown404Throws() async {
        MockURLProtocol.handler = { req in
            let resp = HTTPURLResponse(url: req.url!, statusCode: 404,
                                       httpVersion: nil, headerFields: nil)!
            return (resp, Data("not found".utf8))
        }
        defer { MockURLProtocol.handler = nil }
        let session = MockURLProtocol.makeSession()
        do {
            _ = try await fetchWellKnown(platformURL: "https://platform.arkavo.net",
                                         urlSession: session)
            XCTFail("expected throw")
        } catch let KASDiscoveryError.httpError(status, _) {
            XCTAssertEqual(status, 404)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testParseConnectErrorValidBody() {
        let err = parseConnectError(#"{"code":"unauthenticated","message":"missing bearer token"}"#)
        XCTAssertEqual(err?.code, "unauthenticated")
        XCTAssertEqual(err?.message, "missing bearer token")
    }

    func testParseConnectErrorGarbageReturnsNil() {
        XCTAssertNil(parseConnectError("not json"))
        XCTAssertNil(parseConnectError(""))
        XCTAssertNil(parseConnectError(#"{"unrelated":"shape"}"#))
    }
}
