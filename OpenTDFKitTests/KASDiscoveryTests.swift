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
}
