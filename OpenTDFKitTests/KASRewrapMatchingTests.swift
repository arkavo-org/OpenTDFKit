@preconcurrency import CryptoKit
import Foundation
@testable import OpenTDFKit
import XCTest

/// Path-aware key access object matching: a platform KAS and owner KASs share
/// one host, so a client selects only the objects whose URL is its own KAS,
/// path included (`/kas` counts as no path).
final class KASRewrapMatchingTests: XCTestCase {
    private static let owner = "https://platform.arkavo.net/owner-kas/v1/routes/01HZXK3Q8R4M5N6P7Q8R9S0T1V"

    func testPlatformClientSelectsPlatformKAOsOnly() throws {
        XCTAssertEqual(
            try Self.selected(by: "https://platform.arkavo.net",
                              from: ["https://platform.arkavo.net/kas", "https://platform.arkavo.net", Self.owner]),
            ["https://platform.arkavo.net/kas", "https://platform.arkavo.net"],
        )
    }

    func testKasPathClientSelectsPlatformKAOsOnly() throws {
        XCTAssertEqual(
            try Self.selected(by: "https://platform.arkavo.net/kas",
                              from: ["https://platform.arkavo.net/kas", "https://platform.arkavo.net", Self.owner]),
            ["https://platform.arkavo.net/kas", "https://platform.arkavo.net"],
        )
    }

    func testOwnerClientSelectsOwnKAOOnly() throws {
        XCTAssertEqual(
            try Self.selected(by: Self.owner,
                              from: ["https://platform.arkavo.net/kas", "https://platform.arkavo.net", Self.owner]),
            [Self.owner],
        )
    }

    func testTrailingSlashesIgnored() throws {
        XCTAssertEqual(
            try Self.selected(by: "https://platform.arkavo.net", from: ["https://platform.arkavo.net/kas/"]),
            ["https://platform.arkavo.net/kas/"],
        )
        XCTAssertEqual(try Self.selected(by: Self.owner, from: [Self.owner + "/"]), [Self.owner + "/"])
    }

    func testPathIsCaseSensitiveHostIsNot() throws {
        XCTAssertEqual(
            try Self.selected(by: "https://platform.arkavo.net", from: ["https://PLATFORM.arkavo.net/kas"]),
            ["https://PLATFORM.arkavo.net/kas"],
        )
        let shouted = Self.owner.replacingOccurrences(of: "/owner-kas/", with: "/OWNER-KAS/")
        XCTAssertEqual(try Self.selected(by: Self.owner, from: [shouted]), [])
    }

    /// The cost the spec names: a KAS mounted under another prefix needs that
    /// prefix in the client's configured URL.
    func testOtherPrefixDoesNotMatchPathlessClient() throws {
        XCTAssertEqual(try Self.selected(by: "https://platform.arkavo.net",
                                         from: ["https://platform.arkavo.net/api/kas"]), [])
        XCTAssertEqual(try Self.selected(by: "https://platform.arkavo.net/api/kas",
                                         from: ["https://platform.arkavo.net/api/kas"]),
                       ["https://platform.arkavo.net/api/kas"])
    }

    // MARK: - Helpers

    /// URLs of the key access objects a client configured with `uri` selects.
    static func selected(by uri: String, from urls: [String]) throws -> [String] {
        let client = try KASRewrapClient(configuration: .forKasConnect(uri), oauthToken: "token")
        return try client.keyAccessObjects(in: manifest(kaoURLs: urls)).map(\.url)
    }

    static func manifest(kaoURLs: [String]) throws -> TDFManifest {
        let rsaPEM = try TDFSegmentedPayloadTests.makeRSAPublicKeyPEM()
        let kas = try TDFKasInfo(url: XCTUnwrap(URL(string: "https://kas.example.com")), publicKeyPEM: rsaPEM)
        let policy = try TDFPolicy(json: Data(#"{"uuid":"u","body":{"dataAttributes":[],"dissem":["a@b.c"]}}"#.utf8))
        var manifest = try TDFEncryptor().encrypt(
            plaintext: Data("x".utf8),
            configuration: TDFEncryptionConfiguration(kas: kas, policy: policy),
        ).container.manifest
        let template = manifest.encryptionInformation.keyAccess[0]
        manifest.encryptionInformation.keyAccess = kaoURLs.map { url in
            var kao = template
            kao.url = url
            return kao
        }
        return manifest
    }
}
