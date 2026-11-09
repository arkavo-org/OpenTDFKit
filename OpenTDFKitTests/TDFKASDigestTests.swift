@preconcurrency import CryptoKit
import Foundation
@testable import OpenTDFKit
import XCTest

/// The digests the owner's phone and the receiver both compute: the request
/// token digest, the key access object digest and the public-key fingerprint.
final class TDFKASDigestTests: XCTestCase {
    func testRequestTokenDigestIsSHA256OfTokenBytes() {
        XCTAssertEqual(TDFKAS.requestTokenDigest("a.b.c"), Data(SHA256.hash(data: Data("a.b.c".utf8))))
    }

    /// The encoding written out here, field by field, independently of the
    /// implementation.
    func testKAODigestKnownVector() {
        let kao = Self.fullKAO()
        var expected = Data("OpenTDFKit/kao-digest/v1".utf8)
        for value in ["ec-wrapped", "https://h/owner-kas/v1/routes/R", "kas", "d3JhcHBlZA==", "HS256",
                      "aGFzaA==", "e1", "s1", "bWV0YQ==", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"]
        {
            let bytes = Data(value.utf8)
            expected.append(1)
            expected.append(contentsOf: withUnsafeBytes(of: UInt32(bytes.count).bigEndian) { Array($0) })
            expected.append(bytes)
        }
        XCTAssertEqual(TDFKAS.keyAccessObjectDigest(kao), Data(SHA256.hash(data: expected)))
    }

    func testKAODigestIgnoresSchemaVersion() {
        var withVersion = Self.fullKAO()
        withVersion.schemaVersion = "1.0"
        var withoutVersion = Self.fullKAO()
        withoutVersion.schemaVersion = nil
        XCTAssertEqual(TDFKAS.keyAccessObjectDigest(withVersion), TDFKAS.keyAccessObjectDigest(withoutVersion))
    }

    func testKAODigestEmptyAlgIsHS256() {
        var empty = Self.fullKAO()
        empty.policyBinding.alg = ""
        XCTAssertEqual(TDFKAS.keyAccessObjectDigest(empty), TDFKAS.keyAccessObjectDigest(Self.fullKAO()))
    }

    func testKAODigestChangesWithEachIncludedField() {
        let mutations: [(inout TDFKeyAccessObject) -> Void] = [
            { $0.type = .wrapped },
            { $0.url = "https://h/owner-kas/v1/routes/S" },
            { $0.wrappedKey = "b3RoZXI=" },
            { $0.policyBinding.alg = "GMAC" },
            { $0.policyBinding.hash = "b3RoZXI=" },
            { $0.kid = "e2" },
            { $0.sid = "s2" },
            { $0.encryptedMetadata = "b3RoZXI=" },
            { $0.ephemeralPublicKey = "other" },
        ]
        var digests: Set<Data> = [TDFKAS.keyAccessObjectDigest(Self.fullKAO())]
        for mutate in mutations {
            var kao = Self.fullKAO()
            mutate(&kao)
            digests.insert(TDFKAS.keyAccessObjectDigest(kao))
        }
        // `protocol` has a single value (`kas`), so it cannot be mutated here; the
        // known vector covers its place in the encoding.
        XCTAssertEqual(digests.count, mutations.count + 1)
    }

    func testKAODigestAbsentVersusEmptyDiffer() {
        var absent = Self.fullKAO()
        absent.kid = nil
        var empty = Self.fullKAO()
        empty.kid = ""
        XCTAssertNotEqual(TDFKAS.keyAccessObjectDigest(absent), TDFKAS.keyAccessObjectDigest(empty))
    }

    /// The object in the file and the one the client forwards in its Rewrap
    /// request (which drops `schemaVersion` and reorders keys) digest the same.
    func testKAODigestSameForManifestAndForwardedKAO() throws {
        let kasKey = P256.KeyAgreement.PrivateKey()
        let kas = try TDFKasInfo(
            url: XCTUnwrap(URL(string: "https://kas.example.com/kas")),
            publicKeyPEM: kasKey.publicKey.pemRepresentation,
            kid: "e1",
            keyType: .ecP256,
        )
        let policy = try TDFPolicy(json: Data(#"{"uuid":"u","body":{"dataAttributes":[],"dissem":["a@b.c"]}}"#.utf8))
        let manifest = try TDFEncryptor().encrypt(
            plaintext: Data("x".utf8),
            configuration: TDFEncryptionConfiguration(kas: kas, policy: policy),
        ).container.manifest
        let manifestKAO = manifest.encryptionInformation.keyAccess[0]
        XCTAssertEqual(manifestKAO.schemaVersion, "1.0")

        let client = try KASRewrapClient(
            configuration: .forKasConnect("https://kas.example.com"),
            oauthToken: "token",
        )
        let entry = try client.standardPolicyRequest(manifest: manifest, keyAccessEntries: [manifestKAO])
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(entry)) as? [String: Any])
        let wrapper = try XCTUnwrap((json["keyAccessObjects"] as? [[String: Any]])?.first)
        let forwardedJSON = try JSONSerialization.data(withJSONObject: XCTUnwrap(wrapper["keyAccessObject"]))
        let forwarded = try JSONDecoder().decode(TDFKeyAccessObject.self, from: forwardedJSON)
        XCTAssertNil(forwarded.schemaVersion, "the client drops schemaVersion")

        XCTAssertEqual(TDFKAS.keyAccessObjectDigest(forwarded), TDFKAS.keyAccessObjectDigest(manifestKAO))
    }

    /// The same, for an object with every digest field set, `sid` and
    /// `encryptedMetadata` included.
    func testKAODigestSameForForwardedKAOWithAllFields() throws {
        let manifestKAO = Self.fullKAO()
        let client = try KASRewrapClient(configuration: .forKasConnect("https://h"), oauthToken: "token")
        var manifest = try KASRewrapMatchingTests.manifest(kaoURLs: ["https://h/kas"])
        manifest.encryptionInformation.keyAccess = [manifestKAO]
        let entry = try client.standardPolicyRequest(manifest: manifest, keyAccessEntries: [manifestKAO])
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(entry)) as? [String: Any])
        let wrapper = try XCTUnwrap((json["keyAccessObjects"] as? [[String: Any]])?.first)
        let forwarded = try JSONDecoder().decode(
            TDFKeyAccessObject.self,
            from: JSONSerialization.data(withJSONObject: XCTUnwrap(wrapper["keyAccessObject"])),
        )
        XCTAssertEqual(forwarded.sid, "s1")
        XCTAssertEqual(forwarded.encryptedMetadata, "bWV0YQ==")
        XCTAssertEqual(TDFKAS.keyAccessObjectDigest(forwarded), TDFKAS.keyAccessObjectDigest(manifestKAO))
    }

    func testFingerprintIndependentOfKeyEncoding() throws {
        let key = P256.KeyAgreement.PrivateKey().publicKey
        let expected = Data(SHA256.hash(data: key.x963Representation))
        let parsed = try [
            P256.KeyAgreement.PublicKey(pemRepresentation: key.pemRepresentation),
            P256.KeyAgreement.PublicKey(derRepresentation: key.derRepresentation),
            P256.KeyAgreement.PublicKey(x963Representation: key.x963Representation),
            P256.KeyAgreement.PublicKey(compressedRepresentation: key.compressedRepresentation),
        ]
        for candidate in parsed {
            XCTAssertEqual(TDFKAS.publicKeyFingerprint(candidate), expected)
        }
    }

    // MARK: - Helpers

    static func fullKAO() -> TDFKeyAccessObject {
        TDFKeyAccessObject(
            type: .ecWrapped,
            url: "https://h/owner-kas/v1/routes/R",
            protocolValue: .kas,
            wrappedKey: "d3JhcHBlZA==",
            policyBinding: TDFPolicyBinding(alg: "HS256", hash: "aGFzaA=="),
            encryptedMetadata: "bWV0YQ==",
            kid: "e1",
            sid: "s1",
            schemaVersion: "1.0",
            ephemeralPublicKey: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
        )
    }
}
