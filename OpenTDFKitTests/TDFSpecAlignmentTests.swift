import CryptoKit
import Foundation
@testable import OpenTDFKit
import XCTest

/// Manifest shapes the OpenTDF spec (and in-flight spec PR #70) allows and other
/// SDKs write, which OpenTDFKit must parse and decrypt.
final class TDFSpecAlignmentTests: XCTestCase {
    // MARK: - Manifest decoding

    func testDecodesPolicyBindingStringFormAsHS256() throws {
        let manifest = try decodeManifest(policyBinding: #""Zm9v""#)
        let binding = manifest.encryptionInformation.keyAccess[0].policyBinding
        XCTAssertEqual(binding.alg, "HS256")
        XCTAssertEqual(binding.hash, "Zm9v")
    }

    func testDecodesPolicyBindingWithAbsentOrEmptyAlgAsHS256() throws {
        for binding in [#"{"hash":"Zm9v"}"#, #"{"alg":"","hash":"Zm9v"}"#] {
            let manifest = try decodeManifest(policyBinding: binding)
            XCTAssertEqual(manifest.encryptionInformation.keyAccess[0].policyBinding.alg, "HS256")
        }
    }

    func testDecodesRootSignatureWithAbsentAlgAsHS256() throws {
        let manifest = try decodeManifest(rootSignature: #"{"sig":"Zm9v"}"#)
        XCTAssertEqual(manifest.encryptionInformation.integrityInformation?.rootSignature.alg, "HS256")
    }

    func testDecodesSegmentsWithoutPlaintextSizeUsingDefault() throws {
        let manifest = try decodeManifest(segments: #"[{"hash":"Zm9v","encryptedSegmentSize":0}]"#)
        let segment = try XCTUnwrap(manifest.encryptionInformation.integrityInformation?.segments.first)
        XCTAssertEqual(segment.segmentSize, 2_097_152)
        XCTAssertNil(segment.encryptedSegmentSize, "encryptedSegmentSize 0 means omitted")
    }

    func testDecodesNewKeyAccessTypesAndZipstream() throws {
        for type in ["hybrid-wrapped", "mlkem-wrapped", "ec-wrapped"] {
            let manifest = try decodeManifest(keyAccessType: type, payloadProtocol: "zipstream")
            XCTAssertEqual(manifest.encryptionInformation.keyAccess[0].type.rawValue, type)
            XCTAssertEqual(manifest.payload.protocolValue, .zipstream)
        }
    }

    func testDecodesAnyAssertionStatementFormat() throws {
        let assertion = #"[{"id":"system-metadata","type":"other","scope":"payload","appliesToState":"unencrypted","statement":{"format":"json","schema":"system-metadata-v1","value":"{}"},"binding":{"method":"jws","signature":"x"}}]"#
        let manifest = try decodeManifest(assertions: assertion)
        XCTAssertEqual(manifest.assertions?.first?.statement.format.rawValue, "json")
    }

    // MARK: - Encryption output

    func testEncryptWritesFirstSegmentNonceAsMethodIV() throws {
        let result = try TDFEncryptor().encrypt(
            plaintext: Data(count: 3 * 1024 * 1024),
            configuration: makeConfiguration(),
            segmentSize: 2 * 1024 * 1024,
        )
        let iv = try XCTUnwrap(Data(base64Encoded: result.container.manifest.encryptionInformation.method.iv))
        XCTAssertEqual(iv, result.container.payload.prefix(12))
    }

    func testEncryptAlwaysWritesSpecVersion430() throws {
        let configuration = try makeConfiguration()
        let result = try TDFEncryptor().encrypt(plaintext: Data("x".utf8), configuration: configuration)
        XCTAssertEqual(result.container.manifest.schemaVersion, "4.3.0")
    }

    // MARK: - Decryption checks

    func testDecryptAcceptsRootSignatureWithEmptyAlg() throws {
        let result = try TDFEncryptor().encrypt(plaintext: Data("hello".utf8), configuration: makeConfiguration(), segmentSize: 1024)
        var manifest = result.container.manifest
        manifest.encryptionInformation.integrityInformation?.rootSignature.alg = ""
        let container = TDFContainer(manifest: manifest, payload: result.container.payload)

        XCTAssertEqual(try TDFDecryptor().decrypt(container: container, symmetricKey: result.symmetricKey), Data("hello".utf8))
    }

    func testDecryptRejectsUnsupportedPayloadAlgorithm() throws {
        let result = try TDFEncryptor().encrypt(plaintext: Data("hello".utf8), configuration: makeConfiguration(), segmentSize: 1024)
        var manifest = result.container.manifest
        manifest.encryptionInformation.method.algorithm = "AES-256-CBC"
        let container = TDFContainer(manifest: manifest, payload: result.container.payload)

        XCTAssertThrowsError(try TDFDecryptor().decrypt(container: container, symmetricKey: result.symmetricKey)) { error in
            XCTAssertEqual(error as? TDFDecryptError, .unsupportedPayloadAlgorithm("AES-256-CBC"))
        }
    }

    // MARK: - Key splits

    func testCombinesOneSharePerSplitID() throws {
        let share1 = Data((0 ..< 32).map { UInt8($0) })
        let share2 = Data((0 ..< 32).map { UInt8(255 - $0) })
        // Two alternatives for split "a" (same share), one object for split "b".
        let shares: [(sid: String?, share: Data?)] = [("a", nil), ("a", share1), ("b", share2)]
        let combined = try TDFDecryptor.combineKeyShares(shares.map { entry in
            (sid: entry.sid, unwrap: { () throws -> Data in
                guard let share = entry.share else { throw TDFDecryptError.missingKeyAccess }
                return share
            })
        })
        XCTAssertEqual(combined, Data(zip(share1, share2).map { $0 ^ $1 }))
    }

    func testTreatsObjectsWithoutSplitIDAsAlternatives() throws {
        let share = Data(repeating: 0x5A, count: 32)
        let combined = try TDFDecryptor.combineKeyShares([
            (sid: nil, unwrap: { share }),
            (sid: nil, unwrap: { share }),
        ])
        XCTAssertEqual(combined, share, "same-split objects must not be XORed together")
    }

    func testCombineFailsWhenASplitHasNoUsableShare() {
        XCTAssertThrowsError(try TDFDecryptor.combineKeyShares([
            (sid: "a", unwrap: { Data(count: 32) }),
            (sid: "b", unwrap: { throw TDFDecryptError.missingKeyAccess }),
        ]))
    }

    // MARK: - File multi-segment encryption

    func testFileMultiSegmentEncryptsInputBeyondListedSizes() throws {
        let plaintext = Data((0 ..< 5000).map { UInt8(truncatingIfNeeded: $0) })
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let inputURL = directory.appendingPathComponent("in.bin")
        let outputURL = directory.appendingPathComponent("out.tdf")
        try plaintext.write(to: inputURL)

        let result = try TDFEncryptor().encryptFileMultiSegment(
            inputURL: inputURL,
            outputURL: outputURL,
            configuration: makeConfiguration(),
            segmentSizes: [1000, 1500],
        )

        let segments = try XCTUnwrap(result.container.manifest.encryptionInformation.integrityInformation?.segments)
        XCTAssertEqual(segments.map(\.segmentSize), [1000, 1500, 1500, 1000], "the last size repeats until EOF")
        let loaded = try TDFLoader().load(from: outputURL)
        XCTAssertEqual(try TDFDecryptor().decrypt(container: loaded, symmetricKey: result.symmetricKey), plaintext)
    }

    // MARK: - Helpers

    private static let kasPublicKeyPEM: String? = try? TDFSegmentedPayloadTests.makeRSAPublicKeyPEM()

    private func makeConfiguration() throws -> TDFEncryptionConfiguration {
        let pem = try XCTUnwrap(Self.kasPublicKeyPEM)
        let kasInfo = try TDFKasInfo(url: XCTUnwrap(URL(string: "https://kas.example.com/kas")), publicKeyPEM: pem, kid: "r1")
        let policy = try TDFPolicy(json: Data(#"{"uuid":"3f1c2d4e-5a6b-4c7d-8e9f-0a1b2c3d4e5f","body":{"dataAttributes":[],"dissem":[]}}"#.utf8))
        return TDFEncryptionConfiguration(kas: kasInfo, policy: policy)
    }

    private func decodeManifest(
        policyBinding: String = #"{"alg":"HS256","hash":"Zm9v"}"#,
        rootSignature: String = #"{"alg":"HS256","sig":"Zm9v"}"#,
        segments: String = #"[{"hash":"Zm9v","segmentSize":5,"encryptedSegmentSize":33}]"#,
        keyAccessType: String = "wrapped",
        payloadProtocol: String = "zip",
        assertions: String = "null",
    ) throws -> TDFManifest {
        let json = """
        {"schemaVersion":"4.3.0",
         "payload":{"type":"reference","url":"0.payload","protocol":"\(payloadProtocol)","isEncrypted":true,"mimeType":"application/octet-stream"},
         "encryptionInformation":{"type":"split","policy":"e30=",
          "keyAccess":[{"type":"\(keyAccessType)","url":"https://kas.example.com/kas","protocol":"kas","wrappedKey":"Zm9v","policyBinding":\(policyBinding),"kid":"r1"}],
          "method":{"algorithm":"AES-256-GCM","iv":"","isStreamable":true},
          "integrityInformation":{"rootSignature":\(rootSignature),"segmentHashAlg":"GMAC","segmentSizeDefault":2097152,"encryptedSegmentSizeDefault":2097180,"segments":\(segments)}},
         "assertions":\(assertions)}
        """
        return try JSONDecoder().decode(TDFManifest.self, from: Data(json.utf8))
    }
}
