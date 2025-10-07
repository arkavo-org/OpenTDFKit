import CryptoKit
import Foundation
@testable import OpenTDFKit
import XCTest

/// Tests for developer ergonomics improvements based on API recommendations
final class DeveloperErgonomicsTests: XCTestCase {
    let testPlaintext = "Developer ergonomics test data".data(using: .utf8)!

    // MARK: - Optional Integrity Information Tests

    func testOptionalIntegrityInformation() throws {
        // Create manifest without integrity information
        let symmetricKey = try StandardTDFCrypto.generateSymmetricKey()
        let policyJSON = testPolicyJSON()

        let policyBinding = StandardTDFCrypto.policyBinding(policy: policyJSON, symmetricKey: symmetricKey)
        let wrappedKey = "test-wrapped-key"

        let kasObject = TDFKeyAccessObject(
            type: .wrapped,
            url: "https://kas.example.com",
            protocolValue: .kas,
            wrappedKey: wrappedKey,
            policyBinding: policyBinding,
        )

        let method = TDFMethodDescriptor(
            algorithm: "AES-256-GCM",
            iv: "dGVzdC1pdg==",
            isStreamable: true,
        )

        // Create encryption info WITHOUT integrity information
        let encryptionInfo = TDFEncryptionInformation(
            type: .split,
            keyAccess: [kasObject],
            method: method,
            policy: policyJSON.base64EncodedString(),
        )

        XCTAssertNil(encryptionInfo.integrityInformation, "Integrity information should be nil")

        let payloadDescriptor = TDFPayloadDescriptor(
            type: .reference,
            url: "0.payload",
            protocolValue: .zip,
            isEncrypted: true,
            mimeType: "application/octet-stream",
        )

        let manifest = TDFManifest(
            schemaVersion: "4.3.0",
            payload: payloadDescriptor,
            encryptionInformation: encryptionInfo,
        )

        XCTAssertNil(manifest.encryptionInformation.integrityInformation)
    }

    func testMinimalIntegrityInformation() {
        let minimal = TDFIntegrityInformation.minimal

        XCTAssertEqual(minimal.rootSignature.alg, "HS256")
        XCTAssertEqual(minimal.rootSignature.sig, "")
        XCTAssertEqual(minimal.segmentHashAlg, "GMAC")
        XCTAssertEqual(minimal.segmentSizeDefault, 0)
        XCTAssertNil(minimal.encryptedSegmentSizeDefault)
        XCTAssertTrue(minimal.segments.isEmpty)
    }

    // MARK: - TDFManifestBuilder Tests

    func testManifestBuilderStandard() throws {
        let builder = TDFManifestBuilder()
        let symmetricKey = try StandardTDFCrypto.generateSymmetricKey()
        let policyJSON = testPolicyJSON()

        let policyBinding = StandardTDFCrypto.policyBinding(policy: policyJSON, symmetricKey: symmetricKey)
        let wrappedKey = "test-wrapped-key"

        let manifest = builder.buildStandardManifest(
            wrappedKey: wrappedKey,
            kasURL: URL(string: "https://kas.example.com")!,
            policy: policyJSON.base64EncodedString(),
            iv: "dGVzdC1pdg==",
            mimeType: "application/pdf",
            policyBinding: policyBinding,
        )

        XCTAssertEqual(manifest.schemaVersion, "4.3.0")
        XCTAssertEqual(manifest.payload.type, .reference)
        XCTAssertEqual(manifest.payload.mimeType, "application/pdf")
        XCTAssertEqual(manifest.encryptionInformation.keyAccess.count, 1)
        XCTAssertEqual(manifest.encryptionInformation.keyAccess[0].wrappedKey, wrappedKey)
        XCTAssertNil(manifest.encryptionInformation.integrityInformation)
    }

    func testManifestBuilderWithIntegrity() throws {
        let builder = TDFManifestBuilder()
        let symmetricKey = try StandardTDFCrypto.generateSymmetricKey()
        let policyJSON = testPolicyJSON()

        let policyBinding = StandardTDFCrypto.policyBinding(policy: policyJSON, symmetricKey: symmetricKey)
        let wrappedKey = "test-wrapped-key"

        let manifest = builder.buildStandardManifest(
            wrappedKey: wrappedKey,
            kasURL: URL(string: "https://kas.example.com")!,
            policy: policyJSON.base64EncodedString(),
            iv: "dGVzdC1pdg==",
            policyBinding: policyBinding,
            integrityInformation: .minimal,
        )

        XCTAssertNotNil(manifest.encryptionInformation.integrityInformation)
        XCTAssertEqual(manifest.encryptionInformation.integrityInformation?.segmentHashAlg, "GMAC")
    }

    func testManifestBuilderMultiKAS() throws {
        let builder = TDFManifestBuilder()
        let symmetricKey = try StandardTDFCrypto.generateSymmetricKey()
        let policyJSON = testPolicyJSON()

        let policyBinding = StandardTDFCrypto.policyBinding(policy: policyJSON, symmetricKey: symmetricKey)

        let kasObjects = [
            TDFKeyAccessObject(
                type: .wrapped,
                url: "https://kas1.example.com",
                protocolValue: .kas,
                wrappedKey: "wrapped-key-1",
                policyBinding: policyBinding,
                kid: "key-1",
            ),
            TDFKeyAccessObject(
                type: .wrapped,
                url: "https://kas2.example.com",
                protocolValue: .kas,
                wrappedKey: "wrapped-key-2",
                policyBinding: policyBinding,
                kid: "key-2",
            ),
        ]

        let manifest = builder.buildMultiKASManifest(
            keyAccessObjects: kasObjects,
            policy: policyJSON.base64EncodedString(),
            iv: "dGVzdC1pdg==",
        )

        XCTAssertEqual(manifest.encryptionInformation.keyAccess.count, 2)
        XCTAssertEqual(manifest.encryptionInformation.type, .split)
        XCTAssertEqual(manifest.encryptionInformation.keyAccess[0].kid, "key-1")
        XCTAssertEqual(manifest.encryptionInformation.keyAccess[1].kid, "key-2")
    }

    // MARK: - TDFArchiveWriter buildArchiveToFile Tests

    func testBuildArchiveToFile() throws {
        let manifest = createTestManifest()
        let writer = TDFArchiveWriter()

        let tempDir = FileManager.default.temporaryDirectory
        let outputURL = tempDir.appendingPathComponent("test-\(UUID().uuidString).tdf")
        defer { try? FileManager.default.removeItem(at: outputURL) }

        try writer.buildArchiveToFile(
            manifest: manifest,
            payload: testPlaintext,
            outputURL: outputURL,
        )

        XCTAssertTrue(FileManager.default.fileExists(atPath: outputURL.path))

        let fileData = try Data(contentsOf: outputURL)
        XCTAssertGreaterThan(fileData.count, 0)
        XCTAssertTrue(fileData.starts(with: [0x50, 0x4B]), "Should be a ZIP file")
    }

    func testBuildArchiveToFileFromPayloadURL() throws {
        let manifest = createTestManifest()
        let writer = TDFArchiveWriter()

        let tempDir = FileManager.default.temporaryDirectory
        let payloadURL = tempDir.appendingPathComponent("payload-\(UUID().uuidString).bin")
        let outputURL = tempDir.appendingPathComponent("test-\(UUID().uuidString).tdf")
        defer {
            try? FileManager.default.removeItem(at: payloadURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        try testPlaintext.write(to: payloadURL)

        try writer.buildArchiveToFile(
            manifest: manifest,
            payloadURL: payloadURL,
            outputURL: outputURL,
        )

        XCTAssertTrue(FileManager.default.fileExists(atPath: outputURL.path))

        let reader = try TDFArchiveReader(url: outputURL)
        let payload = try reader.payloadData()
        XCTAssertEqual(payload, testPlaintext)
    }

    // MARK: - Helper Methods

    private func testPolicyJSON() -> Data {
        """
        {
            "uuid": "test-uuid-\(UUID().uuidString)",
            "body": {
                "dataAttributes": [],
                "dissem": []
            }
        }
        """.data(using: .utf8)!
    }

    private func createTestManifest() -> TDFManifest {
        let kasObject = TDFKeyAccessObject(
            type: .wrapped,
            url: "https://kas.example.com",
            protocolValue: .kas,
            wrappedKey: "test-wrapped-key",
            policyBinding: TDFPolicyBinding(alg: "HS256", hash: "test-hash"),
        )

        let method = TDFMethodDescriptor(
            algorithm: "AES-256-GCM",
            iv: "dGVzdC1pdg==",
            isStreamable: true,
        )

        let encryptionInfo = TDFEncryptionInformation(
            type: .split,
            keyAccess: [kasObject],
            method: method,
            policy: "dGVzdC1wb2xpY3k=",
        )

        let payloadDescriptor = TDFPayloadDescriptor(
            type: .reference,
            url: "0.payload",
            protocolValue: .zip,
            isEncrypted: true,
            mimeType: "application/octet-stream",
        )

        return TDFManifest(
            schemaVersion: "4.3.0",
            payload: payloadDescriptor,
            encryptionInformation: encryptionInfo,
        )
    }
}
