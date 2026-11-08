@preconcurrency import CryptoKit
import Foundation
@testable import OpenTDFKit
import Security
import XCTest

/// `TDFEncryptor` with an `.ecP256` KAS writes a TDF `ec-wrapped` key access
/// object that `TDFKAS.rewrap` opens, from every encrypt entry point.
final class TDFKASEncryptorTests: XCTestCase {
    private var tempDirectory: URL!

    override func setUpWithError() throws {
        tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("TDFKASEncryptorTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDirectory)
    }

    // MARK: - Interop link (d)

    // Interop link (d): the encryptor writes the go KAO scheme. These tests prove
    // the encryptor writes a PEM ephemeral key only while `TDFKAS.rewrap` accepts
    // PEM alone; keep this comment true if rewrap's parsing ever changes.

    func testEncryptPlaintextWritesECWrappedKAO() throws {
        let (kas, kasKey) = Self.makeECKas()
        let plaintext = Data("hello, owner".utf8)
        let result = try TDFEncryptor().encrypt(plaintext: plaintext, configuration: Self.configuration(kas))
        try Self.assertECWrappedKAO(result.container.manifest)
        XCTAssertEqual(try Self.openThroughKAS(result.container, kasKey: kasKey), plaintext)
    }

    func testEncryptSegmentedWritesECWrappedKAO() throws {
        let (kas, kasKey) = Self.makeECKas()
        let plaintext = Self.plaintext(count: 5000)
        let result = try TDFEncryptor().encrypt(
            plaintext: plaintext,
            configuration: Self.configuration(kas),
            segmentSize: 1024,
        )
        try Self.assertECWrappedKAO(result.container.manifest)
        XCTAssertEqual(try Self.openThroughKAS(result.container, kasKey: kasKey), plaintext)
    }

    func testEncryptFileWritesECWrappedKAO() throws {
        let (kas, kasKey) = Self.makeECKas()
        let plaintext = Self.plaintext(count: 5000)
        let (input, output) = try writeInput(plaintext)
        _ = try TDFEncryptor().encryptFile(inputURL: input, outputURL: output, configuration: Self.configuration(kas))
        let container = try TDFLoader().load(from: output)
        try Self.assertECWrappedKAO(container.manifest)
        XCTAssertEqual(try Self.openThroughKAS(container, kasKey: kasKey), plaintext)
    }

    func testEncryptFileMultiSegmentWritesECWrappedKAO() throws {
        let (kas, kasKey) = Self.makeECKas()
        let plaintext = Self.plaintext(count: 5000)
        let (input, output) = try writeInput(plaintext)
        _ = try TDFEncryptor().encryptFileMultiSegment(
            inputURL: input,
            outputURL: output,
            configuration: Self.configuration(kas),
            segmentSizes: [1024, 1024, 2952],
        )
        let container = try TDFLoader().load(from: output)
        try Self.assertECWrappedKAO(container.manifest)
        XCTAssertEqual(try Self.openThroughKAS(container, kasKey: kasKey), plaintext)
    }

    // MARK: - Refusals

    func testECKasWithoutKidIsRefused() throws {
        for kid in [nil, ""] as [String?] {
            let (kas, _) = Self.makeECKas(kid: kid)
            let configuration = try Self.configuration(kas)
            XCTAssertThrowsError(try TDFEncryptor().encrypt(plaintext: Data("x".utf8), configuration: configuration)) {
                XCTAssertEqual($0 as? TDFEncryptError, .ecKasRequiresKeyID)
            }
            let (input, output) = try writeInput(Data("x".utf8))
            XCTAssertThrowsError(try TDFEncryptor().encryptFile(
                inputURL: input,
                outputURL: output,
                configuration: configuration,
            )) {
                XCTAssertEqual($0 as? TDFEncryptError, .ecKasRequiresKeyID)
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: output.path), "nothing is written")
        }
    }

    func testECKasWithAES128IsRefused() throws {
        let (kas, _) = Self.makeECKas()
        let configuration = try TDFEncryptionConfiguration(kas: kas, policy: Self.policy(), keySize: .bits128)
        XCTAssertThrowsError(try TDFEncryptor().encrypt(plaintext: Data("x".utf8), configuration: configuration)) {
            XCTAssertEqual($0 as? TDFEncryptError, .ecKasRequiresAES256)
        }
    }

    func testKeyTypeAndPEMMismatchThrows() throws {
        let url = try XCTUnwrap(URL(string: "https://kas.example.com"))
        let rsaPEM = try TDFSegmentedPayloadTests.makeRSAPublicKeyPEM()
        let ecPEM = P256.KeyAgreement.PrivateKey().publicKey.pemRepresentation
        for kas in [
            TDFKasInfo(url: url, publicKeyPEM: rsaPEM, kid: "e1", keyType: .ecP256),
            TDFKasInfo(url: url, publicKeyPEM: ecPEM, kid: "r1", keyType: .rsa),
        ] {
            XCTAssertThrowsError(try TDFEncryptor().encrypt(
                plaintext: Data("x".utf8),
                configuration: Self.configuration(kas),
            ))
        }
    }

    /// The default key type is RSA and writes today's `wrapped` key access object.
    func testRSAKasOutputIsUnchanged() throws {
        let url = try XCTUnwrap(URL(string: "https://kas.example.com"))
        let (publicKeyPEM, privateKey) = try TDFSegmentedPayloadTests.makeRSAKeyPair()
        let kas = TDFKasInfo(url: url, publicKeyPEM: publicKeyPEM, kid: "r1")
        XCTAssertEqual(kas.keyType, .rsa)
        let result = try TDFEncryptor().encrypt(plaintext: Data("x".utf8), configuration: Self.configuration(kas))
        let encryption = result.container.manifest.encryptionInformation
        let kao = try XCTUnwrap(encryption.keyAccess.first)
        XCTAssertEqual(encryption.keyAccess.count, 1)
        XCTAssertEqual(kao.type, .wrapped)
        XCTAssertNil(kao.ephemeralPublicKey)
        XCTAssertEqual(kao.url, "https://kas.example.com")
        XCTAssertEqual(kao.kid, "r1")
        XCTAssertEqual(kao.schemaVersion, "1.0")
        let policyJSON = try XCTUnwrap(Data(base64Encoded: encryption.policy))
        XCTAssertEqual(
            kao.policyBinding.hash,
            TDFCrypto.policyBinding(policy: policyJSON, symmetricKey: result.symmetricKey).hash,
        )
        var error: Unmanaged<CFError>?
        let dek = try SecKeyCreateDecryptedData(
            privateKey,
            .rsaEncryptionOAEPSHA1,
            XCTUnwrap(Data(base64Encoded: kao.wrappedKey)) as CFData,
            &error,
        ) as Data?
        XCTAssertEqual(dek, result.symmetricKey.withUnsafeBytes { Data($0) })
    }

    // MARK: - Swift → go check

    /// Writes a key access object from `TDFEncryptor` and a `TDFKAS.rewrap`
    /// response to `OPENTDFKIT_INTEROP_OUT`, in `GoFixture`'s shape, for
    /// `scripts/interop/ec-wrapped` (`go run . verify <path>`) to open with go.
    /// Skipped unless that variable is set; required before a release is tagged.
    func testWriteSwiftFixtureForGo() throws {
        guard let path = ProcessInfo.processInfo.environment["OPENTDFKIT_INTEROP_OUT"], !path.isEmpty else {
            throw XCTSkip("Set OPENTDFKIT_INTEROP_OUT to write the Swift → go interop fixture")
        }
        let (kas, kasKey) = Self.makeECKas()
        let configuration = try Self.configuration(kas)
        let result = try TDFEncryptor().encrypt(plaintext: Data("interop".utf8), configuration: configuration)
        let encryption = result.container.manifest.encryptionInformation
        let receiver = P256.KeyAgreement.PrivateKey()
        let rewrapped = try TDFKAS.rewrap(
            keyAccessObject: encryption.keyAccess[0],
            policyBase64: encryption.policy,
            kasPrivateKey: kasKey,
            receiverPublicKey: receiver.publicKey,
        )
        let fixture = GoFixture(
            kasPrivateKeyPEM: kasKey.pemRepresentation,
            policyBase64: encryption.policy,
            kao: encryption.keyAccess[0],
            dekBase64: result.symmetricKey.withUnsafeBytes { Data($0) }.base64EncodedString(),
            receiverPrivateKeyPEM: receiver.pemRepresentation,
            response: GoFixture.Response(
                wrappedKeyBase64: rewrapped.wrappedKey.base64EncodedString(),
                sessionPublicKeyPEM: rewrapped.sessionPublicKey.pemRepresentation,
            ),
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        try encoder.encode(fixture).write(to: URL(fileURLWithPath: path))
    }

    // MARK: - Helpers

    static func makeECKas(kid: String? = "e1") -> (TDFKasInfo, P256.KeyAgreement.PrivateKey) {
        let kasKey = P256.KeyAgreement.PrivateKey()
        let kas = TDFKasInfo(
            url: URL(string: "https://kas.example.com")!,
            publicKeyPEM: kasKey.publicKey.pemRepresentation,
            kid: kid,
            keyType: .ecP256,
        )
        return (kas, kasKey)
    }

    static func policy() throws -> TDFPolicy {
        try TDFPolicy(json: Data(
            #"{"uuid":"\#(UUID().uuidString)","body":{"dataAttributes":[],"dissem":["user@example.com"]}}"#.utf8,
        ))
    }

    static func configuration(_ kas: TDFKasInfo) throws -> TDFEncryptionConfiguration {
        try TDFEncryptionConfiguration(kas: kas, policy: policy())
    }

    static func plaintext(count: Int) -> Data {
        Data((0 ..< count).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 7) })
    }

    static func assertECWrappedKAO(
        _ manifest: TDFManifest,
        file: StaticString = #filePath,
        line: UInt = #line,
    ) throws {
        let keyAccess = manifest.encryptionInformation.keyAccess
        XCTAssertEqual(keyAccess.count, 1, file: file, line: line)
        let kao = try XCTUnwrap(keyAccess.first, file: file, line: line)
        XCTAssertEqual(kao.type, .ecWrapped, file: file, line: line)
        XCTAssertEqual(kao.kid, "e1", file: file, line: line)
        XCTAssertEqual(kao.schemaVersion, "1.0", file: file, line: line)
        XCTAssertTrue(
            kao.ephemeralPublicKey?.hasPrefix("-----BEGIN PUBLIC KEY-----") ?? false,
            "ephemeral key is PEM",
            file: file,
            line: line,
        )
    }

    /// Rewraps the container's key access object at the KAS, unwraps it as the
    /// receiver, and decrypts the payload with the result.
    static func openThroughKAS(_ container: TDFContainer, kasKey: P256.KeyAgreement.PrivateKey) throws -> Data {
        let encryption = container.manifest.encryptionInformation
        let receiver = P256.KeyAgreement.PrivateKey()
        let rewrapped = try TDFKAS.rewrap(
            keyAccessObject: encryption.keyAccess[0],
            policyBase64: encryption.policy,
            kasPrivateKey: kasKey,
            receiverPublicKey: receiver.publicKey,
        )
        let dek = try TDFKAS.unwrap(
            wrappedKey: rewrapped.wrappedKey,
            sessionPublicKey: rewrapped.sessionPublicKey,
            receiverPrivateKey: receiver,
        )
        return try TDFDecryptor().decrypt(container: container, symmetricKey: dek)
    }

    private func writeInput(_ plaintext: Data) throws -> (input: URL, output: URL) {
        let name = UUID().uuidString
        let input = tempDirectory.appendingPathComponent("\(name).txt")
        try plaintext.write(to: input)
        return (input, tempDirectory.appendingPathComponent("\(name).tdf"))
    }
}
