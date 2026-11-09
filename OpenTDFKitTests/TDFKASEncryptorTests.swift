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
        for kid in [nil, "", "  \t"] as [String?] {
            let (kas, _) = Self.makeECKas(kid: kid)
            try assertEveryEntryPointRefuses(Self.configuration(kas)) {
                XCTAssertEqual($0 as? TDFEncryptError, .ecKasRequiresKeyID, "kid \(String(describing: kid))")
            }
        }
    }

    func testECKasWithAES128IsRefused() throws {
        let (kas, _) = Self.makeECKas()
        let configuration = try TDFEncryptionConfiguration(kas: kas, policy: Self.policy(), keySize: .bits128)
        try assertEveryEntryPointRefuses(configuration) {
            XCTAssertEqual($0 as? TDFEncryptError, .ecKasRequiresAES256)
        }
    }

    func testKeyTypeAndPEMMismatchThrows() throws {
        for kas in try Self.mismatchedKasInfos() {
            try assertEveryEntryPointRefuses(Self.configuration(kas)) {
                XCTAssertTrue($0 is TDFCryptoError, "expected a key error, got \($0)")
            }
        }
    }

    /// A key type that does not match its PEM is refused before the input is
    /// read: with an input file that does not exist, the key error still wins.
    func testKeyTypeAndPEMMismatchIsRefusedBeforeReadingInput() throws {
        let missing = tempDirectory.appendingPathComponent("missing.txt")
        let output = tempDirectory.appendingPathComponent("out.tdf")
        for kas in try Self.mismatchedKasInfos() {
            let configuration = try Self.configuration(kas)
            XCTAssertThrowsError(try TDFEncryptor().encryptFile(
                inputURL: missing,
                outputURL: output,
                configuration: configuration,
            )) {
                XCTAssertTrue($0 is TDFCryptoError, "expected a key error, got \($0)")
            }
            XCTAssertThrowsError(try TDFEncryptor().encryptFileMultiSegment(
                inputURL: missing,
                outputURL: output,
                configuration: configuration,
                segmentSizes: [1],
            )) {
                XCTAssertTrue($0 is TDFCryptoError, "expected a key error, got \($0)")
            }
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

    /// Writes a key access object and a `TDFKAS.rewrap` response to
    /// `OPENTDFKIT_INTEROP_OUT`, in `GoFixture`'s shape, for
    /// `scripts/interop/ec-wrapped` (`go run . verify <path>`) to open with go.
    /// The key access object and policy are copied byte for byte from the
    /// `manifest.json` an `encryptFile` archive holds, so go reads what ships.
    /// Skipped unless that variable is set; required before a release is tagged.
    func testWriteSwiftFixtureForGo() throws {
        guard let path = ProcessInfo.processInfo.environment["OPENTDFKIT_INTEROP_OUT"], !path.isEmpty else {
            throw XCTSkip("Set OPENTDFKIT_INTEROP_OUT to write the Swift → go interop fixture")
        }
        let (kas, kasKey) = Self.makeECKas()
        let (input, output) = try writeInput(Data("interop".utf8))
        let result = try TDFEncryptor().encryptFile(
            inputURL: input,
            outputURL: output,
            configuration: Self.configuration(kas),
        )

        let manifestJSON = try TDFArchiveReader(url: output).manifestData()
        let manifest = try XCTUnwrap(JSONSerialization.jsonObject(with: manifestJSON) as? [String: Any])
        let encryption = try XCTUnwrap(manifest["encryptionInformation"] as? [String: Any])
        let kaoObject = try XCTUnwrap((encryption["keyAccess"] as? [[String: Any]])?.first)
        let policyBase64 = try XCTUnwrap(encryption["policy"] as? String)

        let receiver = P256.KeyAgreement.PrivateKey()
        let rewrapped = try TDFKAS.rewrap(
            keyAccessObject: JSONDecoder().decode(
                TDFKeyAccessObject.self,
                from: JSONSerialization.data(withJSONObject: kaoObject),
            ),
            policyBase64: policyBase64,
            kasPrivateKey: kasKey,
            receiverPublicKey: receiver.publicKey,
        )
        let fixture: [String: Any] = [
            "kasPrivateKeyPEM": kasKey.pemRepresentation,
            "policyBase64": policyBase64,
            "kao": kaoObject,
            "dekBase64": result.symmetricKey.withUnsafeBytes { Data($0) }.base64EncodedString(),
            "receiverPrivateKeyPEM": receiver.pemRepresentation,
            "response": [
                "wrappedKeyBase64": rewrapped.wrappedKey.base64EncodedString(),
                "sessionPublicKeyPEM": rewrapped.sessionPublicKey.pemRepresentation,
            ],
        ]
        try JSONSerialization.data(withJSONObject: fixture, options: [.prettyPrinted, .sortedKeys])
            .write(to: URL(fileURLWithPath: path))
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

    /// `.ecP256` with an RSA PEM, and `.rsa` with an EC PEM.
    static func mismatchedKasInfos() throws -> [TDFKasInfo] {
        let url = try XCTUnwrap(URL(string: "https://kas.example.com"))
        return try [
            TDFKasInfo(url: url, publicKeyPEM: TDFSegmentedPayloadTests.makeRSAPublicKeyPEM(), kid: "e1", keyType: .ecP256),
            TDFKasInfo(url: url, publicKeyPEM: P256.KeyAgreement.PrivateKey().publicKey.pemRepresentation, kid: "r1"),
        ]
    }

    /// Runs all four `TDFEncryptor` entry points with `configuration`; each must
    /// throw an error `check` accepts, and the file entry points write nothing.
    private func assertEveryEntryPointRefuses(
        _ configuration: TDFEncryptionConfiguration,
        file: StaticString = #filePath,
        line: UInt = #line,
        check: (Error) -> Void,
    ) throws {
        let plaintext = Self.plaintext(count: 100)
        let encryptor = TDFEncryptor()
        XCTAssertThrowsError(
            try encryptor.encrypt(plaintext: plaintext, configuration: configuration),
            file: file, line: line, check,
        )
        XCTAssertThrowsError(
            try encryptor.encrypt(plaintext: plaintext, configuration: configuration, segmentSize: 64),
            file: file, line: line, check,
        )
        let (input, output) = try writeInput(plaintext)
        XCTAssertThrowsError(
            try encryptor.encryptFile(inputURL: input, outputURL: output, configuration: configuration),
            file: file, line: line, check,
        )
        XCTAssertThrowsError(
            try encryptor.encryptFileMultiSegment(
                inputURL: input,
                outputURL: output,
                configuration: configuration,
                segmentSizes: [64, 36],
            ),
            file: file, line: line, check,
        )
        XCTAssertFalse(FileManager.default.fileExists(atPath: output.path), "nothing is written", file: file, line: line)
    }

    private func writeInput(_ plaintext: Data) throws -> (input: URL, output: URL) {
        let name = UUID().uuidString
        let input = tempDirectory.appendingPathComponent("\(name).txt")
        try plaintext.write(to: input)
        return (input, tempDirectory.appendingPathComponent("\(name).tdf"))
    }
}
