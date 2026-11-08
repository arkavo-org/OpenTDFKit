@preconcurrency import CryptoKit
import Foundation
@testable import OpenTDFKit
import XCTest

/// `TDFKAS`: the KAS-side rewrap of a TDF `ec-wrapped` key access object and
/// the matching client unwrap, checked against a fixture produced by go.
final class TDFKASTests: XCTestCase {
    // MARK: - Unwrap

    /// Interop link (a): `unwrap` opens a response sealed the way the platform
    /// KAS seals it, so it uses the go session scheme.
    func testUnwrapOpensGoSealedResponse() throws {
        let fixture = try GoFixture.load()
        let share = try TDFKAS.unwrap(
            wrappedKey: XCTUnwrap(Data(base64Encoded: fixture.response.wrappedKeyBase64)),
            sessionPublicKey: P256.KeyAgreement.PublicKey(pemRepresentation: fixture.response.sessionPublicKeyPEM),
            receiverPrivateKey: P256.KeyAgreement.PrivateKey(pemRepresentation: fixture.receiverPrivateKeyPEM),
        )
        XCTAssertEqual(Self.bytes(share), Data(base64Encoded: fixture.dekBase64))
    }

    func testUnwrapWithAnotherReceiverKeyFails() throws {
        let fixture = try GoFixture.load()
        let wrappedKey = try XCTUnwrap(Data(base64Encoded: fixture.response.wrappedKeyBase64))
        let sessionPublicKey = try P256.KeyAgreement.PublicKey(pemRepresentation: fixture.response.sessionPublicKeyPEM)
        XCTAssertThrowsError(try TDFKAS.unwrap(
            wrappedKey: wrappedKey,
            sessionPublicKey: sessionPublicKey,
            receiverPrivateKey: P256.KeyAgreement.PrivateKey(),
        )) { error in
            XCTAssertEqual(error as? TDFKASError, .keyUnwrapFailed)
        }
    }

    func testUnwrapRefusesNon32ByteShare() throws {
        let receiver = P256.KeyAgreement.PrivateKey()
        let (wrappedKey, sessionPublicKey) = try Self.sealWithTDFSalt(
            Data((0 ..< 16).map { _ in UInt8.random(in: 0 ... 255) }),
            to: receiver.publicKey,
        )
        XCTAssertThrowsError(try TDFKAS.unwrap(
            wrappedKey: wrappedKey,
            sessionPublicKey: sessionPublicKey,
            receiverPrivateKey: receiver,
        )) { error in
            XCTAssertEqual(error as? TDFKASError, .keyUnwrapFailed)
        }
    }

    // MARK: - Rewrap: interop and round trip

    /// Interop links (c) and (b): `rewrap` opens a key access object written by
    /// go, and `unwrap` opens what `rewrap` sealed.
    func testRewrapOpensGoKAOAndUnwrapOpensResult() throws {
        let fixture = try GoFixture.load()
        let receiver = P256.KeyAgreement.PrivateKey()
        let result = try TDFKAS.rewrap(
            keyAccessObject: fixture.kao,
            policyBase64: fixture.policyBase64,
            kasPrivateKey: P256.KeyAgreement.PrivateKey(pemRepresentation: fixture.kasPrivateKeyPEM),
            receiverPublicKey: receiver.publicKey,
        )
        let share = try TDFKAS.unwrap(
            wrappedKey: result.wrappedKey,
            sessionPublicKey: result.sessionPublicKey,
            receiverPrivateKey: receiver,
        )
        XCTAssertEqual(Self.bytes(share), Data(base64Encoded: fixture.dekBase64))
    }

    func testWrapThenRewrapRoundTrip() throws {
        let input = try Self.makeInput()
        XCTAssertTrue(input.kao.ephemeralPublicKey?.hasPrefix("-----BEGIN PUBLIC KEY-----") ?? false)
        let receiver = P256.KeyAgreement.PrivateKey()
        let result = try TDFKAS.rewrap(
            keyAccessObject: input.kao,
            policyBase64: input.policyBase64,
            kasPrivateKey: input.kasKey,
            receiverPublicKey: receiver.publicKey,
        )
        let share = try TDFKAS.unwrap(
            wrappedKey: result.wrappedKey,
            sessionPublicKey: result.sessionPublicKey,
            receiverPrivateKey: receiver,
        )
        XCTAssertEqual(Self.bytes(share), Self.bytes(input.share))
    }

    func testRewrapResultIsFresh() throws {
        let input = try Self.makeInput()
        let receiver = P256.KeyAgreement.PrivateKey().publicKey
        let first = try input.rewrap(to: receiver)
        let second = try input.rewrap(to: receiver)
        XCTAssertNotEqual(first.sessionPublicKey.rawRepresentation, second.sessionPublicKey.rawRepresentation)
        XCTAssertNotEqual(first.wrappedKey.prefix(12), second.wrappedKey.prefix(12))
    }

    // MARK: - Rewrap: policy binding

    func testTamperedPolicyIsRefused() throws {
        let input = try Self.makeInput()
        var characters = Array(input.policyBase64)
        characters[10] = characters[10] == "A" ? "B" : "A"
        assertRewrapFails(input, policyBase64: String(characters), .policyBindingRefused)
    }

    func testDecodedPolicyJSONIsRefused() throws {
        let input = try Self.makeInput()
        assertRewrapFails(input, policyBase64: String(decoding: input.policyJSON, as: UTF8.self), .policyBindingRefused)
    }

    func testTamperedBindingHashIsRefused() throws {
        let input = try Self.makeInput()
        var kao = input.kao
        var characters = Array(kao.policyBinding.hash)
        characters[5] = characters[5] == "A" ? "B" : "A"
        kao.policyBinding.hash = String(characters)
        assertRewrapFails(input, kao: kao, .policyBindingRefused)
    }

    /// go's legacy `Base64(hex(HMAC))` form is a bug and is refused, even over
    /// the correct HMAC.
    func testLegacyHexBindingIsRefused() throws {
        let input = try Self.makeInput()
        let mac = HMAC<SHA256>.authenticationCode(for: Data(input.policyBase64.utf8), using: input.share)
        let hex = Data(mac).map { String(format: "%02x", $0) }.joined()
        var kao = input.kao
        kao.policyBinding.hash = Data(hex.utf8).base64EncodedString()
        assertRewrapFails(input, kao: kao, .policyBindingRefused)
    }

    func testNonHS256AlgIsRefused() throws {
        let input = try Self.makeInput()
        var kao = input.kao
        kao.policyBinding.alg = "GMAC"
        assertRewrapFails(input, kao: kao, .policyBindingRefused)
    }

    /// An empty `alg` means HS256 (OpenTDF spec PR #70), also on a key access
    /// object built by hand rather than decoded.
    func testEmptyAlgIsTreatedAsHS256() throws {
        let input = try Self.makeInput()
        var kao = input.kao
        kao.policyBinding.alg = ""
        XCTAssertNoThrow(try input.rewrap(kao: kao, to: P256.KeyAgreement.PrivateKey().publicKey))
    }

    /// Some writers emit `policyBinding` as a bare string; it decodes as HS256
    /// and verifies normally.
    func testBareStringBindingVerifies() throws {
        let input = try Self.makeInput()
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(input.kao)) as? [String: Any],
        )
        object["policyBinding"] = input.kao.policyBinding.hash
        let kao = try JSONDecoder().decode(
            TDFKeyAccessObject.self,
            from: JSONSerialization.data(withJSONObject: object),
        )
        XCTAssertNoThrow(try input.rewrap(kao: kao, to: P256.KeyAgreement.PrivateKey().publicKey))
    }

    // MARK: - Rewrap: wrapped key

    func testFlippedNonceByteIsRefused() throws {
        let input = try Self.makeInput()
        assertRewrapFails(input, kao: Self.flippingWrappedKeyByte(of: input.kao) { _ in 0 }, .keyUnwrapFailed)
    }

    func testFlippedCiphertextByteIsRefused() throws {
        let input = try Self.makeInput()
        assertRewrapFails(input, kao: Self.flippingWrappedKeyByte(of: input.kao) { _ in 12 }, .keyUnwrapFailed)
    }

    func testFlippedTagByteIsRefused() throws {
        let input = try Self.makeInput()
        assertRewrapFails(input, kao: Self.flippingWrappedKeyByte(of: input.kao) { $0 - 1 }, .keyUnwrapFailed)
    }

    func testTruncatedWrappedKeyIsRefused() throws {
        let input = try Self.makeInput()
        let wrapped = try XCTUnwrap(Data(base64Encoded: input.kao.wrappedKey))
        for truncated in [wrapped.dropLast(), wrapped.prefix(20)] {
            var kao = input.kao
            kao.wrappedKey = Data(truncated).base64EncodedString()
            assertRewrapFails(input, kao: kao, .keyUnwrapFailed)
        }
    }

    func testSixteenByteShareIsRefused() throws {
        let input = try Self.makeInput(share: SymmetricKey(size: .bits128))
        assertRewrapFails(input, .keyUnwrapFailed)
    }

    func testWrongKASPrivateKeyIsRefused() throws {
        let input = try Self.makeInput()
        assertRewrapFails(input, kasKey: P256.KeyAgreement.PrivateKey(), .keyUnwrapFailed)
    }

    func testNonBase64WrappedKeyIsRefused() throws {
        let input = try Self.makeInput()
        var urlAlphabet = input.kao
        urlAlphabet.wrappedKey = "-_" + input.kao.wrappedKey.dropFirst(2)
        assertRewrapFails(input, kao: urlAlphabet, .invalidWrappedKeyEncoding)
        var withNewline = input.kao
        withNewline.wrappedKey.insert("\n", at: withNewline.wrappedKey.index(withNewline.wrappedKey.startIndex, offsetBy: 8))
        assertRewrapFails(input, kao: withNewline, .invalidWrappedKeyEncoding)
    }

    // MARK: - Rewrap: key access object shape

    func testWrongKAOTypeIsRefused() throws {
        let input = try Self.makeInput()
        var kao = input.kao
        kao.type = .wrapped
        assertRewrapFails(input, kao: kao, .unsupportedKeyAccessType("wrapped"))
    }

    func testMissingEphemeralKeyIsRefused() throws {
        let input = try Self.makeInput()
        var kao = input.kao
        kao.ephemeralPublicKey = nil
        assertRewrapFails(input, kao: kao, .missingEphemeralPublicKey)
    }

    func testSEC1EphemeralKeyIsRefused() throws {
        let input = try Self.makeInput()
        var kao = input.kao
        kao.ephemeralPublicKey = P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation.base64EncodedString()
        assertRewrapFails(input, kao: kao, .ephemeralKeyNotPEM)
    }

    /// The TDF-JSON container's EC scheme (compressed SEC1, empty salt) is not
    /// the platform's `ec-wrapped` and is refused with a clear error.
    func testTDFJSONContainerKAOIsRefused() throws {
        let kasKey = P256.KeyAgreement.PrivateKey()
        let result = try TDFJSONBuilder()
            .kasURL(XCTUnwrap(URL(string: "https://kas.example.com")))
            .kasPublicKey(kasKey.publicKey.pemRepresentation)
            .kasKid("e1")
            .policy(TDFPolicy(json: Self.policyJSON()))
            .encrypt(plaintext: Data("hello".utf8))
        let encryption = result.container.manifest.encryptionInformation
        XCTAssertThrowsError(try TDFKAS.rewrap(
            keyAccessObject: encryption.keyAccess[0],
            policyBase64: encryption.policy,
            kasPrivateKey: kasKey,
            receiverPublicKey: P256.KeyAgreement.PrivateKey().publicKey,
        )) { error in
            XCTAssertEqual(error as? TDFKASError, .ephemeralKeyNotPEM)
        }
    }

    func testP384EphemeralKeyIsRefused() throws {
        let input = try Self.makeInput()
        var kao = input.kao
        kao.ephemeralPublicKey = P384.KeyAgreement.PrivateKey().publicKey.pemRepresentation
        assertRewrapFails(input, kao: kao, .invalidEphemeralPublicKey)
    }

    func testRewrapAcceptsCRLFPEM() throws {
        let fixture = try GoFixture.load()
        let kasKey = try P256.KeyAgreement.PrivateKey(pemRepresentation: fixture.kasPrivateKeyPEM)
        let pem = try XCTUnwrap(fixture.kao.ephemeralPublicKey)
        XCTAssertTrue(pem.hasSuffix("\n"), "the go fixture's PEM ends with a newline")
        for variant in [pem.replacingOccurrences(of: "\n", with: "\r\n"), String(pem.dropLast())] {
            var kao = fixture.kao
            kao.ephemeralPublicKey = variant
            XCTAssertNoThrow(try TDFKAS.rewrap(
                keyAccessObject: kao,
                policyBase64: fixture.policyBase64,
                kasPrivateKey: kasKey,
                receiverPublicKey: P256.KeyAgreement.PrivateKey().publicKey,
            ))
        }
    }

    /// go's `pem.Decode`, which the platform KAS uses, accepts any line length,
    /// spaces and tabs inside the body, and text after the END line; so does
    /// `rewrap`.
    func testRewrapAcceptsPEMLayoutsGoAccepts() throws {
        let fixture = try GoFixture.load()
        let kasKey = try P256.KeyAgreement.PrivateKey(pemRepresentation: fixture.kasPrivateKeyPEM)
        let der = try P256.KeyAgreement.PublicKey(pemRepresentation: XCTUnwrap(fixture.kao.ephemeralPublicKey))
            .derRepresentation
        let body = der.base64EncodedString()
        func pem(_ lines: [String], after: String = "") -> String {
            (["-----BEGIN PUBLIC KEY-----"] + lines + ["-----END PUBLIC KEY-----"]).joined(separator: "\n") + "\n" + after
        }
        func chunks(_ width: Int) -> [String] {
            stride(from: 0, to: body.count, by: width).map { start in
                let from = body.index(body.startIndex, offsetBy: start)
                return String(body[from ..< body.index(from, offsetBy: min(width, body.count - start))])
            }
        }
        let variants = [
            "one line": pem([body]),
            "48 columns": pem(chunks(48)),
            "76 columns": pem(chunks(76)),
            "trailing spaces and a tab": pem(chunks(64).map { $0 + " \t " }),
            "text after END": pem(chunks(64), after: "trailing text\n"),
        ]
        for (name, variant) in variants {
            var kao = fixture.kao
            kao.ephemeralPublicKey = variant
            XCTAssertNoThrow(try TDFKAS.rewrap(
                keyAccessObject: kao,
                policyBase64: fixture.policyBase64,
                kasPrivateKey: kasKey,
                receiverPublicKey: P256.KeyAgreement.PrivateKey().publicKey,
            ), name)
        }
    }

    func testMalformedPEMBodyIsRefused() throws {
        let input = try Self.makeInput()
        for variant in [
            "-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----\n",
            "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n",
        ] {
            var kao = input.kao
            kao.ephemeralPublicKey = variant
            assertRewrapFails(input, kao: kao, .invalidEphemeralPublicKey)
        }
    }

    // MARK: - Helpers

    /// A key access object wrapped to a fresh KAS key with the library's EC wrap
    /// for a KAS, plus everything needed to rewrap it.
    struct Input {
        let share: SymmetricKey
        let kasKey: P256.KeyAgreement.PrivateKey
        let policyJSON: Data
        let policyBase64: String
        let kao: TDFKeyAccessObject

        func rewrap(
            kao: TDFKeyAccessObject? = nil,
            to receiver: P256.KeyAgreement.PublicKey,
        ) throws -> TDFKAS.RewrapResult {
            try TDFKAS.rewrap(
                keyAccessObject: kao ?? self.kao,
                policyBase64: policyBase64,
                kasPrivateKey: kasKey,
                receiverPublicKey: receiver,
            )
        }
    }

    static func policyJSON() -> Data {
        Data(#"{"uuid":"\#(UUID().uuidString)","body":{"dataAttributes":[],"dissem":["user@example.com"]}}"#.utf8)
    }

    static func makeInput(share: SymmetricKey = SymmetricKey(size: .bits256)) throws -> Input {
        let kasKey = P256.KeyAgreement.PrivateKey()
        let policyJSON = policyJSON()
        let wrapped = try TDFCrypto.wrapSymmetricKeyWithECForKAS(
            publicKeyPEM: kasKey.publicKey.pemRepresentation,
            symmetricKey: share,
        )
        let kao = TDFKeyAccessObject(
            type: .ecWrapped,
            url: "https://kas.example.com",
            protocolValue: .kas,
            wrappedKey: wrapped.wrappedKey,
            policyBinding: TDFCrypto.policyBinding(policy: policyJSON, symmetricKey: share),
            kid: "e1",
            schemaVersion: "1.0",
            ephemeralPublicKey: wrapped.ephemeralPublicKeyPEM,
        )
        return Input(
            share: share,
            kasKey: kasKey,
            policyJSON: policyJSON,
            policyBase64: policyJSON.base64EncodedString(),
            kao: kao,
        )
    }

    /// Returns `kao` with one byte of its decoded wrapped key flipped, at the
    /// index `position` picks from the wrapped key's length.
    static func flippingWrappedKeyByte(
        of kao: TDFKeyAccessObject,
        at position: (Int) -> Int,
    ) -> TDFKeyAccessObject {
        var wrapped = Data(base64Encoded: kao.wrappedKey)!
        let index = position(wrapped.count)
        wrapped[index] ^= 0x01
        var copy = kao
        copy.wrappedKey = wrapped.base64EncodedString()
        return copy
    }

    func assertRewrapFails(
        _ input: Input,
        kao: TDFKeyAccessObject? = nil,
        policyBase64: String? = nil,
        kasKey: P256.KeyAgreement.PrivateKey? = nil,
        _ expected: TDFKASError,
        file: StaticString = #filePath,
        line: UInt = #line,
    ) {
        XCTAssertThrowsError(try TDFKAS.rewrap(
            keyAccessObject: kao ?? input.kao,
            policyBase64: policyBase64 ?? input.policyBase64,
            kasPrivateKey: kasKey ?? input.kasKey,
            receiverPublicKey: P256.KeyAgreement.PrivateKey().publicKey,
        ), file: file, line: line) { error in
            XCTAssertEqual(error as? TDFKASError, expected, file: file, line: line)
        }
    }

    /// `SHA256("TDF")`, written out here rather than taken from the library.
    static let tdfSalt = Data(SHA256.hash(data: Data("TDF".utf8)))

    static func bytes(_ key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }

    /// Seals `plaintext` to `receiver` the way the platform KAS seals a rewrap
    /// response: a fresh session key, ECDH, HKDF-SHA256 with the TDF salt,
    /// AES-256-GCM, nonce ‖ ciphertext ‖ tag.
    static func sealWithTDFSalt(
        _ plaintext: Data,
        to receiver: P256.KeyAgreement.PublicKey,
    ) throws -> (Data, P256.KeyAgreement.PublicKey) {
        let session = P256.KeyAgreement.PrivateKey()
        let key = try session.sharedSecretFromKeyAgreement(with: receiver).hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: tdfSalt,
            sharedInfo: Data(),
            outputByteCount: 32,
        )
        let sealed = try AES.GCM.seal(plaintext, using: key)
        return try (XCTUnwrap(sealed.combined), session.publicKey)
    }
}
