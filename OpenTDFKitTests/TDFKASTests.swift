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

    // MARK: - Helpers

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
