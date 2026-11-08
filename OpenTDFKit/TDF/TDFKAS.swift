@preconcurrency import CryptoKit
import Foundation

// MARK: - TDFKAS

/// The KAS side of a TDF `ec-wrapped` rewrap, and the matching client unwrap,
/// as pure functions: no network, no storage, keys passed as values.
///
/// The scheme is the go SDK's and the opentdf-platform KAS's: ECDH on P-256,
/// HKDF-SHA256 with salt `SHA256("TDF")` (`KASRewrapClient.standardTDFSessionSalt`),
/// empty info and a 32-byte output, then AES-256-GCM with the wrapped key laid
/// out as nonce (12) ‖ ciphertext ‖ tag (16).
///
/// A key access object wraps its split's **key share**. For a TDF with a single
/// split the share is the DEK; with several splits the shares are XORed
/// (`TDFDecryptor.combineKeyShares`).
public enum TDFKAS {
    /// Size of every key share this path accepts.
    static let shareByteCount = 32

    /// Opens a rewrapped key share on the client, for a response that did not
    /// come from an HTTP rewrap (for example, one relayed from an on-device KAS).
    /// `KASRewrapClient` uses the same implementation for HTTP responses.
    /// - Parameters:
    ///   - wrappedKey: nonce (12) ‖ ciphertext ‖ tag (16), as returned by `rewrap`.
    ///   - sessionPublicKey: The KAS's session public key for this response.
    ///   - receiverPrivateKey: The private half of the key the share was sealed to.
    /// - Returns: The 32-byte key share.
    /// - Throws: `TDFKASError.keyUnwrapFailed` for any failure, including a
    ///   share that is not 32 bytes.
    public static func unwrap(
        wrappedKey: Data,
        sessionPublicKey: P256.KeyAgreement.PublicKey,
        receiverPrivateKey: P256.KeyAgreement.PrivateKey,
    ) throws -> SymmetricKey {
        let share: SymmetricKey
        do {
            share = try KASRewrapClient.unwrapKey(
                wrappedKey: wrappedKey,
                sessionPublicKey: sessionPublicKey.compressedRepresentation,
                clientPrivateKey: receiverPrivateKey.rawRepresentation,
                salt: KASRewrapClient.standardTDFSessionSalt,
            )
        } catch {
            throw TDFKASError.keyUnwrapFailed
        }
        guard share.bitCount == shareByteCount * 8 else {
            throw TDFKASError.keyUnwrapFailed
        }
        return share
    }
}

// MARK: - Errors

/// Failures of `TDFKAS`. No description contains key material, a key share or
/// an HMAC.
public enum TDFKASError: Error, CustomStringConvertible, Equatable {
    /// The key access object's `type` is not `ec-wrapped`.
    case unsupportedKeyAccessType(String)
    /// The key access object has no `ephemeralPublicKey`.
    case missingEphemeralPublicKey
    /// The `ephemeralPublicKey` is not PEM.
    case ephemeralKeyNotPEM
    /// The `ephemeralPublicKey` is PEM but not a P-256 public key.
    case invalidEphemeralPublicKey
    /// The `wrappedKey` is not standard base64.
    case invalidWrappedKeyEncoding
    /// The wrapped key did not open, or did not hold a 32-byte key share.
    case keyUnwrapFailed
    /// The policy binding is absent, malformed, not `HS256`, or does not match.
    case policyBindingRefused

    public var description: String {
        switch self {
        case let .unsupportedKeyAccessType(type):
            "Key access object type '\(type)' is not supported; expected 'ec-wrapped'"
        case .missingEphemeralPublicKey:
            "Key access object has no ephemeral public key"
        case .ephemeralKeyNotPEM:
            "Ephemeral public key is not PEM; the TDF-JSON / TDF-CBOR EC scheme (compressed SEC1, empty salt) is not served here"
        case .invalidEphemeralPublicKey:
            "Ephemeral public key is not a P-256 public key"
        case .invalidWrappedKeyEncoding:
            "Wrapped key is not valid base64"
        case .keyUnwrapFailed:
            "Key unwrap failed"
        case .policyBindingRefused:
            "Policy binding refused"
        }
    }
}
