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

    /// Smallest wrapped key that can hold a share: nonce (12) + 1 byte + tag (16).
    private static let minimumWrappedKeyCount = 12 + 1 + 16

    /// A key share sealed to a receiver by `rewrap`.
    public struct RewrapResult: Sendable {
        /// nonce (12) ‖ ciphertext ‖ tag (16).
        public let wrappedKey: Data
        /// The fresh session public key the receiver needs to open `wrappedKey`.
        public let sessionPublicKey: P256.KeyAgreement.PublicKey

        public init(wrappedKey: Data, sessionPublicKey: P256.KeyAgreement.PublicKey) {
            self.wrappedKey = wrappedKey
            self.sessionPublicKey = sessionPublicKey
        }
    }

    /// The KAS side of a rewrap: opens the key share in an `ec-wrapped` key
    /// access object, verifies the policy binding, and seals the share to the
    /// receiver under a fresh session key. The binding is checked before
    /// anything is sealed, and the opened share is wiped on every exit.
    ///
    /// **What success proves.** Anyone holding the KAS *public* key can wrap a
    /// key of their choosing to it and compute a valid binding over a policy of
    /// their choosing, and `rewrap` will accept that. A passing binding proves
    /// only that `policyBase64` belongs to this key access object, not who made
    /// it. Match the key access object and policy against your own records
    /// before calling, and decide access yourself: this function evaluates no
    /// attributes and does not check the object's `url` or `kid`.
    ///
    /// **Do not forward which step failed.** `.keyUnwrapFailed` versus
    /// `.policyBindingRefused` tells the caller whether a submitted ciphertext
    /// authenticated under the KAS key. Keep that for your own audit; answer a
    /// requester with one failure code for every error.
    ///
    /// - Parameters:
    ///   - keyAccessObject: An `ec-wrapped` key access object with a PEM P-256
    ///     `ephemeralPublicKey`, as the go SDK and `TDFEncryptor` write it.
    ///   - policyBase64: The manifest's `encryptionInformation.policy` string,
    ///     unchanged. The binding is an HMAC over this base64 text, not over the
    ///     decoded JSON.
    ///   - kasPrivateKey: The KAS private key the object was wrapped to.
    ///   - receiverPublicKey: The receiver's P-256 public key.
    /// - Returns: The sealed share and the session public key.
    /// - Throws: `TDFKASError`; a CryptoKit error only if sealing itself fails.
    public static func rewrap(
        keyAccessObject: TDFKeyAccessObject,
        policyBase64: String,
        kasPrivateKey: P256.KeyAgreement.PrivateKey,
        receiverPublicKey: P256.KeyAgreement.PublicKey,
    ) throws -> RewrapResult {
        guard keyAccessObject.type == .ecWrapped else {
            throw TDFKASError.unsupportedKeyAccessType(keyAccessObject.type.rawValue)
        }
        guard let ephemeralPEM = keyAccessObject.ephemeralPublicKey,
              !ephemeralPEM.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else {
            throw TDFKASError.missingEphemeralPublicKey
        }
        let ephemeralPublicKey = try parseEphemeralPublicKey(ephemeralPEM)
        guard let wrappedKey = Data(base64Encoded: keyAccessObject.wrappedKey) else {
            throw TDFKASError.invalidWrappedKeyEncoding
        }

        var share = try openShare(wrappedKey, kasPrivateKey: kasPrivateKey, ephemeralPublicKey: ephemeralPublicKey)
        defer {
            share.secureZero()
        }
        guard share.count == shareByteCount else {
            throw TDFKASError.keyUnwrapFailed
        }
        try verifyPolicyBinding(keyAccessObject.policyBinding, policyBase64: policyBase64, share: share)

        let sessionPrivateKey = P256.KeyAgreement.PrivateKey()
        let sealed = try AES.GCM.seal(share, using: TDFCrypto.deriveKASWrapKey(sessionPrivateKey, receiverPublicKey))
        return RewrapResult(wrappedKey: sealed.combined!, sessionPublicKey: sessionPrivateKey.publicKey)
    }

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
                sessionPublicKey: sessionPublicKey,
                clientPrivateKey: receiverPrivateKey,
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

    // MARK: Scheme

    /// Parses a PEM P-256 public key the way the platform KAS does (go's
    /// `pem.Decode`): any line length and line ending, spaces and tabs inside
    /// the body, and text after the END line are accepted.
    static func parseEphemeralPublicKey(_ text: String) throws -> P256.KeyAgreement.PublicKey {
        let begin = "-----BEGIN PUBLIC KEY-----"
        let end = "-----END PUBLIC KEY-----"
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix(begin) else {
            throw TDFKASError.ephemeralKeyNotPEM
        }
        guard let endRange = trimmed.range(of: end) else {
            throw TDFKASError.invalidEphemeralPublicKey
        }
        let body = trimmed[trimmed.index(trimmed.startIndex, offsetBy: begin.count) ..< endRange.lowerBound]
            .filter { !$0.isWhitespace }
        guard let der = Data(base64Encoded: String(body)) else {
            throw TDFKASError.invalidEphemeralPublicKey
        }
        do {
            return try P256.KeyAgreement.PublicKey(derRepresentation: der)
        } catch {
            throw TDFKASError.invalidEphemeralPublicKey
        }
    }

    /// Opens nonce ‖ ciphertext ‖ tag with the KAS key. Every failure is
    /// `.keyUnwrapFailed`, so the caller cannot tell which step failed.
    private static func openShare(
        _ wrappedKey: Data,
        kasPrivateKey: P256.KeyAgreement.PrivateKey,
        ephemeralPublicKey: P256.KeyAgreement.PublicKey,
    ) throws -> Data {
        guard wrappedKey.count >= minimumWrappedKeyCount else {
            throw TDFKASError.keyUnwrapFailed
        }
        do {
            let key = try TDFCrypto.deriveKASWrapKey(kasPrivateKey, ephemeralPublicKey)
            return try AES.GCM.open(AES.GCM.SealedBox(combined: wrappedKey), using: key)
        } catch {
            throw TDFKASError.keyUnwrapFailed
        }
    }

    /// Spec-form binding only: `alg` is `HS256` (empty means `HS256`, OpenTDF
    /// spec PR #70) and `hash` is Base64 of the raw 32-byte
    /// `HMAC-SHA256(share, policyBase64)`, compared in constant time. go's
    /// legacy `Base64(hex(HMAC))` form is refused.
    private static func verifyPolicyBinding(
        _ binding: TDFPolicyBinding,
        policyBase64: String,
        share: Data,
    ) throws {
        guard binding.alg == "HS256" || binding.alg.isEmpty,
              let expected = Data(base64Encoded: binding.hash),
              expected.count == SHA256.byteCount,
              HMAC<SHA256>.isValidAuthenticationCode(
                  expected,
                  authenticating: Data(policyBase64.utf8),
                  using: SymmetricKey(data: share),
              )
        else {
            throw TDFKASError.policyBindingRefused
        }
    }
}

// MARK: - Errors

/// Failures of `TDFKAS`. No description contains key material, a key share or
/// an HMAC.
public enum TDFKASError: Error, CustomStringConvertible, Equatable {
    /// The key access object's `type` is not `ec-wrapped`.
    case unsupportedKeyAccessType(String)
    /// The key access object has no `ephemeralPublicKey`, or an empty one.
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
    /// A received Rewrap body is over 64 KiB.
    case requestTooLarge
    /// A received Rewrap is not in the expected shape; the value names the part
    /// (never its content).
    case malformedRewrapRequest(String)
    /// The signed request token's `alg` is not `ES256`.
    case unsupportedRequestAlgorithm(String)
    /// The signed request token does not verify under the given key.
    case requestSignatureInvalid
    /// A Rewrap response result is inconsistent; the value names the problem.
    case invalidResult(String)

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
        case .requestTooLarge:
            "Rewrap request is larger than 64 KiB"
        case let .malformedRewrapRequest(part):
            "Rewrap request is malformed: \(part)"
        case let .unsupportedRequestAlgorithm(alg):
            "Signed request token algorithm '\(alg.prefix(16))' is not supported; expected ES256"
        case .requestSignatureInvalid:
            "Signed request token signature is invalid"
        case let .invalidResult(problem):
            "Invalid Rewrap result: \(problem)"
        }
    }
}
