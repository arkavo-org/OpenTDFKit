@preconcurrency import CryptoKit
import Foundation

// MARK: - Shared digests

/// Digests that a KAS and its client must compute identically, for example an
/// owner KAS's signed decision record and the receiver that verifies it. Both
/// sides call these functions; neither hashes JSON bytes, which are not stable
/// across encoders.
public extension TDFKAS {
    /// SHA-256 of a signed request token: the compact JWT string's UTF-8 bytes
    /// (the `signed_request_token` value, not the HTTP body).
    static func requestTokenDigest(_ token: String) -> Data {
        Data(SHA256.hash(data: Data(token.utf8)))
    }

    /// SHA-256 of a key access object's fields in a fixed encoding, so the object
    /// in a TDF's manifest and the one a client forwards in a Rewrap request
    /// (which drops `schemaVersion` and reorders keys) digest the same.
    ///
    /// The input is the tag `OpenTDFKit/kao-digest/v1`, then `type`, `url`,
    /// `protocol`, `wrappedKey`, `policyBinding.alg` (empty means `HS256`),
    /// `policyBinding.hash`, `kid`, `sid`, `encryptedMetadata` and
    /// `ephemeralPublicKey`, in that order. Each field is one presence byte
    /// (`0` absent, `1` present), then, when present, a 4-byte big-endian length
    /// and its UTF-8 bytes. `schemaVersion` is not included.
    static func keyAccessObjectDigest(_ kao: TDFKeyAccessObject) -> Data {
        var input = Data("OpenTDFKit/kao-digest/v1".utf8)
        let alg = kao.policyBinding.alg.isEmpty ? "HS256" : kao.policyBinding.alg
        let fields: [String?] = [
            kao.type.rawValue,
            kao.url,
            kao.protocolValue.rawValue,
            kao.wrappedKey,
            alg,
            kao.policyBinding.hash,
            kao.kid,
            kao.sid,
            kao.encryptedMetadata,
            kao.ephemeralPublicKey,
        ]
        for field in fields {
            guard let field else {
                input.append(0)
                continue
            }
            let bytes = Data(field.utf8)
            input.append(1)
            withUnsafeBytes(of: UInt32(bytes.count).bigEndian) { input.append(contentsOf: $0) }
            input.append(bytes)
        }
        return Data(SHA256.hash(data: input))
    }

    /// SHA-256 of a P-256 public key's 65-byte uncompressed SEC1 point
    /// (`04 ‖ X ‖ Y`), whatever encoding the key arrived in.
    static func publicKeyFingerprint(_ key: P256.KeyAgreement.PublicKey) -> Data {
        Data(SHA256.hash(data: key.x963Representation))
    }
}
