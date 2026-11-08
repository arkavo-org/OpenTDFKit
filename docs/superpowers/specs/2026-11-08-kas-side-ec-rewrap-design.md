# KAS-side TDF EC rewrap and an exposed client unwrap

Date: 2026-11-08
Status: Design, builder-checked, reviewed (advisor, Codex), pending approval
Issue: [#66](https://github.com/arkavo-org/OpenTDFKit/issues/66). Prerequisite for #67.
Consumer: arkavo-ios on-device KAS (arkavo-ios#77; its design §4.6 and ADR-0073, pinned at
`39da0a52b1191b4515eeeec2438ebb78b0ccd4fb`).

## Why

arkavo-ios wants an iPhone to act as a KAS for files its owner encrypts. The phone holds an EC P-256 KAS private key
and answers rewrap requests itself, relayed through a server that never sees key material. The phone needs the KAS half
of the TDF `ec-wrapped` rewrap in Swift. The receiving phone needs the client half for a response that did not
arrive over HTTP. The files are ordinary TDFs (ZIP) and must stay openable by other OpenTDF tools that know
the KAS (ADR-0073), so everything here must be byte-compatible with the go SDK and the opentdf-platform KAS.

Today OpenTDFKit has the KAS side only for NanoTDF (`KASService`), the ZIP encryptor wraps only with RSA, and the client
EC session unwrap exists (`KASRewrapClient.unwrapKey`) but defaults to the NanoTDF salt.

## Goals

1. **KAS-side rewrap.** A public, pure function (no network, no storage, no globals) that takes the KAS P-256 private
   key as a value, an `ec-wrapped` key access object (KAO) and the manifest's policy string. It unwraps the DEK, verifies
   the policy binding, and seals the DEK to a receiver's P-256 public key. It returns `(wrappedKey, sessionPublicKey)`.
2. **Client unwrap, exposed.** A public, pure function that takes `(wrappedKey, sessionPublicKey, receiverPrivateKey)`
   and returns the DEK, with the TDF salt fixed so a caller cannot pick the NanoTDF one by accident.
3. **Encrypt with an `ec-wrapped` KAO.** The ZIP encryptor (`TDFEncryptor`) can wrap to a caller-supplied P-256 KAS
   public key, with a caller-supplied KAO URL, `kid` and policy, in the go SDK's format.
4. **Proof of interop** with go, not only a Swift round trip (see Tests).
5. **A tagged release**, 5.2.0. Tagging and publishing wait for the owner's go-ahead.

## Non-goals

- Multiple KAOs, split or any-of plans (#67).
- Attribute or entitlement evaluation. The caller (the app) decides whether to release; this API only does the
  cryptography of a release it has already decided on.
- Matching the KAO's `url` or `kid` against the KAS. The caller does that; it knows its route and key ID.
- Changing the TDF-JSON or TDF-CBOR containers or their EC scheme.
- An offline "open my own file with the KAS private key" decrypt path in `TDFDecryptor`.
- P-384 and P-521 for this path.
- go's legacy hex binding form, in either direction. It is a bug (the owner's decision, 2026-11-08). OpenTDFKit
  neither writes nor accepts it, so older KASs without #4081 cannot rewrap OpenTDFKit's files, and this KAS-side rewrap
  refuses a TDF whose binding a go SDK wrote in hex.
- A manifest field for arkavo-ios's `arkavo.owner-image/1` profile marker. The OpenTDF spec has no such field and the
  KAS never reads one. A caller can carry it in the policy JSON today (the binding makes it tamper-evident). If
  arkavo-ios settles on a manifest assertion instead, that is a follow-up release.

## Anti-goals

It fails even if it works if:
- an `ec-wrapped` KAO written here cannot be rewrapped by an opentdf-platform KAS with EC enabled and the spec-form
  binding fix (#4081, `ca178b05`), or one written by the go SDK cannot be rewrapped here;
- a tampered policy produces any wrapped key;
- the existing TDF-JSON / TDF-CBOR EC files stop opening;
- an existing RSA caller of `TDFKasInfo` or `TDFEncryptor` has to change code or gets different output.

## Reference facts (verified against the local opentdf-platform checkout, `02813896`)

Two different EC schemes exist, and they must not be mixed:

| | TDF `ec-wrapped` (go SDK / platform) | TDF-JSON / TDF-CBOR drafts (OpenTDFKit today) |
| --- | --- | --- |
| Writer | `sdk/tdf.go` `generateWrapKeyWithEC` | `TDFCrypto.wrapSymmetricKeyWithEC` |
| HKDF salt | `SHA256("TDF")` (`tdfSalt()`) | empty |
| HKDF info / length | empty / 32 bytes | empty / 32 bytes |
| `ephemeralPublicKey` | PEM (SubjectPublicKeyInfo) | base64 compressed SEC1 |
| `wrappedKey` | base64(nonce 12 ‖ ciphertext ‖ tag 16) | same |

- The platform KAS (`service/kas/access/rewrap.go`, `case "ec-wrapped"`) PEM-decodes `ephemeralPublicKey` and refuses
  anything else ("invalid ephemeral public key PEM"). It unwraps with `NewSaltedECDecryptor(sk, TDFSalt(), nil)`
  (`service/internal/security/standard_crypto.go`).
- Policy binding (`rewrap.go`, `dek.VerifyBinding`): `HMAC-SHA256(DEK, policyBody)` where `policyBody` is the
  manifest's `encryptionInformation.policy` string as sent (the base64 text, as bytes). The KAO's `policyBinding.hash`
  is base64 of either the raw 32-byte HMAC (spec form; what OpenTDFKit writes) or the hex string of it (go's legacy
  form). **At `02813896` the KAS verifies only the legacy hex form**: it decodes the spec form into a 33-byte buffer
  and the length-sensitive compare fails. The fix is opentdf/platform#4081 (`ca178b05`, "accept spec-compliant policy
  bindings"), which OpenTDFKit's `xtest.yml` already pins. OpenTDFKit's RSA path already writes the spec form and
  already depends on that fix (`TDFCrypto.policyBinding`'s doc comment); the EC path follows the same rule.
- The platform's `ec-wrapped` case passes the KAO's `kid` straight to the key lookup, with no legacy-key fallback (the
  `wrapped` case has one). An `ec-wrapped` KAO without a `kid` cannot be rewrapped by a platform KAS.
- Rewrap response sealing (`rewrap.go` → `ocrypto.FromPublicPEMWithSalt(clientPublicKey, TDFSalt(), nil)`,
  `ECEncryptor.Encrypt`): a fresh ephemeral P-256 session key, ECDH with the client key, HKDF-SHA-256 with
  `SHA256("TDF")`, empty info, 32 bytes, AES-256-GCM with a random 12-byte nonce, output nonce ‖ ciphertext ‖ tag. The
  session public key is returned as PEM. `KASRewrapClient` already unwraps exactly this from a live platform, with
  `KASRewrapClient.standardTDFSessionSalt`.

The KAO wrap salt and the session salt are the same value, `SHA256("TDF")`.

## Design

### 1. KAS-side rewrap (new file, e.g. `OpenTDFKit/TDF/TDFKAS.swift`)

```swift
public enum TDFKAS {
    /// KAS side: unwrap the key share from an `ec-wrapped` KAO, verify the policy binding, seal the share to the
    /// receiver. See "What a successful rewrap proves" before relying on it.
    public static func rewrap(
        keyAccessObject: TDFKeyAccessObject,
        policyBase64: String,                             // manifest encryptionInformation.policy, unchanged
        kasPrivateKey: P256.KeyAgreement.PrivateKey,
        receiverPublicKey: P256.KeyAgreement.PublicKey,
    ) throws -> TDFKAS.RewrapResult

    /// Client side: open a rewrapped key share that did not come from an HTTP rewrap.
    public static func unwrap(
        wrappedKey: Data,
        sessionPublicKey: P256.KeyAgreement.PublicKey,
        receiverPrivateKey: P256.KeyAgreement.PrivateKey,
    ) throws -> SymmetricKey
}

extension TDFKAS {
    public struct RewrapResult: Sendable {
        public let wrappedKey: Data                       // nonce ‖ ciphertext ‖ tag
        public let sessionPublicKey: P256.KeyAgreement.PublicKey
    }
}
```

**Key share, not DEK.** What a KAO wraps is its split's key share. For a TDF with one split (every KAO in #66) the
share is the DEK. With several splits (#67) the shares are XORed (`TDFDecryptor.combineKeyShares`). The doc comments
say "key share" so #67 needs no signature change.

**`policyBase64`.** The HMAC is over the base64 text of the policy exactly as it appears in the manifest, not the
decoded JSON. The parameter name and doc comment say so; arkavo-ios's §4.4 "policy: bytes as in the TDF" must carry
that same base64 text.

`rewrap` steps, in order:
1. Refuse a KAO whose `type` is not `.ecWrapped`, or that has no `ephemeralPublicKey`.
2. Parse `ephemeralPublicKey` as a PEM P-256 public key, as the platform KAS does. Anything else is refused with its own
   error, whose message says the key is not PEM and that the TDF-JSON / TDF-CBOR EC scheme (compressed SEC1, empty
   salt) is not served by this function. A PEM key not on P-256 is refused.
3. ECDH(KAS private key, ephemeral key) → HKDF-SHA-256(salt `SHA256("TDF")`, info empty, 32) → AES-GCM open of the
   base64-decoded `wrappedKey` (nonce 12 ‖ ciphertext ‖ tag 16). Any failure is one "key unwrap failed" error: it does
   not say which step failed. The opened share must be exactly 32 bytes, or it is the same error.
4. From the moment the share is opened, a `defer` zeroes its bytes, so every later exit (a binding failure, a sealing
   failure, success) wipes it. Best effort, as `TDFCrypto` already does with `secureZero`.
5. Verify the binding over `Data(policyBase64.utf8)` with the share, in the spec form only: `policyBinding.alg` must be
   `HS256` (empty already decodes as `HS256`), and `policyBinding.hash` must base64-decode to exactly 32 bytes equal to
   the HMAC, compared in constant time. Any other `alg`, go's legacy `Base64(hex(HMAC))` form, and any mismatch are
   refused as one binding error. Nothing is sealed.
6. Generate a fresh P-256 session key and a fresh random nonce, ECDH with the receiver key, the same HKDF, AES-256-GCM
   seal. Return.

"A tampered policy fails before any rewrap" means step 5 runs before step 6. The share has to be opened first because
the binding is keyed by it.

`unwrap` delegates to `KASRewrapClient.unwrapKey` with `standardTDFSessionSalt`, so the HTTP and non-HTTP paths share
one implementation. It requires a 32-byte result. `KASRewrapClient.unwrapKey` currently leaves its decrypted `Data`
unwiped; it gets the same `defer` wipe, which also covers the HTTP path.

Errors: a new `TDFKASError` (`CustomStringConvertible`) with cases for an unsupported KAO type, a missing or
non-PEM ephemeral key, an invalid wrapped-key encoding, key unwrap failed, and binding refused. No message contains key
material, the share or the HMAC.

### What a successful rewrap proves (security notes; also in `rewrap`'s doc comment)

- **It does not prove who made the KAO.** Anyone holding the KAS *public* key (it is published in arkavo-ios's route
  record, §4.3) can wrap a key of their choosing to it and compute a valid binding over a policy of their choosing.
  `rewrap` will accept that. A passing binding proves only that the policy belongs to this KAO. The caller must match
  the KAO and policy against its own records (arkavo-ios records policy and KAO digests at protect time) before calling
  `rewrap`.
- **Do not forward which step failed.** The distinct errors (key unwrap failed versus binding refused) tell the caller
  whether a submitted ciphertext authenticated under the KAS key. That is for the caller's own audit. A response to a
  requester should collapse every `rewrap` failure into one code, as the platform's "bad request" does. (arkavo-ios's
  §4.5 lists a `BINDING_MISMATCH` deny code; its builder should map both failures to it.)

### 2. Encrypt with an `ec-wrapped` KAO

- `TDFKasInfo` gains a key type: `public enum KeyType: Sendable { case rsa, ecP256 }`, stored as `keyType`, with an
  `init` parameter defaulting to `.rsa` so every existing caller compiles and behaves the same. #67 reuses this type
  for each recipient in a plan, so keep it a plain enum on `TDFKasInfo`.
- A new go-compatible wrap function in `TDFCrypto`, named so it cannot be confused with the JSON/CBOR one, e.g.
  `wrapSymmetricKeyWithECForKAS(publicKeyPEM:symmetricKey:) -> (wrappedKey: String, ephemeralPublicKeyPEM: String)`.
  It mirrors `generateWrapKeyWithEC`: a fresh P-256 key, PEM ephemeral key, salt `SHA256("TDF")`.
- `TDFEncryptor` wraps in three places today (`encryptFile`, `encryptFileMultiSegment`, `encrypt(plaintext:…)`). Fold
  them into one helper that builds the KAO from `TDFKasInfo`: `.rsa` writes today's `wrapped` KAO byte for byte;
  `.ecP256` writes `type: "ec-wrapped"`, the PEM `ephemeralPublicKey`, the same `url`, `kid`, `schemaVersion` and policy
  binding (spec form) as the RSA path.
- An `.ecP256` `TDFKasInfo` is refused before encryption when its `kid` is nil or empty (no platform KAS can rewrap
  that KAO: verified, neither platform key index falls back for an empty `kid`), or when the configuration's key size
  is `.bits128` (the go SDK only reconstructs a 32-byte payload key, and `rewrap` only accepts 32-byte shares).
- Document the existing `wrapSymmetricKeyWithEC` / `unwrapSymmetricKeyWithEC` as the TDF-JSON / TDF-CBOR draft scheme,
  not the platform's `ec-wrapped`, and fix `ECWrappedKeyResult`'s doc comment (it says PEM; the value is compressed SEC1).

### 3. Tests

**The interop chain.** A Swift round trip alone would pass with the wrong salt. These four links together prove the
Swift code speaks the go scheme in both directions:
- (a) `unwrap` opens a rewrap response sealed by go → `unwrap` uses the go session scheme.
- (b) `unwrap` opens `rewrap`'s output → `rewrap` seals with that same scheme.
- (c) `rewrap` opens a KAO written by go → `rewrap` reads the go KAO scheme.
- (d) `rewrap` opens a KAO written by the Swift encryptor → the encryptor writes the go KAO scheme.

The chain closes only because `rewrap` accepts PEM ephemeral keys alone. If that is ever loosened, (d) stops proving
that the encryptor writes PEM. That dependency is stated in a comment on the (d) test.

The chain proves the cryptography, not serialization details that only go's parsers check (PEM framing, JSON field
spelling). So the go program also checks the reverse direction: it opens a KAO and a rewrap response written by Swift
(a fixture the Swift tests can write out on request) with go's `ocrypto` and the platform's PEM parsing. This runs by
hand, not in CI, and **must pass before the release is tagged**; the result goes in the PR description.

Swift (`swift test`, run in CI):
- Round trip: `TDFEncryptor` with an `.ecP256` KAS → `rewrap` → `unwrap` gives the DEK, and the payload decrypts with
  it. Covered for all three encryptor entry points (`encryptFile`, `encryptFileMultiSegment`, `encrypt(plaintext:…)`).
- Go fixture: links (a) and (c), above. A committed fixture produced by go, embedded in the test file. It holds a KAS
  P-256 private key, a policy string, an `ec-wrapped` KAO written the way `generateWrapKeyWithEC` writes it (with a
  spec-form binding computed by the generator, not go's hex form), the expected DEK, and a rewrap response sealed the
  way the platform seals it (`FromPublicPEMWithSalt(…, TDFSalt(), nil)`) to a fixed receiver key.
- Another receiver private key fails to unwrap.
- Tampering, each refused with nothing sealed: one changed character in the policy base64; the decoded policy JSON
  passed instead of the base64 text; a changed `policyBinding.hash`; the legacy hex binding of the correct HMAC; an
  `alg` other than `HS256`.
- Wrapped-key mutation, each refused: a flipped byte in the nonce, in the ciphertext and in the tag; the wrapped key
  truncated; a KAO wrapping a 16-byte key.
- Two `rewrap` calls on the same input give different session public keys and different nonces.
- A non-`ec-wrapped` KAO, a missing ephemeral key, a base64 SEC1 (non-PEM) ephemeral key, a KAO written by the
  TDF-JSON container, a P-384 ephemeral key and a wrong KAS private key each throw.
- An `.ecP256` `TDFKasInfo` without a `kid`, or with `.bits128`, is refused.
- An `.rsa` `TDFKasInfo` produces the same KAO fields as before this change.

Go program: under `scripts/interop/ec-wrapped/`, using the published `github.com/opentdf/platform/lib/ocrypto` module (a
pinned version in its `go.mod`). `generate` mirrors `generateWrapKeyWithEC` and the platform's response sealing and
prints the fixture; `verify` opens Swift output as above. Run by hand, not in CI.

## Left to the builder

- Exact type and function names, and file placement, provided the TDF EC functions are clearly distinct from
  the JSON/CBOR ones.
- How the Swift tests write out the fixture for the go `verify` step (for example, behind an environment variable).
- An optional manual check against a live opentdf-platform KAS with `ec_tdf_enabled` and #4081 (`ca178b05` or later,
  not the local checkout at `02813896`, which rejects spec-form bindings and would make a correct KAO look broken),
  using `KASRewrapClient` on a TDF written by the new encryptor path.
- README / CLAUDE.md updates for the new API.

## The owner's decisions

- "Standard TDF" just means TDF. New types, functions and files say TDF (`TDFKAS`, not `StandardTDFKAS`). The existing
  public `KASRewrapClient.standardTDFSessionSalt` keeps its name, since renaming it would break callers.

- The policy binding is the spec form only, written and verified. go's legacy hex form is a bug and is refused
  (2026-11-08).

## Calls made in this document (open to correction)

- Accept only a PEM ephemeral key in the KAO, as the platform does (changed from "PEM or SEC1" in chat: the only SEC1
  `ec-wrapped` writer is OpenTDFKit's own TDF-JSON/CBOR path, which uses a different salt, so accepting SEC1 would only
  turn a clear refusal into an opaque unwrap failure).
- Require a `kid` for an `.ecP256` KAS when encrypting.
- Key shares are exactly 32 bytes on this path (changed from "any length"): `rewrap` and `unwrap` refuse anything else,
  and the encryptor refuses `.ecP256` with `.bits128`. The go KAS accepts 16, 24 or 32, but the go SDK reader only
  builds a 32-byte key, so an AES-128 file would not open in other OpenTDF tools.
- Refuse any `policyBinding.alg` other than `HS256`.
- `rewrap` does not check the KAO's `url` or `kid`; the caller does.
- KAO unwrap and binding verification stay internal; only `rewrap` and `unwrap` are public.
- The Swift→go check is required before tagging but runs by hand, not in CI.
- Version 5.2.0, additive.
