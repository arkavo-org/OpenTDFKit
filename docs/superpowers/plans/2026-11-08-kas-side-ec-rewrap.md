# KAS-side TDF EC Rewrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A pure Swift KAS-side rewrap and client unwrap for TDF `ec-wrapped` key access objects, and an
`ec-wrapped` path in the ZIP encryptor, byte-compatible with the go SDK and opentdf-platform KAS (issue #66).

**Architecture:** A new `TDFKAS` namespace (`rewrap`, `unwrap`) with its own error type, built on CryptoKit and
the existing `KASRewrapClient.unwrapKey` / `standardTDFSessionSalt`. A new go-scheme EC wrap function in `TDFCrypto`,
selected by a new `TDFKasInfo.KeyType`, used by one KAO-building helper that all `TDFEncryptor` entry points share.
Interop is proven by a go program that generates a fixture (go → Swift, in CI) and verifies Swift output (Swift → go,
by hand before tagging).

**Tech Stack:** Swift 6.2, CryptoKit, XCTest; Go with `github.com/opentdf/platform/lib/ocrypto` for the interop program.

**Spec:** `docs/superpowers/specs/2026-11-08-kas-side-ec-rewrap-design.md`

## Global Constraints

- No new Swift package dependencies. CryptoKit for all new crypto.
- Salt for both the KAO wrap and the rewrap session: `KASRewrapClient.standardTDFSessionSalt` (`SHA256("TDF")`). HKDF
  info empty, output 32 bytes.
- Wrapped key layout: nonce (12) ‖ ciphertext ‖ tag (16), base64 in the KAO, raw `Data` in `TDFKAS.RewrapResult`.
- KAO `ephemeralPublicKey`: PEM SubjectPublicKeyInfo on P-256. Always written as PEM; only PEM accepted.
- Policy binding: spec form only. `alg` must be `HS256`; `hash` must base64-decode to exactly the 32-byte
  `HMAC-SHA256(share, Data(policyBase64.utf8))`, compared in constant time. The legacy `Base64(hex(HMAC))` form is refused.
- Key shares on this path are exactly 32 bytes.
- No error message contains key material, a key share or an HMAC.
- Existing RSA output and the TDF-JSON / TDF-CBOR EC scheme are unchanged.
- Run `swiftformat --swiftversion 6.2 .` before every commit.
- Work on branch `feat/66-kas-side-ec-rewrap`. Subagents never run `git checkout`, `git switch` or `git reset`; check
  `git branch --show-current` after each commit.
- Commit messages end with:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01XAvDR2wxp8A5rjt3P3FB1B
  ```
- Do not push, tag or publish a release. The owner gives that go-ahead separately.

## Review Focus

1. A KAO `ephemeralPublicKey` PEM with `\r\n` line endings or no trailing newline must parse (Task 2 test
   `testRewrapAcceptsCRLFPEM`).
2. A `TDFKasInfo` whose `keyType` does not match its PEM (`.ecP256` with an RSA PEM, `.rsa` with an EC PEM) must throw,
   not crash or write a broken KAO (Task 3 test `testKeyTypeAndPEMMismatchThrows`).
3. An empty-string `kid` is refused the same as nil (Task 3 test `testECKasWithoutKidIsRefused`).
4. A KAO decoded from JSON whose `policyBinding` is a bare string (decoded as `HS256`) verifies normally (Task 2 test
   `testBareStringBindingVerifies`).
5. A `wrappedKey` that is not standard base64 (base64url alphabet, embedded newline) throws
   `invalidWrappedKeyEncoding` (Task 2 test `testNonBase64WrappedKeyIsRefused`).

---

### Task 1: Go fixture and `TDFKAS.unwrap`

**Files:**
- Create: `scripts/interop/ec-wrapped/main.go`, `scripts/interop/ec-wrapped/go.mod`, `scripts/interop/ec-wrapped/go.sum`,
  `scripts/interop/ec-wrapped/README.md`
- Create: `OpenTDFKit/TDF/TDFKAS.swift`
- Create: `OpenTDFKitTests/TDFKASGoFixture.swift`, `OpenTDFKitTests/TDFKASTests.swift`
- Modify: `OpenTDFKit/KASRewrapClient.swift` (`unwrapKey`, around line 1079)

**Interfaces:**
- Produces:
  - `public enum TDFKAS` with
    `public static func unwrap(wrappedKey: Data, sessionPublicKey: P256.KeyAgreement.PublicKey, receiverPrivateKey: P256.KeyAgreement.PrivateKey) throws -> SymmetricKey`
  - `public enum TDFKASError: Error, CustomStringConvertible, Equatable` with cases
    `unsupportedKeyAccessType(String)`, `missingEphemeralPublicKey`, `ephemeralKeyNotPEM`, `invalidEphemeralPublicKey`,
    `invalidWrappedKeyEncoding`, `keyUnwrapFailed`, `policyBindingRefused`
  - `struct GoFixture: Decodable` (test target) with `kasPrivateKeyPEM`, `policyBase64`, `kao: TDFKeyAccessObject`,
    `dekBase64`, `receiverPrivateKeyPEM`, `response: { wrappedKeyBase64, sessionPublicKeyPEM }`, and
    `static func load() throws -> GoFixture` decoding `TDFKASGoFixture.json`
  - Go program subcommand `generate` (prints that JSON to stdout)

- [ ] **Step 1: Commit the approved spec and this plan**

```bash
git add docs/superpowers/specs/2026-11-08-kas-side-ec-rewrap-design.md docs/superpowers/plans/2026-11-08-kas-side-ec-rewrap.md
git commit -m "docs: design and plan for KAS-side TDF EC rewrap (#66)"
```

- [ ] **Step 2: Write the go program's `generate` subcommand**

`go.mod`: module `github.com/arkavo-org/OpenTDFKit/scripts/interop/ec-wrapped`, `require
github.com/opentdf/platform/lib/ocrypto v0.14.0`. `go mod tidy` writes `go.sum`.

`generate` builds everything with `ocrypto`, mirroring the go reference exactly:
- KAS key: `NewECKeyPair(ECCModeSecp256r1)`; `kasPrivateKeyPEM` = `PrivateKeyInPemFormat()`.
- Random 32-byte DEK. Policy JSON `{"uuid":"<random>","body":{"dataAttributes":[],"dissem":["interop@example.com"]}}`;
  `policyBase64` = std base64 of it.
- KAO, as `sdk/tdf.go` `generateWrapKeyWithEC`: fresh ephemeral pair, `ComputeECDHKey(ephPrivPEM, kasPubPEM)`,
  `CalculateHKDF(sha256("TDF"), ecdh)`, `NewAESGcm(key).Encrypt(dek)`; `wrappedKey` = std base64;
  `ephemeralPublicKey` = ephemeral `PublicKeyInPemFormat()`. JSON keys: `type` `"ec-wrapped"`, `url`
  `"https://kas.example.com"`, `protocol` `"kas"`, `wrappedKey`, `policyBinding` `{"alg":"HS256","hash": base64(raw
  HMAC-SHA256(dek, []byte(policyBase64)))}` (spec form, not hex), `kid` `"e1"`, `schemaVersion` `"1.0"`,
  `ephemeralPublicKey`.
- Response, as the platform's `rewrap.go`: fresh receiver pair; `FromPublicPEMWithSalt(receiverPubPEM, sha256("TDF"),
  nil)`; `Encrypt(dek)` gives `wrappedKeyBase64`; the encryptor's `PublicKeyInPemFormat()` gives
  `sessionPublicKeyPEM`. `receiverPrivateKeyPEM` = the receiver's private PEM.

`README.md`: what the program is, `go run . generate > fixture.json`, and that the output goes into
`OpenTDFKitTests/TDFKASGoFixture.swift` verbatim.

- [ ] **Step 3: Generate the fixture and embed it**

Run: `cd scripts/interop/ec-wrapped && go run . generate`
Expected: one JSON object with every field above. Paste it into `OpenTDFKitTests/TDFKASGoFixture.swift` as
`enum TDFKASGoFixture { static let json = #""" … """# }`, with a comment naming the generator and the ocrypto
version. Add `GoFixture` and `load()` in the same file.

- [ ] **Step 4: Write the failing tests** in `OpenTDFKitTests/TDFKASTests.swift` (`final class TDFKASTests: XCTestCase`)

```swift
/// Interop link (a): unwrap uses the go session scheme.
func testUnwrapOpensGoSealedResponse() throws {
    let f = try GoFixture.load()
    let share = try TDFKAS.unwrap(
        wrappedKey: Data(base64Encoded: f.response.wrappedKeyBase64)!,
        sessionPublicKey: P256.KeyAgreement.PublicKey(pemRepresentation: f.response.sessionPublicKeyPEM),
        receiverPrivateKey: P256.KeyAgreement.PrivateKey(pemRepresentation: f.receiverPrivateKeyPEM))
    XCTAssertEqual(share.withUnsafeBytes { Data($0) }, Data(base64Encoded: f.dekBase64))
}

func testUnwrapWithAnotherReceiverKeyFails() throws {
    // same fixture, receiverPrivateKey: P256.KeyAgreement.PrivateKey()
    // XCTAssertThrowsError → XCTAssertEqual($0 as? TDFKASError, .keyUnwrapFailed)
}

func testUnwrapRefusesNon32ByteShare() throws {
    // seal 16 random bytes to a fresh receiver with `standardTDFSessionSalt` (local helper, CryptoKit)
    // → .keyUnwrapFailed
}
```

- [ ] **Step 5: Run to verify they fail**

Run: `swift test --filter TDFKASTests`
Expected: compile failure, `cannot find 'TDFKAS' in scope`.

- [ ] **Step 6: Implement**

In `TDFKAS.swift`: the error enum (descriptions name the failure only; `ephemeralKeyNotPEM`'s says the key is
not PEM and that the TDF-JSON / TDF-CBOR EC scheme is not served here), and `unwrap`, which calls
`KASRewrapClient.unwrapKey(wrappedKey:sessionPublicKey: sessionPublicKey.compressedRepresentation, clientPrivateKey:
receiverPrivateKey.rawRepresentation, salt: KASRewrapClient.standardTDFSessionSalt)`, maps any thrown error to
`.keyUnwrapFailed`, and refuses a result that is not 32 bytes with `.keyUnwrapFailed`. Doc comments say "key share"
(the DEK for a single-split TDF).

In `KASRewrapClient.unwrapKey`: make the opened `Data` a `var` and `defer { decryptedKey.secureZero() }` before
returning `SymmetricKey(data:)`, as `TDFCrypto.unwrapSymmetricKeyWithEC` already does.

- [ ] **Step 7: Run to verify they pass, and nothing else broke**

Run: `swift test --filter TDFKASTests && swift test --filter KASRewrap`
Expected: all pass.

- [ ] **Step 8: Commit**

```bash
swiftformat --swiftversion 6.2 .
git add scripts/interop/ec-wrapped OpenTDFKit/TDF/TDFKAS.swift OpenTDFKit/KASRewrapClient.swift OpenTDFKitTests/TDFKASGoFixture.swift OpenTDFKitTests/TDFKASTests.swift
git commit -m "feat(kas): TDF EC client unwrap and go interop fixture (#66)"
```

---

### Task 2: Go-scheme EC wrap and `TDFKAS.rewrap`

**Files:**
- Modify: `OpenTDFKit/TDF/TDFCrypto.swift` (new function after the existing EC section)
- Modify: `OpenTDFKit/TDF/TDFKAS.swift`
- Test: `OpenTDFKitTests/TDFKASTests.swift`

**Interfaces:**
- Consumes: Task 1's `TDFKAS`, `TDFKASError`, `GoFixture`.
- Produces:
  - `public struct KASECWrappedKey: Sendable { public let wrappedKey: String; public let ephemeralPublicKeyPEM: String }`
  - `TDFCrypto.wrapSymmetricKeyWithECForKAS(publicKeyPEM: String, symmetricKey: SymmetricKey) throws -> KASECWrappedKey`
  - `TDFKAS.RewrapResult`, declared in an `extension TDFKAS` as `public struct RewrapResult: Sendable { public let wrappedKey: Data; public let sessionPublicKey: P256.KeyAgreement.PublicKey }`
  - `TDFKAS.rewrap(keyAccessObject: TDFKeyAccessObject, policyBase64: String, kasPrivateKey: P256.KeyAgreement.PrivateKey, receiverPublicKey: P256.KeyAgreement.PublicKey) throws -> RewrapResult`

- [ ] **Step 1: Write the failing tests**

Test helper (in the test file): `makeKAO(share: SymmetricKey, kasPublicKey: P256.KeyAgreement.PublicKey, policyJSON:
Data) throws -> (TDFKeyAccessObject, policyBase64: String)` using `wrapSymmetricKeyWithECForKAS(publicKeyPEM:
kasPublicKey.pemRepresentation, …)` and `TDFCrypto.policyBinding(policy:symmetricKey:)`, `type: .ecWrapped`, `kid: "e1"`.

```swift
/// Link (c): rewrap reads the go KAO scheme. Link (b): unwrap opens rewrap's output.
func testRewrapOpensGoKAOAndUnwrapOpensResult() throws {
    let f = try GoFixture.load()
    let receiver = P256.KeyAgreement.PrivateKey()
    let r = try TDFKAS.rewrap(keyAccessObject: f.kao, policyBase64: f.policyBase64,
        kasPrivateKey: .init(pemRepresentation: f.kasPrivateKeyPEM), receiverPublicKey: receiver.publicKey)
    let share = try TDFKAS.unwrap(wrappedKey: r.wrappedKey, sessionPublicKey: r.sessionPublicKey, receiverPrivateKey: receiver)
    XCTAssertEqual(share.withUnsafeBytes { Data($0) }, Data(base64Encoded: f.dekBase64))
}

func testWrapThenRewrapRoundTrip()            // makeKAO → rewrap → unwrap == share; KAO ephemeralPublicKey hasPrefix "-----BEGIN PUBLIC KEY-----"
func testRewrapResultIsFresh()                // two rewraps of one input: sessionPublicKey.rawRepresentation differ, wrappedKey.prefix(12) differ

// Each of these: XCTAssertThrowsError → XCTAssertEqual($0 as? TDFKASError, .policyBindingRefused)
func testTamperedPolicyIsRefused()            // one base64 character of policyBase64 changed
func testDecodedPolicyJSONIsRefused()         // policyBase64: String(decoding: policyJSON, as: UTF8.self)
func testTamperedBindingHashIsRefused()       // one character of policyBinding.hash changed
func testLegacyHexBindingIsRefused()          // hash = base64(hex string of the correct HMAC)
func testNonHS256AlgIsRefused()               // policyBinding.alg = "GMAC"
func testBareStringBindingVerifies()          // KAO JSON re-encoded with "policyBinding": "<hash>", decoded, rewrap succeeds

// Each of these: .keyUnwrapFailed
func testFlippedNonceByteIsRefused()          // byte 0 of the decoded wrappedKey
func testFlippedCiphertextByteIsRefused()     // byte 12
func testFlippedTagByteIsRefused()            // last byte
func testTruncatedWrappedKeyIsRefused()       // drop the last byte; also a 20-byte prefix
func testSixteenByteShareIsRefused()          // makeKAO with SymmetricKey(size: .bits128)
func testWrongKASPrivateKeyIsRefused()

func testNonBase64WrappedKeyIsRefused()       // base64url alphabet ("-", "_") and an embedded "\n" → .invalidWrappedKeyEncoding
func testWrongKAOTypeIsRefused()              // type .wrapped → .unsupportedKeyAccessType("wrapped")
func testMissingEphemeralKeyIsRefused()       // nil → .missingEphemeralPublicKey
func testSEC1EphemeralKeyIsRefused()          // base64 compressed SEC1 → .ephemeralKeyNotPEM
func testTDFJSONContainerKAOIsRefused()       // TDFJSONBuilder().kasURL(…).kasPublicKey(kasPub.pemRepresentation).policy(…).encrypt → keyAccess[0] → .ephemeralKeyNotPEM
func testP384EphemeralKeyIsRefused()          // P384.KeyAgreement.PrivateKey().publicKey.pemRepresentation → .invalidEphemeralPublicKey
func testRewrapAcceptsCRLFPEM()               // ephemeralPublicKey with "\n" → "\r\n", and with the trailing newline removed: both succeed
```

- [ ] **Step 2: Run to verify they fail**

Run: `swift test --filter TDFKASTests`
Expected: compile failure, `type 'TDFKAS' has no member 'rewrap'`.

- [ ] **Step 3: Implement `wrapSymmetricKeyWithECForKAS`**

Load the KAS key with `P256.KeyAgreement.PublicKey(pemRepresentation:)`, fresh ephemeral key, ECDH, HKDF (`standardTDFSessionSalt`,
empty info, 32), `AES.GCM.seal` with a random nonce, `combined` base64. `ephemeralPublicKeyPEM` =
`ephemeral.publicKey.pemRepresentation`. Errors from loading surface as `TDFCryptoError`. Doc comment: the go SDK /
platform `ec-wrapped` scheme, distinct from `wrapSymmetricKeyWithEC`.

- [ ] **Step 4: Implement `rewrap`**

Steps exactly as the spec's §1 list:
1. `type == .ecWrapped` else `.unsupportedKeyAccessType(type.rawValue)`; `ephemeralPublicKey` non-nil else
   `.missingEphemeralPublicKey`.
2. If the trimmed string does not start with `-----BEGIN PUBLIC KEY-----`, `.ephemeralKeyNotPEM`. Normalize `\r\n` to
   `\n`, then `P256.KeyAgreement.PublicKey(pemRepresentation:)`; failure → `.invalidEphemeralPublicKey`.
3. `Data(base64Encoded: wrappedKey)` (no options) else `.invalidWrappedKeyEncoding`. Fewer than 29 bytes,
   `SealedBox(combined:)` or `open` failure, or a result that is not 32 bytes → `.keyUnwrapFailed`.
4. `var share` with `defer { share.secureZero() }` immediately after it is opened.
5. Binding: `alg == "HS256"`, `Data(base64Encoded: hash)` exactly 32 bytes, `HMAC<SHA256>.isValidAuthenticationCode(_:
   authenticating: Data(policyBase64.utf8), using: SymmetricKey(data: share))`. Any failure → `.policyBindingRefused`.
6. Fresh `P256.KeyAgreement.PrivateKey()`, ECDH with `receiverPublicKey`, same HKDF, `AES.GCM.seal(share, …)`, return
   `combined` and the session public key.

`rewrap`'s doc comment carries the spec's two security notes ("does not prove who made the KAO"; "do not forward which
step failed") and the `policyBase64` encoding rule.

- [ ] **Step 5: Run to verify they pass**

Run: `swift test --filter TDFKASTests`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
swiftformat --swiftversion 6.2 .
git add OpenTDFKit/TDF/TDFCrypto.swift OpenTDFKit/TDF/TDFKAS.swift OpenTDFKitTests/TDFKASTests.swift
git commit -m "feat(kas): KAS-side TDF ec-wrapped rewrap (#66)"
```

---

### Task 3: `ec-wrapped` KAOs from `TDFEncryptor`

**Files:**
- Modify: `OpenTDFKit/TDF/TDFProcessor.swift` (`TDFKasInfo` lines 4-16; wrap sites in `encryptFile` ~117,
  `encryptFileMultiSegment` ~229, `makeResult` ~413; new `TDFEncryptError` beside `TDFDecryptError` ~740)
- Modify: `OpenTDFKit/TDF/TDFCrypto.swift` (doc comments of `wrapSymmetricKeyWithEC`, `unwrapSymmetricKeyWithEC`,
  `ECWrappedKeyResult`)
- Test: `OpenTDFKitTests/TDFKASEncryptorTests.swift`

**Interfaces:**
- Consumes: Task 2's `wrapSymmetricKeyWithECForKAS`, `TDFKAS.rewrap`, `TDFKAS.unwrap`.
- Produces:
  - `TDFKasInfo.KeyType: Sendable, Equatable { case rsa, ecP256 }`; `public let keyType: KeyType`;
    `init(url:publicKeyPEM:kid:schemaVersion:keyType: KeyType = .rsa)`
  - `public enum TDFEncryptError: Error, CustomStringConvertible, Equatable { case ecKasRequiresKeyID, ecKasRequiresAES256 }`

- [ ] **Step 1: Write the failing tests** (`final class TDFKASEncryptorTests: XCTestCase`)

Helper: `makeECKas(kid: String? = "e1") -> (TDFKasInfo, P256.KeyAgreement.PrivateKey)` with `keyType: .ecP256` and
`publicKeyPEM: kasKey.publicKey.pemRepresentation`. `openThroughKAS(_ result: TDFEncryptionResult, kasKey:) throws ->
Data` does `rewrap(keyAccessObject: keyAccess[0], policyBase64: encryptionInformation.policy, …)` → `unwrap` →
`TDFDecryptor().decrypt(container:symmetricKey:)`.

```swift
/// Link (d): the encryptor writes the go KAO scheme. This proves PEM output only while
/// rewrap accepts PEM alone; keep that comment if rewrap's parsing ever changes.
func testEncryptPlaintextWritesECWrappedKAO()   // encrypt(plaintext:configuration:): keyAccess.count == 1, type == .ecWrapped,
                                                // kid == "e1", ephemeralPublicKey hasPrefix "-----BEGIN PUBLIC KEY-----",
                                                // openThroughKAS == plaintext
func testEncryptSegmentedWritesECWrappedKAO()   // encrypt(plaintext:configuration:segmentSize: 1024) on 5_000 bytes
func testEncryptFileWritesECWrappedKAO()        // encryptFile to a temp dir, TDFLoader().load, open
func testEncryptFileMultiSegmentWritesECWrappedKAO() // segmentSizes [1024, 1024, 2952]
func testECKasWithoutKidIsRefused()             // kid nil and kid "" → TDFEncryptError.ecKasRequiresKeyID, no output file written
func testECKasWithAES128IsRefused()             // keySize .bits128 → .ecKasRequiresAES256
func testKeyTypeAndPEMMismatchThrows()          // .ecP256 + RSA PEM, .rsa + EC PEM: both throw (any error)
func testRSAKasOutputIsUnchanged()              // default keyType: type .wrapped, ephemeralPublicKey nil, schemaVersion "1.0",
                                                // binding verifies, TDFCrypto.unwrapSymmetricKeyWithRSA gives result.symmetricKey
```

Use `generateTestRSAKeyPair()` (already used by `TDFTests`) for RSA PEMs.

- [ ] **Step 2: Run to verify they fail**

Run: `swift test --filter TDFKASEncryptorTests`
Expected: compile failure, `extra argument 'keyType' in call`.

- [ ] **Step 3: Implement**

- `TDFKasInfo.KeyType` and `keyType` as above.
- `TDFEncryptError` with descriptions.
- A private `TDFEncryptor` helper `func validate(_ configuration: TDFEncryptionConfiguration) throws`, called first in
  `encryptFile`, `encryptFileMultiSegment`, `encrypt(plaintext:configuration:)` and
  `encrypt(plaintext:configuration:segmentSize:)`: for `.ecP256`, a nil or empty `kid` throws `.ecKasRequiresKeyID`
  and `keySize != .bits256` throws `.ecKasRequiresAES256`.
- A private helper `func makeKeyAccessObject(kas: TDFKasInfo, symmetricKey: SymmetricKey, policyBinding:
  TDFPolicyBinding) throws -> TDFKeyAccessObject` replacing the three inline RSA wrap + `TDFKeyAccessObject(…)` blocks:
  `.rsa` builds today's object unchanged; `.ecP256` uses `wrapSymmetricKeyWithECForKAS` and sets `type:
  .ecWrapped`, `ephemeralPublicKey: wrapped.ephemeralPublicKeyPEM`, the same `url`, `kid`, `schemaVersion ?? "1.0"`.
- Doc comments: `wrapSymmetricKeyWithEC` / `unwrapSymmetricKeyWithEC` are the TDF-JSON / TDF-CBOR draft scheme (empty
  salt, compressed SEC1 ephemeral key), not the platform's `ec-wrapped`; point to `wrapSymmetricKeyWithECForKAS`.
  `ECWrappedKeyResult.ephemeralPublicKey` is base64 compressed SEC1, not PEM.

- [ ] **Step 4: Run to verify they pass, plus the existing TDF suites**

Run: `swift test --filter TDFKAS && swift test --filter TDF`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
swiftformat --swiftversion 6.2 .
git add OpenTDFKit/TDF/TDFProcessor.swift OpenTDFKit/TDF/TDFCrypto.swift OpenTDFKitTests/TDFKASEncryptorTests.swift
git commit -m "feat(tdf): ec-wrapped key access objects from TDFEncryptor (#66)"
```

---

### Task 4: Swift → go verification, docs

**Files:**
- Modify: `scripts/interop/ec-wrapped/main.go`, `scripts/interop/ec-wrapped/README.md`
- Modify: `OpenTDFKitTests/TDFKASEncryptorTests.swift`
- Modify: `CLAUDE.md`, `MIGRATION_GUIDE.md`, `README.md` (if it lists TDF APIs)

**Interfaces:**
- Consumes: Tasks 1-3.
- Produces: go subcommand `verify <path>`; env var `OPENTDFKIT_INTEROP_OUT`.

- [ ] **Step 1: Write the fixture-writing test**

`testWriteSwiftFixtureForGo`: `XCTSkip` unless `OPENTDFKIT_INTEROP_OUT` is set. Otherwise: a fresh KAS key, a policy,
`TDFEncryptor().encrypt(plaintext:configuration:)` with `.ecP256`, a fresh receiver key, `TDFKAS.rewrap` of the
written KAO; write JSON in Task 1's fixture shape (`kasPrivateKeyPEM`, `policyBase64`, `kao` as the manifest encodes
it, `dekBase64` = `result.symmetricKey`, `receiverPrivateKeyPEM`, `response` with `sessionPublicKey.pemRepresentation`)
to that path.

- [ ] **Step 2: Write the go `verify` subcommand**

Reads the file and fails loudly at the first mismatch:
- Open the KAO the way the platform does: `pem.Decode` the `ephemeralPublicKey` (fail if nil), `x509.ParsePKIXPublicKey`,
  `*ecdsa.PublicKey`, `CompressedECPublicKey(ECCModeSecp256r1, …)`, then `NewSaltedECDecryptor(ECPrivateKeyFromPem(kas),
  sha256("TDF"), nil).DecryptWithEphemeralKey(wrapped, compressed)`; must equal the DEK.
- Binding: base64-decode `hash` to 32 bytes, `hmac.Equal` with HMAC-SHA256(dek, []byte(policyBase64)); `alg` is `HS256`.
- Open the response the way the go SDK client does: `ComputeECDHKey(receiverPrivPEM, sessionPubPEM)`,
  `CalculateHKDF(sha256("TDF"), …)`, `NewAESGcm(…).Decrypt(wrapped)`; must equal the DEK.
- Print `OK` and exit 0.

- [ ] **Step 3: Run the check**

```bash
OPENTDFKIT_INTEROP_OUT="$PWD/swift-interop.json" swift test --filter TDFKASEncryptorTests/testWriteSwiftFixtureForGo
(cd scripts/interop/ec-wrapped && go run . verify "$OLDPWD/swift-interop.json")
rm swift-interop.json
```
Expected: the test passes (not skipped), then `OK`. Paste the output into the task report; it goes in the PR
description. A failure here blocks the release.

- [ ] **Step 4: Docs**

- `CLAUDE.md` Project Structure: a **TDFKAS** entry (pure KAS-side `ec-wrapped` rewrap and client unwrap, the
  salt, PEM-only, spec-form binding only, 32-byte shares, and the two security notes in one line each), and under
  **TDFProcessor** the `TDFKasInfo.keyType` (`.rsa` default, `.ecP256` needs a `kid` and AES-256).
- `MIGRATION_GUIDE.md`: a `v5.2.0` section, additive: the new types and functions, `TDFKasInfo.keyType`, the
  `KASRewrapClient.unwrapKey` wipe, and that `wrapSymmetricKeyWithEC` is the TDF-JSON/CBOR scheme.
- `README.md`: only if it already documents TDF encryption APIs; one short `ec-wrapped` example.

- [ ] **Step 5: Full suite**

Run: `swift build && swift test`
Expected: all pass except tests that already need a live platform and skip without one.

- [ ] **Step 6: Commit**

```bash
swiftformat --swiftversion 6.2 .
git add scripts/interop/ec-wrapped OpenTDFKitTests/TDFKASEncryptorTests.swift CLAUDE.md MIGRATION_GUIDE.md README.md
git commit -m "test(interop): verify Swift ec-wrapped output with go; docs for 5.2.0 (#66)"
```
