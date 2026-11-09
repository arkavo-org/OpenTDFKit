# Owner KAS Rewrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Items 2–8 of the revised #66: the owner's phone can verify a Rewrap and build its response, and
`KASRewrapClient` can call a KAS that answers later (202 polling, caller `exp`, extension member, full results), with
path-aware key access object matching.

**Architecture:**
- The phone half is pure `TDFKAS` functions: shared digests, request verification and a response builder.
- The client half is new `KASRewrapClient` methods (`prepareRewrap`, `submitRewrap`, `pollRewrap`, `rewrap`) that
  leave the existing methods unchanged.
- Path-aware matching changes `matchesKasURL`, and with it every client path.
- An end-to-end test runs the real client against a fake transport that plays relay and phone with the `TDFKAS`
  functions.

**Tech Stack:** Swift 6.2, CryptoKit, XCTest.

**Spec:** `docs/superpowers/specs/2026-11-09-owner-kas-rewrap-design.md` (extends
`docs/superpowers/specs/2026-11-08-kas-side-ec-rewrap-design.md`).

## Global Constraints

- No new package dependencies. The existing `KASRewrapClient`, `rewrapTDF`, `rewrapAndUnwrapTDF`,
  `rewrapAndUnwrapTDFShares` and bulk API keep their behavior, except for matching (Task 2).
- `requestTokenDigest` = SHA-256 of the compact JWT's UTF-8 bytes. The phone and the client both call
  `TDFKAS.requestTokenDigest`.
- `keyAccessObjectDigest`:
  - SHA-256 over the tag `OpenTDFKit/kao-digest/v1`;
  - then, in order, `type`, `url`, `protocol`, `wrappedKey`, `policyBinding.alg` (empty → `HS256`),
    `policyBinding.hash`, `kid`, `sid`, `encryptedMetadata`, `ephemeralPublicKey`;
  - each field is a presence byte (0/1), then, if present, a 4-byte big-endian length and its UTF-8 bytes;
  - `schemaVersion` is excluded.
- `publicKeyFingerprint` = SHA-256 of `x963Representation` (65 bytes).
- Phone limits:
  - bodies at most 65,536 bytes;
  - only JWT `alg` `ES256`, with a raw 64-byte signature over `header.payload` as received;
  - `exp` is returned, not enforced.
- Standard `requestBody` member names: `clientPublicKey`, `requests`, `keyAccess`, `policy`, `algorithm`,
  `schemaVersion`.
- `Retry-After`: delta-seconds only, default 2 s, clamped to 1–60 s, never past the deadline.
- `Location`: resolved against the Rewrap URL, and must keep its scheme, host and effective port.
- Poll statuses: `202` repeats; `200` is answered; `410` is expired; `404` at or after the handle's `expiresAt` is
  expired; a `404` before it throws `.httpError(404, …)`.
- Matching: case-insensitive scheme and host, the effective port, and the normalized path (trailing `/` trimmed, `/kas`
  ≡ empty, case-sensitive).
- No error description contains key material, a share, an HMAC or a token.
- Run `swiftformat --swiftversion 6.2 .` before every commit.
- Work on branch `feat/66-kas-side-ec-rewrap`. Never `git checkout`, `switch` or `reset`; check
  `git branch --show-current` after each commit.
- Commit messages end with:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01XAvDR2wxp8A5rjt3P3FB1B
  ```
- Push only to update PR #68. No tag or release.

## Review Focus

1. A `requestBody` whose extension holds non-ASCII text or escaped `/` must come back from `verifyRewrapRequest` as
   JSON equal to what was sent (Task 3: `testExtensionRoundTripsUnicodeAndSlashes`).
2. A `Retry-After` of `0`, a negative value or a huge value is clamped, and never sleeps past the deadline (Task 6:
   `testRetryAfterIsClamped`).
3. A `Location` that is absolute but on the same origin is followed; protocol-relative (`//evil.example/x`) and other
   origins are refused (Task 6: `testLocationOriginRules`).
4. A 200 answer with `sessionPublicKey` absent and only fail results (a pure DENY) parses without throwing (Task 6:
   `testDenyOnlyAnswerParses`).
5. A KAO URL with a different-case path (`/OWNER-KAS/…`) does not match; a different-case host does (Task 2:
   `testPathIsCaseSensitiveHostIsNot`).

---

### Task 1: Shared digests

**Files:**
- Create: `OpenTDFKit/TDF/TDFKASDigests.swift`
- Test: `OpenTDFKitTests/TDFKASDigestTests.swift`

**Interfaces:**
- Produces: `TDFKAS.requestTokenDigest(_ token: String) -> Data`,
  `TDFKAS.keyAccessObjectDigest(_ kao: TDFKeyAccessObject) -> Data`,
  `TDFKAS.publicKeyFingerprint(_ key: P256.KeyAgreement.PublicKey) -> Data`

- [ ] **Step 1: Commit the approved spec and this plan.**
  `git add docs/superpowers/specs/2026-11-08-kas-side-ec-rewrap-design.md docs/superpowers/specs/2026-11-09-owner-kas-rewrap-design.md docs/superpowers/plans/2026-11-09-owner-kas-rewrap.md`.
  Commit as `docs: design and plan for owner-KAS rewrap (#66)`.

- [ ] **Step 2: Write the failing tests** (`final class TDFKASDigestTests: XCTestCase`)

```swift
func testRequestTokenDigestIsSHA256OfTokenBytes()      // == Data(SHA256.hash(data: Data("a.b.c".utf8)))
func testKAODigestKnownVector()                        // a fixed KAO (all fields set) → hex string written into the test from a
                                                       // hand-assembled byte buffer built in the test, independently of the implementation
func testKAODigestIgnoresSchemaVersion()               // schemaVersion "1.0" vs nil → equal
func testKAODigestEmptyAlgIsHS256()                    // alg "" vs "HS256" → equal
func testKAODigestChangesWithEachIncludedField()       // mutate each of the 10 fields in turn → all digests distinct
func testKAODigestAbsentVersusEmptyDiffer()            // kid nil vs kid "" → different
func testKAODigestSameForManifestAndForwardedKAO()     // KAO from TDFEncryptor (.ecP256); round-trip it through the client's
                                                       // request encoding (JSONEncoder of the request entry), decode → equal digest
func testFingerprintIndependentOfPEMLayout()           // key from PEM (LF), PEM (CRLF), x963 bytes → equal; == SHA256(x963)
```

- [ ] **Step 3: Run:** `swift test --filter TDFKASDigestTests`. Expected: compile failure, `has no member 'requestTokenDigest'`.

- [ ] **Step 4: Implement** the three functions in `TDFKASDigests.swift` as `extension TDFKAS`. The algorithm is fixed
  by the Global Constraints.

- [ ] **Step 5: Run:** `swift test --filter TDFKASDigestTests`. Expected: PASS.

- [ ] **Step 6: Commit** `feat(kas): shared request, KAO and key digests (#66)`.

---

### Task 2: Path-aware key access object matching

**Files:**
- Modify: `OpenTDFKit/KASRewrapClient.swift` (`matchesKasURL`, ~line 1042)
- Test: `OpenTDFKitTests/KASRewrapMatchingTests.swift`

**Interfaces:**
- Produces: the behavior of `keyAccessObjects(in:)`. Nothing new is public.

- [ ] **Step 1: Write the failing tests.** Clients come from `forKasConnect(uri)`. The manifest holds KAOs at the
  table's URLs, with `h = platform.arkavo.net` and `R = 01HZXK3Q8R4M5N6P7Q8R9S0T1V`.

```swift
func testPlatformClientSelectsPlatformKAOsOnly()       // uri https://h → selects https://h/kas and https://h, not the owner KAO
func testKasPathClientSelectsPlatformKAOsOnly()        // uri https://h/kas → same
func testOwnerClientSelectsOwnKAOOnly()                // uri https://h/owner-kas/v1/routes/R → only that KAO
func testTrailingSlashesIgnored()                      // KAO https://h/kas/ and https://h/owner-kas/v1/routes/R/ match their clients
func testPathIsCaseSensitiveHostIsNot()                // https://H/kas matches the platform client; https://h/OWNER-KAS/v1/routes/R doesn't match the owner client
func testOtherPrefixDoesNotMatchPathlessClient()       // https://h/api/kas does not match uri https://h (the spec's stated cost)
```

- [ ] **Step 2: Run:** `swift test --filter KASRewrapMatchingTests`. Expected: the owner-KAO and prefix tests FAIL,
  because today's matching is host-only.

- [ ] **Step 3: Implement.** In `matchesKasURL`, after the scheme, host and port checks, compare `normalizedPath(_:)`
  of both URLs: trim trailing `/`, then map `/kas` to `""`.

- [ ] **Step 4: Run:** `swift test --filter "KASRewrapMatchingTests|KASRewrap|KASBulkRewrap"`. Expected: PASS, and
  the existing matching tests stay green.

- [ ] **Step 5: Commit** `fix(kas): match key access objects by path too (#66)`.

---

### Task 3: Verify a received Rewrap (phone)

**Files:**
- Create: `OpenTDFKit/TDF/TDFKASRequest.swift`
- Modify: `OpenTDFKit/TDF/TDFKAS.swift` (new `TDFKASError` cases)
- Modify: `OpenTDFKit/KASRewrapClient.swift` (internal `Data.init?(base64URLEncoded:)` beside `base64URLEncodedString`)
- Test: `OpenTDFKitTests/TDFKASRequestTests.swift`

**Interfaces:**
- Consumes: `TDFKAS.requestTokenDigest` (Task 1).
- Produces:
  - `TDFKAS.verifyRewrapRequest(body: Data, signingPublicKey: P256.Signing.PublicKey) throws -> TDFKAS.RewrapRequest`.
  - `TDFKAS.RewrapRequest`, with the fields from the spec: `requestToken`, `requestTokenDigest`, `issuedAt`,
    `expiresAt`, `clientPublicKey`, `policies`, `extensions`.
  - `TDFKAS.RewrapRequest.Policy` holds `policyId`, `policyBase64` and `keyAccessObjects: [KeyAccessEntry]`, where
    `KeyAccessEntry` is a struct `{ id: String; keyAccessObject: TDFKeyAccessObject }` (a struct rather than a tuple,
    so it is `Sendable`).
  - New `TDFKASError` cases: `requestTooLarge`, `malformedRewrapRequest(String)` (the string names the field, never its
    value), `unsupportedRequestAlgorithm(String)`, `requestSignatureInvalid`.

- [ ] **Step 1: Write the failing tests.** A test helper `signedRequest(requestBody: [String: Any], key:, header:
  ["alg": "ES256"], exp:, iat:) -> Data` builds `{"signed_request_token": JWT}` independently of the library. It uses
  JSONSerialization, base64url and `key.signature(for:).rawRepresentation`.

```swift
func testValidRequestVerifies()                // fields equal what was sent: exp, iat, digest == requestTokenDigest(token),
                                               // clientPublicKey, policyId, policyBase64, KAO id and decoded KAO, extensions["arkavo"]
func testExtensionRoundTripsUnicodeAndSlashes() // extension {"v":1,"note":"é/ü"} → JSONSerialization of extensions["arkavo"] equals the input object
func testOtherSigningKeyRefused()              // .requestSignatureInvalid
func testPayloadChangedAfterSigningRefused()   // swap the payload segment for a re-encoded one with exp+1 → .requestSignatureInvalid
func testSignatureChangedRefused()             // flip one signature byte → .requestSignatureInvalid
func testAlgNoneAndHS256Refused()              // → .unsupportedRequestAlgorithm("none") / ("HS256")
func testOversizedBodyRefused()                // 65,537 bytes → .requestTooLarge
func testMalformedShapesRefused()              // non-PEM clientPublicKey; requests []; policy.body not base64;
                                               // KAO missing wrappedKey; no signed_request_token → .malformedRewrapRequest(_)
func testExpiredTokenStillParses()             // exp = now - 3600 → verifies, expiresAt returned
func testStandardMembersAreNotExtensions()     // requestBody with algorithm and keyAccess → extensions is empty for them
```

- [ ] **Step 2: Run:** `swift test --filter TDFKASRequestTests`. Expected: compile failure, `has no member 'verifyRewrapRequest'`.

- [ ] **Step 3: Implement** in the spec's check order (§2, checks 1–7). The claims' `requestBody` is a JSON string.
  Parse it with `JSONSerialization` to collect the extensions as raw member JSON, and decode the standard parts with
  `JSONDecoder` into private Codable types. Re-encode each extension with
  `JSONSerialization.data(withJSONObject:options: [.fragmentsAllowed])`.

- [ ] **Step 4: Run:** `swift test --filter TDFKASRequestTests`. Expected: PASS.

- [ ] **Step 5: Commit** `feat(kas): verify a received Rewrap on the owner KAS (#66)`.

---

### Task 4: Build a Rewrap response (phone)

**Files:**
- Create: `OpenTDFKit/TDF/TDFKASResponse.swift`
- Test: `OpenTDFKitTests/TDFKASResponseTests.swift`

**Interfaces:**
- Produces:
  - `TDFKAS.rewrapResponseBody(sessionPublicKey: P256.KeyAgreement.PublicKey?, responses: [TDFKAS.PolicyResponse]) throws -> Data`.
  - `TDFKAS.PolicyResponse(policyId: String, results: [TDFKAS.KeyAccessResult])`.
  - `TDFKAS.KeyAccessResult(keyAccessObjectId: String, status: TDFKAS.ResultStatus, kasWrappedKey: Data?, error: String?, metadata: [String: KASRewrapClient.RewrapMetadataValue])`.
  - `TDFKAS.ResultStatus { case permit, fail }`.
  - A new `TDFKASError` case, `invalidResult(String)`.

  The spec calls the result type `Result`. It is named `KeyAccessResult` here, so it doesn't shadow `Swift.Result`.

- [ ] **Step 1: Write the failing tests.**

```swift
func testPermitAndFailShape()          // JSONSerialization of the output: sessionPublicKey is PEM; status "permit"/"fail";
                                       // kasWrappedKey std base64; fail result has no kasWrappedKey key; error present only when set
func testMetadataAllValueTypes()       // string, number, bool, array, object, null → decoded back equal (via JSONDecoder of RewrapMetadataValue)
func testDenyWithoutSessionKey()       // sessionPublicKey nil → member absent
func testInvalidCombinationsRefused()  // permit without key; fail with key → .invalidResult(_)
```

- [ ] **Step 2: Run:** `swift test --filter TDFKASResponseTests`. Expected: compile failure.
- [ ] **Step 3: Implement.** Use private `Encodable` structs and `JSONEncoder` with `.sortedKeys`, and omit nil fields.
- [ ] **Step 4: Run:** `swift test --filter TDFKASResponseTests`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(kas): build a Rewrap response on the owner KAS (#66)`.

---

### Task 5: `prepareRewrap` (client)

**Files:**
- Create: `OpenTDFKit/KASRewrapPending.swift`
- Modify: `OpenTDFKit/KASRewrapClient.swift`:
  - `createSignedJWT` gains an `expiresAt: Date` parameter. The default call sites pass `now + 60`.
  - `StandardUnsignedRewrapRequest` encoding is reused.
  - New `KASRewrapError` cases `invalidRewrapOptions(String)`, `pendingWithoutLocation` and `unsafeLocation(String)`,
    with descriptions.
- Test: `OpenTDFKitTests/KASRewrapPendingTests.swift`

**Interfaces:**
- Consumes: `TDFKAS.requestTokenDigest` (Task 1) and `TDFKAS.verifyRewrapRequest` (Task 3, in the tests).
- Produces:
  - `KASRewrapClient.RewrapOptions(expiresAt: Date? = nil, requestBodyExtension: RequestBodyExtension? = nil)`.
  - `KASRewrapClient.RequestBodyExtension(name: String, json: Data)`.
  - `KASRewrapClient.PreparedRewrap { body: Data; requestToken: String; requestTokenDigest: Data; expiresAt: Date; keyAccessObjects: [TDFKeyAccessObject] }`.
    The last field is internal: the KAOs sent, in `kao-<i>` order, for Task 6's `sid`.
  - `func prepareRewrap(manifest: TDFManifest, clientPrivateKey: P256.KeyAgreement.PrivateKey, options: RewrapOptions = .init()) throws -> PreparedRewrap`.

- [ ] **Step 1: Write the failing tests.** The client is built with a fixed `signingKey`. Verification uses
  `TDFKAS.verifyRewrapRequest` with `signingKey.publicKey`.

```swift
func testPreparedRequestVerifiesOnThePhone()     // verifies; requestTokenDigest equal on both sides; expiresAt equal (to the second)
func testPolicyForwardedVerbatim()               // phone policyBase64 == manifest.encryptionInformation.policy
func testSignedWithInitSigningKeyNotClientKey()  // verify with clientPrivateKey's signing form → .requestSignatureInvalid
func testDefaultExpIsSixtySeconds()              // expiresAt - issuedAt == 60
func testCallerExp()                             // expiresAt = now + 900 → token exp equals it
func testPastExpRefused()                        // → KASRewrapError.invalidRewrapOptions
func testExtensionCoveredBySignature()           // phone extensions["arkavo"] == the input JSON (object equality)
func testExtensionNameCollisionRefused()         // each standard name → .invalidRewrapOptions
func testExtensionMustBeJSON()                   // json "not json" → .invalidRewrapOptions
func testOnlyThisKASKAOsSent()                   // a manifest with a platform KAO and an owner KAO; the owner client sends one KAO
```

- [ ] **Step 2: Run:** `swift test --filter KASRewrapPendingTests`. Expected: compile failure.
- [ ] **Step 3: Implement.** Encode the request as today, then add the extension with `JSONSerialization` and
  re-serialize. Sign with `self.signingKey` and `expiresAt`. Compute the digest with `TDFKAS.requestTokenDigest`.
- [ ] **Step 4: Run:** `swift test --filter "KASRewrapPendingTests|KASRewrap"`. Expected: PASS, and the existing
  rewrap tests stay green.
- [ ] **Step 5: Commit** `feat(kas): prepare a signed Rewrap with caller exp and extension (#66)`.

---

### Task 6: `submitRewrap`, `pollRewrap`, `rewrap` (client)

**Files:**
- Modify: `OpenTDFKit/KASRewrapPending.swift`
- Modify: `OpenTDFKit/KASRewrapClient.swift`. It gains internal stored `sleeper: @Sendable (TimeInterval) async throws
  -> Void` (default `Task.sleep`) and `now: @Sendable () -> Date` (default `Date.init`), set through an internal
  initializer that the public initializers call.
- Test: `OpenTDFKitTests/KASRewrapPendingTests.swift`

**Interfaces:**
- Consumes: Task 5's `PreparedRewrap`, and `TDFKAS.unwrap`.
- Produces: the spec's `PendingRewrap`, `RewrapSubmission`, `RewrapPollOutcome`, `RewrapAnswer` (with its
  `Result` → named `RewrapAnswer.KeyAccessResult`), `RewrapAnswer.share(for:clientPrivateKey:) throws -> TDFKeyShare`
  and `RewrapOutcome`, plus:
  - `func submitRewrap(_ prepared: PreparedRewrap) async throws -> RewrapSubmission`
  - `func pollRewrap(_ pending: PendingRewrap, until deadline: Date) async throws -> RewrapPollOutcome`
  - `func rewrap(manifest:clientPrivateKey:options:deadline:) async throws -> RewrapOutcome`

- [ ] **Step 1: Write the failing tests.** They use an actor `ScriptedTransport: KASRewrapTransport`, which replays
  `(status, headers, body)` in order and records each request's method, URL, headers and body. They also use a
  recording sleeper and a controllable clock.

```swift
func testImmediate200IsAnswered()             // .answered; results keep fail entries; no throw on a deny
func testDenyOnlyAnswerParses()               // 200 with only fail results and no sessionPublicKey → .answered, sessionPublicKey nil
func testPendingThenAnswered()                // POST 202 (Location /owner-kas/v1/requests/abc, Retry-After 3), GET 202 (Retry-After 5), GET 200
                                              // → sleeps [3, 5]; GETs to https://h/owner-kas/v1/requests/abc carry the same bearer and no body
func testGoneIsExpired()                      // GET 410 → .expired
func test404AfterExpIsExpired()               // clock past expiresAt → .expired
func test404BeforeExpThrows()                 // → KASRewrapError.httpError(404, _)
func testDeadlineReachedReturnsHandleAndResumes() // deadline before the next wait ends → .deadlineReached(pending); pollRewrap(pending) again → .answered
func testRetryAfterIsClamped()                // "0" → 1; "-5" → default 2; "999" → 60; HTTP-date → 2; missing → 2; never past the deadline
func testLocationOriginRules()                // relative ok; absolute same origin ok; https://evil.example/x, //evil.example/x,
                                              // http://h/x, https://h:8443/x → .unsafeLocation, with no request sent to them
func testPendingWithoutLocationThrows()       // → .pendingWithoutLocation
func testResubmitSendsIdenticalBytes()        // submitRewrap(prepared) twice → both recorded bodies equal
func testRewrapUnwrapsPermittedShares()       // permit with a key sealed by TDFKAS.rewrap → shares contain the DEK with the KAO's sid
func testAnswerShareRefusesFailResult()       // share(for: failResult) throws
```

- [ ] **Step 2: Run:** `swift test --filter KASRewrapPendingTests`. Expected: compile failure.
- [ ] **Step 3: Implement** as in the spec's `submitRewrap` and `pollRewrap` lists. Parse a 200 with the existing
  `RewrapResponse` decoder and map it to `RewrapAnswer`; `sid` comes from `prepared.keyAccessObjects[i]` for id
  `kao-<i>`. `PendingRewrap` carries the internal `keyAccessObjects` too, for `sid` after a resume.
- [ ] **Step 4: Run:** `swift test --filter KASRewrapPendingTests`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(kas): poll a KAS that answers later; return full Rewrap results (#66)`.

---

### Task 7: End to end, docs, PR

**Files:**
- Test: `OpenTDFKitTests/OwnerKASEndToEndTests.swift`
- Modify: `CLAUDE.md`, `MIGRATION_GUIDE.md`

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Write the end-to-end tests.** An actor `FakeOwnerKAS: KASRewrapTransport` plays the relay:
  - On the POST it returns 202 + `Location`.
  - On the first GET it returns 202.
  - On the second GET it plays the phone: `verifyRewrapRequest(body, cnf key)`, then checks
    `keyAccessObjectDigest(kao) == the digest recorded at encrypt time`, then `TDFKAS.rewrap`, then
    `rewrapResponseBody`, with `metadata["arkavo.decision"] = .string("…")`.

```swift
func testOwnerAllowEndToEnd()   // TDFEncryptor(.ecP256, url https://h/owner-kas/v1/routes/R) → client.rewrap → share == DEK,
                                // payload decrypts, metadata["arkavo.decision"] intact, digests equal on both sides
func testOwnerDenyEndToEnd()    // phone answers fail "ACCESS_DENIED" with metadata → .answered with one fail result, no shares, no throw
```

- [ ] **Step 2: Run:** `swift test --filter OwnerKASEndToEndTests`. Expected: PASS. Everything they use exists, so
  a failure is a bug in Tasks 1–6.

- [ ] **Step 3: Docs.**
  - `CLAUDE.md`:
    - in the TDFKAS entry, add the phone functions and the digests;
    - in the KASRewrapClient entry, add prepare/submit/poll/rewrap, path-aware matching and the 404 rule.
  - `MIGRATION_GUIDE.md` v5.2.0:
    - the new API;
    - path-aware matching and its one cost (a KAS mounted under another prefix needs that prefix in its `uri`);
    - the new `KASRewrapError` cases for exhaustive switches.

- [ ] **Step 4: Full suite:** `swift build && swift test`, then `cd scripts/interop/ec-wrapped && go test ./...`.
  Expected: all pass, with the same skipped count as before (15).

- [ ] **Step 5: Commit** `test(kas): owner-KAS end to end; docs (#66)`, push, then retitle PR #68 and update its
  description for the revised #66.
