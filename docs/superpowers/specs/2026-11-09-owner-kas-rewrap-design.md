# Owner KAS: Rewrap on the phone, and a client for a KAS that answers later

Date: 2026-11-09
Status: Design, builder-checked, pending approval
Issue: [#66](https://github.com/arkavo-org/OpenTDFKit/issues/66), as revised on 2026-11-08 (items 2–8).
Extends: `2026-11-08-kas-side-ec-rewrap-design.md` (items 1 and 9, in PR #68). Same PR.
Consumer contract: arkavo-ios `docs/superpowers/specs/2026-11-08-owner-kas-design.md` §4.1–§4.6, at `3fea003`
(which adds the relay's wire details as arkavo-rs built them; the issue links `7d11e02`).

## Why

The owner decided that "OpenTDFKit can hit either KAS (platform KAS or owner KAS)". The owner's iPhone is a KAS.
Its URL is `https://platform.arkavo.net/owner-kas/v1/routes/<route_id>`, where a relay (arkavo-rs) holds requests
until the phone answers. A receiver calls that URL with `KASRewrapClient`, exactly as it calls the platform KAS. Two
things differ:
- **The answer can take up to 15 minutes.** The relay answers the Rewrap POST with `202`, a relative `Location` and
  `Retry-After`. Polls of `Location` get `202` while pending, `200` with the Rewrap response body once answered, and
  `410` after the deadline.
- **The phone is the KAS.** It verifies the signed request and builds the Rewrap response itself.

The previous design's "exposed non-HTTP unwrap" goal is superseded. `TDFKAS.unwrap` stays: the receiver calls it
after verifying the owner's signed decision.

## Goals

KAS side (the owner's phone; pure, keys as values, no network or storage):
1. **Done in PR #68:** `TDFKAS.rewrap`, the `ec-wrapped` rewrap to the request's `clientPublicKey`.
2. **Parse and verify a received Rewrap.** Verify the ES256 signed request token under a given P-256 key. Return its
   `exp`, the request-token digest, `clientPublicKey`, the policies with their key access objects, and any extension
   members.
3. **Build a Rewrap response body**, with caller `metadata`, for ALLOW and DENY alike.

Client side (`KASRewrapClient`, the receiver):
4. **Pending answers:** follow `202` + `Location`, honoring `Retry-After`, until `200`, `410` or the caller's
   deadline. Expired (`410`) is reported distinctly from a denial and from the caller's deadline.
5. **Request-token lifetime:** the caller sets the signed request token's `exp`.
6. **Path-aware matching:** a client selects only key access objects whose URL is its KAS, path included.
7. **One extension member** in `requestBody`, covered by the request signature.
8. **Return what the KAS sent:** each result's status, `error`, `metadata` and `kasWrappedKey`, the
   `sessionPublicKey` and the request-token digest, with the unwrapped share for each permitted result. A denial is a
   result, not a thrown error, so the app can verify the owner's signed DENY.

## Non-goals

- The relay, the owner-KAS token (CWT) and the owner's signed decision record. Those belong to arkavo-rs, authnz-rs
  and arkavo-ios. OpenTDFKit carries `metadata` opaquely.
- Bulk rewrap (`rewrapAndUnwrapTDFs`) through an owner KAS, and multiple key access objects across KASs (#67).
- The go SDK's legacy single-KAO request shape (top-level `keyAccess`, `policy`, `algorithm`) on the phone side. The
  only client of an owner KAS is OpenTDFKit, which sends `requests`.
- DPoP.
- Changing the existing `rewrapTDF`, `rewrapAndUnwrapTDF`, `rewrapAndUnwrapTDFShares` or the bulk API, apart from
  path-aware matching, which applies to all of them.

## Anti-goals

It fails even if it works if:
- the bearer token is ever sent to an origin other than the configured KAS's (a hostile `Location`);
- a 202, an expiry or the caller's deadline is ever reported as the owner's denial;
- the digest the client reports differs from the digest the phone computes for the same request, because the owner's
  decision record binds to it;
- an existing platform-KAS caller stops matching its key access objects, except in the one case listed under
  "Calls made".

## Reference facts

- The relay (arkavo-ios design §4.2) does the following:
  - It accepts `POST <owner KAS URL>/kas.AccessService/Rewrap` (Connect JSON, at most 64 KiB) and answers
    `202 { request_id, status: "pending", deadline }`, with `Location: /owner-kas/v1/requests/{request_id}` (a path)
    and `Retry-After`.
  - It answers `GET Location` (same bearer) with `202` + `Retry-After` while pending, `200` + the stored Rewrap
    response body once answered, and `410 { status: "expired" }` after the deadline. A poll after the request is
    deleted (the deadline plus 10 minutes) gets `404`, which the receiver treats as expired. A poll with any other
    token also gets `404`, so a request's existence isn't revealed.
  - It checks the signed request token's ES256 signature under the bearer's `cnf` key, and that its `exp` is no later
    than the token's.
  - Sending the same body again returns the same `request_id`.
- The platform KAS verifies the signed request token only under a DPoP key (`requireVerification := dpopJWK != nil`,
  `service/kas/access/rewrap.go` at `ca178b05`). Without DPoP it does not care which key signed.
- `OpenTDFConfiguration.forKasConnect(base)` sets `kas.uri = base` and the Rewrap URL to
  `base/kas.AccessService/Rewrap`. `validateKasURL` checks only scheme, host and IP, so a base with a path is fine.
- Platform discovery reports `kas.uri: "https://platform.arkavo.net"`, with no path (`KASDiscoveryTests.swift:27`).
  Key access objects usually carry `…/kas`.
- `KASRewrapClient` already takes a `signingKey` at init. Today only the NanoTDF path uses it; `rewrapTDF` signs with
  the client's ECDH key (`KASRewrapClient.swift:587`). The JWT `exp` is fixed at `iat + 60` (line 1244).
- CryptoKit's ECDSA signatures are randomized, so re-signing the same claims never reproduces the same bytes.

## Design

### Request-token digest (shared)

`TDFKAS.requestTokenDigest(_ token: String) -> Data` is SHA-256 of the compact JWT string's UTF-8 bytes (the
`signed_request_token` value, not the HTTP body). It is arkavo-ios's `request_digest`. The phone side and the client
side both call this one function.

### Key access object digest and key fingerprint (shared)

The owner's phone must check that a forwarded key access object is the one in the file. The client re-encodes it when
it sends it: it drops `schemaVersion`, and its key order is not the manifest's. So no digest of JSON bytes taken at
protect time can equal one taken at service time. OpenTDFKit therefore defines the digests (the owner's decision,
2026-11-09), and arkavo-ios calls the same functions at protect time and at service time:

- `TDFKAS.keyAccessObjectDigest(_ kao: TDFKeyAccessObject) -> Data` is SHA-256 over:
  - the domain tag `OpenTDFKit/kao-digest/v1`;
  - then, in this fixed order, each of `type` (raw value), `url`, `protocol`, `wrappedKey`, `policyBinding.alg`
    (empty means `HS256`), `policyBinding.hash`, `kid`, `sid`, `encryptedMetadata` and `ephemeralPublicKey`.

  Each field is written as one presence byte (`0` absent, `1` present), then, if present, a 4-byte big-endian length
  and its UTF-8 bytes. `schemaVersion` is left out. Every field the client forwards is in it, so the digest of the
  manifest's object equals the digest of the forwarded one.
- `TDFKAS.publicKeyFingerprint(_ key: P256.KeyAgreement.PublicKey) -> Data` is SHA-256 of the 65-byte uncompressed
  SEC1 point (`04 ‖ X ‖ Y`, CryptoKit's `x963Representation`). It is for arkavo-ios's `response_key_fp` (of
  `clientPublicKey`) and `session_key_fp` (of `sessionPublicKey`). It doesn't depend on how the PEM was written.

### 2. Verify a received Rewrap (phone)

```swift
extension TDFKAS {
    public static func verifyRewrapRequest(
        body: Data,                                   // the HTTP body: {"signed_request_token": "<JWT>"}
        signingPublicKey: P256.Signing.PublicKey,     // the bearer token's cnf key
    ) throws -> RewrapRequest

    public struct RewrapRequest: Sendable {
        public let requestToken: String
        public let requestTokenDigest: Data
        public let issuedAt: Date?
        public let expiresAt: Date
        public let clientPublicKey: P256.KeyAgreement.PublicKey
        public let policies: [Policy]
        public let extensions: [String: Data]          // top-level requestBody members, raw JSON, by name

        public struct Policy: Sendable {
            public let policyId: String
            public let policyBase64: String            // the policy body, as sent; what rewrap's binding needs
            public let keyAccessObjects: [(id: String, keyAccessObject: TDFKeyAccessObject)]
        }
    }
}
```

**Checks, in order** (each failure throws a `TDFKASError` naming the check, never the content):
1. The body is at most 64 KiB.
2. It is a JSON object with a string `signed_request_token`.
3. The token has three base64url parts. The header is a JSON object with `alg == "ES256"`; anything else, including
   `none`, is refused.
4. The signature is 64 raw bytes (r ‖ s) and verifies under `signingPublicKey` over `header.payload`, exactly as
   received.
5. The claims hold `requestBody` (a string), a numeric `exp` and an optional numeric `iat`.
6. `requestBody` parses as a JSON object with a PEM P-256 `clientPublicKey` and a non-empty `requests` array. Each
   entry has `policy.id`, a `policy.body` that decodes as base64, and a non-empty `keyAccessObjects` array of
   `{keyAccessObjectId, keyAccessObject}`. Each `keyAccessObject` decodes as `TDFKeyAccessObject`.
7. `extensions` holds every top-level member other than `clientPublicKey`, `requests`, `keyAccess`, `policy`,
   `algorithm` and `schemaVersion`, as that member's JSON bytes.

`exp` is **returned, not enforced**. The phone must be able to parse an expired request so it can send a signed DENY
`REQUEST_EXPIRED`. It applies its own clock and skew.

### 3. Build a Rewrap response (phone)

```swift
extension TDFKAS {
    public static func rewrapResponseBody(
        sessionPublicKey: P256.KeyAgreement.PublicKey?,   // nil when nothing was permitted
        responses: [PolicyResponse],
    ) throws -> Data

    public struct PolicyResponse: Sendable { public let policyId: String; public let results: [Result] }
    public struct Result: Sendable {
        public let keyAccessObjectId: String
        public let status: Status                          // .permit | .fail
        public let kasWrappedKey: Data?                    // required for .permit, absent for .fail
        public let error: String?
        public let metadata: [String: KASRewrapClient.RewrapMetadataValue]
    }
}
```

The output is `{"sessionPublicKey": <PEM>, "responses": [{"policyId", "results": [{"keyAccessObjectId", "status",
"kasWrappedKey", "error", "metadata"}]}]}`: `status` is `permit` or `fail`, `kasWrappedKey` is standard base64, and
absent fields are omitted. A `.permit` without a key, or a `.fail` with one, throws. `metadata` uses the client's
existing public value type, so what the phone writes round-trips through what the client parses.

### 4, 5, 7, 8. Client: prepare, submit, poll

The new API leaves the existing methods unchanged. It signs with the client's `signingKey`, the one given at init,
which for an owner KAS is the bearer token's `cnf` key, not the client's ECDH key.

```swift
extension KASRewrapClient {
    public struct RewrapOptions: Sendable {
        public var expiresAt: Date?                     // the token's exp; default now + 60 s
        public var requestBodyExtension: RequestBodyExtension?
    }
    public struct RequestBodyExtension: Sendable { public let name: String; public let json: Data }

    /// The signed request, as bytes. Submitting the same value again sends identical bytes.
    public struct PreparedRewrap: Sendable {
        public let body: Data
        public let requestToken: String
        public let requestTokenDigest: Data
        public let expiresAt: Date
    }

    public func prepareRewrap(manifest: TDFManifest, clientPrivateKey: P256.KeyAgreement.PrivateKey,
                              options: RewrapOptions = .init()) throws -> PreparedRewrap
    public func submitRewrap(_ prepared: PreparedRewrap) async throws -> RewrapSubmission  // .answered | .pending
    public func pollRewrap(_ pending: PendingRewrap, until deadline: Date) async throws -> RewrapPollOutcome
    public func rewrap(manifest: TDFManifest, clientPrivateKey: P256.KeyAgreement.PrivateKey,
                       options: RewrapOptions = .init(), deadline: Date? = nil) async throws -> RewrapOutcome

    public struct PendingRewrap: Sendable { public let location: URL; public let retryAfter: TimeInterval;
                                            public let requestTokenDigest: Data; public let expiresAt: Date }
    public enum RewrapSubmission: Sendable { case answered(RewrapAnswer), pending(PendingRewrap) }
    public enum RewrapPollOutcome: Sendable { case answered(RewrapAnswer), expired, deadlineReached(PendingRewrap) }

    public struct RewrapAnswer: Sendable {
        public let requestTokenDigest: Data
        public let sessionPublicKey: P256.KeyAgreement.PublicKey?
        public let results: [Result]
        public struct Result: Sendable {
            public let keyAccessObjectId: String
            public let sid: String?                    // from this client's key access object kao-<i>
            public let status: String                  // "permit", "fail", or whatever the KAS sent
            public let kasWrappedKey: Data?
            public let error: String?
            public let metadata: [String: RewrapMetadataValue]
        }
        /// Unwraps one permitted result with TDFKAS.unwrap (TDF session salt).
        public func share(for result: Result, clientPrivateKey: P256.KeyAgreement.PrivateKey) throws -> TDFKeyShare
    }
    /// `rewrap`'s outcome: answered carries the shares of every permitted result, already unwrapped.
    public enum RewrapOutcome: Sendable {
        case answered(RewrapAnswer, shares: [TDFKeyShare]), expired, deadlineReached(PendingRewrap)
    }
}
```

**`prepareRewrap`**
- Builds today's `requestBody` (`clientPublicKey`, one `requests` entry with the manifest's policy and this KAS's key
  access objects, ids `kao-<i>`). `policy.body` is the manifest's `encryptionInformation.policy` string, unchanged, as
  `standardPolicyRequest` already sends it. arkavo-ios digests the decoded policy, and the binding is over that string.
- Adds the extension as one top-level member. Its name may not be one of the standard names listed under check 7.
  Its JSON must parse. It is covered by the signature, because it is inside `requestBody`.
- Signs the claims `{requestBody, iat: now, exp}`. `exp` must be in the future, otherwise it throws.
- Computes the digest with `TDFKAS.requestTokenDigest`.

**`submitRewrap`**
- POSTs `prepared.body`, as today's Rewrap does: bearer, Connect headers, 30 s timeout, through the
  `KASRewrapTransport`.
- `200` gives `.answered`. Every result is kept. A denial is a result, not a throw.
- `202` gives `.pending`:
  - `Location` is required and is resolved against the Rewrap URL.
  - The resolved URL must have the Rewrap URL's scheme, host and effective port, otherwise it throws: the bearer
    goes there.
  - `Retry-After` is parsed as delta-seconds. Anything else, including an HTTP-date, gives the default of 2 s. It is
    clamped to 1–60 s.
- Other statuses throw as today.
- It never retries on its own. Resending the same `PreparedRewrap` after a network failure is safe: the relay
  returns the same `request_id`.

**`pollRewrap`**
- Waits `retryAfter`, then GETs `location` with the same bearer, no body, a 30 s timeout and the same transport.
- `202` repeats, with the new `Retry-After`. `200` gives `.answered`. `410` gives `.expired`.
- `404` at or after the handle's `expiresAt` (the token's `exp`, which is the relay's deadline) gives `.expired`: the
  relay deletes a request after its deadline. A `404` before then throws `.httpError(404)`, because it means the
  request is unknown to the relay (a wrong token, or lost state), which the app shows as unavailable, never as a
  denial.
- Other statuses throw.
- It never sleeps past `deadline`. If the next wait would end after it, it sleeps only until `deadline`, polls once
  more, and returns `.deadlineReached(pending)` with the current handle if that poll is still pending. If the app
  wakes after `deadline` (suspended mid-wait), it returns at once without polling. Each poll's timeout is clamped to
  the time left (1–30 s). *(Revised after the final review, 2026-11-09.)*
- It first checks that the handle's `location` is on this client's KAS origin. A handle from another client throws
  `.unsafeLocation`, and nothing is sent.
- A `403` on submit or poll is `.httpError(403, …)`, never `.accessDenied`: on this path a denial is always a
  result.
- The sleep goes through an internal, injectable sleeper, so tests run instantly.

**`rewrap`** runs prepare, submit and poll, with `deadline` defaulting to `expiresAt`, and unwraps the permitted
shares. Reaching that default deadline is `.expired`, because the KAS's own deadline has passed.
- On task cancellation it throws, and the pending handle is lost. A receiver that must survive backgrounding calls the
  three steps itself and keeps the `PendingRewrap`.

**New `KASRewrapError` cases:** `pendingWithoutLocation`, `unsafeLocation(String)`, `invalidRewrapOptions(String)`.
They are listed in the migration guide, because an exhaustive `switch` over `KASRewrapError` needs them.

### 6. Path-aware matching

`matchesKasURL` (used by `keyAccessObjects(in:)` and therefore every rewrap path) compares:
- scheme and host, case-insensitive;
- the effective port;
- the **normalized path**, case-sensitive. Normalizing trims trailing `/`, and `/kas` counts as empty, because a
  platform KAS lives at `<platform>/kas` for REST and at the root for Connect, and discovery reports it without a path.

Outcomes:

| Configured KAS (`kas.uri`) | KAO `https://h/kas` | KAO `https://h` | KAO `https://h/owner-kas/v1/routes/R` |
| --- | --- | --- | --- |
| `https://h` (platform, from discovery) | match | match | no |
| `https://h/kas` | match | match | no |
| `https://h/owner-kas/v1/routes/R` | no | no | match |

## Tests

- **Verify (phone):**
  - A request from `prepareRewrap` verifies, and its fields equal what was sent, including the extension, byte for
    byte.
  - Each of these is refused: another signing key; a changed payload after signing; a changed signature; `alg` `none`
    or `HS256`; a body over 64 KiB; a non-PEM `clientPublicKey`; an empty `requests`; an invalid KAO.
  - An expired token still parses and returns its `exp`.
- **Digests:**
  - The client's `PreparedRewrap.requestTokenDigest` equals the phone's `RewrapRequest.requestTokenDigest` for the same
    request.
  - `keyAccessObjectDigest` of the manifest's key access object equals that of the object the phone parses from the
    request. That holds for one written by `TDFEncryptor`, with `schemaVersion`, and for one with `sid` and
    `encryptedMetadata`. Changing any one included field changes the digest; changing `schemaVersion` does not.
  - `publicKeyFingerprint` is the same for a key parsed from PEM with LF or CRLF line endings, and from its SEC1 bytes.
  - The phone's `policyBase64` is the manifest's `encryptionInformation.policy` string, byte for byte.
- **Response:** `rewrapResponseBody` output parsed by the client gives the same results. That covers a permit with
  metadata of every value type, and a fail with an error code and metadata but no key. An invalid
  permit/fail-and-key combination is refused.
- **Polling:** each through a scripted fake transport and a recording sleeper.
  - 202 → 202 → 200 honors each `Retry-After`.
  - The deadline returns `.deadlineReached` with a handle, and polling resumes from that handle.
  - 410 gives `.expired`. A 404 after `expiresAt` gives `.expired`; a 404 before it throws.
  - A `Location` on another host, port or scheme is refused before any request is sent to it.
  - A 202 with no `Location` is refused.
  - An HTTP-date or a missing `Retry-After` uses the default, and values are clamped.
  - Submitting the same `PreparedRewrap` twice sends identical bytes.
- **Options:** the token's `exp` equals `expiresAt`; a past `expiresAt` is refused; an extension named `requests`
  (or any other standard name) is refused; the request is signed with the init `signingKey`, verified with its
  public key.
- **Matching:** the table above. A platform client and an owner client on one host each select only their own KAO.
  Existing matching tests stay green.
- **End to end:** the real client against a fake transport that plays relay and phone in-process. The phone side runs
  `verifyRewrapRequest`, then `TDFKAS.rewrap`, then `rewrapResponseBody`.
  - An ALLOW gives a share equal to the DEK, with the metadata intact.
  - A DENY gives a fail result with its metadata and nothing thrown.

## Left to the builder

- File layout. A new `OpenTDFKit/KASRewrapPending.swift` for the client half, and the phone half in `TDFKAS.swift`
  or a sibling file, is the suggestion.
- Error-case names beyond those listed.
- README / CLAUDE.md / migration-guide wording.

## The owner's decisions

- OpenTDFKit defines the key access object digest and the public-key fingerprint, and arkavo-ios uses them, rather
  than comparing JSON bytes (2026-11-09).

## Calls made in this document (open to correction)

1. **Path-aware matching is stricter than the issue's wording.** The issue says to match on path "when the configured
   KAS URL has a path". Discovery gives the platform client a path-less `uri`, so under that rule a platform client
   would also claim owner KAOs, which fails the issue's own "each client selects only its own KAO" test. The rule here
   always compares the normalized path, with `/kas` the same as no path.
   **Cost:** a KAS mounted at another prefix (for example `https://h/api/kas`) no longer matches a path-less client.
   The configured `uri` must then carry that prefix.
2. **Resending is safe by keeping the signed bytes, not by re-signing.** CryptoKit's randomized ECDSA can't reproduce
   a body, so `prepareRewrap` returns the bytes. `submitRewrap` never retries on its own; the app resends the same
   `PreparedRewrap`.
3. **New methods, old ones unchanged.** The new client path signs with the init `signingKey`. The existing
   `rewrapTDF` keeps signing with the client key and keeps throwing on a denial, so no current caller changes
   behavior.
4. **`exp` is returned, not enforced, on the phone,** so an expired request can still get a signed `REQUEST_EXPIRED`.
5. **`Retry-After`:** delta-seconds only, default 2 s, clamped to 1–60 s, and never past the deadline.
8. **A poll `404` is expired only at or after the token's `exp`.** Before then the client can't tell a deleted
   request from a wrong token, so it throws and the app shows the owner as unavailable.
6. **Only a same-origin `Location` is followed.**
7. **Bodies over 64 KiB are refused** on the phone side, the relay's own limit.
