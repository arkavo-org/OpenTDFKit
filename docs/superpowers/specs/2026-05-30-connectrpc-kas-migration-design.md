# ConnectRPC + Well-Known Discovery for the KAS Client (CWT support)

Date: 2026-05-30
Status: Approved design — pending implementation plan
Ports: opentdf-rs PR #86 (`feat(kas)!: migrate to ConnectRPC with well-known discovery`)

## Goal

Migrate the OpenTDFKit native KAS client transport from REST `/kas/v2/*` to
ConnectRPC unary-JSON at `/kas.AccessService/*`, driven by
`/.well-known/opentdf-configuration` discovery. Keep legacy REST reachable as a
fallback. Add SSRF-validated endpoint resolution, no-redirect HTTP, Connect
error-envelope parsing, and opaque bearer-token passthrough (a JWT **or** a
base64url-encoded CWT — the platform decides how to validate it).

This is a faithful port of the Rust change, adapted to Swift/URLSession idioms,
with two corrections validated against the Go `opentdf/platform` SDK (the
golden reference).

## Scope

Full parity with Rust #86. Breaking API change accepted (mirrors Rust's
breaking `KasClient::new`). CLI defaults to Connect with REST fallback.

## Reference facts (verified)

- Platform well-known doc advertises both Connect and REST URLs, plus
  `idp.access_token_format: "application/cwt"`. (`kas_discovery.rs` test fixture,
  captured from `platform.arkavo.net` 2026-05-28.)
- Go `service/kas/kas.proto`:
  `PublicKeyRequest { string algorithm = 1; string fmt = 2; string v = 3; }`,
  `PublicKeyResponse { string public_key = 1; string kid = 2; }`,
  `rpc PublicKey(PublicKeyRequest) returns (PublicKeyResponse)`. Connect path is
  `/kas.AccessService/PublicKey` (package `kas`, service `AccessService`). The
  `algorithm` value is a **request-message field**, encoded as a JSON body field
  over Connect (`protojson` accepts both snake_case and camelCase).
- Connect-Go accepts proto JSON field names in either case, so the existing
  `signed_request_token` body key remains valid for Rewrap over Connect.

## Architecture

### New file: `OpenTDFKit/KASDiscovery.swift`

Mirrors `kas_discovery.rs`. All types `Sendable`; config types `Codable` with
explicit snake_case `CodingKeys` to match the platform JSON.

- `public struct OpenTDFConfiguration: Codable, Sendable`
  - `kas: KasConfig?`, `idp: IdpConfig?`, `platformIssuer: String?`
  - `static func forKasConnect(_ baseURL: String) -> OpenTDFConfiguration`
    — trims trailing `/`; sets
    `connectRewrapURL = {base}/kas.AccessService/Rewrap`,
    `connectPublicKeyURL = {base}/kas.AccessService/PublicKey`, `uri = base`.
  - `static func forKasLegacyRest(_ baseURL: String) -> OpenTDFConfiguration`
    — sets `rewrapURL = {base}/kas/v2/rewrap`,
    `publicKeyURL = {base}/kas/v2/kas_public_key`, `uri = base`.
- `public struct KasConfig: Codable, Sendable`
  - `uri: String`, `algorithms: [String]` (default `[]`),
    `publicKeyURL: String?`, `rewrapURL: String?`,
    `connectPublicKeyURL: String?`, `connectRewrapURL: String?`
  - CodingKeys: `uri`, `algorithms`, `public_key_url`, `rewrap_url`,
    `connect_public_key_url`, `connect_rewrap_url`.
- `public struct IdpConfig: Codable, Sendable`
  - `issuer`, `jwksURI?`, `coseKeysURI?`, `tokenEndpoint?`,
    `authorizationEndpoint?`, `userinfoEndpoint?`, `accessTokenFormat?`,
    `idTokenSigningAlgValuesSupported: [String]` (default `[]`),
    `responseTypesSupported: [String]` (default `[]`),
    `subjectTypesSupported: [String]` (default `[]`).
- `public enum KasTransport: Sendable { case connect, legacyRest }`
- `public struct KasEndpoints: Sendable`
  - `rewrapURL: String`, `publicKeyURL: String`, `transport: KasTransport`
  - `static func from(_ config: OpenTDFConfiguration) throws -> KasEndpoints`
    — Connect-preferred (both `connect_*_url` present), else REST fallback (both
    `*_url` present), else throw. Validates **both** resolved URLs via
    `validateKasURL` before returning.
- `public func validateKasURL(_ urlString: String) throws`
  - Scheme must be `http`/`https`. Plain `http` only for loopback
    (`localhost`, `127.0.0.0/8`, `::1`). SSRF guard rejects IPv4 private
    (`10/8`, `172.16/12`, `192.168/16`), link-local (`169.254/16`),
    unspecified (`0.0.0.0`); IPv6 ULA `fc00::/7`, link-local `fe80::/10`, `::`;
    and IPv4-mapped IPv6 literals folded back to IPv4 before the check.
  - IP parsing/classification via `Darwin.inet_pton` into `in_addr`/`in6_addr`
    plus bit checks (Foundation has no built-in IP range API). Helper
    `isBlockedIP` mirrors Rust `is_blocked_ip`.
- `public struct ConnectError: Codable, Sendable { let code: String; let message: String }`
- `public func parseConnectError(_ body: String) -> ConnectError?`
  — nil for empty/non-JSON/empty-code bodies.
- `public func fetchWellKnown(platformURL: String, urlSession: URLSession = .shared) async throws -> OpenTDFConfiguration`
  — GET `{base}/.well-known/opentdf-configuration`; maps non-2xx to a KAS error.

### `OpenTDFKit/KASRewrapClient.swift` changes (breaking)

- **Init (breaking):**
  `public init(configuration: OpenTDFConfiguration, oauthToken: String, urlSession: URLSession = .shared, signingKey: P256.Signing.PrivateKey? = nil) throws`
  - Resolves `endpoints = try KasEndpoints.from(configuration)`.
  - Stores `endpoints`, `kasIdentityURL = configuration.kas?.uri` (fallback for
    request-body KAS url), `oauthToken`, `urlSession`, `signingKey`, and a
    shared `NoRedirectDelegate`.
  - The old `init(kasURL:oauthToken:...)` is **removed**.
- **No-redirect transport:** add
  `final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate` whose
  `urlSession(_:task:willPerformHTTPRedirection:newRequest:)` returns `nil`.
  Bearer-carrying calls use `urlSession.data(for:delegate:)` with this delegate
  (per-task delegate; macOS 14+). This is the Swift equivalent of
  `redirect::Policy::none()` while keeping `urlSession` injectable for tests.
- **NanoTDF rewrap KAS identity url:** in `rewrapNanoTDF`, resolve the
  request-body `KeyAccessObject.url` from `parsedHeader.kas` (the
  `ResourceLocator`), reconstructed as `"\(scheme)://\(body)"` where scheme is
  `http`/`https` from `protocolEnum`. Fall back to `kasIdentityURL`
  (`config.kas.uri`) when the header locator body is empty/unusable. New private
  helper `resolveNanoKasURL(_ parsedHeader: Header) -> String`.
- **Rewrap request:** POST the resolved `endpoints.rewrapURL` (full URL; same
  for both transports). Headers: `Authorization: Bearer <token>`,
  `Content-Type: application/json`, `Connect-Protocol-Version: 1`. On non-2xx,
  call `parseConnectError`; if present, surface `"<code>: <message>"`, else the
  raw body / `HTTP <status>`.
- **Public-key fetch** (`fetchKasEcPublicKey`) branches on
  `endpoints.transport`:
  - `.connect`: POST `endpoints.publicKeyURL` with JSON body
    `{"algorithm": "<algorithm.rawValue>"}` and `Connect-Protocol-Version: 1`.
  - `.legacyRest`: existing GET `endpoints.publicKeyURL?algorithm=<algorithm>`.
  Response parsing (`KasEcPublicKeyResponse`, camel/snake) and PEM validation
  are unchanged.
- **Error enrichment:** change `case authenticationFailed` to
  `case authenticationFailed(String?)` so the Connect `unauthenticated` reason
  surfaces (mirrors Rust `AuthenticationFailed { reason }`). Update the three
  throw sites (`rewrapNanoTDF`, `rewrapTDF`, `fetchKasEcPublicKey`) and the
  `description` to render the reason when present.
- `matchesKasURL` (used by `rewrapTDF` to filter manifest key-access entries)
  now compares against `kasIdentityURL` (the resolved KAS identity), preserving
  current behavior.

### CLI changes (`OpenTDFKitCLI/`) — Connect with REST fallback

- Add a helper to build an `OpenTDFConfiguration`:
  1. Try `fetchWellKnown(PLATFORMURL)`.
  2. On failure, synthesize `OpenTDFConfiguration.forKasConnect(PLATFORMURL)`.
  3. (Connect URLs always present in 1–2, so resolution lands on `.connect`;
     `.legacyRest` only if a fetched well-known omits Connect URLs.)
- Replace the three `KASRewrapClient(kasURL:oauthToken:)` call sites in
  `Commands.swift` with `try KASRewrapClient(configuration:oauthToken:)`.
- Standalone NanoTDF public-key fetch in `Commands.swift`
  (`fetchKASPublicKey`, currently a GET) routes through the client / resolved
  endpoints so it honors the Connect transport.
- TDF RSA public key continues to load from `TDF_KAS_PUBLIC_KEY_PATH` (file),
  unchanged.

## Data flow

```
PLATFORMURL ──fetchWellKnown──▶ OpenTDFConfiguration ──KasEndpoints.from──▶ endpoints
   (fallback: forKasConnect)                              (validates URLs, picks transport)
                                                                 │
KASRewrapClient(configuration:oauthToken:) ──────────────────────┘
   rewrapNanoTDF: POST endpoints.rewrapURL  (no redirect, Bearer, Connect-Protocol-Version)
                  body KAS url ← parsedHeader.kas (fallback config.kas.uri)
   fetchKasEcPublicKey: .connect → POST publicKeyURL {"algorithm":...}
                        .legacyRest → GET publicKeyURL?algorithm=...
   non-2xx → parseConnectError → "<code>: <message>"
```

## Error handling

- `KasEndpoints.from` throws on missing `kas` block, missing URL pairs, or a
  URL failing `validateKasURL` (`InvalidUrl`-style message).
- `validateKasURL` throws on bad scheme, non-loopback HTTP, or
  private/link-local/unspecified IP targets (SSRF).
- HTTP non-2xx: 401 → `authenticationFailed(reason)`, 403 →
  `accessDenied(reason)`, else `httpError(status, reason)`, where `reason` is the
  Connect envelope `code: message` when parseable.
- `fetchWellKnown` non-2xx → `httpError`; parse failure → a decode error.

## Testing

Unit (no network, mirror `kas_discovery.rs` tests):
- `OpenTDFConfiguration` decodes the captured platform well-known fixture
  (incl. `access_token_format == "application/cwt"`).
- `KasEndpoints.from`: picks Connect when present; REST fallback when Connect
  absent; throws when `kas` block or URL pairs missing; rejects a hostile
  Connect URL (`169.254.169.254`).
- `forKasConnect` / `forKasLegacyRest` build expected URLs; trailing slash
  tolerated.
- `validateKasURL`: accepts https + loopback http; rejects non-loopback http,
  bad scheme, IPv4 private/link-local/metadata, IPv6 ULA/link-local,
  unspecified, and IPv4-mapped metadata literal.
- `parseConnectError`: valid body, garbage, empty, wrong-shape.

Connect transport (mock `URLProtocol`):
- EC public-key Connect fetch POSTs to `/kas.AccessService/PublicKey` with body
  containing `"algorithm":"ec:secp256r1"`; parses PEM + kid.
- Rewrap routes to `endpoints.rewrapURL`; a Connect error envelope on 401 is
  surfaced as `authenticationFailed("unauthenticated: ...")`.

Live integration (skipped by default unless `KAS_INTEGRATION_TESTS=1`, against
`https://platform.arkavo.net`), porting the three Rust tests:
- well-known returns both Connect and REST URLs.
- Connect PublicKey returns a PEM with non-empty kid.
- Connect Rewrap with a fake bearer returns 401 →
  `authenticationFailed`/`accessDenied`/`httpError(≠404)`.

Existing `KASRewrapClientTests` and `IntegrationTests` are updated to the new
`init(configuration:oauthToken:)` (build via `forKasConnect`/`forKasLegacyRest`).

## Out of scope

- IdP token acquisition / CWT minting (tokens remain opaque passthrough).
- TDF RSA public-key fetch via Connect (still file-based per env var).
- Removing the legacy REST path (kept as fallback).

## Call sites to update (breaking init)

- `OpenTDFKitCLI/Commands.swift`: lines ~169, ~570, ~932.
- `OpenTDFKitTests/IntegrationTests.swift`: lines ~77, ~136, ~363, ~456.
- `OpenTDFKitTests/KASRewrapClientTests.swift`: line ~12.
- Any `KASRewrapError.authenticationFailed` pattern matches in tests.
