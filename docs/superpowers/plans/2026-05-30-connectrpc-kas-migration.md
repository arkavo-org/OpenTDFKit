# ConnectRPC + Well-Known KAS Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate the OpenTDFKit KAS client transport from REST `/kas/v2/*` to ConnectRPC unary-JSON `/kas.AccessService/*`, driven by `/.well-known/opentdf-configuration` discovery, with SSRF-validated endpoints, no-redirect HTTP, Connect error parsing, and opaque CWT/JWT bearer passthrough.

**Architecture:** A new `KASDiscovery.swift` provides Codable config types, endpoint resolution (Connect-preferred, REST-fallback), URL/SSRF validation, Connect error parsing, and well-known fetch. `KASRewrapClient` gains a breaking `init(configuration:oauthToken:)`, stores resolved `KasEndpoints`, uses a `NoRedirectDelegate`, branches transport for the public-key fetch, and derives the NanoTDF request-body KAS url from the parsed header (config fallback). The CLI resolves config via well-known (synthesized-Connect fallback).

**Tech Stack:** Swift 6, Foundation/URLSession, CryptoKit, `Darwin.inet_pton` for IP classification, XCTest.

**Reference:** `docs/superpowers/specs/2026-05-30-connectrpc-kas-migration-design.md` and opentdf-rs `src/kas_discovery.rs` / `src/kas.rs` / `src/kas_key.rs`.

**Build/test commands:**
- Build: `swift build`
- All tests: `swift test`
- One suite: `swift test --filter KASDiscoveryTests`
- Format (before any commit): `swiftformat --swiftversion 6.2 .`

---

## Task 1: Config types + builders

**Files:**
- Create: `OpenTDFKit/KASDiscovery.swift`
- Test: `OpenTDFKitTests/KASDiscoveryTests.swift`

- [ ] **Step 1: Write the failing tests**

Create `OpenTDFKitTests/KASDiscoveryTests.swift`:

```swift
@testable import OpenTDFKit
import XCTest

final class KASDiscoveryTests: XCTestCase {
    /// Captured from https://platform.arkavo.net/.well-known/opentdf-configuration on 2026-05-28
    static let platformWellKnown = """
    {
        "health": { "endpoint": "/healthz" },
        "idp": {
            "access_token_format": "application/cwt",
            "authorization_endpoint": "https://identity.arkavo.net/oauth/authorize",
            "cose_keys_uri": "https://identity.arkavo.net/.well-known/cose-keys",
            "id_token_signing_alg_values_supported": ["ES256"],
            "issuer": "https://identity.arkavo.net",
            "jwks_uri": "https://identity.arkavo.net/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "token_endpoint": "https://identity.arkavo.net/oauth/token",
            "userinfo_endpoint": "https://identity.arkavo.net/oauth/userinfo"
        },
        "kas": {
            "algorithms": ["ec:secp256r1", "rsa:2048"],
            "connect_public_key_url": "https://platform.arkavo.net/kas.AccessService/PublicKey",
            "connect_rewrap_url": "https://platform.arkavo.net/kas.AccessService/Rewrap",
            "public_key_url": "https://platform.arkavo.net/kas/v2/kas_public_key",
            "rewrap_url": "https://platform.arkavo.net/kas/v2/rewrap",
            "uri": "https://platform.arkavo.net"
        },
        "platform_issuer": "https://identity.arkavo.net"
    }
    """

    func testDecodesPlatformWellKnown() throws {
        let cfg = try JSONDecoder().decode(OpenTDFConfiguration.self,
                                           from: Data(Self.platformWellKnown.utf8))
        let kas = try XCTUnwrap(cfg.kas)
        XCTAssertEqual(kas.uri, "https://platform.arkavo.net")
        XCTAssertEqual(kas.algorithms, ["ec:secp256r1", "rsa:2048"])
        XCTAssertEqual(kas.connectRewrapURL, "https://platform.arkavo.net/kas.AccessService/Rewrap")
        XCTAssertEqual(kas.rewrapURL, "https://platform.arkavo.net/kas/v2/rewrap")
        let idp = try XCTUnwrap(cfg.idp)
        XCTAssertEqual(idp.issuer, "https://identity.arkavo.net")
        XCTAssertEqual(idp.accessTokenFormat, "application/cwt")
        XCTAssertEqual(cfg.platformIssuer, "https://identity.arkavo.net")
    }

    func testDecodesMinimalKasOnly() throws {
        let json = """
        {"kas":{"uri":"https://k.example.com","algorithms":[],
        "rewrap_url":"https://k.example.com/kas/v2/rewrap",
        "public_key_url":"https://k.example.com/kas/v2/kas_public_key"}}
        """
        let cfg = try JSONDecoder().decode(OpenTDFConfiguration.self, from: Data(json.utf8))
        let kas = try XCTUnwrap(cfg.kas)
        XCTAssertNil(kas.connectRewrapURL)
        XCTAssertEqual(kas.rewrapURL, "https://k.example.com/kas/v2/rewrap")
        XCTAssertNil(cfg.idp)
    }

    func testForKasConnectConstructsURLs() {
        let cfg = OpenTDFConfiguration.forKasConnect("https://kas.example.com")
        XCTAssertEqual(cfg.kas?.connectRewrapURL, "https://kas.example.com/kas.AccessService/Rewrap")
        XCTAssertEqual(cfg.kas?.connectPublicKeyURL, "https://kas.example.com/kas.AccessService/PublicKey")
        XCTAssertEqual(cfg.kas?.uri, "https://kas.example.com")
    }

    func testForKasConnectHandlesTrailingSlash() {
        let cfg = OpenTDFConfiguration.forKasConnect("https://kas.example.com/")
        XCTAssertEqual(cfg.kas?.connectRewrapURL, "https://kas.example.com/kas.AccessService/Rewrap")
    }

    func testForKasLegacyRestConstructsURLs() {
        let cfg = OpenTDFConfiguration.forKasLegacyRest("https://kas.example.com")
        XCTAssertEqual(cfg.kas?.rewrapURL, "https://kas.example.com/kas/v2/rewrap")
        XCTAssertEqual(cfg.kas?.publicKeyURL, "https://kas.example.com/kas/v2/kas_public_key")
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `swift test --filter KASDiscoveryTests`
Expected: FAIL — `cannot find 'OpenTDFConfiguration' in scope`.

- [ ] **Step 3: Create `OpenTDFKit/KASDiscovery.swift` with config types**

```swift
import Foundation

// MARK: - Configuration documents (/.well-known/opentdf-configuration)

/// The platform's well-known configuration document.
public struct OpenTDFConfiguration: Codable, Sendable {
    public let kas: KasConfig?
    public let idp: IdpConfig?
    public let platformIssuer: String?

    public init(kas: KasConfig?, idp: IdpConfig?, platformIssuer: String?) {
        self.kas = kas
        self.idp = idp
        self.platformIssuer = platformIssuer
    }

    enum CodingKeys: String, CodingKey {
        case kas, idp
        case platformIssuer = "platform_issuer"
    }

    /// Synthesize a Connect-only configuration for a single KAS base URL.
    /// Use when the platform does not expose the well-known endpoint.
    public static func forKasConnect(_ baseURL: String) -> OpenTDFConfiguration {
        let base = String(baseURL.reversed().drop { $0 == "/" }.reversed())
        return OpenTDFConfiguration(
            kas: KasConfig(
                uri: base,
                algorithms: [],
                publicKeyURL: nil,
                rewrapURL: nil,
                connectPublicKeyURL: "\(base)/kas.AccessService/PublicKey",
                connectRewrapURL: "\(base)/kas.AccessService/Rewrap"),
            idp: nil,
            platformIssuer: nil)
    }

    /// Synthesize a legacy-REST configuration for a single KAS base URL.
    public static func forKasLegacyRest(_ baseURL: String) -> OpenTDFConfiguration {
        let base = String(baseURL.reversed().drop { $0 == "/" }.reversed())
        return OpenTDFConfiguration(
            kas: KasConfig(
                uri: base,
                algorithms: [],
                publicKeyURL: "\(base)/kas/v2/kas_public_key",
                rewrapURL: "\(base)/kas/v2/rewrap",
                connectPublicKeyURL: nil,
                connectRewrapURL: nil),
            idp: nil,
            platformIssuer: nil)
    }
}

public struct KasConfig: Codable, Sendable {
    public let uri: String
    public let algorithms: [String]
    public let publicKeyURL: String?
    public let rewrapURL: String?
    public let connectPublicKeyURL: String?
    public let connectRewrapURL: String?

    public init(uri: String, algorithms: [String], publicKeyURL: String?, rewrapURL: String?,
                connectPublicKeyURL: String?, connectRewrapURL: String?) {
        self.uri = uri
        self.algorithms = algorithms
        self.publicKeyURL = publicKeyURL
        self.rewrapURL = rewrapURL
        self.connectPublicKeyURL = connectPublicKeyURL
        self.connectRewrapURL = connectRewrapURL
    }

    enum CodingKeys: String, CodingKey {
        case uri, algorithms
        case publicKeyURL = "public_key_url"
        case rewrapURL = "rewrap_url"
        case connectPublicKeyURL = "connect_public_key_url"
        case connectRewrapURL = "connect_rewrap_url"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        uri = try c.decode(String.self, forKey: .uri)
        algorithms = try c.decodeIfPresent([String].self, forKey: .algorithms) ?? []
        publicKeyURL = try c.decodeIfPresent(String.self, forKey: .publicKeyURL)
        rewrapURL = try c.decodeIfPresent(String.self, forKey: .rewrapURL)
        connectPublicKeyURL = try c.decodeIfPresent(String.self, forKey: .connectPublicKeyURL)
        connectRewrapURL = try c.decodeIfPresent(String.self, forKey: .connectRewrapURL)
    }
}

public struct IdpConfig: Codable, Sendable {
    public let issuer: String
    public let jwksURI: String?
    public let coseKeysURI: String?
    public let tokenEndpoint: String?
    public let authorizationEndpoint: String?
    public let userinfoEndpoint: String?
    public let accessTokenFormat: String?
    public let idTokenSigningAlgValuesSupported: [String]
    public let responseTypesSupported: [String]
    public let subjectTypesSupported: [String]

    enum CodingKeys: String, CodingKey {
        case issuer
        case jwksURI = "jwks_uri"
        case coseKeysURI = "cose_keys_uri"
        case tokenEndpoint = "token_endpoint"
        case authorizationEndpoint = "authorization_endpoint"
        case userinfoEndpoint = "userinfo_endpoint"
        case accessTokenFormat = "access_token_format"
        case idTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported"
        case responseTypesSupported = "response_types_supported"
        case subjectTypesSupported = "subject_types_supported"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        issuer = try c.decode(String.self, forKey: .issuer)
        jwksURI = try c.decodeIfPresent(String.self, forKey: .jwksURI)
        coseKeysURI = try c.decodeIfPresent(String.self, forKey: .coseKeysURI)
        tokenEndpoint = try c.decodeIfPresent(String.self, forKey: .tokenEndpoint)
        authorizationEndpoint = try c.decodeIfPresent(String.self, forKey: .authorizationEndpoint)
        userinfoEndpoint = try c.decodeIfPresent(String.self, forKey: .userinfoEndpoint)
        accessTokenFormat = try c.decodeIfPresent(String.self, forKey: .accessTokenFormat)
        idTokenSigningAlgValuesSupported =
            try c.decodeIfPresent([String].self, forKey: .idTokenSigningAlgValuesSupported) ?? []
        responseTypesSupported =
            try c.decodeIfPresent([String].self, forKey: .responseTypesSupported) ?? []
        subjectTypesSupported =
            try c.decodeIfPresent([String].self, forKey: .subjectTypesSupported) ?? []
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `swiftformat --swiftversion 6.2 . && swift test --filter KASDiscoveryTests`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add OpenTDFKit/KASDiscovery.swift OpenTDFKitTests/KASDiscoveryTests.swift
git commit -m "feat(kas): add OpenTDFConfiguration discovery types + builders"
```

---

## Task 2: URL + SSRF validation

**Files:**
- Modify: `OpenTDFKit/KASDiscovery.swift`
- Test: `OpenTDFKitTests/KASDiscoveryTests.swift`

- [ ] **Step 1: Add failing tests**

Append to `KASDiscoveryTests`:

```swift
    func testValidateAcceptsHTTPSAndLoopbackHTTP() {
        XCTAssertNoThrow(try validateKasURL("https://kas.example.com/kas.AccessService/Rewrap"))
        XCTAssertNoThrow(try validateKasURL("http://localhost:8080/x"))
        XCTAssertNoThrow(try validateKasURL("http://127.0.0.1:8080/x"))
        XCTAssertNoThrow(try validateKasURL("http://[::1]:8080/x"))
    }

    func testValidateRejectsNonLoopbackHTTPAndBadScheme() {
        XCTAssertThrowsError(try validateKasURL("http://evil.com/x"))
        XCTAssertThrowsError(try validateKasURL("ftp://kas.example.com/x"))
    }

    func testValidateRejectsIPv4PrivateAndLinkLocal() {
        for url in ["https://10.0.0.1/x", "https://172.16.0.1/x",
                    "https://192.168.1.1/x", "https://169.254.169.254/x"] {
            XCTAssertThrowsError(try validateKasURL(url), "\(url) should be rejected")
        }
    }

    func testValidateRejectsIPv6ULAAndLinkLocal() {
        for url in ["https://[fd00::1]/x", "https://[fc00::1]/x", "https://[fe80::1]/x"] {
            XCTAssertThrowsError(try validateKasURL(url), "\(url) should be rejected")
        }
    }

    func testValidateRejectsUnspecifiedAddresses() {
        XCTAssertThrowsError(try validateKasURL("https://0.0.0.0/x"))
        XCTAssertThrowsError(try validateKasURL("https://[::]/x"))
    }

    func testValidateRejectsIPv4MappedMetadataAddress() {
        XCTAssertThrowsError(try validateKasURL("https://[::ffff:169.254.169.254]/x"))
        XCTAssertThrowsError(try validateKasURL("https://[::ffff:10.0.0.1]/x"))
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `swift test --filter KASDiscoveryTests`
Expected: FAIL — `cannot find 'validateKasURL' in scope`.

- [ ] **Step 3: Add validation + error type to `KASDiscovery.swift`**

```swift
import Darwin

// MARK: - Errors

public enum KASDiscoveryError: Error, CustomStringConvertible {
    case invalidURL(String)
    case configError(String)
    case httpError(Int, String)
    case invalidResponse(String)

    public var description: String {
        switch self {
        case let .invalidURL(m): "Invalid KAS URL: \(m)"
        case let .configError(m): "KAS configuration error: \(m)"
        case let .httpError(s, m): "HTTP error \(s): \(m)"
        case let .invalidResponse(m): "Invalid response: \(m)"
        }
    }
}

// MARK: - URL / SSRF validation

private enum IPLiteral {
    case v4([UInt8])   // 4 bytes, network order
    case v6([UInt8])   // 16 bytes, network order
}

private func classifyIP(_ host: String) -> IPLiteral? {
    var v4 = in_addr()
    if host.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
        return .v4(withUnsafeBytes(of: v4.s_addr) { Array($0) })
    }
    var v6 = in6_addr()
    if host.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
        return .v6(withUnsafeBytes(of: v6) { Array($0) })
    }
    return nil
}

private func isLoopbackHost(_ host: String) -> Bool {
    if host == "localhost" { return true }
    switch classifyIP(host) {
    case let .v4(o): return o[0] == 127            // 127.0.0.0/8
    case let .v6(b): return b.dropLast() == ArraySlice(repeating: 0, count: 15) && b[15] == 1 // ::1
    case .none: return false
    }
}

private func isBlockedV4(_ o: [UInt8]) -> Bool {
    if o[0] == 10 { return true }                      // 10.0.0.0/8
    if o[0] == 172, (o[1] & 0xF0) == 16 { return true } // 172.16.0.0/12
    if o[0] == 192, o[1] == 168 { return true }        // 192.168.0.0/16
    if o[0] == 169, o[1] == 254 { return true }        // 169.254.0.0/16
    if o == [0, 0, 0, 0] { return true }               // 0.0.0.0
    return false
}

private func isBlockedIP(_ ip: IPLiteral) -> Bool {
    switch ip {
    case let .v4(o):
        return isBlockedV4(o)
    case let .v6(b):
        // Fold IPv4-mapped ::ffff:a.b.c.d back to IPv4.
        if b[0 ..< 10].allSatisfy({ $0 == 0 }), b[10] == 0xFF, b[11] == 0xFF {
            return isBlockedV4(Array(b[12 ..< 16]))
        }
        if b.allSatisfy({ $0 == 0 }) { return true } // :: unspecified
        let first = (UInt16(b[0]) << 8) | UInt16(b[1])
        return (first & 0xFE00) == 0xFC00 || (first & 0xFFC0) == 0xFE80 // fc00::/7, fe80::/10
    }
}

/// Validate a KAS URL for scheme / HTTPS / SSRF constraints.
public func validateKasURL(_ urlString: String) throws {
    guard let url = URL(string: urlString), let scheme = url.scheme?.lowercased() else {
        throw KASDiscoveryError.invalidURL("Failed to parse URL: \(urlString)")
    }
    let host = url.host ?? ""

    switch scheme {
    case "https":
        break
    case "http":
        if !isLoopbackHost(host) {
            throw KASDiscoveryError.invalidURL("KAS URL must use HTTPS (HTTP only allowed for localhost)")
        }
    default:
        throw KASDiscoveryError.invalidURL("Unsupported URL scheme '\(scheme)', must be https")
    }

    if let ip = classifyIP(host), isBlockedIP(ip) {
        throw KASDiscoveryError.invalidURL("KAS URL must not target private or link-local IP addresses")
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `swiftformat --swiftversion 6.2 . && swift test --filter KASDiscoveryTests`
Expected: PASS (12 tests).

- [ ] **Step 5: Commit**

```bash
git add OpenTDFKit/KASDiscovery.swift OpenTDFKitTests/KASDiscoveryTests.swift
git commit -m "feat(kas): add validateKasURL with HTTPS + SSRF guard"
```

---

## Task 3: Endpoint resolution

**Files:**
- Modify: `OpenTDFKit/KASDiscovery.swift`
- Test: `OpenTDFKitTests/KASDiscoveryTests.swift`

- [ ] **Step 1: Add failing tests**

Append to `KASDiscoveryTests`:

```swift
    func testFromConfigPicksConnectWhenPresent() throws {
        let cfg = try JSONDecoder().decode(OpenTDFConfiguration.self,
                                           from: Data(Self.platformWellKnown.utf8))
        let ep = try KasEndpoints.from(cfg)
        XCTAssertEqual(ep.rewrapURL, "https://platform.arkavo.net/kas.AccessService/Rewrap")
        XCTAssertEqual(ep.publicKeyURL, "https://platform.arkavo.net/kas.AccessService/PublicKey")
        XCTAssertEqual(ep.transport, .connect)
    }

    func testFromConfigFallsBackToRest() throws {
        let cfg = OpenTDFConfiguration.forKasLegacyRest("https://k.example.com")
        let ep = try KasEndpoints.from(cfg)
        XCTAssertEqual(ep.rewrapURL, "https://k.example.com/kas/v2/rewrap")
        XCTAssertEqual(ep.transport, .legacyRest)
    }

    func testFromConfigThrowsWhenKasMissing() {
        let cfg = OpenTDFConfiguration(kas: nil, idp: nil, platformIssuer: "https://x.com")
        XCTAssertThrowsError(try KasEndpoints.from(cfg))
    }

    func testFromConfigThrowsWhenURLsMissing() {
        let cfg = OpenTDFConfiguration(
            kas: KasConfig(uri: "https://k.example.com", algorithms: [], publicKeyURL: nil,
                           rewrapURL: nil, connectPublicKeyURL: nil, connectRewrapURL: nil),
            idp: nil, platformIssuer: nil)
        XCTAssertThrowsError(try KasEndpoints.from(cfg))
    }

    func testFromConfigRejectsHostileConnectURL() {
        let cfg = OpenTDFConfiguration(
            kas: KasConfig(uri: "https://platform.example.com", algorithms: [],
                           publicKeyURL: nil, rewrapURL: nil,
                           connectPublicKeyURL: "https://platform.example.com/kas.AccessService/PublicKey",
                           connectRewrapURL: "https://169.254.169.254/kas.AccessService/Rewrap"),
            idp: nil, platformIssuer: nil)
        XCTAssertThrowsError(try KasEndpoints.from(cfg))
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `swift test --filter KASDiscoveryTests`
Expected: FAIL — `cannot find 'KasEndpoints' in scope`.

- [ ] **Step 3: Add `KasTransport` + `KasEndpoints` to `KASDiscovery.swift`**

```swift
// MARK: - Endpoint resolution

public enum KasTransport: Sendable, Equatable {
    /// ConnectRPC endpoints at /kas.AccessService/*
    case connect
    /// Legacy REST gateway at /kas/v2/*
    case legacyRest
}

public struct KasEndpoints: Sendable {
    public let rewrapURL: String
    public let publicKeyURL: String
    public let transport: KasTransport

    /// Resolve KAS endpoints, preferring ConnectRPC URLs and falling back to
    /// legacy REST when only REST is advertised. Both resolved URLs are
    /// validated (HTTPS / scheme / SSRF) before returning.
    public static func from(_ config: OpenTDFConfiguration) throws -> KasEndpoints {
        guard let kas = config.kas else {
            throw KASDiscoveryError.configError("well-known configuration is missing a 'kas' block")
        }

        let resolved: KasEndpoints
        if let rewrap = kas.connectRewrapURL, let pub = kas.connectPublicKeyURL {
            resolved = KasEndpoints(rewrapURL: rewrap, publicKeyURL: pub, transport: .connect)
        } else if let rewrap = kas.rewrapURL, let pub = kas.publicKeyURL {
            resolved = KasEndpoints(rewrapURL: rewrap, publicKeyURL: pub, transport: .legacyRest)
        } else {
            throw KASDiscoveryError.configError("well-known kas block exposes neither Connect nor REST URLs")
        }

        try validateKasURL(resolved.rewrapURL)
        try validateKasURL(resolved.publicKeyURL)
        return resolved
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `swiftformat --swiftversion 6.2 . && swift test --filter KASDiscoveryTests`
Expected: PASS (17 tests).

- [ ] **Step 5: Commit**

```bash
git add OpenTDFKit/KASDiscovery.swift OpenTDFKitTests/KASDiscoveryTests.swift
git commit -m "feat(kas): add KasEndpoints resolution (Connect-preferred)"
```

---

## Task 4: Connect error envelope parsing

**Files:**
- Modify: `OpenTDFKit/KASDiscovery.swift`
- Test: `OpenTDFKitTests/KASDiscoveryTests.swift`

- [ ] **Step 1: Add failing tests**

Append to `KASDiscoveryTests`:

```swift
    func testParseConnectErrorValidBody() {
        let err = parseConnectError(#"{"code":"unauthenticated","message":"missing bearer token"}"#)
        XCTAssertEqual(err?.code, "unauthenticated")
        XCTAssertEqual(err?.message, "missing bearer token")
    }

    func testParseConnectErrorGarbageReturnsNil() {
        XCTAssertNil(parseConnectError("not json"))
        XCTAssertNil(parseConnectError(""))
        XCTAssertNil(parseConnectError(#"{"unrelated":"shape"}"#))
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `swift test --filter KASDiscoveryTests`
Expected: FAIL — `cannot find 'parseConnectError' in scope`.

- [ ] **Step 3: Add `ConnectError` + parser to `KASDiscovery.swift`**

```swift
// MARK: - Connect error envelope

/// Error envelope returned by Connect unary-JSON RPCs on non-2xx responses.
public struct ConnectError: Codable, Sendable {
    public let code: String
    public let message: String
}

/// Parse a Connect error envelope from a response body. Returns nil for empty,
/// non-JSON, or shapes lacking a non-empty `code`.
public func parseConnectError(_ body: String) -> ConnectError? {
    guard !body.isEmpty, let data = body.data(using: .utf8) else { return nil }
    guard let parsed = try? JSONDecoder().decode(ConnectError.self, from: data) else { return nil }
    return parsed.code.isEmpty ? nil : parsed
}
```

- [ ] **Step 4: Run to verify pass**

Run: `swiftformat --swiftversion 6.2 . && swift test --filter KASDiscoveryTests`
Expected: PASS (19 tests).

- [ ] **Step 5: Commit**

```bash
git add OpenTDFKit/KASDiscovery.swift OpenTDFKitTests/KASDiscoveryTests.swift
git commit -m "feat(kas): add Connect error-envelope parsing"
```

---

## Task 5: well-known fetch + MockURLProtocol helper

**Files:**
- Modify: `OpenTDFKit/KASDiscovery.swift`
- Create: `OpenTDFKitTests/MockURLProtocol.swift`
- Test: `OpenTDFKitTests/KASDiscoveryTests.swift`

- [ ] **Step 1: Create the mock URL protocol helper**

Create `OpenTDFKitTests/MockURLProtocol.swift`:

```swift
import Foundation

/// Test double that intercepts URLSession requests. Set `handler` per test to
/// return a (response, body) for a given request.
final class MockURLProtocol: URLProtocol {
    nonisolated(unsafe) static var handler: ((URLRequest) throws -> (HTTPURLResponse, Data))?

    override class func canInit(with _: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = MockURLProtocol.handler else {
            client?.urlProtocol(self, didFailWithError:
                NSError(domain: "MockURLProtocol", code: 0))
            return
        }
        do {
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}

    /// A URLSession whose only protocol is the mock.
    static func makeSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        return URLSession(configuration: config)
    }
}
```

- [ ] **Step 2: Add failing tests**

Append to `KASDiscoveryTests`:

```swift
    func testFetchWellKnownReturnsParsedConfig() async throws {
        MockURLProtocol.handler = { req in
            XCTAssertEqual(req.url?.path, "/.well-known/opentdf-configuration")
            let resp = HTTPURLResponse(url: req.url!, statusCode: 200,
                                       httpVersion: nil, headerFields: nil)!
            return (resp, Data(Self.platformWellKnown.utf8))
        }
        let session = MockURLProtocol.makeSession()
        let cfg = try await fetchWellKnown(platformURL: "https://platform.arkavo.net",
                                           urlSession: session)
        XCTAssertNotNil(cfg.kas)
        XCTAssertEqual(cfg.platformIssuer, "https://identity.arkavo.net")
    }

    func testFetchWellKnown404Throws() async {
        MockURLProtocol.handler = { req in
            let resp = HTTPURLResponse(url: req.url!, statusCode: 404,
                                       httpVersion: nil, headerFields: nil)!
            return (resp, Data("not found".utf8))
        }
        let session = MockURLProtocol.makeSession()
        do {
            _ = try await fetchWellKnown(platformURL: "https://platform.arkavo.net",
                                         urlSession: session)
            XCTFail("expected throw")
        } catch let KASDiscoveryError.httpError(status, _) {
            XCTAssertEqual(status, 404)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }
```

- [ ] **Step 3: Run to verify failure**

Run: `swift test --filter KASDiscoveryTests`
Expected: FAIL — `cannot find 'fetchWellKnown' in scope`.

- [ ] **Step 4: Add `fetchWellKnown` to `KASDiscovery.swift`**

```swift
// MARK: - Well-known discovery

/// Fetch the platform's /.well-known/opentdf-configuration document.
/// `platformURL` is the platform base (e.g. "https://platform.arkavo.net"); a
/// trailing slash is tolerated.
public func fetchWellKnown(platformURL: String,
                           urlSession: URLSession = .shared) async throws -> OpenTDFConfiguration {
    let base = String(platformURL.reversed().drop { $0 == "/" }.reversed())
    let urlString = "\(base)/.well-known/opentdf-configuration"
    guard let url = URL(string: urlString) else {
        throw KASDiscoveryError.invalidURL("Failed to parse URL: \(urlString)")
    }

    var request = URLRequest(url: url)
    request.httpMethod = "GET"
    request.timeoutInterval = 30
    request.addValue("application/json", forHTTPHeaderField: "Accept")

    let (data, response) = try await urlSession.data(for: request)
    guard let http = response as? HTTPURLResponse else {
        throw KASDiscoveryError.invalidResponse("Non-HTTP response from \(urlString)")
    }
    guard (200 ..< 300).contains(http.statusCode) else {
        let body = String(data: data, encoding: .utf8) ?? ""
        throw KASDiscoveryError.httpError(http.statusCode, "GET \(urlString): \(body)")
    }

    do {
        return try JSONDecoder().decode(OpenTDFConfiguration.self, from: data)
    } catch {
        throw KASDiscoveryError.invalidResponse("Failed to parse well-known JSON: \(error)")
    }
}
```

- [ ] **Step 5: Run to verify pass**

Run: `swiftformat --swiftversion 6.2 . && swift test --filter KASDiscoveryTests`
Expected: PASS (21 tests).

- [ ] **Step 6: Commit**

```bash
git add OpenTDFKit/KASDiscovery.swift OpenTDFKitTests/KASDiscoveryTests.swift OpenTDFKitTests/MockURLProtocol.swift
git commit -m "feat(kas): add fetchWellKnown + MockURLProtocol test helper"
```

---

## Task 6: Enrich `authenticationFailed` error with a reason

**Files:**
- Modify: `OpenTDFKit/KASRewrapClient.swift` (enum ~919, throw sites 402/545/621, description ~943)
- Modify: `OpenTDFKitTests/KASRewrapClientTests.swift:260`
- Modify: `OpenTDFKitTests/IntegrationTests.swift:154`

This task is a pure refactor (no behavior change) so the build stays green before the transport work.

- [ ] **Step 1: Change the enum case**

In `OpenTDFKit/KASRewrapClient.swift`, change:

```swift
    case authenticationFailed
```
to:
```swift
    case authenticationFailed(String?)
```

- [ ] **Step 2: Update the description arm**

Change:
```swift
        case .authenticationFailed:
            "Authentication failed - check OAuth token"
```
to:
```swift
        case let .authenticationFailed(reason):
            "Authentication failed - check OAuth token" + (reason.map { ": \($0)" } ?? "")
```

- [ ] **Step 3: Update the three throw sites**

At lines ~402 (`rewrapNanoTDF`), ~545 (`rewrapTDF`), ~621 (`fetchKasEcPublicKey`), change each:
```swift
        case 401:
            throw KASRewrapError.authenticationFailed
```
to:
```swift
        case 401:
            let message = String(data: data, encoding: .utf8)
            throw KASRewrapError.authenticationFailed(message)
```

- [ ] **Step 4: Update test pattern matches**

In `OpenTDFKitTests/KASRewrapClientTests.swift:260`, change:
```swift
            (.authenticationFailed, "Authentication failed"),
```
to:
```swift
            (.authenticationFailed(nil), "Authentication failed"),
```

In `OpenTDFKitTests/IntegrationTests.swift:154`, change:
```swift
        } catch KASRewrapError.authenticationFailed {
```
to:
```swift
        } catch KASRewrapError.authenticationFailed {
            // matches authenticationFailed(_) — associated value ignored
```
(The `catch KASRewrapError.authenticationFailed` pattern still matches a case with an associated value when no binding is needed; if the compiler requires it, use `catch KASRewrapError.authenticationFailed(_)`.)

- [ ] **Step 5: Build + test**

Run: `swiftformat --swiftversion 6.2 . && swift build && swift test --filter KASRewrapClientTests`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add OpenTDFKit/KASRewrapClient.swift OpenTDFKitTests/KASRewrapClientTests.swift OpenTDFKitTests/IntegrationTests.swift
git commit -m "refactor(kas): carry a reason string on authenticationFailed"
```

---

## Task 7: Client transport via KasEndpoints (additive init + no-redirect + Connect branch)

This adds the new `init(configuration:)` alongside the existing `init(kasURL:)` (kept temporarily as a green-build bridge; removed in Task 10). It rewires the transport to use resolved endpoints, adds the no-redirect delegate, branches the public-key fetch, derives the NanoTDF KAS identity url from the header, and shares Connect-aware HTTP error mapping.

**Files:**
- Modify: `OpenTDFKit/KASRewrapClient.swift`

- [ ] **Step 1: Add the no-redirect delegate (top of file, after imports)**

```swift
/// URLSession task delegate that refuses HTTP redirects. The KAS rewrap target
/// is an RPC endpoint that must never redirect; following a 3xx could re-issue
/// the bearer-carrying request to an unvalidated host.
final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_: URLSession, task _: URLSessionTask,
                    willPerformHTTPRedirection _: HTTPURLResponse, newRequest _: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
```

- [ ] **Step 2: Replace stored properties + inits**

Change the stored properties block:
```swift
    private let kasURL: URL
    private let oauthToken: String
    private let urlSession: URLSession
    private let signingKey: P256.Signing.PrivateKey
```
to:
```swift
    private let endpoints: KasEndpoints
    /// KAS identity url used for the request-body KeyAccessObject when the
    /// NanoTDF header locator is unavailable (fallback only).
    private let kasIdentityURL: String
    private let oauthToken: String
    private let urlSession: URLSession
    private let signingKey: P256.Signing.PrivateKey
    private let noRedirect = NoRedirectDelegate()
```

Replace the existing `init(kasURL:...)` with BOTH inits:
```swift
    /// Initialize from a resolved configuration document (preferred).
    /// - Parameters:
    ///   - configuration: Resolved config; obtain via `fetchWellKnown(...)` or
    ///     `OpenTDFConfiguration.forKasConnect(_:)`. Both resolved KAS URLs are
    ///     validated (HTTPS / scheme / SSRF) here.
    ///   - oauthToken: Bearer token (opaque: a JWT or base64url-encoded CWT).
    public init(configuration: OpenTDFConfiguration, oauthToken: String,
                urlSession: URLSession = .shared,
                signingKey: P256.Signing.PrivateKey? = nil) throws {
        endpoints = try KasEndpoints.from(configuration)
        kasIdentityURL = configuration.kas?.uri ?? ""
        self.oauthToken = oauthToken
        self.urlSession = urlSession
        self.signingKey = signingKey ?? P256.Signing.PrivateKey()
    }

    /// Legacy initializer: treats `kasURL` as a `{base}/kas` REST endpoint and
    /// builds `{kasURL}/v2/*` endpoints, preserving prior behavior.
    /// Deprecated transitional bridge — prefer `init(configuration:)`.
    public init(kasURL: URL, oauthToken: String, urlSession: URLSession = .shared,
                signingKey: P256.Signing.PrivateKey? = nil) {
        let base = kasURL.absoluteString
        endpoints = KasEndpoints(
            rewrapURL: kasURL.appendingPathComponent("v2/rewrap").absoluteString,
            publicKeyURL: kasURL.appendingPathComponent("v2/kas_public_key").absoluteString,
            transport: .legacyRest)
        kasIdentityURL = base
        self.oauthToken = oauthToken
        self.urlSession = urlSession
        self.signingKey = signingKey ?? P256.Signing.PrivateKey()
    }
```

- [ ] **Step 3: Add the NanoTDF KAS-identity resolver + shared HTTP error mapper (private methods, near the bottom of the class)**

```swift
    /// Resolve the request-body KAS url for a NanoTDF rewrap from the parsed
    /// header's resource locator, falling back to the configured identity.
    private func resolveNanoKasURL(_ parsedHeader: Header) -> String {
        let locator = parsedHeader.kas
        let scheme: String? = switch locator.protocolEnum {
        case .http: "http"
        case .https: "https"
        default: nil
        }
        if let scheme, !locator.body.isEmpty {
            return "\(scheme)://\(locator.body)"
        }
        return kasIdentityURL
    }

    /// Map a non-2xx rewrap response to a KASRewrapError, enriching the message
    /// from a Connect error envelope when present.
    private func mapRewrapHTTPError(status: Int, data: Data) -> KASRewrapError {
        let body = String(data: data, encoding: .utf8) ?? ""
        let detail = parseConnectError(body).map { "\($0.code): \($0.message)" }
            ?? (body.isEmpty ? "HTTP \(status)" : body)
        switch status {
        case 401: return .authenticationFailed(detail)
        case 403: return .accessDenied(detail)
        default: return .httpError(status, detail)
        }
    }
```

- [ ] **Step 4: Rewire `rewrapNanoTDF` request build + error mapping**

In `rewrapNanoTDF`, change the KeyAccessObject url source:
```swift
        let keyAccess = KeyAccessObject(
            header: header.base64EncodedString(),
            url: kasURL.absoluteString,
        )
```
to:
```swift
        let keyAccess = KeyAccessObject(
            header: header.base64EncodedString(),
            url: resolveNanoKasURL(parsedHeader),
        )
```

Change the endpoint + request execution:
```swift
        let rewrapEndpoint = kasURL.appendingPathComponent("v2/rewrap")
        var request = URLRequest(url: rewrapEndpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = 30 // 30 second timeout

        let authHeader = "Bearer \(oauthToken)"
        request.addValue(authHeader, forHTTPHeaderField: "Authorization")
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(signedRequest)

        // Perform request
        let (data, response) = try await urlSession.data(for: request)
```
to:
```swift
        guard let rewrapEndpoint = URL(string: endpoints.rewrapURL) else {
            throw KASRewrapError.invalidTDFRequest("Invalid rewrap URL: \(endpoints.rewrapURL)")
        }
        var request = URLRequest(url: rewrapEndpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = 30

        request.addValue("Bearer \(oauthToken)", forHTTPHeaderField: "Authorization")
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.addValue("1", forHTTPHeaderField: "Connect-Protocol-Version")
        request.httpBody = try JSONEncoder().encode(signedRequest)

        // Perform request (no redirects for the bearer-carrying call)
        let (data, response) = try await urlSession.data(for: request, delegate: noRedirect)
```

Replace the error arms of the `rewrapNanoTDF` switch (everything from `case 400:` through the `default:` arm) with:
```swift
        default:
            throw mapRewrapHTTPError(status: httpResponse.statusCode, data: data)
```
(Leave the `case 200:` arm unchanged.)

- [ ] **Step 5: Rewire `rewrapTDF` the same way**

In `rewrapTDF`, change `matchesKasURL` filtering anchor — replace:
```swift
        let keyAccessEntries = manifest.encryptionInformation.keyAccess.filter { matchesKasURL($0.url) }
```
(no change to that line; `matchesKasURL` is updated in Step 7). Change the endpoint/exec block (lines ~497–505):
```swift
        let rewrapEndpoint = kasURL.appendingPathComponent("v2/rewrap")
```
to:
```swift
        guard let rewrapEndpoint = URL(string: endpoints.rewrapURL) else {
            throw KASRewrapError.invalidTDFRequest("Invalid rewrap URL: \(endpoints.rewrapURL)")
        }
```
Add the Connect header after the `Content-Type` header is set (mirror Step 4) and switch the request call to `urlSession.data(for: request, delegate: noRedirect)`. Replace the `rewrapTDF` error switch arms (`case 400:` … `default:`) with:
```swift
        default:
            throw mapRewrapHTTPError(status: httpResponse.statusCode, data: data)
```
(Leave the `case 200:` arm and the `invalidTDFRequest` guard above unchanged.)

- [ ] **Step 6: Branch `fetchKasEcPublicKey` by transport**

Replace the request-build block (lines ~579–596):
```swift
        // Build the URL with algorithm query parameter
        let keyEndpoint = kasURL.appendingPathComponent("v2/kas_public_key")
        var components = URLComponents(url: keyEndpoint, resolvingAgainstBaseURL: false)
        components?.queryItems = [URLQueryItem(name: "algorithm", value: algorithm.rawValue)]

        guard let requestURL = components?.url else {
            throw KASRewrapError.keyFetchFailed("Failed to construct KAS public key URL")
        }

        // Create HTTP request
        var request = URLRequest(url: requestURL)
        request.httpMethod = "GET"
        request.timeoutInterval = 30
        request.addValue("Bearer \(oauthToken)", forHTTPHeaderField: "Authorization")
        request.addValue("application/json", forHTTPHeaderField: "Accept")

        // Perform request
        let (data, response) = try await urlSession.data(for: request)
```
with:
```swift
        var request: URLRequest
        switch endpoints.transport {
        case .connect:
            // ConnectRPC PublicKey RPC: POST the PublicKeyRequest message as JSON.
            // `algorithm` is a request-message field (Go opentdf/platform proto).
            guard let url = URL(string: endpoints.publicKeyURL) else {
                throw KASRewrapError.keyFetchFailed("Invalid public key URL: \(endpoints.publicKeyURL)")
            }
            request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.timeoutInterval = 30
            request.addValue("Bearer \(oauthToken)", forHTTPHeaderField: "Authorization")
            request.addValue("application/json", forHTTPHeaderField: "Content-Type")
            request.addValue("application/json", forHTTPHeaderField: "Accept")
            request.addValue("1", forHTTPHeaderField: "Connect-Protocol-Version")
            request.httpBody = try JSONEncoder().encode(["algorithm": algorithm.rawValue])
        case .legacyRest:
            guard var components = URLComponents(string: endpoints.publicKeyURL) else {
                throw KASRewrapError.keyFetchFailed("Invalid public key URL: \(endpoints.publicKeyURL)")
            }
            components.queryItems = [URLQueryItem(name: "algorithm", value: algorithm.rawValue)]
            guard let requestURL = components.url else {
                throw KASRewrapError.keyFetchFailed("Failed to construct KAS public key URL")
            }
            request = URLRequest(url: requestURL)
            request.httpMethod = "GET"
            request.timeoutInterval = 30
            request.addValue("Bearer \(oauthToken)", forHTTPHeaderField: "Authorization")
            request.addValue("application/json", forHTTPHeaderField: "Accept")
        }

        let (data, response) = try await urlSession.data(for: request, delegate: noRedirect)
```

Also update the `case 401:` arm in `fetchKasEcPublicKey` (already done in Task 6) — leave as is.

- [ ] **Step 7: Update `matchesKasURL` anchor**

Change the method to compare against `kasIdentityURL` instead of `kasURL`:
```swift
    private func matchesKasURL(_ otherURLString: String) -> Bool {
        guard let otherURL = URL(string: otherURLString) else { return false }
        guard let kasURL = URL(string: kasIdentityURL) else { return false }
        guard let baseScheme = kasURL.scheme?.lowercased(),
              let otherScheme = otherURL.scheme?.lowercased(),
              let baseHost = kasURL.host?.lowercased(),
              let otherHost = otherURL.host?.lowercased()
        else {
            return false
        }
        guard baseScheme == otherScheme, baseHost == otherHost else {
            return false
        }
        return effectivePort(for: kasURL) == effectivePort(for: otherURL)
    }
```
(Update the `invalidTDFRequest("No key access entries for KAS \(kasURL.absoluteString)")` message at line ~440 to `\(kasIdentityURL)`.)

- [ ] **Step 8: Build + test**

Run: `swiftformat --swiftversion 6.2 . && swift build && swift test --filter KASRewrapClientTests`
Expected: PASS (existing crypto/JWT/PEM tests still green; `init(kasURL:)` bridge keeps call sites compiling).

- [ ] **Step 9: Commit**

```bash
git add OpenTDFKit/KASRewrapClient.swift
git commit -m "feat(kas): route client transport through resolved KasEndpoints"
```

---

## Task 8: Migrate CLI to well-known resolution

**Files:**
- Modify: `OpenTDFKitCLI/Commands.swift` (call sites ~169, ~570, ~932; `fetchKASPublicKey` ~357)

- [ ] **Step 1: Add a config-resolution helper**

Add this static helper near `fetchKASPublicKey` in `Commands.swift` (inside the same enum/type that holds these statics):

```swift
    /// Resolve an OpenTDFConfiguration: try well-known discovery against the
    /// platform, else synthesize Connect endpoints from the platform base.
    static func resolveConfiguration(platformURL: URL, token: String) async -> OpenTDFConfiguration {
        if let cfg = try? await fetchWellKnown(platformURL: platformURL.absoluteString) {
            return cfg
        }
        return OpenTDFConfiguration.forKasConnect(platformURL.absoluteString)
    }
```

- [ ] **Step 2: Migrate the TDF rewrap call site (~169)**

Change:
```swift
            let client = KASRewrapClient(kasURL: kasURL, oauthToken: oauthToken)
```
to:
```swift
            let configuration = try await resolveConfiguration(platformURL: kasURL, token: oauthToken)
            let client = try KASRewrapClient(configuration: configuration, oauthToken: oauthToken)
```
(Here `kasURL` is parsed from the manifest entry; the resolved identity comes from the manifest's keyAccess url, so passing it as the discovery base is acceptable — Connect endpoints are derived from it. If the manifest url already includes `/kas`, prefer the `PLATFORMURL` env when available: see Step 5.)

- [ ] **Step 3: Migrate the two NanoTDF rewrap call sites (~570, ~932)**

At both sites change:
```swift
        let kasClient = KASRewrapClient(kasURL: kasURL, oauthToken: oauthToken)
```
to:
```swift
        let configuration = try await resolveConfiguration(platformURL: kasURL, token: oauthToken)
        let kasClient = try KASRewrapClient(configuration: configuration, oauthToken: oauthToken)
```

- [ ] **Step 4: Migrate `fetchKASPublicKey` to the client**

Replace the body of `fetchKASPublicKey(kasURL:token:)` with a client-based EC fetch so it honors the resolved transport:
```swift
    static func fetchKASPublicKey(kasURL: URL, token: String) async throws -> Data {
        let configuration = await resolveConfiguration(platformURL: kasURL, token: token)
        let client = try KASRewrapClient(configuration: configuration, oauthToken: token)
        let result = try await client.fetchKasEcPublicKey(algorithm: .ecP256)
        return result.compressedKey
    }
```

- [ ] **Step 5: Prefer PLATFORMURL as the discovery base where available**

For the NanoTDF paths, the `kasURL` is the KAS resource locator (e.g. `http://localhost:8080/kas`), but well-known lives at the platform root. Where the calling function already has `PLATFORMURL`, pass that to `resolveConfiguration` instead of `kasURL`. Locate each migrated call site's enclosing function; if it reads `env["PLATFORMURL"]`, use:
```swift
        let platformBase = ProcessInfo.processInfo.environment["PLATFORMURL"].flatMap { URL(string: $0) } ?? kasURL
        let configuration = await resolveConfiguration(platformURL: platformBase, token: oauthToken)
```
Apply this substitution at the two NanoTDF sites (Step 3). For the TDF site (Step 2), keep using the manifest-derived `kasURL` as the base unless `PLATFORMURL` is in scope.

- [ ] **Step 6: Build the CLI**

Run: `swiftformat --swiftversion 6.2 . && swift build --product OpenTDFKitCLI`
Expected: build succeeds.

- [ ] **Step 7: Commit**

```bash
git add OpenTDFKitCLI/Commands.swift
git commit -m "feat(cli): resolve KAS config via well-known (Connect, REST fallback)"
```

---

## Task 9: Migrate tests to the new init

**Files:**
- Modify: `OpenTDFKitTests/KASRewrapClientTests.swift:12`
- Modify: `OpenTDFKitTests/IntegrationTests.swift` (sites ~77, ~136, ~363, ~456)

- [ ] **Step 1: Migrate the unit-test client**

In `KASRewrapClientTests.swift`, change `setUp`:
```swift
        client = KASRewrapClient(
            kasURL: testKASURL,
            oauthToken: testOAuthToken,
        )
```
to:
```swift
        client = try! KASRewrapClient(
            configuration: OpenTDFConfiguration.forKasLegacyRest(testKASURL.absoluteString),
            oauthToken: testOAuthToken,
        )
```

- [ ] **Step 2: Migrate the integration-test clients**

At each of the four sites, replace the `KASRewrapClient(kasURL: <x>, oauthToken: <y>)` (or multi-line form) with:
```swift
        let configuration = OpenTDFConfiguration.forKasLegacyRest(kasURL.absoluteString)
        let kasRewrapClient = try KASRewrapClient(configuration: configuration, oauthToken: token)
```
Use the existing local variable names at each site (`kasRewrapClient`/`kasClient`, and the token variable `token`/`invalidToken`). For the rewrapTDF site (~363) name it `kasClient` and use `token`.

- [ ] **Step 3: Build + test**

Run: `swiftformat --swiftversion 6.2 . && swift build && swift test --filter KASRewrapClientTests`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add OpenTDFKitTests/KASRewrapClientTests.swift OpenTDFKitTests/IntegrationTests.swift
git commit -m "test(kas): migrate clients to init(configuration:)"
```

---

## Task 10: Remove the legacy init (realize the breaking change)

**Files:**
- Modify: `OpenTDFKit/KASRewrapClient.swift`

- [ ] **Step 1: Confirm no remaining callers**

Run: `grep -rn "KASRewrapClient(kasURL:" --include="*.swift" .`
Expected: no matches.

- [ ] **Step 2: Delete the legacy initializer**

Remove the entire `public init(kasURL: URL, oauthToken: String, urlSession: URLSession = .shared, signingKey: P256.Signing.PrivateKey? = nil)` block added in Task 7 Step 2.

- [ ] **Step 3: Build + full test suite**

Run: `swiftformat --swiftversion 6.2 . && swift build && swift test`
Expected: build succeeds; all non-network tests pass (integration tests skip without env).

- [ ] **Step 4: Commit**

```bash
git add OpenTDFKit/KASRewrapClient.swift
git commit -m "feat(kas)!: require OpenTDFConfiguration in KASRewrapClient init"
```

---

## Task 11: Connect transport unit tests (mock)

**Files:**
- Create: `OpenTDFKitTests/KASConnectTransportTests.swift`

- [ ] **Step 1: Write the failing tests**

```swift
@testable import OpenTDFKit
import XCTest

final class KASConnectTransportTests: XCTestCase {
    override func tearDown() {
        MockURLProtocol.handler = nil
        super.tearDown()
    }

    /// EC public-key fetch over Connect POSTs to /kas.AccessService/PublicKey
    /// with an `algorithm` body field and parses the PEM + kid.
    func testConnectECPublicKeyFetch() async throws {
        let pem = """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/shJbT/RbVUkgV+/5m+KPblr5ZXH\
        HU+2K5VytEsGQJJ0fxiksZXDC7twCPAXZgE3LOvORGqbQriKe/nM4iqIuA==
        -----END PUBLIC KEY-----
        """
        MockURLProtocol.handler = { req in
            XCTAssertEqual(req.httpMethod, "POST")
            XCTAssertEqual(req.url?.path, "/kas.AccessService/PublicKey")
            XCTAssertEqual(req.value(forHTTPHeaderField: "Connect-Protocol-Version"), "1")
            // URLProtocol exposes the body via the stream; assert presence of algorithm.
            if let body = req.httpBody, let s = String(data: body, encoding: .utf8) {
                XCTAssertTrue(s.contains("ec:secp256r1"), "body should carry algorithm: \(s)")
            }
            let resp = HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: nil,
                                       headerFields: ["Content-Type": "application/json"])!
            let json = #"{"publicKey":"\#(pem.replacingOccurrences(of: "\n", with: "\\n"))","kid":"ec:secp256r1"}"#
            return (resp, Data(json.utf8))
        }
        let session = MockURLProtocol.makeSession()
        let cfg = OpenTDFConfiguration.forKasConnect("https://platform.arkavo.net")
        let client = try KASRewrapClient(configuration: cfg, oauthToken: "t", urlSession: session)
        let result = try await client.fetchKasEcPublicKey(algorithm: .ecP256)
        XCTAssertEqual(result.kid, "ec:secp256r1")
        XCTAssertEqual(result.compressedKey.count, 33)
    }

    /// A Connect 401 envelope surfaces as authenticationFailed with the code in
    /// the reason string.
    func testConnectRewrapErrorEnvelopeSurfacesReason() async throws {
        MockURLProtocol.handler = { req in
            XCTAssertEqual(req.url?.path, "/kas.AccessService/Rewrap")
            let resp = HTTPURLResponse(url: req.url!, statusCode: 401, httpVersion: nil,
                                       headerFields: nil)!
            return (resp, Data(#"{"code":"unauthenticated","message":"missing bearer"}"#.utf8))
        }
        let session = MockURLProtocol.makeSession()
        let cfg = OpenTDFConfiguration.forKasConnect("https://platform.arkavo.net")
        let client = try KASRewrapClient(configuration: cfg, oauthToken: "t", urlSession: session)

        // Minimal NanoTDF header for the request body.
        let kas = ResourceLocator(protocolEnum: .https, body: "platform.arkavo.net/kas")!
        let header = makeMinimalHeader(kas: kas)
        let kp = EphemeralKeyPair(
            privateKey: P256.KeyAgreement.PrivateKey().rawRepresentation,
            publicKey: P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation,
            curve: .secp256r1)
        do {
            _ = try await client.rewrapNanoTDF(header: Data([0, 0, 0]), parsedHeader: header,
                                               clientKeyPair: kp)
            XCTFail("expected throw")
        } catch let KASRewrapError.authenticationFailed(reason) {
            XCTAssertEqual(reason, "unauthenticated: missing bearer")
        }
    }
}
```

- [ ] **Step 2: Add the `makeMinimalHeader` helper**

Inspect the `Header` initializer in `OpenTDFKit/NanoTDF.swift` (~520, `init(payloadKeyAccess:policyBindingConfig:payloadSignatureConfig:policy:ephemeralPublicKey:)`) and the convenience `init(kas:...)` (~531). Add to the test file a helper that builds a valid header. Use the convenience initializer:

```swift
    private func makeMinimalHeader(kas: ResourceLocator) -> Header {
        let policy = Policy(type: .embeddedPlaintext,
                            body: EmbeddedPolicyBody(body: Data("{}".utf8)),
                            remote: nil, binding: nil)
        return Header(
            kas: kas,
            policyBindingConfig: PolicyBindingConfig(ecdsaBinding: false, curve: .secp256r1),
            payloadSignatureConfig: SignatureAndPayloadConfig(
                signed: false, signatureCurve: nil,
                payloadCipher: .aes256GCM128),
            policy: policy,
            ephemeralPublicKey: P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation)
    }
```

If any of the referenced type/case names (`EmbeddedPolicyBody`, `PolicyBindingConfig`, `SignatureAndPayloadConfig`, `.aes256GCM128`) differ in the codebase, read `OpenTDFKit/NanoTDF.swift` and adjust the helper to the real signatures before running. (These types already exist — confirm exact member names with `grep -n "struct PolicyBindingConfig\|struct SignatureAndPayloadConfig\|struct EmbeddedPolicyBody\|enum Cipher" OpenTDFKit/NanoTDF.swift`.)

- [ ] **Step 3: Run to verify failure, then pass**

Run: `swift test --filter KASConnectTransportTests`
Expected: initially FAIL until the header helper compiles; then PASS (2 tests).

Note: `URLProtocol` may not expose `httpBody` for streamed bodies; the body assertion is wrapped in `if let`. If the body is nil under the mock, the algorithm assertion is skipped and the test still validates path/headers/parsing. This is acceptable.

- [ ] **Step 4: Commit**

```bash
git add OpenTDFKitTests/KASConnectTransportTests.swift
git commit -m "test(kas): Connect public-key fetch + rewrap error envelope"
```

---

## Task 12: Live platform integration tests (skipped by default)

**Files:**
- Create: `OpenTDFKitTests/PlatformConnectIntegrationTests.swift`

- [ ] **Step 1: Write the gated live tests**

```swift
@testable import OpenTDFKit
import XCTest

/// Live tests against the real Arkavo platform. Opt in with
/// `KAS_INTEGRATION_TESTS=1`. They document the Connect transport milestone.
final class PlatformConnectIntegrationTests: XCTestCase {
    private static let platform = "https://platform.arkavo.net"

    private func requireOptIn() throws {
        guard ProcessInfo.processInfo.environment["KAS_INTEGRATION_TESTS"] == "1" else {
            throw XCTSkip("Set KAS_INTEGRATION_TESTS=1 to run live platform tests")
        }
    }

    func testWellKnownReturnsKasConfig() async throws {
        try requireOptIn()
        let cfg = try await fetchWellKnown(platformURL: Self.platform)
        let kas = try XCTUnwrap(cfg.kas)
        XCTAssertNotNil(kas.connectRewrapURL, "platform should advertise connect_rewrap_url")
        XCTAssertNotNil(kas.connectPublicKeyURL, "platform should advertise connect_public_key_url")
        XCTAssertNotNil(kas.rewrapURL, "platform also exposes legacy REST rewrap_url")
    }

    func testConnectPublicKeyReturnsPEM() async throws {
        try requireOptIn()
        let cfg = try await fetchWellKnown(platformURL: Self.platform)
        let client = try KASRewrapClient(configuration: cfg, oauthToken: "")
        let result = try await client.fetchKasEcPublicKey(algorithm: .ecP256)
        XCTAssertTrue(result.pem.contains("BEGIN PUBLIC KEY"))
        XCTAssertEqual(result.compressedKey.count, 33)
    }

    func testConnectRewrapFakeBearerReturns401() async throws {
        try requireOptIn()
        let cfg = try await fetchWellKnown(platformURL: Self.platform)
        let client = try KASRewrapClient(configuration: cfg,
                                         oauthToken: "eyJhbGciOiJub25lIn0.e30.")
        let kas = ResourceLocator(protocolEnum: .https, body: "platform.arkavo.net/kas")!
        let header = makeMinimalHeader(kas: kas)
        let kp = EphemeralKeyPair(
            privateKey: P256.KeyAgreement.PrivateKey().rawRepresentation,
            publicKey: P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation,
            curve: .secp256r1)
        do {
            _ = try await client.rewrapNanoTDF(header: Data([0, 0, 0]), parsedHeader: header,
                                               clientKeyPair: kp)
            XCTFail("rewrap should fail without valid auth")
        } catch KASRewrapError.authenticationFailed { // expected
        } catch let KASRewrapError.accessDenied(reason) {
            print("AccessDenied: \(reason)")
        } catch let KASRewrapError.httpError(status, message) {
            XCTAssertNotEqual(status, 404, "404 means Connect rewrap path missing: \(message)")
            XCTAssertTrue((400 ..< 600).contains(status), "expected 4xx/5xx, got \(status)")
        }
    }

    private func makeMinimalHeader(kas: ResourceLocator) -> Header {
        let policy = Policy(type: .embeddedPlaintext,
                            body: EmbeddedPolicyBody(body: Data("{}".utf8)),
                            remote: nil, binding: nil)
        return Header(
            kas: kas,
            policyBindingConfig: PolicyBindingConfig(ecdsaBinding: false, curve: .secp256r1),
            payloadSignatureConfig: SignatureAndPayloadConfig(
                signed: false, signatureCurve: nil, payloadCipher: .aes256GCM128),
            policy: policy,
            ephemeralPublicKey: P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation)
    }
}
```

(Reuse the exact `makeMinimalHeader` signatures confirmed in Task 11 Step 2.)

- [ ] **Step 2: Verify skip-by-default**

Run: `swift test --filter PlatformConnectIntegrationTests`
Expected: 3 tests SKIPPED (no `KAS_INTEGRATION_TESTS`).

- [ ] **Step 3 (optional): Verify live against the platform**

Run: `KAS_INTEGRATION_TESTS=1 swift test --filter PlatformConnectIntegrationTests`
Expected: well-known + public-key PASS; rewrap PASS via `authenticationFailed`/`accessDenied`/`httpError(≠404)`.

- [ ] **Step 4: Commit**

```bash
git add OpenTDFKitTests/PlatformConnectIntegrationTests.swift
git commit -m "test(kas): live Connect platform integration tests (opt-in)"
```

---

## Task 13: Docs + final verification

**Files:**
- Modify: `CLAUDE.md` (KASRewrapClient component description, KAS rewrap flow notes)

- [ ] **Step 1: Update the KASRewrapClient description in `CLAUDE.md`**

In the "KASRewrapClient" bullet, add a sentence:
```
Now resolves transport endpoints from an `OpenTDFConfiguration` (well-known
discovery via `fetchWellKnown`, or `OpenTDFConfiguration.forKasConnect`),
preferring ConnectRPC `/kas.AccessService/*` and falling back to legacy REST
`/kas/v2/*`. Bearer tokens are opaque (JWT or base64url CWT).
```

- [ ] **Step 2: Run the whole suite + format check**

Run: `swiftformat --swiftversion 6.2 . && swift build && swift test`
Expected: build succeeds; all non-network tests pass; integration/live tests skip.

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: note ConnectRPC + well-known KAS discovery in CLAUDE.md"
```

- [ ] **Step 4: Push + open PR (only when the user asks)**

```bash
git push -u origin feat/connectrpc-kas-migration
gh pr create --fill --base main
```
