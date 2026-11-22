import Darwin
import Foundation

// MARK: - Helpers

/// Strip any trailing `/` characters from a base URL string.
private func trimmingTrailingSlashes(_ s: String) -> String {
    var result = s
    while result.hasSuffix("/") {
        result.removeLast()
    }
    return result
}

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
        let base = trimmingTrailingSlashes(baseURL)
        return OpenTDFConfiguration(
            kas: KasConfig(
                uri: base,
                algorithms: [],
                publicKeyURL: nil,
                rewrapURL: nil,
                connectPublicKeyURL: "\(base)/kas.AccessService/PublicKey",
                connectRewrapURL: "\(base)/kas.AccessService/Rewrap",
            ),
            idp: nil,
            platformIssuer: nil,
        )
    }

    /// Synthesize a legacy-REST configuration for a single KAS base URL.
    public static func forKasLegacyRest(_ baseURL: String) -> OpenTDFConfiguration {
        let base = trimmingTrailingSlashes(baseURL)
        return OpenTDFConfiguration(
            kas: KasConfig(
                uri: base,
                algorithms: [],
                publicKeyURL: "\(base)/kas/v2/kas_public_key",
                rewrapURL: "\(base)/kas/v2/rewrap",
                connectPublicKeyURL: nil,
                connectRewrapURL: nil,
            ),
            idp: nil,
            platformIssuer: nil,
        )
    }

    /// If well-known omitted a usable `kas` advertisement, synthesize Connect
    /// endpoints for `fallbackBaseURL` while preserving any `idp` /
    /// `platformIssuer`. Returns self unchanged when a `kas` block already
    /// advertises Connect or REST endpoint URLs.
    ///
    /// Local platforms often serve `/.well-known/opentdf-configuration` with
    /// IdP metadata but no `kas` block; Stage-1 clients must fall back to the
    /// default KAS URL (typically `PLATFORMURL` / stripped `KASURL`) rather
    /// than fail with "missing a 'kas' block".
    ///
    /// **Does not** replace a present kas block whose endpoints fail
    /// validation (SSRF, non-HTTPS, empty host, etc.). Those failures must
    /// propagate from `KasEndpoints.from` so hostile well-known documents
    /// cannot be quietly rewritten to a different KAS identity.
    public func withKasFallback(baseURL: String) -> OpenTDFConfiguration {
        guard needsKasEndpointSynthesis else {
            return self
        }
        let synthesized = OpenTDFConfiguration.forKasConnect(baseURL)
        return OpenTDFConfiguration(
            kas: synthesized.kas,
            idp: idp,
            platformIssuer: platformIssuer,
        )
    }

    /// True when well-known has no kas block or advertises no endpoint URLs at
    /// all. False whenever any endpoint URL is present (even if `kas.uri` is
    /// empty or an endpoint would fail later SSRF/scheme validation), so hostile
    /// or misconfigured kas blocks are never silently overridden.
    var needsKasEndpointSynthesis: Bool {
        guard let kas else { return true }
        let hasAnyEndpoint = kas.connectRewrapURL != nil
            || kas.connectPublicKeyURL != nil
            || kas.rewrapURL != nil
            || kas.publicKeyURL != nil
        if hasAnyEndpoint {
            return false
        }
        return true
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
                connectPublicKeyURL: String?, connectRewrapURL: String?)
    {
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

// MARK: - Errors

public enum KASDiscoveryError: Error, CustomStringConvertible, Sendable {
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
    case v4([UInt8]) // 4 bytes, network order
    case v6([UInt8]) // 16 bytes, network order
}

private func stripIPv6Brackets(_ host: String) -> String {
    if host.hasPrefix("["), host.hasSuffix("]"), host.count >= 2 {
        return String(host.dropFirst().dropLast())
    }
    return host
}

private func isNonCanonicalIPv4Literal(_ host: String) -> Bool {
    let trimmed = host.hasSuffix(".") ? String(host.dropLast()) : host
    guard !trimmed.isEmpty else { return false }
    // IPv6 literals contain colons and are validated by classifyIP.
    if trimmed.contains(":") {
        return false
    }

    // Check dot-separated numeric forms explicitly before inet_pton because
    // some parsers accept leading zeros (octal ambiguity) or normalize forms.
    let parts = trimmed.split(separator: ".", omittingEmptySubsequences: false)
    if (1 ... 4).contains(parts.count), parts.allSatisfy({ part in
        guard !part.isEmpty else { return false }
        if part.hasPrefix("0x") || part.hasPrefix("0X") {
            let digits = part.dropFirst(2)
            return !digits.isEmpty && digits.allSatisfy(\.isHexDigit)
        }
        return part.allSatisfy { $0.isASCII && $0.isNumber }
    }) {
        // Canonical IPv4 requires exactly 4 decimal octets in 0...255 with no leading zeros.
        let isCanonicalV4 = parts.count == 4 && parts.allSatisfy { part in
            if part.count > 1, part.hasPrefix("0") {
                return false
            }
            return UInt8(part) != nil
        }
        return !isCanonicalV4
    }

    // If BSD inet_aton accepts a host that strict inet_pton rejected, it is a
    // non-canonical numeric IPv4 form.
    var v4 = in_addr()
    if trimmed.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
        return false
    }
    var legacy = in_addr()
    if trimmed.withCString({ inet_aton($0, &legacy) }) != 0 {
        return true
    }
    return false
}

/// Extracts the unnormalized host portion from a URL string's authority so
/// non-canonical numeric forms (like octal IPv4) are caught even if Foundation
/// normalizes `url.host`.
private func rawAuthorityHost(from urlString: String) -> String? {
    guard let schemeEnd = urlString.range(of: "://") else { return nil }
    let afterScheme = urlString[schemeEnd.upperBound...]
    let authorityEnd = afterScheme.firstIndex { $0 == "/" || $0 == "?" || $0 == "#" } ?? afterScheme.endIndex
    var authority = afterScheme[..<authorityEnd]
    if let atIndex = authority.lastIndex(of: "@") {
        authority = authority[authority.index(after: atIndex)...]
    }
    if authority.hasPrefix("[") {
        guard let closeBracket = authority.firstIndex(of: "]") else { return nil }
        return String(authority[authority.index(after: authority.startIndex) ..< closeBracket])
    }
    if let colon = authority.firstIndex(of: ":") {
        return String(authority[..<colon])
    }
    return String(authority)
}

private func classifyIP(_ host: String) -> IPLiteral? {
    let normalized = stripIPv6Brackets(host)
    var v4 = in_addr()
    if normalized.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
        return .v4(withUnsafeBytes(of: v4.s_addr) { Array($0) })
    }
    var v6 = in6_addr()
    if normalized.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
        return .v6(withUnsafeBytes(of: v6) { Array($0) })
    }
    return nil
}

private func isLoopbackHost(_ host: String) -> Bool {
    // Normalize case and trailing FQDN dot ("LOCALHOST." resolves to loopback too).
    let stripped = stripIPv6Brackets(host).lowercased()
    let normalized = stripped.hasSuffix(".") ? String(stripped.dropLast()) : stripped
    if normalized == "localhost" {
        return true
    }
    switch classifyIP(normalized) {
    case let .v4(o): return o[0] == 127 // 127.0.0.0/8
    case let .v6(b): return b.dropLast() == ArraySlice(repeating: 0, count: 15) && b[15] == 1 // ::1
    case .none: return false
    }
}

private func isBlockedV4(_ o: [UInt8]) -> Bool {
    // 0.0.0.0/8 ("this network" / unspecified)
    if o[0] == 0 {
        return true
    }
    // 10.0.0.0/8 (RFC 1918)
    if o[0] == 10 {
        return true
    }
    // 100.64.0.0/10 (RFC 6598 CGNAT / shared address space)
    if o[0] == 100, (o[1] & 0xC0) == 64 {
        return true
    }
    // 169.254.0.0/16 (link-local / cloud metadata)
    if o[0] == 169, o[1] == 254 {
        return true
    }
    // 172.16.0.0/12 (RFC 1918)
    if o[0] == 172, (o[1] & 0xF0) == 16 {
        return true
    }
    // 192.168.0.0/16 (RFC 1918)
    if o[0] == 192, o[1] == 168 {
        return true
    }
    // 224.0.0.0/4 (multicast) and 240.0.0.0/4 (reserved / broadcast 255.255.255.255)
    if (o[0] & 0xE0) == 224 {
        return true
    }
    return false
}

private func isBlockedIP(_ ip: IPLiteral) -> Bool {
    switch ip {
    case let .v4(o):
        return isBlockedV4(o)
    case let .v6(b):
        // ::/128 unspecified
        if b.allSatisfy({ $0 == 0 }) {
            return true
        }
        // ::ffff:0:0/96 (IPv4-mapped IPv6, including ::ffff:127.0.0.1 and ::ffff:169.254.169.254)
        if b[0 ..< 10].allSatisfy({ $0 == 0 }), b[10] == 0xFF, b[11] == 0xFF {
            return true
        }
        // ::ffff:0:0:0/96 (IPv4-translated)
        if b[0 ..< 8].allSatisfy({ $0 == 0 }), b[8] == 0xFF, b[9] == 0xFF, b[10] == 0, b[11] == 0 {
            return true
        }
        // 64:ff9b::/96 (NAT64 well-known prefix, RFC 6052) and 64:ff9b:1::/48 (RFC 8215)
        if b[0] == 0x00, b[1] == 0x64, b[2] == 0xFF, b[3] == 0x9B {
            if b[4 ..< 12].allSatisfy({ $0 == 0 }) {
                return true
            }
            if b[4] == 0x00, b[5] == 0x01 {
                return true
            }
        }
        // ff00::/8 multicast
        if b[0] == 0xFF {
            return true
        }
        let first = (UInt16(b[0]) << 8) | UInt16(b[1])
        // fc00::/7 ULA, fe80::/10 link-local, fec0::/10 deprecated site-local
        return (first & 0xFE00) == 0xFC00
            || (first & 0xFFC0) == 0xFE80
            || (first & 0xFFC0) == 0xFEC0
    }
}

/// Validate a KAS URL for scheme / HTTPS / SSRF constraints.
///
/// - `http` is allowed only for loopback hosts (`localhost`, `127.0.0.0/8`, `::1`).
/// - Rejects URL userinfo, IPv6 zone IDs (`%`), non-canonical IPv4 literals
///   (integer, hex, octal, shorthand), and private, CGNAT, link-local,
///   multicast, reserved, NAT64, IPv4-mapped IPv6, and unspecified addresses.
public func validateKasURL(_ urlString: String) throws {
    guard let url = URL(string: urlString), let scheme = url.scheme?.lowercased() else {
        throw KASDiscoveryError.invalidURL("Failed to parse URL: \(urlString)")
    }
    guard url.user == nil, url.password == nil else {
        throw KASDiscoveryError.invalidURL("KAS URL must not contain userinfo")
    }
    let rawHost = url.host ?? ""
    guard !rawHost.isEmpty else {
        throw KASDiscoveryError.invalidURL("KAS URL must have a non-empty host")
    }
    guard !rawHost.contains("%") else {
        throw KASDiscoveryError.invalidURL("KAS URL host must not contain IPv6 zone identifiers")
    }
    let host = stripIPv6Brackets(rawHost)
    if isNonCanonicalIPv4Literal(host) {
        throw KASDiscoveryError.invalidURL("KAS URL must not use non-canonical IPv4 notation")
    }
    if let unnormalizedHost = rawAuthorityHost(from: urlString),
       unnormalizedHost.contains("%") || isNonCanonicalIPv4Literal(unnormalizedHost)
    {
        throw KASDiscoveryError.invalidURL("KAS URL must not use non-canonical IPv4 notation or zone identifiers")
    }

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
        throw KASDiscoveryError.invalidURL("KAS URL must not target private, reserved, or link-local IP addresses")
    }
}

// MARK: - Endpoint resolution

/// The wire protocol used to communicate with a KAS.
public enum KasTransport: Sendable, Equatable {
    /// ConnectRPC endpoints at /kas.AccessService/*
    case connect
    /// Legacy REST gateway at /kas/v2/*
    case legacyRest
}

/// Resolved, validated KAS endpoint URLs and their associated transport.
public struct KasEndpoints: Sendable, Equatable {
    public let rewrapURL: String
    public let publicKeyURL: String
    public let transport: KasTransport

    public init(rewrapURL: String, publicKeyURL: String, transport: KasTransport) {
        self.rewrapURL = rewrapURL
        self.publicKeyURL = publicKeyURL
        self.transport = transport
    }

    /// Resolve KAS endpoints, preferring ConnectRPC URLs and falling back to
    /// legacy REST when only REST is advertised. Both resolved URLs are
    /// validated (HTTPS / scheme / SSRF) before returning.
    public static func from(_ config: OpenTDFConfiguration) throws -> KasEndpoints {
        guard let kas = config.kas else {
            throw KASDiscoveryError.configError("well-known configuration is missing a 'kas' block")
        }
        // `kas.uri` is the KAS identity used to match manifest key-access entries
        // (see KASRewrapClient.matchesKasURL). An empty uri would silently match
        // nothing, so reject it here rather than failing later in rewrapTDF.
        guard !kas.uri.isEmpty else {
            throw KASDiscoveryError.configError("well-known kas block has an empty 'uri'")
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

// MARK: - Bounded, No-Redirect HTTP Helper

enum BoundedHTTPError: Error, Sendable {
    case nonHTTPResponse
    case responseTooLarge(Int)
}

/// Executes a URLRequest on `session` while refusing HTTP redirects and enforcing
/// a strict upper bound on buffered response bytes to prevent OOM DoS.
enum BoundedHTTPClient {
    static let defaultWellKnownMaxBytes = 1 * 1024 * 1024 // 1 MiB
    static let defaultKASMaxBytes = 16 * 1024 * 1024 // 16 MiB

    static func send(
        _ request: URLRequest,
        on session: URLSession,
        maxBytes: Int,
    ) async throws -> (Data, HTTPURLResponse) {
        let delegate = Delegate(maxBytes: maxBytes)
        let task = session.dataTask(with: request)
        task.delegate = delegate

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                delegate.start(task: task, continuation: continuation)
            }
        } onCancel: {
            task.cancel()
        }
    }

    private final class Delegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
        private let maxBytes: Int
        private let lock = NSLock()
        private var continuation: CheckedContinuation<(Data, HTTPURLResponse), Error>?
        private var httpResponse: HTTPURLResponse?
        private var buffer = Data()
        private var overflowed = false
        private var finished = false

        init(maxBytes: Int) {
            self.maxBytes = maxBytes
        }

        func start(
            task: URLSessionDataTask,
            continuation: CheckedContinuation<(Data, HTTPURLResponse), Error>,
        ) {
            lock.withLock {
                self.continuation = continuation
            }
            task.resume()
        }

        private func finish(with result: Result<(Data, HTTPURLResponse), Error>) {
            let cont: CheckedContinuation<(Data, HTTPURLResponse), Error>? = lock.withLock {
                guard !finished else { return nil }
                finished = true
                let c = continuation
                continuation = nil
                return c
            }
            cont?.resume(with: result)
        }

        func urlSession(
            _: URLSession,
            task _: URLSessionTask,
            willPerformHTTPRedirection _: HTTPURLResponse,
            newRequest _: URLRequest,
            completionHandler: @escaping (URLRequest?) -> Void,
        ) {
            completionHandler(nil)
        }

        func urlSession(
            _: URLSession,
            dataTask _: URLSessionDataTask,
            didReceive response: URLResponse,
            completionHandler: @escaping (URLSession.ResponseDisposition) -> Void,
        ) {
            guard let http = response as? HTTPURLResponse else {
                completionHandler(.cancel)
                finish(with: .failure(BoundedHTTPError.nonHTTPResponse))
                return
            }
            if http.expectedContentLength > 0, http.expectedContentLength > Int64(maxBytes) {
                lock.withLock { overflowed = true }
                completionHandler(.cancel)
                finish(with: .failure(BoundedHTTPError.responseTooLarge(maxBytes)))
                return
            }
            lock.withLock {
                httpResponse = http
            }
            completionHandler(.allow)
        }

        func urlSession(_: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
            let exceeded: Bool = lock.withLock {
                if overflowed || finished {
                    return true
                }
                if buffer.count > maxBytes - data.count {
                    overflowed = true
                    buffer.removeAll(keepingCapacity: false)
                    return true
                }
                buffer.append(data)
                return false
            }
            if exceeded {
                dataTask.cancel()
                finish(with: .failure(BoundedHTTPError.responseTooLarge(maxBytes)))
            }
        }

        func urlSession(_: URLSession, task _: URLSessionTask, didCompleteWithError error: Error?) {
            let (isOverflow, response, data) = lock.withLock {
                (overflowed, httpResponse, buffer)
            }
            if isOverflow {
                finish(with: .failure(BoundedHTTPError.responseTooLarge(maxBytes)))
                return
            }
            if let error {
                finish(with: .failure(error))
                return
            }
            guard let response else {
                finish(with: .failure(BoundedHTTPError.nonHTTPResponse))
                return
            }
            finish(with: .success((data, response)))
        }
    }
}

// MARK: - Well-known discovery

/// Fetch the platform's /.well-known/opentdf-configuration document.
/// `platformURL` is the platform base (e.g. "https://platform.arkavo.net"); a
/// trailing slash is tolerated.
public func fetchWellKnown(platformURL: String,
                           urlSession: URLSession = .shared) async throws -> OpenTDFConfiguration
{
    let base = trimmingTrailingSlashes(platformURL)
    let urlString = "\(base)/.well-known/opentdf-configuration"
    try validateKasURL(urlString)
    guard let url = URL(string: urlString) else {
        throw KASDiscoveryError.invalidURL("Failed to parse URL: \(urlString)")
    }

    var request = URLRequest(url: url)
    request.httpMethod = "GET"
    request.timeoutInterval = 30
    request.addValue("application/json", forHTTPHeaderField: "Accept")

    let data: Data
    let http: HTTPURLResponse
    do {
        (data, http) = try await BoundedHTTPClient.send(
            request,
            on: urlSession,
            maxBytes: BoundedHTTPClient.defaultWellKnownMaxBytes,
        )
    } catch BoundedHTTPError.nonHTTPResponse {
        throw KASDiscoveryError.invalidResponse("Non-HTTP response from \(url.host ?? "platform")")
    } catch let BoundedHTTPError.responseTooLarge(limit) {
        throw KASDiscoveryError.invalidResponse("Well-known response exceeded \(limit)-byte limit")
    }

    guard (200 ..< 300).contains(http.statusCode) else {
        let connectCode = String(data: data, encoding: .utf8).flatMap(parseConnectError)?.code
        let detail = connectCode.map { "HTTP \(http.statusCode) (\($0))" } ?? "HTTP \(http.statusCode)"
        throw KASDiscoveryError.httpError(http.statusCode, detail)
    }

    do {
        return try JSONDecoder().decode(OpenTDFConfiguration.self, from: data)
    } catch {
        throw KASDiscoveryError.invalidResponse("Failed to parse well-known JSON: \(error)")
    }
}

// MARK: - Connect error envelope

/// Error envelope returned by Connect unary-JSON RPCs on non-2xx responses.
public struct ConnectError: Codable, Sendable {
    public let code: String
    public let message: String
}

/// Parse a Connect error envelope from a response body. Returns nil for empty,
/// non-JSON, or shapes lacking a non-empty `code`.
public func parseConnectError(_ body: String) -> ConnectError? {
    guard !body.isEmpty, let data = body.data(using: .utf8), let parsed = try? JSONDecoder().decode(ConnectError.self, from: data) else { return nil }
    return parsed.code.isEmpty ? nil : parsed
}
