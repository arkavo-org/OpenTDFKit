import Darwin
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
                connectRewrapURL: "\(base)/kas.AccessService/Rewrap",
            ),
            idp: nil,
            platformIssuer: nil,
        )
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
                connectRewrapURL: nil,
            ),
            idp: nil,
            platformIssuer: nil,
        )
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
    case let .v4(o): return o[0] == 127 // 127.0.0.0/8
    case let .v6(b): return b.dropLast() == ArraySlice(repeating: 0, count: 15) && b[15] == 1 // ::1
    case .none: return false
    }
}

private func isBlockedV4(_ o: [UInt8]) -> Bool {
    if o[0] == 10 { return true } // 10.0.0.0/8
    if o[0] == 172, (o[1] & 0xF0) == 16 { return true } // 172.16.0.0/12
    if o[0] == 192, o[1] == 168 { return true } // 192.168.0.0/16
    if o[0] == 169, o[1] == 254 { return true } // 169.254.0.0/16
    if o == [0, 0, 0, 0] { return true } // 0.0.0.0
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
///
/// - `http` is allowed only for loopback hosts (`localhost`, `127.0.0.0/8`, `::1`).
/// - Private, link-local, and unspecified IPs are rejected (IPv4, IPv6 ULA/link-local,
///   and IPv4-mapped IPv6 literals folded back to IPv4).
public func validateKasURL(_ urlString: String) throws {
    guard let url = URL(string: urlString), let scheme = url.scheme?.lowercased() else {
        throw KASDiscoveryError.invalidURL("Failed to parse URL: \(urlString)")
    }
    let host = url.host ?? ""
    guard !host.isEmpty else {
        throw KASDiscoveryError.invalidURL("KAS URL must have a non-empty host")
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
        throw KASDiscoveryError.invalidURL("KAS URL must not target private or link-local IP addresses")
    }
}
