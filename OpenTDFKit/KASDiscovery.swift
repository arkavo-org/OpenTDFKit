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
