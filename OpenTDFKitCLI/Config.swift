import Foundation

/// Configuration from xtest environment variables
struct Config {
    let clientId: String
    let clientSecret: String
    let kasURL: String
    let platformURL: String

    // Optional parameters from xtest environment
    let withMimeType: String?
    let withAttributes: [String]
    let withAssertions: String?
    let withAssertionVerificationKeys: String?
    let withVerifyAssertions: Bool
    let withECDSABinding: Bool
    let withECWrap: Bool
    let withPlaintextPolicy: Bool
    let withTargetMode: String?
    let withKasAllowlist: [String]
    let withIgnoreKasAllowlist: Bool

    static func fromEnvironment() throws -> Config {
        let env = ProcessInfo.processInfo.environment

        // Required environment variables
        guard let clientId = env["CLIENTID"] else {
            throw ConfigError.missingRequired("CLIENTID")
        }
        guard let clientSecret = env["CLIENTSECRET"] else {
            throw ConfigError.missingRequired("CLIENTSECRET")
        }
        guard let kasURL = env["KASURL"] else {
            throw ConfigError.missingRequired("KASURL")
        }
        guard let platformURL = env["PLATFORMURL"] else {
            throw ConfigError.missingRequired("PLATFORMURL")
        }

        let attributes = parseCommaSeparated(env["XT_WITH_ATTRIBUTES"])
        let kasAllowlist = parseCommaSeparated(
            env["XT_WITH_KAS_ALLOWLIST"] ?? env["XT_WITH_KAS_ALLOW_LIST"],
        )

        return Config(
            clientId: clientId,
            clientSecret: clientSecret,
            kasURL: kasURL,
            platformURL: platformURL,
            withMimeType: env["XT_WITH_MIME_TYPE"],
            withAttributes: attributes,
            withAssertions: env["XT_WITH_ASSERTIONS"],
            withAssertionVerificationKeys: env["XT_WITH_ASSERTION_VERIFICATION_KEYS"],
            withVerifyAssertions: env["XT_WITH_VERIFY_ASSERTIONS"] == "true",
            withECDSABinding: env["XT_WITH_ECDSA_BINDING"] == "true",
            withECWrap: env["XT_WITH_ECWRAP"] == "true",
            withPlaintextPolicy: env["XT_WITH_PLAINTEXT_POLICY"] == "true",
            withTargetMode: env["XT_WITH_TARGET_MODE"],
            withKasAllowlist: kasAllowlist,
            withIgnoreKasAllowlist: env["XT_WITH_IGNORE_KAS_ALLOWLIST"] == "true",
        )
    }

    /// Comma-separated env list → trimmed non-empty tokens.
    static func parseCommaSeparated(_ raw: String?) -> [String] {
        (raw ?? "")
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// `XT_WITH_ATTRIBUTES` FQNs as go SDK `attributeObject` entries: `{"attribute":"<fqn>"}`.
    static func attributeObjectsFromEnvironment(
        env: [String: String] = ProcessInfo.processInfo.environment,
    ) -> [[String: String]] {
        parseCommaSeparated(env["XT_WITH_ATTRIBUTES"]).map { ["attribute": $0] }
    }

    /// Default TDF policy JSON body for encrypt when no TDF_POLICY_* override is set.
    static func defaultPolicyData(
        env: [String: String] = ProcessInfo.processInfo.environment,
    ) throws -> Data {
        let policy: [String: Any] = [
            "uuid": UUID().uuidString.lowercased(),
            "body": [
                "dataAttributes": attributeObjectsFromEnvironment(env: env),
                "dissem": [] as [Any],
            ],
        ]
        guard JSONSerialization.isValidJSONObject(policy),
              let data = try? JSONSerialization.data(withJSONObject: policy, options: [.sortedKeys])
        else {
            throw ConfigError.invalidPolicy
        }
        return data
    }
}

enum ConfigError: Error, CustomStringConvertible {
    case missingRequired(String)
    case invalidPolicy

    var description: String {
        switch self {
        case let .missingRequired(name):
            "Required environment variable '\(name)' is not set"
        case .invalidPolicy:
            "Unable to create default policy JSON"
        }
    }
}

/// TDF format types supported by xtest (Base / standard TDF ZIP, not NATO ZTDF).
enum TDFFormat: String {
    case nano
    case tdf
    /// Legacy wire name used by some xtest shims for Base TDF ZIP — treated as `tdf`.
    case tdfLegacyWire = "ztdf"
    case tdfECWrap = "tdf-ecwrap"
    /// Legacy alias for `tdf-ecwrap`.
    case tdfECWrapLegacy = "ztdf-ecwrap"
    case nanoWithECDSA = "nano-with-ecdsa"

    var isNano: Bool {
        switch self {
        case .nano, .nanoWithECDSA:
            true
        case .tdf, .tdfLegacyWire, .tdfECWrap, .tdfECWrapLegacy:
            false
        }
    }

    var useECDSA: Bool {
        self == .nanoWithECDSA
    }

    var useECWrap: Bool {
        self == .tdfECWrap || self == .tdfECWrapLegacy
    }

    /// Canonical format for CLI dispatch (legacy wire names collapse to Base TDF).
    var canonical: TDFFormat {
        switch self {
        case .tdfLegacyWire: .tdf
        case .tdfECWrapLegacy: .tdfECWrap
        default: self
        }
    }
}
