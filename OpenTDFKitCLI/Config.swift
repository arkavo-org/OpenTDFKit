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

        // Parse attributes and allowlist from comma-separated strings
        let attributes = (env["XT_WITH_ATTRIBUTES"] ?? "")
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }

        let kasAllowlist = (env["XT_WITH_KAS_ALLOWLIST"] ?? env["XT_WITH_KAS_ALLOW_LIST"] ?? "")
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }

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
}

enum ConfigError: Error, CustomStringConvertible {
    case missingRequired(String)

    var description: String {
        switch self {
        case let .missingRequired(name):
            "Required environment variable '\(name)' is not set"
        }
    }
}

/// TDF format types supported by xtest
enum TDFFormat: String {
    case nano
    case ztdf
    case ztdfECWrap = "ztdf-ecwrap"
    case nanoWithECDSA = "nano-with-ecdsa"

    var isNano: Bool {
        switch self {
        case .nano, .nanoWithECDSA:
            true
        case .ztdf, .ztdfECWrap:
            false
        }
    }

    var useECDSA: Bool {
        self == .nanoWithECDSA
    }

    var useECWrap: Bool {
        self == .ztdfECWrap
    }
}
