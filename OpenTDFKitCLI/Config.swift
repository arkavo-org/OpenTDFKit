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

    static func fromEnvironment() -> Config {
        let env = ProcessInfo.processInfo.environment

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
            clientId: env["CLIENTID"] ?? "opentdf-client",
            clientSecret: env["CLIENTSECRET"] ?? "secret",
            kasURL: env["KASURL"] ?? "http://10.0.0.138:8080/kas",
            platformURL: env["PLATFORMURL"] ?? "http://10.0.0.138:8080",
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
            withIgnoreKasAllowlist: env["XT_WITH_IGNORE_KAS_ALLOWLIST"] == "true"
        )
    }
}

/// TDF format types supported by xtest
enum TDFFormat: String {
    case nano = "nano"
    case ztdf = "ztdf"
    case ztdfECWrap = "ztdf-ecwrap"
    case nanoWithECDSA = "nano-with-ecdsa"

    var isNano: Bool {
        switch self {
        case .nano, .nanoWithECDSA:
            return true
        case .ztdf, .ztdfECWrap:
            return false
        }
    }

    var useECDSA: Bool {
        return self == .nanoWithECDSA
    }

    var useECWrap: Bool {
        return self == .ztdfECWrap
    }
}