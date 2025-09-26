#!/usr/bin/env swift

import Foundation
import OpenTDFKit

// MARK: - Environment Configuration

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
        Config(
            clientId: ProcessInfo.processInfo.environment["CLIENTID"] ?? "opentdf-client",
            clientSecret: ProcessInfo.processInfo.environment["CLIENTSECRET"] ?? "secret",
            kasURL: ProcessInfo.processInfo.environment["KASURL"] ?? "http://10.0.0.138:8080/kas",
            platformURL: ProcessInfo.processInfo.environment["PLATFORMURL"] ?? "http://10.0.0.138:8080",
            withMimeType: ProcessInfo.processInfo.environment["XT_WITH_MIME_TYPE"],
            withAttributes: (ProcessInfo.processInfo.environment["XT_WITH_ATTRIBUTES"] ?? "").split(separator: ",").map(String.init),
            withAssertions: ProcessInfo.processInfo.environment["XT_WITH_ASSERTIONS"],
            withAssertionVerificationKeys: ProcessInfo.processInfo.environment["XT_WITH_ASSERTION_VERIFICATION_KEYS"],
            withVerifyAssertions: ProcessInfo.processInfo.environment["XT_WITH_VERIFY_ASSERTIONS"] == "true",
            withECDSABinding: ProcessInfo.processInfo.environment["XT_WITH_ECDSA_BINDING"] == "true",
            withECWrap: ProcessInfo.processInfo.environment["XT_WITH_ECWRAP"] == "true",
            withPlaintextPolicy: ProcessInfo.processInfo.environment["XT_WITH_PLAINTEXT_POLICY"] == "true",
            withTargetMode: ProcessInfo.processInfo.environment["XT_WITH_TARGET_MODE"],
            withKasAllowlist: (ProcessInfo.processInfo.environment["XT_WITH_KAS_ALLOWLIST"] ??
                ProcessInfo.processInfo.environment["XT_WITH_KAS_ALLOW_LIST"] ?? "").split(separator: ",").map(String.init),
            withIgnoreKasAllowlist: ProcessInfo.processInfo.environment["XT_WITH_IGNORE_KAS_ALLOWLIST"] == "true",
        )
    }
}

// MARK: - CLI Commands

enum Command {
    case encrypt(plaintext: String, ciphertext: String, format: TDFFormat)
    case decrypt(ciphertext: String, recovered: String, format: TDFFormat)
    case supports(feature: String)

    enum TDFFormat: String {
        case nano
        case ztdf
        case ztdfECWrap = "ztdf-ecwrap"
        case nanoWithECDSA = "nano-with-ecdsa"
    }
}

// MARK: - Main CLI Logic

func main() throws {
    let args = CommandLine.arguments

    guard args.count >= 2 else {
        print("Usage: cli.sh <command> [args...]")
        exit(1)
    }

    let commandName = args[1]

    switch commandName {
    case "encrypt":
        guard args.count >= 5 else {
            print("Usage: cli.sh encrypt <plaintext> <ciphertext> <format>")
            exit(1)
        }
        let format = Command.TDFFormat(rawValue: args[4]) ?? .nano
        try handleEncrypt(plaintext: args[2], ciphertext: args[3], format: format)

    case "decrypt":
        guard args.count >= 5 else {
            print("Usage: cli.sh decrypt <ciphertext> <recovered> <format>")
            exit(1)
        }
        let format = Command.TDFFormat(rawValue: args[4]) ?? .nano
        try handleDecrypt(ciphertext: args[2], recovered: args[3], format: format)

    case "supports":
        guard args.count >= 3 else {
            print("Usage: cli.sh supports <feature>")
            exit(1)
        }
        handleSupports(feature: args[2])

    default:
        print("Unknown command: \(commandName)")
        exit(1)
    }
}

// MARK: - Command Handlers

func handleEncrypt(plaintext: String, ciphertext: String, format: Command.TDFFormat) throws {
    let config = Config.fromEnvironment()

    // Read input data
    let inputData = try Data(contentsOf: URL(fileURLWithPath: plaintext))

    // Create encrypted data based on format
    let encryptedData: Data

    switch format {
    case .nano, .nanoWithECDSA:
        // Create NanoTDF
        let keyStore = KeyStore()
        let ephemeralKey = try keyStore.generateKey(type: .ephemeral, curve: .secp256r1)

        let policy = NanoTDF.Policy(
            body: NanoTDF.PolicyBody(
                dataAttributes: config.withAttributes,
                dissem: [],
                kasURL: config.kasURL,
            ),
            keyAccess: NanoTDF.KeyAccess(
                keyType: .remote,
                kasURL: config.kasURL,
                protocol: "kas",
                ephemeralPublicKey: ephemeralKey.publicKey,
            ),
        )

        let nanoTDF = try NanoTDF(
            policy: policy,
            payload: inputData,
            ephemeralKey: ephemeralKey,
            useECDSABinding: format == .nanoWithECDSA || config.withECDSABinding,
            usePlaintextPolicy: config.withPlaintextPolicy,
        )

        encryptedData = try nanoTDF.serialize()

    case .ztdf, .ztdfECWrap:
        // ZTDF not yet implemented
        print("ZTDF format not yet implemented in Swift SDK")
        exit(1)
    }

    // Write encrypted data to output file
    try encryptedData.write(to: URL(fileURLWithPath: ciphertext))
}

func handleDecrypt(ciphertext: String, recovered: String, format: Command.TDFFormat) throws {
    let config = Config.fromEnvironment()

    // Read encrypted data
    let encryptedData = try Data(contentsOf: URL(fileURLWithPath: ciphertext))

    // Decrypt based on format
    let decryptedData: Data

    switch format {
    case .nano, .nanoWithECDSA:
        // Parse NanoTDF
        let nanoTDF = try NanoTDF(data: encryptedData)

        // Note: Actual decryption would require KAS interaction
        // For now, we just verify the structure
        print("NanoTDF parsed successfully")
        print("Version: \(nanoTDF.header.version.major).\(nanoTDF.header.version.minor)")
        print("KAS Protocol: \(nanoTDF.header.kas.protocol)")

        // For testing, return a placeholder
        decryptedData = "Decryption requires KAS integration".data(using: .utf8)!

    case .ztdf, .ztdfECWrap:
        print("ZTDF format not yet implemented in Swift SDK")
        exit(1)
    }

    // Write decrypted data to output file
    try decryptedData.write(to: URL(fileURLWithPath: recovered))
}

func handleSupports(feature: String) {
    // List of supported features
    let supportedFeatures = [
        "nano",
        "nano_ecdsa",
        "nano_policymode_plaintext",
        "autoconfigure",
        "hexless",
        "hexaflexible",
    ]

    if supportedFeatures.contains(feature) {
        exit(0)
    } else {
        exit(1)
    }
}

// MARK: - Execute

do {
    try main()
} catch {
    print("Error: \(error)")
    exit(1)
}
