import CryptoKit
import Darwin
import Foundation
import OpenTDFKit
import UniformTypeIdentifiers

enum CLIDataFormat: String {
    case nano
    case nanoWithECDSA = "nano-with-ecdsa"
    case tdf
    case ztdf

    static func parse(_ rawValue: String) throws -> CLIDataFormat {
        let normalized = rawValue.lowercased()
        if normalized == "nano_with_ecdsa" {
            return .nanoWithECDSA
        }
        guard let format = CLIDataFormat(rawValue: normalized) else {
            throw CLIError.unsupportedFormat(rawValue)
        }
        return format
    }
}

@main
struct OpenTDFKitCLI {
    static func main() async {
        // Disable stdout buffering for proper piped output
        setbuf(stdout, nil)

        do {
            let exitCode = try await run()
            Foundation.exit(exitCode)
        } catch {
            fputs("Error: \(error)\n", stderr)
            Foundation.exit(1)
        }
    }

    /// Resolve file path - handles both relative and absolute paths
    /// - Parameter path: Input file path
    /// - Returns: Resolved absolute URL
    /// - Throws: CLIError if path resolution fails
    static func resolvePath(_ path: String) throws -> URL {
        // Handle stdin/stdout special cases
        if path == "-" {
            throw CLIError.invalidPath("Use explicit file paths (stdin/stdout not supported)")
        }

        // Create URL from path
        let url: URL
        if path.hasPrefix("/") || path.hasPrefix("~") {
            // Absolute or home-relative path
            url = URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
        } else {
            // Relative path - resolve against current directory
            let currentDir = FileManager.default.currentDirectoryPath
            url = URL(fileURLWithPath: currentDir).appendingPathComponent(path)
        }

        // Normalize path (resolve . and ..)
        return url.standardizedFileURL
    }

    static func run() async throws -> Int32 {
        let args = CommandLine.arguments

        guard args.count >= 2 else {
            printUsage()
            return 1
        }

        let command = args[1]

        switch command {
        case "--help", "-h", "help":
            printUsage()
            return 0

        case "verify":
            try verifyCommand(args: args)
            return 0

        case "encrypt":
            try await encryptCommand(args: args)
            return 0

        case "decrypt":
            try await decryptCommand(args: args)
            return 0

        case "supports":
            return supportsCommand(args: args)

        default:
            fputs("Error: Unknown command '\(command)'\n", stderr)
            printUsage()
            return 1
        }
    }

    static func printUsage() {
        print("""
        OpenTDFKit CLI - Trusted Data Format Tool

        Usage:
          OpenTDFKitCLI encrypt <input> <output> <format>  Encrypt a file to the selected format
          OpenTDFKitCLI decrypt <input> <output> <format>  Decrypt a file from the selected format
          OpenTDFKitCLI supports <feature>                 Check if feature is supported
          OpenTDFKitCLI verify <file>                      Parse and validate a TDF file
          OpenTDFKitCLI --help                             Show this help message

        Formats:
          nano               Standard NanoTDF
          nano-with-ecdsa    NanoTDF with ECDSA binding
          tdf                Standard ZIP-based TDF
          ztdf               ZTDF alias for standard TDF

        Features (for supports command):
          nano, nano_ecdsa, ztdf, assertions, etc.

        Environment Variables:
          CLIENTID           OAuth client ID
          CLIENTSECRET       OAuth client secret
          KASURL             KAS endpoint URL
          PLATFORMURL        Platform endpoint URL

        Examples:
          OpenTDFKitCLI encrypt input.txt output.ntdf nano
          OpenTDFKitCLI decrypt output.ntdf recovered.txt nano
          OpenTDFKitCLI supports nano
          OpenTDFKitCLI verify test.ntdf
        """)
    }

    static func verifyCommand(args: [String]) throws {
        guard args.count >= 3 else {
            throw CLIError.missingArgument("verify requires a file path")
        }

        let fileURL = try resolvePath(args[2])

        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            throw CLIError.fileNotFound(fileURL.path)
        }

        let data = try Data(contentsOf: fileURL)
        if Commands.isLikelyStandardTDF(data: data) {
            try Commands.verifyStandardTDF(data: data, filename: fileURL.lastPathComponent)
        } else {
            try Commands.verifyNanoTDF(data: data, filename: fileURL.lastPathComponent)
        }
    }

    static func encryptCommand(args: [String]) async throws {
        // encrypt <input> <output> <format>
        guard args.count >= 5 else {
            throw CLIError.missingArgument("encrypt requires: <input> <output> <format>")
        }

        let inputURL = try resolvePath(args[2])
        let outputURL = try resolvePath(args[3])
        let format = try CLIDataFormat.parse(args[4])

        guard FileManager.default.fileExists(atPath: inputURL.path) else {
            throw CLIError.fileNotFound(inputURL.path)
        }

        // Check if output directory exists
        let outputDir = outputURL.deletingLastPathComponent()
        guard FileManager.default.fileExists(atPath: outputDir.path) else {
            throw CLIError.directoryNotFound(outputDir.path)
        }

        let inputData = try Data(contentsOf: inputURL)
        let outputData: Data
        var standardTDFResult: StandardTDFEncryptionResult?
        switch format {
        case .nano:
            outputData = try await Commands.encryptNanoTDF(
                plaintext: inputData,
                useECDSA: false,
            )
        case .nanoWithECDSA:
            outputData = try await Commands.encryptNanoTDF(
                plaintext: inputData,
                useECDSA: true,
            )
        case .tdf, .ztdf:
            let configuration = try buildStandardTDFConfiguration(for: inputURL)
            let result = try Commands.encryptStandardTDF(
                plaintext: inputData,
                configuration: configuration,
            )
            standardTDFResult = result.result
            outputData = result.archiveData
        }

        // Write output file
        try outputData.write(to: outputURL)

        if let result = standardTDFResult {
            try persistSymmetricKeyIfRequested(result.symmetricKey)
        }
    }

    static func decryptCommand(args: [String]) async throws {
        // decrypt <input> <output> <format>
        guard args.count >= 5 else {
            throw CLIError.missingArgument("decrypt requires: <input> <output> <format>")
        }

        let inputURL = try resolvePath(args[2])
        let outputURL = try resolvePath(args[3])
        let format = try CLIDataFormat.parse(args[4])

        guard FileManager.default.fileExists(atPath: inputURL.path) else {
            throw CLIError.fileNotFound(inputURL.path)
        }

        // Check if output directory exists
        let outputDir = outputURL.deletingLastPathComponent()
        guard FileManager.default.fileExists(atPath: outputDir.path) else {
            throw CLIError.directoryNotFound(outputDir.path)
        }

        let data = try Data(contentsOf: inputURL)

        let plaintext: Data
        var usedStandardTDF = false
        switch format {
        case .nano, .nanoWithECDSA:
            plaintext = try await Commands.decryptNanoTDFWithOutput(
                data: data,
                filename: inputURL.lastPathComponent,
            )
        case .tdf, .ztdf:
            let symmetricKey = try loadSymmetricKeyFromEnvironment()
            let privateKey = try loadPrivateKeyPEMFromEnvironment()
            var clientPublicKey: String? = nil
            var oauthToken: String? = nil

            if symmetricKey == nil {
                clientPublicKey = try loadClientPublicKeyPEMFromEnvironment()
                let env = ProcessInfo.processInfo.environment
                let tokenPath = env["TDF_OAUTH_TOKEN_PATH"] ?? env["OAUTH_TOKEN_PATH"] ?? "fresh_token.txt"
                oauthToken = try? Commands.resolveOAuthToken(
                    providedToken: env["TDF_OAUTH_TOKEN"],
                    tokenPath: tokenPath,
                )

                if privateKey == nil {
                    throw DecryptError.missingSymmetricMaterial
                }
            }

            plaintext = try await Commands.decryptStandardTDF(
                data: data,
                filename: inputURL.lastPathComponent,
                symmetricKey: symmetricKey,
                privateKeyPEM: privateKey,
                clientPublicKeyPEM: clientPublicKey,
                oauthToken: oauthToken,
            )
            usedStandardTDF = true
        }

        // Write recovered file
        try plaintext.write(to: outputURL)

        if usedStandardTDF {
            print("✓ Decryption successful")
        }
    }

    // MARK: - Standard TDF Helpers

    private static func buildStandardTDFConfiguration(for inputURL: URL) throws -> StandardTDFEncryptionConfiguration {
        let env = ProcessInfo.processInfo.environment

        guard let kasURLString = env["TDF_KAS_URL"] ?? env["KASURL"], let kasURL = URL(string: kasURLString) else {
            throw CLIError.missingEnvironmentVariable("TDF_KAS_URL or KASURL")
        }

        let publicKeyPEM = try loadPEMString(valueKey: "TDF_KAS_PUBLIC_KEY", pathKey: "TDF_KAS_PUBLIC_KEY_PATH")
        let policyData = try loadPolicyData()
        let mimeType = env["TDF_MIME_TYPE"] ?? inferMimeType(for: inputURL)

        let kasInfo = StandardTDFKasInfo(
            url: kasURL,
            publicKeyPEM: publicKeyPEM,
            kid: env["TDF_KAS_KID"],
            schemaVersion: env["TDF_KAS_SCHEMA_VERSION"],
        )

        let policy = StandardTDFPolicy(json: policyData)
        let specVersion = env["TDF_SPEC_VERSION"] ?? "4.3.0"

        return StandardTDFEncryptionConfiguration(
            kas: kasInfo,
            policy: policy,
            mimeType: mimeType,
            tdfSpecVersion: specVersion,
        )
    }

    private static func loadPolicyData() throws -> Data {
        let env = ProcessInfo.processInfo.environment
        if let policyPath = env["TDF_POLICY_PATH"] {
            let url = try resolvePath(policyPath)
            return try Data(contentsOf: url)
        }

        if let policyBase64 = env["TDF_POLICY_BASE64"], let data = Data(base64Encoded: policyBase64) {
            return data
        }

        if let inlineJSON = env["TDF_POLICY_JSON"], let data = inlineJSON.data(using: .utf8) {
            return data
        }

        let policy: [String: Any] = [
            "uuid": UUID().uuidString.lowercased(),
            "body": [
                "dataAttributes": [],
                "dissem": [],
            ],
        ]

        guard JSONSerialization.isValidJSONObject(policy),
              let data = try? JSONSerialization.data(withJSONObject: policy, options: [.sortedKeys])
        else {
            throw CLIError.invalidPolicy
        }

        return data
    }

    private static func loadPEMString(valueKey: String, pathKey: String) throws -> String {
        let env = ProcessInfo.processInfo.environment
        if let inline = env[valueKey], inline.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false {
            return inline
        }

        if let path = env[pathKey] {
            let url = try resolvePath(path)
            return try String(contentsOf: url, encoding: .utf8)
        }

        throw CLIError.missingEnvironmentVariable(valueKey)
    }

    private static func inferMimeType(for url: URL) -> String? {
        guard let type = UTType(filenameExtension: url.pathExtension), let mime = type.preferredMIMEType else {
            return nil
        }
        return mime
    }

    private static func persistSymmetricKeyIfRequested(_ key: SymmetricKey) throws {
        let env = ProcessInfo.processInfo.environment
        guard let path = env["TDF_OUTPUT_SYMMETRIC_KEY_PATH"] else {
            return
        }
        let keyData = key.withUnsafeBytes { Data($0) }
        let keyBase64 = keyData.base64EncodedString()
        let url = try resolvePath(path)

        let directory = url.deletingLastPathComponent()
        guard FileManager.default.fileExists(atPath: directory.path) else {
            throw CLIError.directoryNotFound(directory.path)
        }

        try keyBase64.write(to: url, atomically: true, encoding: .utf8)
        print("✓ Wrote symmetric key to \(url.path)")
    }

    private static func loadSymmetricKeyFromEnvironment() throws -> SymmetricKey? {
        let env = ProcessInfo.processInfo.environment

        if let path = env["TDF_SYMMETRIC_KEY_PATH"] {
            let url = try resolvePath(path)
            let raw = try String(contentsOf: url, encoding: .utf8)
            return try symmetricKey(fromBase64: raw)
        }

        if let inline = env["TDF_SYMMETRIC_KEY_BASE64"] {
            return try symmetricKey(fromBase64: inline)
        }

        return nil
    }

    private static func symmetricKey(fromBase64 base64: String) throws -> SymmetricKey {
        let trimmed = base64.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = Data(base64Encoded: trimmed) else {
            throw CLIError.invalidSymmetricKey
        }
        return SymmetricKey(data: data)
    }

    private static func loadPrivateKeyPEMFromEnvironment() throws -> String? {
        let env = ProcessInfo.processInfo.environment
        if let inline = env["TDF_CLIENT_PRIVATE_KEY"], inline.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false {
            return inline
        }
        if let inline = env["TDF_PRIVATE_KEY"], inline.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false {
            return inline
        }
        if let path = env["TDF_CLIENT_PRIVATE_KEY_PATH"] {
            let url = try resolvePath(path)
            return try String(contentsOf: url, encoding: .utf8)
        }
        if let path = env["TDF_PRIVATE_KEY_PATH"] {
            let url = try resolvePath(path)
            return try String(contentsOf: url, encoding: .utf8)
        }
        return nil
    }

    private static func loadClientPublicKeyPEMFromEnvironment() throws -> String? {
        do {
            return try loadPEMString(valueKey: "TDF_CLIENT_PUBLIC_KEY", pathKey: "TDF_CLIENT_PUBLIC_KEY_PATH")
        } catch CLIError.missingEnvironmentVariable {
            return nil
        }
    }

    static func supportsCommand(args: [String]) -> Int32 {
        guard args.count >= 3 else {
            fputs("Error: supports requires a feature name\n", stderr)
            return 1
        }

        let feature = args[2]

        // Return 0 for supported features, 1 for unsupported
        switch feature {
        case "nano", "nano_ecdsa":
            return 0
        case "tdf", "ztdf":
            return 0
        case "ztdf-ecwrap", "assertions", "assertion_verification",
             "autoconfigure", "better-messages-2024", "bulk_rewrap",
             "connectrpc", "ecwrap", "hexless", "hexaflexible",
             "kasallowlist", "key_management", "nano_attribute_bug",
             "nano_policymode_plaintext", "ns_grants":
            return 1
        default:
            return 1
        }
    }
}

enum CLIError: LocalizedError {
    case missingArgument(String)
    case fileNotFound(String)
    case directoryNotFound(String)
    case unsupportedFormat(String)
    case invalidPath(String)
    case notYetSupported(String)
    case missingEnvironmentVariable(String)
    case invalidSymmetricKey
    case invalidPolicy

    var errorDescription: String? {
        switch self {
        case let .missingArgument(message):
            message
        case let .fileNotFound(path):
            "File not found: \(path)"
        case let .directoryNotFound(path):
            "Output directory does not exist: \(path)"
        case let .unsupportedFormat(format):
            "Unsupported format: \(format) (supported: nano, nano-with-ecdsa)"
        case let .invalidPath(message):
            "Invalid path: \(message)"
        case let .notYetSupported(message):
            message
        case let .missingEnvironmentVariable(name):
            "Required environment variable '\(name)' is not set."
        case .invalidSymmetricKey:
            "Unable to decode symmetric key. Provide a base64 encoded key via TDF_SYMMETRIC_KEY_PATH or TDF_SYMMETRIC_KEY_BASE64."
        case .invalidPolicy:
            "Unable to load policy JSON for standard TDF encryption."
        }
    }
}
