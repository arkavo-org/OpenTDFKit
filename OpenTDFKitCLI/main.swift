import Darwin
import Foundation

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
        OpenTDFKit CLI - NanoTDF Tool

        Usage:
          OpenTDFKitCLI encrypt <input> <output> <format>  Encrypt a file to NanoTDF
          OpenTDFKitCLI decrypt <input> <output> <format>  Decrypt a NanoTDF file
          OpenTDFKitCLI supports <feature>                 Check if feature is supported
          OpenTDFKitCLI verify <file>                      Parse and validate a NanoTDF file
          OpenTDFKitCLI --help                             Show this help message

        Formats:
          nano               Standard NanoTDF
          nano-with-ecdsa    NanoTDF with ECDSA binding

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
        try Commands.verifyNanoTDF(data: data, filename: fileURL.lastPathComponent)
    }

    static func encryptCommand(args: [String]) async throws {
        // encrypt <input> <output> <format>
        guard args.count >= 5 else {
            throw CLIError.missingArgument("encrypt requires: <input> <output> <format>")
        }

        let inputURL = try resolvePath(args[2])
        let outputURL = try resolvePath(args[3])
        let format = args[4]

        // Check format support
        guard format == "nano" || format == "nano-with-ecdsa" else {
            throw CLIError.unsupportedFormat(format)
        }

        guard FileManager.default.fileExists(atPath: inputURL.path) else {
            throw CLIError.fileNotFound(inputURL.path)
        }

        // Check if output directory exists
        let outputDir = outputURL.deletingLastPathComponent()
        guard FileManager.default.fileExists(atPath: outputDir.path) else {
            throw CLIError.directoryNotFound(outputDir.path)
        }

        let inputData = try Data(contentsOf: inputURL)
        let useECDSA = (format == "nano-with-ecdsa")

        // Call the async encrypt function
        let outputData = try await Commands.encryptNanoTDF(
            plaintext: inputData,
            useECDSA: useECDSA,
        )

        // Write output file
        try outputData.write(to: outputURL)
    }

    static func decryptCommand(args: [String]) async throws {
        // decrypt <input> <output> <format>
        guard args.count >= 5 else {
            throw CLIError.missingArgument("decrypt requires: <input> <output> <format>")
        }

        let inputURL = try resolvePath(args[2])
        let outputURL = try resolvePath(args[3])
        let format = args[4]

        // Check format support
        guard format == "nano" || format == "nano-with-ecdsa" else {
            throw CLIError.unsupportedFormat(format)
        }

        guard FileManager.default.fileExists(atPath: inputURL.path) else {
            throw CLIError.fileNotFound(inputURL.path)
        }

        // Check if output directory exists
        let outputDir = outputURL.deletingLastPathComponent()
        guard FileManager.default.fileExists(atPath: outputDir.path) else {
            throw CLIError.directoryNotFound(outputDir.path)
        }

        let data = try Data(contentsOf: inputURL)

        // Call the async decrypt function
        let plaintext = try await Commands.decryptNanoTDFWithOutput(
            data: data,
            filename: inputURL.lastPathComponent,
        )

        // Write recovered file
        try plaintext.write(to: outputURL)
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
        case "ztdf", "ztdf-ecwrap", "assertions", "assertion_verification",
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
        }
    }
}
