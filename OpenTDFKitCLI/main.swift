import Foundation
import Darwin

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

        case "decrypt":
            try await decryptCommand(args: args)
            return 0

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
          OpenTDFKitCLI verify <file>                    Parse and validate a NanoTDF file
          OpenTDFKitCLI decrypt <file> [--token <token>] Decrypt a NanoTDF file
          OpenTDFKitCLI --help                           Show this help message

        Commands:
          verify     Parse and validate a NanoTDF file structure
          decrypt    Decrypt a NanoTDF file and output plaintext
          --help     Show usage information

        Options:
          --token    OAuth access token for KAS authentication (defaults to fresh_token.txt)

        Examples:
          OpenTDFKitCLI verify test.ntdf
          OpenTDFKitCLI decrypt test.ntdf.tdf
          OpenTDFKitCLI decrypt test.ntdf.tdf --token "eyJhbGciOiJSUzI1NiI..."
          OpenTDFKitCLI --help
        """)
    }

    static func verifyCommand(args: [String]) throws {
        guard args.count >= 3 else {
            throw CLIError.missingArgument("verify requires a file path")
        }

        let filePath = args[2]

        guard FileManager.default.fileExists(atPath: filePath) else {
            throw CLIError.fileNotFound(filePath)
        }

        let data = try Data(contentsOf: URL(fileURLWithPath: filePath))
        try Commands.verifyNanoTDF(data: data, filename: filePath)
    }

    static func decryptCommand(args: [String]) async throws {
        guard args.count >= 3 else {
            throw CLIError.missingArgument("decrypt requires a file path")
        }

        let filePath = args[2]

        // Parse optional --token flag
        var token: String?
        if args.count >= 5 && args[3] == "--token" {
            token = args[4]
        }

        guard FileManager.default.fileExists(atPath: filePath) else {
            throw CLIError.fileNotFound(filePath)
        }

        let data = try Data(contentsOf: URL(fileURLWithPath: filePath))

        // Call the async decrypt function
        try await Commands.decryptNanoTDF(data: data, filename: filePath, token: token)
    }
}

enum CLIError: LocalizedError {
    case missingArgument(String)
    case fileNotFound(String)

    var errorDescription: String? {
        switch self {
        case .missingArgument(let message):
            return message
        case .fileNotFound(let path):
            return "File not found: \(path)"
        }
    }
}