import CryptoKit
import Darwin
import Foundation
import OpenTDFKit
import UniformTypeIdentifiers

enum CLIDataFormat: String {
    case nano
    case nanoWithECDSA = "nano-with-ecdsa"
    case nanoCollection = "nano-collection"
    case tdf
    case ztdf
    case json
    case cbor

    static func parse(_ rawValue: String) throws -> CLIDataFormat {
        let normalized = rawValue.lowercased()
        if normalized == "nano_with_ecdsa" {
            return .nanoWithECDSA
        }
        if normalized == "nano_collection" || normalized == "nano-collection" {
            return .nanoCollection
        }
        if normalized == "tdf-json" || normalized == "tdfjson" {
            return .json
        }
        if normalized == "tdf-cbor" || normalized == "tdfcbor" {
            return .cbor
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

        case "benchmark":
            try await benchmarkCommand(args: args)
            return 0

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
          OpenTDFKitCLI encrypt <input> <output> <format> [--chunk-size <size>] [--segments <sizes>]
          OpenTDFKitCLI decrypt <input> <output> <format> [--chunk-size <size>]
          OpenTDFKitCLI supports <feature>                 Check if feature is supported
          OpenTDFKitCLI verify <file>                      Parse and validate a TDF file
          OpenTDFKitCLI benchmark <input> <format>         Benchmark different chunk sizes
          OpenTDFKitCLI --help                             Show this help message

        Formats:
          nano               Standard NanoTDF
          nano-with-ecdsa    NanoTDF with ECDSA binding
          nano-collection    NanoTDF Collection (single key, multiple payloads)
          tdf                Standard ZIP-based TDF (supports streaming)
          ztdf               ZTDF alias for standard TDF
          json               TDF-JSON format (inline base64 payload)
          cbor               TDF-CBOR format (binary payload)

        Options:
          --chunk-size <size>    Chunk size for streaming (2m, 5m, 25m, or bytes)
          --segments <sizes>     Comma-separated segment sizes (e.g., 2m,5m,2m)

        Features (for supports command):
          nano, nano_ecdsa, nano_collection, ztdf, json, cbor, etc.

        Environment Variables:
          CLIENTID           OAuth client ID
          CLIENTSECRET       OAuth client secret
          KASURL             KAS endpoint URL
          PLATFORMURL        Platform endpoint URL

        Examples:
          OpenTDFKitCLI encrypt input.txt output.ntdf nano
          OpenTDFKitCLI encrypt input.txt output.ntdf nano-collection
          OpenTDFKitCLI encrypt large.dat output.tdf tdf --chunk-size 5m
          OpenTDFKitCLI encrypt large.dat output.tdf tdf --segments 2m,5m,25m
          OpenTDFKitCLI encrypt input.txt output.json json
          OpenTDFKitCLI encrypt input.txt output.cbor cbor
          OpenTDFKitCLI decrypt output.ntdf recovered.txt nano-collection
          OpenTDFKitCLI decrypt output.tdf recovered.dat tdf --chunk-size 5m
          OpenTDFKitCLI decrypt output.json recovered.txt json
          OpenTDFKitCLI decrypt output.cbor recovered.txt cbor
          OpenTDFKitCLI benchmark test.dat tdf
          OpenTDFKitCLI supports json
          OpenTDFKitCLI verify test.ntdf
        """)
    }

    static func parseChunkSize(_ sizeString: String) throws -> Int {
        let trimmed = sizeString.lowercased().trimmingCharacters(in: .whitespaces)
        if trimmed.hasSuffix("m") || trimmed.hasSuffix("mb") {
            let numStr = trimmed.replacingOccurrences(of: "m", with: "").replacingOccurrences(of: "b", with: "")
            guard let num = Int(numStr) else {
                throw CLIError.invalidChunkSize(sizeString)
            }
            return num * 1024 * 1024
        } else if trimmed.hasSuffix("k") || trimmed.hasSuffix("kb") {
            let numStr = trimmed.replacingOccurrences(of: "k", with: "").replacingOccurrences(of: "b", with: "")
            guard let num = Int(numStr) else {
                throw CLIError.invalidChunkSize(sizeString)
            }
            return num * 1024
        } else {
            guard let num = Int(trimmed) else {
                throw CLIError.invalidChunkSize(sizeString)
            }
            return num
        }
    }

    static func parseSegmentSizes(_ segmentString: String) throws -> [Int] {
        let parts = segmentString.split(separator: ",").map { String($0) }
        return try parts.map { try parseChunkSize($0) }
    }

    static func findFlag(_ flag: String, in args: [String]) -> (found: Bool, value: String?) {
        guard let index = args.firstIndex(of: flag), index + 1 < args.count else {
            return (false, nil)
        }
        return (true, args[index + 1])
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

        // Use TDFFormatDetector for automatic format detection
        guard let format = TDFFormatDetector.detect(from: data) else {
            throw CLIError.unsupportedFormat("Unable to detect TDF format from file contents")
        }

        switch format {
        case .archive:
            try Commands.verifyTDF(data: data, filename: fileURL.lastPathComponent)
        case .nano:
            try Commands.verifyNanoTDF(data: data, filename: fileURL.lastPathComponent)
        case .json:
            try Commands.verifyTDFJSON(data: data, filename: fileURL.lastPathComponent)
        case .cbor:
            try Commands.verifyTDFCBOR(data: data, filename: fileURL.lastPathComponent)
        }
    }

    static func encryptCommand(args: [String]) async throws {
        // encrypt <input> <output> <format> [--chunk-size <size>] [--segments <sizes>]
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

        let chunkSizeFlag = findFlag("--chunk-size", in: args)
        let segmentsFlag = findFlag("--segments", in: args)

        let fileAttributes = try FileManager.default.attributesOfItem(atPath: inputURL.path)
        let fileSize = fileAttributes[.size] as? Int64 ?? 0

        let streamingThreshold: Int64 = 10 * 1024 * 1024

        let outputData: Data
        var standardTDFResult: TDFEncryptionResult?
        switch format {
        case .nano:
            let inputData = try Data(contentsOf: inputURL)
            outputData = try await Commands.encryptNanoTDF(
                plaintext: inputData,
                useECDSA: false,
            )
        case .nanoWithECDSA:
            let inputData = try Data(contentsOf: inputURL)
            outputData = try await Commands.encryptNanoTDF(
                plaintext: inputData,
                useECDSA: true,
            )
        case .nanoCollection:
            try await Commands.encryptFileToCollection(inputURL: inputURL, outputURL: outputURL)
            return
        case .tdf, .ztdf:
            let configuration = try buildTDFConfiguration(for: inputURL)

            if let segmentString = segmentsFlag.value {
                let segmentSizes = try parseSegmentSizes(segmentString)
                print("Using multi-segment encryption with sizes: \(segmentSizes.map { "\($0 / 1024 / 1024)MB" }.joined(separator: ", "))")
                let encryptor = TDFEncryptor()
                standardTDFResult = try encryptor.encryptFileMultiSegment(
                    inputURL: inputURL,
                    outputURL: outputURL,
                    configuration: configuration,
                    segmentSizes: segmentSizes,
                )
                outputData = try Data(contentsOf: outputURL)
            } else if fileSize > streamingThreshold || chunkSizeFlag.found {
                let chunkSize = try chunkSizeFlag.value.map { try parseChunkSize($0) } ?? StreamingTDFCrypto.defaultChunkSize
                print("Using streaming encryption (file: \(fileSize / 1024 / 1024)MB, chunk: \(chunkSize / 1024 / 1024)MB)")
                let encryptor = TDFEncryptor()
                standardTDFResult = try encryptor.encryptFile(
                    inputURL: inputURL,
                    outputURL: outputURL,
                    configuration: configuration,
                    chunkSize: chunkSize,
                )
                outputData = try Data(contentsOf: outputURL)
            } else {
                let inputData = try Data(contentsOf: inputURL)
                print("Using in-memory encryption (file: \(fileSize / 1024 / 1024)MB)")
                let result = try Commands.encryptTDF(
                    plaintext: inputData,
                    configuration: configuration,
                )
                standardTDFResult = result.result
                outputData = result.archiveData
                try outputData.write(to: outputURL)
            }
        case .json:
            let inputData = try Data(contentsOf: inputURL)
            let result = try Commands.encryptTDFJSON(
                plaintext: inputData,
                inputURL: inputURL,
            )
            outputData = result.data
            try outputData.write(to: outputURL)
            try persistSymmetricKeyIfRequested(result.symmetricKey)
            return
        case .cbor:
            let inputData = try Data(contentsOf: inputURL)
            let result = try Commands.encryptTDFCBOR(
                plaintext: inputData,
                inputURL: inputURL,
            )
            outputData = result.data
            try outputData.write(to: outputURL)
            try persistSymmetricKeyIfRequested(result.symmetricKey)
            return
        }

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
        case .nanoCollection:
            try await Commands.decryptCollectionToFile(inputURL: inputURL, outputURL: outputURL)
            return
        case .tdf, .ztdf:
            let symmetricKey = try loadSymmetricKeyFromEnvironment()
            let privateKey = try loadPrivateKeyPEMFromEnvironment()
            var oauthToken: String? = nil

            if symmetricKey == nil {
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

            plaintext = try await Commands.decryptTDF(
                data: data,
                filename: inputURL.lastPathComponent,
                symmetricKey: symmetricKey,
                privateKeyPEM: privateKey,
                oauthToken: oauthToken,
            )
            usedStandardTDF = true
        case .json:
            let symmetricKey = try loadSymmetricKeyFromEnvironment()
            let privateKey = try loadPrivateKeyPEMFromEnvironment()

            plaintext = try Commands.decryptTDFJSON(
                data: data,
                filename: inputURL.lastPathComponent,
                symmetricKey: symmetricKey,
                privateKeyPEM: privateKey,
            )
            usedStandardTDF = true
        case .cbor:
            let symmetricKey = try loadSymmetricKeyFromEnvironment()
            let privateKey = try loadPrivateKeyPEMFromEnvironment()

            plaintext = try Commands.decryptTDFCBOR(
                data: data,
                filename: inputURL.lastPathComponent,
                symmetricKey: symmetricKey,
                privateKeyPEM: privateKey,
            )
            usedStandardTDF = true
        }

        // Write recovered file
        try plaintext.write(to: outputURL)

        if usedStandardTDF {
            print("✓ Decryption successful")
        }
    }

    static func benchmarkCommand(args: [String]) async throws {
        guard args.count >= 4 else {
            throw CLIError.missingArgument("benchmark requires: <input> <format>")
        }

        let inputURL = try resolvePath(args[2])
        let format = try CLIDataFormat.parse(args[3])

        guard FileManager.default.fileExists(atPath: inputURL.path) else {
            throw CLIError.fileNotFound(inputURL.path)
        }

        guard format == .tdf || format == .ztdf else {
            throw CLIError.notYetSupported("Benchmark only supports TDF format currently")
        }

        let fileAttributes = try FileManager.default.attributesOfItem(atPath: inputURL.path)
        let fileSize = fileAttributes[.size] as? Int64 ?? 0

        print("Benchmark: Standard TDF Streaming Performance")
        print("==============================================")
        print("Input file: \(inputURL.lastPathComponent)")
        print("File size: \(fileSize / 1024 / 1024) MB (\(fileSize) bytes)\n")

        let chunkSizes: [(name: String, size: Int)] = [
            ("2MB", StreamingTDFCrypto.defaultChunkSize),
            ("5MB", StreamingTDFCrypto.chunkSize5MB),
            ("25MB", StreamingTDFCrypto.chunkSize25MB),
        ]

        for (name, chunkSize) in chunkSizes {
            print("Testing chunk size: \(name)")
            print("----------------------------")

            let tempEncrypted = FileManager.default.temporaryDirectory
                .appendingPathComponent(UUID().uuidString)
                .appendingPathExtension("tdf")
            let tempDecrypted = FileManager.default.temporaryDirectory
                .appendingPathComponent(UUID().uuidString)
                .appendingPathExtension("dat")

            defer {
                try? FileManager.default.removeItem(at: tempEncrypted)
                try? FileManager.default.removeItem(at: tempDecrypted)
            }

            let configuration = try buildTDFConfiguration(for: inputURL)
            let encryptor = TDFEncryptor()

            let encryptStart = Date()
            let result = try encryptor.encryptFile(
                inputURL: inputURL,
                outputURL: tempEncrypted,
                configuration: configuration,
                chunkSize: chunkSize,
            )
            let encryptTime = Date().timeIntervalSince(encryptStart)
            let encryptThroughput = Double(fileSize) / encryptTime / 1024 / 1024

            let encryptedSize = try FileManager.default.attributesOfItem(atPath: tempEncrypted.path)[.size] as? Int64 ?? 0

            let decryptor = TDFDecryptor()
            let decryptStart = Date()
            try decryptor.decryptFile(
                inputURL: tempEncrypted,
                outputURL: tempDecrypted,
                symmetricKey: result.symmetricKey,
                chunkSize: chunkSize,
            )
            let decryptTime = Date().timeIntervalSince(decryptStart)
            let decryptThroughput = Double(fileSize) / decryptTime / 1024 / 1024

            let decryptedSize = try FileManager.default.attributesOfItem(atPath: tempDecrypted.path)[.size] as? Int64 ?? 0

            guard decryptedSize == fileSize else {
                throw CLIError.notYetSupported("Decryption verification failed: size mismatch")
            }

            print("  Encryption time: \(String(format: "%.2f", encryptTime))s (\(String(format: "%.2f", encryptThroughput)) MB/s)")
            print("  Decryption time: \(String(format: "%.2f", decryptTime))s (\(String(format: "%.2f", decryptThroughput)) MB/s)")
            print("  Encrypted size: \(encryptedSize / 1024 / 1024) MB")
            print("  Overhead: \(String(format: "%.2f", Double(encryptedSize - fileSize) / Double(fileSize) * 100))%")
            print("")
        }

        print("Benchmark complete!")
    }

    // MARK: - Standard TDF Helpers

    private static func buildTDFConfiguration(for inputURL: URL) throws -> TDFEncryptionConfiguration {
        let env = ProcessInfo.processInfo.environment

        guard let kasURLString = env["TDF_KAS_URL"] ?? env["KASURL"], let kasURL = URL(string: kasURLString) else {
            throw CLIError.missingEnvironmentVariable("TDF_KAS_URL or KASURL")
        }

        let publicKeyPEM = try loadPEMString(valueKey: "TDF_KAS_PUBLIC_KEY", pathKey: "TDF_KAS_PUBLIC_KEY_PATH")
        let policyData = try loadPolicyData()
        let mimeType = env["TDF_MIME_TYPE"] ?? inferMimeType(for: inputURL)

        let kasInfo = TDFKasInfo(
            url: kasURL,
            publicKeyPEM: publicKeyPEM,
            kid: env["TDF_KAS_KID"],
            schemaVersion: env["TDF_KAS_SCHEMA_VERSION"],
        )

        let policy = try TDFPolicy(json: policyData)
        let specVersion = env["TDF_SPEC_VERSION"] ?? "4.3.0"

        // Parse key size from environment (default: 256-bit)
        let keySize: TDFKeySize = {
            if let keySizeEnv = env["TDF_KEY_SIZE"] {
                return keySizeEnv == "128" ? .bits128 : .bits256
            }
            return .bits256
        }()

        return TDFEncryptionConfiguration(
            kas: kasInfo,
            policy: policy,
            mimeType: mimeType,
            tdfSpecVersion: specVersion,
            keySize: keySize,
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
        case "nano", "nano_ecdsa", "nano_collection":
            return 0
        case "tdf", "ztdf":
            return 0
        case "json", "tdf-json", "tdfjson":
            return 0
        case "cbor", "tdf-cbor", "tdfcbor":
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
    case invalidChunkSize(String)

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
        case let .invalidChunkSize(value):
            "Invalid chunk size: '\(value)'. Use format like: 2m, 5m, 25m, 1024k, or raw bytes."
        }
    }
}
