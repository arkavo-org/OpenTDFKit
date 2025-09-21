import Foundation

// Simple CLI for OpenTDFKit
let args = CommandLine.arguments

func printUsage() {
    print("""
    OpenTDFKit CLI - NanoTDF Tool

    Usage:
      OpenTDFKitCLI verify <file>     Parse and validate a NanoTDF file
      OpenTDFKitCLI --help            Show this help message

    Commands:
      verify     Parse and validate a NanoTDF file structure
      --help     Show usage information

    Examples:
      OpenTDFKitCLI verify test.ntdf
      OpenTDFKitCLI --help
    """)
}

// Check for minimum arguments
guard args.count >= 2 else {
    printUsage()
    exit(1)
}

let command = args[1]

switch command {
case "--help", "-h", "help":
    printUsage()
    exit(0)

case "verify":
    guard args.count >= 3 else {
        print("Error: verify requires a file path")
        printUsage()
        exit(1)
    }

    let filePath = args[2]

    // Check if file exists
    guard FileManager.default.fileExists(atPath: filePath) else {
        print("Error: File not found: \(filePath)")
        exit(1)
    }

    // Read the file
    guard let data = try? Data(contentsOf: URL(fileURLWithPath: filePath)) else {
        print("Error: Could not read file: \(filePath)")
        exit(1)
    }

    // Call the verify function
    do {
        try Commands.verifyNanoTDF(data: data, filename: filePath)
    } catch {
        print("Error: \(error)")
        exit(1)
    }

default:
    print("Error: Unknown command '\(command)'")
    printUsage()
    exit(1)
}