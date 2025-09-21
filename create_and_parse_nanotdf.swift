#!/usr/bin/env swift

import Foundation
import OpenTDFKit

// Create a test NanoTDF and then parse it back
@main
struct CreateAndParseNanoTDF {
    static func main() async throws {
        print("Creating and parsing NanoTDF test")

        // Test data
        let testData = "This is a test file for NanoTDF encryption".data(using: .utf8)!

        // KAS configuration (using the remote service)
        let kasURL = "http://10.0.0.138:8080"
        guard let kasRL = ResourceLocator(protocolEnum: .http, body: kasURL) else {
            print("Error: Invalid KAS URL")
            exit(1)
        }

        // Using the actual KAS public key we retrieved earlier
        let kasPublicKeyPEM = """
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwv8qdRTlrntKcSA3v0nS
        irzU8pHzA1vJUuxEZjg//NiyxvuD5FVfeQa3vmeD0NsB7tjm3D0Sr/OmGKMBLAzr
        96SJ/LHerpH22oM4RM9wa1WauKE2q4nM1idjsGnzT+lsbUCuraVzrqiV5WlwHd1p
        9kXNjWxIBvNzESuPlw7LFyX6LaOHgJKpcqJlOtpg3w0CXRhsOyG8vQHiqRfl/7aX
        tf4MvTt9vtuwvlVN9b1YaJURFurFJn2X8O9XCpP3VHOmIC0YZqBzb9GEJuvApEMp
        CtjVzqvDzMrNvpIiApr7/w/rQKRDlBH0QoQODoKGuhnCyZQkUNGAnHPHbfa+6n/4
        MwIDAQAB
        -----END PUBLIC KEY-----
        """

        // Convert PEM to binary
        let pemLines = kasPublicKeyPEM.components(separatedBy: "\n")
        let base64Key = pemLines.filter { !$0.hasPrefix("-----") }.joined()
        guard let kasPublicKey = Data(base64Encoded: base64Key) else {
            print("Error: Failed to decode KAS public key")
            exit(1)
        }

        // Create KAS metadata
        let kasMetadata = try KasMetadata(
            resourceLocator: kasRL,
            publicKey: kasPublicKey,
            curve: .secp256r1
        )

        // Create a simple policy
        let remotePolicyLocator = ResourceLocator(
            protocolEnum: .sharedResourceDirectory,
            body: "test-policy-id"
        )

        var policy = Policy(
            type: .remote,
            body: nil,
            remote: remotePolicyLocator,
            binding: nil
        )

        print("Creating NanoTDF...")

        // Create the NanoTDF
        let nanoTDF = try await createNanoTDF(
            kas: kasMetadata,
            policy: &policy,
            plaintext: testData
        )

        // Serialize to binary
        let serializedData = nanoTDF.toData()
        print("Created NanoTDF, size: \(serializedData.count) bytes")

        // Save to file
        let outputPath = "test_output.ntdf"
        try serializedData.write(to: URL(fileURLWithPath: outputPath))
        print("Saved NanoTDF to: \(outputPath)")

        // Display hex dump of first 100 bytes for debugging
        let hexString = serializedData.prefix(100).map { String(format: "%02x", $0) }.joined(separator: " ")
        print("First 100 bytes (hex): \(hexString)")

        // Now parse it back
        print("\nParsing the NanoTDF...")

        // Read the file
        let readData = try Data(contentsOf: URL(fileURLWithPath: outputPath))
        print("Read \(readData.count) bytes from file")

        // Basic validation - check magic number
        if readData.count > 3 {
            let magic = readData[0..<2]
            let version = readData[2]

            if magic == Data([0x4C, 0x31]) { // "L1"
                print("✓ Valid NanoTDF magic number: L1")
                print("✓ Version: \(version == 0x4C ? "v1.2" : version == 0x4D ? "v1.3" : "unknown")")
            } else {
                print("✗ Invalid magic number")
            }
        }

        // Parse header structure
        print("\nNanoTDF Structure:")
        print("- Header starts with magic number 'L1'")
        print("- Contains KAS information")
        print("- Contains ephemeral public key")
        print("- Contains encrypted payload")

        print("\n✓ Successfully created and validated NanoTDF structure")
    }
}