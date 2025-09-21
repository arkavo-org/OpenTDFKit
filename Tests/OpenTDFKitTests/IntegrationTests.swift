import Foundation
import Testing
@testable import OpenTDFKit

struct IntegrationTests {
    @Test("Create and parse NanoTDF with remote KAS")
    func testCreateAndParseNanoTDF() async throws {
        // Test data
        let testData = "This is test data for NanoTDF encryption".data(using: .utf8)!

        // KAS public key from the remote service (retrieved earlier)
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

        // Create a KeyStore with ephemeral keys for TDF creation
        let keyStore = KeyStore()
        let ephemeralKey = try keyStore.generateKey(type: .ephemeral, curve: .secp256r1)

        // Create KAS URL - using the remote service
        let kasURL = "http://10.0.0.138:8080"

        // Create policy
        let policy = NanoTDF.Policy(
            body: NanoTDF.PolicyBody(
                dataAttributes: [],
                dissem: [],
                kasURL: kasURL
            ),
            keyAccess: NanoTDF.KeyAccess(
                keyType: .remote,
                kasURL: kasURL,
                protocol: "kas",
                ephemeralPublicKey: ephemeralKey.publicKey
            )
        )

        // Create NanoTDF
        let nanoTDF = try NanoTDF(
            policy: policy,
            payload: testData,
            ephemeralKey: ephemeralKey
        )

        // Serialize the NanoTDF
        let serialized = try nanoTDF.serialize()
        print("Created NanoTDF, size: \(serialized.count) bytes")

        // Parse the serialized NanoTDF
        let parsed = try NanoTDF(data: serialized)

        // Verify header
        #expect(parsed.header.version.major == 1)
        #expect(parsed.header.version.minor == 2)
        #expect(parsed.header.kas.protocol == .kas)

        // Verify policy (should match what we created)
        #expect(parsed.header.payloadSignature.publicKeyOwner == .nano)

        // Save the NanoTDF to a file for potential otdfctl testing
        let outputPath = FileManager.default.currentDirectoryPath + "/test_output.ntdf"
        try serialized.write(to: URL(fileURLWithPath: outputPath))
        print("Saved NanoTDF to: \(outputPath)")

        // Also create a hex dump for debugging
        let hexString = serialized.map { String(format: "%02x", $0) }.joined()
        print("NanoTDF hex (first 200 chars): \(String(hexString.prefix(200)))")
    }

    @Test("Parse existing NanoTDF file if available")
    func testParseExistingNanoTDF() throws {
        // Check if we have a NanoTDF file from otdfctl
        let testFilePath = FileManager.default.currentDirectoryPath + "/test_data.ntdf"

        guard FileManager.default.fileExists(atPath: testFilePath) else {
            print("No existing NanoTDF file found at \(testFilePath), skipping test")
            return
        }

        let data = try Data(contentsOf: URL(fileURLWithPath: testFilePath))
        print("Reading NanoTDF file, size: \(data.count) bytes")

        // Parse the NanoTDF
        let nanoTDF = try NanoTDF(data: data)

        // Display parsed information
        print("NanoTDF Version: \(nanoTDF.header.version.major).\(nanoTDF.header.version.minor)")
        print("KAS Protocol: \(nanoTDF.header.kas.protocol)")
        print("Uses ECDSA Binding: \(nanoTDF.header.useECDSABinding)")
        print("Ephemeral Key Length: \(nanoTDF.header.ephemeralKey.length)")

        if let kasURL = nanoTDF.policy?.keyAccess.kasURL {
            print("KAS URL: \(kasURL)")
        }

        print("Payload size: \(nanoTDF.payload.ciphertext.count) bytes")

        // If we can decrypt (would need proper KAS integration)
        // For now, just verify structure
        #expect(nanoTDF.header.version.major == 1)
        #expect(nanoTDF.payload.ciphertext.count > 0)
    }
}