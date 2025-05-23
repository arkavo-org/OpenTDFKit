import CryptoKit
@testable import OpenTDFKit
import XCTest

final class EncryptedPolicyTests: XCTestCase {
    func testEmbeddedPlaintextPolicy() async throws {
        // Create KAS ResourceLocator
        let kasRL = ResourceLocator(protocolEnum: .http, body: "kas.example.org")!

        // Generate a key pair for the KAS
        let kasKeyPair = P256.KeyAgreement.PrivateKey()
        let kasPubKey = kasKeyPair.publicKey

        // Create KAS metadata
        let kasMetadata = try KasMetadata(resourceLocator: kasRL, publicKey: kasPubKey, curve: .secp256r1)

        // Create policy data
        let policyData = """
        {
            "classification": "confidential",
            "sensitivity": "high",
            "category": "financial"
        }
        """.data(using: .utf8)!

        // Create EmbeddedPolicyBody with plaintext policy
        let embeddedPolicyBody = EmbeddedPolicyBody(
            body: policyData,
            keyAccess: nil
        )

        // Create Policy with embeddedEncryptedWithPolicyKeyAccess type
        var policy = Policy(
            type: .embeddedPlaintext,
            body: embeddedPolicyBody,
            remote: nil,
            binding: nil
        )

        // Create plaintext payload
        let plaintext = "This is sensitive data protected with policy".data(using: .utf8)!

        // Create the NanoTDF with encrypted policy
        let nanoTDF = try await createNanoTDF(kas: kasMetadata, policy: &policy, plaintext: plaintext)

        // Verify the NanoTDF was created properly
        XCTAssertEqual(nanoTDF.header.kas.body, "kas.example.org")
        XCTAssertNotNil(nanoTDF.header.ephemeralPublicKey)
        XCTAssertEqual(nanoTDF.header.policy.type, .embeddedPlaintext)

        // Serialize the NanoTDF
        let serializedData = nanoTDF.toData()
        XCTAssertFalse(serializedData.isEmpty)

        // Round-trip: Parse the serialized data back into a NanoTDF
        let parser = BinaryParser(data: serializedData)

        // Parse the header
        let header = try parser.parseHeader()
        XCTAssertEqual(header.policy.type, .embeddedPlaintext)
        XCTAssertNotNil(header.policy.body)

        // Parse the payload
        let payload = try parser.parsePayload(config: header.payloadSignatureConfig)
        XCTAssertEqual(payload.length, nanoTDF.payload.length)
        XCTAssertEqual(payload.iv, nanoTDF.payload.iv)
        XCTAssertEqual(payload.ciphertext, nanoTDF.payload.ciphertext)
        XCTAssertEqual(payload.mac, nanoTDF.payload.mac)

        // Create a complete parsed NanoTDF
        let parsedNanoTDF = NanoTDF(header: header, payload: payload, signature: nil)

        // Verify the round-trip serialization matches
        let reserializedData = parsedNanoTDF.toData()
        XCTAssertEqual(serializedData, reserializedData, "Serialized data should match after round-trip")
    }

    // TODO: Fix encrypted policy test when the required infrastructure is in place
    // Requires working with KeyStore and proper policy KAS setup
    func disabled_testEncryptedPolicyWithKeyAccess() async throws {
        // Create KAS ResourceLocator
        let kasRL = ResourceLocator(protocolEnum: .http, body: "kas.example.org")!

        // Create Policy KAS ResourceLocator (could be the same or different from main KAS)
        let policyKasRL = ResourceLocator(protocolEnum: .http, body: "policy-kas.example.org")!

        // Generate a key pair for the KAS
        let kasKeyPair = P256.KeyAgreement.PrivateKey()
        let kasPubKey = kasKeyPair.publicKey

        // Generate a key pair for the policy KAS
        let policyKasKeyPair = P256.KeyAgreement.PrivateKey()
        let policyKasPubKey = policyKasKeyPair.publicKey

        // Create KAS metadata
        let kasMetadata = try KasMetadata(resourceLocator: kasRL, publicKey: kasPubKey, curve: .secp256r1)

        // Create policy data
        let policyData = """
        {
            "classification": "confidential",
            "sensitivity": "high",
            "category": "financial"
        }
        """.data(using: .utf8)!

        // Create PolicyKeyAccess with policy KAS information
        let policyKeyAccess = PolicyKeyAccess(
            resourceLocator: policyKasRL,
            ephemeralPublicKey: policyKasPubKey.compressedRepresentation
        )

        // Create EmbeddedPolicyBody with plaintext policy and key access
        let embeddedPolicyBody = EmbeddedPolicyBody(
            body: policyData,
            keyAccess: policyKeyAccess
        )

        // Create Policy with embeddedEncryptedWithPolicyKeyAccess type
        var policy = Policy(
            type: .embeddedEncryptedWithPolicyKeyAccess,
            body: embeddedPolicyBody,
            remote: nil,
            binding: nil
        )

        // Create plaintext payload
        let plaintext = "This is sensitive data protected with encrypted policy".data(using: .utf8)!

        // Create the NanoTDF with encrypted policy
        let nanoTDF = try await createNanoTDF(kas: kasMetadata, policy: &policy, plaintext: plaintext)

        // Verify the NanoTDF was created properly
        XCTAssertEqual(nanoTDF.header.kas.body, "kas.example.org")
        XCTAssertNotNil(nanoTDF.header.ephemeralPublicKey)
        XCTAssertEqual(nanoTDF.header.policy.type, .embeddedEncryptedWithPolicyKeyAccess)
    }
}
