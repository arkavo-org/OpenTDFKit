import CryptoKit
@testable import OpenTDFKit
import XCTest

class NanoTDFCreationTests: XCTestCase {
    func testCreateNanoTDF() async throws {
        let kasRL = ResourceLocator(protocolEnum: .http, body: "localhost:8080")
        XCTAssertNotNil(kasRL)
        let recipientBase64 = "A2ifhGOpE0DjR4R0FPXvZ6YBOrcjayIpxwtxeXTudOts"
        guard let recipientDER = Data(base64Encoded: recipientBase64) else {
            throw NSError(domain: "invalid base64 encoding", code: 0, userInfo: nil)
        }
        let kasPK = try P256.KeyAgreement.PublicKey(compressedRepresentation: recipientDER)
        let kasMetadata = try KasMetadata(resourceLocator: kasRL!, publicKey: kasPK, curve: .secp256r1)
//        let policyBody = "classification:secret".data(using: .utf8)!
//        let embeddedPolicy = EmbeddedPolicyBody(length: policyBody.count, body: policyBody, keyAccess: nil)
        let remotePolicy = ResourceLocator(protocolEnum: .https, body: "localhost/123")
        var policy = Policy(type: .remote, body: nil, remote: remotePolicy, binding: nil)
        let plaintext = "Keep this message secret".data(using: .utf8)!
        // create
        let nanoTDF = try await createNanoTDF(kas: kasMetadata, policy: &policy, plaintext: plaintext)
        XCTAssertNotNil(nanoTDF, "NanoTDF should not be nil")
        XCTAssertNotNil(nanoTDF.header, "Header should not be nil")
        XCTAssertNotNil(nanoTDF.header.policy.remote, "Policy body should not be nil")
        XCTAssertNotNil(nanoTDF.header.ephemeralPublicKey, "Ephemeral PublicKey should not be nil")
        XCTAssertNotNil(nanoTDF.payload, "Payload should not be nil")
        XCTAssertNotNil(nanoTDF.payload.iv, "Payload nonce should not be nil")
        XCTAssertNotNil(nanoTDF.payload.ciphertext, "Payload ciphertext should not be nil")
        XCTAssertEqual(nanoTDF.payload.length, 43)
        print(nanoTDF)
        // round trip - serialize
        let serializedData = nanoTDF.toData()
        var counter = 0
        let serializedHexString = serializedData.map { byte -> String in
            counter += 1
            let newline = counter % 20 == 0 ? "\n" : " "
            return String(format: "%02x", byte) + newline
        }.joined()
        print("Created:")
        print(serializedHexString)
        // round trip - parse
        let parser = BinaryParser(data: serializedData)
        let header = try parser.parseHeader()
        print("Parsed Header:", header)
        let pheader = header.toData()
        counter = 0
        let pheaderHexString = pheader.map { byte -> String in
            counter += 1
            let newline = counter % 20 == 0 ? "\n" : " "
            return String(format: "%02x", byte) + newline
        }.joined()
        print("Parsed Header:")
        print(pheaderHexString)
        // Policy
        let policyHexString = header.policy.toData().map { String(format: "%02x", $0) }.joined(separator: " ")
        print("Policy:", policyHexString)
        // Ephemeral Key
        let ephemeralKeyHexString = header.ephemeralPublicKey.map { String(format: "%02x", $0) }.joined(separator: " ")
        print("Ephemeral Key:", ephemeralKeyHexString)
        let payload = try parser.parsePayload(config: header.payloadSignatureConfig)
        let snanoTDF = NanoTDF(header: header, payload: payload, signature: nil)
        // Print final the signature NanoTDF
        print(snanoTDF)
        XCTAssertEqual(payload.length, 43)
    }
}
