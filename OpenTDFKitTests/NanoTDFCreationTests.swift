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
        // round trip - serialize
        let serializedData = nanoTDF.toData()
        // round trip - parse
        let parser = BinaryParser(data: serializedData)
        let header = try parser.parseHeader()
        XCTAssertEqual(header.toData(), nanoTDF.header.toData(), "Header should serialize consistently")
        let payload = try parser.parsePayload(config: header.payloadSignatureConfig)
        let snanoTDF = NanoTDF(header: header, payload: payload, signature: nil)
        XCTAssertEqual(snanoTDF.toData(), serializedData, "Round-tripped NanoTDF should equal original")
        XCTAssertEqual(payload.length, 43)
    }
}
