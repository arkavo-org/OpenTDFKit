import CryptoKit
@testable import OpenTDFKit
import XCTest

// commented due to need of nanoTDF.storedKey
// public struct NanoTDF {
// public var header: Header
// var payload: Payload
// var signature: Signature?
// #if DEBUG
//    var storedKey: SymmetricKey?
// #endif
// class SymmetricKeyTests: XCTestCase {
//    let originalMessage = "This is a secret message for TDF testing."
//    // Simulating key storage
//    static var storedKey: SymmetricKey?
//    static var nanoTDF: NanoTDF?
//
//    func testSymmetricKeyEncryptionDecryption() throws {
//        // Test data
//        let messageData = Data(originalMessage.utf8)
//        // Create nanoTDF parts
//        let kasRL = ResourceLocator(protocolEnum: .http, body: "localhost:8080")
//        XCTAssertNotNil(kasRL)
//        let recipientBase64 = "A2ifhGOpE0DjR4R0FPXvZ6YBOrcjayIpxwtxeXTudOts"
//        guard let recipientDER = Data(base64Encoded: recipientBase64) else {
//            throw NSError(domain: "invalid base64 encoding", code: 0, userInfo: nil)
//        }
//        let kasPK = try P256.KeyAgreement.PublicKey(compressedRepresentation: recipientDER)
//        let kasMetadata = KasMetadata(resourceLocator: kasRL!, publicKey: kasPK, curve: .secp256r1)
//        let remotePolicy = ResourceLocator(protocolEnum: .https, body: "localhost/123")
//        var policy = Policy(type: .remote, body: nil, remote: remotePolicy, binding: nil)
//        // create and encrypt
//        let nanoTDF = try createNanoTDF(kas: kasMetadata, policy: &policy, plaintext: messageData)
//        // Store key and encrypted data (simulating storage or transmission)
//        Self.storedKey = nanoTDF.storedKey
//        Self.nanoTDF = nanoTDF
//        // Decrypt in a separate function to simulate decryption in a different context
//        try decryptAndVerify(originalMessage: originalMessage)
//    }
//
//    func decryptAndVerify(originalMessage: String) throws {
//        guard let storedKey = Self.storedKey,
//              let nanoTDF = Self.nanoTDF
//        else {
//            XCTFail("Stored key or encrypted data is missing")
//            return
//        }
//
//        let decryptedData = try nanoTDF.getPayloadPlaintext(symmetricKey: storedKey)
//        let decryptedMessage = String(data: decryptedData, encoding: .utf8)
//
//        XCTAssertEqual(decryptedMessage, originalMessage, "Decrypted message doesn't match the original")
//    }
//
//    func writeNanoTDFToFile() throws -> URL {
//        guard let nanoTDF = Self.nanoTDF else {
//            throw NSError(domain: "TestError", code: 0, userInfo: [NSLocalizedDescriptionKey: "NanoTDF is not available"])
//        }
//
//        let data = nanoTDF.toData()
//
//        // Create a temporary file URL
//        let tempDir = FileManager.default.temporaryDirectory
//        let fileName = "test_nanotdf_\(UUID().uuidString).tdf"
//        let fileURL = tempDir.appendingPathComponent(fileName)
//
//        // Write the data to the file
//        try data.write(to: fileURL)
//
//        print("NanoTDF written to file: \(fileURL.path)")
//
//        return fileURL
//    }
//
//    func testWriteAndReadNanoTDF() throws {
//        // First, ensure we have a NanoTDF object (you might need to create one if not already available)
//        // For this example, I'm assuming testSymmetricKeyEncryptionDecryption has been run
//        try testSymmetricKeyEncryptionDecryption()
//
//        // Write NanoTDF to file
//        let fileURL = try writeNanoTDFToFile()
//
//        // Read the file back
//        let readData = try Data(contentsOf: fileURL)
//
//        // Verify the data
//        XCTAssertEqual(readData, Self.nanoTDF?.toData(), "Data read from file doesn't match original NanoTDF data")
//
//        let parser = BinaryParser(data: readData)
//        let header = try parser.parseHeader()
//        let payload = try parser.parsePayload(config: header.payloadSignatureConfig)
//        let nanoTDF = NanoTDF(header: header, payload: payload, signature: nil)
//        Self.nanoTDF = nanoTDF
//        // Decrypt in a separate function to simulate decryption in a different context
//        try decryptAndVerify(originalMessage: originalMessage)
//        // Clean up: delete the file
//        try FileManager.default.removeItem(at: fileURL)
//    }
// }
