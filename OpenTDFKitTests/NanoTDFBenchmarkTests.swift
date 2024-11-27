import XCTest
import CryptoKit
@testable import OpenTDFKit

final class NanoTDFBenchmarkTests: XCTestCase {
    
    func testEncryptionPerformance() throws {
        let kasRL = ResourceLocator(protocolEnum: .http, body: "localhost:8080")!
        let recipientBase64 = "A2ifhGOpE0DjR4R0FPXvZ6YBOrcjayIpxwtxeXTudOts"
        guard let recipientDER = Data(base64Encoded: recipientBase64) else {
            throw NSError(domain: "invalid base64 encoding", code: 0, userInfo: nil)
        }
        let kasPK = try P256.KeyAgreement.PublicKey(compressedRepresentation: recipientDER)
        let kasMetadata = try KasMetadata(resourceLocator: kasRL, publicKey: kasPK, curve: .secp256r1)
        let remotePolicy = ResourceLocator(protocolEnum: .https, body: "localhost/123")!
        let plaintext = String(repeating: "Test message for encryption. ", count: 100).data(using: .utf8)!
        
        measure {
            var policy = Policy(type: .remote, body: nil, remote: remotePolicy, binding: nil)
            let expectation = expectation(description: "Encryption completed")
            
            Task {
                let _ = try await createNanoTDF(kas: kasMetadata, policy: &policy, plaintext: plaintext)
                expectation.fulfill()
            }
            
            wait(for: [expectation], timeout: 10.0)
        }
    }
    
    func testKeyGenerationPerformance() {
        let cryptoHelper = CryptoHelper()
        
        measure {
            let expectation = expectation(description: "Key generation completed")
            
            Task {
                let _ = await cryptoHelper.generateEphemeralKeyPair(curveType: .secp256r1)
                expectation.fulfill()
            }
            
            wait(for: [expectation], timeout: 10.0)
        }
    }
    
    func testSmallPayloadPerformance() throws {
        try runEncryptionBenchmark(messageSize: 1, label: "Small Payload")
    }
    
    func testMediumPayloadPerformance() throws {
        try runEncryptionBenchmark(messageSize: 100, label: "Medium Payload")
    }
    
    func testLargePayloadPerformance() throws {
        try runEncryptionBenchmark(messageSize: 1000, label: "Large Payload")
    }
    
    private func runEncryptionBenchmark(messageSize: Int, label: String) throws {
        let cryptoHelper = CryptoHelper()
        let recipientBase64 = "A2ifhGOpE0DjR4R0FPXvZ6YBOrcjayIpxwtxeXTudOts"
        guard let recipientDER = Data(base64Encoded: recipientBase64) else {
            throw NSError(domain: "invalid base64 encoding", code: 0, userInfo: nil)
        }
        
        let plaintext = String(repeating: "Test message for encryption. ", count: messageSize).data(using: .utf8)!
        let policyBody = "classification:secret".data(using: .utf8)!
        
        measure {
            let expectation = expectation(description: "\(label) encryption completed")
            
            Task {
                let keyPair = await cryptoHelper.generateEphemeralKeyPair(curveType: .secp256r1)!
                let _ = try await cryptoHelper.deriveKeysAndEncrypt(
                    keyPair: keyPair,
                    recipientPublicKey: recipientDER,
                    plaintext: plaintext,
                    policyBody: policyBody
                )
                expectation.fulfill()
            }
            
            wait(for: [expectation], timeout: 10.0)
        }
    }
}
