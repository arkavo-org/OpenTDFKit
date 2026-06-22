import Foundation
import XCTest

@preconcurrency import CryptoKit // Add this to handle Sendable warnings
@testable import OpenTDFKit

final class CryptoHelperTests: XCTestCase {
    func testInitializeSmallNanoTDFPositive() async throws {
        let cryptoHelper = CryptoHelper()

        // Step 1: Initial Key Exchange
        // Recipient Compressed Public Key
        let recipientBase64 = "A2ifhGOpE0DjR4R0FPXvZ6YBOrcjayIpxwtxeXTudOts"
        guard let recipientDER = Data(base64Encoded: recipientBase64) else {
            throw NSError(domain: "invalid base64 encoding", code: 0, userInfo: nil)
        }

        // Generate ephemeral key pair for P256
        guard let keyPair = await cryptoHelper.generateEphemeralKeyPair(curveType: .secp256r1) else {
            XCTFail("Failed to generate ephemeral key pair")
            return
        }

        // Step 3: Derive shared secret and symmetric key in a single actor-isolated call
        let result = try await cryptoHelper.deriveKeysAndEncrypt(
            keyPair: keyPair,
            recipientPublicKey: recipientDER,
            plaintext: "This is a secret message".data(using: .utf8)!,
            policyBody: "classification:secret".data(using: .utf8)!,
        )

        // Step 4: Verify the results
        XCTAssertNotNil(result.gmacTag, "GMAC tag should not be nil")
        XCTAssertEqual(result.gmacTag.count, 8, "GMAC tag should be truncated to 8 bytes (64 bits)")
        XCTAssertNotNil(result.ciphertext, "Ciphertext should not be nil")
        XCTAssertNotNil(result.tag, "Authentication tag should not be nil")
        XCTAssertNotNil(result.nonce, "Nonce should not be nil")

        // Step 5: Verify decryption
        let decrypted = try await cryptoHelper.decryptWithDerivedKeys(
            keyPair: keyPair,
            recipientPublicKey: recipientDER,
            ciphertext: result.ciphertext,
            nonce: result.nonce,
            tag: result.tag,
        )

        XCTAssertEqual(
            String(data: decrypted, encoding: .utf8),
            "This is a secret message",
            "Decrypted text should match original plaintext",
        )
    }
}
