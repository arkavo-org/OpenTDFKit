import CryptoKit
import Foundation
import XCTest

@preconcurrency import CryptoKit  // Add this to handle Sendable warnings

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
            policyBody: "classification:secret".data(using: .utf8)!
        )
        
        // Step 4: Verify the results
        XCTAssertNotNil(result.gmacTag, "GMAC tag should not be nil")
        XCTAssertNotNil(result.ciphertext, "Ciphertext should not be nil")
        XCTAssertNotNil(result.tag, "Authentication tag should not be nil")
        XCTAssertNotNil(result.nonce, "Nonce should not be nil")
        
        // Step 5: Verify decryption
        let decrypted = try await cryptoHelper.decryptWithDerivedKeys(
            keyPair: keyPair,
            recipientPublicKey: recipientDER,
            ciphertext: result.ciphertext,
            nonce: result.nonce,
            tag: result.tag
        )
        
        XCTAssertEqual(
            String(data: decrypted, encoding: .utf8),
            "This is a secret message",
            "Decrypted text should match original plaintext"
        )
    }
}

// Add these to CryptoHelper.swift:
extension CryptoHelper {
    // Combined operation that keeps sensitive types within the actor
    struct EncryptionResult {
        let gmacTag: Data
        let nonce: Data
        let ciphertext: Data
        let tag: Data
    }
    
    func deriveKeysAndEncrypt(
        keyPair: EphemeralKeyPair,
        recipientPublicKey: Data,
        plaintext: Data,
        policyBody: Data
    ) throws -> EncryptionResult {
        // Derive shared secret
        guard let sharedSecret = try deriveSharedSecret(
            keyPair: keyPair,
            recipientPublicKey: recipientPublicKey
        ) else {
            throw CryptoHelperError.keyDerivationFailed
        }
        
        // Derive symmetric key
        let symmetricKey = deriveSymmetricKey(
            sharedSecret: sharedSecret,
            salt: Data("L1L".utf8),
            info: Data("encryption".utf8),
            outputByteCount: 32
        )
        
        // Create GMAC binding
        let gmacTag = try createGMACBinding(
            policyBody: policyBody,
            symmetricKey: symmetricKey
        )
        
        // Generate nonce
        let nonce = generateNonce()
        
        // Encrypt payload
        let (ciphertext, tag) = try encryptPayload(
            plaintext: plaintext,
            symmetricKey: symmetricKey,
            nonce: nonce
        )
        
        return EncryptionResult(
            gmacTag: gmacTag,
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag
        )
    }
    
    func decryptWithDerivedKeys(
        keyPair: EphemeralKeyPair,
        recipientPublicKey: Data,
        ciphertext: Data,
        nonce: Data,
        tag: Data
    ) throws -> Data {
        // Derive shared secret
        guard let sharedSecret = try deriveSharedSecret(
            keyPair: keyPair,
            recipientPublicKey: recipientPublicKey
        ) else {
            throw CryptoHelperError.keyDerivationFailed
        }
        
        // Derive symmetric key
        let symmetricKey = deriveSymmetricKey(
            sharedSecret: sharedSecret,
            salt: Data("L1L".utf8),
            info: Data("encryption".utf8),
            outputByteCount: 32
        )
        
        // Decrypt
        return try decryptPayload(
            ciphertext: ciphertext,
            symmetricKey: symmetricKey,
            nonce: nonce,
            tag: tag
        )
    }
}
