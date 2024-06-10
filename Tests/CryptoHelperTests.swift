import CryptoKit
import Foundation
import XCTest

@testable import NanoTDF

final class CryptoHelperTests: XCTestCase {
    func testInitializeSmallNanoTDFPositive() throws {
        // Step 1: Initial Key Exchange
        // Recipient Compressed Public Key
        let recipientBase64 = "A2ifhGOpE0DjR4R0FPXvZ6YBOrcjayIpxwtxeXTudOts"
        guard let recipientDER = Data(base64Encoded: recipientBase64) else {
            throw NSError(domain: "invalid base64 encoding", code: 0, userInfo: nil)
        }
        // Assume we have recipient's public key
        let recipientPublicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: recipientDER)
        // Generate ephemeral key pair for P256
        if let (ephemeralPrivateKey, _) = CryptoHelper.generateEphemeralKeyPair(curveType: .secp256r1) {
            // Step 3: Derive shared secret
            if let sharedSecret = try CryptoHelper.deriveSharedSecret(curveType: .secp256r1, ephemeralPrivateKey: ephemeralPrivateKey, recipientPublicKey: recipientPublicKey) {
                print("Shared Secret: \(sharedSecret)")
                // Step 4: Derive symmetric key
                let symmetricKey = CryptoHelper.deriveSymmetricKey(sharedSecret: sharedSecret)
                print("Symmetric Key: \(symmetricKey)")
                // Create GMAC binding for the policy body
                let policyBody = "classification:secret".data(using: .utf8)!
                let gmacTag = try CryptoHelper.createGMACBinding(policyBody: policyBody, symmetricKey: symmetricKey)
                print("GMAC Tag: \(gmacTag.base64EncodedString())")
                // Step 5: Generate nonce (IV)
                let nonce = CryptoHelper.generateNonce()
                print("Nonce (IV): \(nonce)")
                // Step 6: Encrypt payload
                let plaintext = Data("This is a secret message".utf8)
                let (ciphertext, tag) = try CryptoHelper.encryptPayload(plaintext: plaintext, symmetricKey: symmetricKey, nonce: nonce)
                print("Ciphertext: \(ciphertext)")
                print("Tag: \(tag)")
            }
        }
    }
}
