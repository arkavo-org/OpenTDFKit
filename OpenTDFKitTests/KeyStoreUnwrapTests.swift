@preconcurrency import CryptoKit
@testable import OpenTDFKit
import XCTest

final class KeyStoreUnwrapTests: XCTestCase {
    func testRewrapKeyWithSharedPublicKeyStore() async throws {
        // Create test ephemeral key pair (simulating the key that will be in PolicyKeyAccess)
        let ephemeralPrivateKey = P256.KeyAgreement.PrivateKey()
        let ephemeralPublicKey = ephemeralPrivateKey.publicKey.compressedRepresentation
        
        // Setup: Create a KeyStore with the test ephemeral key
        let keyStore = KeyStore(curve: .secp256r1)
        let storedKeyPair = StoredKeyPair(
            publicKey: ephemeralPublicKey,
            privateKey: ephemeralPrivateKey.rawRepresentation
        )
        await keyStore.store(keyPair: storedKeyPair)
        
        // Create a PublicKeyStore from the KeyStore
        let publicKeyStore = await keyStore.exportPublicKeyStore()
        
        // Verify the PublicKeyStore has the key
        let publicKeys = await publicKeyStore.publicKeys
        XCTAssertEqual(publicKeys.count, 1)
        XCTAssertEqual(publicKeys.first, ephemeralPublicKey)
        
        // Create test encrypted key data
        let testData = "Test secret message".data(using: .utf8)!
        let nonce = Data([UInt8](repeating: 0, count: 12))
        let symmetricKey = SymmetricKey(size: .bits256)
        let sealedBox = try AES.GCM.seal(testData, using: symmetricKey, nonce: AES.GCM.Nonce(data: nonce))
        
        // Combine nonce, ciphertext, and tag to simulate an encrypted key
        var encryptedKey = Data()
        encryptedKey.append(nonce)
        encryptedKey.append(sealedBox.ciphertext)
        encryptedKey.append(sealedBox.tag)
        
        // Test the rewrapKey method
        let rewrappedKey = try await keyStore.rewrapKey(
            ephemeralPublicKey: ephemeralPublicKey,
            encryptedKey: encryptedKey
        )
        
        // Verify the rewrapped key is not nil and not the same as the input
        XCTAssertNotNil(rewrappedKey)
        XCTAssertNotEqual(rewrappedKey, encryptedKey)
        
        // Verify the rewrapped key is properly structured (should contain data of reasonable size)
        XCTAssertGreaterThan(rewrappedKey.count, 32, "Rewrapped key should have sufficient length")
    }
    
    func testRewrapKeyFailsWithMissingKey() async {
        // Setup: Create a KeyStore with one key
        let keyStore = KeyStore(curve: .secp256r1)
        let keyPair = await keyStore.generateKeyPair()
        await keyStore.store(keyPair: keyPair)
        
        // Create a different ephemeral public key that's not in the store
        let differentEphemeralKey = P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation
        let encryptedKey = Data([UInt8](repeating: 2, count: 48)) // Fake encrypted key data
        
        // Test that rewrapKey fails when the specific key is not found
        do {
            _ = try await keyStore.rewrapKey(
                ephemeralPublicKey: differentEphemeralKey,
                encryptedKey: encryptedKey
            )
            XCTFail("Expected to throw KeyStoreError.keyNotFound")
        } catch {
            XCTAssertEqual(error as? KeyStoreError, KeyStoreError.keyNotFound)
        }
    }
    
    func testRewrapKeyWithMultipleCurves() async throws {
        // Test with multiple curve types to ensure the implementation is robust
        let curves: [Curve] = [.secp256r1, .secp384r1, .secp521r1]
        
        for curve in curves {
            // Skip xsecp256k1 as it's unsupported
            if curve == .xsecp256k1 {
                continue
            }
            
            // Setup: Create an ephemeral key pair for this curve
            let ephemeralPrivateKey: Any
            let ephemeralPublicKey: Data
            let testData = "Test message for \(curve)".data(using: .utf8)!
            
            // Generate appropriate curve-specific ephemeral key
            switch curve {
            case .secp256r1:
                let privKey = P256.KeyAgreement.PrivateKey()
                ephemeralPrivateKey = privKey
                ephemeralPublicKey = privKey.publicKey.compressedRepresentation
            case .secp384r1:
                let privKey = P384.KeyAgreement.PrivateKey()
                ephemeralPrivateKey = privKey
                ephemeralPublicKey = privKey.publicKey.compressedRepresentation
            case .secp521r1:
                let privKey = P521.KeyAgreement.PrivateKey()
                ephemeralPrivateKey = privKey
                ephemeralPublicKey = privKey.publicKey.compressedRepresentation
            default:
                XCTFail("Unexpected curve type")
                continue
            }
            
            // Create a KeyStore and store the ephemeral key
            let keyStore = KeyStore(curve: curve)
            
            // Store the ephemeral key in the KeyStore
            switch curve {
            case .secp256r1:
                let privKey = ephemeralPrivateKey as! P256.KeyAgreement.PrivateKey
                let storedKeyPair = StoredKeyPair(
                    publicKey: ephemeralPublicKey,
                    privateKey: privKey.rawRepresentation
                )
                await keyStore.store(keyPair: storedKeyPair)
            case .secp384r1:
                let privKey = ephemeralPrivateKey as! P384.KeyAgreement.PrivateKey
                let storedKeyPair = StoredKeyPair(
                    publicKey: ephemeralPublicKey,
                    privateKey: privKey.rawRepresentation
                )
                await keyStore.store(keyPair: storedKeyPair)
            case .secp521r1:
                let privKey = ephemeralPrivateKey as! P521.KeyAgreement.PrivateKey
                let storedKeyPair = StoredKeyPair(
                    publicKey: ephemeralPublicKey,
                    privateKey: privKey.rawRepresentation
                )
                await keyStore.store(keyPair: storedKeyPair)
            default:
                continue
            }
            
            // Create test encrypted key data
            let nonce = Data([UInt8](repeating: 0, count: 12))
            let symmetricKey = SymmetricKey(size: .bits256)
            let sealedBox = try AES.GCM.seal(testData, using: symmetricKey, nonce: AES.GCM.Nonce(data: nonce))
            
            var encryptedKey = Data()
            encryptedKey.append(nonce)
            encryptedKey.append(sealedBox.ciphertext)
            encryptedKey.append(sealedBox.tag)
            
            // Execute the test
            do {
                let rewrappedKey = try await keyStore.rewrapKey(
                    ephemeralPublicKey: ephemeralPublicKey,
                    encryptedKey: encryptedKey
                )
                
                // Verify results
                XCTAssertNotNil(rewrappedKey, "Rewrapped key should not be nil for \(curve)")
                XCTAssertNotEqual(rewrappedKey, encryptedKey, "Rewrapped key should differ from input for \(curve)")
                XCTAssertGreaterThan(rewrappedKey.count, 32, "Rewrapped key should have sufficient length for \(curve)")
            } catch {
                XCTFail("Failed to rewrap key for curve \(curve): \(error)")
            }
        }
    }
}