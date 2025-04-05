@preconcurrency import CryptoKit
@testable import OpenTDFKit
import XCTest

final class KASServiceBenchmarkTests: XCTestCase {
    func testKASMetadataGenerationPerformance() async throws {
        let keyStore = KeyStore(curve: .secp256r1, capacity: 1000)
        let baseURL = URL(string: "https://example.kas.com")!
        let credential = KASCredential(clientId: "test-client", clientSecret: "test-secret")

        let kasService = KASService(keyStore: keyStore, baseURL: baseURL, credential: credential)

        let startTime = DispatchTime.now()
        let iterations = 100

        for _ in 0 ..< iterations {
            let _ = try await kasService.generateKasMetadata()
        }

        let endTime = DispatchTime.now()
        let timeInterval = Double(endTime.uptimeNanoseconds - startTime.uptimeNanoseconds) / 1_000_000
        let avgTime = timeInterval / Double(iterations)

        print("\nKAS Metadata Generation Performance:")
        print("- Average time: \(avgTime) ms per operation")
        print("- Operations per second: \(1000 / avgTime)")
        print("- Total time for \(iterations) operations: \(timeInterval) ms")
    }

    func testLocalKeyAccessPerformance() async throws {
        // Create a key store with different curve types
        let curves: [Curve] = [.secp256r1, .secp384r1, .secp521r1]
        let iterations = 10
        let messageSize = 64

        print("\nLocal Key Access Performance for Different Curves:")

        for curve in curves {
            let keyStore = KeyStore(curve: curve, capacity: 100)
            let baseURL = URL(string: "https://example.kas.com")!
            let kasService = KASService(keyStore: keyStore, baseURL: baseURL)

            // Generate and store initial keys
            try await keyStore.generateAndStoreKeyPairs(count: 10)

            // Generate a KAS metadata to get a valid key pair
            let kasMetadata = try await kasService.generateKasMetadata()
            let kasPublicKey = try kasMetadata.getPublicKey()

            // Verify the private key exists in the KeyStore
            guard await keyStore.getPrivateKey(forPublicKey: kasPublicKey) != nil else {
                print("Failed to retrieve private key for \(curve)")
                continue
            }

            // Generate test data
            let cryptoHelper = CryptoHelper()
            let plaintext = Data(repeating: 0xA5, count: messageSize)

            // Start benchmark
            let startTime = DispatchTime.now()

            for _ in 0 ..< iterations {
                // Generate an ephemeral key pair
                guard let ephemeralKeyPair = await cryptoHelper.generateEphemeralKeyPair(curveType: curve) else {
                    continue
                }

                // Create a shared secret for encryption
                guard let sharedSecret = try await cryptoHelper.deriveSharedSecret(
                    keyPair: ephemeralKeyPair,
                    recipientPublicKey: kasPublicKey
                ) else {
                    continue
                }

                // Derive a symmetric key
                let symmetricKey = await cryptoHelper.deriveSymmetricKey(
                    sharedSecret: sharedSecret,
                    salt: Data("test".utf8),
                    info: Data("benchmark".utf8)
                )

                // Encrypt sample data with proper format
                let nonce = await cryptoHelper.generateNonce()
                let paddedNonce = await cryptoHelper.adjustNonce(nonce, to: 12)
                let sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: AES.GCM.Nonce(data: paddedNonce))

                // Prepare encrypted key data in the expected format
                var encryptedKey = Data()
                encryptedKey.append(paddedNonce)
                encryptedKey.append(sealedBox.ciphertext)
                encryptedKey.append(sealedBox.tag)

                // Process key access (the actual benchmark operation)
                do {
                    let _ = try await kasService.processKeyAccess(
                        ephemeralPublicKey: ephemeralKeyPair.publicKey,
                        encryptedKey: encryptedKey,
                        kasPublicKey: kasPublicKey
                    )
                } catch {
                    print("Error processing key access: \(error)")
                    continue
                }
            }

            let endTime = DispatchTime.now()
            let timeInterval = Double(endTime.uptimeNanoseconds - startTime.uptimeNanoseconds) / 1_000_000
            let avgTime = timeInterval / Double(iterations)

            print("- \(curve): \(avgTime) ms per operation, \(1000 / avgTime) ops/sec")
        }
    }

    func testPolicyBindingVerificationPerformance() async throws {
        let kasService = KASService(
            keyStore: KeyStore(curve: .secp256r1, capacity: 10),
            baseURL: URL(string: "https://example.kas.com")!
        )

        // Generate test data
        let policySizes = [10, 100, 1000, 10000]
        let iterations = 1000

        print("\nPolicy Binding Verification Performance:")

        for size in policySizes {
            let policyData = Data(repeating: 0x42, count: size)
            let symmetricKey = SymmetricKey(size: .bits256)

            // Create a GMAC binding
            let policyBinding = try AES.GCM.seal(Data(), using: symmetricKey, authenticating: policyData).tag

            // Start benchmark
            let startTime = DispatchTime.now()

            for _ in 0 ..< iterations {
                let _ = try await kasService.verifyPolicyBinding(
                    policyBinding: policyBinding,
                    policyData: policyData,
                    symmetricKey: symmetricKey
                )
            }

            let endTime = DispatchTime.now()
            let timeInterval = Double(endTime.uptimeNanoseconds - startTime.uptimeNanoseconds) / 1_000_000
            let avgTime = timeInterval / Double(iterations)

            print("- Policy size \(size) bytes: \(avgTime) ms per verification, \(1000 / avgTime) verifications/sec")
        }
    }

    func testKeyStoreScalabilityWithKAS() async throws {
        let keyCounts = [100, 1000, 5000]
        let iterations = 20

        print("\nKAS Service Performance with Different KeyStore Sizes:")

        for count in keyCounts {
            let keyStore = KeyStore(curve: .secp256r1, capacity: count)
            let baseURL = URL(string: "https://example.kas.com")!
            let kasService = KASService(keyStore: keyStore, baseURL: baseURL)

            // Generate and store initial keys
            print("- Generating \(count) keys...")
            try await keyStore.generateAndStoreKeyPairs(count: count)

            // Generate random test keys outside of timing measurement
            var testKeys: [Data] = []
            for _ in 0 ..< iterations {
                let keyPair = await keyStore.generateKeyPair()
                await keyStore.store(keyPair: keyPair)
                testKeys.append(keyPair.publicKey)
            }

            // Start KAS metadata generation benchmark
            print("  Testing KAS metadata generation...")
            let metadataStartTime = DispatchTime.now()

            for _ in 0 ..< iterations {
                let _ = try await kasService.generateKasMetadata()
            }

            let metadataEndTime = DispatchTime.now()
            let metadataTime = Double(metadataEndTime.uptimeNanoseconds - metadataStartTime.uptimeNanoseconds) / 1_000_000
            let avgMetadataTime = metadataTime / Double(iterations)

            // Create a crypto helper for key access testing
            let cryptoHelper = CryptoHelper()

            // Start key access processing benchmark
            print("  Testing key access processing...")
            let accessStartTime = DispatchTime.now()

            for i in 0 ..< iterations {
                let ephemeralKeyPair = await cryptoHelper.generateEphemeralKeyPair(curveType: .secp256r1)!
                let kasPublicKey = testKeys[i]

                // Create dummy encrypted key data
                let encryptedKey = Data(repeating: 0xAA, count: 64)

                do {
                    let _ = try await kasService.processKeyAccess(
                        ephemeralPublicKey: ephemeralKeyPair.publicKey,
                        encryptedKey: encryptedKey,
                        kasPublicKey: kasPublicKey
                    )
                } catch {
                    // Expected to fail with invalid format, we're just measuring performance
                }
            }

            let accessEndTime = DispatchTime.now()
            let accessTime = Double(accessEndTime.uptimeNanoseconds - accessStartTime.uptimeNanoseconds) / 1_000_000
            let avgAccessTime = accessTime / Double(iterations)

            print("""
            - KeyStore with \(count) keys:
              * KAS metadata generation: \(avgMetadataTime) ms per operation
              * Key access processing: \(avgAccessTime) ms per operation
              * Total overhead with \(count) keys: \(avgMetadataTime + avgAccessTime) ms
            """)
        }
    }
}
