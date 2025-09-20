@preconcurrency import CryptoKit
@testable import OpenTDFKit
import XCTest

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

    // New benchmark tests

    func testSignaturePerformance() async throws {
        let kasRL = ResourceLocator(protocolEnum: .http, body: "localhost:8080")!
        let recipientBase64 = "A2ifhGOpE0DjR4R0FPXvZ6YBOrcjayIpxwtxeXTudOts"
        guard let recipientDER = Data(base64Encoded: recipientBase64) else {
            throw NSError(domain: "invalid base64 encoding", code: 0, userInfo: nil)
        }
        let kasPK = try P256.KeyAgreement.PublicKey(compressedRepresentation: recipientDER)
        let kasMetadata = try KasMetadata(resourceLocator: kasRL, publicKey: kasPK, curve: .secp256r1)
        let remotePolicy = ResourceLocator(protocolEnum: .https, body: "localhost/123")!
        let plaintext = String(repeating: "Test message for encryption. ", count: 100).data(using: .utf8)!

        // Generate a signing key once outside the measurement
        let signingKey = P256.Signing.PrivateKey()
        let config = SignatureAndPayloadConfig(signed: true, signatureCurve: .secp256r1, payloadCipher: .aes256GCM128)

        // Measure manually instead of using XCTest measure
        let iterations = 10
        let startTime = DispatchTime.now()

        for _ in 0 ..< iterations {
            var policy = Policy(type: .remote, body: nil, remote: remotePolicy, binding: nil)
            var tdf = try await createNanoTDF(kas: kasMetadata, policy: &policy, plaintext: plaintext)
            try await addSignatureToNanoTDF(nanoTDF: &tdf, privateKey: signingKey, config: config)
        }

        let endTime = DispatchTime.now()
        let timeInterval = Double(endTime.uptimeNanoseconds - startTime.uptimeNanoseconds) / 1_000_000
        let avgTime = timeInterval / Double(iterations)

        print("\nSignature Performance:")
        print("- Average time: \(avgTime) ms per operation")
        print("- Operations per second: \(1000 / avgTime)")
    }

    func testEncryptionPerformanceWithDifferentCurves() async throws {
        let curves: [Curve] = [.secp256r1, .secp384r1, .secp521r1]
        let plaintext = String(repeating: "Test message for encryption. ", count: 100).data(using: .utf8)!
        let cryptoHelper = CryptoHelper()

        print("\nEncryption Performance with Different Curves:")

        for curve in curves {
            let startTime = DispatchTime.now()
            let iterations = 20

            for _ in 0 ..< iterations {
                guard let keyPair = await cryptoHelper.generateEphemeralKeyPair(curveType: curve) else {
                    continue
                }

                // Create a recipient public key of the same curve type
                let recipientKeyPair = await cryptoHelper.generateEphemeralKeyPair(curveType: curve)!

                // Simple encryption with symmetric key derivation
                let sharedSecret = try await cryptoHelper.deriveSharedSecret(
                    keyPair: keyPair,
                    recipientPublicKey: recipientKeyPair.publicKey,
                )!

                let symmetricKey = await cryptoHelper.deriveSymmetricKey(
                    sharedSecret: sharedSecret,
                    salt: Data("test".utf8),
                    info: Data("benchmark".utf8),
                )

                let nonce = await cryptoHelper.generateNonce()
                _ = try await cryptoHelper.encryptPayload(
                    plaintext: plaintext,
                    symmetricKey: symmetricKey,
                    nonce: nonce,
                )
            }

            let endTime = DispatchTime.now()
            let timeInterval = Double(endTime.uptimeNanoseconds - startTime.uptimeNanoseconds) / 1_000_000
            let avgTime = timeInterval / Double(iterations)

            print("- \(curve): \(avgTime) ms per operation, \(1000 / avgTime) ops/sec")
        }
    }

    func testDecryptionPerformance() async throws {
        let cryptoHelper = CryptoHelper()
        let plaintext = String(repeating: "Test message for decryption benchmark. ", count: 100).data(using: .utf8)!

        let symmetricKey = SymmetricKey(size: .bits256)
        let nonce = await cryptoHelper.generateNonce()
        let (ciphertext, tag) = try await cryptoHelper.encryptPayload(
            plaintext: plaintext,
            symmetricKey: symmetricKey,
            nonce: nonce,
        )

        // Measure manually instead of using XCTest measure
        let iterations = 100
        let startTime = DispatchTime.now()

        for _ in 0 ..< iterations {
            _ = try await cryptoHelper.decryptPayload(
                ciphertext: ciphertext,
                symmetricKey: symmetricKey,
                nonce: nonce,
                tag: tag,
            )
        }

        let endTime = DispatchTime.now()
        let timeInterval = Double(endTime.uptimeNanoseconds - startTime.uptimeNanoseconds) / 1_000_000
        let avgTime = timeInterval / Double(iterations)

        print("\nDecryption Performance:")
        print("- Average time: \(avgTime) ms per operation")
        print("- Operations per second: \(1000 / avgTime)")
    }

    func testSerializationPerformance() async throws {
        let kasRL = ResourceLocator(protocolEnum: .http, body: "localhost:8080")!
        let recipientBase64 = "A2ifhGOpE0DjR4R0FPXvZ6YBOrcjayIpxwtxeXTudOts"
        guard let recipientDER = Data(base64Encoded: recipientBase64) else {
            throw NSError(domain: "invalid base64 encoding", code: 0, userInfo: nil)
        }
        let kasPK = try P256.KeyAgreement.PublicKey(compressedRepresentation: recipientDER)
        let kasMetadata = try KasMetadata(resourceLocator: kasRL, publicKey: kasPK, curve: .secp256r1)
        let remotePolicy = ResourceLocator(protocolEnum: .https, body: "localhost/123")!

        // Test with different payload sizes
        let payloadSizes = [10, 100, 1000, 10000]

        print("\nNanoTDF Serialization Performance:")

        for size in payloadSizes {
            let plaintext = String(repeating: "X", count: size).data(using: .utf8)!
            var policy = Policy(type: .remote, body: nil, remote: remotePolicy, binding: nil)

            let tdf = try await createNanoTDF(kas: kasMetadata, policy: &policy, plaintext: plaintext)

            let startTime = DispatchTime.now()
            let iterations = 100

            for _ in 0 ..< iterations {
                _ = tdf.toData()
            }

            let endTime = DispatchTime.now()
            let timeInterval = Double(endTime.uptimeNanoseconds - startTime.uptimeNanoseconds) / 1_000_000
            let avgTime = timeInterval / Double(iterations)

            print("- Size \(size) bytes: \(avgTime) ms per operation, throughput: \(Double(tdf.toData().count) / (avgTime / 1000) / 1024) KB/s")
        }
    }

    // Helper function for benchmarking - complete end-to-end encryption
    private static func deriveKeysAndEncryptBenchmark(
        cryptoHelper: CryptoHelper,
        keyPair: EphemeralKeyPair,
        recipientPublicKey: Data,
        plaintext: Data,
        policyBody: Data,
    ) async throws -> (encryptedData: Data, policyBinding: Data) {
        // 1. Derive shared secret
        guard let sharedSecret = try await cryptoHelper.deriveSharedSecret(
            keyPair: keyPair,
            recipientPublicKey: recipientPublicKey,
        ) else {
            throw CryptoHelperError.keyDerivationFailed
        }

        // 2. Derive symmetric key
        let symmetricKey = await cryptoHelper.deriveSymmetricKey(
            sharedSecret: sharedSecret,
            salt: Data("L1L".utf8),
            info: Data("encryption".utf8),
        )

        // 3. Create policy binding
        let binding = try await cryptoHelper.createGMACBinding(policyBody: policyBody, symmetricKey: symmetricKey)

        // 4. Encrypt payload
        let nonce = await cryptoHelper.generateNonce()
        let (ciphertext, tag) = try await cryptoHelper.encryptPayload(
            plaintext: plaintext,
            symmetricKey: symmetricKey,
            nonce: nonce,
        )

        // 5. Combine encrypted components
        var encryptedData = Data()
        encryptedData.append(nonce)
        encryptedData.append(ciphertext)
        encryptedData.append(tag)

        return (encryptedData, binding)
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
                let _ = try await NanoTDFBenchmarkTests.deriveKeysAndEncryptBenchmark(
                    cryptoHelper: cryptoHelper,
                    keyPair: keyPair,
                    recipientPublicKey: recipientDER,
                    plaintext: plaintext,
                    policyBody: policyBody,
                )
                expectation.fulfill()
            }

            wait(for: [expectation], timeout: 10.0)
        }
    }
}
