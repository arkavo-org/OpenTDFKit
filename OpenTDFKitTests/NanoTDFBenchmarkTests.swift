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
                let _ = cryptoHelper.generateEphemeralKeyPair(curveType: .secp256r1)
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

    func testEncryptionPerformanceWithDifferentCurves() throws {
        let curves: [Curve] = [.secp256r1, .secp384r1, .secp521r1]
        let plaintext = String(repeating: "Test message for encryption. ", count: 100).data(using: .utf8)!
        let cryptoHelper = CryptoHelper()

        print("\nEncryption Performance with Different Curves:")

        for curve in curves {
            let startTime = DispatchTime.now()
            let iterations = 20

            for _ in 0 ..< iterations {
                guard let keyPair = cryptoHelper.generateEphemeralKeyPair(curveType: curve) else {
                    continue
                }

                // Create a recipient public key of the same curve type
                let recipientKeyPair = cryptoHelper.generateEphemeralKeyPair(curveType: curve)!

                // Simple encryption with symmetric key derivation
                let sharedSecret = try cryptoHelper.deriveSharedSecret(
                    keyPair: keyPair,
                    recipientPublicKey: recipientKeyPair.publicKey,
                )!

                let symmetricKey = cryptoHelper.deriveSymmetricKey(
                    sharedSecret: sharedSecret,
                    salt: Data("test".utf8),
                    info: Data("benchmark".utf8),
                )

                let nonce = try cryptoHelper.generateNonce()
                _ = try cryptoHelper.encryptPayload(
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

    func testDecryptionPerformance() throws {
        let cryptoHelper = CryptoHelper()
        let plaintext = String(repeating: "Test message for decryption benchmark. ", count: 100).data(using: .utf8)!

        let symmetricKey = SymmetricKey(size: .bits256)
        let nonce = try cryptoHelper.generateNonce()
        let (ciphertext, tag) = try cryptoHelper.encryptPayload(
            plaintext: plaintext,
            symmetricKey: symmetricKey,
            nonce: nonce,
        )

        // Measure manually instead of using XCTest measure
        let iterations = 100
        let startTime = DispatchTime.now()

        for _ in 0 ..< iterations {
            _ = try cryptoHelper.decryptPayload(
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

    /// Helper function for benchmarking - complete end-to-end encryption
    private static func deriveKeysAndEncryptBenchmark(
        cryptoHelper: CryptoHelper,
        keyPair: EphemeralKeyPair,
        recipientPublicKey: Data,
        plaintext: Data,
        policyBody: Data,
    ) async throws -> (encryptedData: Data, policyBinding: Data) {
        // 1. Derive shared secret
        guard let sharedSecret = try cryptoHelper.deriveSharedSecret(
            keyPair: keyPair,
            recipientPublicKey: recipientPublicKey,
        ) else {
            throw CryptoHelperError.keyDerivationFailed
        }

        // 2. Derive symmetric key
        let symmetricKey = cryptoHelper.deriveSymmetricKey(
            sharedSecret: sharedSecret,
            salt: CryptoConstants.hkdfSalt,
            info: CryptoConstants.hkdfInfoEncryption,
        )

        // 3. Create policy binding
        let binding = try cryptoHelper.createGMACBinding(policyBody: policyBody, symmetricKey: symmetricKey)

        // 4. Encrypt payload
        let nonce = try cryptoHelper.generateNonce()
        let (ciphertext, tag) = try cryptoHelper.encryptPayload(
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

    /// Create → decrypt round trips through the public API, sequentially and from
    /// 8 concurrent tasks, so per-call overhead and cross-task serialization show up.
    func testNanoTDFRoundTripThroughput() async throws {
        let keyStore = KeyStore(curve: .secp256r1)
        let kasService = try KASService(keyStore: keyStore, baseURL: XCTUnwrap(URL(string: "https://kas.example.com")))
        let kasMetadata = try await kasService.generateKasMetadata()
        let kasPublicKey = try kasMetadata.getPublicKey()
        let plaintext = Data(String(repeating: "NanoTDF throughput. ", count: 20).utf8)
        let policyBody = Data(#"{"body":{"dataAttributes":[],"dissem":[]}}"#.utf8)

        @Sendable func roundTrip() async throws {
            var policy = Policy(type: .embeddedPlaintext, body: EmbeddedPolicyBody(body: policyBody), remote: nil, binding: nil)
            let nanoTDF = try await createNanoTDF(kas: kasMetadata, policy: &policy, plaintext: plaintext)
            let symmetricKey = try await keyStore.derivePayloadSymmetricKey(
                kasPublicKey: kasPublicKey,
                tdfEphemeralPublicKey: nanoTDF.header.ephemeralPublicKey,
            )
            let decrypted = try await nanoTDF.getPayloadPlaintext(symmetricKey: symmetricKey)
            XCTAssertEqual(decrypted, plaintext)
        }

        for _ in 0 ..< 20 {
            try await roundTrip()
        }

        let iterations = 400
        let sequentialStart = DispatchTime.now()
        for _ in 0 ..< iterations {
            try await roundTrip()
        }
        let sequentialMs = Double(DispatchTime.now().uptimeNanoseconds - sequentialStart.uptimeNanoseconds) / 1e6

        let tasks = 8
        let concurrentStart = DispatchTime.now()
        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0 ..< tasks {
                group.addTask {
                    for _ in 0 ..< iterations / tasks {
                        try await roundTrip()
                    }
                }
            }
            try await group.waitForAll()
        }
        let concurrentMs = Double(DispatchTime.now().uptimeNanoseconds - concurrentStart.uptimeNanoseconds) / 1e6

        print("\nNanoTDF create+decrypt round trip (P-256, \(plaintext.count)-byte payload):")
        print("- sequential: \(String(format: "%.1f", sequentialMs * 1000 / Double(iterations))) µs per round trip")
        print("- \(tasks) concurrent tasks: \(String(format: "%.1f", concurrentMs * 1000 / Double(iterations))) µs per round trip (wall clock / total)")
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
                let keyPair = cryptoHelper.generateEphemeralKeyPair(curveType: .secp256r1)!
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
