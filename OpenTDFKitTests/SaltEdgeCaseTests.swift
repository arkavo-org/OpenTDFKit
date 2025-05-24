@preconcurrency import CryptoKit
import Foundation
@testable import OpenTDFKit
import Testing

@Suite("Salt Edge Case Tests")
struct SaltEdgeCaseTests {
    @Test("Salt length boundaries in NanoTDF")
    func testSaltLengthBoundaries() async throws {
        let keyStore = KeyStore(curve: .secp256r1)
        let kasService = KASService(keyStore: keyStore, baseURL: URL(string: "https://kas.example.com")!)

        // Generate KAS metadata
        let kasMetadata = try await kasService.generateKasMetadata()

        // Test data
        let plaintext = "Test message".data(using: .utf8)!
        let remotePolicy = ResourceLocator(protocolEnum: .https, body: "kas.example.com/policy/123")!

        // Test default salt generation
        var policy1 = Policy(type: .remote, body: nil, remote: remotePolicy, binding: nil)
        let nanoTDF1 = try await createNanoTDF(
            kas: kasMetadata,
            policy: &policy1,
            plaintext: plaintext
        )
        #expect(nanoTDF1.header.policy.salt != nil)
        #expect(nanoTDF1.header.policy.salt!.count == 16) // Default salt size

        // Test that salt is properly included in header serialization
        let headerData = nanoTDF1.header.toData()
        #expect(headerData.contains(nanoTDF1.header.policy.salt!))

        // Verify NanoTDF can be parsed
        let nanoTDFData = nanoTDF1.toData()
        let parser = BinaryParser(data: nanoTDFData)
        let parsedHeader = try parser.parseHeader()
        #expect(parsedHeader.policy.salt == nanoTDF1.header.policy.salt)
    }

    @Test("Salt serialization in Policy")
    func testPolicySaltSerialization() async throws {
        let testSalt = Data("test-salt-value".utf8)
        let policy = Policy(
            type: .remote,
            body: nil,
            remote: ResourceLocator(protocolEnum: .https, body: "example.com/policy"),
            binding: nil,
            salt: testSalt
        )

        // Test that salt is preserved in policy
        #expect(policy.salt == testSalt)

        // Test serialization to data
        let data = policy.toData()
        #expect(data.count > 0)

        // Salt is stored separately in the header, not in the policy data itself
        let policyType = data[0]
        #expect(policyType == Policy.PolicyType.remote.rawValue)
    }

    @Test("Nonce collision prevention")
    func testNonceCollisionPrevention() async throws {
        let cryptoHelper = CryptoHelper()
        var nonces = Set<Data>()

        // Generate 1000 nonces and ensure no collisions
        for _ in 0 ..< 1000 {
            let nonce = await cryptoHelper.generateNonce(length: 12)
            #expect(nonce.count == 12)
            #expect(!nonces.contains(nonce), "Nonce collision detected")
            nonces.insert(nonce)
        }

        // Test that adjustNonce with random padding doesn't create collisions
        let baseNonce = Data([0x01, 0x02, 0x03])
        var adjustedNonces = Set<Data>()

        for _ in 0 ..< 100 {
            let adjusted = await cryptoHelper.adjustNonce(baseNonce, to: 12)
            #expect(adjusted.count == 12)
            #expect(adjusted.prefix(3) == baseNonce)
            adjustedNonces.insert(adjusted)
        }

        // With random padding, we should have unique nonces
        #expect(adjustedNonces.count == 100)
    }

    @Test("GMAC nonce derivation determinism")
    func testGMACNonceDeterminism() async throws {
        let cryptoHelper = CryptoHelper()
        let policyBody = Data("test-policy".utf8)
        let symmetricKey = SymmetricKey(size: .bits256)

        // Generate GMAC multiple times with same inputs
        let gmac1 = try await cryptoHelper.createGMACBinding(policyBody: policyBody, symmetricKey: symmetricKey)
        let gmac2 = try await cryptoHelper.createGMACBinding(policyBody: policyBody, symmetricKey: symmetricKey)

        // With deterministic nonce derivation, GMAC should be the same
        #expect(gmac1 == gmac2)

        // Different policy should produce different GMAC
        let differentPolicy = Data("different-policy".utf8)
        let gmac3 = try await cryptoHelper.createGMACBinding(policyBody: differentPolicy, symmetricKey: symmetricKey)

        #expect(gmac1 != gmac3)

        // Different key should produce different GMAC
        let differentKey = SymmetricKey(size: .bits256)
        let gmac4 = try await cryptoHelper.createGMACBinding(policyBody: policyBody, symmetricKey: differentKey)

        #expect(gmac1 != gmac4)
    }

    @Test("Secure random padding in adjustNonce")
    func testSecureRandomPadding() async throws {
        let cryptoHelper = CryptoHelper()
        let shortNonce = Data([0x01, 0x02, 0x03])

        // Adjust the same short nonce multiple times
        var paddedNonces = Set<Data>()
        for _ in 0 ..< 10 {
            let padded = await cryptoHelper.adjustNonce(shortNonce, to: 12)
            #expect(padded.count == 12)
            #expect(padded.prefix(3) == shortNonce)
            paddedNonces.insert(padded)
        }

        // With secure random padding, all padded nonces should be unique
        #expect(paddedNonces.count == 10, "Random padding should produce unique nonces")
    }
}
