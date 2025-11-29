@preconcurrency import CryptoKit
@testable import OpenTDFKit
import XCTest

final class NanoTDFCollectionTests: XCTestCase {
    private var keyStore: KeyStore!
    private var kasService: KASService!
    private var kasMetadata: KasMetadata!

    override func setUp() async throws {
        keyStore = KeyStore(curve: .secp256r1)
        let baseURL = URL(string: "https://kas.example.com")!
        kasService = KASService(keyStore: keyStore, baseURL: baseURL)
        kasMetadata = try await kasService.generateKasMetadata()
    }

    override func tearDown() async throws {
        keyStore = nil
        kasService = nil
        kasMetadata = nil
    }

    // MARK: - CollectionItem Tests

    func testCollectionItemCreation() {
        let ivCounter: UInt32 = 1
        let ciphertext = Data([0x01, 0x02, 0x03, 0x04])
        let tag = Data(repeating: 0xAB, count: 16)

        let item = CollectionItem(ivCounter: ivCounter, ciphertext: ciphertext, tag: tag)

        XCTAssertEqual(item.ivCounter, 1)
        XCTAssertEqual(item.ciphertext, ciphertext)
        XCTAssertEqual(item.tag, tag)
        XCTAssertEqual(item.totalSize, 3 + 4 + 16) // IV + ciphertext + tag
    }

    func testCollectionItemIVExtraction() {
        let item = CollectionItem(ivCounter: 0x010203, ciphertext: Data([0x01]), tag: Data(count: 16))

        let iv = item.iv
        XCTAssertEqual(iv.count, 3)
        XCTAssertEqual(iv[0], 0x01)
        XCTAssertEqual(iv[1], 0x02)
        XCTAssertEqual(iv[2], 0x03)
    }

    func testCollectionItemToGCMNonce() {
        let item = CollectionItem(ivCounter: 0x010203, ciphertext: Data([0x01]), tag: Data(count: 16))

        let nonce = item.toGCMNonce()
        XCTAssertEqual(nonce.count, 12)
        // First 9 bytes should be zero
        for i in 0 ..< 9 {
            XCTAssertEqual(nonce[i], 0)
        }
        // Last 3 bytes should match IV
        XCTAssertEqual(nonce[9], 0x01)
        XCTAssertEqual(nonce[10], 0x02)
        XCTAssertEqual(nonce[11], 0x03)
    }

    // MARK: - IV Counter Tests

    func testIVCounterStartsAtOne() async throws {
        let policyLocator = ResourceLocator(protocolEnum: .https, body: "kas.example.com/policy")!
        let collection = try await NanoTDFCollectionBuilder()
            .kasMetadata(kasMetadata)
            .policy(.remote(policyLocator))
            .build()

        // First IV should be 1
        let item = try await collection.encryptItem(plaintext: Data([0x01]))
        XCTAssertEqual(item.ivCounter, 1)

        // Second IV should be 2
        let item2 = try await collection.encryptItem(plaintext: Data([0x02]))
        XCTAssertEqual(item2.ivCounter, 2)
    }

    func testIVCounterIncrementsCorrectly() async throws {
        let policyLocator = ResourceLocator(protocolEnum: .https, body: "kas.example.com/policy")!
        let collection = try await NanoTDFCollectionBuilder()
            .kasMetadata(kasMetadata)
            .policy(.remote(policyLocator))
            .build()

        // Encrypt 10 items
        for i in 1 ... 10 {
            let item = try await collection.encryptItem(plaintext: Data([UInt8(i)]))
            XCTAssertEqual(item.ivCounter, UInt32(i))
        }

        let itemCount = await collection.itemCount
        XCTAssertEqual(itemCount, 10)
    }

    func testRotationThresholdDetection() async throws {
        let policyLocator = ResourceLocator(protocolEnum: .https, body: "kas.example.com/policy")!
        let collection = try await NanoTDFCollectionBuilder()
            .kasMetadata(kasMetadata)
            .policy(.remote(policyLocator))
            .rotationThreshold(5)
            .build()

        // Initially should not need rotation (counter at 1)
        var needsRotation = await collection.needsRotation
        XCTAssertFalse(needsRotation)

        // Encrypt 3 items (counter will be at 4)
        for _ in 1 ... 3 {
            _ = try await collection.encryptItem(plaintext: Data([0x01]))
        }

        // Still should not need rotation (counter at 4, threshold at 5)
        needsRotation = await collection.needsRotation
        XCTAssertFalse(needsRotation)

        // Encrypt one more (counter becomes 5, which equals threshold)
        _ = try await collection.encryptItem(plaintext: Data([0x01]))

        // Now should need rotation (counter at 5 >= threshold 5)
        needsRotation = await collection.needsRotation
        XCTAssertTrue(needsRotation)
    }

    // MARK: - Encryption/Decryption Roundtrip Tests

    func testEncryptDecryptRoundtrip() async throws {
        let policyLocator = ResourceLocator(protocolEnum: .https, body: "kas.example.com/policy")!
        let collection = try await NanoTDFCollectionBuilder()
            .kasMetadata(kasMetadata)
            .policy(.remote(policyLocator))
            .build()

        let originalPlaintext = "Hello, NanoTDF Collection!".data(using: .utf8)!

        // Encrypt
        let item = try await collection.encryptItem(plaintext: originalPlaintext)

        // Get symmetric key for decryption
        let symmetricKey = await collection.getSymmetricKey()

        // Create decryptor
        let decryptor = NanoTDFCollectionDecryptor.withUnwrappedKey(symmetricKey: symmetricKey)

        // Decrypt
        let decryptedPlaintext = try await decryptor.decryptItem(item)

        XCTAssertEqual(decryptedPlaintext, originalPlaintext)
    }

    func testBatchEncryptDecryptRoundtrip() async throws {
        let policyLocator = ResourceLocator(protocolEnum: .https, body: "kas.example.com/policy")!
        let collection = try await NanoTDFCollectionBuilder()
            .kasMetadata(kasMetadata)
            .policy(.remote(policyLocator))
            .build()

        let plaintexts = [
            "Message 1".data(using: .utf8)!,
            "Message 2".data(using: .utf8)!,
            "Message 3".data(using: .utf8)!,
        ]

        // Batch encrypt
        let items = try await collection.encryptBatch(plaintexts: plaintexts)
        XCTAssertEqual(items.count, 3)

        // Verify IV progression
        XCTAssertEqual(items[0].ivCounter, 1)
        XCTAssertEqual(items[1].ivCounter, 2)
        XCTAssertEqual(items[2].ivCounter, 3)

        // Create decryptor and batch decrypt
        let symmetricKey = await collection.getSymmetricKey()
        let decryptor = NanoTDFCollectionDecryptor.withUnwrappedKey(symmetricKey: symmetricKey)

        let decryptedPlaintexts = try await decryptor.decryptBatch(items)

        XCTAssertEqual(decryptedPlaintexts.count, 3)
        for i in 0 ..< 3 {
            XCTAssertEqual(decryptedPlaintexts[i], plaintexts[i])
        }
    }

    func testKeyStoreDecryptor() async throws {
        let policyLocator = ResourceLocator(protocolEnum: .https, body: "kas.example.com/policy")!
        let collection = try await NanoTDFCollectionBuilder()
            .kasMetadata(kasMetadata)
            .policy(.remote(policyLocator))
            .build()

        let originalPlaintext = "KAS-side decryption test".data(using: .utf8)!

        // Encrypt
        let item = try await collection.encryptItem(plaintext: originalPlaintext)
        let header = await collection.header

        // Create KAS-side decryptor using KeyStore
        let decryptor = try await NanoTDFCollectionDecryptor.withKeyStore(
            header: header,
            keyStore: keyStore,
        )

        // Decrypt
        let decryptedPlaintext = try await decryptor.decryptItem(item)

        XCTAssertEqual(decryptedPlaintext, originalPlaintext)
    }

    // MARK: - Wire Format Tests

    func testContainerFramingSerialization() async throws {
        let policyLocator = ResourceLocator(protocolEnum: .https, body: "kas.example.com/policy")!
        let collection = try await NanoTDFCollectionBuilder()
            .kasMetadata(kasMetadata)
            .policy(.remote(policyLocator))
            .wireFormat(.containerFraming)
            .build()

        let plaintext = Data([0x01, 0x02, 0x03, 0x04])
        let item = try await collection.encryptItem(plaintext: plaintext)

        let serialized = await collection.serialize(item: item)

        // Container framing: 3-byte IV + 3-byte length + ciphertext + tag
        let expectedLength = 3 + 3 + item.ciphertext.count + item.tag.count
        XCTAssertEqual(serialized.count, expectedLength)

        // Verify IV is correct
        XCTAssertEqual(serialized[0], 0x00)
        XCTAssertEqual(serialized[1], 0x00)
        XCTAssertEqual(serialized[2], 0x01)
    }

    func testSelfDescribingSerialization() async throws {
        let policyLocator = ResourceLocator(protocolEnum: .https, body: "kas.example.com/policy")!
        let collection = try await NanoTDFCollectionBuilder()
            .kasMetadata(kasMetadata)
            .policy(.remote(policyLocator))
            .wireFormat(.selfDescribing)
            .build()

        let plaintext = Data([0x01, 0x02, 0x03, 0x04])
        let item = try await collection.encryptItem(plaintext: plaintext)

        let serialized = await collection.serialize(item: item)

        // Self-describing: 3-byte IV + 4-byte length + ciphertext + tag
        let expectedLength = 3 + 4 + item.ciphertext.count + item.tag.count
        XCTAssertEqual(serialized.count, expectedLength)
    }

    func testContainerFramingParseRoundtrip() async throws {
        let policyLocator = ResourceLocator(protocolEnum: .https, body: "kas.example.com/policy")!
        let collection = try await NanoTDFCollectionBuilder()
            .kasMetadata(kasMetadata)
            .policy(.remote(policyLocator))
            .wireFormat(.containerFraming)
            .build()

        let plaintext = "Parse roundtrip test".data(using: .utf8)!
        let item = try await collection.encryptItem(plaintext: plaintext)

        // Serialize
        let serialized = await collection.serialize(item: item)

        // Parse
        let parsed = NanoTDFCollectionParser.parseContainerFramed(from: serialized, tagSize: 16)
        XCTAssertNotNil(parsed)

        let (parsedItem, bytesRead) = parsed!
        XCTAssertEqual(bytesRead, serialized.count)
        XCTAssertEqual(parsedItem.ivCounter, item.ivCounter)

        // Decrypt parsed item
        let symmetricKey = await collection.getSymmetricKey()
        let decryptor = NanoTDFCollectionDecryptor.withUnwrappedKey(symmetricKey: symmetricKey)

        let decrypted = try await decryptor.decryptItem(parsedItem)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testSelfDescribingParseRoundtrip() async throws {
        let policyLocator = ResourceLocator(protocolEnum: .https, body: "kas.example.com/policy")!
        let collection = try await NanoTDFCollectionBuilder()
            .kasMetadata(kasMetadata)
            .policy(.remote(policyLocator))
            .wireFormat(.selfDescribing)
            .build()

        let plaintext = "Self-describing test".data(using: .utf8)!
        let item = try await collection.encryptItem(plaintext: plaintext)

        // Serialize
        let serialized = await collection.serialize(item: item)

        // Parse
        let parsed = NanoTDFCollectionParser.parseSelfDescribing(from: serialized, tagSize: 16)
        XCTAssertNotNil(parsed)

        let (parsedItem, bytesRead) = parsed!
        XCTAssertEqual(bytesRead, serialized.count)
        XCTAssertEqual(parsedItem.ivCounter, item.ivCounter)

        // Decrypt parsed item
        let symmetricKey = await collection.getSymmetricKey()
        let decryptor = NanoTDFCollectionDecryptor.withUnwrappedKey(symmetricKey: symmetricKey)

        let decrypted = try await decryptor.decryptItem(parsedItem)
        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - Error Condition Tests

    func testBuilderMissingKASMetadata() async {
        let policyLocator = ResourceLocator(protocolEnum: .https, body: "kas.example.com/policy")!

        do {
            _ = try await NanoTDFCollectionBuilder()
                .policy(.remote(policyLocator))
                .build()
            XCTFail("Expected missingKASMetadata error")
        } catch let error as NanoTDFCollectionError {
            guard case .missingKASMetadata = error else {
                XCTFail("Expected missingKASMetadata error, got \(error)")
                return
            }
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    func testBuilderMissingPolicy() async {
        do {
            _ = try await NanoTDFCollectionBuilder()
                .kasMetadata(kasMetadata)
                .build()
            XCTFail("Expected missingPolicy error")
        } catch let error as NanoTDFCollectionError {
            guard case .missingPolicy = error else {
                XCTFail("Expected missingPolicy error, got \(error)")
                return
            }
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    func testParseInvalidData() {
        let invalidData = Data([0x01, 0x02]) // Too short

        let result = NanoTDFCollectionParser.parseContainerFramed(from: invalidData)
        XCTAssertNil(result)
    }

    // MARK: - Configuration Tests

    func testCipherTagSize() {
        XCTAssertEqual(Cipher.aes256GCM64.tagSize, 8)
        XCTAssertEqual(Cipher.aes256GCM96.tagSize, 12)
        XCTAssertEqual(Cipher.aes256GCM104.tagSize, 13)
        XCTAssertEqual(Cipher.aes256GCM112.tagSize, 14)
        XCTAssertEqual(Cipher.aes256GCM120.tagSize, 15)
        XCTAssertEqual(Cipher.aes256GCM128.tagSize, 16)
    }

    func testDefaultConfiguration() {
        let config = CollectionConfiguration.default

        XCTAssertEqual(config.rotationThreshold, 0x800000) // 2^23
        XCTAssertEqual(config.cipher, .aes256GCM128)
        switch config.wireFormat {
        case .containerFraming:
            break // Expected
        case .selfDescribing:
            XCTFail("Expected containerFraming as default")
        }
    }

    // MARK: - Collection File Format Tests

    func testCollectionFileSerializeAndParse() async throws {
        let policyLocator = ResourceLocator(protocolEnum: .https, body: "kas.example.com/policy")!
        let collection = try await NanoTDFCollectionBuilder()
            .kasMetadata(kasMetadata)
            .policy(.remote(policyLocator))
            .build()

        // Encrypt some items
        let plaintexts = [
            "Item 1".data(using: .utf8)!,
            "Item 2".data(using: .utf8)!,
        ]

        var serializedItems = Data()
        for plaintext in plaintexts {
            let item = try await collection.encryptItem(plaintext: plaintext)
            await serializedItems.append(collection.serialize(item: item))
        }

        // Create file
        let headerBytes = await collection.getHeaderBytes()
        let itemCount = await collection.itemCount
        let fileData = NanoTDFCollectionFile.serialize(
            header: headerBytes,
            items: serializedItems,
            itemCount: itemCount,
        )

        // Parse file
        let (parsedHeader, parsedItems, parsedCount) = try NanoTDFCollectionFile.parse(from: fileData)

        XCTAssertEqual(parsedHeader, headerBytes)
        XCTAssertEqual(parsedItems, serializedItems)
        XCTAssertEqual(parsedCount, 2)
    }
}
