@preconcurrency import CryptoKit
@testable import OpenTDFKit
import XCTest

final class IntegrationTests: XCTestCase {
    private var kasURL: URL?
    private var platformURL: URL?
    private var clientID: String?
    private var clientSecret: String?
    private var oauthToken: String?

    override func setUp() {
        super.setUp()

        kasURL = ProcessInfo.processInfo.environment["KASURL"].flatMap { URL(string: $0) }
        platformURL = ProcessInfo.processInfo.environment["PLATFORMURL"].flatMap { URL(string: $0) }
        clientID = ProcessInfo.processInfo.environment["CLIENTID"]
        clientSecret = ProcessInfo.processInfo.environment["CLIENTSECRET"]
        oauthToken = ProcessInfo.processInfo.environment["OAUTH_TOKEN"]
    }

    private func skipIfEnvironmentNotConfigured() throws {
        guard kasURL != nil,
              platformURL != nil,
              clientID != nil,
              clientSecret != nil
        else {
            throw XCTSkip("""
            Integration tests require environment variables:
            - KASURL: KAS endpoint URL (e.g., http://localhost:8080/kas)
            - PLATFORMURL: Platform endpoint URL (e.g., http://localhost:8080)
            - CLIENTID: OAuth client ID (e.g., opentdf-client)
            - CLIENTSECRET: OAuth client secret
            - OAUTH_TOKEN: (optional) Pre-acquired OAuth token

            To run these tests, set the environment variables before running:
                export KASURL=http://localhost:8080/kas
                export PLATFORMURL=http://localhost:8080
                export CLIENTID=opentdf-client
                export CLIENTSECRET=secret
                swift test
            """)
        }
    }

    func testEndToEndNanoTDFWithKASRewrap() async throws {
        try skipIfEnvironmentNotConfigured()

        guard let kasURL,
              let platformURL
        else {
            XCTFail("Environment not configured")
            return
        }

        let testPlaintext = "Integration test: NanoTDF with KAS rewrap".data(using: .utf8)!

        let keyStore = KeyStore(curve: .secp256r1)
        let kasService = KASService(keyStore: keyStore, baseURL: platformURL)

        let kasMetadata = try await kasService.generateKasMetadata()

        let remotePolicy = ResourceLocator(protocolEnum: .https, body: "\(platformURL.host ?? "localhost")/policy/integration-test")!
        var policy = Policy(type: .remote, body: nil, remote: remotePolicy, binding: nil)

        let nanoTDF = try await createNanoTDF(
            kas: kasMetadata,
            policy: &policy,
            plaintext: testPlaintext,
        )

        XCTAssertNotNil(nanoTDF)
        XCTAssertEqual(nanoTDF.header.toData()[2], Header.version, "NanoTDF should use latest version")

        let token = try await getOAuthToken()

        let kasRewrapClient = KASRewrapClient(
            kasURL: kasURL,
            oauthToken: token,
        )

        let clientKeyPair = EphemeralKeyPair(
            privateKey: P256.KeyAgreement.PrivateKey().rawRepresentation,
            publicKey: P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation,
            curve: .secp256r1,
        )

        let (wrappedKey, sessionPublicKey) = try await kasRewrapClient.rewrapNanoTDF(
            header: nanoTDF.header.toData(),
            parsedHeader: nanoTDF.header,
            clientKeyPair: clientKeyPair,
        )

        XCTAssertFalse(wrappedKey.isEmpty, "Wrapped key should not be empty")
        XCTAssertEqual(sessionPublicKey.count, 33, "Session public key should be 33 bytes (compressed P-256)")

        let unwrappedKey = try KASRewrapClient.unwrapKey(
            wrappedKey: wrappedKey,
            sessionPublicKey: sessionPublicKey,
            clientPrivateKey: clientKeyPair.privateKey,
        )

        let decryptedPlaintext = try await nanoTDF.getPayloadPlaintext(symmetricKey: unwrappedKey)

        XCTAssertEqual(decryptedPlaintext, testPlaintext, "Decrypted plaintext should match original")
    }

    func testKASRewrapWithInvalidToken() async throws {
        try skipIfEnvironmentNotConfigured()

        guard let kasURL,
              let platformURL
        else {
            XCTFail("Environment not configured")
            return
        }

        let testPlaintext = "Integration test: Invalid token".data(using: .utf8)!

        let keyStore = KeyStore(curve: .secp256r1)
        let kasService = KASService(keyStore: keyStore, baseURL: platformURL)

        let kasMetadata = try await kasService.generateKasMetadata()

        let remotePolicy = ResourceLocator(protocolEnum: .https, body: "\(platformURL.host ?? "localhost")/policy/test")!
        var policy = Policy(type: .remote, body: nil, remote: remotePolicy, binding: nil)

        let nanoTDF = try await createNanoTDF(
            kas: kasMetadata,
            policy: &policy,
            plaintext: testPlaintext,
        )

        let invalidToken = "invalid_token_12345"

        let kasRewrapClient = KASRewrapClient(
            kasURL: kasURL,
            oauthToken: invalidToken,
        )

        let clientKeyPair = EphemeralKeyPair(
            privateKey: P256.KeyAgreement.PrivateKey().rawRepresentation,
            publicKey: P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation,
            curve: .secp256r1,
        )

        do {
            _ = try await kasRewrapClient.rewrapNanoTDF(
                header: nanoTDF.header.toData(),
                parsedHeader: nanoTDF.header,
                clientKeyPair: clientKeyPair,
            )
            XCTFail("Expected authentication failure with invalid token")
        } catch KASRewrapError.authenticationFailed {
        } catch let KASRewrapError.httpError(code, _) where code == 401 {
        } catch {
            XCTFail("Expected KASRewrapError.authenticationFailed, got \(error)")
        }
    }

    func testNanoTDFCreationWithAttributes() async throws {
        try skipIfEnvironmentNotConfigured()

        guard let platformURL else {
            XCTFail("Environment not configured")
            return
        }

        let testPlaintext = "Integration test: NanoTDF with attributes".data(using: .utf8)!

        let keyStore = KeyStore(curve: .secp256r1)
        let kasService = KASService(keyStore: keyStore, baseURL: platformURL)

        let kasMetadata = try await kasService.generateKasMetadata()

        let policyWithAttributes = """
        {
            "body": {
                "dataAttributes": [
                    {"attribute": "https://example.com/attr/classification/value/secret"},
                    {"attribute": "https://example.com/attr/department/value/engineering"}
                ],
                "dissem": ["user@example.com"]
            }
        }
        """.data(using: .utf8)!

        let embeddedPolicyBody = EmbeddedPolicyBody(body: policyWithAttributes, keyAccess: nil)
        var policy = Policy(type: .embeddedEncrypted, body: embeddedPolicyBody, remote: nil, binding: nil)

        let nanoTDF = try await createNanoTDF(
            kas: kasMetadata,
            policy: &policy,
            plaintext: testPlaintext,
        )

        XCTAssertNotNil(nanoTDF)
        XCTAssertNotNil(nanoTDF.header.policy.body, "Policy body should be present")

        let kasPublicKey = try kasMetadata.getPublicKey()
        let privateKeyData = await keyStore.getPrivateKey(forPublicKey: kasPublicKey)
        XCTAssertNotNil(privateKeyData, "KAS private key should be in keystore")

        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData!)
        let clientPublicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: nanoTDF.header.ephemeralPublicKey)

        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: clientPublicKey)
        let salt = CryptoHelper.computeHKDFSalt(version: Header.version)

        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: Data(),
            outputByteCount: 32,
        )

        let decryptedPlaintext = try await nanoTDF.getPayloadPlaintext(symmetricKey: symmetricKey)

        XCTAssertEqual(decryptedPlaintext, testPlaintext, "Decrypted plaintext should match original")
    }

    func testKASPublicKeyRetrieval() async throws {
        try skipIfEnvironmentNotConfigured()

        guard let platformURL else {
            XCTFail("Environment not configured")
            return
        }

        let token = try await getOAuthToken()

        let kasPublicKeyURL = platformURL.appendingPathComponent("/kas/v2/kas_public_key")
        var request = URLRequest(url: kasPublicKeyURL)
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.addValue("ec:secp256r1", forHTTPHeaderField: "algorithm")

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200
        else {
            XCTFail("Failed to retrieve KAS public key")
            return
        }

        let pemKey = String(data: data, encoding: .utf8)
        XCTAssertNotNil(pemKey, "KAS public key should be in PEM format")
        XCTAssertTrue(pemKey?.contains("-----BEGIN PUBLIC KEY-----") ?? false, "PEM should have proper header")
    }

    private func getOAuthToken() async throws -> String {
        if let token = oauthToken {
            return token
        }

        guard let platformURL,
              let clientID,
              let clientSecret
        else {
            throw XCTSkip("OAuth configuration incomplete")
        }

        let tokenURL = platformURL.appendingPathComponent("/token")
        var request = URLRequest(url: tokenURL)
        request.httpMethod = "POST"
        request.addValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        let body = "grant_type=client_credentials&client_id=\(clientID)&client_secret=\(clientSecret)"
        request.httpBody = body.data(using: .utf8)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200
        else {
            throw NSError(domain: "IntegrationTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to acquire OAuth token"])
        }

        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        guard let token = json?["access_token"] as? String else {
            throw NSError(domain: "IntegrationTests", code: 2, userInfo: [NSLocalizedDescriptionKey: "No access_token in response"])
        }

        return token
    }

    func testEndToEndStandardTDFWithKASRewrap() async throws {
        try skipIfEnvironmentNotConfigured()

        guard let platformURL else {
            XCTFail("Environment not configured")
            return
        }

        let testPlaintext = "Integration test: Standard TDF with KAS rewrap".data(using: .utf8)!

        let token = try await getOAuthToken()

        let kasRSAPublicKeyURL = platformURL.appendingPathComponent("/kas/v2/kas_public_key")
        var keyRequest = URLRequest(url: kasRSAPublicKeyURL)
        keyRequest.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let (keyData, keyResponse) = try await URLSession.shared.data(for: keyRequest)

        guard let httpKeyResponse = keyResponse as? HTTPURLResponse,
              httpKeyResponse.statusCode == 200
        else {
            throw XCTSkip("Failed to retrieve KAS RSA public key")
        }

        struct KASPublicKeyResponse: Codable {
            let publicKey: String
        }

        let kasPublicKeyResponse = try JSONDecoder().decode(KASPublicKeyResponse.self, from: keyData)
        let kasPublicKeyPEM = kasPublicKeyResponse.publicKey

        let policyJSON = """
        {
            "uuid": "integration-test-\(UUID().uuidString)",
            "body": {
                "dataAttributes": [],
                "dissem": []
            }
        }
        """.data(using: .utf8)!

        let kasInfo = TDFKasInfo(
            url: platformURL.appendingPathComponent("/kas"),
            publicKeyPEM: kasPublicKeyPEM,
            kid: "kas-integration-test",
            schemaVersion: "1.0",
        )

        let policy = try TDFPolicy(json: policyJSON)
        let configuration = TDFEncryptionConfiguration(
            kas: kasInfo,
            policy: policy,
            mimeType: "text/plain",
            tdfSpecVersion: "4.3.0",
        )

        let encryptor = TDFEncryptor()
        let encryptionResult = try encryptor.encrypt(plaintext: testPlaintext, configuration: configuration)

        let tdfData = try encryptionResult.container.serializedData()
        XCTAssertGreaterThan(tdfData.count, 0, "TDF data should not be empty")
        XCTAssertTrue(tdfData.starts(with: [0x50, 0x4B]), "TDF should be a ZIP archive")

        let clientPrivateKey = try generateTestRSAKeyPair()

        let loader = TDFLoader()
        let container = try loader.load(from: tdfData)

        guard let kasURL = URL(string: container.manifest.encryptionInformation.keyAccess[0].url) else {
            XCTFail("Invalid KAS URL in manifest")
            return
        }

        let kasClient = KASRewrapClient(kasURL: kasURL, oauthToken: token)
        let rewrapResult = try await kasClient.rewrapTDF(
            manifest: container.manifest,
            clientPublicKeyPEM: clientPrivateKey.publicKeyPEM,
        )

        XCTAssertFalse(rewrapResult.wrappedKeys.isEmpty, "Should receive wrapped keys from KAS")

        var reconstructedKeyData: Data?
        for (_, wrappedKey) in rewrapResult.wrappedKeys.sorted(by: { $0.key < $1.key }) {
            let unwrappedKey = try TDFCrypto.unwrapSymmetricKeyWithRSA(
                privateKeyPEM: clientPrivateKey.privateKeyPEM,
                wrappedKey: wrappedKey.base64EncodedString(),
            )
            let keyData = TDFCrypto.data(from: unwrappedKey)

            if let existing = reconstructedKeyData {
                reconstructedKeyData = Data(zip(existing, keyData).map { $0 ^ $1 })
            } else {
                reconstructedKeyData = keyData
            }
        }

        guard let finalKeyData = reconstructedKeyData else {
            XCTFail("Failed to reconstruct key")
            return
        }

        let reconstructedKey = SymmetricKey(data: finalKeyData)

        let decryptor = TDFDecryptor()
        let decryptedPlaintext = try decryptor.decrypt(container: container, symmetricKey: reconstructedKey)

        XCTAssertEqual(decryptedPlaintext, testPlaintext, "Decrypted plaintext should match original")
    }

    // MARK: - NanoTDF Collection Integration Tests

    func testEndToEndNanoTDFCollectionWithKASRewrap() async throws {
        try skipIfEnvironmentNotConfigured()

        guard let kasURL,
              let platformURL
        else {
            XCTFail("Environment not configured")
            return
        }

        // Test with multiple items
        let testItems = [
            "Collection item 1: Hello".data(using: .utf8)!,
            "Collection item 2: World".data(using: .utf8)!,
            "Collection item 3: NanoTDF Collection Test".data(using: .utf8)!,
        ]

        let keyStore = KeyStore(curve: .secp256r1)
        let kasService = KASService(keyStore: keyStore, baseURL: platformURL)

        let kasMetadata = try await kasService.generateKasMetadata()

        // Create policy locator
        let policyLocator = ResourceLocator(
            protocolEnum: .https,
            body: "\(platformURL.host ?? "localhost")/policy/collection-test",
        )!

        // Build the collection
        let collection = try await NanoTDFCollectionBuilder()
            .kasMetadata(kasMetadata)
            .policy(.remote(policyLocator))
            .build()

        // Encrypt all items
        var encryptedItems = [CollectionItem]()
        for plaintext in testItems {
            let item = try await collection.encryptItem(plaintext: plaintext)
            encryptedItems.append(item)
        }

        XCTAssertEqual(encryptedItems.count, 3)

        // Verify IV progression
        XCTAssertEqual(encryptedItems[0].ivCounter, 1)
        XCTAssertEqual(encryptedItems[1].ivCounter, 2)
        XCTAssertEqual(encryptedItems[2].ivCounter, 3)

        // Get token for KAS rewrap
        let token = try await getOAuthToken()

        // Get header for rewrap request
        let header = await collection.header
        let headerBytes = await collection.getHeaderBytes()

        let kasRewrapClient = KASRewrapClient(
            kasURL: kasURL,
            oauthToken: token,
        )

        let clientPrivateKey = P256.KeyAgreement.PrivateKey()
        let clientKeyPair = EphemeralKeyPair(
            privateKey: clientPrivateKey.rawRepresentation,
            publicKey: clientPrivateKey.publicKey.compressedRepresentation,
            curve: .secp256r1,
        )

        // Single rewrap call for entire collection
        let (wrappedKey, sessionPublicKey) = try await kasRewrapClient.rewrapNanoTDF(
            header: headerBytes,
            parsedHeader: header,
            clientKeyPair: clientKeyPair,
        )

        XCTAssertFalse(wrappedKey.isEmpty, "Wrapped key should not be empty")

        // Unwrap the symmetric key
        let symmetricKey = try KASRewrapClient.unwrapKey(
            wrappedKey: wrappedKey,
            sessionPublicKey: sessionPublicKey,
            clientPrivateKey: clientKeyPair.privateKey,
        )

        // Create decryptor with the unwrapped key
        let decryptor = NanoTDFCollectionDecryptor.withUnwrappedKey(symmetricKey: symmetricKey)

        // Decrypt all items
        for (index, item) in encryptedItems.enumerated() {
            let decrypted = try await decryptor.decryptItem(item)
            XCTAssertEqual(decrypted, testItems[index], "Item \(index) should decrypt correctly")
        }
    }

    func testNanoTDFCollectionSerializationRoundtrip() async throws {
        try skipIfEnvironmentNotConfigured()

        guard let platformURL else {
            XCTFail("Environment not configured")
            return
        }

        let testItems = [
            "Serialization test 1".data(using: .utf8)!,
            "Serialization test 2".data(using: .utf8)!,
        ]

        let keyStore = KeyStore(curve: .secp256r1)
        let kasService = KASService(keyStore: keyStore, baseURL: platformURL)

        let kasMetadata = try await kasService.generateKasMetadata()

        let policyLocator = ResourceLocator(
            protocolEnum: .https,
            body: "\(platformURL.host ?? "localhost")/policy/serial-test",
        )!

        let collection = try await NanoTDFCollectionBuilder()
            .kasMetadata(kasMetadata)
            .policy(.remote(policyLocator))
            .wireFormat(.containerFraming)
            .build()

        // Encrypt and serialize
        var serializedItems = Data()
        for plaintext in testItems {
            let item = try await collection.encryptItem(plaintext: plaintext)
            let serialized = await collection.serialize(item: item)
            serializedItems.append(serialized)
        }

        // Create collection file
        let headerBytes = await collection.getHeaderBytes()
        let itemCount = await collection.itemCount
        let fileData = NanoTDFCollectionFile.serialize(
            header: headerBytes,
            items: serializedItems,
            itemCount: itemCount,
        )

        // Parse the file
        let (parsedHeader, parsedItems, parsedCount) = try NanoTDFCollectionFile.parse(from: fileData)

        XCTAssertEqual(parsedHeader, headerBytes)
        XCTAssertEqual(parsedItems, serializedItems)
        XCTAssertEqual(parsedCount, UInt32(testItems.count))

        // Parse individual items
        let items = try NanoTDFCollectionParser.parseStream(
            from: parsedItems,
            format: .containerFraming,
            tagSize: 16,
        )

        XCTAssertEqual(items.count, testItems.count)

        // Decrypt using the collection's symmetric key (KAS-side)
        let symmetricKey = await collection.getSymmetricKey()
        let decryptor = NanoTDFCollectionDecryptor.withUnwrappedKey(symmetricKey: symmetricKey)

        for (index, item) in items.enumerated() {
            let decrypted = try await decryptor.decryptItem(item)
            XCTAssertEqual(decrypted, testItems[index])
        }
    }

    func testNanoTDFCollectionBatchEncryption() async throws {
        try skipIfEnvironmentNotConfigured()

        guard let platformURL else {
            XCTFail("Environment not configured")
            return
        }

        // Test batch encryption of many items
        let itemCount = 100
        let testItems = (0 ..< itemCount).map { "Item \($0)".data(using: .utf8)! }

        let keyStore = KeyStore(curve: .secp256r1)
        let kasService = KASService(keyStore: keyStore, baseURL: platformURL)

        let kasMetadata = try await kasService.generateKasMetadata()

        let policyLocator = ResourceLocator(
            protocolEnum: .https,
            body: "\(platformURL.host ?? "localhost")/policy/batch-test",
        )!

        let collection = try await NanoTDFCollectionBuilder()
            .kasMetadata(kasMetadata)
            .policy(.remote(policyLocator))
            .build()

        // Batch encrypt
        let encryptedItems = try await collection.encryptBatch(plaintexts: testItems)

        XCTAssertEqual(encryptedItems.count, itemCount)

        // Verify IV progression
        for (index, item) in encryptedItems.enumerated() {
            XCTAssertEqual(item.ivCounter, UInt32(index + 1))
        }

        // Batch decrypt
        let symmetricKey = await collection.getSymmetricKey()
        let decryptor = NanoTDFCollectionDecryptor.withUnwrappedKey(symmetricKey: symmetricKey)

        let decryptedItems = try await decryptor.decryptBatch(encryptedItems)

        XCTAssertEqual(decryptedItems.count, itemCount)
        for (index, decrypted) in decryptedItems.enumerated() {
            XCTAssertEqual(decrypted, testItems[index])
        }
    }

    private func generateTestRSAKeyPair() throws -> (privateKeyPEM: String, publicKeyPEM: String) {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        task.arguments = ["genrsa", "2048"]

        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()

        try task.run()
        task.waitUntilExit()

        let privateKeyPEM = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)!

        let pubTask = Process()
        pubTask.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        pubTask.arguments = ["rsa", "-pubout"]

        let pubPipe = Pipe()
        let inPipe = Pipe()
        pubTask.standardInput = inPipe
        pubTask.standardOutput = pubPipe
        pubTask.standardError = Pipe()

        try pubTask.run()
        inPipe.fileHandleForWriting.write(privateKeyPEM.data(using: .utf8)!)
        try inPipe.fileHandleForWriting.close()
        pubTask.waitUntilExit()

        let publicKeyPEM = String(data: pubPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)!

        return (privateKeyPEM, publicKeyPEM)
    }
}
