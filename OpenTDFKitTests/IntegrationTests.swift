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
        let hasToken = !(oauthToken?.isEmpty ?? true)
        let hasClientCredentials = clientID != nil && clientSecret != nil
        guard kasURL != nil,
              platformURL != nil,
              hasToken || hasClientCredentials
        else {
            throw XCTSkip("""
            Integration tests require environment variables:
            - KASURL: KAS endpoint URL (e.g., http://localhost:8080/kas)
            - PLATFORMURL: Platform root URL (e.g., http://localhost:8080)
            - and either OAUTH_TOKEN (a pre-acquired bearer token: JWT or CWT)
              or CLIENTID + CLIENTSECRET (client-credentials grant at PLATFORMURL/token)

            To run these tests, set the environment variables before running:
                export KASURL=http://localhost:8080/kas
                export PLATFORMURL=http://localhost:8080
                export CLIENTID=opentdf-client
                export CLIENTSECRET=secret
                swift test
            """)
        }
    }

    // MARK: - Platform helpers

    /// PLATFORMURL without trailing slashes (the platform root, not the `/kas` path).
    private func platformRoot() throws -> String {
        var root = try XCTUnwrap(platformURL).absoluteString
        while root.hasSuffix("/") {
            root.removeLast()
        }
        return root
    }

    /// Resolve KAS endpoints from the platform root, mirroring the CLI's
    /// `resolveConfiguration`: well-known discovery (Connect preferred), with
    /// synthesized Connect endpoints at the root when well-known is missing or
    /// has no usable `kas` block (e.g. a local Go platform).
    private func resolveKasConfiguration() async throws -> OpenTDFConfiguration {
        let root = try platformRoot()
        if let configuration = try? await fetchWellKnown(platformURL: root) {
            return configuration.withKasFallback(baseURL: root)
        }
        return OpenTDFConfiguration.forKasConnect(root)
    }

    /// Fetch a KAS public key over REST: `GET {root}/kas/v2/kas_public_key?algorithm=…`.
    /// Decodes both `publicKey` (Go platform) and `public_key` (arkavo-rs) spellings, plus `kid`.
    private func fetchKasPublicKey(algorithm: String, token: String) async throws -> KASRewrapClient.KasEcPublicKeyResponse {
        var components = try XCTUnwrap(URLComponents(string: "\(platformRoot())/kas/v2/kas_public_key"))
        components.queryItems = [URLQueryItem(name: "algorithm", value: algorithm)]
        var request = try URLRequest(url: XCTUnwrap(components.url))
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.addValue("application/json", forHTTPHeaderField: "Accept")

        let (data, response) = try await URLSession.shared.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? -1
        guard status == 200 else {
            let body = String(data: data, encoding: .utf8) ?? ""
            throw NSError(domain: "IntegrationTests", code: status, userInfo: [
                NSLocalizedDescriptionKey: "GET kas_public_key?algorithm=\(algorithm) failed: HTTP \(status) \(body)",
            ])
        }
        return try JSONDecoder().decode(KASRewrapClient.KasEcPublicKeyResponse.self, from: data)
    }

    /// `KasMetadata` for the platform KAS's real EC (P-256) key, with the locator the
    /// CLI's `encryptNanoTDF` writes: scheme from KASURL, body `host[:port]` (port only
    /// when KASURL names one), identifier = the KAS `kid` (when it is 2, 8, or 32 bytes).
    private func makePlatformKasMetadata(token: String) async throws -> KasMetadata {
        let kasURL = try XCTUnwrap(kasURL)
        let host = try XCTUnwrap(kasURL.host)
        let body = kasURL.port.map { "\(host):\($0)" } ?? host

        let keyResponse = try await fetchKasPublicKey(algorithm: "ec:secp256r1", token: token)
        let (compressedKey, _) = try KASRewrapClient.validateEcPublicKeyPEM(keyResponse.publicKey)
        let identifier = keyResponse.kid
            .map { Data($0.utf8) }
            .flatMap { [2, 8, 32].contains($0.count) ? $0 : nil }

        let locator = try XCTUnwrap(ResourceLocator(
            protocolEnum: kasURL.scheme?.lowercased() == "https" ? .https : .http,
            body: body,
            identifier: identifier,
        ))
        return try KasMetadata(
            resourceLocator: locator,
            publicKey: P256.KeyAgreement.PublicKey(compressedRepresentation: compressedKey),
            curve: .secp256r1,
        )
    }

    /// Open-access embedded policy (no data attributes), as the CLI writes.
    private func makeOpenPolicyJSON() -> Data {
        Data("""
        {"uuid":"\(UUID().uuidString.lowercased())","body":{"dataAttributes":[],"dissem":[]}}
        """.utf8)
    }

    /// Fresh client ephemeral key pair (private and public from the same key).
    private func makeClientKeyPair() -> EphemeralKeyPair {
        let privateKey = P256.KeyAgreement.PrivateKey()
        return EphemeralKeyPair(
            privateKey: privateKey.rawRepresentation,
            publicKey: privateKey.publicKey.compressedRepresentation,
            curve: .secp256r1,
        )
    }

    func testEndToEndNanoTDFWithKASRewrap() async throws {
        try skipIfEnvironmentNotConfigured()

        let testPlaintext = "Integration test: NanoTDF with KAS rewrap".data(using: .utf8)!

        let token = try await getOAuthToken()

        // Encrypt to the platform KAS's real EC key with an embedded policy the KAS can read.
        let kasMetadata = try await makePlatformKasMetadata(token: token)
        var policy = Policy(
            type: .embeddedPlaintext,
            body: EmbeddedPolicyBody(body: makeOpenPolicyJSON()),
            remote: nil,
            binding: nil,
        )

        let nanoTDF = try await createNanoTDF(
            kas: kasMetadata,
            policy: &policy,
            plaintext: testPlaintext,
        )

        XCTAssertNotNil(nanoTDF)
        XCTAssertEqual(nanoTDF.header.toData()[2], Header.versionV12, "NanoTDF should use v12")

        let kasRewrapClient = try await KASRewrapClient(
            configuration: resolveKasConfiguration(),
            oauthToken: token,
        )

        let clientKeyPair = makeClientKeyPair()

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

        let testPlaintext = "Integration test: Invalid token".data(using: .utf8)!

        // A valid token is only used to fetch the KAS public key; the rewrap uses a bogus one.
        let token = try await getOAuthToken()
        let kasMetadata = try await makePlatformKasMetadata(token: token)
        var policy = Policy(
            type: .embeddedPlaintext,
            body: EmbeddedPolicyBody(body: makeOpenPolicyJSON()),
            remote: nil,
            binding: nil,
        )

        let nanoTDF = try await createNanoTDF(
            kas: kasMetadata,
            policy: &policy,
            plaintext: testPlaintext,
        )

        let invalidToken = "invalid_token_12345"

        let kasRewrapClient = try await KASRewrapClient(
            configuration: resolveKasConfiguration(),
            oauthToken: invalidToken,
        )

        let clientKeyPair = makeClientKeyPair()

        do {
            _ = try await kasRewrapClient.rewrapNanoTDF(
                header: nanoTDF.header.toData(),
                parsedHeader: nanoTDF.header,
                clientKeyPair: clientKeyPair,
            )
            XCTFail("Expected authentication failure with invalid token")
        } catch KASRewrapError.authenticationFailed(_) {
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

        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: XCTUnwrap(privateKeyData))
        let clientPublicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: nanoTDF.header.ephemeralPublicKey)

        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: clientPublicKey)
        let salt = CryptoHelper.computeHKDFSalt(version: Header.versionV12)

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

        let token = try await getOAuthToken()

        // `algorithm` is a query parameter (not a header).
        let keyResponse = try await fetchKasPublicKey(algorithm: "ec:secp256r1", token: token)

        XCTAssertTrue(keyResponse.publicKey.contains("-----BEGIN PUBLIC KEY-----"), "PEM should have proper header")
        let (compressedKey, _) = try KASRewrapClient.validateEcPublicKeyPEM(keyResponse.publicKey)
        XCTAssertEqual(compressedKey.count, 33, "ec:secp256r1 should return a P-256 key")
    }

    private func getOAuthToken() async throws -> String {
        if let token = oauthToken, !token.isEmpty {
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

        let kasURL = try XCTUnwrap(kasURL)
        let testPlaintext = "Integration test: Standard TDF with KAS rewrap".data(using: .utf8)!

        let token = try await getOAuthToken()

        // RSA wrapping key and its kid from the KAS (`publicKey` or `public_key`).
        let rsaKey = try await fetchKasPublicKey(algorithm: "rsa:2048", token: token)

        // The KAS parses `uuid` as a UUID; a non-UUID value fails rewrap with "bad request".
        let policyJSON = makeOpenPolicyJSON()

        let kasInfo = TDFKasInfo(
            url: kasURL,
            publicKeyPEM: rsaKey.publicKey,
            kid: rsaKey.kid,
            schemaVersion: "1.0",
        )

        let policy = try TDFPolicy(json: policyJSON)
        let configuration = TDFEncryptionConfiguration(
            kas: kasInfo,
            policy: policy,
            mimeType: "text/plain",
        )

        let encryptor = TDFEncryptor()
        let encryptionResult = try encryptor.encrypt(plaintext: testPlaintext, configuration: configuration)

        let tdfData = try encryptionResult.container.serializedData()
        XCTAssertGreaterThan(tdfData.count, 0, "TDF data should not be empty")
        XCTAssertTrue(tdfData.starts(with: [0x50, 0x4B]), "TDF should be a ZIP archive")

        let loader = TDFLoader()
        let container = try loader.load(from: tdfData)
        XCTAssertEqual(container.manifest.encryptionInformation.keyAccess.count, 1)

        // One-call Standard TDF path: ephemeral P-256 session key, rewrap, and
        // EC session unwrap with the Standard TDF salt.
        let kasClient = try await KASRewrapClient(
            configuration: resolveKasConfiguration(),
            oauthToken: token,
        )
        let symmetricKey = try await kasClient.rewrapAndUnwrapTDF(manifest: container.manifest)

        let decryptor = TDFDecryptor()
        let decryptedPlaintext = try decryptor.decrypt(container: container, symmetricKey: symmetricKey)

        XCTAssertEqual(decryptedPlaintext, testPlaintext, "Decrypted plaintext should match original")
    }

    // MARK: - NanoTDF Collection Integration Tests

    func testEndToEndNanoTDFCollectionWithKASRewrap() async throws {
        try skipIfEnvironmentNotConfigured()

        // Test with multiple items
        let testItems = try [
            XCTUnwrap("Collection item 1: Hello".data(using: .utf8)),
            XCTUnwrap("Collection item 2: World".data(using: .utf8)),
            XCTUnwrap("Collection item 3: NanoTDF Collection Test".data(using: .utf8)),
        ]

        // Get token (used for the KAS public key and the rewrap)
        let token = try await getOAuthToken()

        // Encrypt to the platform KAS's real EC key with an embedded policy
        let kasMetadata = try await makePlatformKasMetadata(token: token)

        // Build the collection
        let collection = try await NanoTDFCollectionBuilder()
            .kasMetadata(kasMetadata)
            .policy(.embeddedPlaintext(makeOpenPolicyJSON()))
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

        // Get header for rewrap request
        let header = await collection.header
        let headerBytes = await collection.getHeaderBytes()

        let kasRewrapClient = try await KASRewrapClient(
            configuration: resolveKasConfiguration(),
            oauthToken: token,
        )

        let clientKeyPair = makeClientKeyPair()

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

        let testItems = try [
            XCTUnwrap("Serialization test 1".data(using: .utf8)),
            XCTUnwrap("Serialization test 2".data(using: .utf8)),
        ]

        let keyStore = KeyStore(curve: .secp256r1)
        let kasService = KASService(keyStore: keyStore, baseURL: platformURL)

        let kasMetadata = try await kasService.generateKasMetadata()

        let policyLocator = try XCTUnwrap(ResourceLocator(
            protocolEnum: .https,
            body: "\(platformURL.host ?? "localhost")/policy/serial-test",
        ))

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

        let policyLocator = try XCTUnwrap(ResourceLocator(
            protocolEnum: .https,
            body: "\(platformURL.host ?? "localhost")/policy/batch-test",
        ))

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
}
