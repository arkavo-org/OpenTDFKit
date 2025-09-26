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
}
