@preconcurrency import CryptoKit
@testable import OpenTDFKit
import XCTest

final class KASRewrapClientTests: XCTestCase {
    private var client: KASRewrapClient!
    private let testKASURL = URL(string: "https://kas.example.com")!
    private let testOAuthToken = "test_token_123"

    override func setUp() {
        super.setUp()
        client = KASRewrapClient(
            kasURL: testKASURL,
            oauthToken: testOAuthToken,
        )
    }

    override func tearDown() {
        client = nil
        super.tearDown()
    }

    func testJWTSigningWithValidKey() throws {
        let signingKey = P256.Signing.PrivateKey()
        let requestBody = "test request body".data(using: .utf8)!

        let jwt = try client.createSignedJWT(requestBody: requestBody, signingKey: signingKey)

        let components = jwt.split(separator: ".")
        XCTAssertEqual(components.count, 3, "JWT should have 3 parts: header.payload.signature")

        let headerData = Data(base64URLDecoded: String(components[0]))!
        let header = try JSONSerialization.jsonObject(with: headerData) as! [String: String]
        XCTAssertEqual(header["alg"], "ES256")
        XCTAssertEqual(header["typ"], "JWT")

        let payloadData = Data(base64URLDecoded: String(components[1]))!
        let payload = try JSONSerialization.jsonObject(with: payloadData) as! [String: Any]
        XCTAssertNotNil(payload["requestBody"])
        XCTAssertNotNil(payload["iat"])
        XCTAssertNotNil(payload["exp"])
    }

    func testJWTSignatureVerification() throws {
        let signingKey = P256.Signing.PrivateKey()
        let requestBody = "verify signature test".data(using: .utf8)!

        let jwt = try client.createSignedJWT(requestBody: requestBody, signingKey: signingKey)

        let components = jwt.split(separator: ".")
        let signingInput = "\(components[0]).\(components[1])".data(using: .utf8)!
        let signatureData = Data(base64URLDecoded: String(components[2]))!

        let signature = try P256.Signing.ECDSASignature(rawRepresentation: signatureData)
        let publicKey = signingKey.publicKey

        XCTAssertTrue(publicKey.isValidSignature(signature, for: signingInput))
    }

    func testJWTExpirationTime() throws {
        let signingKey = P256.Signing.PrivateKey()
        let requestBody = "expiration test".data(using: .utf8)!

        let jwt = try client.createSignedJWT(requestBody: requestBody, signingKey: signingKey)

        let components = jwt.split(separator: ".")
        let payloadData = Data(base64URLDecoded: String(components[1]))!
        let payload = try JSONSerialization.jsonObject(with: payloadData) as! [String: Any]

        let iat = payload["iat"] as! Int
        let exp = payload["exp"] as! Int

        XCTAssertEqual(exp - iat, 60, "Token should expire 60 seconds after issuance")
    }

    func testPEMParsingWithStandardFormat() throws {
        let testKey = P256.KeyAgreement.PrivateKey()
        let derData = testKey.publicKey.derRepresentation
        let base64PEM = derData.base64EncodedString()
        let pemKey = """
        -----BEGIN PUBLIC KEY-----
        \(base64PEM)
        -----END PUBLIC KEY-----
        """

        let compressedKey = try client.extractCompressedKeyFromPEM(pemKey)
        XCTAssertEqual(compressedKey.count, 33, "Compressed P-256 key should be 33 bytes")
        XCTAssertEqual(compressedKey, testKey.publicKey.compressedRepresentation, "Compressed key should match original")
    }

    func testPEMParsingWithECPublicKeyFormat() throws {
        let testKey = P256.KeyAgreement.PrivateKey()
        let derData = testKey.publicKey.derRepresentation
        let base64PEM = derData.base64EncodedString()
        let pemKey = """
        -----BEGIN EC PUBLIC KEY-----
        \(base64PEM)
        -----END EC PUBLIC KEY-----
        """

        let compressedKey = try client.extractCompressedKeyFromPEM(pemKey)
        XCTAssertEqual(compressedKey.count, 33, "Compressed P-256 key should be 33 bytes")
        XCTAssertEqual(compressedKey, testKey.publicKey.compressedRepresentation, "Compressed key should match original")
    }

    func testPEMParsingWithECDSAFormat() throws {
        let testKey = P256.KeyAgreement.PrivateKey()
        let derData = testKey.publicKey.derRepresentation
        let base64PEM = derData.base64EncodedString()
        let pemKey = """
        -----BEGIN ECDSA PUBLIC KEY-----
        \(base64PEM)
        -----END ECDSA PUBLIC KEY-----
        """

        let compressedKey = try client.extractCompressedKeyFromPEM(pemKey)
        XCTAssertEqual(compressedKey.count, 33, "Compressed P-256 key should be 33 bytes")
        XCTAssertEqual(compressedKey, testKey.publicKey.compressedRepresentation, "Compressed key should match original")
    }

    func testPEMParsingWithInvalidBase64() {
        let invalidPEM = """
        -----BEGIN PUBLIC KEY-----
        This is not valid base64!!!
        -----END PUBLIC KEY-----
        """

        XCTAssertThrowsError(try client.extractCompressedKeyFromPEM(invalidPEM)) { error in
            guard case let KASRewrapError.pemParsingFailed(message) = error else {
                XCTFail("Expected pemParsingFailed error")
                return
            }
            XCTAssertTrue(message.contains("base64"), "Error should mention base64 encoding issue")
        }
    }

    func testPEMParsingWithEmptyContent() {
        let emptyPEM = """
        -----BEGIN PUBLIC KEY-----
        -----END PUBLIC KEY-----
        """

        XCTAssertThrowsError(try client.extractCompressedKeyFromPEM(emptyPEM)) { error in
            guard case let KASRewrapError.pemParsingFailed(message) = error else {
                XCTFail("Expected pemParsingFailed error")
                return
            }
            XCTAssertTrue(message.contains("Empty"), "Error should mention empty content")
        }
    }

    func testPEMParsingWithTooShortData() {
        let shortDER = Data([0x00, 0x01, 0x02])
        let shortPEM = """
        -----BEGIN PUBLIC KEY-----
        \(shortDER.base64EncodedString())
        -----END PUBLIC KEY-----
        """

        XCTAssertThrowsError(try client.extractCompressedKeyFromPEM(shortPEM)) { error in
            guard case let KASRewrapError.pemParsingFailed(message) = error else {
                XCTFail("Expected pemParsingFailed error")
                return
            }
            XCTAssertTrue(message.contains("too small") || message.contains("size"), "Error should mention data size")
        }
    }

    func testKeyUnwrappingWithValidKeys() throws {
        let clientPrivateKey = P256.KeyAgreement.PrivateKey()
        let sessionPrivateKey = P256.KeyAgreement.PrivateKey()

        let sharedSecret = try sessionPrivateKey.sharedSecretFromKeyAgreement(with: clientPrivateKey.publicKey)

        let salt = CryptoConstants.hkdfSalt
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: Data(),
            outputByteCount: 32,
        )

        let testKey = SymmetricKey(size: .bits256)
        let testKeyData = testKey.withUnsafeBytes { Data(Array($0)) }

        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(testKeyData, using: symmetricKey, nonce: nonce)

        var wrappedKey = Data()
        nonce.withUnsafeBytes { wrappedKey.append(contentsOf: $0) }
        wrappedKey.append(sealedBox.ciphertext)
        wrappedKey.append(sealedBox.tag)

        let unwrappedKey = try KASRewrapClient.unwrapKey(
            wrappedKey: wrappedKey,
            sessionPublicKey: sessionPrivateKey.publicKey.compressedRepresentation,
            clientPrivateKey: clientPrivateKey.rawRepresentation,
        )

        let unwrappedKeyData = unwrappedKey.withUnsafeBytes { Data(Array($0)) }
        XCTAssertEqual(unwrappedKeyData, testKeyData, "Unwrapped key should match original key")
    }

    func testKeyUnwrappingWithInvalidWrappedKeyFormat() {
        let clientPrivateKey = P256.KeyAgreement.PrivateKey()
        let sessionPrivateKey = P256.KeyAgreement.PrivateKey()

        let tooShortWrappedKey = Data([0x00, 0x01, 0x02])

        XCTAssertThrowsError(
            try KASRewrapClient.unwrapKey(
                wrappedKey: tooShortWrappedKey,
                sessionPublicKey: sessionPrivateKey.publicKey.compressedRepresentation,
                clientPrivateKey: clientPrivateKey.rawRepresentation,
            ),
        ) { error in
            XCTAssertTrue(error is KASRewrapError, "Should throw KASRewrapError")
        }
    }

    func testKeyUnwrappingWithInvalidSessionKey() {
        let clientPrivateKey = P256.KeyAgreement.PrivateKey()
        let invalidSessionKey = Data([0x02] + [UInt8](repeating: 0xFF, count: 32))

        let wrappedKey = Data(count: 48)

        XCTAssertThrowsError(
            try KASRewrapClient.unwrapKey(
                wrappedKey: wrappedKey,
                sessionPublicKey: invalidSessionKey,
                clientPrivateKey: clientPrivateKey.rawRepresentation,
            ),
        ) { error in
            XCTAssertTrue(error is CryptoKitError, "Should throw CryptoKitError for invalid key")
        }
    }

    func testKeyUnwrappingWithInvalidClientKey() {
        let sessionPrivateKey = P256.KeyAgreement.PrivateKey()
        let invalidClientKey = Data([0x00, 0x01, 0x02])

        let wrappedKey = Data(count: 48)

        XCTAssertThrowsError(
            try KASRewrapClient.unwrapKey(
                wrappedKey: wrappedKey,
                sessionPublicKey: sessionPrivateKey.publicKey.compressedRepresentation,
                clientPrivateKey: invalidClientKey,
            ),
        ) { error in
            XCTAssertTrue(error is CryptoKitError, "Should throw CryptoKitError for invalid key")
        }
    }

    func testErrorDescriptions() {
        let errors: [(KASRewrapError, String)] = [
            (.invalidResponse, "Invalid response"),
            (.emptyResponse, "Empty response"),
            (.accessDenied("test reason"), "Access denied: test reason"),
            (.authenticationFailed, "Authentication failed"),
            (.missingWrappedKey, "missing wrapped key"),
            (.missingSessionKey, "missing session public key"),
            (.invalidWrappedKeyFormat, "Invalid wrapped key format"),
            (.pemParsingFailed("bad PEM"), "PEM parsing failed: bad PEM"),
            (.httpError(500, "server error"), "HTTP error 500: server error"),
            (.httpError(404, nil), "HTTP error 404"),
        ]

        for (error, expectedSubstring) in errors {
            let description = error.description
            XCTAssertTrue(
                description.contains(expectedSubstring),
                "Error description '\(description)' should contain '\(expectedSubstring)'",
            )
        }
    }

    func testRewrapRequestStructureSerialization() throws {
        let header = Data([0x4C, 0x31, 0x4D])
        let keyAccess = KASRewrapClient.KeyAccessObject(
            header: header.base64EncodedString(),
            url: "https://kas.example.com",
        )

        let encoder = JSONEncoder()
        let jsonData = try encoder.encode(keyAccess)
        let json = try JSONSerialization.jsonObject(with: jsonData) as! [String: Any]

        XCTAssertEqual(json["type"] as? String, "remote")
        XCTAssertEqual(json["protocol"] as? String, "kas")
        XCTAssertEqual(json["url"] as? String, "https://kas.example.com")
        XCTAssertEqual(json["header"] as? String, header.base64EncodedString())
    }

    func testRewrapRequestEntryWithDefaultAlgorithm() throws {
        let policyBody = "test policy".data(using: .utf8)!
        let policy = KASRewrapClient.Policy(body: policyBody.base64EncodedString())

        let keyAccessObject = KASRewrapClient.KeyAccessObject(
            header: Data().base64EncodedString(),
            url: "https://kas.example.com",
        )
        let wrapper = KASRewrapClient.KeyAccessObjectWrapper(
            keyAccessObjectId: "test-id",
            keyAccessObject: keyAccessObject,
        )

        let requestEntry = KASRewrapClient.RewrapRequestEntry(
            policy: policy,
            keyAccessObjects: [wrapper],
        )

        XCTAssertEqual(requestEntry.algorithm, "ec:secp256r1")
    }

    func testRewrapResponseDeserialization() throws {
        let jsonString = """
        {
            "responses": [{
                "policyId": "policy-1",
                "results": [{
                    "keyAccessObjectId": "kao-1",
                    "status": "permit",
                    "kasWrappedKey": "dGVzdCB3cmFwcGVkIGtleQ==",
                    "metadata": {}
                }]
            }],
            "sessionPublicKey": "-----BEGIN PUBLIC KEY-----\\ntest\\n-----END PUBLIC KEY-----"
        }
        """

        let jsonData = jsonString.data(using: .utf8)!
        let decoder = JSONDecoder()
        let response = try decoder.decode(KASRewrapClient.RewrapResponse.self, from: jsonData)

        XCTAssertEqual(response.responses.count, 1)
        XCTAssertEqual(response.responses[0].policyId, "policy-1")
        XCTAssertEqual(response.responses[0].results[0].status, "permit")
        XCTAssertNotNil(response.sessionPublicKey)
    }

    func testRewrapResponseWithLegacyEntityWrappedKey() throws {
        let jsonString = """
        {
            "responses": [{
                "policyId": "policy-1",
                "results": [{
                    "keyAccessObjectId": "kao-1",
                    "status": "permit",
                    "entityWrappedKey": "bGVnYWN5IHdyYXBwZWQga2V5",
                    "metadata": {}
                }]
            }],
            "sessionPublicKey": "-----BEGIN PUBLIC KEY-----\\ntest\\n-----END PUBLIC KEY-----"
        }
        """

        let jsonData = jsonString.data(using: .utf8)!
        let decoder = JSONDecoder()
        let response = try decoder.decode(KASRewrapClient.RewrapResponse.self, from: jsonData)

        XCTAssertEqual(response.responses[0].results[0].entityWrappedKey, "bGVnYWN5IHdyYXBwZWQga2V5")
        XCTAssertNil(response.responses[0].results[0].kasWrappedKey)
    }

    func testBase64URLEncoding() {
        let testData = Data([0xFF, 0xFE, 0xFD])
        let base64URL = testData.base64URLEncodedString()

        XCTAssertFalse(base64URL.contains("+"))
        XCTAssertFalse(base64URL.contains("/"))
        XCTAssertFalse(base64URL.contains("="))
    }

    func testHexEncoding() {
        let testData = Data([0x01, 0x0A, 0xFF])
        let hex = testData.hexEncodedString()

        XCTAssertEqual(hex, "010aff")
    }
}

extension Data {
    init?(base64URLDecoded string: String) {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        let paddingLength = (4 - base64.count % 4) % 4
        base64 += String(repeating: "=", count: paddingLength)

        self.init(base64Encoded: base64)
    }
}

extension KASRewrapClient {
    func createSignedJWT(requestBody: Data, signingKey: P256.Signing.PrivateKey) throws -> String {
        let header = ["alg": "ES256", "typ": "JWT"]
        let headerJSON = try JSONSerialization.data(withJSONObject: header)
        let headerBase64 = headerJSON.base64URLEncodedString()

        let now = Int(Date().timeIntervalSince1970)
        let requestBodyString = String(data: requestBody, encoding: .utf8) ?? ""
        let claims: [String: Any] = [
            "requestBody": requestBodyString,
            "iat": now,
            "exp": now + 60,
        ]
        let claimsJSON = try JSONSerialization.data(withJSONObject: claims)
        let claimsBase64 = claimsJSON.base64URLEncodedString()

        let signingInput = "\(headerBase64).\(claimsBase64)".data(using: .utf8)!
        let signature = try signingKey.signature(for: signingInput)
        let signatureBase64 = signature.rawRepresentation.base64URLEncodedString()

        return "\(headerBase64).\(claimsBase64).\(signatureBase64)"
    }

    func extractCompressedKeyFromPEM(_ pem: String) throws -> Data {
        let normalizedPEM = pem
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        let beginMarkers = [
            "-----BEGIN PUBLIC KEY-----",
            "-----BEGIN EC PUBLIC KEY-----",
            "-----BEGIN ECDSA PUBLIC KEY-----",
        ]
        let endMarkers = [
            "-----END PUBLIC KEY-----",
            "-----END EC PUBLIC KEY-----",
            "-----END ECDSA PUBLIC KEY-----",
        ]

        var base64Content = normalizedPEM
        for marker in beginMarkers + endMarkers {
            base64Content = base64Content.replacingOccurrences(of: marker, with: "")
        }

        base64Content = base64Content.components(separatedBy: .whitespacesAndNewlines).joined()

        guard !base64Content.isEmpty else {
            throw KASRewrapError.pemParsingFailed("Empty PEM content")
        }

        guard let derData = Data(base64Encoded: base64Content) else {
            throw KASRewrapError.pemParsingFailed("Invalid base64 encoding")
        }

        guard derData.count >= 70 else {
            throw KASRewrapError.pemParsingFailed("DER data too small: \(derData.count) bytes")
        }

        do {
            let publicKey = try P256.KeyAgreement.PublicKey(derRepresentation: derData)
            let compressedKey = publicKey.compressedRepresentation

            guard compressedKey.count == 33 else {
                throw KASRewrapError.pemParsingFailed("Invalid compressed key size: \(compressedKey.count)")
            }

            return compressedKey
        } catch let error as CryptoKitError {
            throw KASRewrapError.pemParsingFailed("CryptoKit error: \(error.localizedDescription)")
        } catch {
            throw KASRewrapError.pemParsingFailed("Failed to parse DER: \(error.localizedDescription)")
        }
    }
}
