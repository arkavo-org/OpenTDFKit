@preconcurrency import CryptoKit
import Foundation
@testable import OpenTDFKit
import SwiftCBOR
import XCTest
@preconcurrency import ZIPFoundation

/// Regression test suite for Issue #69 (security & bug audit findings).
final class SecurityAuditRegressionTests: XCTestCase {
    override func tearDown() {
        MockURLProtocol.handler = nil
        super.tearDown()
    }

    // MARK: - #1 & #2: Embedded Encrypted Policies (NanoTDF & CollectionBuilder)

    func testEmbeddedEncryptedPolicyRetainsAuthTagAndSeparatesKeyFromGMAC() async throws {
        let kasKey = P256.KeyAgreement.PrivateKey()
        let kasRL = try XCTUnwrap(ResourceLocator(protocolEnum: .https, body: "kas.example.com"))
        let kasMetadata = try KasMetadata(resourceLocator: kasRL, publicKey: kasKey.publicKey, curve: .secp256r1)

        let policyPlaintext = Data(#"{"uuid":"p1","body":{"dataAttributes":[],"dissem":[]}}"#.utf8)
        var policy = Policy(
            type: .embeddedEncrypted,
            body: EmbeddedPolicyBody(body: policyPlaintext),
            remote: nil,
            binding: nil,
        )

        let nano = try await createNanoTDF(
            kas: kasMetadata,
            policy: &policy,
            plaintext: Data("secret payload".utf8),
        )

        let encryptedPolicyBody = try XCTUnwrap(nano.header.policy.body?.body)
        // Must NOT be cleartext and MUST include 16-byte GCM tag
        XCTAssertNotEqual(encryptedPolicyBody, policyPlaintext)
        XCTAssertEqual(encryptedPolicyBody.count, policyPlaintext.count + 16)

        // Derive payload symmetric key as KAS would
        let sharedSecret = try kasKey.sharedSecretFromKeyAgreement(
            with: P256.KeyAgreement.PublicKey(compressedRepresentation: nano.header.ephemeralPublicKey),
        )
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: CryptoHelper.computeHKDFSalt(version: Header.versionV12),
            sharedInfo: Data(),
            outputByteCount: 32,
        )

        // Policy binding must verify
        XCTAssertNoThrow(try nano.header.verifyPolicyBinding(symmetricKey: symmetricKey))

        // Embedded encrypted policy decrypts cleanly with domain-separated key
        let recoveredPolicy = try CryptoHelper.decryptEmbeddedPolicy(
            ciphertextWithTag: encryptedPolicyBody,
            using: symmetricKey,
        )
        XCTAssertEqual(recoveredPolicy, policyPlaintext)

        // Tampering with ciphertext or tag must fail authentication
        var tampered = encryptedPolicyBody
        tampered[tampered.count - 1] ^= 0x01
        XCTAssertThrowsError(try CryptoHelper.decryptEmbeddedPolicy(
            ciphertextWithTag: tampered,
            using: symmetricKey,
        ))

        // Domain-separated policy key must NOT equal the raw payload symmetricKey
        let policyKey = CryptoHelper.deriveEmbeddedPolicyKey(from: symmetricKey)
        XCTAssertNotEqual(
            policyKey.withUnsafeBytes { Data($0) },
            symmetricKey.withUnsafeBytes { Data($0) },
        )
    }

    func testEmbeddedEncryptedWithPolicyKeyAccessRetainsAuthTag() async throws {
        let kasKey = P256.KeyAgreement.PrivateKey()
        let kasRL = try XCTUnwrap(ResourceLocator(protocolEnum: .https, body: "kas.example.com"))
        let kasMetadata = try KasMetadata(resourceLocator: kasRL, publicKey: kasKey.publicKey, curve: .secp256r1)

        let policyPlaintext = Data(#"{"classification":"top-secret"}"#.utf8)
        let placeholderKey = P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation
        var policy = Policy(
            type: .embeddedEncryptedWithPolicyKeyAccess,
            body: EmbeddedPolicyBody(
                body: policyPlaintext,
                keyAccess: PolicyKeyAccess(resourceLocator: kasRL, ephemeralPublicKey: placeholderKey),
            ),
            remote: nil,
            binding: nil,
        )

        let nano = try await createNanoTDF(kas: kasMetadata, policy: &policy, plaintext: Data("msg".utf8))
        let encryptedBody = try XCTUnwrap(nano.header.policy.body)
        XCTAssertEqual(encryptedBody.body.count, policyPlaintext.count + 16)

        let policyKeyAccess = try XCTUnwrap(encryptedBody.keyAccess)
        let shared = try kasKey.sharedSecretFromKeyAgreement(
            with: P256.KeyAgreement.PublicKey(compressedRepresentation: policyKeyAccess.ephemeralPublicKey),
        )
        let policyKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: CryptoHelper.computeHKDFSalt(version: Header.versionV12),
            sharedInfo: Data(),
            outputByteCount: 32,
        )
        let nonce = try AES.GCM.Nonce(data: Data(count: 12))
        let ct = encryptedBody.body.dropLast(16)
        let tag = encryptedBody.body.suffix(16)
        let opened = try AES.GCM.open(AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag), using: policyKey)
        XCTAssertEqual(opened, policyPlaintext)
    }

    func testNanoTDFCollectionBuilderEncryptsEmbeddedEncryptedPolicyAndComputesValidBinding() async throws {
        let keyStore = KeyStore(curve: .secp256r1)
        let kasService = KASService(keyStore: keyStore, baseURL: URL(string: "https://kas.example.com")!)
        let kasMetadata = try await kasService.generateKasMetadata()

        let policyPlaintext = Data(#"{"attr":"confidential"}"#.utf8)
        let collection = try await NanoTDFCollectionBuilder()
            .kasMetadata(kasMetadata)
            .policy(.embeddedEncrypted(policyPlaintext))
            .build()

        let header = await collection.header
        let symKey = await collection.getSymmetricKey()
        let storedBody = try XCTUnwrap(header.policy.body?.body)

        // Must NOT be cleartext
        XCTAssertNotEqual(storedBody, policyPlaintext)
        XCTAssertEqual(storedBody.count, policyPlaintext.count + 16)
        XCTAssertEqual(
            try CryptoHelper.decryptEmbeddedPolicy(ciphertextWithTag: storedBody, using: symKey),
            policyPlaintext,
        )

        // Decryptor with KeyStore must verify the GMAC binding over EmbeddedPolicyBody.toData()
        let item = try await collection.encryptItem(plaintext: Data("hello".utf8))
        let decryptor = try await NanoTDFCollectionDecryptor.withKeyStore(header: header, keyStore: keyStore)
        let decrypted = try await decryptor.decryptItem(item)
        XCTAssertEqual(decrypted, Data("hello".utf8))

        // Client-side withUnwrappedKey(header:symmetricKey:) verifies policy binding and rejects tampering
        let clientDecryptor = try NanoTDFCollectionDecryptor.withUnwrappedKey(header: header, symmetricKey: symKey)
        let clientDecrypted = try await clientDecryptor.decryptItem(item)
        XCTAssertEqual(clientDecrypted, Data("hello".utf8))

        var tamperedPolicy = header.policy
        tamperedPolicy.body = EmbeddedPolicyBody(body: Data("tampered-policy".utf8), keyAccess: tamperedPolicy.body?.keyAccess)
        let tamperedHeader = Header(
            payloadKeyAccess: header.payloadKeyAccess,
            policyBindingConfig: header.policyBindingConfig,
            payloadSignatureConfig: header.payloadSignatureConfig,
            policy: tamperedPolicy,
            ephemeralPublicKey: header.ephemeralPublicKey,
        )
        XCTAssertThrowsError(try NanoTDFCollectionDecryptor.withUnwrappedKey(header: tamperedHeader, symmetricKey: symKey)) { error in
            XCTAssertEqual(error as? NanoTDFError, .invalidPolicyBinding)
        }
    }

    // MARK: - #4: Data Slices (startIndex > 0) & Offset Safety

    func testBinaryParserAndCollectionFileHandleNonZeroStartIndexSlices() async throws {
        let keyStore = KeyStore(curve: .secp256r1)
        let kasService = KASService(keyStore: keyStore, baseURL: URL(string: "https://kas.example.com")!)
        let kasMetadata = try await kasService.generateKasMetadata()

        let remote = try XCTUnwrap(ResourceLocator(protocolEnum: .https, body: "kas.example.com/policy"))
        var policy = Policy(type: .remote, body: nil, remote: remote, binding: nil)
        let nano = try await createNanoTDF(kas: kasMetadata, policy: &policy, plaintext: Data("slice test".utf8))
        let raw = nano.toData()

        // Create a Data slice with startIndex > 0
        let padded = Data([0xAA, 0xBB, 0xCC, 0xDD]) + raw
        let slice = padded.dropFirst(4)
        XCTAssertGreaterThan(slice.startIndex, 0)

        let parser = BinaryParser(data: slice)
        let parsedHeader = try parser.parseHeader()
        let parsedPayload = try parser.parsePayload(config: parsedHeader.payloadSignatureConfig)
        XCTAssertEqual(parsedHeader.toData(), nano.header.toData())
        XCTAssertEqual(parsedPayload.ciphertext, nano.payload.ciphertext)

        // Overflow / negative length checks
        XCTAssertNil(parser.read(length: -1))
        XCTAssertNil(parser.read(length: Int.max))

        // NanoTDFCollectionFile.parse with startIndex > 0
        let fileData = NanoTDFCollectionFile.serialize(header: nano.header.toData(), items: Data([1, 2, 3]), itemCount: 1)
        let slicedFile = (Data([0xFF, 0xEE, 0xDD]) + fileData).dropFirst(3)
        XCTAssertGreaterThan(slicedFile.startIndex, 0)
        let parsedFile = try NanoTDFCollectionFile.parse(from: slicedFile)
        XCTAssertEqual(parsedFile.header, nano.header.toData())
        XCTAssertEqual(parsedFile.items, Data([1, 2, 3]))
        XCTAssertEqual(parsedFile.itemCount, 1)

        // Crafted UInt32.max header length must throw rather than overflow/crash
        let hugeHeader = Data([0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00])
        XCTAssertThrowsError(try NanoTDFCollectionFile.parse(from: hugeHeader))
    }

    // MARK: - #5: Non-Zero 3-Byte NanoTDF Nonce

    func testGenerateNonZeroNonceNeverProducesAllZeroBytes() throws {
        let helper = CryptoHelper()
        for _ in 0 ..< 100 {
            let nonce = try helper.generateNonZeroNonce(length: 3)
            XCTAssertEqual(nonce.count, 3)
            XCTAssertNotEqual(nonce, Data([0, 0, 0]))
        }
    }

    // MARK: - #6: addSignatureToNanoTDF Curve Validation

    func testAddSignatureRejectsMismatchedCurveAndDefaultsNilToP256() async throws {
        let kasKey = P256.KeyAgreement.PrivateKey()
        let kasRL = try XCTUnwrap(ResourceLocator(protocolEnum: .https, body: "kas.example.com"))
        let kasMetadata = try KasMetadata(resourceLocator: kasRL, publicKey: kasKey.publicKey, curve: .secp256r1)
        var policy = Policy(type: .remote, body: nil, remote: kasRL, binding: nil)
        var nano = try await createNanoTDF(kas: kasMetadata, policy: &policy, plaintext: Data("hi".utf8))

        let signingKey = P256.Signing.PrivateKey()
        let mismatchedConfig = SignatureAndPayloadConfig(signed: true, signatureCurve: .secp384r1, payloadCipher: .aes256GCM128)
        do {
            try await addSignatureToNanoTDF(nanoTDF: &nano, privateKey: signingKey, config: mismatchedConfig)
            XCTFail("Expected unsupportedCurve for P-384 config with P-256 key")
        } catch CryptoHelperError.unsupportedCurve {}

        let nilCurveConfig = SignatureAndPayloadConfig(signed: false, signatureCurve: nil, payloadCipher: .aes256GCM128)
        try await addSignatureToNanoTDF(nanoTDF: &nano, privateKey: signingKey, config: nilCurveConfig)
        XCTAssertTrue(nano.header.payloadSignatureConfig.signed)
        XCTAssertEqual(nano.header.payloadSignatureConfig.signatureCurve, .secp256r1)
    }

    // MARK: - #7 & #12: Policy Binding Verification & v12 KeyStore Lookup

    func testNanoTDFDecryptVerifiesPolicyBindingAndSupportsParsedV12KeyStoreLookup() async throws {
        let keyStore = KeyStore(curve: .secp256r1)
        let kasService = KASService(keyStore: keyStore, baseURL: URL(string: "https://kas.example.com")!)
        let kasMetadata = try await kasService.generateKasMetadata()

        let policyBody = EmbeddedPolicyBody(body: Data("classification:secret".utf8))
        var policy = Policy(type: .embeddedPlaintext, body: policyBody, remote: nil, binding: nil)
        let plaintext = Data("protected payload".utf8)
        let nano = try await createNanoTDF(kas: kasMetadata, policy: &policy, plaintext: plaintext)

        // Round-trip through BinaryParser (v12 wire format leaves kasPublicKey empty!)
        let parser = BinaryParser(data: nano.toData())
        let parsedHeader = try parser.parseHeader()
        let parsedPayload = try parser.parsePayload(config: parsedHeader.payloadSignatureConfig)
        XCTAssertTrue(parsedHeader.payloadKeyAccess.kasPublicKey.isEmpty)

        // #12: KeyStore decryption succeeds on parsed v12 header (single-key store)
        let parsedNano = NanoTDF(header: parsedHeader, payload: parsedPayload)
        let recovered = try await parsedNano.getPlaintext(using: keyStore)
        XCTAssertEqual(recovered, plaintext)

        // #7: Tampering with policy body must fail with invalidPolicyBinding
        var tamperedPolicy = parsedHeader.policy
        tamperedPolicy.body = EmbeddedPolicyBody(body: Data("classification:public".utf8))
        let tamperedHeader = Header(
            payloadKeyAccess: parsedHeader.payloadKeyAccess,
            policyBindingConfig: parsedHeader.policyBindingConfig,
            payloadSignatureConfig: parsedHeader.payloadSignatureConfig,
            policy: tamperedPolicy,
            ephemeralPublicKey: parsedHeader.ephemeralPublicKey,
        )
        let tamperedNano = NanoTDF(header: tamperedHeader, payload: parsedPayload)
        do {
            _ = try await tamperedNano.getPlaintext(using: keyStore)
            XCTFail("Expected invalidPolicyBinding")
        } catch NanoTDFError.invalidPolicyBinding {}

        // Also test CollectionDecryptor rejects tampered binding
        do {
            _ = try await NanoTDFCollectionDecryptor.withKeyStore(header: tamperedHeader, keyStore: keyStore)
            XCTFail("Expected invalidPolicyBinding")
        } catch NanoTDFError.invalidPolicyBinding {}
    }

    // MARK: - #8 & #34: KASRewrapClient.rewrapNanoTDF Signs with Client Key, Supports P-384, Sends Remote Policy

    func testRewrapNanoTDFSignsWithClientKeySupportsP384AndEncodesRemotePolicy() async throws {
        let clientPriv = P384.KeyAgreement.PrivateKey()
        let clientKeyPair = EphemeralKeyPair(
            privateKey: clientPriv.rawRepresentation,
            publicKey: clientPriv.publicKey.compressedRepresentation,
            curve: .secp384r1,
        )
        let sessionPriv = P384.KeyAgreement.PrivateKey()
        let expectedDEK = SymmetricKey(size: .bits256)

        let remoteLocator = try XCTUnwrap(ResourceLocator(protocolEnum: .https, body: "kas.example.com/policy/42"))
        let kasLocator = try XCTUnwrap(ResourceLocator(protocolEnum: .https, body: "kas.example.com"))
        let header = Header(
            kas: kasLocator,
            policyBindingConfig: PolicyBindingConfig(ecdsaBinding: false, curve: .secp384r1),
            payloadSignatureConfig: SignatureAndPayloadConfig(signed: false, signatureCurve: nil, payloadCipher: .aes256GCM128),
            policy: Policy(type: .remote, body: nil, remote: remoteLocator, binding: Data(count: 8)),
            ephemeralPublicKey: P384.KeyAgreement.PrivateKey().publicKey.compressedRepresentation,
        )

        var verifiedJWT = false
        var seenAlgorithm: String?
        var seenPolicyBody: String?

        MockURLProtocol.handler = { request in
            let body = try XCTUnwrap(Self.readHTTPBody(request))
            let outer = try XCTUnwrap(try JSONSerialization.jsonObject(with: body) as? [String: Any])
            let jwt = try XCTUnwrap(outer["signed_request_token"] as? String)
            let parts = jwt.split(separator: ".")
            XCTAssertEqual(parts.count, 3)

            let jwtHeaderData = try XCTUnwrap(Data(base64URLEncoded: parts[0]))
            let jwtHeader = try XCTUnwrap(try JSONSerialization.jsonObject(with: jwtHeaderData) as? [String: String])
            XCTAssertEqual(jwtHeader["alg"], "ES384")

            // Verify JWT signature using clientKeyPair's P-384 signing public key
            let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
            let sigBytes = try XCTUnwrap(Data(base64URLEncoded: parts[2]))
            let signingPub = try P384.Signing.PrivateKey(rawRepresentation: clientPriv.rawRepresentation).publicKey
            let ecdsaSig = try P384.Signing.ECDSASignature(rawRepresentation: sigBytes)
            verifiedJWT = signingPub.isValidSignature(ecdsaSig, for: signingInput)

            let claimsData = try XCTUnwrap(Data(base64URLEncoded: parts[1]))
            let claims = try XCTUnwrap(try JSONSerialization.jsonObject(with: claimsData) as? [String: Any])
            let reqBodyStr = try XCTUnwrap(claims["requestBody"] as? String)
            let unsigned = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(reqBodyStr.utf8)) as? [String: Any])
            let reqs = try XCTUnwrap(unsigned["requests"] as? [[String: Any]])
            seenAlgorithm = reqs.first?["algorithm"] as? String
            seenPolicyBody = (reqs.first?["policy"] as? [String: Any])?["body"] as? String

            // Wrap DEK with P-384 ECDH + NanoTDF v12 salt
            let shared = try sessionPriv.sharedSecretFromKeyAgreement(with: clientPriv.publicKey)
            let kek = shared.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: CryptoConstants.hkdfSalt,
                sharedInfo: Data(),
                outputByteCount: 32,
            )
            let sealed = try expectedDEK.withUnsafeBytes { try AES.GCM.seal($0, using: kek) }
            let respObj: [String: Any] = [
                "responses": [[
                    "policyId": "policy",
                    "results": [[
                        "keyAccessObjectId": "kao-0",
                        "status": "permit",
                        "kasWrappedKey": sealed.combined!.base64EncodedString(),
                    ]],
                ]],
                "sessionPublicKey": sessionPriv.publicKey.pemRepresentation,
            ]
            let resp = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return try (resp, JSONSerialization.data(withJSONObject: respObj))
        }

        let client = try KASRewrapClient(
            configuration: OpenTDFConfiguration.forKasConnect("https://kas.example.com"),
            oauthToken: "token",
            urlSession: MockURLProtocol.makeSession(),
        )
        let (wrappedKey, sessionPub) = try await client.rewrapNanoTDF(
            header: header.toData(),
            parsedHeader: header,
            clientKeyPair: clientKeyPair,
        )
        XCTAssertTrue(verifiedJWT, "JWT must be signed with clientKeyPair.privateKey")
        XCTAssertEqual(seenAlgorithm, "ec:secp384r1")
        XCTAssertEqual(seenPolicyBody, remoteLocator.toData().base64EncodedString())
        XCTAssertEqual(sessionPub, sessionPriv.publicKey.compressedRepresentation)

        // Unwrap with P-384
        let unwrapped = try KASRewrapClient.unwrapKey(
            wrappedKey: wrappedKey,
            sessionPublicKey: sessionPub,
            clientPrivateKey: clientKeyPair.privateKey,
        )
        XCTAssertEqual(
            unwrapped.withUnsafeBytes { Data($0) },
            expectedDEK.withUnsafeBytes { Data($0) },
        )
    }

    // MARK: - #9, #10, #24: SSRF Bypasses, No-Redirect & Bounded HTTP

    func testValidateKasURLBlocksSSRFBypassesAndAcceptsCaseInsensitiveLocalhost() {
        // Case-insensitive localhost
        XCTAssertNoThrow(try validateKasURL("http://LOCALHOST:8080/kas"))
        XCTAssertNoThrow(try validateKasURL("http://LocalHost.:8080/kas"))

        let blocked = [
            // IPv6 zone IDs
            "https://[fe80::1%25en0]/kas",
            "http://[::1%25lo0]/kas",
            // Non-canonical IPv4 (integer, hex, octal, shorthand, trailing dot)
            "https://2130706433/kas",
            "https://2852039166/kas",
            "https://0x7f000001/kas",
            "https://0177.0.0.1/kas",
            "https://127.1/kas",
            "https://10.1/kas",
            "https://169.254.169.254./kas",
            "https://10.0.0.1./kas",
            "https://127.0.0.1./kas",
            // Missing CIDRs
            "https://0.1.2.3/kas",
            "https://100.64.0.1/kas",
            "https://100.127.255.254/kas",
            "https://224.0.0.1/kas",
            "https://240.0.0.1/kas",
            "https://255.255.255.255/kas",
            "https://[::ffff:127.0.0.1]/kas",
            "https://[::ffff:8.8.8.8]/kas",
            "https://[::7f00:1]/kas",
            "https://[::169.254.169.254]/kas",
            "https://[2002:a9fe:a9fe::]/kas",
            "https://[2001:0000:4136:e378:8000:63bf:3fff:fdd2]/kas",
            "https://[64:ff9b::10.0.0.1]/kas",
            "https://[ff02::1]/kas",
            // Userinfo
            "https://user:pass@kas.example.com/kas",
        ]
        for url in blocked {
            XCTAssertThrowsError(try validateKasURL(url), "Expected \(url) to be rejected")
        }
    }

    func testFetchWellKnownEnforcesSSRFNoRawBodyAndSizeBound() async {
        // SSRF URL rejected before hitting URLSession
        do {
            _ = try await fetchWellKnown(platformURL: "https://169.254.169.254")
            XCTFail("Expected invalidURL")
        } catch KASDiscoveryError.invalidURL {} catch {
            XCTFail("Unexpected error: \(error)")
        }

        // Non-2xx must not leak raw server body
        MockURLProtocol.handler = { req in
            let resp = HTTPURLResponse(url: req.url!, statusCode: 500, httpVersion: nil, headerFields: nil)!
            return (resp, Data("INTERNAL-SECRET-STACK-TRACE".utf8))
        }
        do {
            _ = try await fetchWellKnown(platformURL: "https://platform.example.com", urlSession: MockURLProtocol.makeSession())
            XCTFail("Expected httpError")
        } catch let KASDiscoveryError.httpError(code, msg) {
            XCTAssertEqual(code, 500)
            XCTAssertFalse(msg.contains("INTERNAL-SECRET-STACK-TRACE"))
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        // Redirects (302) are refused rather than followed
        MockURLProtocol.handler = { req in
            let resp = HTTPURLResponse(
                url: req.url!,
                statusCode: 302,
                httpVersion: nil,
                headerFields: ["Location": "https://169.254.169.254/latest/meta-data/"],
            )!
            return (resp, Data())
        }
        do {
            _ = try await fetchWellKnown(platformURL: "https://platform.example.com", urlSession: MockURLProtocol.makeSession())
            XCTFail("Expected httpError(302) without following redirect")
        } catch let KASDiscoveryError.httpError(code, _) {
            XCTAssertEqual(code, 302)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        // Oversized well-known response (> 1 MiB) rejected
        MockURLProtocol.handler = { req in
            let resp = HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (resp, Data(repeating: 0x20, count: BoundedHTTPClient.defaultWellKnownMaxBytes + 1024))
        }
        do {
            _ = try await fetchWellKnown(platformURL: "https://platform.example.com", urlSession: MockURLProtocol.makeSession())
            XCTFail("Expected invalidResponse on oversized well-known response")
        } catch KASDiscoveryError.invalidResponse {} catch {
            XCTFail("Unexpected error: \(error)")
        }

        // Oversized transport response rejected
        MockURLProtocol.handler = { req in
            let resp = HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (resp, Data(repeating: 0x41, count: 4096))
        }
        let transport = URLSessionKASTransport(session: MockURLProtocol.makeSession(), maxResponseBytes: 1024)
        do {
            _ = try await transport.send(URLRequest(url: URL(string: "https://kas.example.com/rewrap")!))
            XCTFail("Expected invalidResponse on oversized response")
        } catch KASRewrapError.invalidResponse {} catch {
            XCTFail("Unexpected error: \(error)")
        }

        // Pre-cancelled task must deterministically throw CancellationError without hanging
        MockURLProtocol.handler = { req in
            let resp = HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return (resp, Data("ok".utf8))
        }
        let cancelledTask = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await BoundedHTTPClient.send(
                URLRequest(url: URL(string: "https://kas.example.com/cancelled")!),
                on: MockURLProtocol.makeSession(),
                maxBytes: 1024,
            )
        }
        do {
            _ = try await cancelledTask.value
            XCTFail("Expected cancellation error for pre-cancelled task")
        } catch is CancellationError {
            // Expected
        } catch let urlErr as URLError where urlErr.code == .cancelled {
            // Also acceptable if URLSession completed cancellation first
        } catch {
            XCTFail("Unexpected error for pre-cancelled task: \(error)")
        }
    }

    func testKASServiceRewrapKeyRejectsSSRFURL() async {
        let keyStore = KeyStore(curve: .secp256r1)
        let service = KASService(
            keyStore: keyStore,
            baseURL: URL(string: "https://169.254.169.254")!,
            credential: KASCredential(clientId: "c", token: "secret-bearer"),
        )
        do {
            _ = try await service.rewrapKey(ephemeralPublicKey: Data(count: 33), encryptedSessionKey: Data(count: 44))
            XCTFail("Expected invalidRequest for SSRF baseURL")
        } catch KASServiceError.invalidRequest {} catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    // MARK: - #11: Atomic One-Time Key Enforcement & Deterministic KeyID

    func testProcessKeyAccessWithKeyIdentifierIsAtomicUnderConcurrency() async throws {
        let keyStore = KeyStore(curve: .secp256r1)
        let kasService = KASService(keyStore: keyStore, baseURL: URL(string: "https://kas.example.com")!)
        let kasPair = await keyStore.generateKeyPair()
        await keyStore.store(keyPair: kasPair)

        let clientPriv = P256.KeyAgreement.PrivateKey()
        let kasPriv = try P256.KeyAgreement.PrivateKey(rawRepresentation: kasPair.privateKey)
        let shared = try kasPriv.sharedSecretFromKeyAgreement(with: clientPriv.publicKey)
        let primaryKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: CryptoConstants.hkdfSaltV12,
            sharedInfo: Data(),
            outputByteCount: 32,
        )
        let sealed = try AES.GCM.seal(Data(repeating: 0x42, count: 16), using: primaryKey)
        let encryptedKey = sealed.combined!
        let policyBody = Data(#"{"uuid":"p1"}"#.utf8)
        let validBinding = try CryptoHelper().createGMACBinding(policyBody: policyBody, symmetricKey: primaryKey)
        let invalidBinding = Data(repeating: 0xFF, count: validBinding.count)

        // Malformed request must NOT burn the one-time key
        do {
            _ = try await kasService.processKeyAccessWithKeyIdentifier(
                ephemeralPublicKey: Data(),
                encryptedKey: Data(),
                kasPublicKey: kasPair.publicKey,
                policyBody: policyBody,
                policyBinding: validBinding,
            )
            XCTFail("Expected malformed request to fail")
        } catch {}

        // Tampered policy binding must fail with accessDenied and NOT burn the key
        do {
            _ = try await kasService.processKeyAccessWithKeyIdentifier(
                ephemeralPublicKey: clientPriv.publicKey.compressedRepresentation,
                encryptedKey: encryptedKey,
                kasPublicKey: kasPair.publicKey,
                policyBody: policyBody,
                policyBinding: invalidBinding,
            )
            XCTFail("Expected tampered binding to fail")
        } catch KASServiceError.accessDenied {} catch {
            XCTFail("Expected accessDenied, got \(error)")
        }

        // Launch 8 concurrent rewraps against the same one-time key; exactly 1 must succeed.
        var successes = 0
        var keyIDs: [UUID] = []
        await withTaskGroup(of: Result<(Data, UUID), Error>.self) { group in
            for _ in 0 ..< 8 {
                group.addTask {
                    do {
                        let res = try await kasService.processKeyAccessWithKeyIdentifier(
                            ephemeralPublicKey: clientPriv.publicKey.compressedRepresentation,
                            encryptedKey: encryptedKey,
                            kasPublicKey: kasPair.publicKey,
                            policyBody: policyBody,
                            policyBinding: validBinding,
                        )
                        return .success(res)
                    } catch {
                        return .failure(error)
                    }
                }
            }
            for await result in group {
                if case let .success((_, id)) = result {
                    successes += 1
                    keyIDs.append(id)
                }
            }
        }
        XCTAssertEqual(successes, 1, "One-time key must succeed at most once under concurrency")

        // Re-insert same key and verify deterministic UUID
        await keyStore.store(keyPair: kasPair)
        let (_, secondID) = try await kasService.processKeyAccessWithKeyIdentifier(
            ephemeralPublicKey: clientPriv.publicKey.compressedRepresentation,
            encryptedKey: encryptedKey,
            kasPublicKey: kasPair.publicKey,
            policyBody: policyBody,
            policyBinding: validBinding,
        )
        XCTAssertEqual(keyIDs.first, secondID)

        // Verify processKeyAccess(header:encryptedKey:) works with a parsed v12 header (empty kasPublicKey)
        await keyStore.store(keyPair: kasPair)
        let kasPubKeyObj = try P256.KeyAgreement.PublicKey(compressedRepresentation: kasPair.publicKey)
        let kasRL = try XCTUnwrap(ResourceLocator(protocolEnum: .https, body: "kas.example.com"))
        let kasMeta = try KasMetadata(
            resourceLocator: kasRL,
            publicKey: kasPubKeyObj,
            curve: .secp256r1,
        )
        var policy = Policy(
            type: .embeddedPlaintext,
            body: EmbeddedPolicyBody(body: Data("v12-policy".utf8), keyAccess: nil),
            remote: nil,
            binding: nil,
        )
        let nano = try await createNanoTDF(kas: kasMeta, policy: &policy, plaintext: Data("secret".utf8))
        let parsedHeader = try BinaryParser(data: nano.toData()).parseHeader()
        XCTAssertTrue(parsedHeader.payloadKeyAccess.kasPublicKey.isEmpty)
        let headerKey = try await keyStore.derivePayloadSymmetricKey(header: parsedHeader)
        let headerEncKey = try AES.GCM.seal(Data(repeating: 0x33, count: 16), using: headerKey).combined!
        let rewrapped = try await kasService.processKeyAccess(header: parsedHeader, encryptedKey: headerEncKey)
        XCTAssertFalse(rewrapped.isEmpty)
    }

    // MARK: - #13, #14, #31: TDF Policy Binding, Algorithm/Key Size & JSON/CBOR Hardening

    func testTDFDecryptorVerifiesPolicyBindingAndKeyBitCount() throws {
        let rsa = try TDFSegmentedPayloadTests.makeRSAKeyPair()
        let kasInfo = TDFKasInfo(url: URL(string: "https://kas.example.com/kas")!, publicKeyPEM: rsa.publicKeyPEM, kid: "r1")
        let policy = try TDFPolicy(json: Data(#"{"uuid":"p1","body":{"dataAttributes":[],"dissem":[]}}"#.utf8))
        let config = TDFEncryptionConfiguration(kas: kasInfo, policy: policy, keySize: .bits256)
        let result = try TDFEncryptor().encrypt(plaintext: Data("hello".utf8), configuration: config)

        // Tamper policy string -> policyBindingFailed
        var tamperedManifest = result.container.manifest
        tamperedManifest.encryptionInformation.policy = Data(#"{"uuid":"evil","body":{"dataAttributes":[],"dissem":[]}}"#.utf8).base64EncodedString()
        let tamperedContainer = TDFContainer(manifest: tamperedManifest, payload: result.container.payload)
        XCTAssertThrowsError(try TDFDecryptor().decrypt(container: tamperedContainer, symmetricKey: result.symmetricKey)) { error in
            XCTAssertEqual(error as? TDFDecryptError, .policyBindingFailed)
        }

        // Clearing keyAccess after tampering policy MUST NOT bypass policy binding
        var emptyKAManifest = tamperedManifest
        emptyKAManifest.encryptionInformation.keyAccess = []
        let emptyKAContainer = TDFContainer(manifest: emptyKAManifest, payload: result.container.payload)
        XCTAssertThrowsError(try TDFDecryptor().decrypt(container: emptyKAContainer, symmetricKey: result.symmetricKey)) { error in
            XCTAssertEqual(error as? TDFDecryptError, .policyBindingFailed)
        }

        // Injecting a second KAO with a different sid MUST NOT bypass policy binding on bare-DEK decrypt
        var fakeSplitManifest = tamperedManifest
        var kao1 = fakeSplitManifest.encryptionInformation.keyAccess[0]
        kao1.sid = "split-a"
        var kao2 = kao1
        kao2.sid = "split-b"
        fakeSplitManifest.encryptionInformation.keyAccess = [kao1, kao2]
        let fakeSplitContainer = TDFContainer(manifest: fakeSplitManifest, payload: result.container.payload)
        XCTAssertThrowsError(try TDFDecryptor().decrypt(container: fakeSplitContainer, symmetricKey: result.symmetricKey)) { error in
            XCTAssertEqual(error as? TDFDecryptError, .policyBindingFailed)
        }

        // Legitimate multi-split decryption via decrypt(container:keyShares:) verifies every share's binding
        let share1Data = Data(repeating: 0xAA, count: 32)
        let dekData = TDFCrypto.data(from: result.symmetricKey)
        let share2Data = Data(zip(dekData, share1Data).map { $0 ^ $1 })
        let share1Key = SymmetricKey(data: share1Data)
        let share2Key = SymmetricKey(data: share2Data)
        var realSplitManifest = result.container.manifest
        var splitKAO1 = realSplitManifest.encryptionInformation.keyAccess[0]
        splitKAO1.sid = "s1"
        splitKAO1.policyBinding = TDFCrypto.policyBinding(policy: policy.json, symmetricKey: share1Key)
        var splitKAO2 = splitKAO1
        splitKAO2.sid = "s2"
        splitKAO2.policyBinding = TDFCrypto.policyBinding(policy: policy.json, symmetricKey: share2Key)
        realSplitManifest.encryptionInformation.keyAccess = [splitKAO1, splitKAO2]
        let realSplitContainer = TDFContainer(manifest: realSplitManifest, payload: result.container.payload)
        // Legitimate multi-split decryption via decrypt(container:keyShares:) verifies every share's binding
        // and skips a bad replica share ahead of a valid share for the same split.
        let badReplicaKey = SymmetricKey(data: Data(repeating: 0x01, count: 32))
        let decryptedMulti = try TDFDecryptor().decrypt(
            container: realSplitContainer,
            keyShares: [
                TDFKeyShare(sid: "s1", key: badReplicaKey),
                TDFKeyShare(sid: "s1", key: share1Key),
                TDFKeyShare(sid: "s2", key: share2Key),
            ],
        )
        XCTAssertEqual(decryptedMulti, Data("hello".utf8))

        // Mismatched key size (128-bit key with AES-256-GCM manifest) -> keySizeMismatch
        let key128 = SymmetricKey(size: .bits128)
        XCTAssertThrowsError(try TDFDecryptor().decrypt(container: result.container, symmetricKey: key128)) { error in
            XCTAssertEqual(error as? TDFDecryptError, .keySizeMismatch(expected: 256, actual: 128))
        }
    }

    func testTDFJSONAndCBORDecryptorsVerifyPolicyBindingIntegrityAndRejectSplits() throws {
        let ecKey = P256.KeyAgreement.PrivateKey()
        let policy = try TDFPolicy(json: Data(#"{"uuid":"u","body":{"dataAttributes":[],"dissem":[]}}"#.utf8))

        // TDF-JSON: tamper policy
        let jsonRes = try TDFJSONBuilder()
            .kasURL(URL(string: "https://kas.example.com")!)
            .kasPublicKey(ecKey.publicKey.pemRepresentation)
            .policy(policy)
            .encrypt(plaintext: Data("json secret".utf8))

        var badJSONEncInfo = jsonRes.container.encryptionInformation
        badJSONEncInfo.policy = Data(#"{"uuid":"tampered"}"#.utf8).base64EncodedString()
        let badJSONEnv = TDFJSONEnvelope(
            tdf: "json",
            version: "1.0.0",
            manifest: TDFJSONManifest(encryptionInformation: badJSONEncInfo),
            payload: jsonRes.container.envelope.payload,
        )
        let badJSONContainer = TDFJSONContainer(envelope: badJSONEnv, payloadData: jsonRes.container.payloadData)
        XCTAssertThrowsError(try TDFJSONDecryptor().decrypt(container: badJSONContainer, symmetricKey: jsonRes.symmetricKey)) { error in
            XCTAssertEqual(error as? TDFDecryptError, .policyBindingFailed)
        }
        XCTAssertThrowsError(try TDFJSONDecryptor().decrypt(container: badJSONContainer, privateKeyPEM: ecKey.pemRepresentation)) { error in
            XCTAssertEqual(error as? TDFDecryptError, .policyBindingFailed)
        }

        // TDF-JSON: payload.length mismatch rejected on decodePayloadValue
        var mismatchedPayload = jsonRes.container.envelope.payload
        mismatchedPayload.length = 999
        let mismatchedEnv = TDFJSONEnvelope(
            tdf: "json",
            version: "1.0.0",
            manifest: jsonRes.container.manifest,
            payload: mismatchedPayload,
        )
        XCTAssertThrowsError(try mismatchedEnv.decodePayloadValue()) { error in
            guard case TDFJSONError.payloadDecodeError = error else {
                return XCTFail("Expected payloadDecodeError, got \(error)")
            }
        }

        // TDF-CBOR: tamper integrity root signature
        let cborRes = try TDFCBORBuilder()
            .kasURL(URL(string: "https://kas.example.com")!)
            .kasPublicKey(ecKey.publicKey.pemRepresentation)
            .policy(policy)
            .encrypt(plaintext: Data("cbor secret".utf8))

        var badCBOREncInfo = cborRes.container.encryptionInformation
        badCBOREncInfo.integrityInformation?.rootSignature.sig = Data(count: 32).base64EncodedString()
        let badCBOREnv = TDFCBOREnvelope(
            manifest: TDFCBORManifest(encryptionInformation: badCBOREncInfo),
            payload: cborRes.container.envelope.payload,
        )
        XCTAssertThrowsError(try TDFCBORDecryptor().decrypt(container: TDFCBORContainer(envelope: badCBOREnv), symmetricKey: cborRes.symmetricKey)) { error in
            XCTAssertEqual(error as? TDFDecryptError, .integrityCheckFailed)
        }

        // TDF-CBOR: reject multi-split manifest
        var splitEncInfo = cborRes.container.encryptionInformation
        var kao1 = splitEncInfo.keyAccess[0]
        kao1.sid = "split-1"
        var kao2 = splitEncInfo.keyAccess[0]
        kao2.sid = "split-2"
        splitEncInfo.keyAccess = [kao1, kao2]
        let splitEnv = TDFCBOREnvelope(manifest: TDFCBORManifest(encryptionInformation: splitEncInfo), payload: cborRes.container.envelope.payload)
        XCTAssertThrowsError(try TDFCBORDecryptor().decrypt(container: TDFCBORContainer(envelope: splitEnv), privateKeyPEM: ecKey.pemRepresentation)) { error in
            guard case TDFCBORError.decryptionFailed = error else {
                return XCTFail("Expected decryptionFailed, got \(error)")
            }
        }
    }

    func testECWrapUnwrapSupportsP384AndP521() throws {
        let dek = SymmetricKey(size: .bits256)
        let p384 = P384.KeyAgreement.PrivateKey()
        let wrapped384 = try TDFCrypto.wrapSymmetricKeyWithEC(publicKeyPEM: p384.publicKey.pemRepresentation, symmetricKey: dek, curve: .p384)
        let unwrapped384 = try TDFCrypto.unwrapSymmetricKeyWithEC(
            privateKeyPEM: p384.pemRepresentation,
            wrappedKey: wrapped384.wrappedKey,
            ephemeralPublicKey: wrapped384.ephemeralPublicKey,
        )
        XCTAssertEqual(TDFCrypto.data(from: unwrapped384), TDFCrypto.data(from: dek))

        let p521 = P521.KeyAgreement.PrivateKey()
        let wrapped521 = try TDFCrypto.wrapSymmetricKeyWithEC(publicKeyPEM: p521.publicKey.pemRepresentation, symmetricKey: dek, curve: .p521)
        let unwrapped521 = try TDFCrypto.unwrapSymmetricKeyWithEC(
            privateKeyPEM: p521.pemRepresentation,
            wrappedKey: wrapped521.wrappedKey,
            ephemeralPublicKey: wrapped521.ephemeralPublicKey,
        )
        XCTAssertEqual(TDFCrypto.data(from: unwrapped521), TDFCrypto.data(from: dek))
    }

    // MARK: - #15: StreamingTDFCrypto Integrity & No Premature Plaintext Writes

    func testStreamingMultiSegmentVerifiesHashesAndWritesNoPlaintextOnFailure() throws {
        let key = SymmetricKey(size: .bits256)
        let inputURL = FileManager.default.temporaryDirectory.appendingPathComponent("stream-in-\(UUID().uuidString)")
        let encURL = FileManager.default.temporaryDirectory.appendingPathComponent("stream-enc-\(UUID().uuidString)")
        let outURL = FileManager.default.temporaryDirectory.appendingPathComponent("stream-out-\(UUID().uuidString)")
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: encURL)
            try? FileManager.default.removeItem(at: outURL)
        }

        try Data("segment-one-data|segment-two-data".utf8).write(to: inputURL)
        try Data().write(to: encURL)
        try Data().write(to: outURL)

        let inHandle = try FileHandle(forReadingFrom: inputURL)
        let encHandle = try FileHandle(forWritingTo: encURL)
        let encResult = try StreamingTDFCrypto.encryptPayloadStreamingMultiSegment(
            inputHandle: inHandle,
            outputHandle: encHandle,
            symmetricKey: key,
            segmentSizes: [16, 17],
        )
        try inHandle.close()
        try encHandle.close()

        // Truncating to 1 segment with nil rootSignature must also be rejected
        let seg0OnlyURL = FileManager.default.temporaryDirectory.appendingPathComponent("stream-seg0-\(UUID().uuidString)")
        let encBytesAll = try Data(contentsOf: encURL)
        let firstSegLen = Int(encResult.segments[0].encryptedSize)
        try Data(encBytesAll.prefix(firstSegLen)).write(to: seg0OnlyURL)
        defer { try? FileManager.default.removeItem(at: seg0OnlyURL) }
        let readSeg0 = try FileHandle(forReadingFrom: seg0OnlyURL)
        let outSeg0 = try FileHandle(forWritingTo: outURL)
        XCTAssertThrowsError(try StreamingTDFCrypto.decryptPayloadStreamingMultiSegment(
            inputHandle: readSeg0,
            outputHandle: outSeg0,
            segments: [encResult.segments[0]],
            symmetricKey: key,
            rootSignature: nil,
        ))
        try readSeg0.close()
        try outSeg0.close()

        // Missing rootSignature on multi-segment payload must be rejected
        let readEncMissingRoot = try FileHandle(forReadingFrom: encURL)
        let outHandleMissingRoot = try FileHandle(forWritingTo: outURL)
        XCTAssertThrowsError(try StreamingTDFCrypto.decryptPayloadStreamingMultiSegment(
            inputHandle: readEncMissingRoot,
            outputHandle: outHandleMissingRoot,
            segments: encResult.segments,
            symmetricKey: key,
            rootSignature: nil,
        ))
        try readEncMissingRoot.close()
        try outHandleMissingRoot.close()

        // Reordered segments + matching swapped payload bytes must be rejected by rootSignature
        let encBytes = try Data(contentsOf: encURL)
        let seg0Len = Int(encResult.segments[0].encryptedSize)
        let swappedBytes = encBytes.dropFirst(seg0Len) + encBytes.prefix(seg0Len)
        let swappedURL = FileManager.default.temporaryDirectory.appendingPathComponent("stream-swap-\(UUID().uuidString)")
        try Data(swappedBytes).write(to: swappedURL)
        defer { try? FileManager.default.removeItem(at: swappedURL) }
        let readSwapped = try FileHandle(forReadingFrom: swappedURL)
        let outHandleSwapped = try FileHandle(forWritingTo: outURL)
        XCTAssertThrowsError(try StreamingTDFCrypto.decryptPayloadStreamingMultiSegment(
            inputHandle: readSwapped,
            outputHandle: outHandleSwapped,
            segments: [encResult.segments[1], encResult.segments[0]],
            symmetricKey: key,
            rootSignature: encResult.rootSignature,
        ))
        try readSwapped.close()
        try outHandleSwapped.close()

        // Corrupt segment 1's expected hash while leaving segment 0 valid
        var tamperedSegments = encResult.segments
        tamperedSegments[1] = StreamingTDFCrypto.EncryptedSegment(
            segmentIndex: 1,
            plaintextSize: tamperedSegments[1].plaintextSize,
            encryptedSize: tamperedSegments[1].encryptedSize,
            hash: Data(repeating: 0x00, count: 16).base64EncodedString(),
        )

        let readEnc = try FileHandle(forReadingFrom: encURL)
        let outHandle = try FileHandle(forWritingTo: outURL)
        XCTAssertThrowsError(try StreamingTDFCrypto.decryptPayloadStreamingMultiSegment(
            inputHandle: readEnc,
            outputHandle: outHandle,
            segments: tamperedSegments,
            symmetricKey: key,
            rootSignature: encResult.rootSignature,
        ))
        try readEnc.close()
        try outHandle.close()

        // Output file MUST remain empty (no unverified segment 0 plaintext leaked)
        let written = try Data(contentsOf: outURL)
        XCTAssertTrue(written.isEmpty, "No plaintext should be written to outputHandle when a later segment fails")

        // Valid multi-segment round-trip with rootSignature succeeds
        let readValid = try FileHandle(forReadingFrom: encURL)
        let outValid = try FileHandle(forWritingTo: outURL)
        try StreamingTDFCrypto.decryptPayloadStreamingMultiSegment(
            inputHandle: readValid,
            outputHandle: outValid,
            segments: encResult.segments,
            symmetricKey: key,
            rootSignature: encResult.rootSignature,
        )
        try readValid.close()
        try outValid.close()
        XCTAssertEqual(try Data(contentsOf: outURL), Data("segment-one-data|segment-two-data".utf8))

        // HS256 segment hash verification succeeds when valid and rejects GMAC-tag substitution
        let seg0Bytes = Data(encBytes.prefix(seg0Len))
        let seg1Bytes = Data(encBytes.dropFirst(seg0Len))
        let hs0 = Data(HMAC<SHA256>.authenticationCode(for: seg0Bytes, using: key))
        let hs1 = Data(HMAC<SHA256>.authenticationCode(for: seg1Bytes, using: key))
        let hsRoot = Data(HMAC<SHA256>.authenticationCode(for: hs0 + hs1, using: key)).base64EncodedString()
        let hsSegments = [
            StreamingTDFCrypto.EncryptedSegment(segmentIndex: 0, plaintextSize: 16, encryptedSize: Int64(seg0Bytes.count), hash: hs0.base64EncodedString()),
            StreamingTDFCrypto.EncryptedSegment(segmentIndex: 1, plaintextSize: 17, encryptedSize: Int64(seg1Bytes.count), hash: hs1.base64EncodedString()),
        ]
        let hsDecrypted = try StreamingTDFCrypto.decryptPayloadMultiSegmentFromMemory(
            encryptedPayload: encBytes,
            segments: hsSegments,
            symmetricKey: key,
            rootSignature: hsRoot,
            segmentHashAlg: "HS256",
        )
        XCTAssertEqual(hsDecrypted, Data("segment-one-data|segment-two-data".utf8))
    }

    // MARK: - #16: ZIP Archive Caps & TDFLoader Default vs Explicit nil

    func testArchiveReaderWritePayloadEnforcesMaxSize() throws {
        XCTAssertEqual(TDFLoader().maxPayloadSize, TDFArchiveReader.defaultPayloadMaxSize)
        XCTAssertNil(TDFLoader(maxPayloadSize: nil).maxPayloadSize)

        let manifest = TDFManifest(
            schemaVersion: "4.3.0",
            payload: TDFPayloadDescriptor(type: .reference, url: "0.payload", protocolValue: .zip, isEncrypted: true),
            encryptionInformation: TDFEncryptionInformation(
                type: .split,
                keyAccess: [],
                method: TDFMethodDescriptor(algorithm: "AES-256-GCM", iv: ""),
                policy: "e30=",
            ),
        )
        let archiveData = try TDFArchiveWriter().buildArchive(manifest: manifest, payload: Data(repeating: 0x42, count: 1024))
        let reader = try TDFArchiveReader(data: archiveData)

        let outURL = FileManager.default.temporaryDirectory.appendingPathComponent("zip-out-\(UUID().uuidString)")
        try Data().write(to: outURL)
        defer { try? FileManager.default.removeItem(at: outURL) }
        let handle = try FileHandle(forWritingTo: outURL)
        defer { try? handle.close() }

        XCTAssertThrowsError(try reader.writePayload(to: handle, maxSize: 100)) { error in
            XCTAssertEqual(error as? TDFArchiveError, .payloadTooLarge)
        }
    }

    // MARK: - #17, #19, #29: CBOR Hardening, Slices & Round-Trip Fidelity

    func testCBORRejectsDeepNestingHugeReadNAndHandlesSlicesAndOptionalFields() throws {
        // #19: hasMagicBytes on Data slice with startIndex > 0
        let cborSlice = Data([0x00, 0x01, 0xD9, 0xD9, 0xF7, 0xA0]).dropFirst(2)
        XCTAssertGreaterThan(cborSlice.startIndex, 0)
        XCTAssertTrue(TDFCBOREnvelope.hasMagicBytes(cborSlice))

        // #17: Deeply nested single-element CBOR array (depth 100 and 10_000) inside a map root
        // must trigger the depth limit specifically (not "Expected CBOR map at root").
        for depth in [100, 10000] {
            var deeplyNested = Data(TDF_CBOR_MAGIC)
            deeplyNested.append(0xA1) // 1-entry map
            deeplyNested.append(0x18)
            deeplyNested.append(0x63) // key 99
            deeplyNested.append(contentsOf: [UInt8](repeating: 0x81, count: depth))
            deeplyNested.append(0x00)
            XCTAssertThrowsError(try TDFCBOREnvelope.fromCBORData(deeplyNested)) { error in
                guard case let TDFCBORError.cborDecodingFailed(msg) = error else {
                    return XCTFail("Expected cborDecodingFailed, got \(error)")
                }
                XCTAssertTrue(msg.contains("nesting depth"), "Expected depth-limit failure, got: \(msg)")
            }
        }

        // #17: Indefinite byte-string and text-string chunk amplification (> maxItems) rejected
        for (indefHeader, emptyChunk): (UInt8, UInt8) in [(0x5F, 0x40), (0x7F, 0x60)] {
            var chunkBomb = Data(TDF_CBOR_MAGIC)
            chunkBomb.append(0xA1)
            chunkBomb.append(0x01)
            chunkBomb.append(indefHeader)
            chunkBomb.append(contentsOf: [UInt8](repeating: emptyChunk, count: 105_000))
            chunkBomb.append(0xFF)
            XCTAssertThrowsError(try TDFCBOREnvelope.fromCBORData(chunkBomb)) { error in
                guard case let TDFCBORError.cborDecodingFailed(msg) = error else {
                    return XCTFail("Expected cborDecodingFailed, got \(error)")
                }
                XCTAssertTrue(msg.contains("item count"), "Expected item-count failure, got: \(msg)")
            }
        }

        // #17: Crafted huge byte string length (0x5B + UInt64.max) rejected before SwiftCBOR allocates
        let hugeBstr = Data(TDF_CBOR_MAGIC + [0x5B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        XCTAssertThrowsError(try TDFCBOREnvelope.fromCBORData(hugeBstr)) { error in
            guard case TDFCBORError.cborDecodingFailed = error else {
                return XCTFail("Expected cborDecodingFailed, got \(error)")
            }
        }

        // #29: PEM ephemeralPublicKey, sid, encryptedMetadata preserved; nil encryptedSegmentSizeDefault stays nil
        let pem = P256.KeyAgreement.PrivateKey().publicKey.pemRepresentation
        let kao = TDFKeyAccessObject(
            type: .ecWrapped,
            url: "https://kas.example.com",
            protocolValue: .kas,
            wrappedKey: Data(repeating: 1, count: 32).base64EncodedString(),
            policyBinding: TDFPolicyBinding(alg: "HS256", hash: Data(repeating: 2, count: 32).base64EncodedString()),
            encryptedMetadata: Data("meta".utf8).base64EncodedString(),
            kid: "k1",
            sid: "split-alpha",
            schemaVersion: "1.0",
            ephemeralPublicKey: pem,
        )
        let integrity = TDFIntegrityInformation(
            rootSignature: TDFRootSignature(alg: "HS256", sig: Data(repeating: 3, count: 32).base64EncodedString()),
            segmentHashAlg: "GMAC",
            segmentSizeDefault: 1024,
            encryptedSegmentSizeDefault: nil,
            segments: [TDFSegment(hash: Data(repeating: 4, count: 16).base64EncodedString(), segmentSize: 10)],
        )
        let env = TDFCBOREnvelope(
            manifest: TDFCBORManifest(
                encryptionInformation: TDFEncryptionInformation(
                    type: .split,
                    keyAccess: [kao],
                    method: TDFMethodDescriptor(algorithm: "AES-256-GCM", iv: Data(count: 12).base64EncodedString()),
                    integrityInformation: integrity,
                    policy: Data("{}".utf8).base64EncodedString(),
                ),
            ),
            payload: TDFBinaryPayload(value: Data(repeating: 5, count: 38)),
        )
        let encoded = try env.toCBORData()
        let decoded = try TDFCBOREnvelope.fromCBORData(encoded)
        let decodedKAO = try XCTUnwrap(decoded.manifest.encryptionInformation.keyAccess.first)
        XCTAssertEqual(decodedKAO.ephemeralPublicKey, pem)
        XCTAssertEqual(decodedKAO.sid, "split-alpha")
        XCTAssertEqual(decodedKAO.encryptedMetadata, Data("meta".utf8).base64EncodedString())
        XCTAssertNil(decoded.manifest.encryptionInformation.integrityInformation?.encryptedSegmentSizeDefault)
    }

    // MARK: - #20: Constant-Time Truncated GCM Tags Match 128-Bit Prefix

    func testTruncatedGCMModesMatchCryptoKitTagPrefixAndRejectTampering() throws {
        let key = SymmetricKey(size: .bits256)
        let iv = Data([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
        let plaintext = Data("constant-time truncated GCM test payload".utf8)
        let full = try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(data: iv))

        for cipher in [Cipher.aes256GCM64, .aes256GCM96, .aes256GCM104, .aes256GCM112, .aes256GCM120] {
            let (ct, tag) = try CryptoHelper.encryptNanoTDF(cipher: cipher, key: key, iv: iv, plaintext: plaintext)
            XCTAssertEqual(ct, full.ciphertext)
            XCTAssertEqual(tag, Data(full.tag.prefix(cipher.tagSize)))

            let opened = try CryptoHelper.decryptNanoTDF(cipher: cipher, key: key, iv: iv, ciphertext: ct, tag: tag)
            XCTAssertEqual(opened, plaintext)

            var badTag = tag
            badTag[badTag.count - 1] ^= 0x01
            XCTAssertThrowsError(try CryptoHelper.decryptNanoTDF(cipher: cipher, key: key, iv: iv, ciphertext: ct, tag: badTag))
        }
    }

    // MARK: - #21, #22, #33: Length Safety, Strict BinaryParser, SharedResourceDirectory

    func testEmbeddedPolicyLengthAndBinaryParserStrictnessAndSharedResourceDirectory() throws {
        // #21: EmbeddedPolicyBody > 65535 throws on serializedData and does not trap on toData
        let hugePolicy = EmbeddedPolicyBody(body: Data(count: 70000))
        XCTAssertThrowsError(try hugePolicy.serializedData()) { error in
            XCTAssertEqual(error as? NanoTDFError, .policyTooLarge(70000))
        }
        let clamped = hugePolicy.toData()
        XCTAssertEqual(clamped.count, 2 + Int(UInt16.max))

        let oversizedPayload = Payload(length: 0x0100_0000, iv: Data(count: 3), ciphertext: Data(), mac: Data(count: 16))
        XCTAssertThrowsError(try oversizedPayload.serializedData()) { error in
            XCTAssertEqual(error as? NanoTDFError, .payloadTooLarge(0x0100_0000))
        }
        let mismatchedPayload = Payload(length: 99, iv: Data(count: 3), ciphertext: Data([1, 2]), mac: Data(count: 16))
        XCTAssertThrowsError(try mismatchedPayload.serializedData()) { error in
            XCTAssertEqual(error as? NanoTDFError, .payloadLengthMismatch(declared: 99, actual: 21))
        }

        // #22: Unknown identifierType (e.g., 0x40 | 0x01 = 0x41) rejected
        var badIdData = Data()
        badIdData.append(Header.magicNumber)
        badIdData.append(Header.versionV12)
        badIdData.append(0x41) // identifierType = 4 (invalid), protocol = https
        badIdData.append(3)
        badIdData.append(Data("kas".utf8))
        XCTAssertThrowsError(try BinaryParser(data: badIdData).parseHeader())

        // #33: sharedResourceDirectory (0xFF -> 0x0F) round-trips through BinaryParser
        let srd = try XCTUnwrap(ResourceLocator(protocolEnum: .sharedResourceDirectory, body: "shared/dir"))
        let header = Header(
            kas: srd,
            policyBindingConfig: PolicyBindingConfig(ecdsaBinding: false, curve: .secp256r1),
            payloadSignatureConfig: SignatureAndPayloadConfig(signed: false, signatureCurve: nil, payloadCipher: .aes256GCM128),
            policy: Policy(type: .remote, body: nil, remote: srd, binding: Data(count: 8)),
            ephemeralPublicKey: Data(count: 33),
        )
        let parsed = try BinaryParser(data: header.toData()).parseHeader()
        XCTAssertEqual(parsed.kas.protocolEnum, .sharedResourceDirectory)
        XCTAssertEqual(parsed.kas.body, "shared/dir")
    }

    // MARK: - #23 & #32: KeyStore totalBytesStored & PublicKeyStore Atomic Deserialize

    func testKeyStoreTotalBytesStoredAndPublicKeyStoreAtomicDeserialize() async throws {
        let store = KeyStore(curve: .secp256r1)
        let pair = await store.generateKeyPair()
        await store.store(keyPair: pair)
        await store.store(keyPair: pair) // overwrite must not double-count
        let expectedSingle = Curve.secp256r1.publicKeyLength + Curve.secp256r1.privateKeyLength
        let bytesAfterOverwrite = await store.totalBytesStored
        XCTAssertEqual(bytesAfterOverwrite, expectedSingle)

        let serialized = await store.serialize()
        let restored = KeyStore(curve: .secp256r1)
        try await restored.deserialize(from: serialized)
        let restoredBytes = await restored.totalBytesStored
        XCTAssertEqual(restoredBytes, expectedSingle)

        try await restored.removeKeyPair(keyID: KeyPairIdentifier(publicKey: pair.publicKey))
        let afterRemoveBytes = await restored.totalBytesStored
        XCTAssertEqual(afterRemoveBytes, 0)

        // #23: PublicKeyStore preserves existing keys if deserialize fails
        let pubStore = PublicKeyStore(curve: .secp256r1)
        await pubStore.addPublicKey(pair.publicKey)
        do {
            try await pubStore.deserialize(from: Data([0x00, 0x00, 0x00, 0x00, 0x05])) // truncated
            XCTFail("Expected invalidData")
        } catch {}
        let keysAfterFailedDeserialize = await pubStore.publicKeys
        XCTAssertEqual(keysAfterFailedDeserialize, [pair.publicKey])
    }

    // MARK: - #25: Numeric KAO Ordering & Unknown KAO ID Rejection

    func testRewrapAndUnwrapTDFSharesSortsNumericallyAndRejectsUnknownKAOIDs() async throws {
        let dek = SymmetricKey(size: .bits256)
        let entries = (0 ..< 12).map { i in
            TDFKeyAccessObject(
                type: .ecWrapped,
                url: "https://kas.example.com/kas",
                protocolValue: .kas,
                wrappedKey: Data(repeating: UInt8(i), count: 32).base64EncodedString(),
                policyBinding: TDFPolicyBinding(alg: "HS256", hash: "b"),
                kid: "k",
                sid: "split-\(i)",
            )
        }
        let manifest = TDFManifest(
            schemaVersion: "4.3.0",
            payload: TDFPayloadDescriptor(type: .reference, url: "0.payload", protocolValue: .zip, isEncrypted: true),
            encryptionInformation: TDFEncryptionInformation(
                type: .split,
                keyAccess: entries,
                method: TDFMethodDescriptor(algorithm: "AES-256-GCM", iv: ""),
                policy: Data("{}".utf8).base64EncodedString(),
            ),
        )

        MockURLProtocol.handler = { req in
            let body = try XCTUnwrap(Self.readHTTPBody(req))
            let outer = try XCTUnwrap(try JSONSerialization.jsonObject(with: body) as? [String: Any])
            let jwt = try XCTUnwrap(outer["signed_request_token"] as? String)
            let parts = jwt.split(separator: ".")
            let claims = try XCTUnwrap(try JSONSerialization.jsonObject(with: XCTUnwrap(Data(base64URLEncoded: parts[1]))) as? [String: Any])
            let unsigned = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(XCTUnwrap(claims["requestBody"] as? String).utf8)) as? [String: Any])
            let clientPub = try P256.KeyAgreement.PublicKey(pemRepresentation: XCTUnwrap(unsigned["clientPublicKey"] as? String))

            let sessionKey = P256.KeyAgreement.PrivateKey()
            let kek = try sessionKey.sharedSecretFromKeyAgreement(with: clientPub).hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: KASRewrapClient.standardTDFSessionSalt,
                sharedInfo: Data(),
                outputByteCount: 32,
            )
            // Return results in reverse order
            let results: [[String: Any]] = try (0 ..< 12).reversed().map { i in
                let sealed = try dek.withUnsafeBytes { try AES.GCM.seal($0, using: kek) }
                return [
                    "keyAccessObjectId": "kao-\(i)",
                    "status": "permit",
                    "kasWrappedKey": sealed.combined!.base64EncodedString(),
                ]
            }
            let payload: [String: Any] = [
                "responses": [["policyId": "policy", "results": results]],
                "sessionPublicKey": sessionKey.publicKey.pemRepresentation,
            ]
            let resp = HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return try (resp, JSONSerialization.data(withJSONObject: payload))
        }

        let client = try KASRewrapClient(
            configuration: OpenTDFConfiguration.forKasConnect("https://kas.example.com"),
            oauthToken: "t",
            urlSession: MockURLProtocol.makeSession(),
        )
        let shares = try await client.rewrapAndUnwrapTDFShares(manifest: manifest)
        // Must be sorted numerically: split-0, split-1, split-2, ..., split-10, split-11 (not split-10 before split-2)
        XCTAssertEqual(shares.map(\.sid), (0 ..< 12).map { "split-\($0)" })

        // Foreign KAO ID in rewrapTDF must be rejected
        MockURLProtocol.handler = { req in
            let payload: [String: Any] = [
                "responses": [[
                    "policyId": "policy",
                    "results": [[
                        "keyAccessObjectId": "kao-999",
                        "status": "permit",
                        "kasWrappedKey": Data(repeating: 1, count: 44).base64EncodedString(),
                    ]],
                ]],
                "sessionPublicKey": P256.KeyAgreement.PrivateKey().publicKey.pemRepresentation,
            ]
            let resp = HTTPURLResponse(url: req.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            return try (resp, JSONSerialization.data(withJSONObject: payload))
        }
        do {
            _ = try await client.rewrapTDF(manifest: manifest, clientPrivateKey: P256.KeyAgreement.PrivateKey())
            XCTFail("Expected invalidResponse for foreign KAO ID")
        } catch KASRewrapError.invalidResponse {}
    }

    // MARK: - #27 & #38: TDFFormatDetector CBOR & Bounded File Read

    func testFormatDetectorDetectsCBORWithDetailsAndBoundsJSONFiles() throws {
        let cborBytes = Data([0xD9, 0xD9, 0xF7, 0xA1, 0x01, 0x64, 0x63, 0x62, 0x6F, 0x72])
        let details = TDFFormatDetector.detectWithDetails(from: cborBytes)
        XCTAssertEqual(details?.format, .cbor)
        XCTAssertEqual(details?.confidence, .definitive)
        XCTAssertEqual(details?.method, .magicBytes)

        // Large file starting with '{' beyond maxJSONDetectionSize returns nil cleanly
        let largeURL = FileManager.default.temporaryDirectory.appendingPathComponent("huge-\(UUID().uuidString).tdf")
        defer { try? FileManager.default.removeItem(at: largeURL) }
        FileManager.default.createFile(atPath: largeURL.path, contents: Data("{".utf8))
        let handle = try FileHandle(forUpdating: largeURL)
        try handle.truncate(atOffset: UInt64(TDFFormatDetector.maxJSONDetectionSize + 1024))
        try handle.close()
        XCTAssertNil(TDFFormatDetector.detect(from: largeURL))
    }

    // MARK: - #30: Overflow-Safe SegmentSize in TDFEncryptor

    func testEncryptRejectsOverflowingSegmentSizeWithoutTrapping() throws {
        let rsa = try TDFSegmentedPayloadTests.makeRSAKeyPair()
        let kasInfo = TDFKasInfo(url: URL(string: "https://kas.example.com/kas")!, publicKeyPEM: rsa.publicKeyPEM, kid: "r1")
        let policy = try TDFPolicy(json: Data(#"{"uuid":"u","body":{"dataAttributes":[],"dissem":[]}}"#.utf8))
        let config = TDFEncryptionConfiguration(kas: kasInfo, policy: policy)

        XCTAssertThrowsError(try TDFEncryptor().encrypt(
            plaintext: Data("hello".utf8),
            configuration: config,
            segmentSize: Int.max,
        ))
        let ok = try TDFEncryptor().encrypt(
            plaintext: Data("hello".utf8),
            configuration: config,
            segmentSize: Int.max - 28,
        )
        XCTAssertEqual(try TDFDecryptor().decrypt(container: ok.container, symmetricKey: ok.symmetricKey), Data("hello".utf8))
    }

    // MARK: - #35: KASBulkRewrap Rejects Zero-Byte DEK

    func testBulkRewrapRejectsZeroByteDEK() async throws {
        let sessionPriv = P256.KeyAgreement.PrivateKey()
        let transport = ZeroByteDEKTransport(sessionKey: sessionPriv)
        let client = try KASRewrapClient(
            configuration: OpenTDFConfiguration.forKasConnect("https://kas.example.com"),
            oauthToken: "t",
            transport: transport,
        )
        let manifest = TDFManifest(
            schemaVersion: "4.3.0",
            payload: TDFPayloadDescriptor(type: .reference, url: "0.payload", protocolValue: .zip, isEncrypted: true),
            encryptionInformation: TDFEncryptionInformation(
                type: .split,
                keyAccess: [TDFKeyAccessObject(
                    type: .ecWrapped,
                    url: "https://kas.example.com/kas",
                    protocolValue: .kas,
                    wrappedKey: Data(repeating: 1, count: 32).base64EncodedString(),
                    policyBinding: TDFPolicyBinding(alg: "HS256", hash: "b"),
                    kid: "k",
                    ephemeralPublicKey: P256.KeyAgreement.PrivateKey().publicKey.pemRepresentation,
                )],
                method: TDFMethodDescriptor(algorithm: "AES-256-GCM", iv: ""),
                policy: Data("{}".utf8).base64EncodedString(),
            ),
        )
        let outcomes = try await client.rewrapAndUnwrapTDFs([manifest])
        XCTAssertEqual(outcomes.count, 1)
        guard case .failed(.unwrapFailed) = outcomes[0] else {
            return XCTFail("Expected .failed(.unwrapFailed) for 0-byte DEK, got \(outcomes[0])")
        }
    }

    // MARK: - Helpers

    private static func readHTTPBody(_ request: URLRequest) -> Data? {
        if let body = request.httpBody {
            return body
        }
        guard let stream = request.httpBodyStream else { return nil }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buf = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let n = stream.read(&buf, maxLength: buf.count)
            if n <= 0 {
                break
            }
            data.append(buf, count: n)
        }
        return data
    }
}

private actor ZeroByteDEKTransport: KASRewrapTransport {
    let sessionKey: P256.KeyAgreement.PrivateKey
    init(sessionKey: P256.KeyAgreement.PrivateKey) {
        self.sessionKey = sessionKey
    }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let body = request.httpBody ?? Data()
        let outer = try XCTUnwrap(try JSONSerialization.jsonObject(with: body) as? [String: Any])
        let jwt = try XCTUnwrap(outer["signed_request_token"] as? String)
        let parts = jwt.split(separator: ".")
        let claims = try XCTUnwrap(try JSONSerialization.jsonObject(with: XCTUnwrap(Data(base64URLEncoded: parts[1]))) as? [String: Any])
        let unsigned = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(XCTUnwrap(claims["requestBody"] as? String).utf8)) as? [String: Any])
        let clientPub = try P256.KeyAgreement.PublicKey(pemRepresentation: XCTUnwrap(unsigned["clientPublicKey"] as? String))

        let kek = try sessionKey.sharedSecretFromKeyAgreement(with: clientPub).hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: KASRewrapClient.standardTDFSessionSalt,
            sharedInfo: Data(),
            outputByteCount: 32,
        )
        // Seal empty 0-byte DEK (produces 28-byte combined box: 12 nonce + 0 ct + 16 tag)
        let sealed = try AES.GCM.seal(Data(), using: kek)
        let json: [String: Any] = [
            "responses": [[
                "policyId": "policy-0",
                "results": [[
                    "keyAccessObjectId": "kao-0",
                    "status": "permit",
                    "kasWrappedKey": sealed.combined!.base64EncodedString(),
                ]],
            ]],
            "sessionPublicKey": sessionKey.publicKey.pemRepresentation,
        ]
        let resp = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
        return try (JSONSerialization.data(withJSONObject: json), resp)
    }
}
