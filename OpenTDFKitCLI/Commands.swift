import CryptoKit
import Darwin
import Foundation
import OpenTDFKit

extension Data {
    func hexEncodedString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}

struct CLIConfig {
    let kasURL: String
    let platformURL: String
    let clientID: String
    let clientSecret: String
    let withECDSABinding: Bool
    let withPlaintextPolicy: Bool

    static func fromEnvironment() throws -> CLIConfig {
        guard let kasURL = ProcessInfo.processInfo.environment["KASURL"] else {
            throw CLIConfigError.missingEnvironmentVariable("KASURL")
        }
        guard let platformURL = ProcessInfo.processInfo.environment["PLATFORMURL"] else {
            throw CLIConfigError.missingEnvironmentVariable("PLATFORMURL")
        }
        guard let clientID = ProcessInfo.processInfo.environment["CLIENTID"] else {
            throw CLIConfigError.missingEnvironmentVariable("CLIENTID")
        }
        guard let clientSecret = ProcessInfo.processInfo.environment["CLIENTSECRET"] else {
            throw CLIConfigError.missingEnvironmentVariable("CLIENTSECRET")
        }

        return CLIConfig(
            kasURL: kasURL,
            platformURL: platformURL,
            clientID: clientID,
            clientSecret: clientSecret,
            withECDSABinding: ProcessInfo.processInfo.environment["XT_WITH_ECDSA_BINDING"] == "true",
            withPlaintextPolicy: ProcessInfo.processInfo.environment["XT_WITH_PLAINTEXT_POLICY"] == "true",
        )
    }
}

enum CLIConfigError: Error, CustomStringConvertible {
    case missingEnvironmentVariable(String)

    var description: String {
        switch self {
        case let .missingEnvironmentVariable(name):
            "Required environment variable '\(name)' is not set. Please export it before running."
        }
    }
}

enum Commands {
    /// Quick signature check to route files to the appropriate parser.
    static func isLikelyStandardTDF(data: Data) -> Bool {
        data.starts(with: [0x50, 0x4B])
    }

    static func resolveOAuthToken(providedToken: String?, tokenPath: String) throws -> String {
        if let providedToken, !providedToken.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return providedToken.trimmingCharacters(in: .whitespacesAndNewlines)
        }

        let tokenURL = URL(fileURLWithPath: tokenPath)
        guard FileManager.default.fileExists(atPath: tokenURL.path) else {
            throw DecryptError.missingOAuthToken
        }

        let tokenData = try Data(contentsOf: tokenURL)
        let oauthToken = String(data: tokenData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        guard !oauthToken.isEmpty else {
            throw DecryptError.missingOAuthToken
        }

        return oauthToken
    }

    /// Parse and report details about a ZIP-based TDF container.
    static func verifyStandardTDF(data: Data, filename: String) throws {
        print("Standard TDF Verification Report")
        print("================================")
        print("File: \(filename)")
        print("Size: \(data.count) bytes\n")

        let loader = StandardTDFLoader()
        let container = try loader.load(from: data)
        let manifest = container.manifest

        print("✓ Manifest parsed successfully")
        print("  Spec Version: \(manifest.schemaVersion)")
        print("  Payload URL: \(manifest.payload.url)")
        print("  Payload Protocol: \(manifest.payload.protocolValue.rawValue)")
        print("  Encrypted: \(manifest.payload.isEncrypted)")

        let enc = manifest.encryptionInformation
        print("\nEncryption Information:")
        print("  Type: \(enc.type.rawValue)")
        print("  Key Access Objects: \(enc.keyAccess.count)")
        print("  Symmetric Algorithm: \(enc.method.algorithm)")

        let integrity = enc.integrityInformation
        print("\nIntegrity Information:")
        print("  Segment Hash Alg: \(integrity.segmentHashAlg)")
        print("  Default Segment Size: \(integrity.segmentSizeDefault)")
        print("  Segments: \(integrity.segments.count)")

        if let assertions = manifest.assertions {
            print("\nAssertions: \(assertions.count)")
        }

        print("\n✓ Standard TDF structure validated")
    }

    /// Load a ZIP-based TDF container without decrypting payload contents.
    static func decryptStandardTDF(
        data: Data,
        filename: String,
        symmetricKey: SymmetricKey?,
        privateKeyPEM: String?,
        clientPublicKeyPEM: String?,
        oauthToken: String?,
    ) async throws -> Data {
        print("Standard TDF Decryption")
        print("========================")
        print("File: \(filename)")
        print("Size: \(data.count) bytes\n")

        let loader = StandardTDFLoader()
        let container = try loader.load(from: data)

        print("✓ Manifest loaded")
        print("  Spec Version: \(container.manifest.schemaVersion)")
        print("  Key Access Entries: \(container.manifest.encryptionInformation.keyAccess.count)")

        let decryptor = StandardTDFDecryptor()

        if let symmetricKey {
            print("  Using provided symmetric key for decryption")
            return try decryptor.decrypt(container: container, symmetricKey: symmetricKey)
        }

        guard let privateKeyPEM else {
            throw DecryptError.missingSymmetricMaterial
        }

        guard let clientPublicKeyPEM, !clientPublicKeyPEM.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw DecryptError.missingSymmetricMaterial
        }

        guard let oauthToken, !oauthToken.isEmpty else {
            throw DecryptError.missingOAuthToken
        }

        print("  Requesting rewrap from KAS")

        var aggregatedWrappedKeys: [String: Data] = [:]
        let uniqueKasURLs = Set(container.manifest.encryptionInformation.keyAccess.map(\.url))

        for kasURLString in uniqueKasURLs {
            guard let kasURL = URL(string: kasURLString) else {
                continue
            }

            let client = KASRewrapClient(kasURL: kasURL, oauthToken: oauthToken)
            let result = try await client.rewrapStandardTDF(
                manifest: container.manifest,
                clientPublicKeyPEM: clientPublicKeyPEM,
            )

            for (kaoIdentifier, wrappedKey) in result.wrappedKeys {
                aggregatedWrappedKeys[kaoIdentifier] = wrappedKey
            }
        }

        guard !aggregatedWrappedKeys.isEmpty else {
            throw DecryptError.missingWrappedKey
        }

        var combinedKeyData: Data?
        let sortedEntries = aggregatedWrappedKeys.sorted { $0.key < $1.key }

        for (_, wrappedKeyData) in sortedEntries {
            let base64 = wrappedKeyData.base64EncodedString()
            let symmetricKeyPart = try StandardTDFCrypto.unwrapSymmetricKeyWithRSA(
                privateKeyPEM: privateKeyPEM,
                wrappedKey: base64,
            )
            let keyData = StandardTDFCrypto.data(from: symmetricKeyPart)

            if let existing = combinedKeyData {
                guard existing.count == keyData.count else {
                    throw DecryptError.invalidWrappedKeyFormat
                }
                combinedKeyData = xorKeyData(existing, keyData)
            } else {
                combinedKeyData = keyData
            }
        }

        guard let finalKeyData = combinedKeyData else {
            throw DecryptError.missingSymmetricMaterial
        }

        let finalSymmetricKey = SymmetricKey(data: finalKeyData)
        return try decryptor.decrypt(container: container, symmetricKey: finalSymmetricKey)
    }

    private static func xorKeyData(_ lhs: Data, _ rhs: Data) -> Data {
        precondition(lhs.count == rhs.count, "Key share lengths must match")
        var result = Data(count: lhs.count)
        result.withUnsafeMutableBytes { resPtr in
            lhs.withUnsafeBytes { lhsPtr in
                rhs.withUnsafeBytes { rhsPtr in
                    guard let resBytes = resPtr.bindMemory(to: UInt8.self).baseAddress,
                          let lhsBytes = lhsPtr.bindMemory(to: UInt8.self).baseAddress,
                          let rhsBytes = rhsPtr.bindMemory(to: UInt8.self).baseAddress
                    else {
                        return
                    }
                    for index in 0 ..< lhs.count {
                        resBytes[index] = lhsBytes[index] ^ rhsBytes[index]
                    }
                }
            }
        }
        return result
    }

    /// Encrypt plaintext to NanoTDF v1.2 format (L1L) using OpenTDFKit's NanoTDF API
    static func encryptNanoTDF(plaintext: Data, useECDSA: Bool) async throws -> Data {
        print("NanoTDF Encryption")
        print("==================")
        print("Plaintext size: \(plaintext.count) bytes")
        print("ECDSA binding: \(useECDSA)")

        // Get configuration from environment
        let config = try CLIConfig.fromEnvironment()

        // Parse KAS URL
        guard let kasURL = URL(string: config.kasURL),
              let kasHost = kasURL.host
        else {
            throw EncryptError.invalidKASURL
        }

        let kasPort = kasURL.port ?? 8080
        // For NanoTDF ResourceLocator, only include host:port, not the path
        let kasBody = "\(kasHost):\(kasPort)"

        // Get OAuth token for fetching KAS public key
        let tokenURL = URL(fileURLWithPath: "fresh_token.txt")
        let tokenData = try Data(contentsOf: tokenURL)
        let oauthToken = String(data: tokenData, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        // Fetch KAS public key - construct full URL for the API call
        let kasFullURL = URL(string: "http://\(kasBody)/kas")!
        let kasPublicKeyData = try await fetchKASPublicKey(
            kasURL: kasFullURL,
            token: oauthToken,
        )
        print("✓ Retrieved KAS public key")

        // Create resource locator for KAS
        guard let kasLocator = ResourceLocator(
            protocolEnum: ProtocolEnum(rawValue: 0x00)!, // HTTP
            body: kasBody,
            identifier: Data([0x65, 0x31]), // "e1" for EC key
        ) else {
            throw EncryptError.invalidKASURL
        }

        // Convert compressed key data to CryptoKit public key
        let kasPublicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: kasPublicKeyData)

        // Create KAS metadata with the public key
        let kasMetadata = try KasMetadata(
            resourceLocator: kasLocator,
            publicKey: kasPublicKey,
            curve: .secp256r1,
        )

        // Create policy with actual attributes
        var policy: Policy

        // Create a valid policy with no attributes (open access)
        let policyUUID = UUID().uuidString.lowercased()
        let policyJSON = """
        {
            "uuid": "\(policyUUID)",
            "body": {
                "dataAttributes": [],
                "dissem": []
            }
        }
        """
        let policyData = policyJSON.data(using: .utf8)!

        if config.withPlaintextPolicy {
            policy = Policy(
                type: .embeddedPlaintext,
                body: EmbeddedPolicyBody(body: policyData),
                remote: nil,
                binding: nil,
            )
        } else {
            policy = Policy(
                type: .embeddedEncrypted,
                body: EmbeddedPolicyBody(body: policyData),
                remote: nil,
                binding: nil,
            )
        }

        // Create v1.2 NanoTDF for otdfctl compatibility
        let nanoTDF = try await createNanoTDFv12(
            kas: kasMetadata,
            policy: &policy,
            plaintext: plaintext,
        )

        // Get the binary data
        let nanoTDFData = nanoTDF.toData()

        // Add ECDSA signature if requested
        // Note: This would require additional implementation

        print("✓ Created NanoTDF (\(nanoTDFData.count) bytes)")
        return nanoTDFData
    }

    /// Encrypt plaintext to Standard TDF using local configuration.
    static func encryptStandardTDF(
        plaintext: Data,
        configuration: StandardTDFEncryptionConfiguration,
    ) throws -> (result: StandardTDFEncryptionResult, archiveData: Data) {
        print("Standard TDF Encryption")
        print("=======================")
        print("Plaintext size: \(plaintext.count) bytes")
        print("KAS URL: \(configuration.kas.url.absoluteString)")

        let encryptor = StandardTDFEncryptor()
        let result = try encryptor.encrypt(plaintext: plaintext, configuration: configuration)
        let archiveData = try result.container.serializedData()

        print("✓ Created Standard TDF archive (\(archiveData.count) bytes)")
        print("  Key Access entries: \(result.container.manifest.encryptionInformation.keyAccess.count)")

        return (result, archiveData)
    }

    /// Fetch KAS public key
    static func fetchKASPublicKey(kasURL: URL, token: String) async throws -> Data {
        // Request EC key for NanoTDF (not RSA)
        let urlWithParams = kasURL.appendingPathComponent("v2/kas_public_key")
        var components = URLComponents(url: urlWithParams, resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "algorithm", value: "ec:secp256r1")]

        var request = URLRequest(url: components.url!)
        request.httpMethod = "GET"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200
        else {
            throw EncryptError.kasRequestFailed
        }

        // Parse JSON response to get public key
        struct KASPublicKeyResponse: Decodable {
            let publicKey: String
        }

        let decoder = JSONDecoder()
        let keyResponse = try decoder.decode(KASPublicKeyResponse.self, from: data)

        // Convert PEM to compressed key
        guard let keyData = extractCompressedKeyFromPEM(keyResponse.publicKey) else {
            throw EncryptError.invalidKASPublicKey
        }

        return keyData
    }

    /// Extract compressed P256 public key from PEM
    static func extractCompressedKeyFromPEM(_ pem: String) -> Data? {
        let pemLines = pem
            .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")

        guard let spkiData = Data(base64Encoded: pemLines) else {
            return nil
        }

        // Parse SPKI to get compressed key
        do {
            let publicKey = try P256.KeyAgreement.PublicKey(derRepresentation: spkiData)
            return publicKey.compressedRepresentation
        } catch {
            return nil
        }
    }

    /// Verify and parse a NanoTDF file using OpenTDFKit's parser
    static func verifyNanoTDF(data: Data, filename: String) throws {
        print("NanoTDF Verification Report")
        print("============================")
        print("File: \(filename)")
        print("Size: \(data.count) bytes\n")

        // Use OpenTDFKit's BinaryParser
        let parser = BinaryParser(data: data)

        // Parse the header
        let header: Header
        do {
            header = try parser.parseHeader()
            print("✓ Header parsed successfully")
        } catch {
            print("❌ Failed to parse header: \(error)")
            throw error
        }

        // Determine version from raw data
        let versionByte = data[2]
        let versionString = versionByte == 0x4C ? "1.2 (L1L)" : "1.3 (L1M)"
        print("  Version: \(versionString)")

        // Display what we can access
        print("\nKAS Information:")
        print("  URL: \(header.payloadKeyAccess.kasLocator.body)")
        if let identifier = header.payloadKeyAccess.kasLocator.identifier {
            print("  Identifier: \(String(data: identifier, encoding: .utf8) ?? identifier.hexEncodedString())")
        }
        if header.payloadKeyAccess.kasPublicKey.count > 0 {
            print("  KAS Public Key: \(header.payloadKeyAccess.kasPublicKey.count) bytes")
        }

        print("\nEphemeral Key:")
        print("  Length: \(header.ephemeralPublicKey.count) bytes")

        // Check for otdfctl's wrapped format
        if header.ephemeralPublicKey.count == 101 {
            print("  Format: otdfctl wrapped (68 bytes metadata + 33 bytes P-256 key)")
            print("  Note: otdfctl only supports secp256r1")
        } else {
            let curveName = switch header.ephemeralPublicKey.count {
            case 33: "secp256r1 (P-256)"
            case 49: "secp384r1 (P-384)"
            case 67: "secp521r1 (P-521)"
            default: "unknown"
            }
            print("  Detected curve: \(curveName)")
        }

        print("\nPolicy:")
        print("  Type: \(header.policy.type)")
        if let policyBody = header.policy.body {
            print("  Body size: \(policyBody.body.count) bytes")
        }

        // Try to parse payload
        print("\nPayload:")
        do {
            let payload = try parser.parsePayload(config: header.payloadSignatureConfig)
            print("  ✓ Parsed successfully")
            print("  Length: \(payload.length) bytes")
            print("  Ciphertext: \(payload.ciphertext.count) bytes")
            print("  MAC: \(payload.mac.count) bytes")
        } catch {
            print("  ⚠️  Could not parse payload: \(error)")
        }

        // Summary
        print("\n✓ NanoTDF structure validated using OpenTDFKit parser")
    }

    /// Decrypt a NanoTDF file and return plaintext
    static func decryptNanoTDFWithOutput(data: Data, filename _: String) async throws -> Data {
        try await performDecryption(data: data, verbose: false)
    }

    /// Decrypt a NanoTDF file with verbose console output
    static func decryptNanoTDF(data: Data, filename: String, token: String? = nil, tokenPath: String = "fresh_token.txt") async throws {
        print("NanoTDF Decryption")
        print("==================")
        print("File: \(filename)")
        print("Size: \(data.count) bytes\n")

        let decryptedData = try await performDecryption(data: data, verbose: true, token: token, tokenPath: tokenPath)
        let plaintext = String(data: decryptedData, encoding: .utf8) ?? "<binary data>"

        print("\n✓ Decryption successful!")
        print("\nPlaintext:")
        print("----------")
        print(plaintext)
    }

    /// Core decryption logic shared between verbose and silent modes
    private static func performDecryption(
        data: Data,
        verbose: Bool,
        token: String? = nil,
        tokenPath: String = "fresh_token.txt",
    ) async throws -> Data {
        let parser = BinaryParser(data: data)
        let header: Header
        do {
            header = try parser.parseHeader()
            if verbose { print("✓ Header parsed successfully") }
        } catch {
            if verbose { print("❌ Failed to parse header: \(error)") }
            throw DecryptError.invalidFormat
        }

        // Extract KAS URL - handle both formats: host:port and host:port/kas
        let kasURLString = header.payloadKeyAccess.kasLocator.body
        let kasURLWithPath = if kasURLString.contains("/kas") {
            // otdfctl format: already includes /kas path
            "http://\(kasURLString)"
        } else {
            // Our format: just host:port, need to add /kas path
            "http://\(kasURLString)/kas"
        }
        guard let kasURL = URL(string: kasURLWithPath) else {
            if verbose { print("❌ Invalid KAS URL: \(kasURLString)") }
            throw DecryptError.invalidKASURL
        }
        if verbose { print("KAS URL: \(kasURL)") }

        // Get OAuth token (from parameter or file)
        let oauthToken: String
        oauthToken = try resolveOAuthToken(providedToken: token, tokenPath: tokenPath)
        if verbose {
            print("✓ OAuth token loaded")
        }

        // Generate client ephemeral key pair
        let privateKey = P256.KeyAgreement.PrivateKey()
        let clientKeyPair = EphemeralKeyPair(
            privateKey: privateKey.rawRepresentation,
            publicKey: privateKey.publicKey.compressedRepresentation,
            curve: .secp256r1,
        )

        // Convert to PEM format for KAS request
        let publicKeyPEM = try convertToSPKIPEM(compressedKey: clientKeyPair.publicKey)
        let pemKeyPair = EphemeralKeyPair(
            privateKey: clientKeyPair.privateKey,
            publicKey: publicKeyPEM.data(using: String.Encoding.utf8)!,
            curve: .secp256r1,
        )
        if verbose { print("✓ Generated client ephemeral key pair") }

        // Find header boundary
        let headerSize = calculateHeaderSize(from: data, parsedHeader: header, verbose: verbose)
        let rawHeader = data.prefix(headerSize)

        // Call KAS rewrap endpoint
        if verbose { print("\nCalling KAS rewrap endpoint...") }
        let kasClient = KASRewrapClient(kasURL: kasURL, oauthToken: oauthToken)

        let (wrappedKey, sessionPublicKey): (Data, Data)
        do {
            (wrappedKey, sessionPublicKey) = try await kasClient.rewrapNanoTDF(
                header: rawHeader,
                parsedHeader: header,
                clientKeyPair: pemKeyPair,
            )
            if verbose { print("✓ KAS rewrap successful") }
        } catch {
            if verbose { print("❌ KAS rewrap failed: \(error)") }
            throw error
        }

        // Unwrap the key
        let payloadKey: SymmetricKey
        do {
            payloadKey = try KASRewrapClient.unwrapKey(
                wrappedKey: wrappedKey,
                sessionPublicKey: sessionPublicKey,
                clientPrivateKey: clientKeyPair.privateKey,
            )
            if verbose { print("✓ Key unwrapped successfully") }
        } catch {
            if verbose { print("❌ Key unwrap failed: \(error)") }
            throw error
        }

        // Parse and decrypt the payload
        let payload = try parser.parsePayload(config: header.payloadSignatureConfig)
        if verbose {
            print("\nPayload:")
            print("  Length: \(payload.length) bytes")
            print("  IV: \(payload.iv.hexEncodedString())")
            print("  Ciphertext: \(payload.ciphertext.count) bytes")
            print("  MAC: \(payload.mac.count) bytes")
            print("\n✓ Using \(payload.mac.count)-byte MAC tag")
        }

        // Construct nonce: 9 bytes zeros + 3-byte payload IV
        var adjustedIV = Data(count: 9)
        adjustedIV.append(payload.iv)

        // Decrypt using GCM
        guard let cipher = header.payloadSignatureConfig.payloadCipher else {
            throw DecryptError.decryptionFailed
        }

        do {
            return try OpenTDFKit.CryptoHelper.decryptNanoTDF(
                cipher: cipher,
                key: payloadKey,
                iv: adjustedIV,
                ciphertext: payload.ciphertext,
                tag: payload.mac,
            )
        } catch {
            if verbose {
                print("\n✗ GCM decryption failed: \(error)")
                let keyData = payloadKey.withUnsafeBytes { Data($0) }
                print("  Payload key: \(keyData.hexEncodedString())")
                print("  IV (adjusted): \(adjustedIV.hexEncodedString())")
            }
            throw error
        }
    }

    /// Calculate the header size from raw NanoTDF data
    private static func calculateHeaderSize(from data: Data, parsedHeader: Header, verbose: Bool) -> Int {
        // Try to find payload marker
        for i in NanoTDFConstants.headerSearchStart ..< min(data.count - 2, NanoTDFConstants.headerSearchEnd) {
            if data[i] == 0x00, data[i + 1] == 0x00 {
                if i + 2 < data.count {
                    let potentialLength = Int(data[i + 2])
                    if potentialLength > 0, potentialLength < 100, (i + 3 + potentialLength) <= data.count {
                        if verbose { print("Found payload at offset \(i)") }
                        return i
                    }
                }
            }
        }

        // Fallback to reconstructed header size
        let reconstructed = parsedHeader.toData().count
        if verbose { print("Using reconstructed header size: \(reconstructed) bytes") }
        return reconstructed
    }
}

enum NanoTDFConstants {
    static let headerSearchStart = 100
    static let headerSearchEnd = 300
    static let nonceZeroPadding = 9
}

enum DecryptError: Error, CustomStringConvertible {
    case invalidKASURL
    case missingOAuthToken
    case decryptionFailed
    case keyFormatError
    case invalidFormat
    case missingSymmetricMaterial
    case missingWrappedKey
    case invalidWrappedKeyFormat

    var description: String {
        switch self {
        case .invalidKASURL: "Invalid KAS URL format"
        case .missingOAuthToken: "OAuth token not found"
        case .decryptionFailed: "Payload decryption failed"
        case .keyFormatError: "Invalid key format"
        case .invalidFormat: "Invalid NanoTDF format"
        case .missingSymmetricMaterial: "Provide TDF_SYMMETRIC_KEY_PATH or TDF_PRIVATE_KEY_PATH to decrypt standard TDF files"
        case .missingWrappedKey: "KAS response missing wrapped key"
        case .invalidWrappedKeyFormat: "Key share length mismatch in multi-share TDF"
        }
    }
}

enum EncryptError: Error, CustomStringConvertible {
    case invalidKASURL
    case kasRequestFailed
    case invalidKASPublicKey
    case encryptionFailed
    case missingConfiguration(String)

    var description: String {
        switch self {
        case .invalidKASURL: "Invalid KAS URL format"
        case .kasRequestFailed: "KAS public key request failed"
        case .invalidKASPublicKey: "Invalid KAS public key format"
        case .encryptionFailed: "Encryption operation failed"
        case let .missingConfiguration(message): message
        }
    }
}

/// Convert compressed P256 public key to SPKI PEM format with proper DER encoding
func convertToSPKIPEM(compressedKey: Data) throws -> String {
    guard compressedKey.count == 33 else {
        throw DecryptError.keyFormatError
    }

    // Convert compressed to uncompressed using x963Representation (65 bytes)
    let tempKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: compressedKey)
    let x963Key = tempKey.x963Representation // This is the uncompressed format (0x04 + X + Y)

    // Standard SPKI DER structure for P-256
    var derData = Data()

    // SEQUENCE header for SubjectPublicKeyInfo
    derData.append(0x30) // SEQUENCE
    derData.append(0x59) // Total length (89 bytes)

    // Algorithm Identifier SEQUENCE
    derData.append(0x30) // SEQUENCE
    derData.append(0x13) // Length (19 bytes)

    // OID for ecPublicKey
    derData.append(contentsOf: [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])

    // OID for prime256v1/secp256r1
    derData.append(contentsOf: [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])

    // BIT STRING for public key
    derData.append(0x03) // BIT STRING
    derData.append(0x42) // Length (66 bytes)
    derData.append(0x00) // No unused bits

    // Add the uncompressed public key point (65 bytes)
    derData.append(x963Key)

    // Verify DER structure is correct size
    guard derData.count == 91 else {
        throw DecryptError.keyFormatError
    }

    // Convert to PEM format with proper padding
    let base64String = derData.base64EncodedString(options: [
        .lineLength64Characters,
        .endLineWithLineFeed,
    ])

    return """
    -----BEGIN PUBLIC KEY-----
    \(base64String)
    -----END PUBLIC KEY-----
    """
}

extension String {
    func chunked(into size: Int) -> [String] {
        stride(from: 0, to: count, by: size).map {
            let start = index(startIndex, offsetBy: $0)
            let end = index(start, offsetBy: min(size, count - $0))
            return String(self[start ..< end])
        }
    }
}
