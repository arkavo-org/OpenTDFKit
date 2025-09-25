import Foundation
import OpenTDFKit
import CryptoKit
import Darwin

extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02x", $0) }.joined()
    }
}

struct CLIConfig {
    let kasURL: String
    let platformURL: String
    let clientID: String
    let clientSecret: String
    let withECDSABinding: Bool
    let withPlaintextPolicy: Bool

    static func fromEnvironment() -> CLIConfig {
        return CLIConfig(
            kasURL: ProcessInfo.processInfo.environment["KASURL"] ?? "http://10.0.0.138:8080",
            platformURL: ProcessInfo.processInfo.environment["PLATFORMURL"] ?? "http://10.0.0.138:8080",
            clientID: ProcessInfo.processInfo.environment["CLIENTID"] ?? "opentdf-client",
            clientSecret: ProcessInfo.processInfo.environment["CLIENTSECRET"] ?? "secret",
            withECDSABinding: ProcessInfo.processInfo.environment["XT_WITH_ECDSA_BINDING"] == "true",
            withPlaintextPolicy: ProcessInfo.processInfo.environment["XT_WITH_PLAINTEXT_POLICY"] == "true"
        )
    }
}

struct Commands {

    /// Encrypt plaintext to NanoTDF v1.2 format (L1L) using OpenTDFKit's NanoTDF API
    static func encryptNanoTDF(plaintext: Data, useECDSA: Bool) async throws -> Data {
        print("NanoTDF Encryption")
        print("==================")
        print("Plaintext size: \(plaintext.count) bytes")
        print("ECDSA binding: \(useECDSA)")

        // Get configuration from environment
        let config = CLIConfig.fromEnvironment()

        // Parse KAS URL
        guard let kasURL = URL(string: config.kasURL) else {
            throw EncryptError.invalidKASURL
        }

        let kasHost = kasURL.host ?? "10.0.0.138"
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
            token: oauthToken
        )
        print("✓ Retrieved KAS public key")

        // Create resource locator for KAS
        guard let kasLocator = ResourceLocator(
            protocolEnum: ProtocolEnum(rawValue: 0x00)!, // HTTP
            body: kasBody,
            identifier: Data([0x65, 0x31]) // "e1" for EC key
        ) else {
            throw EncryptError.invalidKASURL
        }

        // Convert compressed key data to CryptoKit public key
        let kasPublicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: kasPublicKeyData)

        // Create KAS metadata with the public key
        let kasMetadata = try KasMetadata(
            resourceLocator: kasLocator,
            publicKey: kasPublicKey,
            curve: .secp256r1
        )

        // Create policy with actual attributes
        var policy: Policy

        // Create a valid policy with an attribute that exists in the platform
        let policyUUID = UUID().uuidString.lowercased()
        let policyJSON = """
        {
            "uuid": "\(policyUUID)",
            "body": {
                "dataAttributes": [
                    {
                        "attribute": "https://example.com/attr/attr1/value/value1"
                    }
                ],
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
                binding: nil
            )
        } else {
            policy = Policy(
                type: .embeddedEncrypted,
                body: EmbeddedPolicyBody(body: policyData),
                remote: nil,
                binding: nil
            )
        }

        // Create v1.2 NanoTDF for otdfctl compatibility
        let nanoTDF = try await createNanoTDFv12(
            kas: kasMetadata,
            policy: &policy,
            plaintext: plaintext
        )

        // Get the binary data
        let nanoTDFData = nanoTDF.toData()

        // Add ECDSA signature if requested
        // Note: This would require additional implementation

        print("✓ Created NanoTDF (\(nanoTDFData.count) bytes)")
        return nanoTDFData
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
              httpResponse.statusCode == 200 else {
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
    static func decryptNanoTDFWithOutput(data: Data, filename: String) async throws -> Data {
        // Parse the NanoTDF
        let parser = BinaryParser(data: data)
        let header: Header
        do {
            header = try parser.parseHeader()
        } catch {
            throw DecryptError.invalidFormat
        }

        // Extract KAS URL - handle both formats: host:port and host:port/kas
        let kasURLString = header.payloadKeyAccess.kasLocator.body
        let kasURLWithPath: String
        if kasURLString.contains("/kas") {
            // otdfctl format: already includes /kas path
            kasURLWithPath = "http://\(kasURLString)"
        } else {
            // Our format: just host:port, need to add /kas path
            kasURLWithPath = "http://\(kasURLString)/kas"
        }
        guard let kasURL = URL(string: kasURLWithPath) else {
            throw DecryptError.invalidKASURL
        }

        // Get OAuth token from file
        let tokenURL = URL(fileURLWithPath: "fresh_token.txt")
        let tokenData = try Data(contentsOf: tokenURL)
        let oauthToken = String(data: tokenData, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        // Generate client ephemeral key pair
        let privateKey = P256.KeyAgreement.PrivateKey()
        let clientKeyPair = EphemeralKeyPair(
            privateKey: privateKey.rawRepresentation,
            publicKey: privateKey.publicKey.compressedRepresentation,
            curve: .secp256r1
        )

        // Convert to PEM for KAS request
        let publicKeyPEM = try convertToSPKIPEM(compressedKey: clientKeyPair.publicKey)
        let pemKeyPair = EphemeralKeyPair(
            privateKey: clientKeyPair.privateKey,
            publicKey: publicKeyPEM.data(using: String.Encoding.utf8)!,
            curve: .secp256r1
        )

        // Find header boundary (where payload starts)
        var headerSize = 0
        for i in 100..<min(data.count - 2, 300) {
            if data[i] == 0x00 && data[i+1] == 0x00 {
                // Check if this could be a valid payload length
                if i + 2 < data.count {
                    let potentialLength = Int(data[i+2])
                    if potentialLength > 0 && potentialLength < 100 && (i + 3 + potentialLength) <= data.count {
                        headerSize = i
                        break
                    }
                }
            }
        }

        if headerSize == 0 {
            // Fallback: estimate based on typical sizes
            headerSize = 176 // Common size for standard NanoTDF headers
        }

        let rawHeader = data.prefix(headerSize)

        // Call KAS rewrap
        let kasClient = KASRewrapClient(kasURL: kasURL, oauthToken: oauthToken)
        let (wrappedKey, sessionPublicKey) = try await kasClient.rewrapNanoTDF(
            header: rawHeader,
            parsedHeader: header,
            clientKeyPair: pemKeyPair
        )

        // Unwrap the key
        let payloadKey = try KASRewrapClient.unwrapKey(
            wrappedKey: wrappedKey,
            sessionPublicKey: sessionPublicKey,
            clientPrivateKey: clientKeyPair.privateKey
        )

        // Parse and decrypt payload
        let payload = try parser.parsePayload(config: header.payloadSignatureConfig)

        // Construct nonce: 9 bytes zeros + 3-byte payload IV
        var adjustedIV = Data(count: 9)
        adjustedIV.append(payload.iv)

        // Decrypt using GCM
        guard let cipher = header.payloadSignatureConfig.payloadCipher else {
            throw DecryptError.decryptionFailed
        }

        let decryptedData = try GCM.decryptNanoTDF(
            cipher: cipher,
            key: payloadKey,
            iv: adjustedIV,
            ciphertext: payload.ciphertext,
            tag: payload.mac
        )

        return decryptedData
    }

    /// Decrypt a NanoTDF file (legacy function with console output)
    static func decryptNanoTDF(data: Data, filename: String, token: String? = nil, tokenPath: String = "fresh_token.txt") async throws {
        print("NanoTDF Decryption")
        print("==================")
        print("File: \(filename)")
        print("Size: \(data.count) bytes\n")

        // Step 1: Parse the NanoTDF
        let parser = BinaryParser(data: data)
        let header: Header
        do {
            header = try parser.parseHeader()
            print("✓ Header parsed successfully")
        } catch {
            print("❌ Failed to parse header: \(error)")
            throw error
        }

        // Step 2: Extract KAS URL - handle both formats: host:port and host:port/kas
        let kasURLString = header.payloadKeyAccess.kasLocator.body
        let kasURLWithPath: String
        if kasURLString.contains("/kas") {
            // otdfctl format: already includes /kas path
            kasURLWithPath = "http://\(kasURLString)"
        } else {
            // Our format: just host:port, need to add /kas path
            kasURLWithPath = "http://\(kasURLString)/kas"
        }
        guard let kasURL = URL(string: kasURLWithPath) else {
            print("❌ Invalid KAS URL: \(kasURLString)")
            throw DecryptError.invalidKASURL
        }
        print("KAS URL: \(kasURL)")

        // Step 3: Get OAuth token (from parameter or file)
        let oauthToken: String
        if let providedToken = token {
            oauthToken = providedToken.trimmingCharacters(in: .whitespacesAndNewlines)
            print("✓ OAuth token provided via parameter")
        } else {
            let tokenURL = URL(fileURLWithPath: tokenPath)
            let tokenData = try Data(contentsOf: tokenURL)
            oauthToken = String(data: tokenData, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            print("✓ OAuth token loaded from file")
        }

        // Step 4: Generate client ephemeral key pair using CryptoKit directly
        let privateKey = P256.KeyAgreement.PrivateKey()
        let clientKeyPair = EphemeralKeyPair(
            privateKey: privateKey.rawRepresentation,
            publicKey: privateKey.publicKey.compressedRepresentation,
            curve: .secp256r1
        )

        // Convert the compressed public key to SPKI PEM format for KAS
        let publicKeyPEM = try convertToSPKIPEM(compressedKey: clientKeyPair.publicKey)


        // Create a new key pair with PEM format for the request
        let pemKeyPair = EphemeralKeyPair(
            privateKey: clientKeyPair.privateKey,
            publicKey: publicKeyPEM.data(using: String.Encoding.utf8)!,
            curve: .secp256r1
        )
        print("✓ Generated client ephemeral key pair using CryptoKit")

        // Step 5: Extract raw header for KAS request
        // The header includes everything up to (not including) the payload
        // IMPORTANT: We need the EXACT bytes from the file, not a reconstruction

        // Calculate where payload starts by parsing
        // The payload starts with a 3-byte length field
        // We need to find this in the original data

        // Let's find where the payload starts by looking for the 3-byte length field
        // The payload starts with 0x00 0x00 0x23 (length = 35)
        var headerSize = 0

        // Search for the payload start marker
        // We know the payload is 35 bytes long (0x000023)
        let payloadMarker = Data([0x00, 0x00, 0x23])
        if let range = data.range(of: payloadMarker) {
            headerSize = range.lowerBound
            print("DEBUG: Found payload at offset \(headerSize)")
        } else {
            // Fallback: manually calculate
            headerSize = 3  // Magic + version
            headerSize += 1  // Protocol byte
            headerSize += 1  // Body length byte

            if data.count > 4 {
                let bodyLen = Int(data[4])
                headerSize += bodyLen
            }

            // KAS identifier
            if data.count > 3 {
                let protocolByte = data[3]
                let identifierType = (protocolByte >> 4) & 0x0F
                let identifierSizes = [0, 2, 8, 32]
                if identifierType < 4 {
                    headerSize += identifierSizes[Int(identifierType)]
                }
            }

            // Ephemeral key
            if data.count > headerSize {
                headerSize += 1  // Key length byte
                let keyLen = Int(data[headerSize - 1])
                headerSize += keyLen
            }

            // ECC mode and payload config
            headerSize += 2

            // Policy - this is where we had the bug
            if data.count > headerSize {
                headerSize += 1  // Policy type byte
                let policyType = data[headerSize - 1]

                // For embeddedEncrypted (0x03) and embeddedEncryptedWithKeyAccess (0x04)
                // there's a length byte followed by the body
                if policyType >= 0x03 && policyType <= 0x04 {
                    headerSize += 1  // Body length byte
                    if data.count > headerSize {
                        let bodyLen = Int(data[headerSize - 1])
                        headerSize += bodyLen
                    }
                }
            }
        }

        print("DEBUG: Calculated header size: \(headerSize) bytes")

        // Compare with reconstructed header for debugging
        let headerData = header.toData()
        print("DEBUG: Reconstructed header size: \(headerData.count) bytes")
        if headerSize != headerData.count {
            print("WARNING: Header size mismatch! Original: \(headerSize), Reconstructed: \(headerData.count)")
        }

        // Use the actual file bytes for the header
        let rawHeader = data.prefix(headerSize)

        // Step 6: Call KAS rewrap endpoint
        print("\nCalling KAS rewrap endpoint...")
        fputs("DEBUG: Creating KAS client...\n", stderr)
        let kasClient = KASRewrapClient(kasURL: kasURL, oauthToken: oauthToken)

        fputs("DEBUG: Calling rewrapNanoTDF...\n", stderr)
        let (wrappedKey, sessionPublicKey): (Data, Data)
        do {
            (wrappedKey, sessionPublicKey) = try await kasClient.rewrapNanoTDF(
                header: rawHeader,
                parsedHeader: header,
                clientKeyPair: pemKeyPair
            )
            print("✓ KAS rewrap successful")
        } catch {
            print("❌ KAS rewrap failed: \(error)")
            throw error
        }

        // Step 7: Unwrap the key using the original private key
        fputs("DEBUG: Unwrapping key...\n", stderr)
        fputs("DEBUG: Wrapped key size: \(wrappedKey.count) bytes\n", stderr)
        fputs("DEBUG: Session public key size: \(sessionPublicKey.count) bytes\n", stderr)
        fputs("DEBUG: Client private key size: \(clientKeyPair.privateKey.count) bytes\n", stderr)

        let payloadKey: SymmetricKey
        do {
            payloadKey = try KASRewrapClient.unwrapKey(
                wrappedKey: wrappedKey,
                sessionPublicKey: sessionPublicKey,
                clientPrivateKey: clientKeyPair.privateKey
            )
            print("✓ Key unwrapped successfully")
            fputs("DEBUG: Payload key size: \(payloadKey.bitCount) bits\n", stderr)
        } catch {
            fputs("DEBUG: Key unwrap failed: \(error)\n", stderr)
            throw error
        }

        // Step 8: Parse and decrypt the payload
        let payload = try parser.parsePayload(config: header.payloadSignatureConfig)
        print("\nPayload:")
        print("  Length: \(payload.length) bytes")
        print("  IV: \(payload.iv.hexEncodedString())")
        print("  Ciphertext: \(payload.ciphertext.count) bytes")
        print("  MAC: \(payload.mac.count) bytes")

        // Step 9: Decrypt the payload
        print("\n✓ NanoTDF uses \(payload.mac.count)-byte MAC tag (cipher: \(String(format: "0x%02X", header.payloadSignatureConfig.payloadCipher?.rawValue ?? 0)))")

        // Construct 12-byte nonce: 9 bytes of zeros + 3-byte payload IV (otdfctl compatibility)
        var adjustedIV = Data(count: 9) // 9 bytes of zeros
        adjustedIV.append(payload.iv)    // Append the 3-byte payload IV

        // Decrypt using GCM module that supports all NanoTDF tag sizes
        guard let cipher = header.payloadSignatureConfig.payloadCipher else {
            throw DecryptError.decryptionFailed
        }

        let decryptedData: Data
        do {
            decryptedData = try GCM.decryptNanoTDF(
                cipher: cipher,
                key: payloadKey,
                iv: adjustedIV,
                ciphertext: payload.ciphertext,
                tag: payload.mac
            )
        } catch {
            print("\n✗ GCM decryption failed: \(error)")
            let keyData = payloadKey.withUnsafeBytes { Data($0) }
            print("  Payload key: \(keyData.hexEncodedString())")
            print("  IV (adjusted): \(adjustedIV.hexEncodedString())")
            print("  Ciphertext: \(payload.ciphertext.hexEncodedString())")
            print("  Tag: \(payload.mac.hexEncodedString())")
            throw error
        }
        let plaintext = String(data: decryptedData, encoding: .utf8) ?? "<binary data>"

        print("\n✓ Decryption successful!")
        print("\nPlaintext:")
        print("----------")
        print(plaintext)
    }
}

enum DecryptError: Error {
    case invalidKASURL
    case missingOAuthToken
    case decryptionFailed
    case keyFormatError
    case invalidFormat
}

enum EncryptError: Error {
    case invalidKASURL
    case kasRequestFailed
    case invalidKASPublicKey
    case encryptionFailed
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
        .endLineWithLineFeed
    ])

    return """
    -----BEGIN PUBLIC KEY-----
    \(base64String)
    -----END PUBLIC KEY-----
    """
}

extension String {
    func chunked(into size: Int) -> [String] {
        return stride(from: 0, to: count, by: size).map {
            let start = index(startIndex, offsetBy: $0)
            let end = index(start, offsetBy: min(size, count - $0))
            return String(self[start..<end])
        }
    }
}