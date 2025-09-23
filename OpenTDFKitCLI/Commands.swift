import Foundation
import OpenTDFKit
import CryptoKit
import Darwin

extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02x", $0) }.joined()
    }
}

struct Commands {

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

    /// Decrypt a NanoTDF file
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

        // Step 2: Extract KAS URL
        let kasURLString = header.payloadKeyAccess.kasLocator.body
        guard let kasURL = URL(string: "http://\(kasURLString)") else {
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
        let headerData = header.toData()
        let rawHeader = data.prefix(headerData.count)

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
        // Check if we're using a non-standard tag size
        if payload.mac.count != 16 {
            print("\n⚠️  Warning: NanoTDF uses \(payload.mac.count)-byte MAC tag")
            print("   CryptoKit only supports 16-byte (128-bit) tags")
            print("   Files created with aes256GCM96 or other non-128-bit tags cannot be decrypted")
            print("   Consider recreating the file with aes256GCM128 (cipher 0x05)")
            throw DecryptError.decryptionFailed
        }

        // Adjust IV to 12 bytes for AES-GCM
        var adjustedIV = payload.iv
        while adjustedIV.count < 12 {
            adjustedIV.append(0)
        }

        // Decrypt using AES-GCM
        let nonce = try AES.GCM.Nonce(data: adjustedIV)
        let sealedBox = try AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: payload.ciphertext,
            tag: payload.mac
        )

        let decryptedData = try AES.GCM.open(sealedBox, using: payloadKey)
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
}

/// Convert compressed P256 public key to SPKI PEM format
func convertToSPKIPEM(compressedKey: Data) throws -> String {
    // For now, use a simplified approach - convert compressed to uncompressed first
    // This is a temporary implementation until we have proper CryptoKit integration

    guard compressedKey.count == 33 else {
        throw DecryptError.keyFormatError
    }

    // Create a temporary P256 key from compressed representation to get uncompressed
    let tempKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: compressedKey)
    let uncompressedKey = tempKey.rawRepresentation

    // Standard SPKI DER structure for P-256
    let spkiHeader: [UInt8] = [
        0x30, 0x59, // SEQUENCE, 89 bytes
        0x30, 0x13, // AlgorithmIdentifier SEQUENCE, 19 bytes
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // ecPublicKey OID
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // prime256v1 OID
        0x03, 0x42, 0x00 // BIT STRING, 66 bytes, 0 unused bits
    ]

    // Combine header + 0x04 prefix + uncompressed key
    var spkiBytes = Data(spkiHeader)
    spkiBytes.append(0x04) // uncompressed point format indicator
    spkiBytes.append(uncompressedKey)

    // Convert to PEM format
    let base64String = spkiBytes.base64EncodedString()
    let lines = base64String.chunked(into: 64)

    var pemString = "-----BEGIN PUBLIC KEY-----\n"
    for line in lines {
        pemString += line + "\n"
    }
    pemString += "-----END PUBLIC KEY-----\n"

    return pemString
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