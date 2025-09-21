import Foundation
import OpenTDFKit

struct Commands {

    /// Verify and parse a NanoTDF file
    static func verifyNanoTDF(data: Data, filename: String) throws {
        print("NanoTDF Verification Report")
        print("============================")
        print("File: \(filename)")
        print("Size: \(data.count) bytes\n")

        var offset = 0

        // 1. Magic Number and Version (3 bytes)
        guard data.count >= 3 else {
            throw VerifyError.tooSmall("File too small to be a valid NanoTDF (< 3 bytes)")
        }

        let magic = data[0..<2]
        let version = data[2]

        guard magic == Data([0x4C, 0x31]) else { // "L1"
            let hexMagic = magic.map { String(format: "%02x", $0) }.joined()
            throw VerifyError.invalidMagic("Expected 'L1' (4c31), got '\(hexMagic)'")
        }

        print("Header:")
        print("  ✓ Magic Number: L1")

        let versionName: String
        switch version {
        case 0x4C: // 'L'
            versionName = "1.2 (L1L)"
        case 0x4D: // 'M'
            versionName = "1.3 (L1M)"
        default:
            throw VerifyError.unknownVersion(String(format: "0x%02x", version))
        }
        print("  ✓ Version: \(versionName)")
        offset = 3

        // 2. KAS Resource Locator
        guard offset + 2 <= data.count else {
            throw VerifyError.truncated("KAS locator")
        }

        let kasProtocol = data[offset]
        offset += 1

        let kasBodyLength = Int(data[offset])
        offset += 1

        guard offset + kasBodyLength <= data.count else {
            throw VerifyError.truncated("KAS body")
        }

        let kasBody = data[offset..<offset + kasBodyLength]
        let kasURL = String(data: kasBody, encoding: .utf8) ?? "<binary>"
        offset += kasBodyLength

        print("\nKAS Information:")
        print("  Protocol: \(formatKASProtocol(kasProtocol))")
        print("  URL: \(kasURL)")

        // 3. Ephemeral Public Key
        guard offset + 1 <= data.count else {
            throw VerifyError.truncated("ephemeral key length")
        }

        let ephemeralKeyLength = Int(data[offset])
        offset += 1

        guard offset + ephemeralKeyLength <= data.count else {
            throw VerifyError.truncated("ephemeral key")
        }

        let ephemeralKey = data[offset..<offset + ephemeralKeyLength]
        offset += ephemeralKeyLength

        print("\nEphemeral Key:")
        print("  Length: \(ephemeralKeyLength) bytes")

        // otdfctl wraps the ephemeral key with metadata
        // The actual key is in the last portion of the field
        var actualKeyCurve = "unknown"
        if ephemeralKeyLength == 101 {
            // otdfctl format: 68 bytes metadata + 33 bytes P-256 key
            print("  Format: otdfctl wrapped key (68 bytes metadata + 33 bytes key)")
            actualKeyCurve = "secp256r1 (P-256)"
            let actualKey = ephemeralKey.suffix(33)
            let keyPreview = actualKey.prefix(16).map { String(format: "%02x", $0) }.joined(separator: " ")
            print("  Actual key (last 33 bytes): \(keyPreview)...")
        } else if ephemeralKeyLength == 33 || ephemeralKeyLength == 49 || ephemeralKeyLength == 67 {
            // Standard compressed EC key sizes
            switch ephemeralKeyLength {
            case 33: actualKeyCurve = "secp256r1 (P-256)"
            case 49: actualKeyCurve = "secp384r1 (P-384)"
            case 67: actualKeyCurve = "secp521r1 (P-521)"
            default: break
            }
            let keyPreview = ephemeralKey.prefix(16).map { String(format: "%02x", $0) }.joined(separator: " ")
            print("  Format: Standard compressed EC key (\(actualKeyCurve))")
            print("  Key: \(keyPreview)...")
        } else {
            let keyPreview = ephemeralKey.prefix(16).map { String(format: "%02x", $0) }.joined(separator: " ")
            print("  Format: Unknown")
            print("  Key: \(keyPreview)...")
        }
        print("  Detected curve: \(actualKeyCurve)")

        // 4. Policy Binding Configuration (1 byte)
        guard offset + 1 <= data.count else {
            throw VerifyError.truncated("policy binding config")
        }

        let policyBinding = data[offset]
        let useECDSABinding = (policyBinding & 0x80) != 0
        let ephemeralCurve = policyBinding & 0x07
        offset += 1

        print("\nPolicy Binding:")
        print("  Type: \(useECDSABinding ? "ECDSA" : "GMAC")")
        print("  Ephemeral Curve value: 0x\(String(format: "%02x", ephemeralCurve))")
        print("  Note: otdfctl only supports secp256r1, curve value may not match OpenTDFKit enum")

        // 5. Payload Signature Configuration (1 byte)
        guard offset + 1 <= data.count else {
            throw VerifyError.truncated("payload signature config")
        }

        let payloadConfig = data[offset]
        let hasSignature = (payloadConfig & 0x80) != 0
        let signatureCurve = (payloadConfig >> 4) & 0x07
        let symmetricCipher = payloadConfig & 0x0F
        offset += 1

        print("\nPayload Configuration:")
        print("  Has Signature: \(hasSignature)")
        if hasSignature {
            print("  Signature Curve: \(formatCurve(signatureCurve))")
        }
        print("  Symmetric Cipher: \(formatCipher(symmetricCipher))")

        // Debug: show raw bytes
        print("  Debug - Policy binding byte: 0x\(String(format: "%02x", policyBinding))")
        print("  Debug - Payload config byte: 0x\(String(format: "%02x", payloadConfig))")

        // 6. Policy section
        print("\nPolicy:")

        // The policy structure varies by version and type
        // For now, we'll try to identify the type
        if offset < data.count {
            let nextByte = data[offset]

            // Check for remote policy indicators
            if nextByte == 0x00 || nextByte == 0x01 || nextByte == 0xFF {
                print("  Type: Remote")
                offset += 1

                // Try to parse resource locator
                if offset + 1 < data.count {
                    let bodyLen = Int(data[offset])
                    offset += 1

                    if offset + bodyLen <= data.count {
                        let policyRef = data[offset..<offset + bodyLen]
                        if let policyStr = String(data: policyRef, encoding: .utf8) {
                            print("  Reference: \(policyStr)")
                        } else {
                            let hexStr = policyRef.prefix(16).map { String(format: "%02x", $0) }.joined(separator: " ")
                            print("  Reference (hex): \(hexStr)...")
                        }
                        offset += bodyLen
                    }
                }
            } else {
                print("  Type: Embedded or other")
                // Skip detailed parsing for now
            }
        }

        // 7. Payload
        print("\nPayload:")

        // Look for the payload section (starts with 3-byte length)
        var payloadFound = false
        let remainingBytes = data.count - offset

        if remainingBytes >= 3 {
            // Try to interpret next 3 bytes as payload length
            let payloadLength = (UInt32(data[offset]) << 16) |
                               (UInt32(data[offset + 1]) << 8) |
                               UInt32(data[offset + 2])

            // Sanity check the length
            if payloadLength > 0 && payloadLength < 100000 {
                print("  Length field: \(payloadLength) bytes")
                print("  Offset: \(offset)")
                payloadFound = true

                offset += 3

                if offset + Int(payloadLength) <= data.count {
                    let payloadData = data[offset..<offset + Int(payloadLength)]

                    if payloadData.count >= 3 {
                        let iv = payloadData[0..<3]
                        print("  IV: \(iv.map { String(format: "%02x", $0) }.joined(separator: " "))")

                        let macSize = symmetricCipher == 0 ? 8 : 16
                        let ciphertextSize = payloadData.count - 3 - macSize

                        if ciphertextSize > 0 {
                            print("  Ciphertext: \(ciphertextSize) bytes")
                            print("  MAC: \(macSize) bytes")
                        }
                    }
                }
            }
        }

        if !payloadFound {
            print("  ⚠️  Could not clearly identify payload structure")
            print("  Remaining bytes: \(remainingBytes)")
        }

        // Summary
        print("\nValidation Summary:")
        print("  ✓ Valid magic number and version")
        print("  ✓ KAS information present")
        print("  ✓ Ephemeral key present")
        print("  ✓ Policy binding configured")

        if useECDSABinding && !hasSignature {
            print("  ⚠️  ECDSA binding specified but no signature flag set")
        }

        if payloadFound {
            print("  ✓ Payload structure identified")
        } else {
            print("  ⚠️  Payload structure unclear")
        }

        print("\n✓ NanoTDF structure verification complete")
    }

    // Helper functions
    private static func formatKASProtocol(_ proto: UInt8) -> String {
        switch proto {
        case 0x00: return "HTTP (0x00)"
        case 0x01: return "HTTPS (0x01)"
        case 0xFF: return "Shared Resource Directory (0xFF)"
        default: return String(format: "Unknown (0x%02x)", proto)
        }
    }

    private static func formatCurve(_ curve: UInt8) -> String {
        switch curve {
        case 0x00: return "secp256r1"
        case 0x01: return "secp384r1"
        case 0x02: return "secp521r1"
        case 0x03: return "secp256k1"
        default: return String(format: "Unknown (0x%02x)", curve)
        }
    }

    private static func formatCipher(_ cipher: UInt8) -> String {
        switch cipher {
        case 0x00: return "AES-256-GCM-64"
        case 0x01: return "AES-256-GCM-96"
        case 0x02: return "AES-256-GCM-104"
        case 0x03: return "AES-256-GCM-112"
        case 0x04: return "AES-256-GCM-120"
        case 0x05: return "AES-256-GCM-128"
        default: return String(format: "Unknown (0x%02x)", cipher)
        }
    }
}

// Error types for verification
enum VerifyError: Error, CustomStringConvertible {
    case tooSmall(String)
    case invalidMagic(String)
    case unknownVersion(String)
    case truncated(String)
    case invalidStructure(String)

    var description: String {
        switch self {
        case .tooSmall(let msg): return "File too small: \(msg)"
        case .invalidMagic(let msg): return "Invalid magic number: \(msg)"
        case .unknownVersion(let msg): return "Unknown version: \(msg)"
        case .truncated(let msg): return "Truncated data at: \(msg)"
        case .invalidStructure(let msg): return "Invalid structure: \(msg)"
        }
    }
}