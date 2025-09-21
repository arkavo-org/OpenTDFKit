#!/usr/bin/env swift

import Foundation
import OpenTDFKit

// Parse the NanoTDF created by otdfctl
@main
struct ParseNanoTDF {
    static func main() async throws {
        print("Parsing NanoTDF created by otdfctl")
        print("==================================\n")

        let filePath = "test_output.ntdf.tdf"

        // Read the NanoTDF file
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: filePath)) else {
            print("Error: Could not read file \(filePath)")
            exit(1)
        }

        print("File: \(filePath)")
        print("Size: \(data.count) bytes\n")

        // Check magic number (first 3 bytes should be "L1L" or "L1M")
        if data.count >= 3 {
            let magic = data[0..<2]
            let version = data[2]

            let magicString = String(data: magic, encoding: .ascii) ?? "unknown"
            print("Magic Number: '\(magicString)' (hex: \(magic.map { String(format: "%02x", $0) }.joined()))")

            if magic == Data([0x4C, 0x31]) { // "L1"
                print("✓ Valid NanoTDF magic number")

                let versionChar = String(format: "%c", version)
                switch version {
                case 0x4C: // 'L'
                    print("Version: 1.2 (L1L)")
                case 0x4D: // 'M'
                    print("Version: 1.3 (L1M)")
                default:
                    print("Version: Unknown (\(versionChar))")
                }
            } else {
                print("✗ Invalid magic number")
                exit(1)
            }
        }

        // Parse KAS information
        print("\nParsing Header:")
        print("---------------")

        var offset = 3 // Skip magic number and version

        // Read KAS Resource Locator
        if offset < data.count {
            // Protocol (1 byte)
            let kasProtocol = data[offset]
            offset += 1

            print("KAS Protocol: \(String(format: "0x%02x", kasProtocol))")

            // Body length (1 byte)
            if offset < data.count {
                let bodyLength = Int(data[offset])
                offset += 1

                // Body content
                if offset + bodyLength <= data.count {
                    let kasBody = data[offset..<offset + bodyLength]
                    if let kasURL = String(data: kasBody, encoding: .utf8) {
                        print("KAS URL: \(kasURL)")
                    }
                    offset += bodyLength
                }
            }

            // Ephemeral Public Key Length
            if offset < data.count {
                let keyLength = Int(data[offset])
                offset += 1

                print("Ephemeral Key Length: \(keyLength) bytes")

                if offset + keyLength <= data.count {
                    let ephemeralKey = data[offset..<offset + keyLength]
                    print("Ephemeral Key (first 16 bytes): \(ephemeralKey.prefix(16).map { String(format: "%02x", $0) }.joined(separator: " "))")
                    offset += keyLength
                }
            }
        }

        // Policy Binding Config (1 byte)
        if offset < data.count {
            let policyBinding = data[offset]
            let useECDSA = (policyBinding & 0x80) != 0
            let curve = policyBinding & 0x07

            print("\nPolicy Binding:")
            print("  ECDSA Binding: \(useECDSA)")
            print("  Curve: \(curve)")
            offset += 1
        }

        // Payload info
        print("\nPayload:")
        print("--------")
        let remainingBytes = data.count - offset
        print("Remaining bytes (encrypted payload + MAC): \(remainingBytes)")

        // The rest is the encrypted payload
        if offset < data.count {
            let encryptedPayload = data[offset...]

            // Payload structure: 3 bytes length + IV + ciphertext + MAC
            if encryptedPayload.count >= 3 {
                let payloadLength = (UInt32(encryptedPayload[0]) << 16) |
                                   (UInt32(encryptedPayload[1]) << 8) |
                                   UInt32(encryptedPayload[2])
                print("Payload length field: \(payloadLength)")

                // Show first few bytes of encrypted data
                let encryptedPreview = encryptedPayload.dropFirst(3).prefix(32)
                print("Encrypted data (first 32 bytes): \(encryptedPreview.map { String(format: "%02x", $0) }.joined(separator: " "))")
            }
        }

        print("\n✓ Successfully parsed NanoTDF structure created by otdfctl")

        // Now try to parse using OpenTDFKit structures
        print("\nAttempting to parse with OpenTDFKit...")

        // Since NanoTDF doesn't have a public initializer from Data,
        // we'll validate what we can
        print("Note: Full parsing would require access to internal NanoTDF parsing methods")
        print("      or implementation of the binary format parser")
    }
}