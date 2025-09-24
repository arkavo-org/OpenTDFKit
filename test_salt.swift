import Foundation
import CryptoKit

// Compute the HKDF salt for v12 (L1L)
let magicNumber = Data([0x4C, 0x31]) // "L1"
let versionV12: UInt8 = 0x4C // 'L'
let magicAndVersion = magicNumber + Data([versionV12])

print("Magic + Version: \(magicAndVersion.map { String(format: "%02x", $0) }.joined())")
print("  ASCII: '\(String(data: magicAndVersion, encoding: .ascii) ?? "")'")

let salt = Data(SHA256.hash(data: magicAndVersion))
print("HKDF Salt (SHA256): \(salt.map { String(format: "%02x", $0) }.joined())")

// The spec says for v12 the salt should be:
let expectedSalt = "3de3ca1e50cf62d8b6aba603a96fca6761387a7ac86c3d3afe85ae2d1812edfc"
print("Expected salt: \(expectedSalt)")
print("Match: \(salt.map { String(format: "%02x", $0) }.joined() == expectedSalt)")
