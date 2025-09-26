import Foundation

let data = Data([
    0x00, 0x00, 0x23, // Length: 35 bytes
    0x90, 0xF8, 0x65, // IV: 3 bytes
    // Ciphertext: 20 bytes
    0x64, 0xD5, 0x20, 0xF4, 0x9C, 0x0D, 0xD6, 0x6A, 0xF7, 0x6D,
    0x9E, 0x32, 0x6B, 0xEF, 0x7D, 0xAB, 0x32, 0x53, 0x5D, 0xB4,
    // Tag: 12 bytes
    0xFB, 0x8C, 0xF7, 0x64, 0xEA, 0xD4, 0x49, 0xE6, 0x37, 0x4D, 0x61, 0x14,
])

let length = Int(data[0]) << 16 | Int(data[1]) << 8 | Int(data[2])
print("Payload length: \(length) bytes")

let iv = data[3 ..< 6]
print("IV: \(iv.map { String(format: "%02x", $0) }.joined())")

// For 96-bit tag (12 bytes)
let tagSize = 12
let ciphertextEnd = 3 + length - tagSize
let ciphertext = data[6 ..< ciphertextEnd]
let tag = data[ciphertextEnd ..< (3 + length)]

print("Ciphertext: \(ciphertext.count) bytes - \(ciphertext.map { String(format: "%02x", $0) }.joined())")
print("Tag: \(tag.count) bytes - \(tag.map { String(format: "%02x", $0) }.joined())")
