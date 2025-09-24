import Foundation

let data = Data([
    0x00, 0x00, 0x23,  // Length: 35 bytes
    0x90, 0xf8, 0x65,  // IV: 3 bytes
    // Ciphertext: 20 bytes
    0x64, 0xd5, 0x20, 0xf4, 0x9c, 0x0d, 0xd6, 0x6a, 0xf7, 0x6d,
    0x9e, 0x32, 0x6b, 0xef, 0x7d, 0xab, 0x32, 0x53, 0x5d, 0xb4,
    // Tag: 12 bytes
    0xfb, 0x8c, 0xf7, 0x64, 0xea, 0xd4, 0x49, 0xe6, 0x37, 0x4d, 0x61, 0x14
])

let length = Int(data[0]) << 16 | Int(data[1]) << 8 | Int(data[2])
print("Payload length: \(length) bytes")

let iv = data[3..<6]
print("IV: \(iv.map { String(format: "%02x", $0) }.joined())")

// For 96-bit tag (12 bytes)
let tagSize = 12
let ciphertextEnd = 3 + length - tagSize
let ciphertext = data[6..<ciphertextEnd]
let tag = data[ciphertextEnd..<(3 + length)]

print("Ciphertext: \(ciphertext.count) bytes - \(ciphertext.map { String(format: "%02x", $0) }.joined())")
print("Tag: \(tag.count) bytes - \(tag.map { String(format: "%02x", $0) }.joined())")
