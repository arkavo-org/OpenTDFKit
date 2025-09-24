#!/usr/bin/env swift

import Foundation

// Test with known AES-256-GCM test vector with 12-byte tag
// From: https://github.com/krzyzanowskim/CryptoSwift/blob/main/Tests/CryptoSwiftTests/AESGCMTests.swift

print("Testing CryptoSwift GCM with known test vector...")

// Test vector with 96-bit (12-byte) tag
let keyHex = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
let ivHex = "cafebabefacedbaddecaf888"
let plaintextHex = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
let ciphertextHex = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
let tagHex = "76fc6ece0f4e1768cddf8853"  // 12-byte tag

func hexToBytes(_ hex: String) -> [UInt8] {
    var bytes = [UInt8]()
    var hex = hex
    while hex.count > 0 {
        let index = hex.index(hex.startIndex, offsetBy: 2)
        let byte = hex[..<index]
        hex = String(hex[index...])
        if let num = UInt8(byte, radix: 16) {
            bytes.append(num)
        }
    }
    return bytes
}

let key = hexToBytes(keyHex)
let iv = hexToBytes(ivHex)
let plaintext = hexToBytes(plaintextHex)
let expectedCiphertext = hexToBytes(ciphertextHex)
let expectedTag = hexToBytes(tagHex)

print("Key: \(key.count) bytes")
print("IV: \(iv.count) bytes")
print("Plaintext: \(plaintext.count) bytes")
print("Expected tag: \(expectedTag.count) bytes")

// Try to import and use CryptoSwift programmatically
print("\nAttempting to use CryptoSwift...")
