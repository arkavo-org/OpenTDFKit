import CryptoKit
import Foundation
import OpenTDFKit

// Test the nonce construction for NanoTDF
let payload_iv = Data([0x01, 0x02, 0x03]) // Example 3-byte payload IV

// Old way (incorrect - padding with zeros at end)
var oldNonce = payload_iv
while oldNonce.count < 12 {
    oldNonce.append(0)
}

// New way (correct - 9 bytes zeros + 3 bytes payload IV)
var newNonce = Data(count: 9)
newNonce.append(payload_iv)

print("Payload IV (3 bytes): \(payload_iv.map { String(format: "%02x", $0) }.joined())")
print("Old nonce (incorrect): \(oldNonce.map { String(format: "%02x", $0) }.joined())")
print("New nonce (correct):   \(newNonce.map { String(format: "%02x", $0) }.joined())")

// Test with actual data from the file
let testData = Data([0xED, 0x65, 0x64]) // First 3 bytes from the actual payload
var correctNonce = Data(count: 9)
correctNonce.append(testData)
print("\nActual payload IV from test file: \(testData.map { String(format: "%02x", $0) }.joined())")
print("Constructed 12-byte nonce: \(correctNonce.map { String(format: "%02x", $0) }.joined())")
