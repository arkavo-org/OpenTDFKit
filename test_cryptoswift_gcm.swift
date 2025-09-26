import Foundation

// Simple test to verify CryptoSwift GCM works
let plaintext = "Test OpenTDFKit GCM\n"
print("Plaintext: '\(plaintext)' (\(plaintext.count) bytes)")

// Use the actual key we got from KAS
let keyHex = "e05f9a6ca22376bfb5274187ddef7920c1af98841aba8cb6ff638657688f3ae7"
let key = hexToData(keyHex)
print("Key: \(keyHex)")

// Use the same IV construction: 9 zeros + 3 bytes
let ivSuffix = Data([0x90, 0xF8, 0x65])
var iv = Data(count: 9)
iv.append(ivSuffix)
print("IV: \(iv.map { String(format: "%02x", $0) }.joined())")

// Expected ciphertext and tag from the file
let expectedCiphertext = hexToData("64d520f49c0dd66af76d9e326bef7dab32535db4")
let expectedTag = hexToData("fb8cf764ead449e6374d6114")

print("\nExpected from file:")
print("  Ciphertext: \(expectedCiphertext.map { String(format: "%02x", $0) }.joined())")
print("  Tag: \(expectedTag.map { String(format: "%02x", $0) }.joined())")

func hexToData(_ hex: String) -> Data {
    var data = Data()
    var hex = hex
    while hex.count > 0 {
        let index = hex.index(hex.startIndex, offsetBy: 2)
        let byte = hex[..<index]
        hex = String(hex[index...])
        if let num = UInt8(byte, radix: 16) {
            data.append(num)
        }
    }
    return data
}
