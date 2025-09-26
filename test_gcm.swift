import CryptoKit
import Foundation

// Test data from the actual file
let keyHex = "e05f9a6ca22376bfb5274187ddef7920c1af98841aba8cb6ff638657688f3ae7"
let ivHex = "00000000000000000090f865"
let ciphertextHex = "64d520f49c0dd66af76d9e326bef7dab32535db4"
let tagHex = "fb8cf764ead449e6374d6114"

// Convert hex to Data
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

let key = SymmetricKey(data: hexToData(keyHex))
let iv = hexToData(ivHex)
let ciphertext = hexToData(ciphertextHex)
let tag = hexToData(tagHex)

print("Key: \(keyHex)")
print("IV: \(ivHex)")
print("Ciphertext: \(ciphertextHex)")
print("Tag (12 bytes): \(tagHex)")

// Try with 16-byte tag by padding with zeros
var paddedTag = tag
paddedTag.append(contentsOf: [0, 0, 0, 0])
print("Padded tag (16 bytes): \(paddedTag.map { String(format: "%02x", $0) }.joined())")

do {
    let nonce = try AES.GCM.Nonce(data: iv)
    let sealedBox = try AES.GCM.SealedBox(
        nonce: nonce,
        ciphertext: ciphertext,
        tag: paddedTag,
    )
    let plaintext = try AES.GCM.open(sealedBox, using: key)
    print("Success! Plaintext: \(String(data: plaintext, encoding: .utf8) ?? plaintext.hexEncodedString())")
} catch {
    print("Failed: \(error)")
}

extension Data {
    func hexEncodedString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}
