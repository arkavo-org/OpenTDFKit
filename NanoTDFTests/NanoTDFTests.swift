//
//  NanoTDFTests.swift
//  NanoTDFTests
//
//  Created by Paul Flynn on 4/29/24.
//

import CryptoKit
@testable import NanoTDF
import XCTest

final class NanoTDFTests: XCTestCase {
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    // 6.1.5 nanotdf
    func testSpecExampleBinaryParser() throws {
        let stringWithSpaces = """
        4c 31 4c 01 0e 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 80
        80 00 01 15 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 2f 70
        6f 6c 69 63 79 b5 e4 13 a6 02 11 e5 f1 7b 22 34 a0 cd 3f 36
        ff 7b ba 6d 8f e8 df 23 f6 2c 9d 09 35 6f 85 82 f8 a9 cf 15
        12 6c 8a 9d a4 6c 5e 4e 0c bc c8 26 97 19 ac 05 1b 80 62 5c
        c7 54 03 03 6f fb 82 87 1f 02 f7 7f ba e5 26 09 da c5 e8 eb
        f7 86 e1 1b 7a ed d7 0f 89 80 f9 48 0c 7e 67 1c ba ab 8e 24
        50 92 00 00 10 9e bd 09 17 52 26 8e 03 f9 fd 80 14 af 7c cb
        06 02 d5 cf b9 7f 55 24 c5 90 3f 62 73 62 05 93 36 aa 71 a4
        c2 ee 16 d0 5b 78 34 03 97 e2 ae 07 1d 2e 9d 9b 8a e3 30 ef
        70 23 ea 56 99 b5 20 4b bc 7d 56 8d ff fa 3f fa 53 57 e1 fc
        d2 90 f3 1a d1 ef 62 ce 46 f0 d9 5d f4 31 6b ca f3 72 8d 4f
        75 cd 15 95 01 0b f2 04 20 74 ac 94 de 29 76 ba 02 f3
        """
        let hexString = stringWithSpaces.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: "\n", with: "")
        let binaryData = Data(hexString: hexString)
        let parser = BinaryParser(data: binaryData!)
        do {
            let header = try parser.parse()
            print("Parsed Header:", header)
            // KAS
            print("KAS:", header.kas.body)
            if "kas.virtru.com" != header.kas.body {
                XCTFail("")
            }
            // Ephemeral Key
            let ephemeralKeyHexString = header.ephemeralKey.map { String(format: "%02x", $0) }.joined(separator: " ")
            print("Ephemeral Key:", ephemeralKeyHexString)
            let compareHexString = """
        02 f7 7f ba e5 26 09 da c5 e8 eb f7 86 e1 1b 7a ed d7 0f 89
        80 f9 48 0c 7e 67 1c ba ab 8e 24 50 92
        """.replacingOccurrences(of: "\n", with: " ")
            if ephemeralKeyHexString == compareHexString {
                print("Ephemeral Key equals comparison string.")
            } else {
                XCTFail("Ephemeral Key does not equal comparison string.")
            }
        } catch {
            XCTFail("Failed to parse data: \(error)")
        }
    }

    // 6.2 No Signature Example
    func testNoSignatureSpecExampleBinaryParser() throws {
        let stringWithSpaces = """
        4c 31 4c 01 0f 6b 61 73 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d
        80 35 00 01 1d 6b 61 73 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d
        2f 70 6f 6c 69 63 79 2f 61 62 63 64 65 66 61 aa 06 8d 76 c2
        0d f3 a5 63 76 33 98 62 9f 52 30 72 d0 86 d4 4d 4b e6 6e 25
        74 e1 3b c3 2c c7 02 2a 4c dc 7a a7 ef cb a6 03 c1 98 3f 87
        72 ef 1d 10 e8 2e 0d 40 06 f4 bd dd 92 78 79 35 66 73 03 e8
        b3 3f 44 9a 73 92 77 13 d4 a4 a2 b4 e5 e9 45 2e 2f 05 34 33
        9d 35 91 1b df a1 5e e1 8b 3a db 00 00 2b 50 e4 9c fa ab 69
        18 52 26 1b 2d 63 60 83 1a cb d5 f2 03 fb ef 17 f9 46 be fe
        c7 9e e5 11 9b a0 92 33 3b 2c 0e ea cb 9e 2f 8d c8
        """
        let hexString = stringWithSpaces.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: "\n", with: "")
        let binaryData = Data(hexString: hexString)
        let parser = BinaryParser(data: binaryData!)
        do {
            let header = try parser.parse()
            print("Parsed Header:", header)
            // Magic Number
            let magicNumberHexString = header.magicNumber.map { String(format: "%02x", $0) }.joined(separator: " ")
            print("Magic Number Hex:", magicNumberHexString)
            // Version
            let versionHexString = header.version.map { String(format: "%02x", $0) }.joined(separator: " ")
            print("Version Hex:", versionHexString)
            // KAS
            print("KAS:", header.kas.body)
            if "kas.example.com" != header.kas.body {
                XCTFail("KAS incorrect")
            }
            if "kas.example.com/policy/abcdef" != header.policy.remote?.body {
                XCTFail("Policy Body incorrect")
            }
            // Ephemeral Key
            let ephemeralKeyHexString = header.ephemeralKey.map { String(format: "%02x", $0) }.joined(separator: " ")
            print("Ephemeral Key:", ephemeralKeyHexString)
            let compareHexString = """
        03 e8 b3 3f 44 9a 73 92 77 13 d4 a4 a2 b4 e5 e9 45 2e 2f 05
        34 33 9d 35 91 1b df a1 5e e1 8b 3a db
        """.replacingOccurrences(of: "\n", with: " ")
            print("Comemeral Key:", compareHexString)
            if ephemeralKeyHexString == compareHexString {
                print("Ephemeral Key equals comparison string.")
            } else {
                XCTFail("Ephemeral Key does not equal comparison string.")
            }
        } catch {
            XCTFail("Failed to parse data: \(error)")
        }
    }
    
    func testNoPolicyBinaryParser() throws {
        let stringWithSpaces = """
        4c 31 4c 01 1a 70 6c 61 74 66 6f 72 6d 2e 76 69 72 74 72 75
        2e 75 73 2f 61 70 69 2f 6b 61 73 00 01 02 00 64 d6 a4 ae a5
        52 c4 7c 8f 96 77 ad 4c 9e 2b a3 0e e9 b2 5e ee 86 bd 1a 4c
        98 3e 35 c8 e1 78 e3 35 13 da a2 1f 64 71 d1 d3 ce 6e 6d fd
        45 78 47 1d f3 29 ab 5d 61 80 46 32 46 9d 8f e6 c4 02 29 cf
        4e 6b ee d2 9e 42 67 10 5f b8 34 0a 4e 90 c4 04 44 a0 38 90
        26 62 bb bb 0b ee c5 e3 51 57 49 34 3e c7 d8 2d 88 df 06 c7
        08 41 95 0a 02 55 6e 95 07 f9 94 d1 d7 21 ce bb 92 1a f4 84
        ac f3 63 51 6a a3 1c 28 f5 93 da e0 be e6 40 6b b0 00 00 1c
        00 00 01 1d c7 a4 85 be b0 0f 60 11 b7 73 3b 7f e6 05 6d 72
        1b 78 91 43 f7 49 e1 a8
        """
        let hexString = stringWithSpaces.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: "\n", with: "")
        let binaryData = Data(hexString: hexString)
        let parser = BinaryParser(data: binaryData!)
        do {
            let header = try parser.parse()
            print("Parsed Header:", header)
            print("Policy type:", header.policy.type)
            print("Policy body:", header.policy.body as Any)
        } catch {
            XCTFail("Failed to parse data: \(error)")
        }
    }

    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        measure {
            // Put the code you want to measure the time of here.
        }
    }

    func testEncryptionDecryption() throws {
        // Generate a random key.
        let key = SymmetricKey(size: .bits256)

        // Initialize a string and convert it to data.
        let originalString = "This is a test"
        guard let originalData = originalString.data(using: .utf8) else {
            XCTFail("Failed to convert original string to data.")
            return
        }

        // Test the `encrypt` function.
        guard let encryptedData = encrypt(data: originalData, using: key) else {
            XCTFail("Failed to encrypt the original data.")
            return
        }

        // Test the `decrypt` function.
        guard let decryptedData = decrypt(data: encryptedData, using: key) else {
            XCTFail("Failed to decrypt the encrypted data.")
            return
        }

        // Convert the decrypted data back to a string.
        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            XCTFail("Failed to convert decrypted data back to a string.")
            return
        }

        // Assert that the decrypted string is equal to the original string.
        XCTAssertEqual(decryptedString, originalString)
    }

    func testNanoTDFHeaderEncodingDecoding() {
        let header = NanoTDFHeader(magicNumber: 12345, version: 1, kas: ResourceLocator(protocolEnum: ProtocolEnum.https, body: "example.com"), eccMode: 1, payloadSigMode: 2, policy: Data([0x01]), ephemeralKey: Data([0x01, 0x02, 0x03]))
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        do {
            let encoded = try encoder.encode(header)
            let decoded = try decoder.decode(NanoTDFHeader.self, from: encoded)
            XCTAssertEqual(decoded.magicNumber, header.magicNumber)
            XCTAssertEqual(decoded.version, header.version)
            // Add more assertions as needed
            print("Encoded NanoTDF size:", encoded)
            if let json = try? JSONSerialization.jsonObject(with: encoded, options: []),
               let data = try? JSONSerialization.data(withJSONObject: json, options: .prettyPrinted),
               let prettyPrintedString = String(data: data, encoding: .utf8)
            {
                print(prettyPrintedString)
            } else {
                XCTFail("Failed to pretty print the JSON")
            }
        } catch {
            XCTFail("Encoding or decoding failed: \(error)")
        }
    }
    
    func testWebSocket() {
        let webSocketManager = WebSocketManager()

        // Connect to the WebSocket server
        webSocketManager.connect()

        // Send a message
        webSocketManager.sendMessage("Hello, server!")
        
        // Optionally, disconnect when done or needed
         webSocketManager.disconnect()

    }
}

extension Data {
    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        for i in 0 ..< len {
            let j = hexString.index(hexString.startIndex, offsetBy: i * 2)
            let k = hexString.index(j, offsetBy: 2)
            let bytes = hexString[j ..< k]
            if let byte = UInt8(bytes, radix: 16) {
                data.append(byte)
            } else {
                return nil
            }
        }
        self = data
    }
}
