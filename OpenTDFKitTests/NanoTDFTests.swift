import CryptoKit
@testable import OpenTDFKit
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
        let hexString = """
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
        """.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: "\n", with: "")
        let binaryData = Data(hexString: hexString)
        let parser = BinaryParser(data: binaryData!)
        do {
            let header = try parser.parseHeader()
            print("Parsed Header:", header)
            // KAS
            print("KAS:", header.kas.body)
            if header.kas.body != "kas.virtru.com" {
                XCTFail("")
            }
            // Ephemeral Key
            let ephemeralKeyHexString = header.ephemeralPublicKey.map { String(format: "%02x", $0) }.joined(separator: " ")
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

    // 6.1.5 nanotdf
    func testSpecExampleBinaryParserSerializerParser() throws {
        let hexString = """
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
        """.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: "\n", with: "")
        let binaryData = Data(hexString: hexString)
        do {
            let parser = BinaryParser(data: binaryData!)
            let header = try parser.parseHeader()
            // EccMode
            let serializedEccMode = header.policyBindingConfig.toData()
            let serializedEccModeHexString = serializedEccMode.map { String(format: "%02x", $0) }.joined(separator: " ")
            var compareHexString = """
            80
            """.replacingOccurrences(of: "\n", with: " ")
            if serializedEccModeHexString == compareHexString {
                print("EccMode equals comparison string.")
            } else {
                print(serializedEccModeHexString)
                XCTFail("EccMode does not equal comparison string.")
            }
            let payload = try parser.parsePayload(config: header.payloadSignatureConfig)
            let serializedPayloadMacHexString = payload.mac.map { String(format: "%02x", $0) }.joined(separator: " ")
            compareHexString = """
            f9 fd 80 14 af 7c cb 06
            """.replacingOccurrences(of: "\n", with: " ")
            if serializedPayloadMacHexString == compareHexString {
                print("MAC equals comparison string.")
            } else {
                print(serializedPayloadMacHexString)
                XCTFail("MAC does not equal comparison string.")
            }
            let signature = try parser.parseSignature(config: header.payloadSignatureConfig)
            let nano = NanoTDF(header: header, payload: payload, signature: signature)
            let serializedNanoTDF = nano.toData()
            var counter = 0
            let serializedNanoTDFHexString = serializedNanoTDF.map { byte -> String in
                counter += 1
                let newline = counter % 20 == 0 ? "\n" : " "
                return String(format: "%02x", byte) + newline
            }.joined()
            print("Actual:")
            print(serializedNanoTDFHexString)
            if serializedNanoTDF == binaryData {
                print("NanoTDF equals comparison bytes.")
            } else {
                XCTFail("NanoTDF does not equal comparison bytes.")
            }
            // back again
            let bparser = BinaryParser(data: serializedNanoTDF)
            let bheader = try bparser.parseHeader()
            _ = try bparser.parsePayload(config: bheader.payloadSignatureConfig)
            _ = try bparser.parseSignature(config: bheader.payloadSignatureConfig)
        } catch {
            XCTFail("Failed to parse data: \(error)")
        }
    }

    // 6.1.5 nanotdf
    func testSpecExampleDecryptPayload() {
        let hexString = """
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
        """.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: "\n", with: "")
        let binaryData = Data(hexString: hexString)
        let parser = BinaryParser(data: binaryData!)
        do {
            let header = try parser.parseHeader()
            // Ephemeral Key
            let ephemeralKeyHexString = header.ephemeralPublicKey.map { String(format: "%02x", $0) }.joined(separator: " ")
            print("Ephemeral Key:", ephemeralKeyHexString)
            // Parse payload
            let payload = try parser.parsePayload(config: header.payloadSignatureConfig)
            let payloadIvHexString = payload.iv.map { String(format: "%02x", $0) }.joined(separator: " ")
            print("Payload IV:", payloadIvHexString)
            var compareHexString = """
            9e bd 09
            """.replacingOccurrences(of: "\n", with: " ")
            if payloadIvHexString == compareHexString {
                print("Payload IV equals comparison string.")
            } else {
                XCTFail("Payload IV does not equal comparison string.")
            }
            let payloadCiphertextHexString = payload.ciphertext.map { String(format: "%02x", $0) }.joined(separator: " ")
            print("Payload Ciphertext:", payloadCiphertextHexString)
            compareHexString = """
            17 52 26 8e 03
            """.replacingOccurrences(of: "\n", with: " ")
            if payloadCiphertextHexString == compareHexString {
                print("Payload Ciphertext equals comparison string.")
            } else {
                XCTFail("Payload Ciphertext does not equal comparison string.")
            }
            // Create the symmetric key
            _ = SymmetricKey(size: .bits256)

            // Combine the IV-nonce, ciphertext, and MAC-tag
            let _ = payload.iv + payload.ciphertext + payload.mac

            // Decrypt the payload
//            let sealedBox = try AES.GCM.SealedBox(combined: combinedData)
//            let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey)
//
//            // Assert the decrypted data is as expected
//            let expectedDecryptedData = "DON'T"
//            XCTAssertEqual(decryptedData, decryptedData)
        } catch {
            XCTFail("Decryption failed: \(error)")
        }
    }

    // 6.2 No Signature Example
    func testNoSignatureSpecExampleBinaryParser() throws {
        let hexString = """
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
        """.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: "\n", with: "")
        let binaryData = Data(hexString: hexString)
        let parser = BinaryParser(data: binaryData!)
        do {
            let header = try parser.parseHeader()
            print("Parsed Header:", header)
            // KAS
            print("KAS:", header.kas.body)
            if header.kas.body != "kas.example.com" {
                XCTFail("KAS incorrect")
            }
            if header.policy.remote?.body != "kas.example.com/policy/abcdef" {
                XCTFail("Policy Body incorrect")
            }
            // Ephemeral Key
            let ephemeralKeyHexString = header.ephemeralPublicKey.map { String(format: "%02x", $0) }.joined(separator: " ")
            print("Ephemeral Key:", ephemeralKeyHexString)
            let compareHexString = """
            03 e8 b3 3f 44 9a 73 92 77 13 d4 a4 a2 b4 e5 e9 45 2e 2f 05
            34 33 9d 35 91 1b df a1 5e e1 8b 3a db
            """.replacingOccurrences(of: "\n", with: " ")
            print("Compare Key:", compareHexString)
            if ephemeralKeyHexString == compareHexString {
                print("Ephemeral Key equals comparison string.")
            } else {
                XCTFail("Ephemeral Key does not equal comparison string.")
            }
            // ECC and Binding Mode
            if header.policyBindingConfig.toData() == Data([0x80]) {
                print("EccMode equals comparison.")
            } else {
                XCTFail("EccMode does not equal comparison.")
            }
            // Symmetric and Payload Config
            if header.payloadSignatureConfig.toData() == Data([0x35]) {
                print("SigMode equals comparison.")
            } else {
                XCTFail("SigMode does not equal comparison.")
            }
            // Signature
            XCTAssertFalse(header.payloadSignatureConfig.signed)
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
            let header = try parser.parseHeader()
            print("Parsed Header:", header)
            print("Policy type:", header.policy.type)
            print("Policy body:", header.policy.body as Any)
        } catch {
            XCTFail("Failed to parse data: \(error)")
        }
    }

    func testAddSignature() {
        // Parse a NanoTDF without a signature
        let hexString = """
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
        """.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: "\n", with: "")
        let binaryData = Data(hexString: hexString)
        let parser = BinaryParser(data: binaryData!)
        do {
            let header = try parser.parseHeader()
            let payload = try parser.parsePayload(config: header.payloadSignatureConfig)
            var nanoTDF = NanoTDF(header: header, payload: payload, signature: nil)
            // Generate an ECDSA private key
            let privateKey = P256.Signing.PrivateKey()
            // Add the signature to the NanoTDF
            print("Adding signature")
            try addSignatureToNanoTDF(nanoTDF: &nanoTDF, privateKey: privateKey, config: header.payloadSignatureConfig)
            // Print the updated NanoTDF
            print(nanoTDF)
            var serializedSignature = nanoTDF.signature?.toData()
            print("Added signature length:", serializedSignature?.count as Any)
            // round trip - serialize
            let serializedWithSignature = nanoTDF.toData()
            var counter = 0
            let serializedNanoTDFHexString = serializedWithSignature.map { byte -> String in
                counter += 1
                let newline = counter % 20 == 0 ? "\n" : " "
                return String(format: "%02x", byte) + newline
            }.joined()
            print("Added:")
            print(serializedNanoTDFHexString)
            // round trip - parse
            let sparser = BinaryParser(data: serializedWithSignature)
            let sheader = try sparser.parseHeader()
            let spayload = try sparser.parsePayload(config: sheader.payloadSignatureConfig)
            let ssignature = try sparser.parseSignature(config: sheader.payloadSignatureConfig)
            let snanoTDF = NanoTDF(header: sheader, payload: spayload, signature: ssignature)
            // Print final the signature NanoTDF
            print(snanoTDF)
            serializedSignature = snanoTDF.signature?.toData()
            print("Added signature length:", serializedSignature?.count as Any)
            let sserializedWithSignature = snanoTDF.toData()
            counter = 0
            let sserializedNanoTDFHexString = sserializedWithSignature.map { byte -> String in
                counter += 1
                let newline = counter % 20 == 0 ? "\n" : " "
                return String(format: "%02x", byte) + newline
            }.joined()
            print("Parsed:")
            print(sserializedNanoTDFHexString)
            if serializedWithSignature == sserializedWithSignature {
                print("NanoTDF equals comparison bytes.")
            } else {
                XCTFail("NanoTDF does not equal comparison bytes.")
            }
        } catch {
            XCTFail("Failed to parse data: \(error)")
        }
    }

    func testCreateAddVerifySignature() throws {
        let locator = ResourceLocator(protocolEnum: .http, body: "localhost:8080")
        XCTAssertNotNil(locator)
        var nanoTDF = initializeSmallNanoTDF(kasResourceLocator: locator!)
        // Generate an ECDSA private key
        let privateKey = P256.Signing.PrivateKey()

        // Add the signature to the NanoTDF
        try addSignatureToNanoTDF(nanoTDF: &nanoTDF, privateKey: privateKey, config: nanoTDF.header.payloadSignatureConfig)
        XCTAssertEqual(64, nanoTDF.signature?.signature.count)
//        // Serialize the NanoTDF
//        let serializedData = nanoTDF.toData()
//
//        // Parse the NanoTDF
//        let parser = BinaryParser(data: serializedData)
//        let parsedHeader = try parser.parseHeader()
//        _ = try parser.parsePayload(config: parsedHeader.payloadSignatureConfig)
//        let signature = try parser.parseSignature(config: parsedHeader.payloadSignatureConfig)
//
//        // Verify the parsed NanoTDF
//        XCTAssertEqual(parsedHeader.payloadSignatureConfig.signed, true)
//        XCTAssertEqual(parsedHeader.payloadSignatureConfig.signatureCurve, .secp256r1)
//        XCTAssertEqual(parsedHeader.payloadSignatureConfig.payloadCipher, .aes256GCM128)
//        XCTAssertEqual(signature?.publicKey, privateKey.publicKey.rawRepresentation)
//        XCTAssertEqual(signature?.signature, nanoTDF.signature?.signature)
    }

    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        measure {
            // Put the code you want to measure the time of here.
        }
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

class SymmetricAndPayloadConfigTests: XCTestCase {
    func testToDataWithSignature() {
        let config = SignatureAndPayloadConfig(signed: true, signatureCurve: .secp256r1, payloadCipher: .aes256GCM128)
        let data = config.toData()
        XCTAssertEqual(data.count, 1)
        XCTAssertEqual(data[0], 0b1000_0101) // 0b10000000 (HAS_SIGNATURE) | 0b00000000 (Signature ECC Mode secp256r1) | 0b00000101 (Symmetric Cipher Enum GCM_128)
    }

    func testToDataWithoutSignature() {
        let config = SignatureAndPayloadConfig(signed: false, signatureCurve: nil, payloadCipher: .aes256GCM128)
        let data = config.toData()
        XCTAssertEqual(data.count, 1)
        XCTAssertEqual(data[0], 0b0000_0101) // 0b00000101 (Symmetric Cipher Enum GCM_128)
    }

    func testParseWithSignature() {
        let data = Data([0b1000_0101])
        let config = SignatureAndPayloadConfig.parse(from: data)
        XCTAssertNotNil(config)
        XCTAssertEqual(config?.signed, true)
        XCTAssertEqual(config?.signatureCurve, .secp256r1)
        XCTAssertEqual(config?.payloadCipher, .aes256GCM128)
    }

    func testParseWithoutSignature() {
        let data = Data([0b0000_0101])
        let config = SignatureAndPayloadConfig.parse(from: data)
        XCTAssertNotNil(config)
        XCTAssertEqual(config?.signed, false)
        XCTAssertNil(config?.signatureCurve)
        XCTAssertEqual(config?.payloadCipher, .aes256GCM128)
    }

    func testParseInvalidData() {
        let data = Data([0b1111_1111]) // Invalid combination
        let config = SignatureAndPayloadConfig.parse(from: data)
        XCTAssertNil(config)
    }
}

// Extend SymmetricAndPayloadConfig to include a parsing method
extension SignatureAndPayloadConfig {
    static func parse(from data: Data) -> SignatureAndPayloadConfig? {
        guard data.count == 1 else { return nil }

        let byte = data[0]
        let signed = (byte & 0b1000_0000) != 0
        let signatureECCMode = Curve(rawValue: (byte & 0b0111_0000) >> 4)
        let symmetricCipherEnum = Cipher(rawValue: byte & 0b0000_1111)

        guard let signatureMode = signatureECCMode, let symmetricCipher = symmetricCipherEnum else {
            return nil
        }

        if !signed {
            return SignatureAndPayloadConfig(signed: signed, signatureCurve: nil, payloadCipher: symmetricCipher)
        }
        return SignatureAndPayloadConfig(signed: signed, signatureCurve: signatureMode, payloadCipher: symmetricCipher)
    }
}

class PayloadTests: XCTestCase {
    func testToData() {
        let payload = Payload(length: 12345, iv: Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C]), ciphertext: Data([0x0D, 0x0E, 0x0F, 0x10]), mac: Data([0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20]))
        let data = payload.toData()

        let expectedData = Data([0x00, 0x30, 0x39]) +
            Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C]) +
            Data([0x0D, 0x0E, 0x0F, 0x10]) +
            Data([0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20])

        XCTAssertEqual(data, expectedData)
    }

    func testParse() {
        let hexString = """
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
        """.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: "\n", with: "")
        let binaryData = Data(hexString: hexString)
        let parser = BinaryParser(data: binaryData!)
        do {
            let header = try parser.parseHeader()
            let payload = try parser.parsePayload(config: header.payloadSignatureConfig)
            XCTAssertEqual(payload.iv.count, 3)
            XCTAssertEqual(payload.mac.count, 16)
        } catch {
            XCTFail("Failed to parse data: \(error)")
        }
    }

    func testParseInvalidData() {
        // corrupted
        let hexString = """
        4c 31 4c 01 0f 6b 61 73 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d
        80 35 00 01 1d 6b 61 73 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d
        2f 70 6f 6c 69 63 79 2f 61 62 63 64 65 66 61 aa 06 8d 76 c2
        0d f3 a5 63 76 33 98 62 9f 52 30 72 d0 86 d4 4d 4b e6 6e 25
        74 e1 3b c3 2c c7 02 2a 4c dc 7a a7 ef cb a6 03 c1 98 3f 87
        72 ef 1d 10 e8 2e 0d 40 06 f4 bd dd 92 78 79 35 66 73 03 e8
        b3 3f 44 9a 73 92 77 13 d4 a4 a2 b4 e5 e9 45 2e 2f 05 34 33
        9d 35 91 1b df a1 5e e1 8b 3a db 00 00 99 50 e4 9c fa ab 69
        18 52 26 1b 2d 63 60 83 1a cb d5 f2 03 fb ef 17 f9 46 be fe
        c7 9e e5 11 9b a0 92 33 3b 2c 0e ea cb 9e 2f 8d c8
        """.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: "\n", with: "")
        let binaryData = Data(hexString: hexString)
        let parser = BinaryParser(data: binaryData!)
        do {
            let header = try parser.parseHeader()
            let payload = try parser.parsePayload(config: header.payloadSignatureConfig)
            print(payload)
            XCTFail("Negative should have failed")
        } catch {
            // pass
        }
    }
}
