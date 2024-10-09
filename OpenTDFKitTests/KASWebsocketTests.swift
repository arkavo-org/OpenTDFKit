import CryptoKit
@testable import OpenTDFKit
import XCTest

final class KASWebsocketTests: XCTestCase {
    func testEncryptDecrypt() throws {
        measure(metrics: [XCTCPUMetric()]) {
            let nanoTDFManager = NanoTDFManager()
            let webSocket = KASWebSocket(kasUrl: URL(string: "wss://kas.arkavo.net")!, token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
//            let webSocket = KASWebSocket(kasUrl: URL(string: "ws://localhost:8080")!, token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
            let plaintext = "Keep this message secret".data(using: .utf8)!
            webSocket.setRewrapCallback { identifier, symmetricKey in
//                defer {
//                    print("END setRewrapCallback")
//                }
//                print("BEGIN setRewrapCallback")
//                print("Received Rewrapped identifier: \(identifier.hexEncodedString())")
//                print("Received Rewrapped Symmetric key: \(String(describing: symmetricKey))")
                let nanoTDF = nanoTDFManager.getNanoTDF(withIdentifier: identifier)
                nanoTDFManager.removeNanoTDF(withIdentifier: identifier)
                if symmetricKey == nil {
                    // DENY
                    return
                }
                let payload = nanoTDF?.payload
                let rawIV = payload?.iv
                // Pad the IV
                let paddedIV = CryptoHelper.adjustNonce(rawIV!, to: 12)
                let authTag = payload?.mac
                let ciphertext = payload?.ciphertext
                // Create AES-GCM SealedBox
                do {
//                    print("Symmetric key (first 4 bytes): \(symmetricKey!.withUnsafeBytes { Data($0.prefix(4)).hexEncodedString() })")
//                    print("Raw IV: \(rawIV!.hexEncodedString())")
//                    print("Padded IV: \(paddedIV.hexEncodedString())")
//                    print("Ciphertext length: \(ciphertext!.count)")
//                    print("Auth tag: \(authTag!.hexEncodedString())")
                    let sealedBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: paddedIV),
                                                          ciphertext: ciphertext!,
                                                          tag: authTag!)
//                    print("SealedBox created successfully")
                    let dplaintext = try AES.GCM.open(sealedBox, using: symmetricKey!)
//                    print("plaintext: \(dplaintext)")
                    // print("Decryption successful")
                    XCTAssertEqual(plaintext, dplaintext)
                } catch {
                    print("Error decryption nanoTDF payload: \(error)")
                }
            }
            webSocket.setKASPublicKeyCallback { publicKey in
                let kasRL = ResourceLocator(protocolEnum: .http, body: "localhost:8080")
                let kasMetadata = KasMetadata(resourceLocator: kasRL!, publicKey: publicKey, curve: .secp256r1)
                let remotePolicy = ResourceLocator(protocolEnum: .sharedResourceDirectory, body: "5Cqk3ERPToSMuY8UoKJtcmo4fs1iVyQpq6ndzWzpzWezAF1W")
                var policy = Policy(type: .remote, body: nil, remote: remotePolicy, binding: nil)

                do {
                    var i = 0
                    while i < 2000 {
                        i += 1
                        // create
                        let nanoTDF = try createNanoTDF(kas: kasMetadata, policy: &policy, plaintext: plaintext)
                        // print("Encryption successful")
                        // store nanoTDF
                        let id = nanoTDF.header.ephemeralPublicKey
                        nanoTDFManager.addNanoTDF(nanoTDF, withIdentifier: id)
                        webSocket.sendRewrapMessage(header: nanoTDF.header)
                    }

                } catch {
                    print("Error creating nanoTDF: \(error)")
                }
            }
            webSocket.connect()
            webSocket.sendPublicKey()
            webSocket.sendKASKeyMessage()
            // wait
            Thread.sleep(forTimeInterval: 0.5)
            print("+++++++++++++++++", nanoTDFManager.getCount())
            while !nanoTDFManager.isEmpty() {
                Thread.sleep(forTimeInterval: 0.1)
                print("+++++++++++++++++", nanoTDFManager.getCount())
            }
            // Optionally, disconnect when done or needed
            webSocket.disconnect()
        }
    }

    func testWebsocket() throws {
        let webSocket = KASWebSocket(kasUrl: URL(string: "ws://localhost:8080")!, token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        let expectation = XCTestExpectation(description: "Receive rewrapped key")
        // Create a 33-byte identifier
        let testIdentifier = Data((0 ..< 33).map { _ in UInt8.random(in: 0 ... 255) })

        webSocket.setRewrapCallback { identifier, symmetricKey in
            XCTAssertEqual(identifier.count, 33, "Identifier should be 33 bytes")
            if identifier == testIdentifier, symmetricKey != nil {
                print("Received rewrapped key for identifier: \(identifier)")
                expectation.fulfill()
            }
        }
        // Connect to the WebSocket server
        webSocket.connect()
//        webSocket.sendKASKeyMessage()
//        webSocket.sendKASKeyMessage()
//        webSocket.sendKASKeyMessage()
        // Decrypt
        // Send a client public key for decrypt
        webSocket.sendPublicKey()
//        webSocket.sendPublicKey()
        // send a nano header No signature for decrypting
//        webSocket.sendRewrapMessage(header: getHeaderNoSignature())
        // send a nano header No signature for decrypting
        webSocket.sendRewrapMessage(header: getHeaderBasic())
//        webSocket.sendPublicKey()
        // Encrypt
        // Send a request for KAS key for encrypt
//        webSocket.sendKASKeyMessage()
        // wait
        Thread.sleep(forTimeInterval: 1.0)
        // Optionally, disconnect when done or needed
        webSocket.disconnect()
    }

    func getHeaderNoSignature() -> Header {
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
            return header
        } catch {
            XCTFail("Failed to parse data: \(error)")
        }
        let locator = ResourceLocator(protocolEnum: .http, body: "localhost:8080")
        XCTAssertNotNil(locator)
        let nanoTDF = initializeSmallNanoTDF(kasResourceLocator: locator!)
        return nanoTDF.header
    }

    func getHeaderBasic() -> Header {
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
            return header
        } catch {
            XCTFail("Failed to parse data: \(error)")
        }
        let locator = ResourceLocator(protocolEnum: .http, body: "localhost:8080")
        XCTAssertNotNil(locator)
        let nanoTDF = initializeSmallNanoTDF(kasResourceLocator: locator!)
        return nanoTDF.header
    }
}
