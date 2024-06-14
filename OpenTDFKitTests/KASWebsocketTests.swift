@testable import OpenTDFKit
import XCTest

final class KASWebsocketTests: XCTestCase {
    func testWebsocket() throws {
        let webSocket = KASWebSocket()
        // Connect to the WebSocket server
        webSocket.connect()
        // Send a message
        webSocket.sendPublicKey()
        // Send a message
        webSocket.sendKASKeyMessage()
        // send a nano header
        webSocket.sendRewrapMessage(header: getHeader())
        // wait
        Thread.sleep(forTimeInterval: 2.0)
        // Optionally, disconnect when done or needed
        webSocket.disconnect()
    }
    
    func getHeader() -> Header {
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
}
