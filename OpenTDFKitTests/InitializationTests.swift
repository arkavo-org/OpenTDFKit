@testable import OpenTDFKit
import XCTest

final class InitializationTests: XCTestCase {
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testInitializeSmallNanoTDFPositive() throws {
        let locator = ResourceLocator(protocolEnum: .http, body: "localhost:8080")
        XCTAssertNotNil(locator)
        let nanoTDF = initializeSmallNanoTDF(kasResourceLocator: locator!)
        // Validate the Header
        XCTAssertEqual(nanoTDF.header.version, Data([0x0C]))
        XCTAssertEqual(nanoTDF.header.kas.protocolEnum, locator!.protocolEnum)
        XCTAssertEqual(nanoTDF.header.kas.body, locator!.body)
        // Validate the Payload
        XCTAssertEqual(nanoTDF.payload.length, 7)
        XCTAssertEqual(nanoTDF.payload.iv, Data([0x07, 0x08, 0x09]))
        // As there signature is nil in this scenario
        XCTAssertNil(nanoTDF.signature)
    }

    func testInitializeSmallNanoTDFNegative() throws {
        // out of spec - too small
        var locator = ResourceLocator(protocolEnum: .http, body: "")
        XCTAssertNil(locator)
        
        // out of spec - too large
        let body256Bytes = String(repeating: "a", count: 256)
        locator = ResourceLocator(protocolEnum: .http, body: body256Bytes)
        XCTAssertNil(locator)
        
        locator = ResourceLocator(protocolEnum: .http, body: "localhost:8080")
        XCTAssertNotNil(locator)
      
        // Test valid header creation
        XCTAssertNoThrow(Header(
            version: Data([0x0C]),
            kas: locator!,
            policyBindingConfig: PolicyBindingConfig(ecdsaBinding: false, curve: .secp256r1),
            payloadSignatureConfig: SignatureAndPayloadConfig(signed: false, signatureCurve: nil, payloadCipher: .aes256GCM128),
            policy: Policy(type: .embeddedPlaintext, body: nil, remote: nil, binding: nil),
            ephemeralPublicKey: Data([0x04, 0x05, 0x06])
        ))
    }

    func testSmallNanoTDFSize() throws {
        let locator = ResourceLocator(protocolEnum: .http, body: "localhost:8080")
        XCTAssertNotNil(locator)
        let nanoTDF = initializeSmallNanoTDF(kasResourceLocator: locator!)
        let data = nanoTDF.toData()
        print("data.count", data.count)
        XCTAssertLessThan(data.count, 240)
    }

    func testSmallNanoTDFPerformance() throws {
        // This is an example of a performance test case.
        measure {
            // Put the code you want to measure the time of here.
        }
    }
}
