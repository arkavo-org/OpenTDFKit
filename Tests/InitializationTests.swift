//
//  InitializationTests.swift
//  Tests
//
//  Created by Paul Flynn on 6/9/24.
//

@testable import NanoTDF
import XCTest

final class InitializationTests: XCTestCase {
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testInitializeSmallNanoTDF_Positive() throws {
        let locator = ResourceLocator(protocolEnum: .http, body: "localhost:8080")
        XCTAssertNotNil(locator)
        let nanoTDF = initializeSmallNanoTDF(kasResourceLocator: locator!)
        // Validate the Header
        XCTAssertEqual(nanoTDF.header.magicNumber, Data([0x4C, 0x31]))
        XCTAssertEqual(nanoTDF.header.version, Data([0x0C]))
        XCTAssertEqual(nanoTDF.header.kas.protocolEnum, locator!.protocolEnum)
        XCTAssertEqual(nanoTDF.header.kas.body, locator!.body)
        // Validate the Payload
        XCTAssertEqual(nanoTDF.payload.length, 1)
        XCTAssertEqual(nanoTDF.payload.iv, Data([0x07, 0x08, 0x09]))
        // As there signature is nil in this scenario
        XCTAssertNil(nanoTDF.signature)
    }

    func testInitializeSmallNanoTDF_Negative() throws {
        // out of spec - too small
        var locator = ResourceLocator(protocolEnum: .http, body: "")
        XCTAssertNil(locator)
        // out of spec - too large
        let body256Bytes = String(repeating: "a", count: 256)
        locator = ResourceLocator(protocolEnum: .http, body: body256Bytes)
        XCTAssertNil(locator)
        locator = ResourceLocator(protocolEnum: .http, body: "localhost:8080")
        let header = Header(magicNumber: Data([0xFF, 0xFF]),
                            version: Data([0xFF]),
                            kas: locator!,
                            eccMode: PolicyBindingConfig(ecdsaBinding: false,
                                                         curve: .secp256r1),
                            payloadSigMode: SignatureAndPayloadConfig(signed: false,
                                                                      signatureCurve: nil,
                                                                      payloadCipher: .aes256GCM128),
                            policy: Policy(type: .embeddedPlaintext,
                                           body: nil,
                                           remote: nil,
                                           binding: nil,
                                           keyAccess: nil),
                            ephemeralKey: Data([0x04, 0x05, 0x06]))
        XCTAssertNil(header)
    }

    func testSmallNanoTDF_Size() throws {
        let locator = ResourceLocator(protocolEnum: .http, body: "localhost:8080")
        XCTAssertNotNil(locator)
        let nanoTDF = initializeSmallNanoTDF(kasResourceLocator: locator!)
        let data = nanoTDF.toData()
        // TODO: use NanoTDFDecorator
        print("data.count", data.count)
        XCTAssertLessThan(data.count, 240)
    }

    func testSmallNanoTDF_Performance() throws {
        // This is an example of a performance test case.
        measure {
            // Put the code you want to measure the time of here.
        }
    }
}
