@testable import OpenTDFKit
import XCTest

/// Initializes a basic, small NanoTDF object, primarily useful for testing or simple examples.
/// Uses placeholder values for ephemeral keys and payload.
/// - Parameter kasResourceLocator: The `ResourceLocator` for the KAS.
/// - Returns: A minimally initialized `NanoTDF` object.
func initializeSmallNanoTDF(kasResourceLocator: ResourceLocator) -> NanoTDF {
    let curve: Curve = .secp256r1 // Default curve for this example
    
    // Create a PayloadKeyAccess structure with the KAS ResourceLocator
    let payloadKeyAccess = PayloadKeyAccess(
        kasEndpointLocator: kasResourceLocator,
        kasKeyCurve: curve,
        kasPublicKey: Data([0x02, 0x03, 0x04]) // Placeholder compressed public key
    )
    
    // Create a placeholder header
    let header = Header(
        payloadKeyAccess: payloadKeyAccess,
        policyBindingConfig: PolicyBindingConfig(ecdsaBinding: false, curve: curve), // GMAC binding
        payloadSignatureConfig: SignatureAndPayloadConfig(signed: false, signatureCurve: curve, payloadCipher: .aes256GCM128), // Not signed, AES-256-GCM-128
        policy: Policy(type: .remote, body: nil, remote: kasResourceLocator, binding: nil), // Remote policy pointing to KAS URL, no binding yet
        ephemeralPublicKey: Data([0x04, 0x05, 0x06]) // Placeholder ephemeral public key
    )

    // Create a placeholder payload
    let payload = Payload(
        length: 7, // Minimal length (3 IV + 1 Ciphertext + 3 Placeholder MAC)
        iv: Data([0x07, 0x08, 0x09]), // Placeholder IV
        ciphertext: Data([0x00]), // Placeholder ciphertext
        mac: Data([0x13, 0x14, 0x15]) // Placeholder MAC tag (incorrect size for AES-GCM-128)
    )

    // Return the NanoTDF object
    return NanoTDF(header: header,
                   payload: payload,
                   signature: nil) // No signature
}

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
        XCTAssertEqual(nanoTDF.header.kas.protocolEnum, locator!.protocolEnum)
        XCTAssertEqual(nanoTDF.header.kas.body, locator!.body)
        // Validate the Payload
        XCTAssertEqual(nanoTDF.payload.length, 7)
        XCTAssertEqual(nanoTDF.payload.iv, Data([0x07, 0x08, 0x09]))
        // As there signature is nil in this scenario
        XCTAssertNil(nanoTDF.signature)
    }

    func testInitializeSmallNanoTDFNegative() throws {
        // Empty body is now allowed for HTTP and HTTPS due to "None" identifier support
        // We'll just test the too-large case
        
        // out of spec - too large
        let body256Bytes = String(repeating: "a", count: 256)
        let locator = ResourceLocator(protocolEnum: .http, body: body256Bytes)
        XCTAssertNil(locator)

        // Create a valid locator
        let validLocator = ResourceLocator(protocolEnum: .http, body: "localhost:8080")
        XCTAssertNotNil(validLocator)

        // Test valid header creation
        XCTAssertNoThrow(Header(
            kas: validLocator!,
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
