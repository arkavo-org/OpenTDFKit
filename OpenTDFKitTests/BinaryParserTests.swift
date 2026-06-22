import Foundation
@testable import OpenTDFKit
import XCTest

final class BinaryParserTests: XCTestCase {
    func testInvalidMagicNumberThrows() {
        let data = Data([0x00, 0x00, 0x4C])
        let parser = BinaryParser(data: data)

        XCTAssertThrowsError(try parser.parseHeader()) { error in
            guard let parsingError = error as? ParsingError,
                  case .invalidMagicNumber = parsingError
            else {
                XCTFail("Expected ParsingError.invalidMagicNumber, got \(error)")
                return
            }
        }
    }

    func testInvalidVersionThrows() {
        // Valid magic number ("L1") followed by unsupported v13 (0x4D)
        let data = Data([0x4C, 0x31, 0x4D])
        let parser = BinaryParser(data: data)

        XCTAssertThrowsError(try parser.parseHeader()) { error in
            guard let parsingError = error as? ParsingError,
                  case .invalidVersion = parsingError
            else {
                XCTFail("Expected ParsingError.invalidVersion, got \(error)")
                return
            }
        }
    }

    func testTruncatedHeaderThrowsInvalidFormat() {
        // Magic + version only; missing KAS locator, ECC mode, payload config, policy, and ephemeral key
        let data = Data([0x4C, 0x31, 0x4C])
        let parser = BinaryParser(data: data)

        XCTAssertThrowsError(try parser.parseHeader()) { error in
            guard let parsingError = error as? ParsingError,
                  case .invalidFormat = parsingError
            else {
                XCTFail("Expected ParsingError.invalidFormat, got \(error)")
                return
            }
        }
    }

    func testMissingEphemeralKeyThrowsInvalidFormat() {
        // Valid magic + version + valid KAS locator + valid ECC mode + valid payload config + remote policy
        var data = Data()
        data.append(Header.magicNumber)
        data.append(Header.versionV12)
        data.append(ResourceLocator(protocolEnum: .http, body: "kas.example.com")!.toData())
        data.append(PolicyBindingConfig(ecdsaBinding: false, curve: .secp256r1).toData())
        data.append(SignatureAndPayloadConfig(signed: false, signatureCurve: nil, payloadCipher: .aes256GCM128).toData())
        data.append(Policy.PolicyType.remote.rawValue)
        data.append(ResourceLocator(protocolEnum: .http, body: "kas.example.com/policy")!.toData())
        data.append(Data(count: 8)) // placeholder GMAC binding
        // Intentionally omit the ephemeral public key

        let parser = BinaryParser(data: data)
        XCTAssertThrowsError(try parser.parseHeader()) { error in
            guard let parsingError = error as? ParsingError,
                  case .invalidFormat = parsingError
            else {
                XCTFail("Expected ParsingError.invalidFormat, got \(error)")
                return
            }
        }
    }

    func testMalformedResourceLocatorThrows() {
        var data = Data()
        data.append(Header.magicNumber)
        data.append(Header.versionV12)
        // Protocol byte with invalid protocol value (0xFF) and zero-length body
        data.append(contentsOf: [0xFF, 0x00])

        let parser = BinaryParser(data: data)
        XCTAssertThrowsError(try parser.parseHeader()) { error in
            guard let parsingError = error as? ParsingError,
                  case .invalidFormat = parsingError
            else {
                XCTFail("Expected ParsingError.invalidFormat, got \(error)")
                return
            }
        }
    }
}
