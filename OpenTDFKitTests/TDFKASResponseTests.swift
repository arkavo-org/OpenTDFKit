@preconcurrency import CryptoKit
import Foundation
@testable import OpenTDFKit
import XCTest

/// `TDFKAS.rewrapResponseBody`: the owner KAS's Rewrap response, for ALLOW and
/// DENY alike, in the shape `KASRewrapClient` parses.
final class TDFKASResponseTests: XCTestCase {
    typealias Value = KASRewrapClient.RewrapMetadataValue

    func testPermitAndFailShape() throws {
        let session = P256.KeyAgreement.PrivateKey().publicKey
        let wrapped = Data((0 ..< 60).map { UInt8($0) })
        let body = try TDFKAS.rewrapResponseBody(sessionPublicKey: session, responses: [
            TDFKAS.PolicyResponse(policyId: "policy", results: [
                TDFKAS.KeyAccessResult(keyAccessObjectId: "kao-0", status: .permit, kasWrappedKey: wrapped,
                                       error: nil, metadata: ["arkavo.decision": .string("ZGVj")]),
                TDFKAS.KeyAccessResult(keyAccessObjectId: "kao-1", status: .fail, kasWrappedKey: nil,
                                       error: "ACCESS_DENIED", metadata: [:]),
            ]),
        ])
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(json["sessionPublicKey"] as? String, session.pemRepresentation)
        let response = try XCTUnwrap((json["responses"] as? [[String: Any]])?.first)
        XCTAssertEqual(response["policyId"] as? String, "policy")
        let results = try XCTUnwrap(response["results"] as? [[String: Any]])
        XCTAssertEqual(results[0]["keyAccessObjectId"] as? String, "kao-0")
        XCTAssertEqual(results[0]["status"] as? String, "permit")
        XCTAssertEqual(results[0]["kasWrappedKey"] as? String, wrapped.base64EncodedString())
        XCTAssertNil(results[0]["error"])
        XCTAssertEqual((results[0]["metadata"] as? [String: Any])?["arkavo.decision"] as? String, "ZGVj")
        XCTAssertEqual(results[1]["status"] as? String, "fail")
        XCTAssertNil(results[1]["kasWrappedKey"])
        XCTAssertEqual(results[1]["error"] as? String, "ACCESS_DENIED")
        XCTAssertNil(results[1]["metadata"], "empty metadata is omitted")
    }

    func testMetadataAllValueTypes() throws {
        let metadata: [String: Value] = [
            "s": .string("x/é"), "n": .number(42), "b": .bool(true), "z": .null,
            "a": .array([.string("one"), .number(2)]), "o": .object(["k": .bool(false)]),
        ]
        let body = try TDFKAS.rewrapResponseBody(sessionPublicKey: nil, responses: [
            TDFKAS.PolicyResponse(policyId: "policy", results: [
                TDFKAS.KeyAccessResult(keyAccessObjectId: "kao-0", status: .fail, kasWrappedKey: nil,
                                       error: "ACCESS_DENIED", metadata: metadata),
            ]),
        ])
        let decoded = try JSONDecoder().decode(Wire.self, from: body)
        XCTAssertEqual(decoded.responses[0].results[0].metadata, metadata)
    }

    func testDenyWithoutSessionKey() throws {
        let body = try TDFKAS.rewrapResponseBody(sessionPublicKey: nil, responses: [
            TDFKAS.PolicyResponse(policyId: "policy", results: [
                TDFKAS.KeyAccessResult(keyAccessObjectId: "kao-0", status: .fail, kasWrappedKey: nil,
                                       error: "ACCESS_REVOKED", metadata: [:]),
            ]),
        ])
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertNil(json["sessionPublicKey"])
    }

    func testInvalidCombinationsRefused() {
        let cases = [
            TDFKAS.KeyAccessResult(keyAccessObjectId: "kao-0", status: .permit, kasWrappedKey: nil,
                                   error: nil, metadata: [:]),
            TDFKAS.KeyAccessResult(keyAccessObjectId: "kao-0", status: .fail, kasWrappedKey: Data([1]),
                                   error: "ACCESS_DENIED", metadata: [:]),
        ]
        for result in cases {
            XCTAssertThrowsError(try TDFKAS.rewrapResponseBody(
                sessionPublicKey: P256.KeyAgreement.PrivateKey().publicKey,
                responses: [TDFKAS.PolicyResponse(policyId: "policy", results: [result])],
            )) { error in
                guard case .invalidResult = error as? TDFKASError else {
                    return XCTFail("expected invalidResult, got \(error)")
                }
            }
        }
    }

    func testPermitWithoutSessionKeyRefused() {
        XCTAssertThrowsError(try TDFKAS.rewrapResponseBody(sessionPublicKey: nil, responses: [
            TDFKAS.PolicyResponse(policyId: "policy", results: [
                TDFKAS.KeyAccessResult(keyAccessObjectId: "kao-0", status: .permit, kasWrappedKey: Data([1]),
                                       error: nil, metadata: [:]),
            ]),
        ])) { error in
            guard case .invalidResult = error as? TDFKASError else {
                return XCTFail("expected invalidResult, got \(error)")
            }
        }
    }

    private struct Wire: Decodable {
        struct Response: Decodable {
            struct Result: Decodable {
                let metadata: [String: Value]?
            }

            let results: [Result]
        }

        let responses: [Response]
    }
}
