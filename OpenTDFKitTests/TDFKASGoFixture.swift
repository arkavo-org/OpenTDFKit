import Foundation
@testable import OpenTDFKit

/// A TDF `ec-wrapped` fixture produced by go, for interop tests.
///
/// Generated with `scripts/interop/ec-wrapped` (`go run . generate`) using
/// `github.com/opentdf/platform/lib/ocrypto` v0.14.0. The key access object is
/// written the way the go SDK's `generateWrapKeyWithEC` writes it, with a
/// spec-form policy binding; the response is sealed the way the platform KAS
/// seals a rewrap response (`FromPublicPEMWithSalt(…, TDFSalt(), nil)`).
/// The keys are test-only. Paste regenerated output verbatim.
enum TDFKASGoFixture {
    static let json = #"""
    {
      "kasPrivateKeyPEM": "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghweFQhphb8Lrauj4\ngJFzdsntNFr4l1ShW7xEzRfT3i+hRANCAASntnUsgzAEhJwwIigaz2hJ5BhCUTD8\nIwr6amBePzDhBfUr5c+KeqqHjQDBzMewqbmnWb4YqpWwHBB41ZmEknPS\n-----END PRIVATE KEY-----\n",
      "policyBase64": "eyJ1dWlkIjoiNTk3MGFiYTA0MDMzN2M1MDI2NjY3OGU1MGUxNmYyNmEiLCJib2R5Ijp7ImRhdGFBdHRyaWJ1dGVzIjpbXSwiZGlzc2VtIjpbImludGVyb3BAZXhhbXBsZS5jb20iXX19",
      "kao": {
        "type": "ec-wrapped",
        "url": "https://kas.example.com",
        "protocol": "kas",
        "wrappedKey": "hZAhO9vauzJcmEE7gDcHrtPVB23hocMuSahynpk/LuUb5nHA2Bf2oNv5KIFc+sFsyGWheONfXZzO/md2",
        "policyBinding": {
          "alg": "HS256",
          "hash": "x9uIIft5a5NWqoh11ZyDgkiPEFs1W9NBfJpjgYYsy8g="
        },
        "kid": "e1",
        "schemaVersion": "1.0",
        "ephemeralPublicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcwk8wg5dqdX6AkKV0tKJAZUOTpIm\n+VC7DVP/q7jVsaCMsGaKydfehJXeE1xA70D5emk0eHnXRGgDTtkHxqd5JQ==\n-----END PUBLIC KEY-----\n"
      },
      "dekBase64": "ipNR5VUgfpWh/DjgDOxhEn91u5ssZFtH0F+sh99YJjk=",
      "receiverPrivateKeyPEM": "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgl9QYa3BirblQa2nc\nFF+0sdnx8OKE1ZFcfVdX8bR9FY2hRANCAATI0d+F2ppE5jV2w5QooAS2y2t6bXzr\no+fog3ozbW2VTDN52MB5/zC97eLMmO9tJukTrZpxTl7xkr6AkvVuCKWB\n-----END PRIVATE KEY-----\n",
      "response": {
        "wrappedKeyBase64": "SACl2IFUyamGDbRzPX77ygYfdkLbrJY6Qu1QPoXGXV5O2pglyc9es1Z7RbMO1ax5sAwKY0pp+R7d+pTv",
        "sessionPublicKeyPEM": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVyorF3XWehWzEPezbbaekVn8Ul/Y\nK5o4zvdc13+THoEUYYHnXQweLD5ENaOog/qJHU/duHXqKF/Qh8ED19TFqA==\n-----END PUBLIC KEY-----\n"
      }
    }
    """#
}

/// The decoded form of `TDFKASGoFixture.json`. The Swift → go check
/// (`TDFKASEncryptorTests.testWriteSwiftFixtureForGo`) writes the same shape.
struct GoFixture: Codable {
    struct Response: Codable {
        let wrappedKeyBase64: String
        let sessionPublicKeyPEM: String
    }

    let kasPrivateKeyPEM: String
    let policyBase64: String
    let kao: TDFKeyAccessObject
    let dekBase64: String
    let receiverPrivateKeyPEM: String
    let response: Response

    static func load() throws -> GoFixture {
        try JSONDecoder().decode(GoFixture.self, from: Data(TDFKASGoFixture.json.utf8))
    }
}
