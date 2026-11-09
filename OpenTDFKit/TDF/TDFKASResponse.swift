@preconcurrency import CryptoKit
import Foundation

// MARK: - Build a Rewrap response (KAS side)

public extension TDFKAS {
    /// A key access object's outcome in a Rewrap response.
    enum ResultStatus: String, Sendable {
        case permit
        case fail
    }

    /// One key access object's result: a permit carries the share wrapped to the
    /// client's key (`TDFKAS.rewrap`'s `wrappedKey`); a fail carries none.
    struct KeyAccessResult: Sendable {
        public let keyAccessObjectId: String
        public let status: ResultStatus
        public let kasWrappedKey: Data?
        public let error: String?
        /// Passed through to the client as is (for example an owner KAS's signed
        /// decision record).
        public let metadata: [String: KASRewrapClient.RewrapMetadataValue]

        public init(
            keyAccessObjectId: String,
            status: ResultStatus,
            kasWrappedKey: Data?,
            error: String?,
            metadata: [String: KASRewrapClient.RewrapMetadataValue],
        ) {
            self.keyAccessObjectId = keyAccessObjectId
            self.status = status
            self.kasWrappedKey = kasWrappedKey
            self.error = error
            self.metadata = metadata
        }
    }

    /// The results for one policy request.
    struct PolicyResponse: Sendable {
        public let policyId: String
        public let results: [KeyAccessResult]

        public init(policyId: String, results: [KeyAccessResult]) {
            self.policyId = policyId
            self.results = results
        }
    }

    /// Builds the Rewrap response body `KASRewrapClient` parses:
    /// `{"sessionPublicKey": <PEM>, "responses": [{"policyId", "results":
    /// [{"keyAccessObjectId", "status", "kasWrappedKey", "error", "metadata"}]}]}`.
    /// `status` is `permit` or `fail`, `kasWrappedKey` is standard base64, and
    /// absent fields (and empty metadata) are omitted.
    /// - Parameter sessionPublicKey: `TDFKAS.rewrap`'s session key; `nil` when
    ///   nothing was permitted.
    /// - Throws: `TDFKASError.invalidResult` for a permit without a wrapped key
    ///   or without a session key, or a fail with a wrapped key.
    static func rewrapResponseBody(
        sessionPublicKey: P256.KeyAgreement.PublicKey?,
        responses: [PolicyResponse],
    ) throws -> Data {
        let wire = try WireResponse(
            sessionPublicKey: sessionPublicKey?.pemRepresentation,
            responses: responses.map { response in
                try WireResponse.Policy(
                    policyId: response.policyId,
                    results: response.results.map { result in
                        switch (result.status, result.kasWrappedKey) {
                        case (.permit, nil):
                            throw TDFKASError.invalidResult("permit without kasWrappedKey")
                        case (.permit, .some) where sessionPublicKey == nil:
                            throw TDFKASError.invalidResult("permit without sessionPublicKey")
                        case (.fail, .some):
                            throw TDFKASError.invalidResult("fail with kasWrappedKey")
                        default:
                            break
                        }
                        return WireResponse.Result(
                            keyAccessObjectId: result.keyAccessObjectId,
                            status: result.status.rawValue,
                            kasWrappedKey: result.kasWrappedKey?.base64EncodedString(),
                            error: result.error,
                            metadata: result.metadata.isEmpty ? nil : result.metadata,
                        )
                    },
                )
            },
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(wire)
    }
}

// MARK: - Wire types

private struct WireResponse: Encodable {
    struct Policy: Encodable {
        let policyId: String
        let results: [Result]
    }

    struct Result: Encodable {
        let keyAccessObjectId: String
        let status: String
        let kasWrappedKey: String?
        let error: String?
        let metadata: [String: KASRewrapClient.RewrapMetadataValue]?
    }

    let sessionPublicKey: String?
    let responses: [Policy]
}
