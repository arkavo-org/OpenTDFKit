import Foundation

/// Builder pattern for creating TDFManifest with less boilerplate
public struct TDFManifestBuilder {
    public init() {}

    /// Build a standard TDF manifest with common defaults
    public func buildStandardManifest(
        wrappedKey: String,
        kasURL: URL,
        policy: String,
        iv: String,
        mimeType: String = "application/octet-stream",
        tdfSpecVersion: String = "4.3.0",
        policyBinding: TDFPolicyBinding,
        integrityInformation: TDFIntegrityInformation? = nil,
    ) -> TDFManifest {
        let keyAccessObject = TDFKeyAccessObject(
            type: .wrapped,
            url: kasURL.absoluteString,
            protocolValue: .kas,
            wrappedKey: wrappedKey,
            policyBinding: policyBinding,
            encryptedMetadata: nil,
            kid: nil,
            sid: nil,
            schemaVersion: "1.0",
            ephemeralPublicKey: nil,
        )

        let method = TDFMethodDescriptor(
            algorithm: "AES-256-GCM",
            iv: iv,
            isStreamable: true,
        )

        let encryptionInformation = TDFEncryptionInformation(
            type: .split,
            keyAccess: [keyAccessObject],
            method: method,
            integrityInformation: integrityInformation,
            policy: policy,
        )

        let payloadDescriptor = TDFPayloadDescriptor(
            type: .reference,
            url: "0.payload",
            protocolValue: .zip,
            isEncrypted: true,
            mimeType: mimeType,
        )

        return TDFManifest(
            schemaVersion: tdfSpecVersion,
            payload: payloadDescriptor,
            encryptionInformation: encryptionInformation,
            assertions: nil,
        )
    }

    /// Build a manifest with multiple KAS objects (split key scenario)
    public func buildMultiKASManifest(
        keyAccessObjects: [TDFKeyAccessObject],
        policy: String,
        iv: String,
        mimeType: String = "application/octet-stream",
        tdfSpecVersion: String = "4.3.0",
        integrityInformation: TDFIntegrityInformation? = nil,
    ) -> TDFManifest {
        let method = TDFMethodDescriptor(
            algorithm: "AES-256-GCM",
            iv: iv,
            isStreamable: true,
        )

        let encryptionInformation = TDFEncryptionInformation(
            type: .split,
            keyAccess: keyAccessObjects,
            method: method,
            integrityInformation: integrityInformation,
            policy: policy,
        )

        let payloadDescriptor = TDFPayloadDescriptor(
            type: .reference,
            url: "0.payload",
            protocolValue: .zip,
            isEncrypted: true,
            mimeType: mimeType,
        )

        return TDFManifest(
            schemaVersion: tdfSpecVersion,
            payload: payloadDescriptor,
            encryptionInformation: encryptionInformation,
            assertions: nil,
        )
    }
}
