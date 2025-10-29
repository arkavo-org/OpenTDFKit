import Foundation
@preconcurrency import ZIPFoundation

/// Supported Trusted Data Format variants.
public enum TrustedDataFormatKind: Sendable {
    case nano
    case archive
}

/// Format-agnostic container interface allowing shared tooling.
public protocol TrustedDataContainer: Sendable {
    var formatKind: TrustedDataFormatKind { get }
    func serializedData() throws -> Data
}

public struct TDFContainer: TrustedDataContainer {
    public var manifest: TDFManifest
    public var payload: Data
    public var compression: ZIPFoundation.CompressionMethod

    public init(
        manifest: TDFManifest,
        payload: Data,
        compression: ZIPFoundation.CompressionMethod = .none,
    ) {
        self.manifest = manifest
        self.payload = payload
        self.compression = compression
    }

    public var formatKind: TrustedDataFormatKind { .archive }

    public func serializedData() throws -> Data {
        let writer = TDFArchiveWriter(compressionMethod: compression)
        return try writer.buildArchive(manifest: manifest, payload: payload)
    }

    public func payloadData() throws -> Data {
        payload
    }
}
