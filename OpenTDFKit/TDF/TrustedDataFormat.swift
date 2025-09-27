import Foundation
@preconcurrency import ZIPFoundation

/// Supported Trusted Data Format variants.
public enum TrustedDataFormatKind: Sendable {
    case nano
    case standard
}

/// Format-agnostic container interface allowing shared tooling.
public protocol TrustedDataContainer: Sendable {
    var formatKind: TrustedDataFormatKind { get }
    func serializedData() throws -> Data
}

public struct StandardTDFContainer: TrustedDataContainer {
    public enum PayloadStorage: Sendable {
        case inMemory(Data)
        case fileURL(URL)
    }

    public var manifest: TDFManifest
    public var payload: PayloadStorage
    public var compression: ZIPFoundation.CompressionMethod

    public init(
        manifest: TDFManifest,
        payload: PayloadStorage,
        compression: ZIPFoundation.CompressionMethod = .deflate
    ) {
        self.manifest = manifest
        self.payload = payload
        self.compression = compression
    }

    public var formatKind: TrustedDataFormatKind { .standard }

    public func serializedData() throws -> Data {
        let writer = TDFArchiveWriter(compressionMethod: compression)
        switch payload {
        case let .inMemory(data):
            return try writer.buildArchive(manifest: manifest, payload: data)
        case let .fileURL(url):
            return try writer.buildArchive(manifest: manifest, payloadURL: url)
        }
    }

    public func payloadData() throws -> Data {
        switch payload {
        case let .inMemory(data):
            return data
        case let .fileURL(url):
            return try Data(contentsOf: url)
        }
    }
}

public enum StandardTDFError: Error {
    case invalidPayloadLocator
}
