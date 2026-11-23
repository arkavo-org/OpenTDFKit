import Foundation

public struct TDFBuilder {
    public init() {}

    public func container(manifest: TDFManifest, payload: Data) -> TDFContainer {
        TDFContainer(manifest: manifest, payload: payload)
    }

    public func container(manifest: TDFManifest, payloadURL: URL) throws -> TDFContainer {
        let payload = try Data(contentsOf: payloadURL)
        return TDFContainer(manifest: manifest, payload: payload)
    }
}

public struct TDFLoader {
    /// Largest payload `load` accepts, in bytes; `nil` for no cap.
    public let maxPayloadSize: Int?

    /// - Parameter maxPayloadSize: Upper bound on payload bytes read into memory;
    ///   defaults to `TDFArchiveReader.defaultPayloadMaxSize` (512 MiB). Pass
    ///   `nil` explicitly to opt out of the cap.
    public init(maxPayloadSize: Int? = TDFArchiveReader.defaultPayloadMaxSize) {
        self.maxPayloadSize = maxPayloadSize
    }

    public func load(from data: Data) throws -> TDFContainer {
        let reader = try TDFArchiveReader(data: data)
        let manifest = try reader.manifest()
        let payload = try reader.payloadData(maxSize: maxPayloadSize)
        return TDFContainer(manifest: manifest, payload: payload)
    }

    public func load(from url: URL) throws -> TDFContainer {
        let reader = try TDFArchiveReader(url: url)
        let manifest = try reader.manifest()
        let payload = try reader.payloadData(maxSize: maxPayloadSize)
        return TDFContainer(manifest: manifest, payload: payload)
    }
}
