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
    public init() {}

    public func load(from data: Data) throws -> TDFContainer {
        let reader = try TDFArchiveReader(data: data)
        let manifest = try reader.manifest()
        let payload = try reader.payloadData()
        return TDFContainer(manifest: manifest, payload: payload)
    }

    public func load(from url: URL) throws -> TDFContainer {
        let reader = try TDFArchiveReader(url: url)
        let manifest = try reader.manifest()
        let payload = try reader.payloadData()
        return TDFContainer(manifest: manifest, payload: payload)
    }
}
