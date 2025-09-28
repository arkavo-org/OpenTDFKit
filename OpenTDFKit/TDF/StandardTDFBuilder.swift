import Foundation

public struct StandardTDFBuilder {
    public init() {}

    public func container(manifest: TDFManifest, payload: Data) -> StandardTDFContainer {
        StandardTDFContainer(manifest: manifest, payload: payload)
    }

    public func container(manifest: TDFManifest, payloadURL: URL) throws -> StandardTDFContainer {
        let payload = try Data(contentsOf: payloadURL)
        return StandardTDFContainer(manifest: manifest, payload: payload)
    }
}

public struct StandardTDFLoader {
    public init() {}

    public func load(from data: Data) throws -> StandardTDFContainer {
        let reader = try TDFArchiveReader(data: data)
        let manifest = try reader.manifest()
        let payload = try reader.payloadData()
        return StandardTDFContainer(manifest: manifest, payload: payload)
    }

    public func load(from url: URL) throws -> StandardTDFContainer {
        let reader = try TDFArchiveReader(url: url)
        let manifest = try reader.manifest()
        let payload = try reader.payloadData()
        return StandardTDFContainer(manifest: manifest, payload: payload)
    }
}
