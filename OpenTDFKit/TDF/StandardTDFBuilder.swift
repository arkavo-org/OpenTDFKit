import Foundation

public struct StandardTDFBuilder {
    public init() {}

    public func container(manifest: TDFManifest, payload: Data) -> StandardTDFContainer {
        StandardTDFContainer(manifest: manifest, payload: StandardTDFContainer.PayloadStorage.inMemory(payload))
    }

    public func container(manifest: TDFManifest, payloadURL: URL) -> StandardTDFContainer {
        StandardTDFContainer(manifest: manifest, payload: StandardTDFContainer.PayloadStorage.fileURL(payloadURL))
    }
}

public struct StandardTDFLoader {
    public init() {}

    public func load(from data: Data) throws -> StandardTDFContainer {
        let reader = try TDFArchiveReader(data: data)
        let manifest = try reader.manifest()
        let payload = try reader.payloadData()
        return StandardTDFContainer(manifest: manifest, payload: StandardTDFContainer.PayloadStorage.inMemory(payload))
    }

    public func load(from url: URL) throws -> StandardTDFContainer {
        let reader = try TDFArchiveReader(url: url)
        let manifest = try reader.manifest()
        let payloadURL = try writePayloadToTemporaryURL(reader: reader)
        return StandardTDFContainer(
            manifest: manifest,
            payload: StandardTDFContainer.PayloadStorage.fileURL(payloadURL)
        )
    }

    private func writePayloadToTemporaryURL(reader: TDFArchiveReader) throws -> URL {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        let filename = UUID().uuidString + ".payload"
        let fileURL = directory.appendingPathComponent(filename, isDirectory: false)
        FileManager.default.createFile(atPath: fileURL.path, contents: nil)
        guard let handle = try? FileHandle(forWritingTo: fileURL) else {
            throw StandardTDFError.invalidPayloadLocator
        }
        defer { try? handle.close() }
        try reader.writePayload(to: handle)
        return fileURL
    }
}
