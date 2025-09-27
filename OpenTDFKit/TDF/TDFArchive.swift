import Foundation
@preconcurrency import ZIPFoundation

private let manifestEntryName = "0.manifest.json"
private let payloadEntryName = "0.payload"

public struct TDFArchiveReader {
    public static let defaultManifestMaxSize = 10 * 1024 * 1024

    private let archive: ZIPFoundation.Archive

    public init(data: Data) throws {
        do {
            archive = try ZIPFoundation.Archive(data: data, accessMode: .read)
        } catch {
            throw TDFArchiveError.unreadableArchive
        }
    }

    public init(url: URL) throws {
        do {
            archive = try ZIPFoundation.Archive(url: url, accessMode: .read)
        } catch {
            throw TDFArchiveError.unreadableArchive
        }
    }

    public func manifestData(maxSize: Int = TDFArchiveReader.defaultManifestMaxSize) throws -> Data {
        guard let entry = archive[manifestEntryName] else {
            throw TDFArchiveError.missingManifest
        }
        var total = 0
        var result = Data()
        let _ = try archive.extract(entry) { chunk in
            total += chunk.count
            if total > maxSize {
                throw TDFArchiveError.manifestTooLarge
            }
            result.append(chunk)
        }
        return result
    }

    public func manifest(maxSize: Int = TDFArchiveReader.defaultManifestMaxSize) throws -> TDFManifest {
        let data = try manifestData(maxSize: maxSize)
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(TDFManifest.self, from: data)
    }

    public func payloadSize() throws -> Int64 {
        guard let entry = archive[payloadEntryName] else {
            throw TDFArchiveError.missingPayload
        }
        return Int64(entry.uncompressedSize)
    }

    public func payloadData() throws -> Data {
        guard let entry = archive[payloadEntryName] else {
            throw TDFArchiveError.missingPayload
        }
        var result = Data(capacity: Int(entry.uncompressedSize))
        let _ = try archive.extract(entry) { chunk in
            result.append(chunk)
        }
        return result
    }

    public func writePayload(to handle: FileHandle) throws {
        guard let entry = archive[payloadEntryName] else {
            throw TDFArchiveError.missingPayload
        }
        _ = try archive.extract(entry) { chunk in
            try handle.write(contentsOf: chunk)
        }
    }
}

public struct TDFArchiveWriter {
    public var compressionMethod: ZIPFoundation.CompressionMethod

    public init(compressionMethod: ZIPFoundation.CompressionMethod = .deflate) {
        self.compressionMethod = compressionMethod
    }

    public func buildArchive(manifest: TDFManifest, payload: Data) throws -> Data {
        let archive: ZIPFoundation.Archive
        do {
            archive = try ZIPFoundation.Archive(data: Data(), accessMode: .create)
        } catch {
            throw TDFArchiveError.creationFailed
        }
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.outputFormatting = [.sortedKeys]
        let manifestData = try encoder.encode(manifest)
        try addEntry(named: manifestEntryName, data: manifestData, to: archive)
        try addEntry(named: payloadEntryName, data: payload, to: archive)
        guard let resultData = archive.data else {
            throw TDFArchiveError.creationFailed
        }
        return resultData
    }

    public func buildArchive(manifest: TDFManifest, payloadURL: URL) throws -> Data {
        let payloadData = try Data(contentsOf: payloadURL)
        return try buildArchive(manifest: manifest, payload: payloadData)
    }

    private func addEntry(named name: String, data: Data, to archive: ZIPFoundation.Archive) throws {
        try archive.addEntry(
            with: name,
            type: .file,
            uncompressedSize: Int64(data.count),
            compressionMethod: compressionMethod,
            bufferSize: ZIPFoundation.defaultWriteChunkSize,
            provider: { position, size -> Data in
                let start = Int(position)
                guard start < data.count, size > 0 else {
                    return Data()
                }
                let upper = min(start + size, data.count)
                return data.subdata(in: start ..< upper)
            }
        )
    }
}

public enum TDFArchiveError: Error, CustomStringConvertible {
    case unreadableArchive
    case missingManifest
    case missingPayload
    case manifestTooLarge
    case creationFailed

    public var description: String {
        switch self {
        case .unreadableArchive:
            return "Unable to read TDF archive: invalid ZIP format or corrupted file"
        case .missingManifest:
            return "Missing manifest: 0.manifest.json not found in archive"
        case .missingPayload:
            return "Missing payload: 0.payload not found in archive"
        case .manifestTooLarge:
            return "Manifest exceeds maximum allowed size"
        case .creationFailed:
            return "Failed to create TDF archive"
        }
    }
}
