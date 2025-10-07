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

        try validateEntryPath(entry.path)

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

        try validateEntryPath(entry.path)

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

        try validateEntryPath(entry.path)

        _ = try archive.extract(entry) { chunk in
            try handle.write(contentsOf: chunk)
        }
    }

    private func validateEntryPath(_ path: String) throws {
        if path.contains("../") || path.hasPrefix("/") || path.contains("\\") {
            throw TDFArchiveError.maliciousPath
        }

        let normalizedPath = path.replacingOccurrences(of: "//", with: "/")
        if normalizedPath != path {
            throw TDFArchiveError.maliciousPath
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

    /// Build archive directly to file, avoiding memory overhead for large payloads
    public func buildArchiveToFile(manifest: TDFManifest, payload: Data, outputURL: URL) throws {
        let archiveData = try buildArchive(manifest: manifest, payload: payload)
        try archiveData.write(to: outputURL)
    }

    /// Build archive directly to file from payload file, avoiding double memory load
    public func buildArchiveToFile(manifest: TDFManifest, payloadURL: URL, outputURL: URL) throws {
        let archiveData = try buildArchive(manifest: manifest, payloadURL: payloadURL)
        try archiveData.write(to: outputURL)
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
            },
        )
    }
}

public enum TDFArchiveError: Error, CustomStringConvertible, Equatable {
    case unreadableArchive
    case missingManifest
    case missingPayload
    case manifestTooLarge
    case creationFailed
    case maliciousPath

    public var description: String {
        switch self {
        case .unreadableArchive:
            "Unable to read TDF archive: invalid ZIP format or corrupted file"
        case .missingManifest:
            "Missing manifest: 0.manifest.json not found in archive"
        case .missingPayload:
            "Missing payload: 0.payload not found in archive"
        case .manifestTooLarge:
            "Manifest exceeds maximum allowed size"
        case .creationFailed:
            "Failed to create TDF archive"
        case .maliciousPath:
            "Archive contains unsafe path: path traversal detected"
        }
    }
}
