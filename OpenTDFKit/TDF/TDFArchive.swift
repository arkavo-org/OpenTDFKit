import Foundation
@preconcurrency import ZIPFoundation

/// Zip member names for the TDF container (opentdf/spec schema/OpenTDF/README.md).
public enum TDFArchiveEntryNames {
    /// The manifest MUST be `manifest.json` at the archive root.
    public static let manifest = "manifest.json"
    /// Name every SDK wrote before spec compliance; accepted on read forever.
    public static let legacyManifest = "0.manifest.json"
    /// Default payload member; writers put this same value in `payload.url`.
    public static let payload = "0.payload"

    static func isSafe(_ name: String) -> Bool {
        if name.isEmpty || name.hasPrefix("/") || name.contains("\\") {
            return false
        }
        return !name.split(separator: "/", omittingEmptySubsequences: false).contains("..")
    }

    /// Payload member for a manifest: `payload.url`, or `0.payload` when empty.
    static func payloadEntry(for manifest: TDFManifest) throws -> String {
        let url = manifest.payload.url
        if url.isEmpty {
            return payload
        }
        guard isSafe(url) else { throw TDFArchiveError.unsafePayloadURL(url) }
        return url
    }
}

/// Reference-type box holding the decoded manifest so `TDFArchiveReader` (a `public struct`
/// used as `let` by callers, with non-`mutating` methods) can cache across calls without
/// changing its value-type API.
private final class ManifestCache {
    var manifest: TDFManifest?
    var maxSize: Int?
}

public struct TDFArchiveReader {
    public static let defaultManifestMaxSize = 10 * 1024 * 1024

    private let archive: ZIPFoundation.Archive
    private let cache = ManifestCache()

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

    private func manifestEntry() throws -> ZIPFoundation.Entry {
        if let e = archive[TDFArchiveEntryNames.manifest] {
            return e
        }
        if let e = archive[TDFArchiveEntryNames.legacyManifest] {
            return e
        }
        throw TDFArchiveError.missingManifest
    }

    private func payloadEntry() throws -> ZIPFoundation.Entry {
        let name = try TDFArchiveEntryNames.payloadEntry(for: manifest())
        guard let entry = archive[name] else {
            if name == TDFArchiveEntryNames.payload {
                throw TDFArchiveError.missingPayload
            }
            throw TDFArchiveError.missingPayloadEntry(name)
        }
        try validateEntryPath(entry.path)
        return entry
    }

    public func manifestData(maxSize: Int = TDFArchiveReader.defaultManifestMaxSize) throws -> Data {
        let entry = try manifestEntry()
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

    /// Decodes and returns the manifest, caching the result after the first successful decode.
    ///
    /// `payloadData()`, `payloadSize()`, and `writePayload(to:)` all resolve `payload.url` via
    /// this method, and `TDFLoader.load` also calls it directly; without caching, the manifest
    /// JSON would be parsed twice per load. The decoded value is cached on first success, and
    /// later calls return the cached manifest without re-reading or re-decoding, ignoring
    /// `maxSize` on the cache hit.
    ///
    /// `maxSize` semantics with caching: a smaller `maxSize` passed after a cached success is
    /// still safe to ignore, because the cached decode already completed under a
    /// larger-or-equal cap (i.e. the manifest is known to fit). A failed decode (for example
    /// `TDFArchiveError.manifestTooLarge`) is never cached, so a later call — even with a
    /// larger `maxSize` — re-reads and re-decodes normally.
    ///
    /// Thread-safety: `TDFArchiveReader` is not `Sendable`. This cache uses a plain (unlocked)
    /// reference box, so concurrent `manifest()` calls on the same reader instance from
    /// multiple threads are not supported.
    public func manifest(maxSize: Int = TDFArchiveReader.defaultManifestMaxSize) throws -> TDFManifest {
        if let cached = cache.manifest {
            return cached
        }
        let data = try manifestData(maxSize: maxSize)
        let decoded = try JSONDecoder().decode(TDFManifest.self, from: data)
        cache.manifest = decoded
        cache.maxSize = maxSize
        return decoded
    }

    public func payloadSize() throws -> Int64 {
        try Int64(payloadEntry().uncompressedSize)
    }

    public func payloadData() throws -> Data {
        let entry = try payloadEntry()
        var result = Data(capacity: Int(entry.uncompressedSize))
        let _ = try archive.extract(entry) { chunk in
            result.append(chunk)
        }
        return result
    }

    public func writePayload(to handle: FileHandle) throws {
        let entry = try payloadEntry()
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

    public init(compressionMethod: ZIPFoundation.CompressionMethod = .none) {
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
        let payloadName = try TDFArchiveEntryNames.payloadEntry(for: manifest)
        try addEntry(named: TDFArchiveEntryNames.manifest, data: manifestData, to: archive)
        try addEntry(named: payloadName, data: payload, to: archive)
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
    case missingPayloadEntry(String)
    case unsafePayloadURL(String)
    case manifestTooLarge
    case creationFailed
    case maliciousPath

    public var description: String {
        switch self {
        case .unreadableArchive:
            "Unable to read TDF archive: invalid ZIP format or corrupted file"
        case .missingManifest:
            "Missing manifest: neither manifest.json nor 0.manifest.json found in archive"
        case .missingPayload:
            "Missing payload: 0.payload not found in archive"
        case let .missingPayloadEntry(name):
            "Missing payload: manifest payload.url names '\(name)', which is not in the archive"
        case let .unsafePayloadURL(url):
            "Unsafe payload url in manifest: '\(url)'"
        case .manifestTooLarge:
            "Manifest exceeds maximum allowed size"
        case .creationFailed:
            "Failed to create TDF archive"
        case .maliciousPath:
            "Archive contains unsafe path: path traversal detected"
        }
    }
}
