import Foundation

/// Format detector for TDF documents.
///
/// Detects the format of TDF data by examining magic bytes and structure.
/// Detection order: CBOR (magic bytes) → ZIP (magic bytes) → JSON (starts with '{')
public enum TDFFormatDetector {
    /// CBOR magic bytes: self-describe CBOR tag.
    /// D9 D9F7 = tag(55799) for self-describe CBOR.
    /// The following byte must be a CBOR map (0xA0-0xBF).
    public static let cborMagic: [UInt8] = [0xD9, 0xD9, 0xF7]

    /// ZIP magic bytes (PK signature)
    public static let zipMagic: [UInt8] = [0x50, 0x4B, 0x03, 0x04]

    /// JSON start character '{'
    public static let jsonStart: UInt8 = 0x7B

    /// NanoTDF magic bytes (version signature)
    public static let nanoMagic: [UInt8] = [0x4C, 0x31] // "L1" for version 1.0

    /// Detect the TDF format from raw data
    ///
    /// - Parameter data: Raw bytes to analyze
    /// - Returns: Detected format kind, or nil if unknown
    public static func detect(from data: Data) -> TrustedDataFormatKind? {
        guard !data.isEmpty else { return nil }

        // Check CBOR magic bytes first (definitive)
        if data.count >= 4 {
            let header = [UInt8](data.prefix(4))
            let prefix = [UInt8](data.prefix(cborMagic.count))
            // Match the self-describe CBOR tag and ensure the next byte is a CBOR map.
            if prefix == cborMagic, header[cborMagic.count] & 0xE0 == 0xA0 {
                return .cbor
            }
        }

        // Check ZIP magic bytes (definitive for archive TDF)
        if data.count >= 4 {
            let header = [UInt8](data.prefix(4))
            if header == zipMagic {
                return .archive
            }
        }

        // Check NanoTDF magic
        if data.count >= 2 {
            let header = [UInt8](data.prefix(2))
            if header == nanoMagic {
                return .nano
            }
        }

        // Check for JSON (speculative - starts with '{')
        if data.first == jsonStart,
           // Try to validate it's actually JSON with TDF structure
           isTDFJSON(data)
        {
            return .json
        }

        return nil
    }

    /// Maximum file size (10 MiB) read into memory for speculative TDF-JSON detection.
    public static let maxJSONDetectionSize = 10 * 1024 * 1024

    /// Detect the TDF format from a file URL without mapping large files into RAM.
    ///
    /// - Parameter url: File URL to analyze
    /// - Returns: Detected format kind, or nil if unknown
    public static func detect(from url: URL) -> TrustedDataFormatKind? {
        // First try by extension
        let ext = url.pathExtension.lowercased()
        switch ext {
        case "tdf":
            // Could be archive or other - need to check content
            break
        case "ntdf":
            return .nano
        case "tdfjson":
            return .json
        case "tdfcbor":
            return .cbor
        default:
            // Check compound extensions
            let filename = url.lastPathComponent.lowercased()
            if filename.hasSuffix(".tdf.json") {
                return .json
            } else if filename.hasSuffix(".tdf.cbor") {
                return .cbor
            }
        }

        // Fall back to bounded header inspection first (reads at most 4 bytes)
        guard let handle = try? FileHandle(forReadingFrom: url) else {
            return nil
        }
        defer { try? handle.close() }
        guard let header = try? handle.read(upToCount: 4), !header.isEmpty else {
            return nil
        }

        let headerBytes = [UInt8](header)
        if headerBytes.count >= 4 {
            if Array(headerBytes.prefix(cborMagic.count)) == cborMagic,
               headerBytes[cborMagic.count] & 0xE0 == 0xA0
            {
                return .cbor
            }
            if headerBytes == zipMagic {
                return .archive
            }
        }
        if headerBytes.count >= 2, Array(headerBytes.prefix(2)) == nanoMagic {
            return .nano
        }

        // Speculative JSON detection: bound bytes read directly to prevent TOCTOU races
        if headerBytes.first == jsonStart {
            guard (try? handle.seek(toOffset: 0)) != nil,
                  let data = try? handle.read(upToCount: maxJSONDetectionSize + 1),
                  data.count <= maxJSONDetectionSize
            else {
                return nil
            }
            return isTDFJSON(data) ? .json : nil
        }

        return nil
    }

    /// Check if data appears to be TDF-JSON
    private static func isTDFJSON(_ data: Data) -> Bool {
        // Quick validation: try to parse and check for "tdf": "json"
        guard let jsonObject = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return false
        }
        return jsonObject["tdf"] as? String == "json"
    }
}

// MARK: - TDF Format Detection Result

/// Result of TDF format detection with confidence level
public struct TDFFormatDetectionResult: Sendable {
    /// Detected format kind
    public let format: TrustedDataFormatKind

    /// Confidence level of detection
    public let confidence: DetectionConfidence

    /// Detection method used
    public let method: DetectionMethod

    public enum DetectionConfidence: Sendable {
        case definitive // Magic bytes match exactly
        case high // Strong structural indicators
        case medium // File extension or partial match
        case low // Speculative parse
    }

    public enum DetectionMethod: Sendable {
        case magicBytes
        case fileExtension
        case structuralParse
    }
}

public extension TDFFormatDetector {
    /// Detect format with detailed result
    static func detectWithDetails(from data: Data) -> TDFFormatDetectionResult? {
        guard !data.isEmpty else { return nil }

        // Check CBOR magic bytes first (3-byte self-describe tag + CBOR map major type)
        if data.count >= 4 {
            let header = [UInt8](data.prefix(4))
            let prefix = [UInt8](header.prefix(cborMagic.count))
            if prefix == cborMagic, header[cborMagic.count] & 0xE0 == 0xA0 {
                return TDFFormatDetectionResult(
                    format: .cbor,
                    confidence: .definitive,
                    method: .magicBytes,
                )
            }
        }

        // Check ZIP magic bytes
        if data.count >= 4 {
            let header = [UInt8](data.prefix(4))
            if header == zipMagic {
                return TDFFormatDetectionResult(
                    format: .archive,
                    confidence: .definitive,
                    method: .magicBytes,
                )
            }
        }

        // Check NanoTDF magic
        if data.count >= 2 {
            let header = [UInt8](data.prefix(2))
            if header == nanoMagic {
                return TDFFormatDetectionResult(
                    format: .nano,
                    confidence: .definitive,
                    method: .magicBytes,
                )
            }
        }

        // Check for JSON
        if data.first == jsonStart, isTDFJSON(data) {
            return TDFFormatDetectionResult(
                format: .json,
                confidence: .high,
                method: .structuralParse,
            )
        }

        return nil
    }
}
