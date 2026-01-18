import Foundation

/// Format detector for TDF documents.
///
/// Detects the format of TDF data by examining magic bytes and structure.
/// Detection order: CBOR (magic bytes) → ZIP (magic bytes) → JSON (starts with '{')
public enum TDFFormatDetector {
    /// CBOR magic bytes: self-describe CBOR tag + map + key 1
    /// D9 D9F7 = tag(55799) for self-describe CBOR
    /// A5 = map(5) for 5 elements
    /// 01 = unsigned int 1 (first key)
    public static let cborMagic: [UInt8] = [0xD9, 0xD9, 0xF7, 0xA5]

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
            if header == cborMagic {
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
        if data.first == jsonStart {
            // Try to validate it's actually JSON with TDF structure
            if isTDFJSON(data) {
                return .json
            }
        }

        return nil
    }

    /// Detect the TDF format from a file URL
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

        // Fall back to content detection
        guard let data = try? Data(contentsOf: url, options: [.mappedIfSafe]) else {
            return nil
        }
        return detect(from: data)
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
        case definitive  // Magic bytes match exactly
        case high        // Strong structural indicators
        case medium      // File extension or partial match
        case low         // Speculative parse
    }

    public enum DetectionMethod: Sendable {
        case magicBytes
        case fileExtension
        case structuralParse
    }
}

extension TDFFormatDetector {
    /// Detect format with detailed result
    public static func detectWithDetails(from data: Data) -> TDFFormatDetectionResult? {
        guard !data.isEmpty else { return nil }

        // Check CBOR magic bytes first
        if data.count >= 4 {
            let header = [UInt8](data.prefix(4))
            if header == cborMagic {
                return TDFFormatDetectionResult(
                    format: .cbor,
                    confidence: .definitive,
                    method: .magicBytes
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
                    method: .magicBytes
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
                    method: .magicBytes
                )
            }
        }

        // Check for JSON
        if data.first == jsonStart {
            if isTDFJSON(data) {
                return TDFFormatDetectionResult(
                    format: .json,
                    confidence: .high,
                    method: .structuralParse
                )
            }
        }

        return nil
    }
}
