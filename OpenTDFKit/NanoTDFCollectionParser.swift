import Foundation

// MARK: - Collection Parser

/// Parser for NanoTDF Collection wire formats.
/// Provides static methods for parsing collection items from serialized data.
public enum NanoTDFCollectionParser {
    // MARK: - Container Framing

    /// Parses a CollectionItem from container framing format.
    /// Format: 3-byte IV + 3-byte length + ciphertext+tag
    ///
    /// - Parameters:
    ///   - data: The wire data to parse
    ///   - offset: Starting offset in the data
    ///   - tagSize: Size of the authentication tag in bytes (default: 16 for GCM-128)
    /// - Returns: Tuple of parsed CollectionItem and bytes consumed, or nil if parsing fails
    public static func parseContainerFramed(
        from data: Data,
        at offset: Int = 0,
        tagSize: Int = 16,
    ) -> (item: CollectionItem, bytesRead: Int)? {
        let headerSize = 6 // 3-byte IV + 3-byte length
        guard offset >= 0, offset <= data.count, data.count - offset >= headerSize, tagSize > 0 else { return nil }

        let start = data.startIndex + offset
        let iv = UInt32(data[start]) << 16 |
            UInt32(data[start + 1]) << 8 |
            UInt32(data[start + 2])

        let length = Int(data[start + 3]) << 16 |
            Int(data[start + 4]) << 8 |
            Int(data[start + 5])

        let contentStart = offset + headerSize
        guard length >= tagSize, length <= data.count - contentStart else { return nil }

        let contentStartIndex = data.startIndex + contentStart
        let ciphertextWithTag = data[contentStartIndex ..< contentStartIndex + length]
        let item = CollectionItem(ivCounter: iv, ciphertextWithTag: ciphertextWithTag, tagSize: tagSize)
        return (item, headerSize + length)
    }

    /// Parses a CollectionItem from container framing format and returns the result or throws.
    ///
    /// - Parameters:
    ///   - data: The wire data to parse
    ///   - offset: Starting offset in the data
    ///   - tagSize: Size of the authentication tag in bytes
    /// - Returns: Tuple of parsed CollectionItem and bytes consumed
    /// - Throws: `NanoTDFCollectionError` if parsing fails
    public static func parseContainerFramedOrThrow(
        from data: Data,
        at offset: Int = 0,
        tagSize: Int = 16,
    ) throws -> (item: CollectionItem, bytesRead: Int) {
        guard let result = parseContainerFramed(from: data, at: offset, tagSize: tagSize) else {
            if offset < 0 || offset > data.count || data.count - offset < 6 {
                throw NanoTDFCollectionError.unexpectedEndOfData
            }
            throw NanoTDFCollectionError.invalidItemFormat("Failed to parse container framed item at offset \(offset)")
        }
        return result
    }

    // MARK: - Self-Describing Format

    /// Parses a CollectionItem from self-describing format.
    /// Format: 3-byte IV + 4-byte length + ciphertext+tag
    ///
    /// - Parameters:
    ///   - data: The wire data to parse
    ///   - offset: Starting offset in the data
    ///   - tagSize: Size of the authentication tag in bytes (default: 16 for GCM-128)
    /// - Returns: Tuple of parsed CollectionItem and bytes consumed, or nil if parsing fails
    public static func parseSelfDescribing(
        from data: Data,
        at offset: Int = 0,
        tagSize: Int = 16,
    ) -> (item: CollectionItem, bytesRead: Int)? {
        let headerSize = 7 // 3-byte IV + 4-byte length
        guard offset >= 0, offset <= data.count, data.count - offset >= headerSize, tagSize > 0 else { return nil }

        let start = data.startIndex + offset
        let iv = UInt32(data[start]) << 16 |
            UInt32(data[start + 1]) << 8 |
            UInt32(data[start + 2])

        let length = Int(data[start + 3]) << 24 |
            Int(data[start + 4]) << 16 |
            Int(data[start + 5]) << 8 |
            Int(data[start + 6])

        let contentStart = offset + headerSize
        guard length >= tagSize, length <= data.count - contentStart else { return nil }

        let contentStartIndex = data.startIndex + contentStart
        let ciphertextWithTag = data[contentStartIndex ..< contentStartIndex + length]
        let item = CollectionItem(ivCounter: iv, ciphertextWithTag: ciphertextWithTag, tagSize: tagSize)
        return (item, headerSize + length)
    }

    /// Parses a CollectionItem from self-describing format and returns the result or throws.
    ///
    /// - Parameters:
    ///   - data: The wire data to parse
    ///   - offset: Starting offset in the data
    ///   - tagSize: Size of the authentication tag in bytes
    /// - Returns: Tuple of parsed CollectionItem and bytes consumed
    /// - Throws: `NanoTDFCollectionError` if parsing fails
    public static func parseSelfDescribingOrThrow(
        from data: Data,
        at offset: Int = 0,
        tagSize: Int = 16,
    ) throws -> (item: CollectionItem, bytesRead: Int) {
        guard let result = parseSelfDescribing(from: data, at: offset, tagSize: tagSize) else {
            if offset < 0 || offset > data.count || data.count - offset < 7 {
                throw NanoTDFCollectionError.unexpectedEndOfData
            }
            throw NanoTDFCollectionError.invalidItemFormat("Failed to parse self-describing item at offset \(offset)")
        }
        return result
    }

    // MARK: - Stream Parsing

    /// Parses multiple items from a data stream.
    ///
    /// - Parameters:
    ///   - data: The wire data containing multiple items
    ///   - format: The wire format used
    ///   - tagSize: Size of the authentication tag in bytes
    /// - Returns: Array of parsed CollectionItems
    /// - Throws: `NanoTDFCollectionError` if parsing fails
    public static func parseStream(
        from data: Data,
        format: CollectionWireFormat,
        tagSize: Int = 16,
    ) throws -> [CollectionItem] {
        var items = [CollectionItem]()
        var offset = 0

        while offset < data.count {
            let result: (item: CollectionItem, bytesRead: Int) = switch format {
            case .containerFraming:
                try parseContainerFramedOrThrow(from: data, at: offset, tagSize: tagSize)
            case .selfDescribing:
                try parseSelfDescribingOrThrow(from: data, at: offset, tagSize: tagSize)
            }

            items.append(result.item)
            offset += result.bytesRead
        }

        return items
    }

    /// Parses a single item based on the specified wire format.
    ///
    /// - Parameters:
    ///   - data: The wire data to parse
    ///   - offset: Starting offset in the data
    ///   - format: The wire format used
    ///   - tagSize: Size of the authentication tag in bytes
    /// - Returns: Tuple of parsed CollectionItem and bytes consumed, or nil if parsing fails
    public static func parse(
        from data: Data,
        at offset: Int = 0,
        format: CollectionWireFormat,
        tagSize: Int = 16,
    ) -> (item: CollectionItem, bytesRead: Int)? {
        switch format {
        case .containerFraming:
            parseContainerFramed(from: data, at: offset, tagSize: tagSize)
        case .selfDescribing:
            parseSelfDescribing(from: data, at: offset, tagSize: tagSize)
        }
    }
}

// MARK: - Collection File Format

/// Helper for reading/writing complete collection files.
/// Format:
/// - Header length (4 bytes, big-endian)
/// - Header bytes (variable)
/// - Item count (4 bytes, big-endian)
/// - Items in wire format
public enum NanoTDFCollectionFile {
    /// Serializes a collection header and items to a file format
    ///
    /// - Parameters:
    ///   - header: The collection header data
    ///   - items: The serialized item data
    ///   - itemCount: Number of items in the collection
    /// - Returns: Complete serialized file data
    public static func serialize(header: Data, items: Data, itemCount: UInt32) -> Data {
        var data = Data()

        // Header length (4 bytes, big-endian)
        let headerLength = UInt32(header.count)
        data.append(UInt8((headerLength >> 24) & 0xFF))
        data.append(UInt8((headerLength >> 16) & 0xFF))
        data.append(UInt8((headerLength >> 8) & 0xFF))
        data.append(UInt8(headerLength & 0xFF))

        // Header bytes
        data.append(header)

        // Item count (4 bytes, big-endian)
        data.append(UInt8((itemCount >> 24) & 0xFF))
        data.append(UInt8((itemCount >> 16) & 0xFF))
        data.append(UInt8((itemCount >> 8) & 0xFF))
        data.append(UInt8(itemCount & 0xFF))

        // Items
        data.append(items)

        return data
    }

    /// Parses a collection file and returns header and items data
    ///
    /// - Parameter data: The complete file data
    /// - Returns: Tuple of header data, items data, and item count
    /// - Throws: `NanoTDFCollectionError` if parsing fails
    public static func parse(from data: Data) throws -> (header: Data, items: Data, itemCount: UInt32) {
        guard data.count >= 8 else {
            throw NanoTDFCollectionError.unexpectedEndOfData
        }

        // Read header length
        let headerLength = UInt32(data[0]) << 24 |
            UInt32(data[1]) << 16 |
            UInt32(data[2]) << 8 |
            UInt32(data[3])

        let headerEnd = 4 + Int(headerLength)
        guard data.count >= headerEnd + 4 else {
            throw NanoTDFCollectionError.unexpectedEndOfData
        }

        // Extract header
        let header = data.subdata(in: 4 ..< headerEnd)

        // Read item count
        let itemCount = UInt32(data[headerEnd]) << 24 |
            UInt32(data[headerEnd + 1]) << 16 |
            UInt32(data[headerEnd + 2]) << 8 |
            UInt32(data[headerEnd + 3])

        // Extract items
        let itemsStart = headerEnd + 4
        let items = data.subdata(in: itemsStart ..< data.count)

        return (header, items, itemCount)
    }
}
