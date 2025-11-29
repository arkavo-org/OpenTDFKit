import CryptoKit
import Foundation

// MARK: - Error Types

/// Errors specific to NanoTDF Collection operations
public enum NanoTDFCollectionError: Error, CustomStringConvertible {
    /// KAS metadata was not provided to the builder
    case missingKASMetadata
    /// Policy was not provided to the builder
    case missingPolicy
    /// Invalid configuration provided
    case invalidConfiguration(String)
    /// IV counter has exceeded the maximum value (16,777,215)
    case ivExhausted
    /// Encryption operation failed
    case encryptionFailed(String)
    /// Decryption operation failed
    case decryptionFailed(String)
    /// Key derivation failed during collection creation
    case keyDerivationFailed(String)
    /// Invalid wire format data encountered during parsing
    case invalidItemFormat(String)
    /// Unexpected end of data while parsing
    case unexpectedEndOfData

    public var description: String {
        switch self {
        case .missingKASMetadata:
            "NanoTDF Collection requires KAS metadata - call kasMetadata() on builder"
        case .missingPolicy:
            "NanoTDF Collection requires policy - call policy() on builder"
        case let .invalidConfiguration(detail):
            "Invalid collection configuration: \(detail)"
        case .ivExhausted:
            "IV counter exhausted - maximum 16,777,215 items per collection"
        case let .encryptionFailed(detail):
            "Encryption failed: \(detail)"
        case let .decryptionFailed(detail):
            "Decryption failed: \(detail)"
        case let .keyDerivationFailed(detail):
            "Key derivation failed: \(detail)"
        case let .invalidItemFormat(detail):
            "Invalid collection item format: \(detail)"
        case .unexpectedEndOfData:
            "Unexpected end of data while parsing collection item"
        }
    }
}

// MARK: - Wire Format

/// Wire format variants for serializing NanoTDF Collection items
public enum CollectionWireFormat: Sendable {
    /// Container framing: 3-byte IV + 3-byte length + ciphertext+tag
    /// Used for FLV/RTMP where container provides outer framing
    case containerFraming

    /// Self-describing: 3-byte IV + 4-byte length + ciphertext+tag
    /// Used for standalone streaming where length must be explicit for larger payloads
    case selfDescribing
}

// MARK: - Configuration

/// Configuration for NanoTDF Collection behavior
public struct CollectionConfiguration: Sendable {
    /// Rotation threshold - when IV counter reaches this value, client should rotate to a new collection
    /// Default: 2^23 = 8,388,608 (half of max to allow headroom)
    public let rotationThreshold: UInt32

    /// Wire format for serialization
    public let wireFormat: CollectionWireFormat

    /// Cipher for payload encryption
    public let cipher: Cipher

    /// Default configuration with container framing and AES-256-GCM-128
    public static let `default` = CollectionConfiguration(
        rotationThreshold: 0x800000, // 2^23 = 8,388,608
        wireFormat: .containerFraming,
        cipher: .aes256GCM128,
    )

    public init(
        rotationThreshold: UInt32 = 0x800000,
        wireFormat: CollectionWireFormat = .containerFraming,
        cipher: Cipher = .aes256GCM128,
    ) {
        self.rotationThreshold = rotationThreshold
        self.wireFormat = wireFormat
        self.cipher = cipher
    }
}

// MARK: - Collection Item

/// A single encrypted item in a NanoTDF Collection.
/// Uses ContiguousArray for cache-friendly memory layout and zero-copy access.
public struct CollectionItem: Sendable {
    /// 3-byte IV counter as UInt32 (range: 1 to 16,777,215; 0 reserved for policy)
    public let ivCounter: UInt32

    /// Ciphertext + authentication tag stored contiguously for memory efficiency
    private let storage: ContiguousArray<UInt8>

    /// Offset where ciphertext ends and tag begins
    private let tagOffset: Int

    /// Extract the 3-byte IV from the counter
    public var iv: Data {
        Data([
            UInt8((ivCounter >> 16) & 0xFF),
            UInt8((ivCounter >> 8) & 0xFF),
            UInt8(ivCounter & 0xFF),
        ])
    }

    /// Access the ciphertext portion (zero-copy where possible)
    public var ciphertext: Data {
        storage.withUnsafeBufferPointer { buffer in
            Data(bytes: buffer.baseAddress!, count: tagOffset)
        }
    }

    /// Access the authentication tag portion (zero-copy where possible)
    public var tag: Data {
        storage.withUnsafeBufferPointer { buffer in
            let tagStart = buffer.baseAddress!.advanced(by: tagOffset)
            return Data(bytes: tagStart, count: buffer.count - tagOffset)
        }
    }

    /// Combined ciphertext and tag as contiguous data
    public var ciphertextWithTag: Data {
        storage.withUnsafeBufferPointer { buffer in
            Data(bytes: buffer.baseAddress!, count: buffer.count)
        }
    }

    /// Total serialized size: IV (3 bytes) + ciphertext + tag
    public var totalSize: Int {
        3 + storage.count
    }

    /// Convert 3-byte IV to 12-byte GCM nonce: [0,0,0,0,0,0,0,0,0,b1,b2,b3]
    /// This matches the NanoTDF nonce padding convention
    public func toGCMNonce() -> Data {
        var nonce = Data(count: 12)
        nonce[9] = UInt8((ivCounter >> 16) & 0xFF)
        nonce[10] = UInt8((ivCounter >> 8) & 0xFF)
        nonce[11] = UInt8(ivCounter & 0xFF)
        return nonce
    }

    /// Initialize with IV counter and pre-encrypted data
    /// - Parameters:
    ///   - ivCounter: The 3-byte IV counter value (1 to 16,777,215)
    ///   - ciphertext: The encrypted payload data
    ///   - tag: The authentication tag
    public init(ivCounter: UInt32, ciphertext: Data, tag: Data) {
        self.ivCounter = ivCounter
        tagOffset = ciphertext.count

        // Single allocation for ciphertext + tag
        var bytes = ContiguousArray<UInt8>()
        bytes.reserveCapacity(ciphertext.count + tag.count)
        ciphertext.withUnsafeBytes { bytes.append(contentsOf: $0) }
        tag.withUnsafeBytes { bytes.append(contentsOf: $0) }
        storage = bytes
    }

    /// Initialize from combined ciphertext+tag data
    /// - Parameters:
    ///   - ivCounter: The 3-byte IV counter value
    ///   - ciphertextWithTag: Combined ciphertext and tag data
    ///   - tagSize: Size of the authentication tag in bytes
    public init(ivCounter: UInt32, ciphertextWithTag: Data, tagSize: Int) {
        self.ivCounter = ivCounter
        tagOffset = ciphertextWithTag.count - tagSize

        var bytes = ContiguousArray<UInt8>()
        bytes.reserveCapacity(ciphertextWithTag.count)
        ciphertextWithTag.withUnsafeBytes { bytes.append(contentsOf: $0) }
        storage = bytes
    }
}

// MARK: - Cipher Extension

public extension Cipher {
    /// Returns the authentication tag size in bytes for this cipher
    var tagSize: Int {
        switch self {
        case .aes256GCM64: 8
        case .aes256GCM96: 12
        case .aes256GCM104: 13
        case .aes256GCM112: 14
        case .aes256GCM120: 15
        case .aes256GCM128: 16
        }
    }
}

// MARK: - NanoTDF Collection Actor

/// Thread-safe manager for NanoTDF Collection encryption operations.
///
/// NanoTDFCollection maintains shared cryptographic material across multiple
/// encrypted payloads, enabling efficient streaming encryption for RTMP/FLV contexts.
///
/// - Important: IV 0 is reserved for policy encryption; payload IVs start at 1.
/// - Note: Maximum 16,777,215 items (24-bit IV range minus reserved 0).
///
/// ## Performance
/// - Expensive operations (ECDH, HKDF) are performed once at initialization
/// - Per-item encryption uses pre-allocated buffers for minimal overhead
/// - Batch APIs reduce actor hop overhead for high-throughput scenarios
///
/// ## Example Usage
/// ```swift
/// let collection = try await NanoTDFCollectionBuilder()
///     .kasMetadata(kasMetadata)
///     .policy(.embeddedPlaintext(policyData))
///     .configuration(.default)
///     .build()
///
/// let item1 = try await collection.encryptItem(plaintext: data1)
/// let item2 = try await collection.encryptItem(plaintext: data2)
/// ```
public actor NanoTDFCollection {
    // MARK: - Constants

    /// Maximum number of items per collection (2^24 - 1 = 16,777,215)
    public static let maxItems: UInt32 = 0xFFFFFF

    // MARK: - Pre-computed State (computed once at init)

    /// The shared NanoTDF header for this collection
    public let header: Header

    /// Serialized header bytes (computed once, reused for transmission)
    private let headerBytes: Data

    /// The derived symmetric key for payload encryption
    private let symmetricKey: SymmetricKey

    /// Collection configuration
    public let configuration: CollectionConfiguration

    // MARK: - Mutable State

    /// Current IV counter (starts at 1; 0 reserved for policy)
    private var ivCounter: UInt32 = 1

    /// Pre-allocated 12-byte nonce buffer (reused for each encryption)
    /// Format: [0,0,0,0,0,0,0,0,0, iv[0], iv[1], iv[2]]
    private var nonceBuffer: ContiguousArray<UInt8>

    // MARK: - Properties

    /// Number of items encrypted in this collection
    public var itemCount: UInt32 {
        ivCounter - 1
    }

    /// Current IV counter value (next available IV)
    public var currentIVCounter: UInt32 {
        ivCounter
    }

    /// Whether the collection has reached rotation threshold
    public var needsRotation: Bool {
        ivCounter >= configuration.rotationThreshold
    }

    /// Whether the collection has reached maximum capacity
    public var isExhausted: Bool {
        ivCounter > Self.maxItems
    }

    // MARK: - Initialization

    /// Internal initializer - use NanoTDFCollectionBuilder to create instances
    init(
        header: Header,
        symmetricKey: SymmetricKey,
        configuration: CollectionConfiguration,
    ) {
        self.header = header
        headerBytes = header.toData()
        self.symmetricKey = symmetricKey
        self.configuration = configuration

        // Pre-allocate nonce buffer with zero padding
        nonceBuffer = ContiguousArray<UInt8>(repeating: 0, count: 12)
    }

    // MARK: - IV Counter Management

    /// Atomically gets and increments the IV counter
    @inline(__always)
    private func nextIV() -> UInt32? {
        guard ivCounter <= Self.maxItems else { return nil }
        let current = ivCounter
        ivCounter += 1
        return current
    }

    // MARK: - Encryption

    /// Encrypts a single plaintext payload and returns a CollectionItem with atomically assigned IV.
    ///
    /// - Parameter plaintext: The data to encrypt
    /// - Returns: A CollectionItem containing the IV, ciphertext, and authentication tag
    /// - Throws: `NanoTDFCollectionError.ivExhausted` if maximum items reached
    public func encryptItem(plaintext: Data) throws -> CollectionItem {
        guard let iv = nextIV() else {
            throw NanoTDFCollectionError.ivExhausted
        }

        // Update nonce buffer with new IV (last 3 bytes)
        nonceBuffer[9] = UInt8((iv >> 16) & 0xFF)
        nonceBuffer[10] = UInt8((iv >> 8) & 0xFF)
        nonceBuffer[11] = UInt8(iv & 0xFF)

        // Use CryptoKit for 128-bit tags (fastest path)
        if configuration.cipher == .aes256GCM128 {
            let nonce = try nonceBuffer.withUnsafeBufferPointer { buffer in
                try AES.GCM.Nonce(data: Data(buffer))
            }
            let sealed = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: nonce)
            return CollectionItem(ivCounter: iv, ciphertext: sealed.ciphertext, tag: sealed.tag)
        }

        // For other tag sizes, use CryptoHelper's CryptoSwift path
        let (ciphertext, tag) = try CryptoHelper.encryptNanoTDF(
            cipher: configuration.cipher,
            key: symmetricKey,
            iv: Data(nonceBuffer),
            plaintext: plaintext,
        )
        return CollectionItem(ivCounter: iv, ciphertext: ciphertext, tag: tag)
    }

    /// Encrypts multiple plaintexts efficiently in a single actor call.
    /// Reduces actor hop overhead for high-throughput scenarios.
    ///
    /// - Parameter plaintexts: Array of data to encrypt
    /// - Returns: Array of CollectionItems in the same order as input
    /// - Throws: `NanoTDFCollectionError.ivExhausted` if maximum items would be exceeded
    public func encryptBatch(plaintexts: [Data]) throws -> [CollectionItem] {
        // Check if we have enough IVs for the batch
        let remaining = Self.maxItems - ivCounter + 1
        guard plaintexts.count <= remaining else {
            throw NanoTDFCollectionError.ivExhausted
        }

        var results = [CollectionItem]()
        results.reserveCapacity(plaintexts.count)

        for plaintext in plaintexts {
            try results.append(encryptItem(plaintext: plaintext))
        }

        return results
    }

    // MARK: - Serialization

    /// Serializes a CollectionItem to wire format
    /// - Parameters:
    ///   - item: The CollectionItem to serialize
    ///   - format: Optional wire format override (defaults to configuration)
    /// - Returns: Serialized data in the specified wire format
    public func serialize(item: CollectionItem, format: CollectionWireFormat? = nil) -> Data {
        let wireFormat = format ?? configuration.wireFormat
        var data = Data()

        // Write IV (3 bytes)
        data.append(contentsOf: item.iv)

        // Write length
        let contentLength = item.ciphertext.count + item.tag.count
        switch wireFormat {
        case .containerFraming:
            // 3-byte length (big-endian)
            data.append(UInt8((contentLength >> 16) & 0xFF))
            data.append(UInt8((contentLength >> 8) & 0xFF))
            data.append(UInt8(contentLength & 0xFF))
        case .selfDescribing:
            // 4-byte length (big-endian)
            data.append(UInt8((contentLength >> 24) & 0xFF))
            data.append(UInt8((contentLength >> 16) & 0xFF))
            data.append(UInt8((contentLength >> 8) & 0xFF))
            data.append(UInt8(contentLength & 0xFF))
        }

        // Write ciphertext + tag
        data.append(item.ciphertextWithTag)

        return data
    }

    /// Returns the pre-serialized header bytes for transmission
    public func getHeaderBytes() -> Data {
        headerBytes
    }

    /// Returns the symmetric key for offline decryption scenarios
    /// - Warning: Handle with care - this key can decrypt all items in the collection
    public func getSymmetricKey() -> SymmetricKey {
        symmetricKey
    }
}
