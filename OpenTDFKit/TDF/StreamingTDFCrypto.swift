import CryptoKit
import Foundation

public enum StreamingTDFCrypto {
    public static let defaultChunkSize = 2 * 1024 * 1024
    public static let chunkSize5MB = 5 * 1024 * 1024
    public static let chunkSize25MB = 25 * 1024 * 1024

    public static func encryptPayloadStreamingToMemory(
        inputHandle: FileHandle,
        symmetricKey: SymmetricKey,
        chunkSize: Int = defaultChunkSize,
    ) throws -> (encryptedPayload: Data, result: StreamingEncryptionResult) {
        guard chunkSize > 0 else { throw StreamingCryptoError.invalidChunkSize }
        let startOffset = try inputHandle.offset()
        let endOffset = try inputHandle.seekToEnd()
        guard endOffset >= startOffset else { throw StreamingCryptoError.segmentReadFailed }
        let totalSize = endOffset - startOffset
        guard totalSize <= UInt64(Int.max - 28) else { throw StreamingCryptoError.invalidSegmentSize }
        try inputHandle.seek(toOffset: startOffset)

        let nonceData = try TDFCrypto.randomBytes(count: 12)
        let nonce = try AES.GCM.Nonce(data: nonceData)

        var encryptedPayload = Data()
        encryptedPayload.reserveCapacity(Int(totalSize) + 28)
        encryptedPayload.append(Data(nonce))

        var totalPlaintextRead: Int64 = 0
        var plaintextAccumulator = Data()
        plaintextAccumulator.reserveCapacity(Int(totalSize))

        while totalPlaintextRead < Int64(totalSize) {
            let remaining = Int64(totalSize) - totalPlaintextRead
            let readSize = min(remaining, Int64(chunkSize))
            guard let chunk = try inputHandle.read(upToCount: Int(readSize)), !chunk.isEmpty else {
                throw StreamingCryptoError.segmentReadFailed
            }
            plaintextAccumulator.append(chunk)
            totalPlaintextRead += Int64(chunk.count)
        }

        let sealed = try AES.GCM.seal(plaintextAccumulator, using: symmetricKey, nonce: nonce)

        encryptedPayload.append(sealed.ciphertext)
        encryptedPayload.append(Data(sealed.tag))

        let totalEncrypted = Int64(encryptedPayload.count)
        let segmentHash = Data(sealed.tag).base64EncodedString()

        let segment = EncryptedSegment(
            segmentIndex: 0,
            plaintextSize: totalPlaintextRead,
            encryptedSize: totalEncrypted,
            hash: segmentHash,
        )

        let result = StreamingEncryptionResult(
            iv: Data(nonce),
            tag: Data(sealed.tag),
            segments: [segment],
            totalPlaintextSize: totalPlaintextRead,
            totalEncryptedSize: totalEncrypted,
        )

        return (encryptedPayload, result)
    }

    public static func encryptPayloadStreamingMultiSegmentToMemory(
        inputHandle: FileHandle,
        symmetricKey: SymmetricKey,
        segmentSizes: [Int],
    ) throws -> (encryptedPayload: Data, result: StreamingEncryptionResult) {
        guard !segmentSizes.isEmpty, segmentSizes.allSatisfy({ $0 > 0 }) else {
            throw StreamingCryptoError.invalidSegmentSize
        }
        try inputHandle.seek(toOffset: 0)

        var totalCapacity = 0
        for segmentSize in segmentSizes {
            guard segmentSize <= Int.max - totalCapacity else { throw StreamingCryptoError.invalidSegmentSize }
            totalCapacity += segmentSize
        }
        guard segmentSizes.count <= (Int.max - totalCapacity) / 28 else { throw StreamingCryptoError.invalidSegmentSize }
        totalCapacity += segmentSizes.count * 28

        var encryptedPayload = Data()
        encryptedPayload.reserveCapacity(totalCapacity)

        var segments: [EncryptedSegment] = []
        var totalPlaintextRead: Int64 = 0
        var totalEncryptedWritten: Int64 = 0
        var segmentIndex = 0
        var firstIV: Data?
        var lastTag: Data?

        var sizeIndex = 0
        while true {
            // The listed sizes first, then the last one repeated until EOF, so
            // input longer than their sum is not dropped.
            let segmentSize = segmentSizes[min(sizeIndex, segmentSizes.count - 1)]
            sizeIndex += 1
            var plaintextAccumulator = Data()
            plaintextAccumulator.reserveCapacity(segmentSize)
            var segmentPlaintextSize: Int64 = 0
            var reachedEOF = false

            while segmentPlaintextSize < segmentSize, !reachedEOF {
                let remaining = segmentSize - Int(segmentPlaintextSize)
                let readSize = min(remaining, 1024 * 1024)
                let chunk = try inputHandle.read(upToCount: readSize) ?? Data()
                if chunk.isEmpty {
                    reachedEOF = true
                } else {
                    plaintextAccumulator.append(chunk)
                    segmentPlaintextSize += Int64(chunk.count)
                }
            }

            if segmentPlaintextSize == 0 {
                break
            }

            let nonceData = try TDFCrypto.randomBytes(count: 12)
            let nonce = try AES.GCM.Nonce(data: nonceData)
            let sealed = try AES.GCM.seal(plaintextAccumulator, using: symmetricKey, nonce: nonce)

            if firstIV == nil {
                firstIV = Data(nonce)
            }
            lastTag = Data(sealed.tag)

            let segmentStart = encryptedPayload.count
            encryptedPayload.append(Data(nonce))
            encryptedPayload.append(sealed.ciphertext)
            encryptedPayload.append(Data(sealed.tag))
            let segmentEnd = encryptedPayload.count

            let segmentEncryptedSize = Int64(segmentEnd - segmentStart)
            let segmentHash = Data(sealed.tag).base64EncodedString()

            let segment = EncryptedSegment(
                segmentIndex: segmentIndex,
                plaintextSize: segmentPlaintextSize,
                encryptedSize: segmentEncryptedSize,
                hash: segmentHash,
            )
            segments.append(segment)

            totalPlaintextRead += segmentPlaintextSize
            totalEncryptedWritten += segmentEncryptedSize
            segmentIndex += 1

            if segmentPlaintextSize < segmentSize {
                break
            }
        }

        guard let ivData = firstIV, let tagData = lastTag, !segments.isEmpty else {
            throw StreamingCryptoError.invalidSegmentSize
        }

        let result = StreamingEncryptionResult(
            iv: ivData,
            tag: tagData,
            segments: segments,
            totalPlaintextSize: totalPlaintextRead,
            totalEncryptedSize: totalEncryptedWritten,
        )

        return (encryptedPayload, result)
    }

    public struct EncryptedSegment: Sendable {
        public let segmentIndex: Int
        public let plaintextSize: Int64
        public let encryptedSize: Int64
        public let hash: String

        public init(segmentIndex: Int, plaintextSize: Int64, encryptedSize: Int64, hash: String) {
            self.segmentIndex = segmentIndex
            self.plaintextSize = plaintextSize
            self.encryptedSize = encryptedSize
            self.hash = hash
        }
    }

    public struct StreamingEncryptionResult: Sendable {
        public let iv: Data
        public let tag: Data
        public let segments: [EncryptedSegment]
        public let totalPlaintextSize: Int64
        public let totalEncryptedSize: Int64

        public init(iv: Data, tag: Data, segments: [EncryptedSegment], totalPlaintextSize: Int64, totalEncryptedSize: Int64) {
            self.iv = iv
            self.tag = tag
            self.segments = segments
            self.totalPlaintextSize = totalPlaintextSize
            self.totalEncryptedSize = totalEncryptedSize
        }
    }

    public static func encryptPayloadStreaming(
        inputHandle: FileHandle,
        outputHandle: FileHandle,
        symmetricKey: SymmetricKey,
        chunkSize: Int = defaultChunkSize,
    ) throws -> StreamingEncryptionResult {
        guard chunkSize > 0 else { throw StreamingCryptoError.invalidChunkSize }
        let startOffset = try inputHandle.offset()
        let endOffset = try inputHandle.seekToEnd()
        guard endOffset >= startOffset else { throw StreamingCryptoError.segmentReadFailed }
        let totalSize = endOffset - startOffset
        guard totalSize <= UInt64(Int.max) else { throw StreamingCryptoError.invalidSegmentSize }
        try inputHandle.seek(toOffset: startOffset)

        let nonceData = try TDFCrypto.randomBytes(count: 12)
        let nonce = try AES.GCM.Nonce(data: nonceData)

        try outputHandle.write(contentsOf: Data(nonce))

        var totalPlaintextRead: Int64 = 0
        var plaintextAccumulator = Data()
        plaintextAccumulator.reserveCapacity(Int(totalSize))

        while totalPlaintextRead < Int64(totalSize) {
            let remaining = Int64(totalSize) - totalPlaintextRead
            let readSize = min(remaining, Int64(chunkSize))
            guard let chunk = try inputHandle.read(upToCount: Int(readSize)), !chunk.isEmpty else {
                throw StreamingCryptoError.segmentReadFailed
            }
            plaintextAccumulator.append(chunk)
            totalPlaintextRead += Int64(chunk.count)
        }

        let sealed = try AES.GCM.seal(plaintextAccumulator, using: symmetricKey, nonce: nonce)

        try outputHandle.write(contentsOf: sealed.ciphertext)
        try outputHandle.write(contentsOf: Data(sealed.tag))
        try outputHandle.synchronize()

        let totalEncrypted = Int64(nonceData.count + sealed.ciphertext.count + sealed.tag.count)
        let segmentHash = Data(sealed.tag).base64EncodedString()

        let segment = EncryptedSegment(
            segmentIndex: 0,
            plaintextSize: totalPlaintextRead,
            encryptedSize: totalEncrypted,
            hash: segmentHash,
        )

        return StreamingEncryptionResult(
            iv: Data(nonce),
            tag: Data(sealed.tag),
            segments: [segment],
            totalPlaintextSize: totalPlaintextRead,
            totalEncryptedSize: totalEncrypted,
        )
    }

    public static func encryptPayloadStreamingMultiSegment(
        inputHandle: FileHandle,
        outputHandle: FileHandle,
        symmetricKey: SymmetricKey,
        segmentSizes: [Int],
    ) throws -> StreamingEncryptionResult {
        guard !segmentSizes.isEmpty, segmentSizes.allSatisfy({ $0 > 0 }) else {
            throw StreamingCryptoError.invalidSegmentSize
        }
        try inputHandle.seek(toOffset: 0)

        var segments: [EncryptedSegment] = []
        var totalPlaintextRead: Int64 = 0
        var totalEncryptedWritten: Int64 = 0
        var segmentIndex = 0
        var firstIV: Data?
        var lastTag: Data?

        var sizeIndex = 0
        while true {
            // The listed sizes first, then the last one repeated until EOF, so
            // input longer than their sum is not dropped.
            let segmentSize = segmentSizes[min(sizeIndex, segmentSizes.count - 1)]
            sizeIndex += 1
            var plaintextAccumulator = Data()
            plaintextAccumulator.reserveCapacity(segmentSize)
            var segmentPlaintextSize: Int64 = 0
            var reachedEOF = false

            while segmentPlaintextSize < segmentSize, !reachedEOF {
                let remaining = segmentSize - Int(segmentPlaintextSize)
                let readSize = min(remaining, 1024 * 1024)
                let chunk = try inputHandle.read(upToCount: readSize) ?? Data()
                if chunk.isEmpty {
                    reachedEOF = true
                } else {
                    plaintextAccumulator.append(chunk)
                    segmentPlaintextSize += Int64(chunk.count)
                }
            }

            if segmentPlaintextSize == 0 {
                break
            }

            let nonceData = try TDFCrypto.randomBytes(count: 12)
            let nonce = try AES.GCM.Nonce(data: nonceData)
            let sealed = try AES.GCM.seal(plaintextAccumulator, using: symmetricKey, nonce: nonce)

            if firstIV == nil {
                firstIV = Data(nonce)
            }
            lastTag = Data(sealed.tag)

            let segmentStartOffset = try outputHandle.offset()
            try outputHandle.write(contentsOf: Data(nonce))
            try outputHandle.write(contentsOf: sealed.ciphertext)
            try outputHandle.write(contentsOf: Data(sealed.tag))
            let segmentEndOffset = try outputHandle.offset()

            let segmentEncryptedSize = Int64(segmentEndOffset - segmentStartOffset)
            let segmentHash = Data(sealed.tag).base64EncodedString()

            let segment = EncryptedSegment(
                segmentIndex: segmentIndex,
                plaintextSize: segmentPlaintextSize,
                encryptedSize: segmentEncryptedSize,
                hash: segmentHash,
            )
            segments.append(segment)

            totalPlaintextRead += segmentPlaintextSize
            totalEncryptedWritten += segmentEncryptedSize
            segmentIndex += 1

            if segmentPlaintextSize < segmentSize {
                break
            }
        }

        try outputHandle.synchronize()

        guard let ivData = firstIV, let tagData = lastTag, !segments.isEmpty else {
            throw StreamingCryptoError.invalidSegmentSize
        }

        return StreamingEncryptionResult(
            iv: ivData,
            tag: tagData,
            segments: segments,
            totalPlaintextSize: totalPlaintextRead,
            totalEncryptedSize: totalEncryptedWritten,
        )
    }

    public static func decryptPayloadStreaming(
        inputHandle: FileHandle,
        outputHandle: FileHandle,
        iv: Data,
        tag: Data,
        symmetricKey: SymmetricKey,
        chunkSize: Int = defaultChunkSize,
    ) throws {
        guard chunkSize > 0 else { throw StreamingCryptoError.invalidChunkSize }
        guard iv.count == 12, tag.count == 16 else { throw StreamingCryptoError.malformedSegment(0) }
        let startOffset = try inputHandle.offset()
        let endOffset = try inputHandle.seekToEnd()
        guard endOffset >= startOffset, endOffset - startOffset >= 28 else {
            throw StreamingCryptoError.malformedSegment(0)
        }

        let ciphertextSize = endOffset - startOffset - 28
        guard ciphertextSize <= UInt64(Int.max) else { throw StreamingCryptoError.invalidSegmentSize }
        let payloadStart = startOffset + 12
        try inputHandle.seek(toOffset: payloadStart)

        var ciphertextAccumulator = Data()
        ciphertextAccumulator.reserveCapacity(Int(ciphertextSize))
        var totalRead = 0
        while totalRead < Int(ciphertextSize) {
            let remaining = Int(ciphertextSize) - totalRead
            let readSize = min(remaining, chunkSize)
            guard let chunk = try inputHandle.read(upToCount: readSize), !chunk.isEmpty else {
                throw StreamingCryptoError.segmentReadFailed
            }
            ciphertextAccumulator.append(chunk)
            totalRead += chunk.count
        }

        let nonce = try AES.GCM.Nonce(data: iv)
        let sealed = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertextAccumulator, tag: tag)
        let plaintext = try AES.GCM.open(sealed, using: symmetricKey)

        try outputHandle.write(contentsOf: plaintext)
    }

    public static func decryptPayloadStreamingMultiSegment(
        inputHandle: FileHandle,
        outputHandle: FileHandle,
        segments: [EncryptedSegment],
        symmetricKey: SymmetricKey,
        chunkSize: Int = defaultChunkSize,
    ) throws {
        guard chunkSize > 0 else { throw StreamingCryptoError.invalidChunkSize }
        let startOffset = try inputHandle.offset()
        let endOffset = try inputHandle.seekToEnd()
        guard endOffset >= startOffset else { throw StreamingCryptoError.segmentReadFailed }
        var currentOffset = startOffset

        for segment in segments {
            guard segment.encryptedSize >= 28 else {
                throw StreamingCryptoError.malformedSegment(segment.segmentIndex)
            }
            let segmentSize = UInt64(segment.encryptedSize)
            guard currentOffset <= endOffset, segmentSize <= endOffset - currentOffset else {
                throw StreamingCryptoError.malformedSegment(segment.segmentIndex)
            }
            try inputHandle.seek(toOffset: currentOffset)

            let ivData = try inputHandle.read(upToCount: 12) ?? Data()
            guard ivData.count == 12 else {
                throw StreamingCryptoError.malformedSegment(segment.segmentIndex)
            }

            let ciphertextSize = Int(segment.encryptedSize) - 28
            var ciphertextAccumulator = Data()
            ciphertextAccumulator.reserveCapacity(ciphertextSize)
            var totalRead = 0

            while totalRead < ciphertextSize {
                let remaining = ciphertextSize - totalRead
                let readSize = min(remaining, chunkSize)
                guard let chunk = try inputHandle.read(upToCount: readSize), !chunk.isEmpty else {
                    throw StreamingCryptoError.segmentReadFailed
                }
                ciphertextAccumulator.append(chunk)
                totalRead += chunk.count
            }

            let tagData = try inputHandle.read(upToCount: 16) ?? Data()
            guard tagData.count == 16 else {
                throw StreamingCryptoError.malformedSegment(segment.segmentIndex)
            }

            let nonce = try AES.GCM.Nonce(data: ivData)
            let sealed = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertextAccumulator, tag: tagData)
            let plaintext = try AES.GCM.open(sealed, using: symmetricKey)

            try outputHandle.write(contentsOf: plaintext)
            currentOffset += segmentSize
        }

        guard currentOffset == endOffset else {
            throw StreamingCryptoError.malformedSegment(segments.last?.segmentIndex ?? 0)
        }
    }

    public static func decryptPayloadMultiSegmentFromMemory(
        encryptedPayload: Data,
        segments: [EncryptedSegment],
        symmetricKey: SymmetricKey,
    ) throws -> Data {
        var plaintext = Data()
        plaintext.reserveCapacity(encryptedPayload.count)
        var offset = 0

        for segment in segments {
            guard segment.encryptedSize >= 28 else {
                throw StreamingCryptoError.malformedSegment(segment.segmentIndex)
            }
            let segmentSize = Int(segment.encryptedSize)
            guard offset <= encryptedPayload.count, segmentSize <= encryptedPayload.count - offset else {
                throw StreamingCryptoError.malformedSegment(segment.segmentIndex)
            }

            let start = encryptedPayload.startIndex + offset
            let ivData = encryptedPayload[start ..< start + 12]
            let ciphertextSize = segmentSize - 28
            let ciphertextData = encryptedPayload[start + 12 ..< start + 12 + ciphertextSize]
            let tagData = encryptedPayload[start + 12 + ciphertextSize ..< start + segmentSize]

            let nonce = try AES.GCM.Nonce(data: ivData)
            let sealed = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertextData, tag: tagData)
            let segmentPlaintext = try AES.GCM.open(sealed, using: symmetricKey)

            plaintext.append(segmentPlaintext)
            offset += segmentSize
        }

        guard offset == encryptedPayload.count else {
            throw StreamingCryptoError.malformedSegment(segments.last?.segmentIndex ?? 0)
        }
        return plaintext
    }
}

extension FileHandle {
    func readDataFromSegmentStart(offset: Int64, length: Int) throws -> Data {
        let originalOffset = try self.offset()
        defer {
            try? seek(toOffset: originalOffset)
        }
        guard offset >= 0, length >= 0 else { throw StreamingCryptoError.invalidSegmentSize }
        try seek(toOffset: UInt64(offset))
        return try read(upToCount: length) ?? Data()
    }

    func readDataFromSegmentEnd(offset _: Int64, length: Int) throws -> Data {
        let originalOffset = try offset()
        defer {
            try? seek(toOffset: originalOffset)
        }
        guard length >= 0 else { throw StreamingCryptoError.invalidSegmentSize }
        let endOffset = try seekToEnd()
        guard UInt64(length) <= endOffset else { throw StreamingCryptoError.malformedSegment(0) }
        try seek(toOffset: endOffset - UInt64(length))
        return try read(upToCount: length) ?? Data()
    }
}

public enum StreamingCryptoError: Error, CustomStringConvertible {
    case malformedSegment(Int)
    case invalidSegmentSize
    case invalidChunkSize
    case segmentReadFailed

    public var description: String {
        switch self {
        case let .malformedSegment(index):
            "Malformed encrypted segment at index \(index)"
        case .invalidSegmentSize:
            "Invalid segment size specified"
        case .invalidChunkSize:
            "Chunk size must be positive"
        case .segmentReadFailed:
            "Failed to read segment data"
        }
    }
}
