import CryptoKit
import Foundation

public enum StreamingStandardTDFCrypto {
    public static let defaultChunkSize = 2 * 1024 * 1024
    public static let chunkSize5MB = 5 * 1024 * 1024
    public static let chunkSize25MB = 25 * 1024 * 1024

    public static func encryptPayloadStreamingToMemory(
        inputHandle: FileHandle,
        symmetricKey: SymmetricKey,
        chunkSize: Int = defaultChunkSize,
    ) throws -> (encryptedPayload: Data, result: StreamingEncryptionResult) {
        let startOffset = try inputHandle.offset()
        let endOffset = try inputHandle.seekToEnd()
        let totalSize = Int64(endOffset - startOffset)
        try inputHandle.seek(toOffset: startOffset)

        let nonceData = try StandardTDFCrypto.randomBytes(count: 12)
        let nonce = try AES.GCM.Nonce(data: nonceData)

        var encryptedPayload = Data()
        encryptedPayload.reserveCapacity(Int(totalSize) + 28)
        encryptedPayload.append(Data(nonce))

        var totalPlaintextRead: Int64 = 0
        var plaintextAccumulator = Data()
        plaintextAccumulator.reserveCapacity(min(Int(totalSize), chunkSize * 2))
        var shouldBreak = false

        while !shouldBreak {
            autoreleasepool {
                if let chunk = try? inputHandle.read(upToCount: chunkSize), !chunk.isEmpty {
                    plaintextAccumulator.append(chunk)
                    totalPlaintextRead += Int64(chunk.count)
                } else {
                    shouldBreak = true
                }
            }
            if totalPlaintextRead >= totalSize {
                break
            }
        }

        let sealed = try AES.GCM.seal(plaintextAccumulator, using: symmetricKey, nonce: nonce)

        encryptedPayload.append(sealed.ciphertext)
        encryptedPayload.append(Data(sealed.tag))

        let totalEncrypted = Int64(encryptedPayload.count)

        let segmentHash = try StandardTDFCrypto.segmentSignatureGMAC(
            segmentCiphertext: encryptedPayload,
            symmetricKey: symmetricKey,
        )

        let segment = EncryptedSegment(
            segmentIndex: 0,
            plaintextSize: totalPlaintextRead,
            encryptedSize: totalEncrypted,
            hash: segmentHash.base64EncodedString(),
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
        try inputHandle.seek(toOffset: 0)

        var encryptedPayload = Data()
        let totalCapacity = segmentSizes.reduce(0, +) + (segmentSizes.count * 28)
        encryptedPayload.reserveCapacity(totalCapacity)

        var segments: [EncryptedSegment] = []
        var totalPlaintextRead: Int64 = 0
        var totalEncryptedWritten: Int64 = 0
        var segmentIndex = 0
        var firstIV: Data?
        var lastTag: Data?

        for segmentSize in segmentSizes {
            var plaintextAccumulator = Data()
            plaintextAccumulator.reserveCapacity(segmentSize)
            var segmentPlaintextSize: Int64 = 0
            var shouldBreak = false

            while segmentPlaintextSize < segmentSize, !shouldBreak {
                autoreleasepool {
                    let remaining = segmentSize - Int(segmentPlaintextSize)
                    let readSize = min(remaining, 1024 * 1024)
                    if let chunk = try? inputHandle.read(upToCount: readSize), !chunk.isEmpty {
                        plaintextAccumulator.append(chunk)
                        segmentPlaintextSize += Int64(chunk.count)
                    } else {
                        shouldBreak = true
                    }
                }
            }

            if segmentPlaintextSize == 0 {
                break
            }

            let nonceData = try StandardTDFCrypto.randomBytes(count: 12)
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

            let segmentData = encryptedPayload.subdata(in: segmentStart ..< segmentEnd)
            let segmentHash = try StandardTDFCrypto.segmentSignatureGMAC(
                segmentCiphertext: segmentData,
                symmetricKey: symmetricKey,
            )

            let segment = EncryptedSegment(
                segmentIndex: segmentIndex,
                plaintextSize: segmentPlaintextSize,
                encryptedSize: segmentEncryptedSize,
                hash: segmentHash.base64EncodedString(),
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
        let startOffset = try inputHandle.offset()
        let endOffset = try inputHandle.seekToEnd()
        let totalSize = Int64(endOffset - startOffset)
        try inputHandle.seek(toOffset: startOffset)

        let nonceData = try StandardTDFCrypto.randomBytes(count: 12)
        let nonce = try AES.GCM.Nonce(data: nonceData)

        try outputHandle.write(contentsOf: Data(nonce))

        var totalPlaintextRead: Int64 = 0
        var plaintextAccumulator = Data()
        plaintextAccumulator.reserveCapacity(min(Int(totalSize), chunkSize * 2))
        var shouldBreak = false

        while !shouldBreak {
            autoreleasepool {
                if let chunk = try? inputHandle.read(upToCount: chunkSize), !chunk.isEmpty {
                    plaintextAccumulator.append(chunk)
                    totalPlaintextRead += Int64(chunk.count)
                } else {
                    shouldBreak = true
                }
            }
            if totalPlaintextRead >= totalSize {
                break
            }
        }

        let sealed = try AES.GCM.seal(plaintextAccumulator, using: symmetricKey, nonce: nonce)

        try outputHandle.write(contentsOf: sealed.ciphertext)
        try outputHandle.write(contentsOf: Data(sealed.tag))
        try outputHandle.synchronize()

        let totalEncrypted = Int64(nonceData.count + sealed.ciphertext.count + sealed.tag.count)

        let segmentHash = try StandardTDFCrypto.segmentSignatureGMAC(
            segmentCiphertext: Data(nonce) + sealed.ciphertext + Data(sealed.tag),
            symmetricKey: symmetricKey,
        )

        let segment = EncryptedSegment(
            segmentIndex: 0,
            plaintextSize: totalPlaintextRead,
            encryptedSize: totalEncrypted,
            hash: segmentHash.base64EncodedString(),
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
        try inputHandle.seek(toOffset: 0)

        var segments: [EncryptedSegment] = []
        var totalPlaintextRead: Int64 = 0
        var totalEncryptedWritten: Int64 = 0
        var segmentIndex = 0
        var firstIV: Data?
        var lastTag: Data?

        for segmentSize in segmentSizes {
            var plaintextAccumulator = Data()
            plaintextAccumulator.reserveCapacity(segmentSize)
            var segmentPlaintextSize: Int64 = 0
            var shouldBreak = false

            while segmentPlaintextSize < segmentSize, !shouldBreak {
                autoreleasepool {
                    let remaining = segmentSize - Int(segmentPlaintextSize)
                    let readSize = min(remaining, 1024 * 1024)
                    if let chunk = try? inputHandle.read(upToCount: readSize), !chunk.isEmpty {
                        plaintextAccumulator.append(chunk)
                        segmentPlaintextSize += Int64(chunk.count)
                    } else {
                        shouldBreak = true
                    }
                }
            }

            if segmentPlaintextSize == 0 {
                break
            }

            let nonceData = try StandardTDFCrypto.randomBytes(count: 12)
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

            let segmentHash = try StandardTDFCrypto.segmentSignatureGMAC(
                segmentCiphertext: Data(nonce) + sealed.ciphertext + Data(sealed.tag),
                symmetricKey: symmetricKey,
            )

            let segment = EncryptedSegment(
                segmentIndex: segmentIndex,
                plaintextSize: segmentPlaintextSize,
                encryptedSize: segmentEncryptedSize,
                hash: segmentHash.base64EncodedString(),
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
        let startOffset = try inputHandle.offset()
        let endOffset = try inputHandle.seekToEnd()
        let totalSize = Int64(endOffset - startOffset)
        try inputHandle.seek(toOffset: startOffset)

        var ciphertextAccumulator = Data()

        let ivSize = 12
        let tagSize = 16
        let payloadStart = startOffset + UInt64(ivSize)
        let payloadEnd = endOffset - UInt64(tagSize)

        try inputHandle.seek(toOffset: payloadStart)
        let ciphertextSize = Int(payloadEnd - payloadStart)

        var totalRead = 0
        while totalRead < ciphertextSize {
            let remaining = ciphertextSize - totalRead
            let readSize = min(remaining, chunkSize)
            let chunk = try inputHandle.read(upToCount: readSize) ?? Data()
            if chunk.isEmpty {
                break
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
        let startOffset = try inputHandle.offset()
        var currentOffset = startOffset

        for segment in segments {
            try inputHandle.seek(toOffset: currentOffset)

            let ivSize = 12
            let tagSize = 16
            let ivData = try inputHandle.read(upToCount: ivSize) ?? Data()
            guard ivData.count == ivSize else {
                throw StreamingCryptoError.malformedSegment(segment.segmentIndex)
            }

            let ciphertextSize = Int(segment.encryptedSize) - ivSize - tagSize
            var ciphertextAccumulator = Data()
            var totalRead = 0

            while totalRead < ciphertextSize {
                let remaining = ciphertextSize - totalRead
                let readSize = min(remaining, chunkSize)
                let chunk = try inputHandle.read(upToCount: readSize) ?? Data()
                if chunk.isEmpty {
                    break
                }
                ciphertextAccumulator.append(chunk)
                totalRead += chunk.count
            }

            let tagData = try inputHandle.read(upToCount: tagSize) ?? Data()
            guard tagData.count == tagSize else {
                throw StreamingCryptoError.malformedSegment(segment.segmentIndex)
            }

            let nonce = try AES.GCM.Nonce(data: ivData)
            let sealed = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertextAccumulator, tag: tagData)
            let plaintext = try AES.GCM.open(sealed, using: symmetricKey)

            try outputHandle.write(contentsOf: plaintext)

            currentOffset += UInt64(segment.encryptedSize)
        }
    }

    public static func decryptPayloadMultiSegmentFromMemory(
        encryptedPayload: Data,
        segments: [EncryptedSegment],
        symmetricKey: SymmetricKey,
    ) throws -> Data {
        var plaintext = Data()
        var offset = 0

        for segment in segments {
            let ivSize = 12
            let tagSize = 16
            let segmentSize = Int(segment.encryptedSize)

            guard offset + segmentSize <= encryptedPayload.count else {
                throw StreamingCryptoError.malformedSegment(segment.segmentIndex)
            }

            let ivData = encryptedPayload.subdata(in: offset ..< offset + ivSize)
            let ciphertextSize = segmentSize - ivSize - tagSize
            let ciphertextData = encryptedPayload.subdata(in: offset + ivSize ..< offset + ivSize + ciphertextSize)
            let tagData = encryptedPayload.subdata(in: offset + ivSize + ciphertextSize ..< offset + segmentSize)

            let nonce = try AES.GCM.Nonce(data: ivData)
            let sealed = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertextData, tag: tagData)
            let segmentPlaintext = try AES.GCM.open(sealed, using: symmetricKey)

            plaintext.append(segmentPlaintext)
            offset += segmentSize
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
        try seek(toOffset: UInt64(offset))
        return try read(upToCount: length) ?? Data()
    }

    func readDataFromSegmentEnd(offset _: Int64, length: Int) throws -> Data {
        let originalOffset = try offset()
        defer {
            try? seek(toOffset: originalOffset)
        }
        let endOffset = try seekToEnd()
        try seek(toOffset: endOffset - UInt64(length))
        return try read(upToCount: length) ?? Data()
    }
}

public enum StreamingCryptoError: Error, CustomStringConvertible {
    case malformedSegment(Int)
    case invalidSegmentSize
    case segmentReadFailed

    public var description: String {
        switch self {
        case let .malformedSegment(index):
            "Malformed encrypted segment at index \(index)"
        case .invalidSegmentSize:
            "Invalid segment size specified"
        case .segmentReadFailed:
            "Failed to read segment data"
        }
    }
}
