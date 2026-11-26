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
            // Drain FileHandle's autoreleased read buffers after each append.
            try autoreleasepool {
                let remaining = Int64(totalSize) - totalPlaintextRead
                let readSize = min(remaining, Int64(chunkSize))
                guard let chunk = try inputHandle.read(upToCount: Int(readSize)), !chunk.isEmpty else {
                    throw StreamingCryptoError.segmentReadFailed
                }
                plaintextAccumulator.append(chunk)
                totalPlaintextRead += Int64(chunk.count)
            }
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

        let rootSig = Data(HMAC<SHA256>.authenticationCode(for: Data(sealed.tag), using: symmetricKey)).base64EncodedString()

        let result = StreamingEncryptionResult(
            iv: Data(nonce),
            tag: Data(sealed.tag),
            segments: [segment],
            totalPlaintextSize: totalPlaintextRead,
            totalEncryptedSize: totalEncrypted,
            rootSignature: rootSig,
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
        var rawTags: [Data] = []
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
                // Keep read buffers from accumulating across segments.
                try autoreleasepool {
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
            let tagData = Data(sealed.tag)
            lastTag = tagData
            rawTags.append(tagData)

            let segmentStart = encryptedPayload.count
            encryptedPayload.append(Data(nonce))
            encryptedPayload.append(sealed.ciphertext)
            encryptedPayload.append(tagData)
            let segmentEnd = encryptedPayload.count

            let segmentEncryptedSize = Int64(segmentEnd - segmentStart)
            let segmentHash = tagData.base64EncodedString()

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

        let rootSig = Data(HMAC<SHA256>.authenticationCode(
            for: Data(rawTags.joined()),
            using: symmetricKey,
        )).base64EncodedString()

        let result = StreamingEncryptionResult(
            iv: ivData,
            tag: tagData,
            segments: segments,
            totalPlaintextSize: totalPlaintextRead,
            totalEncryptedSize: totalEncryptedWritten,
            rootSignature: rootSig,
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
        public let rootSignature: String?

        public init(
            iv: Data,
            tag: Data,
            segments: [EncryptedSegment],
            totalPlaintextSize: Int64,
            totalEncryptedSize: Int64,
            rootSignature: String? = nil,
        ) {
            self.iv = iv
            self.tag = tag
            self.segments = segments
            self.totalPlaintextSize = totalPlaintextSize
            self.totalEncryptedSize = totalEncryptedSize
            self.rootSignature = rootSignature
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
            // Drain FileHandle's autoreleased read buffers after each append.
            try autoreleasepool {
                let remaining = Int64(totalSize) - totalPlaintextRead
                let readSize = min(remaining, Int64(chunkSize))
                guard let chunk = try inputHandle.read(upToCount: Int(readSize)), !chunk.isEmpty else {
                    throw StreamingCryptoError.segmentReadFailed
                }
                plaintextAccumulator.append(chunk)
                totalPlaintextRead += Int64(chunk.count)
            }
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

        let rootSig = Data(HMAC<SHA256>.authenticationCode(for: Data(sealed.tag), using: symmetricKey)).base64EncodedString()

        return StreamingEncryptionResult(
            iv: Data(nonce),
            tag: Data(sealed.tag),
            segments: [segment],
            totalPlaintextSize: totalPlaintextRead,
            totalEncryptedSize: totalEncrypted,
            rootSignature: rootSig,
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
        var rawTags: [Data] = []
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
                // Keep read buffers from accumulating across segments.
                try autoreleasepool {
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
            let tagData = Data(sealed.tag)
            lastTag = tagData
            rawTags.append(tagData)

            let segmentStartOffset = try outputHandle.offset()
            try outputHandle.write(contentsOf: Data(nonce))
            try outputHandle.write(contentsOf: sealed.ciphertext)
            try outputHandle.write(contentsOf: tagData)
            let segmentEndOffset = try outputHandle.offset()

            let segmentEncryptedSize = Int64(segmentEndOffset - segmentStartOffset)
            let segmentHash = tagData.base64EncodedString()

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

        let rootSig = Data(HMAC<SHA256>.authenticationCode(
            for: Data(rawTags.joined()),
            using: symmetricKey,
        )).base64EncodedString()

        return StreamingEncryptionResult(
            iv: ivData,
            tag: tagData,
            segments: segments,
            totalPlaintextSize: totalPlaintextRead,
            totalEncryptedSize: totalEncryptedWritten,
            rootSignature: rootSig,
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

    private static func computeSegmentSignature(
        ivData: some DataProtocol,
        ciphertext: some DataProtocol,
        tagData: Data,
        algorithm: String,
        symmetricKey: SymmetricKey,
    ) throws -> Data {
        switch algorithm.uppercased() {
        case "GMAC":
            return tagData
        case "HS256":
            var hmac = HMAC<SHA256>(key: symmetricKey)
            hmac.update(data: ivData)
            hmac.update(data: ciphertext)
            hmac.update(data: tagData)
            return Data(hmac.finalize())
        default:
            throw StreamingCryptoError.integrityCheckFailed
        }
    }

    /// Single-pass streaming multi-segment decryption directly to `outputURL`.
    /// Decrypts and verifies each segment's GCM tag and manifest hash into a private (`0600`)
    /// staging file beside `outputURL` (peak memory is O(largest segment)), then verifies the
    /// HS256 root signature before atomically moving the staging file into place. The parent
    /// directory of `outputURL` must be writable, and existing directories at `outputURL` are
    /// rejected. Removes the staging file on any failure, cutting disk I/O and AES-GCM CPU in
    /// half compared to two-pass `FileHandle` decryption.
    public static func decryptPayloadStreamingMultiSegment(
        inputHandle: FileHandle,
        outputURL: URL,
        segments: [EncryptedSegment],
        symmetricKey: SymmetricKey,
        chunkSize: Int = defaultChunkSize,
        rootSignature: String,
        segmentHashAlg: String = "GMAC",
    ) throws {
        guard chunkSize > 0 else { throw StreamingCryptoError.invalidChunkSize }
        guard !segments.isEmpty else { throw StreamingCryptoError.malformedSegment(0) }

        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: outputURL.path, isDirectory: &isDir), isDir.boolValue {
            throw CocoaError(.fileWriteUnknown)
        }

        let startOffset = try inputHandle.offset()
        let endOffset = try inputHandle.seekToEnd()
        guard endOffset >= startOffset else { throw StreamingCryptoError.segmentReadFailed }
        try inputHandle.seek(toOffset: startOffset)

        let stagingURL = outputURL.deletingLastPathComponent()
            .appendingPathComponent(".\(outputURL.lastPathComponent).\(UUID().uuidString).partial")
        let fd = open(stagingURL.path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
        guard fd >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EACCES)
        }
        let stagingHandle = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        var stagingClosed = false
        var committed = false
        defer {
            if !stagingClosed {
                try? stagingHandle.close()
            }
            if !committed {
                try? FileManager.default.removeItem(at: stagingURL)
            }
        }

        var currentOffset = startOffset
        var segmentSignatures: [Data] = []
        segmentSignatures.reserveCapacity(segments.count)

        for segment in segments {
            try autoreleasepool {
                guard segment.encryptedSize >= 28,
                      let segmentSizeInt = Int(exactly: segment.encryptedSize)
                else {
                    throw StreamingCryptoError.malformedSegment(segment.segmentIndex)
                }
                let segmentSize = UInt64(segment.encryptedSize)
                guard currentOffset <= endOffset, segmentSize <= endOffset - currentOffset else {
                    throw StreamingCryptoError.malformedSegment(segment.segmentIndex)
                }

                let ivData = try inputHandle.read(upToCount: 12) ?? Data()
                guard ivData.count == 12 else {
                    throw StreamingCryptoError.malformedSegment(segment.segmentIndex)
                }

                let ciphertextSize = segmentSizeInt - 28
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

                let computedSig = try computeSegmentSignature(
                    ivData: ivData,
                    ciphertext: ciphertextAccumulator,
                    tagData: tagData,
                    algorithm: segmentHashAlg,
                    symmetricKey: symmetricKey,
                )
                guard let expectedHash = Data(base64Encoded: segment.hash),
                      CryptoHelper.constantTimeEquals(expectedHash, computedSig)
                else {
                    throw StreamingCryptoError.integrityCheckFailed
                }

                let nonce = try AES.GCM.Nonce(data: ivData)
                let sealed = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertextAccumulator, tag: tagData)
                var plaintext: Data
                do {
                    plaintext = try AES.GCM.open(sealed, using: symmetricKey)
                } catch {
                    throw StreamingCryptoError.integrityCheckFailed
                }
                defer { plaintext.secureZero() }
                try stagingHandle.write(contentsOf: plaintext)

                segmentSignatures.append(computedSig)
                currentOffset += segmentSize
            }
        }

        guard currentOffset == endOffset else {
            throw StreamingCryptoError.malformedSegment(segments.last?.segmentIndex ?? 0)
        }

        let computedRoot = Data(HMAC<SHA256>.authenticationCode(
            for: Data(segmentSignatures.joined()),
            using: symmetricKey,
        ))
        guard let expectedRoot = Data(base64Encoded: rootSignature),
              CryptoHelper.constantTimeEquals(expectedRoot, computedRoot)
        else {
            throw StreamingCryptoError.integrityCheckFailed
        }

        try stagingHandle.close()
        stagingClosed = true

        if FileManager.default.fileExists(atPath: outputURL.path) {
            _ = try FileManager.default.replaceItemAt(outputURL, withItemAt: stagingURL)
        } else {
            try FileManager.default.moveItem(at: stagingURL, to: outputURL)
        }
        committed = true
    }

    public static func decryptPayloadStreamingMultiSegment(
        inputHandle: FileHandle,
        outputHandle: FileHandle,
        segments: [EncryptedSegment],
        symmetricKey: SymmetricKey,
        chunkSize: Int = defaultChunkSize,
        rootSignature: String? = nil,
        segmentHashAlg: String = "GMAC",
    ) throws {
        guard chunkSize > 0 else { throw StreamingCryptoError.invalidChunkSize }
        guard !segments.isEmpty else { throw StreamingCryptoError.malformedSegment(0) }
        // Require a rootSignature for every payload (including 1-segment) so an attacker
        // cannot truncate an N-segment payload down to 1 segment and strip the root.
        guard let rootSignature else {
            throw StreamingCryptoError.integrityCheckFailed
        }
        let startOffset = try inputHandle.offset()
        let endOffset = try inputHandle.seekToEnd()
        guard endOffset >= startOffset else { throw StreamingCryptoError.segmentReadFailed }

        // Pass 1: authenticate every segment (GCM tag + manifest segment hash) and the
        // root signature without writing any unverified plaintext to `outputHandle` or disk.
        var currentOffset = startOffset
        var segmentSignatures: [Data] = []
        segmentSignatures.reserveCapacity(segments.count)

        for segment in segments {
            guard segment.encryptedSize >= 28,
                  let segmentSizeInt = Int(exactly: segment.encryptedSize)
            else {
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

            let ciphertextSize = segmentSizeInt - 28
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

            let computedSig = try computeSegmentSignature(
                ivData: ivData,
                ciphertext: ciphertextAccumulator,
                tagData: tagData,
                algorithm: segmentHashAlg,
                symmetricKey: symmetricKey,
            )
            guard let expectedHash = Data(base64Encoded: segment.hash),
                  CryptoHelper.constantTimeEquals(expectedHash, computedSig)
            else {
                throw StreamingCryptoError.integrityCheckFailed
            }

            let nonce = try AES.GCM.Nonce(data: ivData)
            let sealed = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertextAccumulator, tag: tagData)
            var verifiedPlaintext = try AES.GCM.open(sealed, using: symmetricKey)
            verifiedPlaintext.secureZero()

            segmentSignatures.append(computedSig)
            currentOffset += segmentSize
        }

        guard currentOffset == endOffset else {
            throw StreamingCryptoError.malformedSegment(segments.last?.segmentIndex ?? 0)
        }

        let computedRoot = Data(HMAC<SHA256>.authenticationCode(
            for: Data(segmentSignatures.joined()),
            using: symmetricKey,
        ))
        guard let expectedRoot = Data(base64Encoded: rootSignature),
              CryptoHelper.constantTimeEquals(expectedRoot, computedRoot)
        else {
            throw StreamingCryptoError.integrityCheckFailed
        }

        // Pass 2: stream verified plaintext directly to outputHandle, re-verifying every
        // reread segment against its Pass-1 root-authenticated signature before emitting bytes.
        currentOffset = startOffset
        for (index, segment) in segments.enumerated() {
            let segmentSizeInt = Int(segment.encryptedSize)
            let segmentSize = UInt64(segment.encryptedSize)
            try inputHandle.seek(toOffset: currentOffset)

            let ivData = try inputHandle.read(upToCount: 12) ?? Data()
            guard ivData.count == 12 else {
                throw StreamingCryptoError.malformedSegment(segment.segmentIndex)
            }
            let ciphertextSize = segmentSizeInt - 28
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

            let rereadSig = try computeSegmentSignature(
                ivData: ivData,
                ciphertext: ciphertextAccumulator,
                tagData: tagData,
                algorithm: segmentHashAlg,
                symmetricKey: symmetricKey,
            )
            guard CryptoHelper.constantTimeEquals(rereadSig, segmentSignatures[index]) else {
                throw StreamingCryptoError.integrityCheckFailed
            }

            let nonce = try AES.GCM.Nonce(data: ivData)
            let sealed = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertextAccumulator, tag: tagData)
            var plaintext = try AES.GCM.open(sealed, using: symmetricKey)
            defer { plaintext.secureZero() }
            try outputHandle.write(contentsOf: plaintext)

            currentOffset += segmentSize
        }
    }

    public static func decryptPayloadMultiSegmentFromMemory(
        encryptedPayload: Data,
        segments: [EncryptedSegment],
        symmetricKey: SymmetricKey,
        rootSignature: String? = nil,
        segmentHashAlg: String = "GMAC",
    ) throws -> Data {
        guard !segments.isEmpty else {
            throw StreamingCryptoError.malformedSegment(0)
        }
        guard let rootSignature else {
            throw StreamingCryptoError.integrityCheckFailed
        }
        var plaintext = Data()
        plaintext.reserveCapacity(encryptedPayload.count)
        var succeeded = false
        defer {
            if !succeeded {
                plaintext.secureZero()
            }
        }
        var segmentSignatures: [Data] = []
        segmentSignatures.reserveCapacity(segments.count)
        var offset = 0

        for segment in segments {
            guard segment.encryptedSize >= 28,
                  let segmentSize = Int(exactly: segment.encryptedSize),
                  offset <= encryptedPayload.count, segmentSize <= encryptedPayload.count - offset
            else {
                throw StreamingCryptoError.malformedSegment(segment.segmentIndex)
            }

            let start = encryptedPayload.startIndex + offset
            let ivSlice = encryptedPayload[start ..< start + 12]
            let ciphertextSize = segmentSize - 28
            let ciphertextSlice = encryptedPayload[start + 12 ..< start + 12 + ciphertextSize]
            let tagSlice = encryptedPayload[start + 12 + ciphertextSize ..< start + segmentSize]
            let tagData = Data(tagSlice)

            let computedSig = try computeSegmentSignature(
                ivData: ivSlice,
                ciphertext: ciphertextSlice,
                tagData: tagData,
                algorithm: segmentHashAlg,
                symmetricKey: symmetricKey,
            )
            guard let expectedHash = Data(base64Encoded: segment.hash),
                  CryptoHelper.constantTimeEquals(expectedHash, computedSig)
            else {
                throw StreamingCryptoError.integrityCheckFailed
            }

            let nonce = try AES.GCM.Nonce(data: ivSlice)
            let sealed = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertextSlice, tag: tagSlice)
            let segmentPlaintext = try AES.GCM.open(sealed, using: symmetricKey)

            plaintext.append(segmentPlaintext)
            segmentSignatures.append(computedSig)
            offset += segmentSize
        }

        guard offset == encryptedPayload.count else {
            throw StreamingCryptoError.malformedSegment(segments.last?.segmentIndex ?? 0)
        }

        let computedRoot = Data(HMAC<SHA256>.authenticationCode(
            for: Data(segmentSignatures.joined()),
            using: symmetricKey,
        ))
        guard let expectedRoot = Data(base64Encoded: rootSignature),
              CryptoHelper.constantTimeEquals(expectedRoot, computedRoot)
        else {
            throw StreamingCryptoError.integrityCheckFailed
        }
        succeeded = true
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
    case integrityCheckFailed

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
        case .integrityCheckFailed:
            "Segment or root integrity verification failed"
        }
    }
}
