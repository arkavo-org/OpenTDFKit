import CryptoKit
import Foundation
@testable import OpenTDFKit
import XCTest

final class StreamingBenchmarkTests: XCTestCase {
    let chunkSizes: [(name: String, size: Int)] = [
        ("2MB", 2 * 1024 * 1024),
        ("5MB", 5 * 1024 * 1024),
        ("25MB", 25 * 1024 * 1024),
    ]

    func testStreamingEncryptionWith2MBChunk() async throws {
        try await measureStreamingEncryption(fileSize: 10 * 1024 * 1024, chunkSize: chunkSizes[0].size, chunkName: chunkSizes[0].name)
    }

    func testStreamingEncryptionWith5MBChunk() async throws {
        try await measureStreamingEncryption(fileSize: 10 * 1024 * 1024, chunkSize: chunkSizes[1].size, chunkName: chunkSizes[1].name)
    }

    func testStreamingEncryptionWith25MBChunk() async throws {
        try await measureStreamingEncryption(fileSize: 10 * 1024 * 1024, chunkSize: chunkSizes[2].size, chunkName: chunkSizes[2].name)
    }

    func testLargeFileStreamingWith2MB() async throws {
        try await measureStreamingEncryption(fileSize: 100 * 1024 * 1024, chunkSize: chunkSizes[0].size, chunkName: chunkSizes[0].name)
    }

    func testLargeFileStreamingWith5MB() async throws {
        try await measureStreamingEncryption(fileSize: 100 * 1024 * 1024, chunkSize: chunkSizes[1].size, chunkName: chunkSizes[1].name)
    }

    func testLargeFileStreamingWith25MB() async throws {
        try await measureStreamingEncryption(fileSize: 100 * 1024 * 1024, chunkSize: chunkSizes[2].size, chunkName: chunkSizes[2].name)
    }

    func testMultiSegmentEncryption() throws {
        let fileSize = 20 * 1024 * 1024
        let segmentSizes = [2 * 1024 * 1024, 5 * 1024 * 1024, 25 * 1024 * 1024]

        let testData = generateTestData(size: fileSize)
        let inputURL = try writeTemporaryFile(data: testData)
        let outputURL = temporaryFileURL(extension: "tdf")

        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        let configuration = try createTestConfiguration()
        let encryptor = TDFEncryptor()

        let startTime = Date()
        let result = try encryptor.encryptFileMultiSegment(
            inputURL: inputURL,
            outputURL: outputURL,
            configuration: configuration,
            segmentSizes: segmentSizes,
        )
        let encryptionTime = Date().timeIntervalSince(startTime)

        XCTAssertGreaterThan(result.container.manifest.encryptionInformation.integrityInformation?.segments.count ?? 0, 1)
        print("Multi-segment encryption (2MB/5MB/25MB): \(String(format: "%.2f", encryptionTime))s")

        let decryptedURL = temporaryFileURL(extension: "dat")
        defer { try? FileManager.default.removeItem(at: decryptedURL) }

        let decryptor = TDFDecryptor()
        let decryptStart = Date()
        try decryptor.decryptFileMultiSegment(
            inputURL: outputURL,
            outputURL: decryptedURL,
            symmetricKey: result.symmetricKey,
        )
        let decryptionTime = Date().timeIntervalSince(decryptStart)

        let decryptedData = try Data(contentsOf: decryptedURL)
        XCTAssertEqual(decryptedData, testData, "Decrypted data should match original")
        print("Multi-segment decryption: \(String(format: "%.2f", decryptionTime))s")
    }

    func testVariableSegmentSizes() throws {
        let segmentSizes = [
            2 * 1024 * 1024,
            5 * 1024 * 1024,
            2 * 1024 * 1024,
            25 * 1024 * 1024,
            5 * 1024 * 1024,
        ]
        let totalSize = segmentSizes.reduce(0, +)

        let testData = generateTestData(size: totalSize)
        let inputURL = try writeTemporaryFile(data: testData)
        let outputURL = temporaryFileURL(extension: "tdf")

        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        let configuration = try createTestConfiguration()
        let encryptor = TDFEncryptor()

        let result = try encryptor.encryptFileMultiSegment(
            inputURL: inputURL,
            outputURL: outputURL,
            configuration: configuration,
            segmentSizes: segmentSizes,
        )

        XCTAssertEqual(result.container.manifest.encryptionInformation.integrityInformation?.segments.count, segmentSizes.count)

        let decryptedURL = temporaryFileURL(extension: "dat")
        defer { try? FileManager.default.removeItem(at: decryptedURL) }

        let decryptor = TDFDecryptor()
        try decryptor.decryptFileMultiSegment(
            inputURL: outputURL,
            outputURL: decryptedURL,
            symmetricKey: result.symmetricKey,
        )

        let decryptedData = try Data(contentsOf: decryptedURL)
        XCTAssertEqual(decryptedData.count, testData.count, "Decrypted size should match original")
        XCTAssertEqual(decryptedData, testData, "Decrypted data should match original")
    }

    func testMemoryUsageWith2MBChunk() throws {
        try requireOwnProcess()
        let fileSize = 50 * 1024 * 1024
        let chunkSize = 2 * 1024 * 1024

        let testData = generateTestData(size: fileSize)
        let inputURL = try writeTemporaryFile(data: testData)
        let outputURL = temporaryFileURL(extension: "tdf")

        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        let peakMemory = try measurePeakMemory {
            try autoreleasepool {
                let configuration = try createTestConfiguration()
                let encryptor = TDFEncryptor()

                _ = try encryptor.encryptFile(
                    inputURL: inputURL,
                    outputURL: outputURL,
                    configuration: configuration,
                    chunkSize: chunkSize,
                )
            }
        }

        print("Peak memory usage (2MB chunks, 50MB file): \(peakMemory / 1024 / 1024) MB")
        assertWithinEncryptFileBudget(peakMemory, fileSize: fileSize)
    }

    func testMemoryUsageWith25MBChunk() throws {
        try requireOwnProcess()
        let fileSize = 50 * 1024 * 1024
        let chunkSize = 25 * 1024 * 1024

        let testData = generateTestData(size: fileSize)
        let inputURL = try writeTemporaryFile(data: testData)
        let outputURL = temporaryFileURL(extension: "tdf")

        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        let peakMemory = try measurePeakMemory {
            try autoreleasepool {
                let configuration = try createTestConfiguration()
                let encryptor = TDFEncryptor()

                _ = try encryptor.encryptFile(
                    inputURL: inputURL,
                    outputURL: outputURL,
                    configuration: configuration,
                    chunkSize: chunkSize,
                )
            }
        }

        print("Peak memory usage (25MB chunks, 50MB file): \(peakMemory / 1024 / 1024) MB")
        assertWithinEncryptFileBudget(peakMemory, fileSize: fileSize)
    }

    private func measureStreamingEncryption(fileSize: Int, chunkSize: Int, chunkName: String) async throws {
        let testData = generateTestData(size: fileSize)
        let inputURL = try writeTemporaryFile(data: testData)
        let outputURL = temporaryFileURL(extension: "tdf")

        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        let configuration = try createTestConfiguration()
        let encryptor = TDFEncryptor()

        let startTime = Date()
        let result = try encryptor.encryptFile(
            inputURL: inputURL,
            outputURL: outputURL,
            configuration: configuration,
            chunkSize: chunkSize,
        )
        let encryptionTime = Date().timeIntervalSince(startTime)
        let throughput = Double(fileSize) / encryptionTime / 1024 / 1024

        print("\(chunkName) chunk - \(fileSize / 1024 / 1024)MB file:")
        print("  Encryption: \(String(format: "%.2f", encryptionTime))s (\(String(format: "%.2f", throughput)) MB/s)")

        let decryptedURL = temporaryFileURL(extension: "dat")
        defer { try? FileManager.default.removeItem(at: decryptedURL) }

        let decryptor = TDFDecryptor()
        let decryptStart = Date()
        try decryptor.decryptFile(
            inputURL: outputURL,
            outputURL: decryptedURL,
            symmetricKey: result.symmetricKey,
            chunkSize: chunkSize,
        )
        let decryptionTime = Date().timeIntervalSince(decryptStart)
        let decryptThroughput = Double(fileSize) / decryptionTime / 1024 / 1024

        print("  Decryption: \(String(format: "%.2f", decryptionTime))s (\(String(format: "%.2f", decryptThroughput)) MB/s)")

        let decryptedData = try Data(contentsOf: decryptedURL)
        XCTAssertEqual(decryptedData, testData, "Decrypted data should match original")

        XCTAssertGreaterThan(throughput, 1.0, "Throughput should be at least 1 MB/s")
    }

    private func generateTestData(size: Int) -> Data {
        var data = Data(count: size)
        data.withUnsafeMutableBytes { buffer in
            guard let baseAddress = buffer.baseAddress else { return }
            arc4random_buf(baseAddress, size)
        }
        return data
    }

    private func writeTemporaryFile(data: Data) throws -> URL {
        let url = temporaryFileURL(extension: "dat")
        try data.write(to: url)
        return url
    }

    private func temporaryFileURL(extension ext: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathExtension(ext)
    }

    private func createTestConfiguration() throws -> TDFEncryptionConfiguration {
        let kasURL = URL(string: "http://localhost:8080/kas")!
        let publicKeyPEM = TestFixtures.testRSAPublicKeyPEM

        let kasInfo = TDFKasInfo(
            url: kasURL,
            publicKeyPEM: publicKeyPEM,
        )

        let policyJSON = """
        {
            "uuid": "\(UUID().uuidString.lowercased())",
            "body": {
                "dataAttributes": [],
                "dissem": []
            }
        }
        """
        let policy = try TDFPolicy(json: policyJSON.data(using: .utf8)!)

        return TDFEncryptionConfiguration(
            kas: kasInfo,
            policy: policy,
            mimeType: "application/octet-stream",
        )
    }

    /// The allocator keeps large freed buffers resident and reuses them, so
    /// earlier tests in the same process would absorb this test's allocations
    /// and hide its cost. These tests run only in a process of their own.
    private func requireOwnProcess() throws {
        try XCTSkipUnless(
            ProcessInfo.processInfo.environment["OPENTDFKIT_MEMORY_BENCHMARK"] == "1",
            "Run alone: OPENTDFKIT_MEMORY_BENCHMARK=1 swift test --filter StreamingBenchmarkTests/<test>",
        )
    }

    /// `encryptFile` holds the plaintext, the sealed box, and the payload in
    /// memory at once, about three times the file size; the chunk size bounds
    /// reads, not memory. More than four times means an extra copy or a leak.
    private func assertWithinEncryptFileBudget(_ peak: Int64, fileSize: Int, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertLessThan(peak, Int64(4 * fileSize), "encryptFile peak \(peak >> 20) MB for a \(fileSize >> 20) MB file", file: file, line: line)
    }

    /// Peak growth of the process footprint while `operation` runs.
    private func measurePeakMemory(operation: () throws -> Void) throws -> Int64 {
        let start = try FootprintSampler.physicalFootprint()
        let sampler = FootprintSampler()
        sampler.start()
        do {
            try operation()
        } catch {
            _ = sampler.stop()
            throw error
        }
        let peak = try max(sampler.stop(), FootprintSampler.physicalFootprint())
        return max(peak - start, 0)
    }
}

/// Samples the process's physical footprint about every millisecond on a
/// background thread and keeps the highest value seen.
private final class FootprintSampler: @unchecked Sendable {
    private let lock = NSLock()
    private var peak: Int64 = 0
    private var running = true

    func start() {
        Thread.detachNewThread { [self] in
            while lock.withLock({ running }) {
                if let footprint = try? Self.physicalFootprint() {
                    lock.withLock { peak = max(peak, footprint) }
                }
                usleep(1000)
            }
        }
    }

    /// Stops sampling and returns the peak seen.
    func stop() -> Int64 {
        lock.withLock {
            running = false
            return peak
        }
    }

    static func physicalFootprint() throws -> Int64 {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        guard result == KERN_SUCCESS else {
            throw NSError(domain: "FootprintSampler", code: Int(result))
        }
        return Int64(info.phys_footprint)
    }
}

private enum TestFixtures {
    static let testRSAPublicKeyPEM = """
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw7tVx7Xt8VXzFgXVUTkn
    UGthp/LiXLMTHVJXk4nJBfTHO3uGTJE4V2/3EHsYn3PQmQVqZVPHKlWtQZfVJ2rS
    +fB9C8pqHxLqRg3qPVkH7yzqGBGj9R1YlGVhfvXJYNrqFCN/R7hLz2RsTEbVnD9T
    qFhPG+FTdWHYT7Z4+R3Lq6yvXZfqHv5VDn6VQGWHmTIz7BpQ5XVWXPQHhNXh4WKp
    X3o6q0vGm8WVhSNcGKUz0nKqBHHYPq8VHxDqh8+VFdKpNXPbkGLJRYF4vVCXHdXy
    QVx8ZLlVVqC7LqPqLLhqFLlYCHNqFXLLBGLFhYqLqPHFVqCqLqPqLLhqFLlYCHNq
    FQIDAQAB
    -----END PUBLIC KEY-----
    """
}
