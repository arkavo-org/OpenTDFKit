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

    func testMultiSegmentEncryption() async throws {
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
        let encryptor = StandardTDFEncryptor()

        let startTime = Date()
        let result = try encryptor.encryptFileMultiSegment(
            inputURL: inputURL,
            outputURL: outputURL,
            configuration: configuration,
            segmentSizes: segmentSizes,
        )
        let encryptionTime = Date().timeIntervalSince(startTime)

        XCTAssertGreaterThan(result.container.manifest.encryptionInformation.integrityInformation.segments.count, 1)
        print("Multi-segment encryption (2MB/5MB/25MB): \(String(format: "%.2f", encryptionTime))s")

        let decryptedURL = temporaryFileURL(extension: "dat")
        defer { try? FileManager.default.removeItem(at: decryptedURL) }

        let decryptor = StandardTDFDecryptor()
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

    func testVariableSegmentSizes() async throws {
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
        let encryptor = StandardTDFEncryptor()

        let result = try encryptor.encryptFileMultiSegment(
            inputURL: inputURL,
            outputURL: outputURL,
            configuration: configuration,
            segmentSizes: segmentSizes,
        )

        XCTAssertEqual(result.container.manifest.encryptionInformation.integrityInformation.segments.count, segmentSizes.count)

        let decryptedURL = temporaryFileURL(extension: "dat")
        defer { try? FileManager.default.removeItem(at: decryptedURL) }

        let decryptor = StandardTDFDecryptor()
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
        let fileSize = 50 * 1024 * 1024
        let chunkSize = 2 * 1024 * 1024

        let peakMemory = try measurePeakMemory {
            try autoreleasepool {
                let testData = generateTestData(size: fileSize)
                let inputURL = try writeTemporaryFile(data: testData)
                let outputURL = temporaryFileURL(extension: "tdf")

                defer {
                    try? FileManager.default.removeItem(at: inputURL)
                    try? FileManager.default.removeItem(at: outputURL)
                }

                let configuration = try createTestConfiguration()
                let encryptor = StandardTDFEncryptor()

                _ = try encryptor.encryptFile(
                    inputURL: inputURL,
                    outputURL: outputURL,
                    configuration: configuration,
                    chunkSize: chunkSize,
                )
            }
        }

        print("Peak memory usage (2MB chunks, 50MB file): \(peakMemory / 1024 / 1024) MB")
        XCTAssertLessThan(peakMemory, Int64(15 * 1024 * 1024), "Peak memory should be less than 15MB")
    }

    func testMemoryUsageWith25MBChunk() throws {
        let fileSize = 50 * 1024 * 1024
        let chunkSize = 25 * 1024 * 1024

        let peakMemory = try measurePeakMemory {
            try autoreleasepool {
                let testData = generateTestData(size: fileSize)
                let inputURL = try writeTemporaryFile(data: testData)
                let outputURL = temporaryFileURL(extension: "tdf")

                defer {
                    try? FileManager.default.removeItem(at: inputURL)
                    try? FileManager.default.removeItem(at: outputURL)
                }

                let configuration = try createTestConfiguration()
                let encryptor = StandardTDFEncryptor()

                _ = try encryptor.encryptFile(
                    inputURL: inputURL,
                    outputURL: outputURL,
                    configuration: configuration,
                    chunkSize: chunkSize,
                )
            }
        }

        print("Peak memory usage (25MB chunks, 50MB file): \(peakMemory / 1024 / 1024) MB")
        XCTAssertLessThan(peakMemory, Int64(80 * 1024 * 1024), "Peak memory should be less than 80MB")
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
        let encryptor = StandardTDFEncryptor()

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

        let decryptor = StandardTDFDecryptor()
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

    private func createTestConfiguration() throws -> StandardTDFEncryptionConfiguration {
        let kasURL = URL(string: "http://localhost:8080/kas")!
        let publicKeyPEM = TestFixtures.testRSAPublicKeyPEM

        let kasInfo = StandardTDFKasInfo(
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
        let policy = try StandardTDFPolicy(json: policyJSON.data(using: .utf8)!)

        return StandardTDFEncryptionConfiguration(
            kas: kasInfo,
            policy: policy,
            mimeType: "application/octet-stream",
        )
    }

    private func measurePeakMemory(operation: () throws -> Void) throws -> Int64 {
        let startMemory = getMemoryUsage()
        try operation()
        let endMemory = getMemoryUsage()
        return max(endMemory - startMemory, 0)
    }

    private func getMemoryUsage() -> Int64 {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size) / 4
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: 1) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }
        return result == KERN_SUCCESS ? Int64(info.resident_size) : 0
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
