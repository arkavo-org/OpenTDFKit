import CryptoKit
import Foundation
@testable import OpenTDFKit
import XCTest

/// Repeating an operation must not keep adding to the process footprint.
///
/// On current Apple platforms a large `Data` grown by repeated `append` keeps
/// its old pages after it is freed, so an operation that builds file-sized
/// output that way leaks roughly one file size per call. These tests run each
/// operation several times and measure only the later calls, after any
/// first-call allocator caching has settled.
final class MemoryRetentionTests: XCTestCase {
    private let fileSize = 20 * 1024 * 1024
    /// Far below the 20–40 MB per call the leak adds, far above allocator noise.
    private let allowedGrowth: Int64 = 8 * 1024 * 1024

    func testRepeatedEncryptFileDoesNotRetainMemory() throws {
        let inputURL = try writeTemporaryFile(size: fileSize)
        let outputURL = temporaryURL(extension: "tdf")
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }
        let configuration = try makeConfiguration()

        let growth = try footprintGrowthOverLaterCalls {
            _ = try TDFEncryptor().encryptFile(inputURL: inputURL, outputURL: outputURL, configuration: configuration)
        }

        XCTAssertLessThan(growth, allowedGrowth, "encryptFile retained \(growth >> 20) MB over two calls")
    }

    /// Known leak: ZIPFoundation's in-memory archive overwrites its initial
    /// end record by removing the whole buffer, which drops any reserved
    /// capacity, so the archive grows by `append`. `encryptFile` avoids this
    /// by writing the archive to a file (`buildArchiveToFile`).
    func testRepeatedBuildArchiveDoesNotRetainMemory() throws {
        XCTExpectFailure("In-memory buildArchive retains about one archive size per call", strict: false)
        let payload = Data(repeating: 0x5A, count: fileSize)
        let manifest = try makeManifest()

        let growth = try footprintGrowthOverLaterCalls {
            let archive = try TDFArchiveWriter().buildArchive(manifest: manifest, payload: payload)
            XCTAssertGreaterThan(archive.count, payload.count)
        }

        XCTAssertLessThan(growth, allowedGrowth, "buildArchive retained \(growth >> 20) MB over two calls")
    }

    // MARK: - Helpers

    /// Runs `operation` twice to settle, then twice more, and returns the
    /// footprint growth across the last two calls.
    private func footprintGrowthOverLaterCalls(_ operation: () throws -> Void) throws -> Int64 {
        for _ in 0 ..< 2 {
            try autoreleasepool { try operation() }
        }
        let before = try physicalFootprint()
        for _ in 0 ..< 2 {
            try autoreleasepool { try operation() }
        }
        return try physicalFootprint() - before
    }

    private func physicalFootprint() throws -> Int64 {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        guard result == KERN_SUCCESS else {
            throw XCTSkip("task_info(TASK_VM_INFO) failed: \(result)")
        }
        return Int64(info.phys_footprint)
    }

    private func writeTemporaryFile(size: Int) throws -> URL {
        let url = temporaryURL(extension: "bin")
        try Data(repeating: 0xA5, count: size).write(to: url)
        return url
    }

    private func temporaryURL(extension ext: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("memory-retention-\(UUID().uuidString)")
            .appendingPathExtension(ext)
    }

    private func makeConfiguration() throws -> TDFEncryptionConfiguration {
        try TDFEncryptionConfiguration(
            kas: TDFKasInfo(url: URL(string: "https://kas.example.com/kas")!,
                            publicKeyPEM: TDFSegmentedPayloadTests.makeRSAPublicKeyPEM()),
            policy: TDFPolicy(json: Data(#"{"uuid":"u","body":{"dataAttributes":[],"dissem":[]}}"#.utf8)),
        )
    }

    private func makeManifest() throws -> TDFManifest {
        TDFManifest(
            schemaVersion: "4.3.0",
            payload: TDFPayloadDescriptor(type: .reference, url: "0.payload", protocolValue: .zip, isEncrypted: true),
            encryptionInformation: TDFEncryptionInformation(
                type: .split,
                keyAccess: [],
                method: TDFMethodDescriptor(algorithm: "AES-256-GCM", iv: "", isStreamable: true),
                policy: "e30=",
            ),
        )
    }
}
