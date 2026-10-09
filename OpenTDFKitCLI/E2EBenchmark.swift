import CryptoKit
import Foundation
import OpenTDFKit

// MARK: - End-to-end Standard TDF benchmark

/// `benchmark e2e`: in-process Standard TDF encrypt → KAS rewrap → decrypt timing.
///
/// Mirrors the cross-SDK harness in github.com/eugenioenko/opentdf-sdk
/// (`tests/bench`): one contiguous monotonic timer covers public encryption
/// (including archive serialization) followed by loading and decrypting that
/// same archive through a real KAS rewrap, ending with the plaintext fully
/// materialized. Input generation, OAuth, well-known discovery, KAS public-key
/// fetch and the plaintext check are outside the timer. Per-pair phase
/// timestamps split the interval into encrypt / load / rewrap / decrypt so the
/// network share is visible.
///
/// `--offline` skips the KAS and decrypts with the DEK returned by encryption,
/// isolating SDK compute.
enum E2EBenchmark {
    struct Options {
        var sizes: [Int] = [1 << 20, 10 << 20, 50 << 20]
        var samples = 5
        var warmups = 5
        var segmentSize = 2 << 20
        var offline = false
        var jsonPath: String?
        var keepDirectory: String?
    }

    struct PairTiming {
        var totalMs: Double
        var encryptMs: Double
        var loadMs: Double
        var rewrapMs: Double
        var decryptMs: Double
    }

    static func run(args: [String]) async throws {
        let options = try parseOptions(args)
        let env = ProcessInfo.processInfo.environment

        guard let kasURLString = env["TDF_KAS_URL"] ?? env["KASURL"], let kasURL = URL(string: kasURLString) else {
            throw CLIError.missingEnvironmentVariable("TDF_KAS_URL or KASURL")
        }
        let platformURL = env["PLATFORMURL"]

        let token = try? Commands.resolveOAuthToken(
            providedToken: env["TDF_OAUTH_TOKEN"] ?? env["OAUTH_TOKEN"],
            tokenPath: env["TDF_OAUTH_TOKEN_PATH"] ?? env["OAUTH_TOKEN_PATH"] ?? "fresh_token.txt",
        )
        if !options.offline, token == nil {
            throw CLIError.missingEnvironmentVariable("TDF_OAUTH_TOKEN, OAUTH_TOKEN or a token file (required unless --offline)")
        }

        // Untimed setup: KAS RSA public key, policy, discovery.
        let kasKey: (pem: String, kid: String?)
        if let path = env["TDF_KAS_PUBLIC_KEY_PATH"] {
            kasKey = try (String(contentsOfFile: path, encoding: .utf8), env["TDF_KAS_KID"])
        } else if let token {
            let fetched = try await Commands.fetchKASRSAPublicKey(kasURL: kasURL, platformURL: platformURL, token: token)
            kasKey = (fetched.pem, env["TDF_KAS_KID"] ?? fetched.kid)
        } else {
            throw CLIError.missingEnvironmentVariable("TDF_KAS_PUBLIC_KEY_PATH (or a token to fetch the KAS key)")
        }

        let configuration = try TDFEncryptionConfiguration(
            kas: TDFKasInfo(url: kasURL, publicKeyPEM: kasKey.pem, kid: kasKey.kid),
            policy: TDFPolicy(json: Config.defaultPolicyData(env: env)),
            mimeType: "application/octet-stream",
        )
        let kasConfiguration: OpenTDFConfiguration? = if options.offline {
            nil
        } else {
            await Commands.resolveConfiguration(kasURL: kasURL, token: token ?? "")
        }

        var results: [[String: Any]] = []
        for size in options.sizes {
            let input = deterministicInput(count: size)
            log("size \(size) bytes: \(options.warmups) warmups + \(options.samples) samples, \(options.offline ? "offline (no KAS)" : "real KAS rewrap")")

            var warmups: [PairTiming] = []
            var samples: [PairTiming] = []
            var lastArchive = Data()
            for index in 0 ..< options.warmups + options.samples {
                let (timing, archive) = try await measurePair(
                    input: input,
                    configuration: configuration,
                    segmentSize: options.segmentSize,
                    kasConfiguration: kasConfiguration,
                    token: token,
                )
                if index < options.warmups {
                    warmups.append(timing)
                } else {
                    samples.append(timing)
                }
                lastArchive = archive
            }
            if let directory = options.keepDirectory {
                try lastArchive.write(to: URL(fileURLWithPath: directory).appendingPathComponent("opentdfkit-\(size).tdf"))
            }

            let totals = samples.map(\.totalMs)
            log(String(
                format: "  median %.2f ms (min %.2f, max %.2f) | encrypt %.2f, load %.2f, rewrap %.2f, decrypt %.2f",
                median(totals), totals.min() ?? 0, totals.max() ?? 0,
                median(samples.map(\.encryptMs)), median(samples.map(\.loadMs)),
                median(samples.map(\.rewrapMs)), median(samples.map(\.decryptMs)),
            ))

            results.append([
                "size_bytes": size,
                "samples_ms": totals,
                "warmup_ms": warmups.map(\.totalMs),
                "median_ms": median(totals),
                "minimum_ms": totals.min() ?? 0,
                "maximum_ms": totals.max() ?? 0,
                "phases_ms": [
                    "encrypt": samples.map(\.encryptMs),
                    "load": samples.map(\.loadMs),
                    "rewrap": samples.map(\.rewrapMs),
                    "decrypt": samples.map(\.decryptMs),
                ],
                "peak_rss_bytes_so_far": peakRSSBytes(),
            ])
        }

        let report: [String: Any] = [
            "sdk": "OpenTDFKit",
            "mode": options.offline ? "offline" : "e2e",
            "build": isReleaseBuild ? "release" : "debug",
            "kas_url": kasURL.absoluteString,
            "kid": kasKey.kid ?? "",
            "wrapping": "rsa:2048",
            "response_session": options.offline ? "none" : "ec:secp256r1 (ephemeral per rewrap)",
            "segment_size": options.segmentSize,
            "segment_integrity": "GMAC",
            "root_integrity": "HS256",
            "warmups": options.warmups,
            "samples": options.samples,
            "cpu": sysctlString("machdep.cpu.brand_string") ?? "unknown",
            "os": ProcessInfo.processInfo.operatingSystemVersionString,
            "results": results,
            "peak_rss_bytes": peakRSSBytes(),
            "peak_footprint_bytes": peakFootprintBytes() ?? -1,
        ]
        let json = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
        if let path = options.jsonPath {
            try json.write(to: URL(fileURLWithPath: path))
        }
        FileHandle.standardOutput.write(json)
        FileHandle.standardOutput.write(Data([0x0A]))
    }

    /// One encrypt → decrypt pair under a single contiguous timer. The plaintext
    /// comparison runs after the timer stops.
    private static func measurePair(
        input: Data,
        configuration: TDFEncryptionConfiguration,
        segmentSize: Int,
        kasConfiguration: OpenTDFConfiguration?,
        token: String?,
    ) async throws -> (PairTiming, Data) {
        let clock = ContinuousClock()
        let start = clock.now

        let encrypted = try TDFEncryptor().encrypt(plaintext: input, configuration: configuration, segmentSize: segmentSize)
        let archive = try encrypted.container.serializedData()
        let afterEncrypt = clock.now

        let container = try TDFLoader().load(from: archive)
        let afterLoad = clock.now

        let dek: SymmetricKey
        if let kasConfiguration, let token {
            // A fresh client per pair (new ES256 request-signing key and ephemeral
            // P-256 session key); HTTP connections are reused via URLSession.shared.
            let client = try KASRewrapClient(configuration: kasConfiguration, oauthToken: token)
            dek = try await client.rewrapAndUnwrapTDF(manifest: container.manifest)
        } else {
            dek = encrypted.symmetricKey
        }
        let afterRewrap = clock.now

        let plaintext = try TDFDecryptor().decrypt(container: container, symmetricKey: dek)
        let end = clock.now

        guard plaintext == input else {
            throw CLIError.notYetSupported("benchmark plaintext mismatch")
        }

        let timing = PairTiming(
            totalMs: milliseconds(end - start),
            encryptMs: milliseconds(afterEncrypt - start),
            loadMs: milliseconds(afterLoad - afterEncrypt),
            rewrapMs: milliseconds(afterRewrap - afterLoad),
            decryptMs: milliseconds(end - afterRewrap),
        )
        return (timing, archive)
    }

    // MARK: - Options

    private static func parseOptions(_ args: [String]) throws -> Options {
        var options = Options()
        if let value = OpenTDFKitCLI.findFlag("--sizes", in: args).value {
            options.sizes = try OpenTDFKitCLI.parseSegmentSizes(value)
        }
        if let value = OpenTDFKitCLI.findFlag("--samples", in: args).value {
            guard let samples = Int(value), samples > 0 else { throw CLIError.missingArgument("--samples must be a positive integer") }
            options.samples = samples
        }
        if let value = OpenTDFKitCLI.findFlag("--warmups", in: args).value {
            guard let warmups = Int(value), warmups >= 0 else { throw CLIError.missingArgument("--warmups must be a non-negative integer") }
            options.warmups = warmups
        }
        if let value = OpenTDFKitCLI.findFlag("--segment-size", in: args).value {
            options.segmentSize = try OpenTDFKitCLI.parseChunkSize(value)
        }
        options.offline = args.contains("--offline")
        options.jsonPath = OpenTDFKitCLI.findFlag("--json", in: args).value
        options.keepDirectory = OpenTDFKitCLI.findFlag("--keep", in: args).value
        return options
    }

    // MARK: - Helpers

    /// Deterministic input shared with the cross-SDK harness: byte i = (i*131 + (i>>8)*17) & 255.
    static func deterministicInput(count: Int) -> Data {
        var data = Data(count: count)
        data.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) in
            for index in 0 ..< count {
                buffer[index] = UInt8(truncatingIfNeeded: index &* 131 &+ (index >> 8) &* 17)
            }
        }
        return data
    }

    private static func milliseconds(_ duration: Duration) -> Double {
        let components = duration.components
        return Double(components.seconds) * 1000 + Double(components.attoseconds) / 1e15
    }

    private static func median(_ values: [Double]) -> Double {
        guard !values.isEmpty else { return 0 }
        let sorted = values.sorted()
        let middle = sorted.count / 2
        return sorted.count.isMultiple(of: 2) ? (sorted[middle - 1] + sorted[middle]) / 2 : sorted[middle]
    }

    private static func peakRSSBytes() -> Int {
        var usage = rusage()
        getrusage(RUSAGE_SELF, &usage)
        #if os(Linux)
            return Int(usage.ru_maxrss) * 1024
        #else
            return Int(usage.ru_maxrss)
        #endif
    }

    /// Peak physical footprint (the figure Jetsam and Xcode report). Unlike
    /// `ru_maxrss` it excludes freed pages the allocator keeps cached, which
    /// otherwise make the peak grow with the number of pairs run.
    private static func peakFootprintBytes() -> Int? {
        #if os(macOS) || os(iOS)
            var info = task_vm_info_data_t()
            var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
            let status = withUnsafeMutablePointer(to: &info) {
                $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                    task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
                }
            }
            return status == KERN_SUCCESS ? Int(info.ledger_phys_footprint_peak) : nil
        #else
            return nil
        #endif
    }

    private static func sysctlString(_ name: String) -> String? {
        #if os(macOS)
            var size = 0
            guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
            var buffer = [CChar](repeating: 0, count: size)
            guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else { return nil }
            return String(cString: buffer)
        #else
            return nil
        #endif
    }

    private static var isReleaseBuild: Bool {
        #if DEBUG
            false
        #else
            true
        #endif
    }

    private static func log(_ message: String) {
        FileHandle.standardError.write(Data((message + "\n").utf8))
    }
}
