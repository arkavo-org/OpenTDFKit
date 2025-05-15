import Foundation
import OpenTDFKit

@main
struct KeyStoreProfiler {
    static func main() async throws {
        print("Starting KeyStore Performance Profiling...")

        // Profile different curve types
        let curves: [Curve] = [.secp256r1, .secp384r1, .secp521r1]

        for curve in curves {
            print("\nProfiling curve: \(curve)")

            // Initialize store
            let store = KeyStore(curve: curve, capacity: 10000)

            // Profile batch generation
            let batchSizes = [100, 1000, 5000]
            for size in batchSizes {
                let start = DispatchTime.now()
                try await store.generateAndStoreKeyPairs(count: size)
                let end = DispatchTime.now()

                let nanoTime = end.uptimeNanoseconds - start.uptimeNanoseconds
                let timeInterval = Double(nanoTime) / 1_000_000_000

                let bytesStored = await store.totalBytesStored
                print("Generated \(size) pairs in \(String(format: "%.3f", timeInterval))s")
                print("Memory used: \(ByteCountFormatter.string(fromByteCount: Int64(bytesStored), countStyle: .memory))")
            }

            // Profile serialization
            let startSerialization = DispatchTime.now()
            let serializedData = await store.serialize()
            let endSerialization = DispatchTime.now()

            let serializationTime = Double(endSerialization.uptimeNanoseconds - startSerialization.uptimeNanoseconds) / 1_000_000_000
            let pairCount = await store.keyPairCount
            print("\nSerialization of \(pairCount) pairs:")
            print("Time: \(String(format: "%.3f", serializationTime))s")
            print("Serialized size: \(ByteCountFormatter.string(fromByteCount: Int64(serializedData.count), countStyle: .memory))")
        }
    }
}

public extension KeyStore {
    var keyPairCount: Int {
        keyPairs.count
    }

    func getFirstKeyPair() -> StoredKeyPair? {
        keyPairs.first?.value
    }
}
