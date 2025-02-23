import XCTest
@preconcurrency import CryptoKit
@testable import OpenTDFKit

final class KeyStoreBenchmarkTests: XCTestCase {
    func testGenerateAndStore8192EC521Keys() async throws {
        let keyStore = KeyStore(capacity: 8192)
        let startTime = DispatchTime.now()
        
        // Generate and store keys in a single batch
        try await keyStore.generateAndStoreKeyPairs(count: 8192, curve: .secp521r1)
        
        let endTime = DispatchTime.now()
        let timeInterval = Double(endTime.uptimeNanoseconds - startTime.uptimeNanoseconds) / 1_000_000_000
        print("Time to generate and store 8192 EC 521 keys: \(timeInterval) seconds")
        
        // Test serialization metrics
        let serializedData = await keyStore.serialize()
        print("Serialized data size: \(serializedData.count) bytes")
        print("Average bytes per key pair: \(Double(serializedData.count) / 8192)")
        
        // Test key lookup
        let testKeyPair = await keyStore.generateKeyPair(curve: .secp521r1)
        await keyStore.store(keyPair: testKeyPair)
        
        let lookupStartTime = DispatchTime.now()
        let foundPrivateKey = await keyStore.getPrivateKey(forPublicKey: testKeyPair.publicKey)
        let lookupEndTime = DispatchTime.now()
        let lookupTimeInterval = Double(lookupEndTime.uptimeNanoseconds - lookupStartTime.uptimeNanoseconds) / 1_000_000
        
        XCTAssertNotNil(foundPrivateKey)
        XCTAssertEqual(foundPrivateKey, testKeyPair.privateKey)
        print("Time to lookup key: \(lookupTimeInterval) milliseconds")
    }
    
    func testKeyLookupPerformance() async throws {
        let totalPairs = 1000
        let lookupIterations = 10000
        let keyStore = KeyStore(capacity: totalPairs)
        
        print("Generating \(totalPairs) test key pairs...")
        try await keyStore.generateAndStoreKeyPairs(count: totalPairs, curve: .secp521r1)
        
        let publicKeys = await keyStore.getAllPublicKeys()
        
        print("Running \(lookupIterations) random key lookups...")
        let startTime = DispatchTime.now()
        
        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<lookupIterations {
                group.addTask {
                    let randomIndex = Int.random(in: 0..<publicKeys.count)
                    let publicKey = publicKeys[randomIndex]
                    let privateKey = await keyStore.getPrivateKey(forPublicKey: publicKey)
                    XCTAssertNotNil(privateKey, "Failed to find private key")
                }
            }
            try await group.waitForAll()
        }
        
        let endTime = DispatchTime.now()
        let nanoTime = endTime.uptimeNanoseconds - startTime.uptimeNanoseconds
        let totalTimeMs = Double(nanoTime) / 1_000_000
        let avgLookupTimeMs = totalTimeMs / Double(lookupIterations)
        
        print("""
        Lookup Performance Metrics:
        - Total lookups: \(lookupIterations)
        - Total time: \(totalTimeMs) ms
        - Average lookup time: \(avgLookupTimeMs) ms
        - Lookups per second: \(Double(lookupIterations) / (totalTimeMs / 1000))
        """)
    }
    
    func testSerializationPerformance() async throws {
        let keyCounts = [100, 1000, 10000]
        
        for count in keyCounts {
            let keyStore = KeyStore(capacity: count)
            
            print("\nGenerating \(count) key pairs...")
            let genStartTime = DispatchTime.now()
            try await keyStore.generateAndStoreKeyPairs(count: count, curve: .secp521r1)
            let genEndTime = DispatchTime.now()
            let genTimeMs = Double(genEndTime.uptimeNanoseconds - genStartTime.uptimeNanoseconds) / 1_000_000
            
            print("Testing serialization with \(count) keys...")
            var serializedSize: Int = 0
            let iterations = 5
            
            let startTime = DispatchTime.now()
            for i in 1...iterations {
                let data = await keyStore.serialize()
                serializedSize = data.count
                print("Iteration \(i): \(data.count) bytes")
            }
            let endTime = DispatchTime.now()
            
            let totalTimeMs = Double(endTime.uptimeNanoseconds - startTime.uptimeNanoseconds) / 1_000_000
            let avgTimeMs = totalTimeMs / Double(iterations)
            
            print("""
            Performance Metrics for \(count) keys:
            - Generation time: \(genTimeMs) ms
            - Average serialization time: \(avgTimeMs) ms
            - Serialized size: \(serializedSize) bytes
            - Bytes per key pair: \(Double(serializedSize) / Double(count))
            - Serialization throughput: \(Double(serializedSize) * Double(iterations) / (totalTimeMs / 1000) / 1024 / 1024) MB/s
            """)
        }
    }
    
    func testKeyExchangePerformance() async throws {
        let keyStore = KeyStore()
        let recipientKeyPair = await keyStore.generateKeyPair(curve: .secp521r1)
        
        measure {
            let expectation = expectation(description: "Key exchange completed")
            
            Task {
                let (sharedSecret, _) = try await keyStore.performKeyExchange(
                    publicKey: recipientKeyPair.publicKey,
                    curve: .secp521r1
                )
                
                XCTAssertNotNil(sharedSecret)
                expectation.fulfill()
            }
            
            wait(for: [expectation], timeout: 10.0)
        }
    }
}

// Extension to help with testing
extension KeyStore {
    func getAllPublicKeys() -> [Data] {
        return Array(keyPairs.values.map { $0.publicKey })
    }
}
