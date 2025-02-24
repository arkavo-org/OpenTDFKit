import XCTest
@preconcurrency import CryptoKit
@testable import OpenTDFKit

final class KeyStoreBenchmarkTests: XCTestCase {
    func testGenerateAndStore8192EC521Keys() async throws {
        let keyStore = KeyStore(curve: .secp521r1, capacity: 8192)
        let startTime = DispatchTime.now()
        
        // Generate and store keys in a single batch
        try await keyStore.generateAndStoreKeyPairs(count: 8192)
        
        let endTime = DispatchTime.now()
        let timeInterval = Double(endTime.uptimeNanoseconds - startTime.uptimeNanoseconds) / 1_000_000_000
        print("Time to generate and store 8192 EC 521 keys: \(timeInterval) seconds")
        
        // Test serialization metrics
        let serializedData = await keyStore.serialize()
        print("Serialized data size: \(serializedData.count) bytes")
        print("Average bytes per key pair: \(Double(serializedData.count) / 8192)")
        
        // Test key lookup
        let testKeyPair = await keyStore.generateKeyPair()
        await keyStore.store(keyPair: testKeyPair)
        
        // Test hasKey performance
        let lookupStartTime = DispatchTime.now()
        let exists = await keyStore.hasKey(publicKey: testKeyPair.publicKey)
        let lookupEndTime = DispatchTime.now()
        let lookupTimeInterval = Double(lookupEndTime.uptimeNanoseconds - lookupStartTime.uptimeNanoseconds) / 1_000_000
        
        XCTAssertTrue(exists)
        print("Time to check key existence: \(lookupTimeInterval) milliseconds")
        
        // Test private key retrieval
        let privateKeyStartTime = DispatchTime.now()
        let foundPrivateKey = await keyStore.getPrivateKey(forPublicKey: testKeyPair.publicKey)
        let privateKeyEndTime = DispatchTime.now()
        let privateKeyTimeInterval = Double(privateKeyEndTime.uptimeNanoseconds - privateKeyStartTime.uptimeNanoseconds) / 1_000_000
        
        XCTAssertNotNil(foundPrivateKey)
        XCTAssertEqual(foundPrivateKey, testKeyPair.privateKey)
        print("Time to retrieve private key: \(privateKeyTimeInterval) milliseconds")
    }
    
    func testKeyLookupPerformance() async throws {
        let totalPairs = 1000
        let lookupIterations = 10000
        let keyStore = KeyStore(curve: .secp521r1, capacity: totalPairs)
        
        print("Generating \(totalPairs) test key pairs...")
        try await keyStore.generateAndStoreKeyPairs(count: totalPairs)
        
        let publicKeys = await keyStore.getAllPublicKeys()
        
        // Test hasKey performance
        print("Running \(lookupIterations) random existence checks...")
        let existsStartTime = DispatchTime.now()
        
        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<lookupIterations {
                group.addTask {
                    let randomIndex = Int.random(in: 0..<publicKeys.count)
                    let publicKey = publicKeys[randomIndex]
                    let exists = await keyStore.hasKey(publicKey: publicKey)
                    XCTAssertTrue(exists, "Failed existence check")
                }
            }
            try await group.waitForAll()
        }
        
        let existsEndTime = DispatchTime.now()
        let existsTimeMs = Double(existsEndTime.uptimeNanoseconds - existsStartTime.uptimeNanoseconds) / 1_000_000
        let avgExistsTimeMs = existsTimeMs / Double(lookupIterations)
        
        // Test private key retrieval performance
        print("Running \(lookupIterations) random private key retrievals...")
        let retrievalStartTime = DispatchTime.now()
        
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
        
        let retrievalEndTime = DispatchTime.now()
        let retrievalTimeMs = Double(retrievalEndTime.uptimeNanoseconds - retrievalStartTime.uptimeNanoseconds) / 1_000_000
        let avgRetrievalTimeMs = retrievalTimeMs / Double(lookupIterations)
        
        print("""
        Lookup Performance Metrics:
        - Total lookups: \(lookupIterations)
        - Average existence check time: \(avgExistsTimeMs) ms
        - Existence checks per second: \(Double(lookupIterations) / (existsTimeMs / 1000))
        - Average private key retrieval time: \(avgRetrievalTimeMs) ms
        - Private key retrievals per second: \(Double(lookupIterations) / (retrievalTimeMs / 1000))
        """)
    }
    
    func testSerializationPerformance() async throws {
        let keyCounts = [100, 1000, 10000]
        
        for count in keyCounts {
            let keyStore = KeyStore(curve: .secp521r1, capacity: count)
            
            print("\nGenerating \(count) key pairs...")
            let genStartTime = DispatchTime.now()
            try await keyStore.generateAndStoreKeyPairs(count: count)
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
        let keyStore = KeyStore(curve: .secp521r1)
        let recipientKeyPair = await keyStore.generateKeyPair()
        
        measure {
            let expectation = expectation(description: "Key exchange completed")
            
            Task {
                let (sharedSecret, _) = try await keyStore.performKeyExchange(
                    publicKey: recipientKeyPair.publicKey
                )
                
                XCTAssertNotNil(sharedSecret)
                expectation.fulfill()
            }
            
            wait(for: [expectation], timeout: 10.0)
        }
    }
}
