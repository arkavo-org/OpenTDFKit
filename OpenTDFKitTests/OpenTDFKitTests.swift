import XCTest
@testable import OpenTDFKit

final class OpenTDFKitTests: XCTestCase {
    
    // Test for KASClient's rewrap function
    func testKASClientRewrap() {
        let kasClient = KASRest(baseURL: "https://platform.virtru.us/api/kas", apiKey: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        let expectation = self.expectation(description: "Rewrap key")
        
        kasClient.rewrap(key: "testKey") { result in
            switch result {
            case .success(let rewrappedKey):
                // In a real test, replace with expected value
                XCTAssertEqual(rewrappedKey, "expectedRewrappedKey")
            case .failure(let error):
                XCTAssertFalse(error.localizedDescription.isEmpty)
            }
            expectation.fulfill()
        }
        
        waitForExpectations(timeout: 5, handler: nil)
    }
}
