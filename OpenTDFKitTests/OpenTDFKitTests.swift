@testable import OpenTDFKit
import XCTest

final class OpenTDFKitTests: XCTestCase {
    // Test for KASClient's rewrap function
    func testKASClientRewrap() {
        let kasClient = KASRest(baseURL: "https://platform.virtru.us/api/kas", apiKey: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        let expectation = expectation(description: "Rewrap key")

        kasClient.rewrap(key: "testKey") { result in
            switch result {
            case let .success(rewrappedKey):
                // In a real test, replace with expected value
                XCTAssertEqual(rewrappedKey, "expectedRewrappedKey")
            case let .failure(error):
                XCTAssertFalse(error.localizedDescription.isEmpty)
            }
            expectation.fulfill()
        }

        waitForExpectations(timeout: 5, handler: nil)
    }
}
