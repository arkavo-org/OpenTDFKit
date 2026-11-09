import Foundation
@testable import OpenTDFKit
import XCTest

/// `StrictJSON.hasDuplicateMembers`: duplicate member names anywhere, compared
/// after unescaping, with no false positives from arrays or string content.
final class StrictJSONTests: XCTestCase {
    func testDetectsDuplicates() {
        for json in [
            #"{"a":1,"a":2}"#,
            #"{"a":1,"a":2}"#,
            #"{"x":{"b":true,"b":false}}"#,
            #"[{"k":"v"},{"k":"v","k":"w"}]"#,
            #"{"🔒":1,"🔒":2}"#,
        ] {
            XCTAssertTrue(StrictJSON.hasDuplicateMembers(Data(json.utf8)), json)
        }
    }

    func testNoFalsePositives() {
        for json in [
            #"{"a":[{"a":1},{"a":2}],"b":"{\"a\":1,\"a\":2}"}"#,
            #"{"a":1,"A":2,"a ":3}"#,
            #"[1,2.5e3,true,false,null,"s"]"#,
            #"{}"#,
            #"{"esc":"\"\\\/\b\f\n\r\té"}"#,
        ] {
            XCTAssertFalse(StrictJSON.hasDuplicateMembers(Data(json.utf8)), json)
        }
    }

    func testTooDeepIsRefused() {
        let deep = String(repeating: "[", count: 600) + String(repeating: "]", count: 600)
        XCTAssertTrue(StrictJSON.hasDuplicateMembers(Data(deep.utf8)))
    }
}
