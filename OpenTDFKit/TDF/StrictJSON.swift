import Foundation

/// Checks JSON that Foundation has already parsed for duplicate object member
/// names, which Foundation's parsers resolve silently (first wins), while
/// RFC 7515 §10.12 and RFC 7519 §4 require a JOSE recipient to reject them, and
/// another parser (a relay's) may resolve them differently. Member names are
/// compared after unescaping, so `"a"` and `"a"` are the same name.
enum StrictJSON {
    /// Deeper nesting than this is treated as a duplicate (refused), so the scan
    /// can't exhaust the stack.
    static let maxDepth = 512

    /// `true` when any object in `data` repeats a member name, or when the
    /// input can't be scanned.
    static func hasDuplicateMembers(_ data: Data) -> Bool {
        var scanner = Scanner(bytes: Array(data))
        guard let duplicate = try? scanner.scanValue(depth: 0) else {
            return true
        }
        return duplicate
    }

    private struct ScanError: Error {}

    private struct Scanner {
        let bytes: [UInt8]
        var index = 0

        init(bytes: [UInt8]) {
            self.bytes = bytes
        }

        /// Scans one value; returns whether a duplicate member was found in it.
        mutating func scanValue(depth: Int) throws -> Bool {
            guard depth <= StrictJSON.maxDepth else {
                throw ScanError()
            }
            skipWhitespace()
            guard index < bytes.count else {
                throw ScanError()
            }
            switch bytes[index] {
            case UInt8(ascii: "{"):
                return try scanObject(depth: depth)
            case UInt8(ascii: "["):
                return try scanArray(depth: depth)
            case UInt8(ascii: "\""):
                _ = try scanString()
                return false
            default:
                while index < bytes.count, !Self.isDelimiter(bytes[index]) {
                    index += 1
                }
                return false
            }
        }

        mutating func scanObject(depth: Int) throws -> Bool {
            index += 1
            var names = Set<String>()
            skipWhitespace()
            if peek() == UInt8(ascii: "}") {
                index += 1
                return false
            }
            while true {
                skipWhitespace()
                guard peek() == UInt8(ascii: "\"") else {
                    throw ScanError()
                }
                if try !names.insert(scanString()).inserted {
                    return true
                }
                skipWhitespace()
                guard peek() == UInt8(ascii: ":") else {
                    throw ScanError()
                }
                index += 1
                if try scanValue(depth: depth + 1) {
                    return true
                }
                skipWhitespace()
                switch peek() {
                case UInt8(ascii: ","):
                    index += 1
                case UInt8(ascii: "}"):
                    index += 1
                    return false
                default:
                    throw ScanError()
                }
            }
        }

        mutating func scanArray(depth: Int) throws -> Bool {
            index += 1
            skipWhitespace()
            if peek() == UInt8(ascii: "]") {
                index += 1
                return false
            }
            while true {
                if try scanValue(depth: depth + 1) {
                    return true
                }
                skipWhitespace()
                switch peek() {
                case UInt8(ascii: ","):
                    index += 1
                case UInt8(ascii: "]"):
                    index += 1
                    return false
                default:
                    throw ScanError()
                }
            }
        }

        /// Scans a string starting at its opening quote and returns it unescaped.
        mutating func scanString() throws -> String {
            index += 1
            var utf8: [UInt8] = []
            while index < bytes.count {
                let byte = bytes[index]
                index += 1
                switch byte {
                case UInt8(ascii: "\""):
                    guard let text = String(bytes: utf8, encoding: .utf8) else {
                        throw ScanError()
                    }
                    return text
                case UInt8(ascii: "\\"):
                    guard index < bytes.count else {
                        throw ScanError()
                    }
                    let escape = bytes[index]
                    index += 1
                    switch escape {
                    case UInt8(ascii: "\""), UInt8(ascii: "\\"), UInt8(ascii: "/"):
                        utf8.append(escape)
                    case UInt8(ascii: "b"): utf8.append(0x08)
                    case UInt8(ascii: "f"): utf8.append(0x0C)
                    case UInt8(ascii: "n"): utf8.append(0x0A)
                    case UInt8(ascii: "r"): utf8.append(0x0D)
                    case UInt8(ascii: "t"): utf8.append(0x09)
                    case UInt8(ascii: "u"):
                        var scalar = try scanHex4()
                        if (0xD800 ... 0xDBFF).contains(scalar) {
                            guard peek() == UInt8(ascii: "\\"), peek(1) == UInt8(ascii: "u") else {
                                throw ScanError()
                            }
                            index += 2
                            let low = try scanHex4()
                            guard (0xDC00 ... 0xDFFF).contains(low) else {
                                throw ScanError()
                            }
                            scalar = 0x10000 + ((scalar - 0xD800) << 10) + (low - 0xDC00)
                        }
                        guard let unicode = Unicode.Scalar(scalar) else {
                            throw ScanError()
                        }
                        utf8.append(contentsOf: Array(String(Character(unicode)).utf8))
                    default:
                        throw ScanError()
                    }
                default:
                    utf8.append(byte)
                }
            }
            throw ScanError()
        }

        mutating func scanHex4() throws -> UInt32 {
            guard index + 4 <= bytes.count,
                  let value = UInt32(String(decoding: bytes[index ..< index + 4], as: UTF8.self), radix: 16)
            else {
                throw ScanError()
            }
            index += 4
            return value
        }

        mutating func skipWhitespace() {
            while index < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[index]) {
                index += 1
            }
        }

        func peek(_ offset: Int = 0) -> UInt8? {
            index + offset < bytes.count ? bytes[index + offset] : nil
        }

        static func isDelimiter(_ byte: UInt8) -> Bool {
            [UInt8(ascii: ","), UInt8(ascii: "}"), UInt8(ascii: "]"), 0x20, 0x09, 0x0A, 0x0D].contains(byte)
        }
    }
}
