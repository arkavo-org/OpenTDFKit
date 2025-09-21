# NanoTDF Interoperability Findings

## Executive Summary

During integration testing between OpenTDFKit and otdfctl (OpenTDF platform CLI), we discovered that OpenTDFKit's parser does not handle the optional Identifier field in Resource Locators, causing it to misparse otdfctl-generated NanoTDFs. The root cause is a missing implementation detail in OpenTDFKit's BinaryParser, not a specification violation by either implementation.

## Test Environment

- **OpenTDFKit**: Current main branch
- **otdfctl**: Binary from OpenTDF platform
- **Test Platform**: OpenTDF services at 10.0.0.138:8080 (platform) and :8888 (OIDC)
- **Test File**: `test_output.ntdf.tdf` (237 bytes) created via otdfctl

## Root Cause Analysis

### The Real Issue: Missing Resource Locator Identifier Parsing

**Discovery**: The "101-byte ephemeral key" was a misreading caused by OpenTDFKit not parsing the KAS Resource Locator's identifier field.

**What Actually Happens**:

1. **otdfctl generates** (all spec-compliant):
   - KAS Protocol Enum: `0x10` (HTTP protocol with 2-byte identifier)
   - KAS Body Length: 19 bytes
   - KAS Body: "10.0.0.138:8080/kas"
   - KAS Identifier: `0x6531` ("e1" - the KAS key ID)
   - Ephemeral Key follows after the identifier

2. **OpenTDFKit's parser**:
   - Correctly parses Protocol Enum, Body Length, and Body
   - **MISSING**: Does not parse the 2-byte identifier
   - Incorrectly reads byte at offset 0x18 (`0x65`, ASCII 'e' from "e1") as the ephemeral key length
   - Interprets `0x65` as 101 decimal, leading to the "101-byte ephemeral key" error

### Specification Reference

**Section 3.4.1 (Resource Locator)** clearly defines:
- Protocol Enum (1 byte) with bits 7-4 indicating identifier size
- Identifier field: 0, 2, 8, or 32 bytes based on Protocol Enum bits

**Protocol Enum `0x10` breakdown**:
- Bits 3-0: `0x0` = HTTP protocol
- Bits 7-4: `0x1` = 2-byte identifier

## Technical Details

### Hex Dump Analysis

```
Offset  Data          Interpretation
------  -----------   --------------
0x0003  10            Protocol Enum (HTTP + 2-byte ID)
0x0004  13            Body Length (19 bytes)
0x0005  31 30 2e...   "10.0.0.138:8080/kas" (19 bytes)
0x0018  65 31         "e1" (2-byte identifier) ← OpenTDFKit reads 0x65 as key length!
0x001a  [actual ephemeral key starts here]
```

### otdfctl inspect output confirms

```json
{
  "kid": "e1"  // This 2-byte identifier is not being parsed by OpenTDFKit
}
```

## Impact

1. **Parser Failure**: OpenTDFKit's `BinaryParser` fails with `invalidFormat` when encountering Resource Locators with identifiers
2. **Not a Specification Issue**: Both implementations follow the spec; OpenTDFKit just has an incomplete implementation
3. **Simple Fix Required**: Add identifier parsing to OpenTDFKit's Resource Locator handling

## Solution

### Required Changes to OpenTDFKit

In `BinaryParser.swift`, the `readResourceLocator()` function needs to:

1. Read the Protocol Enum byte
2. Extract identifier size from bits 7-4
3. Read and skip the identifier bytes after the body:

```swift
private func readResourceLocator() -> ResourceLocator? {
    guard let protocolByte = readByte(),
          let bodyLength = readByte(),
          let body = read(length: Int(bodyLength)),
          let bodyString = String(data: body, encoding: .utf8)
    else {
        return nil
    }

    // Extract identifier size from protocol byte
    let identifierType = (protocolByte >> 4) & 0x0F
    let identifierSizes = [0, 2, 8, 32]
    let identifierSize = identifierType < 4 ? identifierSizes[Int(identifierType)] : 0

    // Read and store identifier if present
    var identifier: Data? = nil
    if identifierSize > 0 {
        identifier = read(length: identifierSize)
    }

    // Return ResourceLocator with identifier
    return ResourceLocator(
        protocolEnum: ProtocolEnum(rawValue: protocolByte & 0x0F),
        body: bodyString,
        identifier: identifier
    )
}
```

## Testing Verification

After implementing identifier parsing, OpenTDFKit should:
1. Correctly parse the KAS Resource Locator with its 2-byte identifier
2. Find the actual ephemeral key at the correct offset
3. Successfully parse otdfctl-generated NanoTDFs

## Conclusion

The incompatibility is due to an incomplete implementation in OpenTDFKit's BinaryParser, specifically the lack of support for the optional Identifier field in Resource Locators. This is not a specification violation or format incompatibility, but rather a missing feature in OpenTDFKit that can be easily fixed by properly implementing the complete Resource Locator parsing as defined in Section 3.4.1 of the NanoTDF specification.

Both otdfctl and OpenTDFKit are following the specification correctly; OpenTDFKit just needs to implement the full Resource Locator format including the optional identifier field.