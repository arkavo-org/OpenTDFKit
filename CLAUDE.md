# OpenTDFKit Guide for Claude

OpenTDFKit is a Swift implementation of the OpenTDF (Trusted Data Format) specification, focusing on the NanoTDF format. It provides a secure framework for encrypting, decrypting, and managing protected data with policy-based access controls in Apple ecosystems.

## Prerequisites

- Swift 6.0 or later
- Xcode 16.0 or later
- macOS 15.0+ for development

## Installation

### Swift Package Manager

Add OpenTDFKit to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/opentdf/openTDFKit.git", from: "1.0.0")
]
```

## Commands

```bash
# Basic build
swift build

# Build with optimizations
swift build -c release

# Format code (required before submitting PRs)
swiftformat --swiftversion 6.0 .

# Build for profiling
swift build -c release
swift run -c release OpenTDFKitProfiler

# Run all tests
swift test

# Run a specific test suite
swift test --filter KASServiceTests

# Run performance benchmarks
swift test --configuration release --filter "BenchmarkTests"

# Generate documentation
swift package generate-documentation

# Update dependencies
swift package update
```

## Code Style

- **Imports**: Place Foundation first, use @preconcurrency when needed
- **Types**: Use Swift's value types (structs), ensure Sendable conformance for thread safety
- **Naming**: camelCase for properties/functions, PascalCase for types
- **Formatting**: 4-space indentation, logical section breaks with MARK comments
- **Error Handling**: Define custom Error types, properly propagate errors with meaningful messages
- **Documentation**: Comment complex logic, document all public APIs with DocC-compatible format
- **Testing**: Use descriptive test names, separate benchmarks from unit tests
- **Concurrency**: Use modern async/await pattern and actors, ensure thread safety with Sendable compliance

## Project Structure

OpenTDFKit is composed of several key components that work together to implement the NanoTDF specification:

- **KeyStore**: Manages cryptographic keys with support for various elliptic curves. Provides efficient key generation, storage, and retrieval in a thread-safe manner. Supports serialization for key data persistence.

- **NanoTDF**: Core implementation of the NanoTDF format according to the OpenTDF specification. Handles the creation, serialization, and parsing of NanoTDF containers, including policy binding and payload encryption/decryption.

- **CryptoHelper**: Provides cryptographic primitives for OpenTDF operations. Supports various elliptic curves (secp256r1, secp384r1, secp521r1) and implements secure key derivation and symmetric encryption methods.

- **KASService**: Enables key access services for policy-based decryption. Implements secure key exchange protocols and policy binding verification.

- **PublicKeyStore**: Manages only public keys for sharing with peers. Allows secure distribution of one-time use TDF keys.

## Performance Considerations

OpenTDFKit is designed for high-performance cryptographic operations. When implementing features, keep in mind:

- Minimize memory allocations, especially in cryptographic hot paths
- Use contiguous memory where possible for better performance
- Leverage Swift's value semantics for thread safety without excessive locking
- Consider the documented performance benchmarks when making changes

## Version Compatibility

- Swift 6.0+: Fully supported with all features
- Apple Platforms: Supports macOS 13.0+, iOS 16.0+, watchOS 9.0+, and tvOS 16.0+

## Contribution Guidelines

1. Ensure code follows the style guidelines above
2. Run `swiftformat` before submitting PRs
3. Write tests for all new functionality
4. Update documentation for public API changes
5. Run performance tests to ensure changes don't negatively impact performance
6. For significant changes, consider adding benchmark comparisons
