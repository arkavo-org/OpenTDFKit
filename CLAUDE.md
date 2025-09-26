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

## Authentication

### Getting an OAuth Token

The OpenTDF test environment uses a mock OIDC provider for authentication. To get an access token:

```bash
# Get token from mock OIDC provider (port 8888, not the main platform port 8080)
# Set OIDC_ENDPOINT environment variable, defaults to http://localhost:8888
curl -s -X POST "${OIDC_ENDPOINT:-http://localhost:8888}/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=opentdf-client&client_secret=secret" \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])" > fresh_token.txt

# The token will be saved to fresh_token.txt for use by the CLI tools
```

### Getting KAS Public Keys

The KAS endpoint returns different key types based on the algorithm parameter:

```bash
# Get EC key for NanoTDF (secp256r1/P-256)
# Set PLATFORMURL environment variable, defaults to http://localhost:8080
curl -H "Authorization: Bearer $(cat fresh_token.txt)" \
  "${PLATFORMURL:-http://localhost:8080}/kas/v2/kas_public_key?algorithm=ec:secp256r1"

# Get RSA key (default, for standard TDF)
curl -H "Authorization: Bearer $(cat fresh_token.txt)" \
  "${PLATFORMURL:-http://localhost:8080}/kas/v2/kas_public_key"
```

## Commands

```bash
# Basic build
swift build

# Build with optimizations
swift build -c release

# Format code (required before submitting PRs)
swiftformat --swiftversion 6.2 .

# Build for profiling
swift build -c release
swift run -c release OpenTDFKitProfiler

# Build CLI tool
swift build -c release --product OpenTDFKitCLI

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

## CLI Tool

OpenTDFKit includes a command-line interface for encrypting and decrypting NanoTDF files, designed for cross-SDK testing with xtest.

### Building the CLI

```bash
# Build the CLI in release mode
swift build -c release --product OpenTDFKitCLI

# The binary will be at: .build/release/OpenTDFKitCLI
```

### CLI Usage

```bash
# Encrypt a file to NanoTDF
.build/release/OpenTDFKitCLI encrypt input.txt output.ntdf nano

# Encrypt with ECDSA binding
.build/release/OpenTDFKitCLI encrypt input.txt output.ntdf nano-with-ecdsa

# Decrypt a NanoTDF file
.build/release/OpenTDFKitCLI decrypt output.ntdf recovered.txt nano

# Check supported features
.build/release/OpenTDFKitCLI supports nano          # exit 0 (supported)
.build/release/OpenTDFKitCLI supports nano_ecdsa    # exit 0 (supported)
.build/release/OpenTDFKitCLI supports ztdf          # exit 1 (not supported)
```

### Environment Configuration

The CLI reads configuration from environment variables (compatible with xtest):

```bash
# Required for KAS integration
export CLIENTID=opentdf-client
export CLIENTSECRET=secret
export KASURL=http://localhost:8080/kas
export PLATFORMURL=http://localhost:8080

# Optional xtest parameters
export XT_WITH_ECDSA_BINDING=true
export XT_WITH_PLAINTEXT_POLICY=true
export XT_WITH_ATTRIBUTES="attr1,attr2"
export XT_WITH_MIME_TYPE="application/pdf"
```

### Integration Testing

For cross-SDK testing with otdfctl:

```bash
# Create a NanoTDF with otdfctl (if working)
otdfctl encrypt --tdf-type nano test.txt --out test.ntdf

# Parse it with OpenTDFKit CLI
.build/release/OpenTDFKitCLI decrypt test.ntdf recovered.txt nano

# Or create with OpenTDFKit and decrypt with otdfctl
.build/release/OpenTDFKitCLI encrypt test.txt test.ntdf nano
otdfctl decrypt test.ntdf --out recovered.txt
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
