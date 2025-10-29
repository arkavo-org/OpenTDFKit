# OpenTDFKit Guide for Claude

OpenTDFKit is a Swift implementation of the OpenTDF (Trusted Data Format) specification, supporting both **NanoTDF** (compact binary format) and **TDF (Archive Envelope)** (ZIP-based format). It provides a secure framework for encrypting, decrypting, and managing protected data with policy-based access controls in Apple ecosystems.

## Prerequisites

- Swift 6.0 or later
- Xcode 16.0 or later
- macOS 14.0+ for development

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

# Get RSA key (default, for.archive TDF)
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

# Encrypt to TDF (Archive Envelope)
.build/release/OpenTDFKitCLI encrypt input.txt output.tdf tdf

# Decrypt TDF (Archive Envelope)
.build/release/OpenTDFKitCLI decrypt output.tdf recovered.txt tdf

# Verify TDF structure
.build/release/OpenTDFKitCLI verify output.tdf

# Check supported features
.build/release/OpenTDFKitCLI supports nano          # exit 0 (supported)
.build/release/OpenTDFKitCLI supports nano_ecdsa    # exit 0 (supported)
.build/release/OpenTDFKitCLI supports tdf           # exit 0 (supported)
.build/release/OpenTDFKitCLI supports ztdf          # exit 0 (supported)
```

### Environment Configuration

The CLI reads configuration from environment variables (compatible with xtest):

#### NanoTDF Configuration
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

#### TDF (Archive Envelope) Configuration
```bash
# Required for encryption
export TDF_KAS_URL=http://localhost:8080/kas
export TDF_KAS_PUBLIC_KEY_PATH=/path/to/kas-rsa-public.pem  # RSA public key (min 2048-bit)
export TDF_OUTPUT_SYMMETRIC_KEY_PATH=/path/to/save-key.txt  # Where to save generated key

# Required for decryption (choose one method)
# Method 1: Offline decryption with symmetric key
export TDF_SYMMETRIC_KEY_PATH=/path/to/symmetric-key.txt    # Symmetric key from encryption

# Method 2: KAS rewrap decryption (recommended for production)
export TDF_CLIENT_PRIVATE_KEY_PATH=/path/to/client-private.pem  # RSA private key for unwrapping
export TDF_CLIENT_PUBLIC_KEY_PATH=/path/to/client-public.pem    # RSA public key for rewrap request
# Also requires OAuth token (via fresh_token.txt or inline)

# Optional configuration
export TDF_MIME_TYPE=application/pdf                         # Content MIME type
export TDF_POLICY_JSON='{"uuid":"...","body":{...}}'         # Custom policy JSON
export TDF_POLICY_PATH=/path/to/policy.json                  # Or load from file
export TDF_SPEC_VERSION=4.3.0                                # TDF spec version (default: 4.3.0)
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

OpenTDFKit is composed of several key components that work together to implement both NanoTDF and TDF (Archive Envelope) specifications:

### NanoTDF Components

- **KeyStore**: Manages cryptographic keys with support for various elliptic curves. Provides efficient key generation, storage, and retrieval in a thread-safe manner. Supports serialization for key data persistence.

- **NanoTDF**: Core implementation of the NanoTDF format according to the OpenTDF specification. Handles the creation, serialization, and parsing of NanoTDF containers, including policy binding and payload encryption/decryption.

- **CryptoHelper**: Provides cryptographic primitives for OpenTDF operations. Supports various elliptic curves (secp256r1, secp384r1, secp521r1) and implements secure key derivation and symmetric encryption methods.

- **KASService**: Enables key access services for policy-based decryption. Implements secure key exchange protocols and policy binding verification.

- **PublicKeyStore**: Manages only public keys for sharing with peers. Allows secure distribution of one-time use TDF keys.

- **KASRewrapClient**: Client for interacting with KAS rewrap endpoints. Implements JWT signing (ES256), PEM parsing, and key unwrapping protocols. Supports both NanoTDF (EC key wrapping) and TDF (Archive Envelope) (RSA key wrapping) rewrap requests. Designed with protocol-based architecture for testability.

### TDF (Archive Envelope) Components

- **TDFManifest**: Complete OpenTDF schema data structures for TDF (Archive Envelope) v1.0.0. Includes manifest, payload descriptor, encryption information, key access objects, and integrity information with proper Codable conformance.

- **TDFCrypto**: RSA and AES cryptographic operations for TDF (Archive Envelope). Implements RSA-2048+ key wrapping with OAEP padding, AES-256-GCM encryption, HMAC-SHA256 for integrity and policy binding. Includes key size validation (minimum 2048 bits).

- **TDFProcessor**: High-level encryption and decryption operations. Handles symmetric key generation, key wrapping, policy binding, segment signatures, and multi-KAS key reconstruction via XOR. Supports both offline decryption (with symmetric key) and KAS rewrap decryption (with RSA key pair).

- **TDFArchive**: ZIP archive I/O using ZIPFoundation. Reads and writes TDF (Archive Envelope) containers with proper `0.manifest.json` and `0.payload` structure. Supports both camelCase .archive) JSON encoding.

- **TrustedDataFormat**: Format abstraction protocol enabling polymorphic handling of both NanoTDF and TDF (Archive Envelope) containers.

- **TDFBuilder/Loader**: Builder pattern for container creation and loader for parsing existing TDF files.

## Architecture

### Component Interactions

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       ├─ Create NanoTDF ────────────────────────────────────┐
       │                                                      │
       ▼                                                      ▼
┌─────────────┐      ┌──────────────┐      ┌──────────────────────┐
│  KeyStore   │◄─────│  KASService  │◄─────│   CryptoHelper       │
└─────────────┘      └──────┬───────┘      └──────────────────────┘
                            │                         │
                            │                         │ ECDH + HKDF
                            │                         │ AES-GCM Encrypt
                            │                         │
       ┌────────────────────┴────────┐                │
       │                             │                │
       ▼                             ▼                ▼
┌─────────────┐              ┌─────────────┐   ┌──────────┐
│  NanoTDF    │              │   Policy    │   │ Payload  │
│   Header    │              │   Binding   │   │ Encrypted│
└─────────────┘              └─────────────┘   └──────────┘

       │
       ├─ Decrypt NanoTDF ────────────────────────────────────┐
       │                                                      │
       ▼                                                      ▼
┌─────────────────┐                            ┌──────────────────────┐
│ KASRewrapClient │──── JWT + HTTPS ──────────►│   KAS Server         │
└─────────┬───────┘                            └──────────┬───────────┘
          │                                               │
          │ 1. Send signed JWT with policy                │
          │ 2. KAS validates policy                       │
          │ 3. KAS rewraps key                            │
          │◄──────── Wrapped Key + Session PubKey ────────┤
          │                                               │
          ▼                                               ▼
┌─────────────────┐                            ┌──────────────────────┐
│  ECDH Unwrap    │                            │  Policy Enforcement  │
└─────────┬───────┘                            └──────────────────────┘
          │
          ▼
┌─────────────────┐
│ AES-GCM Decrypt │
└─────────────────┘
```

### KAS Rewrap Flow

The KAS rewrap protocol enables secure key distribution with policy enforcement:

1. **Request Preparation**
   - Client creates ephemeral key pair (P-256)
   - Constructs rewrap request with NanoTDF header and policy
   - Signs request with ES256 JWT (60-second expiration)

2. **KAS Processing**
   - Validates OAuth bearer token
   - Verifies JWT signature
   - Evaluates policy against client attributes
   - Performs ECDH with client's ephemeral public key
   - Derives symmetric key using HKDF-SHA256 with NanoTDF salt
   - Encrypts payload key with AES-GCM-128 (platform uses 16-byte tags)

3. **Key Unwrapping**
   - Client receives wrapped key (nonce + ciphertext + tag format)
   - Performs ECDH with KAS session public key
   - Derives same symmetric key using HKDF-SHA256
   - Decrypts wrapped key with AES-GCM
   - Uses unwrapped key to decrypt NanoTDF payload

### Cryptographic Operations

#### Key Agreement
- **Algorithm**: ECDH with P-256 curve (secp256r1)
- **Key Derivation**: HKDF-SHA256
  - Salt: SHA256(magicNumber + version) for version compatibility
  - Info: Empty (per NanoTDF spec section 4)
  - Output: 32 bytes (AES-256)

#### Symmetric Encryption
- **Algorithm**: AES-256-GCM
- **Supported Tag Sizes**: 64, 96, 104, 112, 120, 128 bits
  - 128-bit tags use CryptoKit (optimized)
  - Other tag sizes use CryptoSwift
- **IV Size**: 12 bytes (96 bits)
- **Nonce Handling**: 3-byte NanoTDF nonce + 9-byte zero padding

#### Policy Binding
- **Algorithm**: GMAC (GCM with empty plaintext)
- **Tag Size**: 64 bits (8 bytes, truncated per spec 3.3.1.3)
- **Purpose**: Cryptographic binding between payload key and policy

#### JWT Signing
- **Algorithm**: ES256 (ECDSA with P-256 and SHA-256)
- **Key Type**: Ephemeral P256.Signing.PrivateKey per client instance
- **Claims**: requestBody, iat, exp (60-second lifetime)

### Error Handling

OpenTDFKit implements comprehensive error handling:

- **KASRewrapError**: HTTP errors (400/401/403/404/500/502/503/504), authentication failures, PEM parsing errors
- **CryptoHelperError**: Unsupported curves, key derivation failures, invalid states
- **NanoTDFError**: (component-specific errors defined in NanoTDF.swift)

All errors implement CustomStringConvertible with actionable messages.

## Testing Strategy

### Unit Tests
- **KASRewrapClientTests**: JWT signing, PEM parsing, HTTP error handling, key unwrapping
- **GCMEncryptionTests**: All tag sizes (64-128 bits), validation, CryptoKit vs CryptoSwift
- **CryptoHelperTests**: ECDH, HKDF, encryption/decryption, policy binding
- **KeyStoreTests**: Key generation, storage, retrieval, serialization
- **NanoTDFTests**: Header parsing, payload encryption, version compatibility

### Integration Tests
- **Environment-based**: Uses KASURL, PLATFORMURL, CLIENTID, CLIENTSECRET environment variables
- **No hardcoded credentials**: All secrets from environment or test fixtures
- **Graceful skipping**: Tests skip with clear instructions if environment not configured
- **End-to-end**: Full NanoTDF creation, KAS rewrap, and decryption flow

### Benchmark Tests
- **Performance metrics**: Encryption/decryption throughput, key generation speed
- **Memory profiling**: Allocation counts, contiguous memory usage
- **Comparison baselines**: Track performance across changes

### Running Tests
```bash
# Run all tests
swift test

# Run specific test suite
swift test --filter KASRewrapClientTests
swift test --filter GCMEncryptionTests
swift test --filter IntegrationTests

# Run with environment for integration tests
export KASURL=http://localhost:8080/kas
export PLATFORMURL=http://localhost:8080
export CLIENTID=opentdf-client
export CLIENTSECRET=secret
swift test --filter IntegrationTests

# Run benchmarks
swift test --configuration release --filter "BenchmarkTests"
```

## Format Selection Guide

### When to Use NanoTDF

**Advantages:**
- Compact binary format (~240-260 bytes overhead)
- Optimized for small payloads (<10KB)
- Full KAS integration with rewrap support
- ECDSA binding available
- Lower bandwidth requirements

**Use Cases:**
- IoT device communications
- Real-time messaging
- Small file transfers
- Bandwidth-constrained environments

### When to Use TDF (Archive Envelope)

**Advantages:**
- Industry.archive ZIP-based format
- Better for large files (>1KB)
- Cross-SDK compatibility (with caveats)
- Extensible with assertions (future)
- Human-readable manifest (JSON)

**Use Cases:**
- Document encryption
- Large file storage
- Multi-segment files (future)
- Cross-platform workflows

**File Size Overhead:**
| Input Size | NanoTDF Overhead | TDF (Archive Envelope) Overhead | Recommendation |
|-----------|------------------|----------------------|----------------|
| 10 bytes  | ~250 bytes (2500%) | ~1,110 bytes (11,060%) | NanoTDF |
| 100 bytes | ~250 bytes (250%) | ~1,110 bytes (1,108%) | NanoTDF |
| 1 KB      | ~250 bytes (25%) | ~1,110 bytes (111%) | Either |
| 10 KB     | ~250 bytes (2.5%) | ~1,115 bytes (11%) | TDF (Archive Envelope) |
| 100 KB    | ~250 bytes (0.25%) | ~1,141 bytes (1.1%) | TDF (Archive Envelope) |

## Performance Considerations

OpenTDFKit is designed for high-performance cryptographic operations. When implementing features, keep in mind:

- Minimize memory allocations, especially in cryptographic hot paths
- Use contiguous memory where possible for better performance
- Leverage Swift's value semantics for thread safety without excessive locking
- Consider the documented performance benchmarks when making changes

### TDF (Archive Envelope) Specific Notes

- **Memory Usage**: Current implementation loads entire payload into memory
- **Large Files**: For files >100MB, consider external chunking before encryption
- **Single-Segment**: Only single-segment TDFs currently supported
- **RSA Operations**: Key wrapping/unwrapping is computationally intensive

## Version Compatibility

- Swift 6.0+: Fully supported with all features
- Apple Platforms: Supports macOS 14.0+, iOS 18.0+, watchOS 11.0+, tvOS 18.0+
- GitHub Actions CI: Runs on macos-latest (currently macOS 14)

## Contribution Guidelines

1. Ensure code follows the style guidelines above
2. Run `swiftformat` before submitting PRs
3. Write tests for all new functionality
4. Update documentation for public API changes
5. Run performance tests to ensure changes don't negatively impact performance
6. For significant changes, consider adding benchmark comparisons
