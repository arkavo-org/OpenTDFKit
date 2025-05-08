# OpenTDFKit Guide for Claude

This is a production library.

## Commands
```bash
# Format code
swiftformat --swiftversion 6.0 .

# Build for profiling
swift build -c release
swift run -c release OpenTDFKitProfiler

# Run a specific test
swift test --filter KASServiceTests

# Run performance benchmark
swift test --configuration release --filter KeyStoreBenchmarkTests
```

## Code Style
- **Imports**: Place Foundation first, use @preconcurrency when needed
- **Types**: Use Swift's value types (structs), ensure Sendable conformance
- **Naming**: camelCase for properties/functions, PascalCase for types
- **Formatting**: 4-space indentation, logical section breaks
- **Error Handling**: Define custom Error types, properly propagate errors
- **Documentation**: Comment complex logic, document public APIs
- **Testing**: Use descriptive test names, separate benchmarks from unit tests
- **Concurrency**: Use modern async/await pattern, ensure thread safety

## Project Structure
Main components: KeyStore, NanoTDF, CryptoHelper, KASService