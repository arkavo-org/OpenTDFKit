## Context

READ CLAUDE.md, README.md, and SPECIFICATIONS.md to understand the context of the OpenTDFKit project. Then run `git ls-files` and `swift files` to get a full picture of the repository structure.

## Coding

For coding tasks, ensure you follow the code style guidelines in CLAUDE.md:
- Place Foundation first in imports, use @preconcurrency when needed
- Use Swift's value types (structs) and ensure Sendable conformance
- Follow camelCase for properties/functions, PascalCase for types
- Use 4-space indentation and logical section breaks
- Define custom Error types and properly propagate errors
- Document public APIs and comment complex logic
- Use descriptive test names and separate benchmarks from unit tests
- Use the modern async/await pattern and ensure thread safety

When implementing features, run `swift build` to verify your changes compile correctly.

## Testing

For testing, run the specific test suite related to your changes:
```
swift test --filter KASServiceTests
```

For performance testing, use:
```
swift test --configuration release --filter "BenchmarkTests"
```

## Code Formatting

Before submitting changes, format your code using:
```
swiftformat --swiftversion 6.0 .
```

## Profiling

For performance profiling:
```
swift build -c release
swift run -c release OpenTDFKitProfiler
```
