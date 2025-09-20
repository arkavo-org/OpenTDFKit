# Repository Guidelines

## Project Structure & Module Organization
- `Package.swift` defines the Swift Package targets; the default module `OpenTDFKit` exports the public API for NanoTDF operations.
- Sources live under `OpenTDFKit/` with focused files such as `NanoTDF.swift`, `KeyStore.swift`, and `KASService.swift` governing parsing, key handling, and KAS integrations.
- Tests reside in `OpenTDFKitTests/`, following XCTest conventions (`*Tests`, `*BenchmarkTests`) for functional, policy, and performance coverage.
- `OpenTDFKitProfiler/` contains profiling harnesses for release builds, while `OpenTDFKit.xcodeproj` supports Xcode development.

## Build, Test, and Development Commands
- `swift build` compiles all targets with the Swift 6 toolchain.
- `swift test` runs the full XCTest suite; add `--filter NanoTDFTests` for targeted checks.
- `swift test --configuration release --filter "BenchmarkTests"` executes the performance suites before publishing metrics.
- `swiftformat --swiftversion 6.2 .` enforces consistent formatting; run prior to every commit.
- `swift run -c release OpenTDFKitProfiler` drives the profiler target when validating cryptographic hot paths.

## Coding Style & Naming Conventions
- Follow Swift API Design Guidelines: UpperCamelCase types, lowerCamelCase members, and explicit access control (`public`/`internal`) for SDK clarity.
- Prefer value types (structs, enums) over classes unless reference semantics are required; group extensions by responsibility.
- Indentation is 4 spaces; do not mix tabs. Keep imports minimal and alphabetized.
- Leave explanatory comments only where algorithms or protocols are non-obvious, especially around cryptography.

## Testing Guidelines
- Add XCTest coverage adjacent to the feature in `OpenTDFKitTests/FeatureNameTests.swift`.
- Name tests `testFunctionality_whenCondition_expectOutcome` to document intent and edge cases.
- Place benchmarks in `*BenchmarkTests.swift`; guard runtime-heavy code with `#if !CI` when necessary.
- Verify new tests locally with `swift test` and note any targeted filters in the PR description.

## Commit & Pull Request Guidelines
- Write imperative, concise commit messages (e.g., `Add NanoTDF concurrent (#12)`), referencing PR numbers when applicable.
- Squash fixups before review and avoid committing generated artifacts or secrets.
- Pull requests must include a change summary, test results, and linked GitHub issues; attach screenshots or payload samples when behavior shifts.
- Request review from crypto maintainers for changes touching key derivation, storage, or network flows.
- Confirm `swiftformat` and `swift test` have both run before requesting a merge.
