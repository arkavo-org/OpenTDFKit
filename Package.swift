// swift-tools-version:6.2
import PackageDescription

let package = Package(
    name: "OpenTDFKit",
    platforms: [
        .iOS(.v18),
        .macOS(.v14),
        .tvOS(.v18),
        .watchOS(.v11),
    ],
    products: [
        .library(
            name: "OpenTDFKit",
            targets: ["OpenTDFKit"],
        ),
        .executable(
            name: "OpenTDFKitProfiler",
            targets: ["OpenTDFKitProfiler"],
        ),
        .executable(
            name: "OpenTDFKitCLI",
            targets: ["OpenTDFKitCLI"],
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift", from: "1.8.0"),
    ],
    targets: [
        .target(
            name: "OpenTDFKit",
            dependencies: ["CryptoSwift"],
            path: "OpenTDFKit",
        ),
        .executableTarget(
            name: "OpenTDFKitProfiler",
            dependencies: ["OpenTDFKit"],
            path: "OpenTDFKitProfiler",
        ),
        .testTarget(
            name: "OpenTDFKitTests",
            dependencies: ["OpenTDFKit"],
            path: "OpenTDFKitTests",
        ),
        .executableTarget(
            name: "OpenTDFKitCLI",
            dependencies: ["OpenTDFKit"],
            path: "OpenTDFKitCLI",
            exclude: ["REQUIREMENTS_XTEST.md", "INTEGRATION.md"],
            swiftSettings: [
                .unsafeFlags(["-parse-as-library"]),
            ],
        ),
    ],
)
