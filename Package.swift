// swift-tools-version:6.2
import PackageDescription

let package = Package(
    name: "OpenTDFKit",
    platforms: [
        .iOS(.v26),
        .macOS(.v26),
        .tvOS(.v26),
        .watchOS(.v26),
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
    dependencies: [],
    targets: [
        .target(
            name: "OpenTDFKit",
            dependencies: [],
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
        ),
    ],
)
