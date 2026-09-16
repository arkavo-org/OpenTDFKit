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
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift", from: "1.10.0"),
        // 0.9.20 still warns on watchOS(.v4); development includes the #388 manifest fix
        .package(url: "https://github.com/weichsel/ZIPFoundation", revision: "e7a17d57c583067eaa6659cd6d9521265b7664e9"),
        .package(url: "https://github.com/valpackett/SwiftCBOR", from: "0.6.0"),
    ],
    targets: [
        .target(
            name: "OpenTDFKit",
            dependencies: [
                "CryptoSwift",
                .product(name: "ZIPFoundation", package: "ZIPFoundation"),
                .product(name: "SwiftCBOR", package: "SwiftCBOR"),
            ],
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
