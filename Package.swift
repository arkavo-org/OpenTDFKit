// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "NanoTDF",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
        .tvOS(.v18),
        .watchOS(.v11),
    ],
    products: [
        .library(
            name: "NanoTDF",
            targets: ["NanoTDF"]
        ),
    ],
    dependencies: [
        // Dependencies
    ],
    targets: [
        .target(
            name: "NanoTDF",
            dependencies: [],
            path: "NanoTDF"
        ),
        .testTarget(
            name: "Tests",
            dependencies: ["NanoTDF"],
            path: "Tests"
        ),
    ]
)
