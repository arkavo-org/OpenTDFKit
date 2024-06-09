// swift-tools-version:5.1
import PackageDescription

let package = Package(
    name: "NanoTDF",
    platforms: [
        .macOS(.v13), // Update to the latest macOS version
        .iOS(.v16), // Update to the latest iOS version
        .tvOS(.v16), // Update to the latest tvOS version
        .watchOS(.v9) // Update to the latest watchOS version
    ],
    products: [
        .library(
            name: "NanoTDF",
            targets: ["NanoTDF"]),
    ],
    dependencies: [
        // Dependencies
    ],
    targets: [
        .target(
        name: "NanoTDF",
        dependencies: [],
        path: "NanoTDF"),
        .testTarget(
            name: "Tests",
            dependencies: ["NanoTDF"],
            path: "Tests")
    ]
)
