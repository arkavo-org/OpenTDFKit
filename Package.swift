// swift-tools-version:5.1
import PackageDescription

let package = Package(
    name: "NanoTDF",
    platforms: [
        .macOS(.v10_15)
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
