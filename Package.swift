// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "OpenTDFKit",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
        .iPadOS(.v17)
    ],
    products: [
        .library(
            name: "OpenTDFKit",
            targets: ["KASClient"]),
    ],
    dependencies: [
    ],
    targets: [
        .target(
            name: "OpenTDFKit",
            dependencies: []),
        .testTarget(
            name: "OpenTDFKitTests",
            dependencies: ["KASClient"]),
    ]
)
