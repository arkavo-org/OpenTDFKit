// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "OpenTDFKit",
    platforms: [
        .iOS(.v18),
        .macOS(.v15),
        .tvOS(.v18),
        .watchOS(.v11),
    ],
    products: [
        .library(
            name: "OpenTDFKit",
            targets: ["OpenTDFKit"]
        ),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "OpenTDFKit",
            dependencies: [],
            path: "OpenTDFKit"
        ),
        .testTarget(
            name: "OpenTDFKitTests",
            dependencies: ["OpenTDFKit"],
            path: "OpenTDFKitTests"
        ),
    ]
)
