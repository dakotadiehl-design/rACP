// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "AuroraACP",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(name: "ACPModel", targets: ["ACPModel"]),
        .library(name: "ACPEncoding", targets: ["ACPEncoding"]),
        .library(name: "ACPSession", targets: ["ACPSession"]),
    ],
    targets: [
        .target(name: "ACPModel"),
        .target(name: "ACPEncoding", dependencies: ["ACPModel"]),
        .target(
            name: "ACPSession",
            dependencies: ["ACPModel", "ACPEncoding"],
            resources: [.copy("registry.json")]
        ),
        .testTarget(name: "ACPModelTests", dependencies: ["ACPModel"]),
        .testTarget(name: "ACPEncodingTests", dependencies: ["ACPEncoding"]),
        .testTarget(name: "ACPSessionTests", dependencies: ["ACPSession", "ACPEncoding"]),
    ]
)
