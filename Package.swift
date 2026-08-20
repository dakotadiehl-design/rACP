// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AuroraCommunicationsProtocol",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(name: "AuroraACP", targets: ["AuroraACP"]),
        .executable(name: "acp-framed-hello", targets: ["acp-framed-hello"]),
    ],
    targets: [
        .target(
            name: "AuroraACP",
            resources: [
                .copy("Codec/schema_pack.json"),
                .copy("Session/registry.json"),
            ]
        ),
        .executableTarget(
            name: "acp-framed-hello",
            dependencies: ["AuroraACP"]
        ),
        .testTarget(
            name: "AuroraACPTests",
            dependencies: ["AuroraACP"],
            path: "tests/AuroraACPTests"
        ),
    ]
)
