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
        .executable(name: "acp-enrollment-fixture", targets: ["acp-enrollment-fixture"]),
    ],
    targets: [
        .target(
            name: "AuroraACP",
            resources: [
                .copy("Codec/schema_pack.json"),
                .copy("Session/registry.json"),
                .copy("Security/constants.json"),
            ]
        ),
        .executableTarget(
            name: "acp-framed-hello",
            dependencies: ["AuroraACP"]
        ),
        .executableTarget(
            name: "acp-enrollment-fixture",
            dependencies: ["AuroraACP"],
            path: "tools/acp-enrollment-fixture"
        ),
        .testTarget(
            name: "AuroraACPTests",
            dependencies: ["AuroraACP"],
            path: "tests/AuroraACPTests"
        ),
    ]
)
