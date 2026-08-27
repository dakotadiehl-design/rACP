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
        .library(name: "AuroraACPAppleSecurity", targets: ["AuroraACPAppleSecurity"]),
        .executable(name: "acp-framed-hello", targets: ["acp-framed-hello"]),
        .executable(name: "acp-enrollment-fixture", targets: ["acp-enrollment-fixture"]),
        .executable(name: "acp-apple-full-qualification", targets: ["acp-apple-full-qualification"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-certificates.git", exact: "1.19.4"),
        .package(url: "https://github.com/apple/swift-asn1.git", exact: "1.7.1"),
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
        .target(
            name: "AuroraACPAppleSecurity",
            dependencies: [
                "AuroraACP", "AuroraACPSPAKE2",
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ],
            linkerSettings: [
                .linkedFramework("Network"), .linkedFramework("Security"),
                .linkedLibrary("c++"),
            ]
        ),
        .binaryTarget(
            name: "AuroraACPSPAKE2",
            path: "Artifacts/AuroraACPSPAKE2.xcframework"
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
        .executableTarget(
            name: "acp-apple-full-qualification",
            dependencies: ["AuroraACP", "AuroraACPAppleSecurity"],
            path: "tools/acp-apple-full-qualification"
        ),
        .testTarget(
            name: "AuroraACPTests",
            dependencies: ["AuroraACP"],
            path: "tests/AuroraACPTests"
        ),
        .testTarget(
            name: "AuroraACPAppleSecurityTests",
            dependencies: [
                "AuroraACP", "AuroraACPAppleSecurity",
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ],
            path: "tests/AuroraACPAppleSecurityTests"
        ),
    ]
)
