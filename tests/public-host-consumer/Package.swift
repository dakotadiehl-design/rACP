// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ACPPublicHostConsumer",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(name: "AuroraCommunicationsProtocol", path: "../.."),
    ],
    targets: [
        .executableTarget(
            name: "ACPPublicHostConsumer",
            dependencies: [
                .product(name: "AuroraACP", package: "AuroraCommunicationsProtocol"),
                .product(name: "AuroraACPAppleSecurity", package: "AuroraCommunicationsProtocol"),
            ]),
    ]
)
