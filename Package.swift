// swift-tools-version: 6.0

import PackageDescription

let package = Package(
  name: "ReasonableACP",
  platforms: [.macOS(.v13), .iOS(.v16), .tvOS(.v16)],
  products: [.library(name: "ReasonableACP", targets: ["ReasonableACP"])],
  targets: [
    .target(name: "ReasonableACP"),
    .executableTarget(name: "RACPInteropPeer", dependencies: ["ReasonableACP"]),
    .testTarget(name: "ReasonableACPTests", dependencies: ["ReasonableACP"]),
  ]
)
