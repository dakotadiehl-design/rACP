# Supported Apple platforms and architectures

AuroraACP Apple security v1 supports:

| Platform | Minimum OS | Architectures |
| --- | --- | --- |
| macOS | 13 | arm64 |
| iOS device | 16 | arm64 |
| iOS Simulator | 16 | arm64 |

Intel `x86_64` macOS and Simulator builds are not supported. This is an
explicit distribution policy: `AuroraACPSPAKE2.xcframework` intentionally
contains only `macos-arm64`, `ios-arm64`, and `ios-arm64-simulator` slices.
Consumers must not infer Universal macOS support from the Swift package's
platform declaration. Adding Intel support requires a separately built and
qualified native SPAKE2+ artifact and a policy revision; applications must not
work around the missing slice by weakening or replacing the provider.
