# Aurora Communications Protocol
## Swift Package Conversion and Distribution Handoff for Grok

**Document purpose:** Convert the existing Swift implementation of the Aurora Communications Protocol (ACP) into the canonical, standalone Swift Package used by Aurora applications such as Prism, Remote, Conductor, and Lyric.

**Primary architectural rule:** ACP must exist in exactly one canonical source repository. Aurora applications consume ACP as a dependency. They must not contain copied or forked ACP protocol source.

---

# 1. Objective

Refactor/package the existing Swift ACP implementation as a standalone Swift Package Manager (SPM) library named `AuroraACP` without changing established protocol behavior unless a packaging defect makes a small change unavoidable.

The resulting ACP repository must:

- Build independently of Prism, Remote, Conductor, Lyric, or any other application.
- Export a stable Swift library product named `AuroraACP`.
- Be consumable as either:
  - a local Swift package during active multi-repository development, or
  - a remote Git-hosted Swift package pinned by version/tag for normal integration and release builds.
- Own all generic ACP protocol behavior.
- Contain no Prism-specific, Remote-specific, Conductor-specific, or Lyric-specific domain code.
- Preserve the existing ACP wire protocol, session semantics, acknowledgement methodology, discovery behavior, profiles, capability negotiation, error handling, and tests.
- Pass `swift build` and `swift test` from the repository root.

Do not redesign ACP merely because it is becoming a Swift package. This task is primarily packaging, modularity, public API hygiene, dependency cleanup, and test independence.

---

# 2. Target Repository Layout

Prefer one primary Swift module initially. Do not split ACP into many modules unless an existing technical constraint clearly requires it.

```text
AuroraCommunicationsProtocol/
├── Package.swift
├── README.md
├── CHANGELOG.md
├── LICENSE                 # if applicable
├── Documentation/
│   ├── ACP_Interface_Control_Document.*
│   └── ...
├── Sources/
│   └── AuroraACP/
│       ├── Core/
│       ├── Codec/
│       ├── Transport/
│       ├── Session/
│       ├── Discovery/
│       ├── Profiles/
│       │   ├── Remote/
│       │   └── ...
│       ├── Assets/
│       ├── Diagnostics/
│       └── Utilities/
└── Tests/
    └── AuroraACPTests/
        ├── Core/
        ├── Codec/
        ├── Transport/
        ├── Session/
        ├── Discovery/
        ├── Profiles/
        ├── Interop/
        └── Fixtures/
```

Folder names may be adjusted to reflect the actual existing source tree. The important constraints are:

1. Production Swift sources belong under `Sources/AuroraACP`.
2. Tests belong under `Tests/AuroraACPTests`.
3. The package must compile independently.
4. Application integration/adapters do not belong in this repository.

---

# 3. Package.swift Requirements

Create a root `Package.swift` manifest appropriate for the Swift toolchain and deployment targets actually used by the Aurora applications.

A baseline shape is:

```swift
// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "AuroraCommunicationsProtocol",
    platforms: [
        .macOS(.v14),
        .iOS(.v17)
    ],
    products: [
        .library(
            name: "AuroraACP",
            targets: ["AuroraACP"]
        )
    ],
    targets: [
        .target(
            name: "AuroraACP"
        ),
        .testTarget(
            name: "AuroraACPTests",
            dependencies: ["AuroraACP"]
        )
    ]
)
```

This is an architectural example, not an instruction to blindly impose those deployment versions. Determine the minimum supported macOS/iOS versions from the current Aurora projects and select compatible package platform floors. The package must not unnecessarily raise the deployment target of a consuming app.

If ACP has genuine external dependencies, declare them explicitly in `Package.swift`. Do not rely on dependencies that happen to exist in Prism's Xcode project.

---

# 4. Module and Import Contract

The expected application-facing module name is:

```swift
import AuroraACP
```

A consuming application should never need to include ACP `.swift` files directly.

The package product should therefore be named `AuroraACP`, backed initially by a target/module also named `AuroraACP`.

Do not require consumers to import a pile of tiny ACP modules unless there is a compelling reason. Internal logical grouping should initially be represented by folders and namespaces within the single module.

---

# 5. Access-Control Audit

Moving ACP out of an application target and into a separate Swift module changes Swift access-control behavior. Audit the complete API surface.

Do **not** mechanically mark every declaration `public`.

Classify declarations into two groups.

## 5.1 Public ACP API

Types and members intentionally consumed by Aurora applications should be public. Examples may include, depending on the current implementation:

- ACP session types
- ACP identity types
- capability models
- envelope/message types intended for host/client integration
- profile contracts
- Remote profile command/state models
- asset identity/manifest contracts
- connection state/event surfaces
- host/client configuration
- errors intentionally surfaced to applications
- diagnostics intentionally surfaced to applications

Public initializers and methods required to construct/use those types must also be public.

## 5.2 Internal ACP implementation

Implementation details should remain `internal` or `private`, including where applicable:

- frame parser internals
- byte-buffer helpers
- codec implementation details
- socket plumbing
- retry machinery
- timer implementation
- state-machine internals
- bookkeeping containers
- private synchronization primitives
- private sequence/ACK tracking internals

The objective is a deliberate supported API, not merely "whatever compiled before."

---

# 6. Application Independence

Search the current ACP implementation for imports, references, extensions, protocols, callbacks, or types owned by any Aurora application.

ACP must not depend on:

```text
Prism
Remote
Conductor
Lyric
Bridge application domain models
```

Examples of things that must remain in Prism rather than ACP:

```text
PrismACPHost
PrismRemoteAdapter
PrismAssetAdapter
PrismACPStatePublisher
PrismCueCommandHandler
PrismControlActionRouter bindings
```

ACP may define generic protocol concepts that these adapters implement or consume, but it must not know Prism's cue engine, programmer state, fixture store, UI, or other application internals.

Target dependency direction:

```text
AuroraACP
    ↓
Prism ACP integration/adapters
    ↓
Prism application services
    ↓
ControlActionRouter / authoritative Prism state
```

Never:

```text
AuroraACP → Prism
```

---

# 7. Preserve Protocol Behavior

This packaging task must not silently change network compatibility.

Unless separately specified, preserve:

- discovery behavior
- WebSocket transport behavior
- ACP framing and serialization
- message names/types
- identifiers
- version negotiation
- capability negotiation
- ACK semantics
- sequencing
- duplicate handling
- timeout behavior
- retry behavior
- error codes
- authentication/authorization behavior, if present
- Remote profile semantics
- asset synchronization semantics
- diagnostics semantics

If a behavior change is required to make the package independent, document it explicitly and add tests covering it.

---

# 8. Test Requirements

All existing ACP tests should move with ACP rather than remain trapped inside Prism or another app.

The package must support:

```bash
swift build
swift test
```

from the ACP repository root.

Tests should cover at minimum all existing coverage and retain/expand tests for:

- encode/decode round trips
- malformed frames/messages
- protocol version handling
- handshake/session establishment
- capability negotiation
- ACK correlation
- sequence handling
- duplicate/replay behavior where defined
- timeouts
- reconnect behavior
- disconnect cleanup
- Remote profile commands
- Remote profile state/snapshot/delta behavior
- asset identity and manifest handling
- error propagation
- representative interop/test vectors

Tests must not require launching Prism.

Where integration tests need an endpoint, use package-owned test doubles, loopback transports, or fixtures.

---

# 9. Consumer Integration Model

Aurora applications will consume the package in one of two ways.

## 9.1 Local package during active development

A development checkout may look like:

```text
~/Development/Aurora/
├── ACP/
├── Prism/
├── Remote/
├── Conductor/
└── Lyric/
```

Xcode can add `~/Development/Aurora/ACP` as a local package. Multiple applications may point at the same local checkout while ACP is under active development.

This is the preferred workflow when protocol and application integrations are being developed together.

## 9.2 Remote Git package for stable integration

The canonical ACP repository should use semantic version tags, for example:

```text
1.0.0
1.1.0
1.1.1
1.2.0
```

Stable application branches/releases should consume the remote package by repository URL and a deliberate version requirement, preferably a pinned release or a controlled compatible range depending on release policy.

Example lifecycle:

```text
ACP development
    ↓
package tests pass
    ↓
commit / review
    ↓
tag ACP 1.2.0
    ↓
Prism adopts 1.2.0
Remote adopts 1.2.0
Conductor adopts 1.2.0
```

Do not make stable Aurora releases depend on an arbitrary moving branch such as `main` unless explicitly requested for a development-only workflow.

---

# 10. Semantic Versioning Policy

Use semantic versioning for the Swift package and protocol implementation release.

```text
MAJOR.MINOR.PATCH
```

Interpretation:

- PATCH: compatible bug fix, no intentional public API or protocol break.
- MINOR: backward-compatible capability/API addition.
- MAJOR: breaking public API or protocol compatibility change.

The ACP wire protocol's own version-negotiation semantics remain authoritative for network compatibility. Package version and wire-protocol version are related release metadata but must not be conflated if the existing protocol already distinguishes them.

---

# 11. Package.resolved and Reproducibility

Consumers should allow Swift Package Manager/Xcode to record the resolved dependency version in the consuming project/workspace's `Package.resolved` as appropriate.

Do not hand-copy ACP source as a workaround for dependency resolution.

Do not use Git submodules for the primary Swift application integration unless specifically directed later. Swift Package Manager is the intended distribution mechanism.

---

# 12. Documentation Requirements

Update the ACP README with a short "Using AuroraACP" section that includes:

1. What the package is.
2. Supported platforms.
3. How to add it as a local package in Xcode.
4. How to add it by repository URL.
5. The module import statement:

```swift
import AuroraACP
```

6. A minimal usage example that does not depend on any Aurora application.
7. How to run:

```bash
swift build
swift test
```

8. Release/tagging convention.

Do not make the README a replacement for the ACP Interface Control Document. The README is developer onboarding; the ICD remains the protocol authority.

---

# 13. Prism Migration Expectations

This repository task should leave ACP ready for a separate Prism migration pass.

Prism's subsequent work will be:

1. Add the local or remote `AuroraACP` package dependency.
2. Add the `AuroraACP` library product to the Prism application target.
3. Replace direct inclusion of ACP protocol source with:

```swift
import AuroraACP
```

4. Retain Prism-specific adapters in Prism.
5. Delete duplicate ACP protocol source from Prism once package linkage is verified.
6. Run Prism tests and ACP/Prism integration tests.

Do not solve application integration by putting Prism source into the package.

---

# 14. Migration Safety

Perform the conversion in a way that makes accidental behavior drift obvious.

Recommended sequence:

1. Inventory current ACP source files and tests.
2. Establish the Swift package skeleton.
3. Move protocol source into `Sources/AuroraACP` with minimal code edits.
4. Move ACP-owned tests into `Tests/AuroraACPTests`.
5. Resolve package-only compile failures.
6. Audit `public` vs `internal` access control.
7. Remove application dependencies through abstractions/adapters where necessary.
8. Run the complete package test suite.
9. Compare protocol fixtures/golden vectors before and after migration.
10. Only then integrate the package into Prism.
11. Remove Prism's duplicate ACP implementation after integration tests pass.

Do not delete the only working source copy until the package builds/tests independently and Prism successfully consumes it.

---

# 15. Explicit Non-Goals

This task is **not** permission to:

- redesign ACP
- rename wire-level messages casually
- change serialization formats
- change ACK semantics
- replace WebSocket transport
- change discovery semantics
- add compatibility shims for Prism's retired legacy remote stack
- move Prism domain logic into ACP
- create separate copies of ACP per application
- introduce Git submodules as the primary sharing mechanism
- break the existing ACP Interface Control Document without an explicit protocol revision

---

# 16. Acceptance Criteria

The conversion is complete when all of the following are true:

- [ ] ACP has a valid root `Package.swift`.
- [ ] `AuroraACP` is exposed as a Swift library product.
- [ ] `swift build` succeeds from the ACP repository root.
- [ ] `swift test` succeeds from the ACP repository root.
- [ ] Existing ACP behavior is preserved or every intentional difference is documented.
- [ ] ACP has no dependency on Prism/Remote/Conductor/Lyric application code.
- [ ] Public API has been deliberately audited.
- [ ] Implementation details remain internal/private where possible.
- [ ] ACP tests live with ACP.
- [ ] README explains local and remote SPM consumption.
- [ ] The package can be added to a clean sample Xcode app and imported with `import AuroraACP`.
- [ ] The package can be consumed locally from a filesystem checkout.
- [ ] The package can be consumed from its Git repository/tag.
- [ ] A release/tagging procedure is documented.
- [ ] No consuming application needs copied ACP protocol `.swift` files.

---

# 17. Deliverables From Grok

Return:

1. The converted standalone Swift package repository.
2. Updated `Package.swift`.
3. Migrated/updated ACP test suite.
4. Updated README package-consumption instructions.
5. A migration report containing:
   - source files moved,
   - public API changes made for module boundaries,
   - any application dependencies removed,
   - any behavior changes, ideally none,
   - test/build results,
   - recommended ACP version/tag for the package conversion.
6. Any separate Prism integration notes required for the consuming-app migration.

The finished architecture must have one canonical ACP implementation and many consumers, not many copies.

---

# 18. Architectural North Star

```text
                        Canonical ACP Repository
                      ┌──────────────────────────┐
                      │       AuroraACP          │
                      │ Swift Package + Tests    │
                      └────────────┬─────────────┘
                                   │
                       versioned dependency
                                   │
           ┌───────────────────────┼───────────────────────┐
           │                       │                       │
           ▼                       ▼                       ▼
        Prism                   Remote                Conductor
           │                       │                       │
    Prism ACP adapters       Remote adapters       Conductor adapters
           │                       │                       │
           ▼                       ▼                       ▼
    Prism domain model       Remote domain         Show-management domain
```

**Final rule:** applications may adapt ACP; applications must not fork ACP.
