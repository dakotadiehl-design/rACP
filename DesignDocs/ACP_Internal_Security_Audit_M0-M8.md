# ACP Internal Security Audit — M0–M8

Audit date: 2026-08-26

## Audit baseline and findings freeze

- Repository: `/Users/dakota/code/AuroraCommunicationsProtocol`
- Branch: `main`
- Starting commit: `597f5d79cffbb462873eb243ea1ca36ec0def777`
- Starting worktree: dirty; the complete listed working tree, including uncommitted M8 review changes, is in scope and is preserved.
- Audit mode through this section: read-only implementation review. No production behavior was changed before this finding set was frozen.

The audit covered the Swift package, Python package, Rust workspace, schemas, constants, golden and malformed vectors, interoperability fixtures, security-provider probes, Apple Keychain adapter, Wireshark tooling, CI/dependency policy, and the security design/freeze/review documents. The review traced discovery through parsing, enrollment, credential installation, authenticated transport evidence, HELLO binding, principal construction, authorization, revocation, migration, reset, Remote control, and persistent operational state.

### Frozen findings summary

| Severity | Count |
|---|---:|
| BLOCKER | 1 |
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 6 |
| LOW | 1 |
| INFORMATIONAL | 2 |

The following set was deduplicated and challenged against callers, guards, tests, cross-language behavior, and the frozen contract before remediation began.

### AT-IA-001 — Production cryptographic and transport adapters are absent

- **Severity:** BLOCKER
- **Affected files/symbols:** `security_providers.py`; `ACPSecurityProviders.swift`; `acp-security` provider traits; `ACPAuthenticatedTransport`; `security_transport.py`; `transport.rs`; security probe sources
- **Affected language/platform:** Swift, Python, Rust; all production platforms
- **Security property violated:** deployable authentication must derive evidence from qualified cryptography and transport state rather than caller assertions.
- **Attack preconditions:** a product treats these SDK interfaces or completion reports as a production authentication implementation and supplies incomplete or dishonest provider evidence.
- **Attack path:** the SDK consumes booleans such as `peer_certificate_valid`, `isolated_trust_store`, and `peer_san_extracted`; this repository has no production SPAKE2+, TLS/X.509/exporter adapter that proves those facts.
- **Impact:** a miswired product can manufacture authenticated transport evidence without performing the required cryptography. Provider probes prove selected capabilities, not product wiring.
- **Evidence:** repository-wide provider implementation search finds protocols/traits, test fixtures, and probes only.
- **Confidence:** High.
- **Recommended remediation:** keep production control disabled until each product wires a reviewed provider adapter; add adapter conformance tests and platform qualification. This cannot be safely completed in this protocol-only repository without product/platform implementations and external qualification.
- **Required regression tests:** provider-negative integration tests proving facts cannot be caller-injected; physical/platform TLS, Keychain/Secure Enclave, and Lightweight HIL gates.
- **Compatibility impact:** none to the frozen wire contract.

### AT-IA-002 — Rust host identity writes follow a predictable temporary-file symlink

- **Severity:** HIGH
- **Affected files/symbols:** `rust/acp-security/src/credential.rs`, `HostIdentityStore::new`, `atomic_write`
- **Affected language/platform:** Rust host filesystems
- **Security property violated:** credential persistence must resist filesystem substitution and remain atomic.
- **Attack preconditions:** a local attacker can pre-create or replace entries in the configured identity directory, or the directory itself is supplied as a symlink.
- **Attack path:** `.name.tmp` is opened with create/truncate and follows symlinks; constructor also accepts a symlink root.
- **Impact:** overwrite/truncate of another accessible file, credential installation corruption, or attacker-directed persistence.
- **Evidence:** predictable `format!(".{name}.tmp")`, `OpenOptions::truncate(true)`, no no-follow or exclusive creation.
- **Confidence:** High.
- **Recommended remediation:** reject symlink roots, create unique exclusive temporary files, restrict permissions, sync, atomically rename, and clean up safely.
- **Required regression tests:** symlink root, pre-created temporary symlink, invalid names, and atomic replacement tests.

### AT-IA-003 — Swift secret container is unsafely declared Sendable

- **Severity:** MEDIUM
- **Affected files/symbols:** `ACPSecuritySecrets.swift`, `ACPSecretBytes`
- **Affected language/platform:** Swift concurrency
- **Security property violated:** secret access and destruction must not data-race.
- **Attack preconditions:** the same secret is used or cleared concurrently across actors/tasks, which `@unchecked Sendable` explicitly permits.
- **Attack path:** mutable `Data` is read through `withUnsafeBytes` while `clear` mutates it without synchronization.
- **Impact:** undefined/data-race behavior, crashes, corrupted cryptographic input, or incomplete clearing.
- **Evidence:** mutable class storage plus unchecked Sendable and no lock/actor isolation.
- **Confidence:** High.
- **Recommended remediation:** serialize storage access and clearing; document realistic runtime copy/zeroization limits.
- **Required regression tests:** concurrent reads/clear under Swift concurrency and redacted descriptions.

### AT-IA-004 — Swift network parsers use alignment-sensitive raw loads

- **Severity:** MEDIUM
- **Affected files/symbols:** `ACPCbor.swift` float decoding; `ACPFramed.swift` frame length decoding
- **Affected language/platform:** Swift
- **Security property violated:** malformed or adversarial network bytes must fail without process traps.
- **Attack preconditions:** attacker controls framing or CBOR bytes and the runtime supplies a non-suitably-aligned buffer view.
- **Attack path:** `UnsafeRawBufferPointer.load(as:)` requires alignment that `Data` views do not promise.
- **Impact:** remotely triggerable availability failure on affected runtime/layout combinations.
- **Evidence:** direct `load(as: UInt32/UInt64.self)` on `Data`/prefix storage; bytewise decoding elsewhere shows no need for the unsafe load.
- **Confidence:** Medium; allocator behavior often masks it, but the API precondition is not guaranteed.
- **Recommended remediation:** decode integers bytewise.
- **Required regression tests:** deliberately offset buffers for float and frame headers.

### AT-IA-005 — Public Swift/Rust decoders lack uniform total input bounds

- **Severity:** MEDIUM
- **Affected files/symbols:** `ACPEncoding.decodeJSON/decodeCBOR`; `acp_codec::decode_json/decode_cbor`; Python raw CBOR decode boundary
- **Affected language/platform:** Swift, Rust, Python
- **Security property violated:** all untrusted parser entry points must enforce the frozen total message bound.
- **Attack preconditions:** an application invokes the public decoder directly or a future transport omits its own frame cap.
- **Attack path:** parsing and allocation occur before a total input-size check; inner CBOR element limits do not cap aggregate input.
- **Impact:** memory/CPU exhaustion and cross-language differential behavior.
- **Evidence:** Python envelope decoding checks `max_message_bytes`; Swift/Rust public envelope decoders do not.
- **Confidence:** High for the API differential; current framed transports provide defense in depth.
- **Recommended remediation:** enforce the same 8 MiB cap at every public envelope decoder.
- **Required regression tests:** exactly-at-limit and limit-plus-one JSON/CBOR cases in all SDKs.

### AT-IA-006 — Rust Lightweight preface omits the credential-format invariant

- **Severity:** MEDIUM
- **Affected files/symbols:** `rust/acp-security/src/transport.rs`, `parse_lightweight_preface`
- **Affected language/platform:** Rust Lightweight
- **Security property violated:** profile and credential format must agree before evidence is accepted.
- **Attack preconditions:** a faulty or malicious credential validator returns active Lightweight evidence carrying another credential format.
- **Attack path:** Rust checks profile and status but not `CredentialFormat::CompactV1`; Swift/Python check the exact format.
- **Impact:** profile confusion at this public boundary. The current Rust session binder later rejects the mismatch, limiting exploitability in that path.
- **Evidence:** direct three-language comparison.
- **Confidence:** High.
- **Recommended remediation:** require `CompactV1` in the Rust preface parser.
- **Required regression tests:** active Lightweight evidence with X.509 format must fail.

### AT-IA-007 — Python operational-state loading is unbounded

- **Severity:** MEDIUM
- **Affected files/symbols:** `python/src/acp/security_operations.py`, `OperationalStateStore.load`
- **Affected language/platform:** Python host operations
- **Security property violated:** persisted security state must have explicit resource bounds before parsing.
- **Attack preconditions:** corruption or a same-account/local attacker can replace or inflate `operations.json`.
- **Attack path:** `json.load` reads the whole file before the declared audit-entry cap is enforced.
- **Impact:** operator CLI memory/CPU exhaustion and inability to administer or revoke nodes.
- **Evidence:** no stat/read byte cap on the state path.
- **Confidence:** High.
- **Recommended remediation:** bounded no-follow read before JSON parsing, plus a declared maximum serialized-state size.
- **Required regression tests:** oversized regular file and symlink input fail closed.

### AT-IA-008 — Framing flag semantics differ across SDKs

- **Severity:** LOW
- **Affected files/symbols:** Python, Swift, and Rust framed transports
- **Affected language/platform:** cross-language test/host framing
- **Security property violated:** reserved wire bits should not have differential meaning.
- **Attack preconditions:** peer sends a flag byte other than 0 or 1.
- **Attack path:** Python tests bit zero, Swift treats any nonzero as text, and Rust behavior differs by implementation detail.
- **Impact:** parser/encoding disagreement and connection failure; no authorization bypass was found.
- **Evidence:** direct framing decoder comparison.
- **Confidence:** High.
- **Recommended remediation:** reject reserved bits and accept exactly 0/1 in all SDKs.
- **Required regression tests:** flag values 2, 3, and 255.

### AT-IA-009 — Secret zeroization is best-effort

- **Severity:** INFORMATIONAL
- **Affected files/symbols:** Swift `Data`, Python `bytearray`/runtime copies, Rust `Vec`; provider/FFI boundaries
- **Security property:** minimize secret lifetime without overstating guarantees.
- **Evidence and impact:** containers clear their owned mutable buffers, but language/runtime/library copies and native-provider buffers cannot be proven erased here.
- **Recommendation:** retain narrow callback interfaces, avoid String/log conversion, and document best-effort rather than guaranteed zeroization.

### AT-IA-010 — Operational audit hashes are not an independent integrity root

- **Severity:** INFORMATIONAL
- **Affected files/symbols:** Python operational state audit chain
- **Security property:** tamper evidence against a fully writable local account.
- **Evidence and impact:** an attacker able to rewrite all state can recompute unkeyed hashes. This does not create a network bypass but limits forensic non-repudiation.
- **Recommendation:** export to a separately protected/signed audit sink where that property is required.

### AT-IA-011 — Rust sessions opt into unauthenticated plaintext by default

- **Severity:** HIGH
- **Affected files/symbols:** `rust/acp-session/src/session.rs`, `Session::new`
- **Affected language/platform:** Rust
- **Security property violated:** insecure transport must require explicit opt-in; SDK defaults must fail closed.
- **Attack preconditions:** a product constructs the public Rust `Session` and does not remember to mutate `allow_plaintext` before handshake.
- **Attack path:** constructor sets `auth_mode = "trusted_lan"` and `allow_plaintext = true`, so an unauthenticated handshake succeeds by default. Swift and Python default to false.
- **Impact:** accidental deployment of an unauthenticated ACP session and exposure of any application path that incorrectly assumes session establishment implies authentication.
- **Evidence:** constructor and `plaintext_required` test, which only proves denial after manually changing the default to false.
- **Confidence:** High.
- **Recommended remediation:** default to false and require explicit opt-in at trusted-LAN diagnostic call sites.
- **Required regression tests:** a newly constructed Rust session must reject trusted-LAN handshake without mutation; explicit opt-in remains interoperable.

### AT-IA-012 — Swift framed sender omits the outbound message bound

- **Severity:** MEDIUM
- **Discovery phase:** post-remediation security re-review
- **Affected files/symbols:** `Sources/AuroraACP/Transport/ACPFramed.swift`, `send`
- **Affected language/platform:** Swift
- **Security property violated:** security-sensitive queues and framing must enforce symmetric, cross-language resource limits before integer conversion.
- **Attack preconditions:** application-controlled or forwarded content reaches the public sender above the frozen 8 MiB bound.
- **Attack path:** Swift narrows `Data.count` to `UInt32` and writes without the cap enforced by Python and Rust.
- **Impact:** excessive buffering and a possible conversion trap for extreme inputs; cross-language differential behavior.
- **Evidence:** direct sender comparison after the first remediation pass.
- **Confidence:** High.
- **Recommended remediation:** reject over-limit content before framing.
- **Required regression tests:** outbound limit-plus-one rejects without transport write.

## Implemented threat model

Trust roots are locally provisioned trust-domain authorities and persistent device identity keys. Enrollment assumes a private bootstrap secret or physical/local authorization and binds candidate/commissioner node and instance identities, role, requested permissions, protocol/security versions, suite, and key identity into a canonical transcript. Subsequent Full connections require TLS 1.3 mutual authentication, isolated trust anchors, validated certificate/SAN evidence, no resumption or 0-RTT, and equality of a 32-byte HELLO TLS exporter binding. Lightweight connections use compact credentials and a symmetric Finished construction. Authentication creates device identity only; effective permissions are the intersection of credential constraints, current local policy, negotiated capabilities, safety policy, and optional independently authenticated operator policy.

Discovery is untrusted location metadata. Revocation is signed, monotonic, bounded, freshness-checked state; hardened active sessions terminate when revoked. Reset revokes active credentials and advances epoch. Persistent credential rotation uses staged/committed generations and proof of possession. `trusted_lan` can support migration/diagnostic viewing but cannot grant sensitive production control, and hardened failures do not downgrade.

The model withstands passive observers, active LAN injection, replay, malformed senders, unauthorized authenticated peers, revoked reconnects, and downgrade attempts only when a qualified product adapter supplies truthful cryptographic evidence and protected storage. Compromise of private keys, trust anchors, the local policy account, or provider implementation is outside what protocol-only validation can repair; recovery and revocation limit but do not erase those consequences.

## Remediation and final assessment

### Remediation summary

AT-IA-002 through AT-IA-008 and AT-IA-011 through AT-IA-012 are resolved in the audited working tree. Rust identity persistence now rejects symlink roots and uses exclusive unique temporary files; Swift secret access is serialized; Swift network integer parsing is bytewise; all public decoders enforce the total document bound; Rust Lightweight parsing requires the compact format; Python operational state is bounded before JSON parsing; framed transports reject reserved flags; Rust plaintext requires explicit opt-in; and Swift outbound framing enforces the common cap. Test fixtures that deliberately exercise legacy trusted-LAN behavior now opt in visibly.

AT-IA-001 remains a release BLOCKER because production provider/product wiring and platform qualification are outside this protocol-only repository. AT-IA-009 and AT-IA-010 remain documented informational limitations.

### Tests added or strengthened

- Rust host-store symlink/substitution regression.
- Rust Lightweight credential-format negative.
- Swift/Python/Rust oversized public decoder regressions.
- Python oversized operational-state regression.
- Swift concurrent secret access/clear regression.
- Rust default-plaintext denial regression, with explicit opt-in in trusted-LAN fixtures.
- Cross-SDK reserved framing behavior and existing malformed/negative suites exercised in the final gates.

### Cross-language result

Swift, Python, and Rust agree on canonical IDs, timestamps, compact credentials, revocation bounds, enrollment transcripts and key schedule, profile-specific credential formats, channel bindings, permission intersection, plaintext opt-in, framing flags, and total message bounds. No wire-format or frozen cryptographic-profile change was required. The only compatibility-visible behavior change is intentional fail-closed rejection of previously accepted invalid/reserved input and Rust's secure plaintext default.

### Platform qualification

| Environment/capability | Status | Qualification boundary |
|---|---|---|
| macOS arm64 Botan 3.13.0 provider probes | PASS | Recorded capability probe; does not prove product adapter wiring |
| macOS arm64 Swift/Python/Rust host SDK tests | PASS | Full local regression and interoperability evidence |
| iOS Simulator arm64 probes | PASS | Simulator-only evidence; not hardware-backed qualification |
| iOS physical device / Secure Enclave | DEFERRED | Hardware unavailable |
| Pico-class Lightweight HIL | DEFERRED | Hardware unavailable |
| Linux x86_64 | NOT RUN | Not available in this audit environment |
| Linux arm64 / Raspberry Pi | NOT RUN | Not available in this audit environment |
| Windows x86_64 | NOT RUN | Not available in this audit environment |
| macOS x86_64 | NOT RUN | Not available in this audit environment |
| Current online dependency advisories | NOT RUN | Network-backed CI gate exists; offline version/license check passed |
| Independent external security review | DEFERRED | Review package exists; approval has not occurred |

### Final regression evidence

The complete final-tree gate passed twice:

- Python: 235 tests per run; Ruff and mypy clean across 63 files.
- Rust: 60 tests per run; rustfmt and clippy clean with warnings denied.
- Swift: 106 tests per run.
- Registry: 109 messages; security vectors: 17 sets / 31 hashed artifacts.
- Deterministic security fuzz smoke: 2,000 iterations per run.
- Frozen dependency/version/license policy: PASS; current online advisories: NOT RUN.
- WebSocket HELLO and Remote, three-SDK enrollment, Python/Rust and Python/Swift framed HELLO/session/Remote/negative suites, and Rust/Swift framed sessions: PASS twice.

### Final invariant checklist

| Invariant | Result |
|---|---|
| Unauthenticated peers cannot gain authorization | PASS in SDK boundaries; production adapter wiring remains blocked |
| Authenticated peers cannot exceed granted authority | PASS |
| Capability negotiation does not grant authorization | PASS |
| Discovery does not establish trust | PASS |
| Revoked peers cannot reconnect or resume | PASS in implemented state/evidence boundaries; resumption is rejected |
| Old sessions do not survive authority reset improperly | PASS |
| Downgrade is prevented | PASS |
| Peer identity is bound to the secure session | PASS at exporter/evidence boundary; provider wiring DEFERRED |
| ACP is bound to the intended TLS channel | PASS at exporter contract; production adapter wiring DEFERRED |
| Replayed authentication material fails | PASS |
| Malformed crypto evidence fails closed | PASS |
| Storage failure fails closed | PASS |
| Provider failure fails closed | PASS at interfaces |
| No silent insecure fallback exists | PASS; Rust default corrected |
| Pending security state is cleaned on failure/cancellation | PASS |
| Cross-language security semantics agree | PASS for reviewed implementation |
| Security-sensitive inputs are bounded | PASS for reviewed public boundaries |
| Secrets are not logged | PASS; zeroization remains best-effort |

### Residual risk and frozen protocol impact

The protocol repository cannot guarantee honesty of externally supplied TLS/X.509/SPAKE2+/storage evidence. Private-key theft, trust-anchor compromise, or full compromise of the local policy account remains outside the protocol's containment boundary. Audit hashes are not an independent integrity root, runtime secret zeroization is best-effort, current advisory data was not fetched, and unavailable hardware/platforms are not qualified.

No frozen wire bytes, transcript fields, cryptographic algorithms, credential encoding, or migration format changed during remediation.

## Final verdict

**NO-GO for show-critical production deployment.**

The host-available M0–M8 implementation is internally suitable as an external-review and product-integration candidate, and no unresolved CRITICAL/HIGH/MEDIUM source defect remains in the reviewed SDK boundaries. The verdict remains NO-GO because AT-IA-001 is a real production trust-boundary BLOCKER: qualified provider facts are not yet wired and enforced by production adapters in this repository. Physical iOS/Secure Enclave and Lightweight HIL evidence, other claimed platforms, fresh advisories, and independent external approval are also outstanding.
