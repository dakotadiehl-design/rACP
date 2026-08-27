# ACP implementation status

Status: **Current implementation guide**  
Verified against source and tests: **2026-08-27**

“Implemented” means code and automated tests exist. “Qualified” is stronger and applies only where a dated artifact says so.

| Area | Swift | Rust | Python |
|---|---|---|---|
| Models and ACP-CDE-1.2 | Implemented | Implemented | Reference implementation |
| Session negotiation and sequencing | Implemented | Implemented | Implemented |
| Authenticated evidence boundary | Sealed capability | Sealed capability | Provenance-sealed model |
| Authorization intersection | Implemented, atomic policy consumption | Implemented | Implemented |
| Credential/revocation models | Implemented | Implemented | Implemented |
| Cross-language security fixtures | Consumer/producer | Consumer/producer | Consumer/producer |
| Full TLS 1.3 mTLS host | Apple Network.framework provider | Model/contract only | Model/contract only |
| Apple authority and leaf custody | Secure Enclave or non-exportable Keychain; fail closed | N/A | N/A |
| Apple SPAKE2+ provider | Botan 3.13.0 restricted wrapper | Portable semantics | Portable semantics |
| Remote authority engine | Safety core/simulator; product adapter pending | Simulator | Reference production engine |
| Prism/Remote product integration | Contract ready; external app work pending | N/A | Test/reference tooling |
| Lightweight transport | Frozen contract; target HIL not complete | Model and tests | Model and tests |

Current automated baseline: Swift 148 tests with zero failures and two explicit unsigned-host custody skips; Rust 65 tests plus Clippy; Python 245 tests plus Ruff and mypy. See `qualification/security-hardening/apple-process-checkpoint-2026-08-27.json` for the dated checkpoint.

The two Swift skips are not exemptions. Production Apple qualification requires a signed application target with the intended entitlements. If Secure Enclave and non-exportable Keychain custody are both unavailable, startup/enrollment fails closed.

