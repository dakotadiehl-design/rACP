# ACP Aurora Trust Conformance Matrix

> **Historical record.** This document preserves the plan, review, or evidence at the time it was written. For current normative and integration guidance, start at [`docs/README.md`](../docs/README.md).

**Status:** M0–M8 implementation evidence assembled; production release gate remains deferred.

The normative machine-readable index is `DesignDocs/ACP_Aurora_Trust_Conformance_Matrix.json`. It uses only `PASS`, `FAIL`, `NOT RUN`, `DEFERRED`, and `NOT APPLICABLE`.

| Area | Status | Evidence / release qualification |
|---|---|---|
| M0 profile and vectors | PASS | Freeze 2.1.1 review, provider decision record, `vectors/security`, and security probe results |
| M1 schema/registry/vectors | PASS | Registry and generated/frozen vector gates |
| M2 shared models/providers | PASS | Swift, Python, and Rust security model/provider test suites |
| M3 enrollment | PASS | Cross-language enrollment state and interoperability suites |
| M4 credentials/lifecycle | PASS | Credential, transactional storage, rotation, revocation, and recovery suites |
| M5 authenticated transports | PASS | Full and Lightweight semantic tests; macOS arm64 adapter qualified |
| M6 authorization/product gates | PASS | Exact permission intersection and live fail-closed product boundaries |
| M7 operations/migration | PASS | Operations CLI, audit/state binding, migration enforcement, and runbook |
| M8 properties/fuzz/bounds/concurrency | PASS | `test_security_properties.py`, `security_fuzz_smoke.py`, cross-SDK hardening tests |
| Dependency/profile/license checks | PASS | `scripts/check_security_dependencies.py` |
| Fresh advisory scan | NOT RUN | Network-backed `dependency-advisories` CI job is configured; local freshness is not claimed |
| Physical iOS qualification | DEFERRED | Required before claiming physical-device or Secure Enclave production support |
| Pico-class Lightweight HIL | DEFERRED | Required before production Lightweight qualification |
| Other platform adapters | NOT RUN | Linux/Windows/Pi and untested Apple adapters remain unqualified |
| Internal independent-style review | PASS | `ACP_Aurora_Trust_Final_Internal_Security_Review.md` |
| Independent external review | DEFERRED | Review package is ready; no external approval is claimed |

Completion of source implementation is not production qualification. A platform may claim Aurora Trust support only when its adapter probes pass. Show-critical release additionally requires fresh advisory results, applicable physical/HIL evidence, and independent external approval.
