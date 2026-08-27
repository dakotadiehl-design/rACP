# ACP documentation traceability

Status: **Current implementation guide**  
Baseline date: **2026-08-27**

| Requirement | Normative source | Primary implementation | Evidence |
|---|---|---|---|
| Canonical encoding and bounds | `WIRE_ENCODING.md` | Swift codec, `rust/acp-codec`, `python/src/acp/cbor_cde.py` | golden, malformed, and cross-language vectors |
| Enrollment-restricted state | `SECURITY.md` §13; `STATE_MACHINES.md` | security enrollment/session routers | Swift/Rust/Python enrollment tests |
| SPAKE2+ confirmation before issuance | `SECURITY.md` §§2–6 | `ACPAppleSPAKE2Plus`, `ACPCredentialIssuance` | transcript, mismatch, and one-use tests |
| Non-exportable Apple custody | `SECURITY.md` §17 | Apple authority/identity stores | custody classification tests; signed-host qualification pending |
| TLS 1.3 mTLS and HELLO binding | `SECURITY.md` §§8–9 | Apple full connection factory | real Keychain loopback all-up test |
| Authorization intersection | `SECURITY.md` §13 | Swift/Rust/Python authorization modules | exhaustive matrix and policy-race tests |
| Credential lifecycle and recovery | `SECURITY.md` §§6–8, 14 | two-slot lifecycle stores | corruption, recovery, rotation tests |
| Revocation rollback protection | `SECURITY.md` §11 | Swift/Rust/Python revocation state | epoch/hash-chain/property tests |
| Active-session revocation policy | `SECURITY.md` §11 | trust/session policy stores | terminate/grace behavior tests |
| Remote server authority | `REMOTE.md` | Python `RemoteHost`; Swift host boundary | Remote suite and integration contracts |
| Historical separation | `docs/README.md` | documentation layout/checker | documentation validation script |

Canonical machine-readable inputs are `schema/`, `schemas/security/`, `Sources/AuroraACP/Session/registry.json`, `Sources/AuroraACP/Security/constants.json`, and `vectors/security/conformance/`. Generated reference text must never become an independent source of truth.

