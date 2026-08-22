# Aurora Trust M0 Provider, License, and Security-Update Approval Package

**Date:** 2026-08-21  
**Profile:** Candidate Freeze 2.1.1  
**Package status:** TECHNICALLY COMPLETE — PROJECT OWNER DECISION REQUIRED  
**Scope:** Provider selection and maintenance evidence only; not legal advice and not M0 completion

## Decision summary

The technical recommendation is:

- Approve Botan 3.13.0 as the exact Full-profile crypto-provider baseline, subject to per-platform adapter qualification. The provider-level crypto probes and macOS arm64 adapter pass; other Full platforms remain `NOT_RUN` and are not approved by implication.
- Do not approve a version range. A later Botan release is a new qualified provider version only after security vectors, provider probes on every shipping platform, and the complete ACP regression suite pass.
- Retain Mbed TLS as the Lightweight research candidate only. No Mbed TLS release is production-qualified for Aurora Trust because Pico HIL, Raw Public Key behavior, SPAKE2+ integration, storage, and resource evidence remain absent.
- Do not approve an automatic fallback provider. Replacement or fallback changes provider behavior and packaging and requires the same qualification gate.

The protocol bytes remain fixed independently of these providers. A provider failure does not authorize changing Candidate Freeze 2.1.1.

## Provider record: Botan

| Field | Record |
|---|---|
| Provider | Botan |
| Exact qualified version | 3.13.0 |
| Qualified build | Homebrew 3.13.0 arm64 bottle, shared linkage, public C++ APIs |
| Qualified target | macOS arm64 only |
| Other targets | `NOT_RUN`; require their own packaging and adapter evidence |
| License | Simplified BSD / BSD-2-Clause |
| License source | Botan 3.13.0 `license.txt`; upstream release source |
| Distribution obligations | Preserve copyright, conditions, and disclaimer in source distributions; reproduce them in documentation or other materials accompanying binary distributions |
| Linkage considerations | The license permits source and binary redistribution with or without modification; static versus dynamic linkage does not remove notice obligations |
| ACP-used features | RFC 9383 SPAKE2+ P-256/SHA-256 through `from_prehashed`; SHA-256; HMAC-SHA-256; HKDF-SHA-256; AES-256-GCM; P-256 ECDSA; X.509; TLS 1.3 mutual authentication; peer certificate evidence; TLS exporter |
| ACP adapter requirements | Never call `skip_confirmation`; normalize outbound ECDSA to strict DER low-S and reject malformed/high-S input before verification; isolated ACP trust store; exact SAN/domain/node/EKU checks; `Session_Manager_Noop`; zero tickets; no early data |
| Explicitly unused | Provider password/Argon2 registration defaults, public Web PKI, OCSP/AIA/CRLDP fallback, TLS 1.2, resumption, 0-RTT, `skip_confirmation` |
| Advisory source | Botan handbook security page and GitHub Security Advisories |
| Release source | Botan release feed/tags and authenticated package-manager metadata |
| Maintenance status | 3.13.0 is current qualified baseline; qualification does not promise future maintenance |
| Limitations | Only macOS arm64 has passed the complete adapter probe; new SPAKE2+ code has limited deployment history; Swift/Rust/Python bindings and packaging remain platform work |
| Fallback provider | None approved |
| Replacement consequence | Re-run vectors, full provider suite, platform packaging, SBOM/license review, ACP regressions, and security review for material behavioral changes |

## Provider record: Mbed TLS / TF-PSA-Crypto

| Field | Record |
|---|---|
| Provider | Mbed TLS with TF-PSA-Crypto |
| Observed upstream release | 4.2.0, published 2026-07-07 |
| Qualified version | None |
| Status | Research candidate for Lightweight only; `HARDWARE_REQUIRED` |
| License | Dual Apache-2.0 OR GPL-2.0-or-later; technical recommendation is Apache-2.0 if approved |
| Distribution obligations under recommended choice | Include Apache-2.0 license; retain applicable notices; identify modified files; include NOTICE attributions if a distributed release contains a NOTICE file; observe patent-termination terms |
| Linkage considerations | Apache-2.0 is permissive for static or dynamic firmware linkage subject to its conditions; owner/legal review must confirm the chosen distribution process |
| Intended ACP features | TLS 1.3 mutual Raw Public Keys, CSPRNG/entropy integration, P-256, SHA/HMAC/HKDF, compact-credential verification, exporter, transactional protected-flash integration |
| Unsupported/unproven | ACP SPAKE2+ integration, exact RPK negotiation, exporter equality, Pico resource bounds, entropy readiness, power-loss storage, physical/fault side-channel posture |
| Advisory source | Mbed TLS `SECURITY.md`, maintained-branches record, and TrustedFirmware vulnerability process |
| Release source | Official Mbed TLS GitHub releases and maintained branches |
| Maintenance status | Upstream instructs users to remain on the latest release of a maintained branch; ACP has not selected such a branch |
| Limitations | Upstream documents limited timing-attack protection and no general physical/fault-injection guarantee; platform countermeasures and HIL are mandatory |
| Fallback provider | None approved |
| Replacement consequence | Lightweight profile must remain closed or be revised and independently reviewed; no homemade substitute is permitted |

## Version policy

```text
Protocol profile:
    Candidate Freeze 2.1.1 exact algorithms and bytes

Qualified provider:
    Botan 3.13.0 only, and only on adapters with a PASS result

Upgrade policy:
    no automatic range approval
    candidate upgrade -> advisory/license diff -> golden vectors
    -> provider probes on every shipping target -> ACP regression/interoperability
    -> SBOM and release approval
```

Dependency resolution must pin an exact qualified release and record its source hash/package identity in the shipping SBOM. Package-manager resolution to a newer minor or patch release is not approval.

## Security-update policy

The project security owner must monitor Botan and Mbed TLS/TrustedFirmware advisories and release notices at least weekly and on every build intended for distribution.

| Trigger | Required response |
|---|---|
| Known exploitation, critical remote compromise, authentication bypass, private-key disclosure, RNG failure, PAKE/TLS/X.509 validation defect | Triage immediately; stop affected release; begin expedited update or mitigation within 24 hours |
| High severity affecting an enabled ACP feature or dependency path | Triage within one business day; patch target within seven calendar days unless a documented risk decision is approved |
| Medium affecting an enabled feature | Triage within five business days; schedule in the next maintenance release |
| Low or unused feature | Record applicability and disposition; monitor upstream changes |

Every security update requires:

1. exact source/version/SBOM and license-diff review;
2. all security golden vectors;
3. provider probes on each shipping platform and feature combination;
4. full Python, Swift, Rust, JSON/CBOR, framed, and WebSocket regressions;
5. explicit confirmation that TLS 1.3-only, mutual identity, exporter equality, no resumption/0-RTT, isolated trust stores, and redaction remain intact; and
6. release notes linking the advisory, affected Aurora releases, mitigation, and requalification evidence.

An emergency upgrade may shorten release ceremony but may not skip the vector/provider tests for affected paths. If a safe provider update cannot be qualified promptly, hardened authentication-dependent control remains disabled rather than falling back to `trusted_lan`.

## PROJECT OWNER DECISION

```text
Provider: Botan for the ACP Full profile, subject to ACP qualification
Version policy: Botan 3.13.x initial line; compatible Botan 3.x updates require the complete ACP security-vector, provider-probe, interoperability, and regression gates; major versions require renewed owner approval
License approved: YES — Simplified BSD
Distribution obligations accepted: YES
Security-update policy approved: YES — applicable critical/high advisories require expedited evaluation and qualification; emergency updates do not waive ACP gates
Date: 2026-08-21
Approver: Project owner, via ACP Aurora Trust Conditional M0 Close / M1 Transition Directive
Notes: Approval does not cover or imply Pico/Lightweight production qualification. It does not qualify any platform adapter lacking ACP evidence.
```

This records only the bounded decision supplied by the project owner. Botan use remains subject to ACP qualification on each shipping adapter.
