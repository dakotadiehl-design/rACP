# ACP Aurora Trust Dependency and License Review

> **Historical record.** This document preserves the plan, review, or evidence at the time it was written. For current normative and integration guidance, start at [`docs/README.md`](../docs/README.md).

Date: 2026-08-26

The frozen security profile requires Botan 3.13.0 exactly. The checked macOS arm64 probe result reports that version and PASS. Rust lockfile security dependencies checked offline are `hmac 0.12.1`, `sha2 0.10.9`, `subtle 2.6.1`, and `uuid 1.18.1`. Python security-vector tooling is constrained to `cryptography >=50,<51`; it is tooling/test support and does not silently replace the frozen Botan production profile. The lower bound was raised after the 2026-08-26 fresh advisory gate found applicable advisories through 49.0.0, with the latest applicable fix requiring 50.0.0. Swift CryptoKit use remains subject to Apple platform SDK terms and its platform qualification boundary.

Recorded license policy: Botan is BSD-2-Clause; the listed RustCrypto crates are MIT OR Apache-2.0; Python cryptography is Apache-2.0 OR BSD-3-Clause. Exact assertions are executable through `python3 scripts/check_security_dependencies.py`.

Fresh advisory status requires network-backed databases and is intentionally reported as `NOT RUN` by the offline script. CI separately runs `cargo audit` and `pip-audit`; a recent successful CI run is a release gate. Dependency upgrades that change the frozen provider/profile require requalification rather than an automatic green build.
