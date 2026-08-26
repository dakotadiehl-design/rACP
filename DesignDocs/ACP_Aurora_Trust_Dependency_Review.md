# ACP Aurora Trust Dependency and License Review

Date: 2026-08-26

The frozen security profile requires Botan 3.13.0 exactly. The checked macOS arm64 probe result reports that version and PASS. Rust lockfile security dependencies checked offline are `hmac 0.12.1`, `sha2 0.10.9`, `subtle 2.6.1`, and `uuid 1.18.1`. Python security-vector tooling is constrained to `cryptography >=43,<44`; it is tooling/test support and does not silently replace the frozen Botan production profile. Swift CryptoKit use remains subject to Apple platform SDK terms and its platform qualification boundary.

Recorded license policy: Botan is BSD-2-Clause; the listed RustCrypto crates are MIT OR Apache-2.0; Python cryptography is Apache-2.0 OR BSD-3-Clause. Exact assertions are executable through `python3 scripts/check_security_dependencies.py`.

Fresh advisory status requires network-backed databases and is intentionally reported as `NOT RUN` by the offline script. CI separately runs `cargo audit` and `pip-audit`; a recent successful CI run is a release gate. Dependency upgrades that change the frozen provider/profile require requalification rather than an automatic green build.
