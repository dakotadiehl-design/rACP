# ACP documentation baseline — 2026-08-27

Status: **Qualification evidence**

This baseline reconciles current documentation to ACP 1.2 source, schemas, tests, and the Aurora Trust extension 1.0 implementation at repository revision following security-hardening commit `4f611d071893fc9ab78a4f4c4ac485d2d33bfa53`.

## Covered

- Documentation authority/status taxonomy and historical separation.
- Current Swift, Rust, and Python implementation matrix.
- Enrollment, SPAKE2+ confirmation, issuance, Apple custody, TLS, authorization, credential lifecycle, revocation, and recovery semantics.
- Prism, Remote, migration, signed Apple qualification, and future Conductor integration guidance.
- Remote/session/wire/catalog navigation and canonical machine-readable ownership.

## Evidence baseline

- Swift: 148 tests passed, zero failures, two explicit unsigned-host custody skips.
- Rust: 65 tests passed; formatting and Clippy clean.
- Python: 245 tests passed; Ruff and mypy clean.
- Security source/API boundary, release artifact, dependency, SPAKE2+ boundary, and fuzz-smoke checks passed.

## Known qualification boundary

Signed Prism and Remote application targets must still qualify Secure Enclave or non-exportable Keychain custody with their production entitlements. Lightweight representative-hardware HIL is not complete. Product adapter integration occurs in the product repositories and is not proven by this documentation baseline.

Run `python3 scripts/check_documentation.py` to validate status metadata, historical labels, local links, and high-risk frozen security claims.

