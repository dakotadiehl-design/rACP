# Issuer Implementation Remediation Review

Date: 2026-08-27  
Reviewed baseline: current AuroraACP working tree

## Closed in this milestone

- Added application-neutral Swift, Rust, and Python authority/commissioner/issuance/revocation metadata models.
- Added a provenance-rich conformance manifest and foundational foreign-producer fixtures.
- Added foreign-consumer validation in Swift, Rust, and Python.
- Removed Rust's raw caller-controlled X.509 issuance callback.

## Required subsequent remediation

1. Add automatic Secure Enclave preference and qualified non-exportable Keychain fallback.
2. Implement strict independent Rust and Python Full-profile X.509 validation before either can claim complete certificate conformance.
3. Add sealed Rust/Python issuance and installation evidence; portable metadata must remain non-authoritative.
4. Expand the corpus to every positive and negative family required by the architecture.
5. Extend `scripts/check_security_api_boundary.py` to enforce new Rust/Python issuance and installation boundaries after those types exist.
6. Integrate the Apple coordinator only after live enrollment machinery is the sole producer of issuance authorization.
7. Add restart/fault-injection qualification for journal, installation, renewal, replacement, and revocation boundaries.

No Apple custody implementation is changed by this milestone.
