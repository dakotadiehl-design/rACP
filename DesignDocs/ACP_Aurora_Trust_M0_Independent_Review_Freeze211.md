# ACP Aurora Trust M0 Independent Confirmation (Candidate Freeze 2.1.1)

> **Historical record.** This document preserves the plan, review, or evidence at the time it was written. For current normative and integration guidance, start at [`docs/README.md`](../docs/README.md).

**Reviewer:** Grok 4.6 (delta confirmation of Freeze 2.1.1 only)
**Date:** 2026-08-21
**Subject:** Aurora Communications Protocol (ACP) Aurora Trust Candidate Freeze 2.1.1
**Normative candidate:** `docs/SECURITY.md`
**Prior reviews:** Freeze 1 NO-GO; Freeze 2 CONDITIONAL GO; Freeze 2.1 CONDITIONAL GO
**Decision:** **GO** (cryptographic profile document)

AT-M0-042, AT-M0-043, and AT-M0-044 are closed. No new BLOCKER or HIGH finding was introduced. Candidate Freeze 2.1.1 is precise enough for independent Swift, Python, and Rust implementations of the wire contract.

This is **not** M0 completion and **not** authorization to start M1. Provider probes, Pico HIL, license approval, and ACP golden vectors remain absent. It is not formal cryptographic certification.

---

## 1. Executive summary

Freeze 2.1.1 applied the remaining CONDITIONAL GO patch:

- Closed `security.enrollment.install_result` map and HMAC-without-`confirmation` rule
- Typed `storage_posture`
- Forbade a v1 commissioner receipt; `commissioner_confirm` is reserved and must not appear on the wire
- Compact `format` / `serial` / sorted `role_constraints`
- Global pre-Established list now names Lightweight binding and defers to the tighter state machines

The cryptographic contract in `docs/SECURITY.md` can be implemented without inventing KDFs, point encodings, hashed field sets, or extra messages. Remaining uncertainty is whether selected providers and Pico-class hardware can execute that contract, which does not change the bytes.

---

## 2. Review scope

Read-only confirmation of Freeze 2.1.1 against AT-M0-042–044 only. Previously closed findings were not re-litigated. New HIGH defects from this patch were hunted.

---

## 3. Material inspected

- `docs/SECURITY.md` §§5–6, §10 (Candidate Freeze 2.1.1)
- `docs/STATE_MACHINES.md` pre-Established / `LightweightBinding` paragraphs
- `DesignDocs/ACP_Aurora_Trust_M0_Review_Remediation.md`
- `DesignDocs/ACP_Aurora_Trust_M0_Decision_Record.md`
- Prior review `ACP_Aurora_Trust_M0_Independent_Review_Freeze21.md`

---

## 4. Tests executed / results

| Check | Result |
|---|---|
| `python3 scripts/check_registry.py` | 93 messages, pass |
| `git diff --check` | pass |
| Author-reported Python / Swift / Rust / interop | 142 / 75 / 25+docs / all framed+WS suites; documentation-only delta; not a Trust-crypto proof |
| ACP security vectors / provider probes / Pico HIL | **none; not claimed** |

---

## 5–17. Delta assessment

**AT-M0-042.** Install-result is a closed map: `attempt_id`, `status` (`"installed"` only), `credential_id`, `identity_key_id`, `trust_domain_id`, `storage_posture`, `proof_of_possession`, `confirmation`. `storage_posture` is exactly `class`, `hardware_backed`, `private_key_exportable` with an enumerated `class` and booleans. HMAC input is CDE of that map with `confirmation` absent (not null/empty). ECDSA PoP remains over `SHA-256("ACP enrollment install proof v1" || transcript_hash || credential_id_ascii)`. Failures use a generic authenticated error, not this success map. `commissioner_confirm` MUST NOT produce a v1 wire message; enrollment completes after HMAC + PoP + durable read-back + one-time attempt consume. **Closed.** Option (b) from the Freeze 2.1 review was taken correctly.

**AT-M0-043.** Compact `format` is `acp-compact-credential-v1`; `serial` is uint64; `role_constraints` are 0..16 unique UTF-8 strings of 1..64 bytes, sorted by encoded UTF-8 bytes. **Closed.**

**AT-M0-044.** Global legal-types sentence names the enrollment allowlist and the Lightweight binding message, and states that `EnrollmentRestricted` / `LightweightBinding` override the global list. **Closed.**

No new HIGH. Residual LOW items do not change interop bytes (see §18).

Why remaining external uncertainty does not invalidate the contract: Botan/Mbed/CryptoKit are execution engines behind `from_prehashed`, uncompressed 65-byte shares, RFC 5869, and TLS exporters. If a provider cannot produce those bytes, it is nonconforming; the profile does not absorb provider defaults. Pico HIL can fail the Lightweight *target*, not the specified preface/RPK/finished bytes. Missing vectors are evidence, not specification. License approval is a redistribution gate, not a wire-format gate.

---

## 18. Findings table (this delta)

| ID | Severity | Disposition |
|---|---|---|
| AT-M0-042 | HIGH | **Addressed.** |
| AT-M0-043 | MEDIUM | **Addressed.** |
| AT-M0-044 | LOW | **Addressed.** |
| AT-M0-045 | LOW | `storage_posture.class` may be `hardware_backed` while the sibling boolean is false; production should reject `ephemeral` except test providers. |
| AT-M0-046 | LOW | Compact `extensions` keys still “OID/name”; pin to dotted numeric OID in M1 schema. |

No BLOCKER or HIGH remains on the profile text.

---

## 19. Detailed leftover (non-blocking)

**AT-M0-045 — LOW.** Two `hardware_backed` concepts (enum vs boolean) can disagree. `ephemeral` is a legal class; design forbade it in production. M4 policy: reject `ephemeral` for non-test enrollment; optionally require `class == hardware_backed` iff the boolean is true.

**AT-M0-046 — LOW.** Extension map keys as either names or OIDs will be pinned when `schema/security/` is written. Unknown critical extensions already fail closed.

---

## 20. Required remediation

**None on the cryptographic profile** for GO.

M1 schemas should encode the closed maps as written, including install-result HMAC omission and compact sort rules. Do not reopen HELLO projection, LightweightBinding, or suite split.

---

## 21. Remaining external / hardware evidence (M0 still blocked)

1. Provider probes on every Full target: RFC 9383 Appendix C; ACP registration including `0x00` / `0xff` / non-UTF-8 secrets; uncompressed shares; AES-256-GCM; low-S DER ECDSA; TLS 1.3 mTLS; exporter equality; no 0-RTT/resumption.
2. Pico-class HIL: CSPRNG, RAW128 SPAKE2+, RPK, exporter, RAM/flash/time, transactional storage — or Lightweight removed from the production freeze.
3. ACP golden vectors for registration, context, shares, confirms, HKDF labels, approval, install-result HMAC/PoP, compact credential, Lightweight finished.
4. Owner approval of Botan Simplified BSD and Mbed TLS Apache-2.0, plus a security-update policy.
5. Rust MSRV reconciliation if any selected binding exceeds 1.75.

---

## 22. Final decision

# GO

Candidate Freeze 2.1.1 is internally coherent. Normative cryptographic behavior is precise enough for independent Swift, Python, and Rust implementations. No BLOCKER or HIGH findings remain on the document.

GO means the security profile is sound enough to treat as the frozen *contract* for later engineering. It does **not** mean:

- M0’s execution gate is passed
- M1 schemas/SDK cryptography may start under the approved milestone-order contract
- providers or Pico hardware are qualified
- formal professional cryptographic certification

**M0 remains blocked. M1 remains closed** until the evidence in §21 exists.

The remaining uncertainty (unproven provider APIs, unproven Pico bounds, missing vectors, pending licenses) does not change the bytes in `docs/SECURITY.md`. A provider that cannot implement those bytes is nonconforming; it is not a license to invent a second profile.
