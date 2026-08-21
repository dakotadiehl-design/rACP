# ACP Aurora Trust M0 Independent Security Re-Review (Candidate Freeze 2)

**Reviewer:** Grok 4.6 (independent of Codex; re-review of Freeze 2, not a restatement of Freeze 1)
**Date:** 2026-08-21
**Subject:** Aurora Communications Protocol (ACP) Aurora Trust Candidate Freeze 2
**Normative candidate:** `docs/SECURITY.md`
**Prior review:** `DesignDocs/ACP_Aurora_Trust_M0_Independent_Review.md` (NO-GO of Freeze 1)
**Remediation record:** `DesignDocs/ACP_Aurora_Trust_M0_Review_Remediation.md`
**Decision:** **CONDITIONAL GO**

Freeze 1 was rejected because it was not a byte contract. Freeze 2 is a real cryptographic contract for SPAKE2+ registration, uncompressed RFC shares, closed enrollment context, approval AEAD, install PoP, X.509, isolated mTLS, downgrade policy, and split Full/Lightweight-safe registration suites. That architectural failure is fixed.

This is not GO. Three residual HIGH byte-closure defects remain, plus the original external/hardware/license gates. M1 stays closed.

GO is unavailable until the HIGH items below are amended and this review is re-checked against those patches. CONDITIONAL GO means the remaining work is narrowly bounded and does not require redesigning the PAKE, transport, or authorization model.

---

## 1. Executive summary

Candidate Freeze 2 independently re-derived against RFC 9383, Botan 3.13.0 behavior, ACP-CDE-1.2, and the Freeze 1 findings.

**Remediated in substance (original AT-M0-001 through AT-M0-031):** uncompressed 65-byte shares; binary-safe registration with both identities, LE64 framing, and context excluded from PBKDF; separate `RAW128` and `PBKDF2-100K` suite IDs; no provider-default Argon2id; challenge/response/confirm field mapping; identity key bound into context/AAD; instance IDs on the wire; empty-only permission digest; closed approval maps; ECDSA install PoP; unified identity tuple and local-policy Full-profile roles; RFC 7093 SKI; Remote SAN revision; Crockford 26-character encoding; enrollment-restricted state machine; hardened `tls`/`trusted_lan` rejection; RFC 5869 Expand; `skip_confirmation` forbidden; revocation signature/epoch/bounds; compact credential schema; Full concurrency 2; isolated trust store; both EKUs and low-S; unified external `security.authentication_failed`; 2+2 minute clock skew; Full and Lightweight 0-RTT/resumption disabled.

**Still HIGH**

1. HELLO exporter inner maps and optional fields are not closed, so channel-binding bytes can still diverge.
2. `security.lightweight.finished` is required before HELLO but is not legal in `STATE_MACHINES.md` before Established.
3. Compact-credential outer `body` encoding (nested map vs bstr) and Lightweight finished HMAC inputs (`raw_spki`, node/domain IDs) are not exact.

These are one-page patches, not a new architecture. They still prevent three SDKs from hashing the same HELLO or the same compact credential.

**Still not evidenced:** provider probes, Pico HIL, license approval, ACP golden vectors. Those cannot be manufactured from documents.

---

## 2. Review scope

Read-only adversarial re-review of Candidate Freeze 2. Freeze 1 conclusions were re-checked, not inherited. New composition bugs introduced by the remediation were hunted. Pico hardware was not available and is not claimed. Licenses remain pending owner approval.

---

## 3. Material inspected

- `docs/SECURITY.md` (Candidate Freeze 2)
- `DesignDocs/ACP_Aurora_Trust_M0_Review_Remediation.md`
- `DesignDocs/ACP_Aurora_Trust_M0_Decision_Record.md`
- `DesignDocs/ACP_Aurora_Trust_Conformance_Matrix.md`
- `DesignDocs/ACP_Aurora_Trust_M0_Independent_Review.md` (prior NO-GO)
- `docs/STATE_MACHINES.md`, `docs/REMOTE.md`, `docs/ACP_SPEC.md`, `docs/WIRE_ENCODING.md`
- `DesignDocs/ACP_Aurora_Trust_Authentication_Implementation_Design.md` (precedence note and leftover examples)
- RFC 9383 Appendix C / Botan 3.13 SPAKE2+ behavior from the Freeze 1 review

---

## 4. Tests executed / results

Documentation-only remediation. Existing ACP 1.2 tests were re-run; they still do not prove Trust cryptography.

| Check | Result |
|---|---|
| `python3 scripts/check_registry.py` | 93 messages, pass |
| `git diff --check` | pass |
| Python tests | **142 passed**, coverage **81.41%** |
| Rust `cargo test` | **25** unit tests plus doc tests, pass |
| Swift `swift test` | **75** passed |
| SPAKE2+ / ACP security vectors | **none exist** |
| Provider probes / Pico HIL | **not available; not claimed** |

WebSocket/framed interop was not re-run this pass; the Freeze 1 pass of those suites plus the doc-only delta and the unit/registry re-run are consistent with preservation of ACP 1.2. They remain non-evidence for Aurora Trust.

---

## 5. Provider assessment

Unchanged from Freeze 1 and correctly still blocked in the decision record.

Botan 3.13.0 remains the leading Full-profile candidate **if** ACP uses `from_prehashed` / equivalent with Freeze 2 `w0`/`w1`, uncompressed 65-byte shares, and never `const char *` passwords. Botan’s default Argon2id is now forbidden for ACP registration. That is the correct relationship: ACP defines the KDF, the provider supplies group operations.

Mbed TLS + RFC 7250 RPK remains unproven. Lightweight MUST use `RAW128` registration on Pico; `PBKDF2-100K` is inappropriate as a required Pico suite (100k HMAC-SHA-256 iterations). Freeze 2 allows omitting a suite by not advertising it, but does not say Lightweight may omit `PBKDF2-100K`.

Licenses: Botan Simplified BSD, Mbed TLS Apache-2.0 — **owner approval pending**.

Rust 1.75: still compatible with a Botan C FFI; `pakery-spake2plus` still rejected.

---

## 6. SPAKE2+ assessment

Freeze 2’s online protocol matches RFC 9383 Appendix C encoding: uncompressed `0x04||X||Y`, 65-byte shares, 32-byte HMAC confirms, split Botan `shareV||confirmV` at offset 65, `skip_confirmation` forbidden, both confirms before approval.

Registration is now an ACP function:

```text
registration_input = LE64(len(pw)) || pw || LE64(16) || idProver || LE64(16) || idVerifier
salt = SHA-256("ACP SPAKE2+ registration salt v1" || LE64(16)||enrollment_id || LE64(16)||idProver || LE64(16)||idVerifier)
```

`RAW128` uses RFC 5869 HKDF-SHA-256 (Extract+Expand, L=80). `PBKDF2-100K` uses PBKDF2-HMAC-SHA-256, 100000 iterations, L=80. Split 40+40 bytes, big-endian, reduce mod n. Context is online-only. Passwords are octet strings. Enrollment_id in the salt gives per-ceremony records. Commissioner id comes from `begin` before `shareP`. This closes AT-M0-001–005 and the Botan/Matter split.

Residual: a peer that advertises **both** suite IDs for one enrollment can be steered to numeric-code registration (weaker online entropy). Design §7.4 lets the commissioner pick from the intersection. Freeze 2 forbids applying the wrong KDF under a suite ID but does not forbid advertising both for one secret.

---

## 7. Transcript / context assessment

The enrollment context is a closed map, no nulls, no extra keys, CDE text UUIDs, 16-byte IDs only for RFC identities/salt. `identity_algorithm` / `identity_key_id` are bound. Begin/challenge carry the instance IDs. Candidate builds context before `shareP`; commissioner rebuilds after validating challenge SPKI. Application transcript is the five-bstr CDE array. Permission digest is SHA-256 of `{}` only.

That is exact enough to implement enrollment context bytes, pending golden `context.cbor`.

HELLO exporter context is **not** yet exact (AT-M0-032).

---

## 8. Enrollment-state-machine assessment

`EnrollmentRestricted` is the right composition: no ACP principal, only `security.enrollment.*` plus `error.report`, no control families, close and open a fresh authenticated session after success. Attempt IDs consumed on cryptographic failure. Concurrency 2. This closes AT-M0-015/016/027 for enrollment.

Lightweight finished is a **different** pre-HELLO state and is missing from the allowlist (AT-M0-033).

---

## 9. Persistent identity assessment

Tuple `(trust_domain_id, node_id, identity_key_id, credential_id)` is unified. SPKI is RFC 5480 uncompressed P-256. Install PoP is low-S DER ECDSA over `SHA-256("ACP enrollment install proof v1" || transcript_hash || credential_id_ascii)` after durable read-back. `credential_id_ascii` should be explicitly the `sha256:` + 64 hex UTF-8 string (AT-M0-037, MEDIUM).

---

## 10. X.509 / mTLS assessment

Both EKUs, low-S, RFC 7093 method 1 SKI (leftmost 160 bits of SHA-256 of subjectPublicKey, excluding tag/length/unused bits — follow the RFC text, not a loose “contents” paraphrase), AKI = issuer SKI only, isolated trust store, no AIA/OCSP/DNS-ID/CN/system-root, ACP revocation authoritative, 0-RTT and resumption disabled, SAN URN with HELLO equality, legacy `acp://` unauthenticated only. Full v1 roles are local policy. This closes AT-M0-011/012/013 (SAN)/025/028/029.

---

## 11. Authentication / authorization assessment

Normative: claims and capabilities never grant; requested permissions never grant; `tls` and `trusted_lan` are unauthenticated; hardened mode fails closed; peer `auth.mode` must match evidence. SDK enforcement remains M2/M5/M6, which is correct sequencing.

---

## 12. Downgrade assessment

Hardened rejection of missing Trust evidence, stripped capabilities, `tls`, and `trusted_lan` is now in the profile. Residual: dual-suite advertisement (MEDIUM).

---

## 13. Revocation / rotation / recovery assessment

Detached ECDSA over prefix||body, omit-not-null optionals, delta `base+1`, full snapshot may jump forward, 64 KiB/4096 Full and 8 KiB/128 Lightweight caps, hardened session kill default. `issued_at` / `next_update` still say “RFC3339 UTC” while entry times are tag 0 (AT-M0-038). Rotation wire format remains later-milestone. Authority backup AEAD is still unspecified (LOW/MEDIUM, not a Freeze 1 blocker reopened as HIGH).

Clock: 2-minute backdate + 2-minute tolerance; monotonic enrollment deadlines; commissioner time only after PAKE inside approval. Closes AT-M0-031.

---

## 14. Lightweight assessment

Freeze 2 is a protocol, not a header-constant sketch: length-prefixed preface, validate-then-TLS, mutual RPK, exporter-derived finished HMAC, compact credential CDDL-like map, bounds.

It is still not freeze-complete:

- Finished message illegal under current `STATE_MACHINES.md` (HIGH).
- HMAC covers credentials and SPKIs only; envelope node/domain IDs are unprotected unless equality with the signed credential is mandatory (HIGH if unspecified).
- `client_raw_spki` / `server_raw_spki` may be read as 65-byte points or DER SPKI (HIGH).
- Pico exporter, RPK, entropy, RAM, flash, power-loss: **unproven**.

Lightweight remains blocked from production freeze until the HIGH patches and HIL exist. Do not start M5 Lightweight code from Freeze 2 as written.

---

## 15. Secret / resource-bound assessment

Numeric caps are in the profile (concurrency 2/1, message 64 KiB/8 KiB, credentials 8 KiB/2 KiB, revocation caps). Codec enforcement is M1/M8. Unified external authentication error closes the confirmation oracle. QR URI remains secret material (inherent). Design §9.1 still shows a 24-character Crockford example; `SECURITY.md` wins.

---

## 16. Cross-language assessment

Enrollment SPAKE2+/context/approval should now agree **if** implementers follow only `SECURITY.md` and ignore leftover design examples.

Remaining divergence points: HELLO inner maps and optional `product_version`; capability array order after set-typed models; compact `body` map vs bstr; Lightweight SPKI naming; AAD `message_type` literal; `credential_id_ascii`; revocation timestamp tags; design §24 distinct error codes (local vs external — profile wins).

---

## 17. Compatibility assessment

Required frozen-protocol edits are now explicit: `REMOTE.md` SAN, `STATE_MACHINES.md` enrollment allowlist, `trusted_lan` HELLO remains valid but unauthenticated, `tls` remains decodable but not mutual ACP auth, Trust fields under `auth`. Lightweight finished still needs the same class of explicit allowlist.

---

## 18. Findings table

### Original Freeze 1 findings

| ID | Freeze 2 disposition |
|---|---|
| AT-M0-001 | **Addressed.** Uncompressed 65-byte SEC1; RFC TT uses uncompressed points. |
| AT-M0-002 | **Addressed.** Binary-safe registration, both IDs, LE64, HKDF/PBKDF2 specified, context excluded, `from_prehashed` required. |
| AT-M0-003 | **Addressed.** Distinct `RAW128` and `PBKDF2-100K` suite IDs. Residual dual-advertise: AT-M0-035. |
| AT-M0-004 | **Partially addressed.** Bytes exist; legality/HMAC/SPKI holes are AT-M0-033/034. Hardware still required. |
| AT-M0-005 | **Addressed.** 65/65+32/32 mapping; candidate/commissioner labels. |
| AT-M0-006 | **Addressed.** `identity_key_id` in context and AAD; SPKI rehashed. |
| AT-M0-007 | **Addressed.** Begin/challenge carry instance IDs. |
| AT-M0-008 | **Addressed.** Empty-map digest only; requests are not grants. |
| AT-M0-009 | **Addressed** as a closed map. Residual `message_type` literal: AT-M0-036. |
| AT-M0-010 | **Addressed.** Low-S DER ECDSA install proof + read-back. Residual `credential_id_ascii`: AT-M0-037. |
| AT-M0-011 | **Addressed.** Unified tuple; Full v1 local-policy roles. |
| AT-M0-012 | **Addressed.** RFC 7093 method 1 + AKI = issuer SKI. |
| AT-M0-013 | **Partially addressed.** Top-level HELLO/auth closed; SAN revised. Inner maps: AT-M0-032. |
| AT-M0-014 | **Addressed.** 26 chars, alphabet, MSB padding bits, first char `0–7`. |
| AT-M0-015 | **Addressed** for enrollment. Lightweight finished: AT-M0-033. |
| AT-M0-016 | **Addressed** as profile text. SDK work remains M2/M5/M6. |
| AT-M0-017 | **Addressed.** RFC 5869 Extract/Expand; Expand-Label forbidden. |
| AT-M0-018 | **Addressed.** `skip_confirmation` forbidden. |
| AT-M0-019 | **Addressed** except snapshot `issued_at`/`next_update` tag: AT-M0-038. |
| AT-M0-020 | **Partially addressed.** Closed maps; outer `body` encoding: AT-M0-034. |
| AT-M0-021 | **Addressed** as profile bounds. Codec wiring remains M1/M8. |
| AT-M0-022 | **Addressed** via precedence. Leftover 24-char example: AT-M0-039. |
| AT-M0-023 | Accepted informational. |
| AT-M0-024 | Still pending owner license approval. |
| AT-M0-025 | **Addressed.** Full and Lightweight resumption/0-RTT disabled. |
| AT-M0-026 | **Addressed.** `tls`/`trusted_lan` unauthenticated; hardened reject. |
| AT-M0-027 | **Addressed.** Concurrency 2; no Argon2id in ACP registration. |
| AT-M0-028 | **Addressed.** Isolated store; Web-PKI/OCSP/DNS disabled. |
| AT-M0-029 | **Addressed.** Both EKUs, low-S, RFC 7093 SKI. |
| AT-M0-030 | **Addressed.** External `security.authentication_failed`. |
| AT-M0-031 | **Addressed.** 2+2 minute skew; monotonic enrollment; post-PAKE checkpoint. |

### New Freeze 2 findings

| ID | Severity | Location | One-line issue |
|---|---|---|---|
| AT-M0-032 | **HIGH** | `SECURITY.md` §9; HELLO `node`/`capability` schemas | Exporter hash inner maps and optional fields not closed; array order after typed parse unspecified |
| AT-M0-033 | **HIGH** | `STATE_MACHINES.md` pre-Established list vs `SECURITY.md` §10 | `security.lightweight.finished` required before HELLO but not legal before Established |
| AT-M0-034 | **HIGH** | `SECURITY.md` §10 | Compact `body` map vs bstr; `raw_spki` 65-byte vs DER; finished HMAC omits envelope node/domain IDs |
| AT-M0-035 | **MEDIUM** | `SECURITY.md` §2; design §7.4 | Advertising both suite IDs for one enrollment allows steering to numeric-code registration |
| AT-M0-036 | **MEDIUM** | `SECURITY.md` §6 AAD | `message_type` literal not named |
| AT-M0-037 | **MEDIUM** | `SECURITY.md` §6 install proof | `credential_id_ascii` not defined as `sha256:` + 64 hex UTF-8 |
| AT-M0-038 | **MEDIUM** | `SECURITY.md` §11 | Snapshot `issued_at`/`next_update` not stated as CBOR tag 0 |
| AT-M0-039 | **LOW** | design §9.1 | Stale 24-character Crockford example |
| AT-M0-040 | **LOW** | `SECURITY.md` §5 | `candidate_confirm` / `commissioner_confirm` derived but no message binds them |
| AT-M0-041 | **INFORMATIONAL** | Pico + `PBKDF2-100K` | Lightweight should advertise `RAW128` only; 100k PBKDF2 is not Pico-friendly |

---

## 19. Detailed new findings

### AT-M0-032 — HIGH — HELLO exporter inner maps

**Where:** `SECURITY.md` §9.

**Issue:** Top-level HELLO keys and `auth` keys are closed. `node` currently allows `product_version` and `additionalProperties`. Capability objects and arrays are unordered sets in some models. CDE arrays preserve order; two legitimate HELLOs with the same set in different order, or with/without `product_version`, produce different exporter contexts.

**Consequence:** Cross-language Full sessions fail channel binding, or one SDK omits the exporter check.

**Remediation:** Hashed semantic maps, `additionalProperties` false:

- `node`: exactly `node_id`, `instance_id`, `role`, `name`
- `protocol`: exactly `min`, `max`
- each capability: exactly `id`, `version`
- `encodings`/`profiles`/`capabilities`/`security_capabilities`: order of the **sender HELLO being bound**, after projection, with no sort/dedup
- omit empty optionals; never `null`

Receiver hashes the received projected HELLO, not a locally reconstructed sorted set.

**Normative ACP 1.2 change?** No (hashing subset).
**Tests:** Two HELLOs differing only in `product_version` or capability order; vectors for the projected CBOR.

---

### AT-M0-033 — HIGH — Lightweight finished is illegal before Established

**Where:** `STATE_MACHINES.md` line 22 vs `SECURITY.md` §10 steps 4–6.

**Issue:** Pre-Established legal types are hello, hello_ack, error.report, discovery, and the enrollment allowlist. `security.lightweight.finished` is none of those, but MUST be sent after TLS Finished and before HELLO.

**Consequence:** A STATE_MACHINES-faithful router rejects the binding message as `malformed_envelope`. Implementations that special-case it anyway diverge.

**Remediation:** Add an explicit Lightweight pre-HELLO state: after mutual RPK TLS, only `security.lightweight.finished` and `error.report` are legal; HELLO is illegal until both finished messages verify; then ordinary HELLO proceeds. Do not overload `EnrollmentRestricted`.

**Normative ACP 1.2 change?** **Yes**, same class as the enrollment allowlist.
**Tests:** Finished before HELLO accepted; any other type rejected; HELLO before finished rejected.

---

### AT-M0-034 — HIGH — Compact credential and finished HMAC inputs

**Where:** `SECURITY.md` §10.

**Issue:** (1) `{body, algorithm, signature}` does not say whether `body` is a nested map or a bstr of `body_cbor`. `credential_id` hashes the complete canonical object, so this choice is identity. (2) `client_raw_spki` is named “raw” but identity keys are DER SPKI. (3) HMAC covers credentials and SPKIs, not `sender_node_id` / `trust_domain_id` in the envelope. Equality with the signed compact body is implied, not required.

**Remediation:** `body` is the nested map (not a wrapping bstr). `credential_id` = SHA-256 of CDE(`{body, algorithm, signature}`). Finished context SPKIs are the same canonical DER SPKI bytes as `identity_public_key`. Require `sender_node_id` / `trust_domain_id` / credential IDs in the finished payload equal the signed compact body and the TLS RPK; mismatch is `security.authentication_failed`.

**Normative ACP 1.2 change?** No.
**Tests:** Map vs bstr negative vector; SPKI 65-byte vs DER mismatch; finished node_id ≠ credential node_id.

---

### AT-M0-035 — MEDIUM — Dual suite advertisement

One enrollment ID should advertise exactly one suite, matching the bootstrap secret form. Candidate must reject a selected suite that does not match the secret it holds.

### AT-M0-036 — MEDIUM — AAD `message_type`

Fix the value to `security.enrollment.approval`.

### AT-M0-037 — MEDIUM — `credential_id_ascii`

Fix to UTF-8 of the identifier `sha256:` ∥ 64 lowercase hex digits. `transcript_hash` is raw 32 bytes, not hex.

### AT-M0-038 — MEDIUM — Revocation snapshot times

`issued_at` and `next_update` are ACP-CDE tag 0, same as entry revocation time and compact credential times. Omit optional keys.

### AT-M0-039 — LOW — Design Crockford example

Replace or delete the 24-character example; do not leave a 120-bit sample next to a 128-bit rule.

### AT-M0-040 — LOW — Unused ACP confirm keys

Either MAC `install_result` with `candidate_confirm` in addition to ECDSA, or state that the labels exist only for domain separation / future SAS and MUST NOT be used as ad hoc MACs.

### AT-M0-041 — INFORMATIONAL — Lightweight suite

Lightweight targets MUST advertise `RAW128` and MUST NOT require `PBKDF2-100K`.

---

## 20. Required remediation (Freeze 2.1)

Before treating the profile as frozen (still not M1):

1. Close HELLO hashed inner maps and array-order rule (AT-M0-032).
2. Legalize `security.lightweight.finished` in `STATE_MACHINES.md` (AT-M0-033).
3. Fix compact `body`, DER SPKI naming, and finished equality rules (AT-M0-034).
4. Take AT-M0-035–038 in the same patch (cheap, prevents a third review cycle).

Then re-check **only** those amendments. If they are exact and introduce no new HIGH, this CONDITIONAL GO can convert to GO on the document, with provider/Pico/license still external.

Do not open production schemas or SDK Trust cryptography until GO on the document **and** the M0 execution-contract evidence gates.

---

## 21. Remaining external / hardware evidence

Unchanged; not fabricated:

- Provider probes on macOS Swift, iOS, Linux Swift, Python 3.11 (macOS/Linux/Windows), Rust (macOS/Linux/Windows/Pi): RFC 9383 Appendix C, ACP registration including `0x00`/`0xff`/non-UTF-8 secrets, uncompressed shares, AES-GCM, P-256 low-S DER, TLS 1.3 mTLS, exporter equality, no 0-RTT/resumption.
- Pico-class HIL: CSPRNG, RAW128 SPAKE2+, RPK, exporter, RAM/flash/time, transactional storage, concurrency 1, preface 2 KiB.
- ACP golden vectors for registration, context, shares, confirms, HKDF labels, approval, install PoP, identifiers, compact credential, Lightweight finished.
- Project-owner approval of Botan Simplified BSD and Mbed TLS Apache-2.0, plus security-update policy.

---

## 22. Final decision

# CONDITIONAL GO

Candidate Freeze 2 repaired the Freeze 1 failure: Swift, Python, and Rust can implement the **enrollment PAKE, approval AEAD, X.509, and downgrade policy** from `SECURITY.md` without inventing a KDF or point encoding. That is a different document from Freeze 1.

It is **not** GO:

- AT-M0-032, AT-M0-033, and AT-M0-034 are HIGH byte-closure defects. The M0 GO bar forbids unresolved HIGH findings.
- Provider probes, Pico HIL, golden vectors, and license approval remain absent.

**Conditions (all required):**

1. Land Freeze 2.1 covering AT-M0-032–038 with no new HIGH.
2. Independent confirmation that those patches are exact (this reviewer or equivalent; not a full 31-finding redo if the delta is only those sections).
3. Full-platform provider probes as in §21.
4. Pico-class HIL as in §21, or Lightweight removed from the production freeze.
5. Project-owner license approval.

M1 remains closed. This CONDITIONAL GO is not formal cryptographic certification. It is a finding that the remaining uncertainty is bounded spec closure plus external evidence, and that the cryptographic contract for M1 is no longer the unstructured mess that caused Freeze 1’s NO-GO.

If Freeze 2.1 is not applied, treat the profile as **not frozen** and do not encode HELLO binding, compact credentials, or Lightweight finished into SDKs.
