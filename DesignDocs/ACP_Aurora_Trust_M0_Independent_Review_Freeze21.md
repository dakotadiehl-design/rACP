# ACP Aurora Trust M0 Independent Confirmation (Candidate Freeze 2.1)

**Reviewer:** Grok 4.6 (delta confirmation of Freeze 2.1 only)
**Date:** 2026-08-21
**Subject:** Aurora Communications Protocol (ACP) Aurora Trust Candidate Freeze 2.1
**Normative candidate:** `docs/SECURITY.md`
**Prior reviews:** Freeze 1 NO-GO; Freeze 2 CONDITIONAL GO
**Decision:** **CONDITIONAL GO**

AT-M0-032 through AT-M0-041 are closed as requested. Assigning `candidate_confirm` / `commissioner_confirm` (AT-M0-040) introduced one new HIGH: the install-result MAC has no closed payload map, and the commissioner receipt is an unnamed message. That is not an architectural reject. It is still a byte hole, so this is not GO.

M1 remains closed. Provider probes, Pico HIL, and license approval remain unsatisfied and unfabricated.

---

## 1. Executive summary

Freeze 2.1 did the work asked for on HELLO projection, LightweightBinding, compact credentials, finished HMAC inputs, one suite per enrollment, RAW128-only Lightweight, AAD literal, credential-ID ASCII, revocation tag-0 times, and the Crockford example.

The remaining problem is local to §5–6: `confirmation = HMAC-SHA-256(candidate_confirm, install_result_cbor_without_confirmation)` without listing the CBOR keys, plus an unspecified “terminal commissioner receipt.” Three SDKs will HMAC different maps or invent a receipt type that `EnrollmentRestricted` will reject.

Patch that closed map (and either name the receipt in the allowlist or drop it). Then this confirmation can convert to **GO on the document**. External M0 gates still apply.

---

## 2. Review scope

Read-only confirmation of the Freeze 2.1 delta against AT-M0-032–041. New defects from those edits were hunted. Full Freeze 1/2 arguments were not re-litigated where the text is unchanged.

---

## 3. Material inspected

- `docs/SECURITY.md` (Candidate Freeze 2.1)
- `docs/STATE_MACHINES.md` (`LightweightBinding`)
- `docs/REMOTE.md` SAN paragraph
- `DesignDocs/ACP_Aurora_Trust_M0_Review_Remediation.md`
- `DesignDocs/ACP_Aurora_Trust_Authentication_Implementation_Design.md` §9.1 example and §12.5 install_result example

---

## 4. Tests executed / results

| Check | Result |
|---|---|
| `python3 scripts/check_registry.py` | 93 messages, pass |
| `git diff --check` | pass |
| Python / Swift / Rust / interop | Not re-run this pass; Freeze 2.1 is documentation-only and the previous unit/registry run plus the author’s identical counts are consistent. They still do not prove Trust cryptography. |
| ACP security vectors / provider probes / Pico HIL | **none** |

---

## 5–17. Delta assessment

**SPAKE2+ / registration / transcripts / X.509 / downgrade / revocation timestamps / Crockford:** unchanged from Freeze 2 except the requested closures. Dual-suite advertisement is now forbidden. Lightweight advertises RAW128 only.

**HELLO exporter (AT-M0-032):** Closed inner maps (`node` = id/instance/role/name; `protocol` = min/max; capabilities = id/version; `auth` without `channel_binding`). Receiver hashes the **received** projection and MUST NOT sort or reconstruct arrays. `product_version` is excluded. **Closed.**

**LightweightBinding (AT-M0-033):** Distinct state after mutual RPK TLS; only `security.lightweight.finished` and `error.report`; HELLO illegal until both finished verify. **Closed.** Editorial LOW: the global pre-Established sentence still lists HELLO without mentioning this tighter state; the LightweightBinding paragraph is specific and sufficient.

**Compact / finished (AT-M0-034):** `body` is a nested map; `credential_id` hashes the outer CDE object; finished context includes DER SPKIs, node IDs, and trust-domain ID; equality across preface, RPK, finished payload, and HELLO is mandatory. **Closed.** Residual MEDIUM: compact `format`/`serial` types and `role_constraints` sort are not named.

**Confirm keys (AT-M0-040):** HMAC on install_result and an unnamed receipt. **Not closed** — AT-M0-042.

---

## 18. Findings table (Freeze 2.1)

| ID | Severity | Disposition |
|---|---|---|
| AT-M0-032 | HIGH | **Addressed.** |
| AT-M0-033 | HIGH | **Addressed.** |
| AT-M0-034 | HIGH | **Addressed.** |
| AT-M0-035 | MEDIUM | **Addressed.** |
| AT-M0-036 | MEDIUM | **Addressed.** |
| AT-M0-037 | MEDIUM | **Addressed.** |
| AT-M0-038 | MEDIUM | **Addressed.** |
| AT-M0-039 | LOW | **Addressed** (26-character example `03N8-W5CJ-VA7K-M4QP-F9H2-DT6R-X3`). |
| AT-M0-040 | LOW | **Partially addressed**; opened AT-M0-042. |
| AT-M0-041 | INFORMATIONAL | **Addressed.** |
| AT-M0-042 | **HIGH** | Install-result MAC payload is not a closed map; commissioner receipt is unnamed and not in the enrollment allowlist. |
| AT-M0-043 | MEDIUM | Compact `format` const, `serial` type, and `role_constraints` uniqueness/sort not specified. |
| AT-M0-044 | LOW | `STATE_MACHINES.md` global pre-Established list does not mention `LightweightBinding`. |

---

## 19. Detailed finding

### AT-M0-042 — HIGH — Install-result MAC and unnamed receipt

**Where:** `docs/SECURITY.md` §5–6.

**Issue:** `candidate_confirm` MACs “the deterministic-CBOR `security.enrollment.install_result` payload excluding its `confirmation` field.” The payload is described as “the installed IDs, `confirmation`, and `proof_of_possession`.” That is not a closed key set. Design §12.5 still shows `attempt_id`, `status`, `credential_id`, `identity_key_id`, `trust_domain_id`, and `storage_posture`, and the architecture doc is not normative for bytes.

`commissioner_confirm` authenticates a “terminal commissioner receipt over the same payload plus its verified disposition.” No message type, no map, not in `EnrollmentRestricted`.

**Consequence:** Swift includes `storage_posture`; Python omits it; HMAC fails on every successful install, or one SDK skips the HMAC. A commissioner that sends a homemade receipt is `malformed_envelope`. This is the same class of hole Freeze 2 closed for approval plaintext.

**Attack/failure:** Not a credential theft. It is cross-language enrollment failure or a skipped MAC. Either blocks the freeze bar (“exact bytes for three SDKs”).

**Remediation:** Closed install_result map, no extras, no nulls, for example:

```text
attempt_id, status, credential_id, identity_key_id, trust_domain_id,
storage_posture, proof_of_possession, confirmation
```

with typed `storage_posture` (`class`, `hardware_backed`, `private_key_exportable`). HMAC input is CDE of that map with `confirmation` omitted. Either (a) name `security.enrollment.receipt` with a closed map, add it to the enrollment allowlist, and MAC it with `commissioner_confirm`, or (b) state that enrollment is complete after verified install_result and that `commissioner_confirm` is reserved and MUST NOT be sent in v1.

**Normative ACP 1.2 change?** Additive security messages only.
**Tests:** Golden install_result CBOR with and without `confirmation`; extra-key reject; no unnamed receipt on the wire if (b).

### AT-M0-043 — MEDIUM — Compact body field types

Fix `format` = `acp-compact-credential-v1`, `serial` as uint64, `role_constraints` as sorted unique text (same rule as approval).

### AT-M0-044 — LOW — Pre-Established sentence

Mention `LightweightBinding` beside the enrollment allowlist in the global legal-types sentence.

---

## 20. Required remediation (Freeze 2.1.1)

1. Close the install_result map and HMAC input (AT-M0-042).
2. Name or forbid the commissioner receipt (AT-M0-042).
3. Take AT-M0-043 in the same patch.

If that patch is exact and adds no new HIGH, independent confirmation of **only those paragraphs** is enough to issue **GO on the document**.

---

## 21. Remaining external / hardware evidence

Unchanged; not claimed:

- Provider probes (RFC 9383 Appendix C, ACP registration including `0x00`/`0xff`/non-UTF-8, uncompressed shares, AES-GCM, low-S ECDSA, TLS 1.3 mTLS, exporter, no 0-RTT/resumption) on every Full target.
- Pico HIL (CSPRNG, RAW128, RPK, exporter, RAM/flash/time, transactional storage) or Lightweight removed from the production freeze.
- Golden vectors.
- Owner approval of Botan Simplified BSD and Mbed TLS Apache-2.0.

---

## 22. Final decision

# CONDITIONAL GO

The Freeze 2.1 delta **did** close AT-M0-032–039 and AT-M0-041. HELLO binding, LightweightBinding, compact nested body, finished equality, and suite rules are now precise enough to implement.

It is **not** GO because AT-M0-042 is HIGH. The confirm-key assignment turned a LOW leftover into a MAC over an unspecified map.

**Conditions:**

1. Land the AT-M0-042/043 closed install_result (and receipt name-or-forbid) with no new HIGH.
2. Independent confirmation of that delta only.
3. Provider probes.
4. Pico HIL or Lightweight dropped from production freeze.
5. Owner license approval.

M0 stays blocked. M1 stays closed. Do not encode `install_result` HMAC bytes into SDKs until condition 1–2 land. Do not treat HELLO projection, LightweightBinding, or compact encoding as still open; those CONDITIONAL GO items are done.
