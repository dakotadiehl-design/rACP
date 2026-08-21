# ACP Aurora Trust M0 Independent Security Review

**Reviewer:** Grok 4.6 (independent of the Codex M0 package)
**Date:** 2026-08-21
**Subject:** Aurora Communications Protocol (ACP) Aurora Trust Candidate Freeze 1
**Normative candidate:** `docs/SECURITY.md`
**Decision:** **NO-GO**

Codex’s decision record already marked M0 blocked on missing independent review and missing provider/hardware probes. That record is **not** adopted here. Re-deriving the cryptographic contract against RFC 9383, Botan 3.13.0 source, ACP-CDE-1.2, and the three current SDKs shows that Candidate Freeze 1 is **not internally precise enough to freeze**. Several items Codex listed as “candidate specified” do not resolve to exact bytes, and one of them contradicts both RFC 9383 Appendix C and the proposed Botan provider.

GO is unavailable: BLOCKER and HIGH findings remain, wire cryptography is ambiguous, and the Full/Lightweight provider composition is unsafe under a single suite identifier.

This is a read-only review. No ACP production code, schemas, registry rows, or vectors were modified to produce it.

---

## 1. Executive summary

The architecture is the right shape: discovery is untrusted, SPAKE2+ enrolls a device credential, TLS 1.3 (or an audited RPK channel) authenticates, authorization is local, `trusted_lan` is not an authenticator, and device identity is separate from operator assignment. Those layering rules in `docs/SECURITY.md` §1 and the implementation design are sound and should be kept.

Candidate Freeze 1 is **not** a freeze. Independent Swift, Python, and Rust implementers following only the freeze text would produce different registration records, different SPAKE2+ shares, different application transcripts, and different HELLO channel-binding hashes. The proposed shared provider, Botan 3.13.0, uses **uncompressed** P-256 shares and Argon2id with **64 MiB** RAM. The freeze text requires **compressed** SEC1 encoding and treats Lightweight as the same suite. Those cannot be true together.

This is not a claim that SPAKE2+ or TLS 1.3 is weak. It is a claim that **ACP has not yet written down one interoperable embedding**.

**Do not start M1 production cryptography, schemas that lock these bytes, or SDK enrollment code until the BLOCKER/HIGH items below are amended into the normative profile and re-reviewed.**

---

## 2. Review scope

Read-only adversarial GO / NO-GO of Milestone 0 Candidate Freeze 1 against the following threat model: LAN observer/injector, replay, discovery spoofing, identity/role/capability forgery, races, reorder, malformed CBOR/JSON, enrollment exhaustion, interrupted writes, stale/revoked credentials, unauthorized-but-legitimate nodes, and cross-domain/protocol reuse.

Composition was reviewed, not just primitive strength. Pico hardware was not available; outstanding Pico tests are preserved and not fabricated. Provider licenses are technically identified; project-owner licensing approval is **pending**.

---

## 3. Material inspected

**Normative / planning**

- `docs/SECURITY.md` (Candidate Freeze 1)
- `docs/ACP_SPEC.md`, `WIRE_ENCODING.md`, `STATE_MACHINES.md`, `CAPABILITIES.md`, `ERROR_CODES.md`, `REMOTE.md`, `CONSTANTS.md`
- `DesignDocs/ACP_Aurora_Trust_Authentication_Implementation_Design.md`
- `DesignDocs/ACP_Aurora_Trust_Implementation_Plan.md`
- `DesignDocs/ACP_Aurora_Trust_M0_Decision_Record.md`
- `DesignDocs/ACP_Aurora_Trust_Conformance_Matrix.md`

**Frozen ACP 1.2 contract and code**

- `schema/common/defs.schema.json`, `schema/session/messages.schema.json`, `schema/discovery/messages.schema.json`, `schema/constants.json`, `schema/registry.json`, Remote schemas
- Swift: `Sources/AuroraACP/Session/ACPSession.swift`, Discovery, Remote, Codec
- Python: `python/src/acp/session.py`, `codec.py`, `cbor_cde.py`, `ws.py`, `discovery.py`, `remote.py`, `transfer.py`
- Rust: `rust/acp-session`, `acp-codec`, `Cargo.toml` (`rust-version = "1.75"`)

**External (not deferred to Codex)**

- RFC 9383 (SPAKE2+, including Appendix C vectors)
- Botan 3.13.0 handbook and `spake2p.cpp` (share encoding, Argon2id parameters, TT construction, C FFI password type)
- Current Python TLS SAN extractor vs freeze SAN URI

No Aurora Trust production crypto, security schemas, or `vectors/security/` exist. That is expected at M0; it also means **no cryptographic property is evidenced by tests**.

---

## 4. Tests executed / results

Existing ACP 1.2 regression was run without modifying code. These tests prove current codec/session/Remote compatibility. They do **not** prove SPAKE2+, enrollment, mTLS, revocation, or downgrade properties.

| Check | Result |
|---|---|
| `python3 scripts/check_registry.py` | 93 messages, pass |
| `git diff --check` | pass |
| Python tests (`cd python && pytest tests --cov=acp --cov-fail-under=70`) | **142 passed**, coverage **81.41%** |
| Rust `cargo test --manifest-path rust/Cargo.toml` | **25** unit tests passed; doc tests passed |
| Swift `swift test` | **75** tests passed |
| Python WS interop `tests/interop/test_ws_hello.py` | pass |
| Python WS Remote interop `tests/interop/test_ws_remote.py` | pass |
| Python/Rust framed interop hello, session, remote, negative; JSON and CBOR | pass |
| Python/Swift framed interop hello, session, remote, negative; JSON and CBOR | pass |
| Rust/Swift framed interop session; JSON and CBOR | pass |
| SPAKE2+ / RFC 9383 / ACP security vectors | **none exist** |
| Provider capability probes | **none exist** |
| Pico-class hardware | **not available; not claimed** |

Security-property coverage (wrong secret, replay, reflection, downgrade, transcript mutation, revoked/future credentials, interrupted install/rotation, revocation rollback, secret leakage) is **empty** because there is no Trust implementation. Passing ACP 1.2 tests are not evidence that Candidate Freeze 1 is correct.

---

## 5. Provider assessment

| Candidate | Documented support | ACP-qualified support | Verdict |
|---|---|---|---|
| **Botan 3.13.0** (shared Full-profile candidate) | RFC 9383 SPAKE2+ P-256/SHA-256, SHA-256, HMAC, HKDF, AES-GCM, P-256 ECDSA, X.509, TLS 1.3, C/C++/Python, FFI | **Not qualified.** SPAKE2+ is new in 3.13. No ACP vectors. No SwiftPM/wheel/Windows/macOS/Linux packaging proof. No TLS exporter/peer-evidence probe. **Wire encoding is uncompressed, 65-byte P-256 shares.** Registration is Argon2id **m=64 MiB, t=3, p=4**. C FFI takes `const char *` password; Python binding takes `password: str`. `skip_confirmation()` exists. | Leading Full-profile candidate **if ACP adopts Botan’s actual profile**, not the freeze’s compressed-point text. License: Simplified BSD (**owner approval pending**). |
| Rust `spake2` crate | Balanced SPAKE2 | Incompatible with SPAKE2+ | Correctly rejected |
| `pakery-spake2plus` | RFC 9383, Rust 1.79 | Not 1.75 MSRV; unaudited | Correctly rejected as production provider |
| BoringSSL SPAKE2+ | Internal API, no third-party ABI promise | Not a public ACP provider | Correctly rejected |
| OpenSSL 3.5 / LibreSSL 3.3.6 (macOS `openssl`) | No public SPAKE2+ | Not evidence | Correctly rejected |
| Apple CryptoKit | P-256, AEAD, Secure Enclave; **no RFC 9383 API** | Signing/storage only | Correct |
| Mbed TLS + Matter PAL | TLS 1.3 and RFC 7250 RPK **identifiers**; Matter SPAKE2+ adapter | Header constants ≠ qualified RPK. Matter SPAKE2+ is typically PBKDF2, **not** Botan Argon2id-64MiB. Pico RAM/flash/entropy/storage **unproven**. | Not ACP-qualified. Cannot share Botan registration under one suite ID. |
| Android | None | None | Out of M0 production path |

**Documented ≠ qualified.** Using Botan as “the RFC 9383 API” without pinning registration parameters, point encoding, and password encoding is how three SDKs diverge.

Rust 1.75: current workspace `rust-version = "1.75"`; existing crates tested successfully. A Botan C FFI can stay on 1.75 if the binding crate also supports 1.75. Adopting `pakery-spake2plus` would raise MSRV to 1.79 and is not acceptable without an explicit MSRV change.

---

## 6. SPAKE2+ assessment

RFC 9383 P-256/SHA-256/HKDF-HMAC-SHA256, M/N from §4, bidirectional confirmation, and “no approval before both confirmations succeed” are the right **protocol** choices.

The freeze does **not** specify an interoperable **embedding**.

**What is actually true**

- Candidate = Prover (knows bootstrap secret). Commissioner = Verifier (stores ephemeral registration record). That mapping is correct for an augmented PAKE.
- RFC 9383 TT already binds Context, idProver, idVerifier, M, N, shares, Z, V, w0 with 8-byte little-endian length prefixes. ACP’s extra application transcript is additional, not a replacement — if the inner RFC transcript is left to a conforming provider.
- Botan 3.13.0 `spake2p.cpp`:
  - Shares: `serialize_uncompressed()`, `share_size() = 1 + 2 * p_bytes` → **65 bytes on P-256**.
  - TT uses uncompressed M, N, Z, V.
  - Verifier wire message is **`shareV || confirmV`** (97 bytes).
  - Registration: Argon2id **64 MiB / t=3 / p=4**; PBKDF input is `len(pw)||pw||len(idP)||idP||len(idV)||idV` with 8-byte LE lengths.
  - Context is an **online** `ProverContext` / `VerifierContext` argument, not a registration input.
  - `skip_confirmation()` exists and skips `confirmP`.
  - C FFI password is `const char *`.

**What the freeze gets wrong or leaves open**

- “Compressed SEC1 point encoding” vs RFC 9383 Appendix C **and** Botan: both use **uncompressed** `0x04` shares in the protocol/TT. The freeze conflates “M/N constants are published compressed” with “shares are sent compressed.”
- Registration is delegated to “the selected provider’s RFC 9383 registration API” with `identity = candidate node_id` only. Botan requires **both** `prover_id` and `verifier_id`. RFC 9383’s recommended PBKDF input includes both identities. Freeze text, Botan API, and RFC recommendation are three different functions.
- Freeze lists `context` as a registration-API argument. RFC 9383 and Botan put Context only in TT.
- Password is 16 raw bytes; Botan C FFI is `const char *`; Python API is `str`. Embedded `0x00` truncates (~1/256 secrets). Implementers will pass Crockford text, hex, or truncated C strings. Those are different `w0`/`w1`.
- Argon2id 64 MiB cannot run on Pico-class RAM. Matter/Mbed SPAKE2+ will not produce the same record. A single suite ID `ACP-SPAKE2PLUS-P256-SHA256-HKDFSHA256-v1` covering Full and Lightweight is false.
- RFC 9383 Appendix C supplies `w0`/`w1` directly and **does not test PBKDF**. “Reproduce Appendix C” does not freeze ACP registration.
- ACP `client_confirm` / `server_confirm` names do not map to Prover/Verifier. Enrollment has no TLS client/server. This will reverse confirmation order in at least one SDK.
- `skip_confirmation` is a footgun relative to “both RFC 9383 confirmations must succeed.”

Wrong-secret behavior of SPAKE2+ itself is fine (one online guess per attempt). Lockout of 5 attempts per enrollment ID is fine. The failure is **ACP-specific byte agreement**, not the PAKE math.

---

## 7. Transcript / context assessment

The application context map is a good idea. It is **not** exact bytes.

Required map keys are listed, and ACP-CDE-1.2 sorts text keys by encoded key bytes. Python `cbor_cde.py` is the reference encoder. Missing pieces:

- `additionalProperties` is not forbidden. Extra keys change the CBOR.
- UUID in the context map is ACP-CDE-1.2 **text**. RFC 9383 `idProver`/`idVerifier` are 16 raw bytes. Salt concatenation uses `enrollment_id_bytes || candidate_node_id_bytes` without saying text vs RFC 4122 binary.
- `requested_permissions_digest` hashes “the complete requested permission object.” That object has **no schema**. Empty vs absent is specified (empty map). Everything else is not.
- `candidate_instance_id` and `commissioner_instance_id` are in the context but **not** in the enrollment `begin`/`challenge` examples. Parties cannot agree on those values from the specified messages.
- Candidate identity public key is sent in `challenge` and is **not** in context, application transcript, or approval AAD.
- Application transcript is `SHA-256(CDE([context, shareP, shareV, confirmV, confirmP]))`. Botan emits `shareV||confirmV` as one blob. Freeze never says how to split it (`share_size` + `confirmation_size` is the Botan answer, and it depends on uncompressed 65+32).
- HELLO exporter context is SHA-256 of “canonical HELLO payload with `auth.channel_binding` omitted.” HELLO `additionalProperties: true`. Python `filter_payload` **drops unknown top-level HELLO keys**; Swift/Rust keep them. JSON key order already differs across SDKs (Python unsorted, Swift/Rust sorted). The freeze correctly says “canonicalize through the semantic model then CDE,” but does not list the closed field set. Omit vs `null` vs empty bstr is unspecified.

Substitution of `node_id`, role, domain, suite, or versions **would** be caught **if** those fields are in the agreed context **and** both peers serialize it identically. Today they will not.

Until golden `context.cbor` exists, the following each independently change RFC 9383 `Context` and/or the ACP transcript hash:

1. Point encoding compressed vs uncompressed
2. `w0`/`w1` KDF
3. Password C-string vs 16 raw bytes
4. Which identities enter PBKDF
5. Context in PBKDF vs only `TT`
6. `shareV||confirmV` vs split bstrs
7. HKDF RFC 5869 vs Expand-Label; `K_shared` length
8. Context key order / extra keys / nulls
9. UUID text vs 16-byte
10. Permission object CBOR
11. Role string normalization
12. Identity SPKI in or out of transcript
13. Instance ID source
14. HELLO omission of `channel_binding`
15. AAD map vs array; hash hex vs bstr
16. SPKI compressed vs uncompressed inside DER
17. Compact credential canonical bytes
18. Revocation body CBOR + signature
19. Crockford length/alphabet
20. Salt label concatenation without length prefixes if anyone uses UUID text

**The normative transcript does not resolve to exact bytes.**

---

## 8. Enrollment-state-machine assessment

Design §11/§12 is a reasonable ceremony: enrollment_id-keyed state, bounded concurrency, deadlines, restart invalidates PAKE, approval after both confirmations, atomic install, previous identity retained on failure.

Gaps that break the ceremony if implemented from the freeze alone:

- Transient state is said to be keyed by `enrollment_id`, not address. Good. The freeze does not specify attempt_id uniqueness, consumption on **success and failure**, or how a restarted commissioner with a new `instance_id` is distinguished from a MITM.
- Design allows enrollment messages pre-HELLO or on an enrollment session. Frozen `STATE_MACHINES.md` and all three `admit()` paths only allow `session.hello`, `session.hello_ack`, `error.report`, and discovery before Established. Enrollment therefore requires an **explicit** registry/`STATE_MACHINES.md` change. Silent additive interpretation will be rejected as `malformed_envelope`.
- Approval ciphertext transplant is blocked **if** AAD is the specified CBOR and implementations encode it identically. AAD field types/order are not a closed schema.
- Installation result “proves possession of the new identity private key” — **how** is unspecified (sign `transcript_hash`? TLS? which encoding?). A commissioner can mark Complete without a cryptographic PoP.
- Concurrent attempts, cancellation races, and address rebinding are described in the design, not frozen as testable transitions.
- Distinct confirmation error codes can oracle “wrong password” versus “wrong context.”

---

## 9. Persistent identity assessment

Stable tuple in freeze: `(trust_domain_id, node_id, identity_key_id, credential_id)`.
Design §14.1: `(trust_domain_id, node_id, identity_public_key, credential_serial)`.

Those are different identities. Key ID construction (`sha256:` + lowercase hex of DER SPKI) is precise. Credential ID for Full (leaf DER) vs Lightweight (signed compact object) is precise **if** compact canonical bytes are specified; they are not. DER SPKI itself may use compressed or uncompressed ECPoint encoding; that is unspecified and changes `identity_key_id`.

Transactional stage/verify/commit/rollback is correctly required. No production store exists. Interrupted-write recovery is a later-milestone property, but the freeze must not leave “credential becomes active without PoP” as an SDK choice.

---

## 10. X.509 / mTLS assessment

Full-profile intent is good: TLS 1.3 only, mutual certificates, SAN URI not CN, critical KU `digitalSignature`, BC CA:FALSE on leaves, path length bounded, SHA-1/RSA/P-384 leaves rejected, 90-day default / 397-day max, 128-bit random serials with DER sign-padding, no plaintext fallback.

Defects:

- **Role constraints are not in the X.509 profile.** Compact credentials have `role_constraints`. Full-profile certs have only a node URN SAN. Authorization formula includes “credential role constraints.” Full-profile credentials currently cannot carry them.
- SKI/AKI are “required” with **no construction** (RFC 5280 SHA-1 of SPKI bit string vs SHA-256 vs issuer+serial AKI). Three SDKs will emit different certs. SHA-1 signatures are rejected, but SKI is commonly SHA-1 of the public key — implementers may reject every cert.
- EKU “clientAuth and/or serverAuth according to issued node use”: ACP nodes are often both. Wrong EKU causes fail-closed or operators disable EKU checks.
- ECDSA “strict DER” does not require low-S; signatures are malleable.
- Python today extracts TLS identity from **`acp://<uuid>`** (`python/src/acp/ws.py` 161–178; `docs/REMOTE.md` TLS identity). Freeze SAN is `urn:aurora:acp:node:<domain>:<node>`. That is a **normative change** to an existing documented rule, and the current extractor will return `None` on freeze certs. `getpeercert()` without `binary_form=True` cannot compute `credential_id`.
- A TLS handshake success must not become `AuthenticatedPrincipal` without chain/domain/SAN/EKU/time/revocation/PoP/HELLO `node_id` equality. Freeze says this. Current stacks never do it: Swift has no TLS; Rust `allow_plaintext` defaults **true** and non-`trusted_lan` `auth_mode` **skips** the plaintext gate; Swift/Rust **ignore peer `auth.mode`**.
- Freeze never says to ignore AIA/CRLDP/OCSP and use only ACP snapshots. Default OS verify will fail closed offline or fail open on the system store.
- Full-profile 0-RTT/resumption is forbidden only for Lightweight. Full-profile ticket resumption can skip client-cert revalidation.

Exporter label `EXPORTER-Aurora-ACP-1.2-HELLO`, 32-byte length, no fallback in hardened mode: good. Platform exporter APIs are unproven (Apple Network.framework especially). That is remaining evidence **after** the context bytes are closed.

---

## 11. Authentication / authorization assessment

The intended pipeline is correct:

`discovery → identity claim → authentication → capability negotiation → authorization → operational safety`

and

`authenticated identity ∩ credential constraints ∩ local policy ∩ negotiated capabilities ∩ operational safety`

Current ACP 1.2 does the opposite and Trust **must not inherit it**:

- HELLO `role` is used as sender authorization (`admit()` in all three SDKs).
- Capability advertisement **is** a grant (`docs/CAPABILITIES.md`; intersection of self-asserted lists). Default capability sets include `resource.transfer` and Remote invoke.
- Python Remote production authority already ignores client-claimed Remote roles and keys policy by `node_id` — good. Swift/Rust Remote simulators key by session ID string — not production, but dangerous if copied.
- Resource transfer auto-accepts chunked offers for any role that negotiated the capability.
- `requested_permissions_digest` is in the PAKE context. Operators may treat requested as granted unless the freeze restates that requested ≠ issued ≠ effective.

Device vs operator identity in the design is correct: reassignment must not reenroll; revocation must not delete show assets. That contract should remain. It is not yet implemented.

---

## 12. Downgrade assessment

Hardened fail-closed is written down. Current code cannot enforce it:

- `default_auth_mode: trusted_lan`.
- Swift handshake **only** works with `allowPlaintext`.
- Rust defaults `allow_plaintext: true`; setting `auth_mode` to `"mutual_tls"` skips the gate and still does plaintext.
- Swift/Rust never read the peer’s `auth.mode`.
- Discovery missing `sec` → `trusted_lan`; Python missing advert `security_mode` → `trusted_lan`.
- Capability intersection **continues** if a Trust capability is absent. A MITM that strips `security.mutual_tls` still gets `established`.
- Frozen enum still includes unilateral `tls`. It looks stronger than `trusted_lan` and is not mutual node authentication.

Trust must be **local policy fail-closed**, not a negotiated optional capability that peers can omit. The freeze says that; M1 schemas must not encode the opposite.

---

## 13. Revocation / rotation / recovery assessment

Signed deterministic-CBOR snapshots with strictly increasing epochs, fail-closed on rollback/wrong domain/bad signature, no implicit offline grace: good direction.

Remaining holes:

- Signature algorithm ID and ECDSA encoding (DER vs raw `r||s`) not stated.
- Optional `previous_snapshot_hash`: absent vs null.
- Timestamp encoding: RFC3339 text vs ACP-CDE tag 0.
- Missing deltas vs accepting a later full snapshot is implied, not tested. Epoch gap handling is not stated.
- Active-session kill is “local policy” — fine, but must not default to “leave revoked nodes in control.”
- Rotation two-phase commit is in the design, not a frozen byte protocol. Power-loss during overlap can yield two valid keys or none.
- Authority identity `(trust_domain_id, authority_key_id)` is the right recovery rule. Backup encryption algorithm is not frozen. Human-readable names are correctly declared non-identities.
- Cloned **same** `(trust_domain_id, authority_key_id)` from backup can split a show: two authorities issue distinct serials/epochs. New or factory-reset nodes that fetch epoch 1 after a restore can trust a previously revoked cert.

Clock policy (`trusted_wall` / `authenticated_checkpoint` / `untrusted`, 2-minute tolerance, commissioner time not setting the RTC) is a reasonable constrained-device model. Hardware proof is missing. Production fail-closed when validity cannot be evaluated is the right default.

Five-minute `notBefore` backdate plus two-minute tolerance is a seven-minute future-cert window. Numeric-code expiry is wall-clock, not monotonic. Pico enrollment that needs commissioner time to validate the credential it is about to install is circular.

---

## 14. Lightweight assessment

**Not freezeable.** `docs/SECURITY.md` §10 already admits this. Independent review agrees, for stronger reasons than “Pico not in the lab.”

- Preface credentials before TLS are unauthenticated metadata. Binding “preface key = TLS RPK = HELLO node_id” can work **if** RPK is actually verified and the finished exchange is specified. The finished message, transcript inputs, and MAC are **not** specified.
- Compact credential `identity_public_key` is “bytes” with no SPKI-vs-raw-point rule. Signature-over-body is not a closed CBOR schema. Critical-extension bit is mentioned; encoding of that bit is not.
- TLS 1.3 0-RTT forbidden and resumption disabled: good for Lightweight; Full should match.
- Botan Argon2id 64 MiB **cannot** be the Lightweight registration function. Matter SPAKE2+ cannot silently substitute under the same suite ID.
- Pico CSPRNG, RAM high-water, flash, transactional storage, power-loss, and bounded concurrency: **not evidenced**. Desktop simulation is not a substitute.

Do not approve Lightweight because Mbed TLS headers mention `RawPublicKey`.

---

## 15. Secret / resource-bound assessment

Design redaction policy is correct (no bootstrap secrets, PAKE material, keys, or decrypted approvals in logs/PCAP/errors). Nothing implements it yet. Current HELLO_ACK errors stringify exceptions — that will become an oracle if Trust puts verifier state in exception text. Distinct confirmation error codes are already an oracle (wrong secret vs wrong context).

QR URI embeds the raw secret by design. Freeze does not require consume-on-success, screenshot/log redaction, or forbidding the URI in discovery/crash reports.

Bounds in design §27 (1 concurrent Lightweight enrollment, 8 KiB security messages, 2 KiB compact credential) are reasonable. They are **not** wired into codecs:

- CBOR decoders allow **8 MiB** strings and **1,048,576** collection items.
- `max_decoded_bytes` (4 MiB / 32 KiB) is unused in codecs.
- Framed TCP allows 8 MiB frames vs 1 MiB ACP max message.
- Python decoder nesting 32 vs profile 16/8.
- 8 concurrent Full enrollments × Botan Argon2id 64 MiB = **512 MiB** per flood of `begin`.

Malformed input can allocate far beyond Lightweight limits today. That is an M1/M8 requirement, not a reason to freeze an unbounded Lightweight profile.

No pairing secrets were found in current fixtures. There is no Trust material to leak yet.

---

## 16. Cross-language assessment

Places Swift, Python, and Rust will reasonably disagree **from Candidate Freeze 1 as written**:

| Topic | Divergence |
|---|---|
| SPAKE2+ shares | Freeze compressed vs RFC/Botan uncompressed |
| Registration | identity-only vs prover+verifier; Argon2id params; password `str` / `const char *` vs 16 bytes vs Crockford text; context in PBKDF vs TT only |
| Context UUIDs | CDE text vs 16 raw bytes in salt/idProver |
| Permission digest | no object schema |
| HKDF | `HKDF-Expand(PRK, label, 32)` vs full HKDF Extract+Expand vs TLS Expand-Label |
| Confirm names | client/server vs prover/verifier vs candidate/commissioner |
| HELLO hash | Python drops extra top-level keys; Swift/Rust keep; JSON key order differs; omit vs null |
| Timestamps | Python requires CBOR tag 0; Swift/Rust accept untagged strings |
| UUID case | Swift can emit uppercase if given Foundation UUID without lowercasing caller input |
| X.509 SKI/AKI, role extensions, EKU, low-S | unspecified |
| Compact public key | unspecified |
| TLS SAN | `acp://uuid` vs `urn:aurora:acp:node:...` |
| Pre-handshake legality | hardcoded hello/ack vs registry `legal_before_handshake` |
| Peer `auth.mode` | Python checks; Swift/Rust ignore |
| `allow_plaintext` default | Python/Swift false; Rust true |

Without golden `vectors/security/` that pin **every** one of these, M2 “three SDKs produce identical context bytes” will fail or, worse, pass on accidental shared bugs.

---

## 17. Compatibility assessment

Aurora Trust **can** remain additive if, and only if:

- New `auth.mode` values and security capabilities are an **explicit** schema/registry revision.
- Enrollment messages get `legal_before_handshake` (or a dedicated enrollment session) via an explicit `STATE_MACHINES.md` change.
- Extra HELLO fields live under `auth.*` (Python will drop unknown **top-level** HELLO keys).
- Remote hello stays `additionalProperties: false` except `extensions`.
- Non-Trust peers keep working; hardened fail-closed is **local policy**.
- SAN URI change vs `docs/REMOTE.md` `acp://<uuid>` is an explicit spec revision.
- Existing golden `session.hello` vectors with `auth: {mode: trusted_lan}` remain valid and unauthenticated.

The freeze does **not** currently call out those frozen-protocol edits. They are required, not silent.

---

## 18. Findings table

| ID | Severity | Location | One-line issue |
|---|---|---|---|
| AT-M0-001 | **BLOCKER** | `docs/SECURITY.md` §2; RFC 9383 App. C; Botan `share_size()` | Point encoding: freeze says compressed; RFC vectors and Botan use uncompressed 65-byte shares |
| AT-M0-002 | **BLOCKER** | `SECURITY.md` §3; Botan `from_password`; RFC 9383 §3.2 | Registration is not one function: identities, salt UUID encoding, password representation, Argon2id 64 MiB, context-as-registration-input, C FFI NUL truncation |
| AT-M0-003 | **BLOCKER** | `SECURITY.md` §2–3, §10 | Same suite ID cannot cover Botan Argon2id-64MiB Full and Pico/Matter Lightweight |
| AT-M0-004 | **BLOCKER** | `SECURITY.md` §10 | Lightweight preface → RPK → security-finished binding is not a byte protocol |
| AT-M0-005 | **HIGH** | `SECURITY.md` §4–5; Botan verifier message | Application transcript splits `shareV`/`confirmV`; Botan concatenates them; ACP confirm keys named client/server |
| AT-M0-006 | **HIGH** | `SECURITY.md` §4; design §12.3 | Candidate identity public key not bound into context, transcript, or approval AAD |
| AT-M0-007 | **HIGH** | `SECURITY.md` §4; design §12.2 | Instance IDs in context are not on the specified enrollment messages |
| AT-M0-008 | **HIGH** | `SECURITY.md` §4 | Requested-permission object for the digest has no schema |
| AT-M0-009 | **HIGH** | `SECURITY.md` §6; design §12.4 | Approval plaintext is not a closed deterministic-CBOR schema |
| AT-M0-010 | **HIGH** | `SECURITY.md` §7; design §12.5 | Installation PoP algorithm unspecified |
| AT-M0-011 | **HIGH** | `SECURITY.md` §8 vs design §14.1 | Full-profile X.509 has no role-constraint encoding; identity tuples disagree |
| AT-M0-012 | **HIGH** | `SECURITY.md` §8 | SKI/AKI construction unspecified |
| AT-M0-013 | **HIGH** | `SECURITY.md` §9; `ws.py` 161–178; `REMOTE.md` | HELLO exporter field set unspecified; SAN URI replaces documented `acp://` |
| AT-M0-014 | **HIGH** | `SECURITY.md` §3; design §9.1 | 16-byte secret vs 24-character Crockford example; padding/checksum unspecified |
| AT-M0-015 | **HIGH** | `STATE_MACHINES.md`; all `admit()` | Enrollment is illegal before Established unless registry/spec are explicitly revised |
| AT-M0-016 | **HIGH** | Current session/discovery/caps | Peer auth ignored; capability/role self-claims grant; Rust plaintext default |
| AT-M0-017 | **MEDIUM** | `SECURITY.md` §5 | HKDF-Expand vs full HKDF Extract+Expand vs TLS Expand-Label not stated |
| AT-M0-018 | **MEDIUM** | Botan `skip_confirmation` | Provider API can skip `confirmP` |
| AT-M0-019 | **MEDIUM** | `SECURITY.md` §11 | Revocation signature alg/encoding; optional fields absent vs null; time tag |
| AT-M0-020 | **MEDIUM** | `SECURITY.md` §10 / design §14.3 | Compact credential public-key and critical-extension encoding |
| AT-M0-021 | **MEDIUM** | Codecs vs `constants.json` | Lightweight size/nesting limits not enforced in CBOR codecs |
| AT-M0-022 | **LOW** | Design vs freeze | Ed25519 optional, SAS assets, identity tuple, “length prefix or CBOR” leftover text |
| AT-M0-023 | **INFORMATIONAL** | Design §5.3 | Buttonless enrollment without a private bootstrap secret cannot be secure — correctly admitted |
| AT-M0-024 | **INFORMATIONAL** | Botan / Mbed licenses | Simplified BSD / Apache-2.0 typical; **owner approval pending** |
| AT-M0-025 | **HIGH** | `SECURITY.md` §10 vs §8–9 | Full-profile 0-RTT/resumption not forbidden; ticket resume can skip cert revalidation |
| AT-M0-026 | **HIGH** | `defs.schema.json` `auth_mode`; `SECURITY.md` | Unilateral `tls` remains a lookalike upgrade of `trusted_lan` |
| AT-M0-027 | **HIGH** | Design §27; Botan Argon2id | 8 concurrent Full enrollments × 64 MiB = 512 MiB memory DoS |
| AT-M0-028 | **HIGH** | `SECURITY.md` §8, §11 | PKIX AIA/CRLDP/OCSP defaults vs ACP-only revocation; isolated trust store unspecified |
| AT-M0-029 | **MEDIUM** | `SECURITY.md` §8 | EKU both-roles default, ECDSA low-S, and SKI-as-SHA-1 collision with “no SHA-1” |
| AT-M0-030 | **MEDIUM** | Design §24; `SECURITY.md` §6 | Distinct confirmation errors oracle wrong-secret vs wrong-context |
| AT-M0-031 | **MEDIUM** | `SECURITY.md` §12 | 5-minute notBefore + 2-minute tolerance; wall-clock code expiry; Pico enrollment clock circularity |

---

## 19. Detailed findings

### AT-M0-001 — BLOCKER — Compressed vs uncompressed SPAKE2+ points

**Where:** `docs/SECURITY.md` §2: “compressed SEC1 point encoding”; RFC 9383 Appendix C: “All points are encoded using the uncompressed format”; Botan `SystemParameters::share_size()` = `1 + 2 * p_bytes`, `serialize_uncompressed()`.

**Issue:** Freeze implementers who compress shares will not match RFC 9383 vectors or Botan. Implementers who follow Botan will violate the freeze text.

**Consequence:** Swift/Python/Rust (or Full vs a second provider) fail key confirmation on every enrollment, or worse, one language “succeeds” against a non-Botan stack with a different encoding and a different TT.

**Attack/failure:** Commissioner Botan verifier rejects candidate compressed `shareP` (`deserialize_uncompressed` fails) → permanent enrollment failure. A custom compressed implementation that still derives keys internally is not wire-compatible.

**Remediation:** Freeze **uncompressed SEC1** (`0x04` ∥ X ∥ Y) for shareP, shareV, and RFC TT contents, matching Appendix C and Botan. State that M/N **constants** may be published compressed but **are uncompressed in TT**. Publish an ACP vector with hex shares.

**Normative ACP 1.2 change?** No (new extension).
**Tests:** RFC 9383 Appendix C `shareP`/`shareV` hex equality; Botan P-256 share length 65.

---

### AT-M0-002 — BLOCKER — Registration is not a byte contract

**Where:** `SECURITY.md` §3; RFC 9383 §3.2; Botan `derive_w0_w1` in `spake2p.cpp`; Botan FFI `botan_spake2p_derive_secret(..., const char * password, ...)`.

**Issue:** Freeze says ProverSecret from provider API with `identity = 16 raw bytes of candidate node_id`, custom SHA-256 salt, password = 16 raw bytes, context = enrollment CBOR. Botan uses Argon2id(m=64MiB,t=3,p=4) over `len(pw)||pw||len(idP)||idP||len(idV)||idV`, **both** identities, salt as Argon2 salt, and a **C string** password. Context is online-only. RFC 9383 requires the application to define `w0`/`w1` computation; delegating that to “the selected provider” is the opposite of a freeze.

**Consequence:** Two “RFC 9383 P-256-SHA256” implementations produce different `w0`/`L`. Enrollment fails closed if lucky, or Full cannot commission Lightweight at all. Secrets containing `0x00` truncate (~1/256).

**Attack/failure:** Python passes Crockford text as `str`; Rust FFI passes 16 raw bytes through `const char *` and truncates at NUL; Swift binding NUL-terminates. Three `w0` values. Candidate computes the record when printing the QR (commissioner unknown → empty `idVerifier`); commissioner computes after `begin` with its node ID in PBKDF. Attacker does not need a cryptanalytic break; operators cannot enroll.

**Remediation:** Specify, as ACP bytes, not “whatever Botan does unless we change providers”:

1. `idProver` = 16-byte RFC 4122 `candidate_node_id`
2. `idVerifier` = 16-byte RFC 4122 `commissioner_node_id`
3. `pw` = decoded 16-byte secret **or** ASCII digit bytes of the numeric code — **never** display Crockford, never `const char *`
4. PBKDF = Argon2id, RFC 9106 memory-constrained **or** a Lightweight-safe function **with a different suite ID**
5. Argon2 salt = the specified SHA-256 concat, with UUID encoding named
6. Output length ≥ 80 bytes, split in half, reduced mod n
7. Context is **only** RFC 9383 `Context` / Botan online `context`. Registration uses password, IDs, salt only.

Require `from_prehashed` if a provider’s default PBKDF differs. Pin Botan 3.13.0 **only after** ACP vectors match that pin. For 128-bit random secrets, HKDF-SHA-256 is enough and Pico-viable; if two KDFs are needed, they are two suite IDs.

**Normative ACP 1.2 change?** No.
**Tests:** Fixed secret/IDs/salt → fixed `w0`/`w1`/`L` hex in all three languages, independent of provider default APIs. Secrets with `00`, `ff`, and non-UTF-8 bytes. Same password/IDs/salt with two contexts → same `w0`, different `K_shared`.

---

### AT-M0-003 — BLOCKER — One suite ID for Full and Lightweight

**Where:** Suite `ACP-SPAKE2PLUS-P256-SHA256-HKDFSHA256-v1`; Botan Argon2id 64 MiB; Pico SRAM ~264 KiB; Matter SPAKE2+ typically PBKDF2.

**Issue:** RFC 9383 says PBKDF is not in the ciphersuite name **because it does not affect online share encoding**. It **does** affect whether Prover and Verifier share `w0`. ACP uses one suite ID across profiles.

**Consequence:** A Full commissioner using Botan cannot enroll a Pico candidate using Matter/Mbed under the advertised suite. Operators will “fix” it by weakening Full or inventing a silent second hash.

**Attack/failure:** Installer types the printed code into Conductor (Botan) against a Pico (PBKDF2). Confirmation fails. Installer switches the Pico to an unauthenticated fallback if product UX allows it — which current ACP `trusted_lan` behavior encourages.

**Remediation:** Either (a) one memory-bounded PBKDF for **all** profiles (Botan `from_prehashed`, not `from_password`), or (b) **two suite IDs** with no silent negotiation between them. Pico must not attempt 64 MiB Argon2id.

**Normative ACP 1.2 change?** No.
**Tests:** Cross-profile enrollment vectors; explicit `security.no_common_suite` when suites differ.

---

### AT-M0-004 — BLOCKER — Lightweight channel is a sketch

**Where:** `SECURITY.md` §10.

**Issue:** Steps 1–5 name a preface, RPK, and a “security-finished” exchange. There is no message type, MAC input, exporter label, or compact-credential canonical encoding. RPK is unproven on the target Mbed TLS config. The section itself says production freeze is blocked.

**Consequence:** M1/M5 implementers will invent a custom channel and ship it as “TLS 1.3.” That is the unaudited-crypto outcome the plan forbids.

**Attack/failure:** Preface replay of a valid compact credential plus a mismatched RPK should fail — if implementations check. Without a finished transcript, a stack that treats “TLS succeeded with some RPK” as authenticated ACP identity skips the credential bind. A successful TLS handshake becomes a principal (forbidden). Pico without a TRNG ships zeros into SPAKE2+ `x`/`y`.

**Remediation:** Remove Lightweight from Candidate Freeze 1 **or** specify the finished message and credential CBOR to the same standard as Full SPAKE2+ **and** prove RPK on hardware. Do not freeze “TLS 1.3 + RPK constants.”

**Normative ACP 1.2 change?** New profile only.
**Tests:** Mismatch preface vs RPK vs HELLO node_id; finished MAC failure; 0-RTT rejected; memory caps.

---

### AT-M0-005 — HIGH — Transcript split and confirmation naming

**Where:** `SECURITY.md` §4–5; Botan verifier `concat(share_v, confirm_v)`.

**Issue:** Application transcript needs five separate bstrs. Botan’s online messages are `shareP`, `shareV||confirmV`, `confirmP`. Freeze never assigns those to ACP `challenge`/`response`/`confirm`. HKDF labels are `client confirm` / `server confirm`.

**Consequence:** One SDK treats Botan’s 97-byte blob as `shareV`; another splits 65+32; a third puts confirmations in ACP HKDF MACs and calls `skip_confirmation`. Reflection/order bugs follow.

**Attack/failure:** Candidate acting as TLS server (common for headless nodes) uses “server_confirm” while commissioner also uses “server_confirm.” Both skip verifying the peer’s ACP MAC, then encrypt approval under a key the MITM does not have — enrollment fails — **or** if RFC confirmation was skipped, a MITM who injected shares proceeds.

**Remediation:** Name keys `prover_confirm` / `verifier_confirm` or `candidate_*` / `commissioner_*`. Map: challenge=`shareP` (65 bytes uncompressed); response=`shareV` (65) plus `confirmV` (32), never an underspecified concat unless the concat is the official opaque blob **and** the transcript still splits it. Forbid `skip_confirmation`. RFC confirmations remain mandatory; ACP MACs only protect later approval/install.

**Normative ACP 1.2 change?** No.
**Tests:** Reflection of confirmP as confirmV; swapped client/server labels fail; Botan concat round-trip.

---

### AT-M0-006 — HIGH — Identity public key unbound

**Where:** Design §12.3 challenge contains `candidate_identity_key`; `SECURITY.md` context/AAD omit it.

**Issue:** A MITM without the bootstrap secret cannot decrypt approval, so they cannot steal a usable credential. They **can** replace the challenge public key and force the commissioner to issue a cert for a key the candidate does not hold → failed PoP / DoS, and a commissioner that skips PoP (AT-M0-010) records a false enrollment.

**Remediation:** Put `identity_key_id` (and algorithm) in the SPAKE2+ context, application transcript, and approval AAD. Issue the credential only for that key. Require PoP of that key before Complete.

**Normative ACP 1.2 change?** No.
**Tests:** Mutate challenge SPKI after copies are taken; confirmation or approval must fail.

---

### AT-M0-007 — HIGH — Instance IDs not on the wire

**Where:** Context includes `candidate_instance_id`, `commissioner_instance_id`; `begin` example does not.

**Issue:** Both parties must hash the same context. Instance IDs change on boot. If each side fills its own and guesses the peer’s from unauthenticated discovery, a MITM substitutes discovery instance IDs and causes consistent **or** inconsistent transcripts (DoS vs binding failure).

**Remediation:** Put both instance IDs on `begin` and echo on `challenge`. Discovery hints are not authoritative. Context is computed after those fields are received, before `shareP`.

**Normative ACP 1.2 change?** No (new messages).
**Tests:** Mutate each instance_id; expect `security.transcript_mismatch`.

---

### AT-M0-008 — HIGH — Permission digest hashes an unspecified object

Empty map is specified. Any real permission request is not. Extra key order, absent vs null, unknown permissions, and integer widths will desynchronize SPAKE2+ without a visible protocol error until confirmation.

**Remediation:** Freeze a closed CBOR map (or hash a canonical empty map until M1 permission schema exists) and **forbid** hashing ad hoc JSON. Restate that requested permissions are a request; issued credential may only encode constraints; effective permissions are server-derived.

**Normative ACP 1.2 change?** No.

---

### AT-M0-009 — HIGH — Approval plaintext not closed

AAD list is almost enough to stop transplants **if** encoded identically. Plaintext is “fields required by design §12.4” — a bullet list, not CBOR keys. Nonce is 12 random bytes, one-use key: good AEAD hygiene. Unspecified: map vs array; UUID text vs bytes; `transcript_hash` as 32-byte bstr vs `sha256:` hex; ciphertext encoding.

**Remediation:** Closed map: key names, types, CDE rules, `additionalProperties: false`. State nonce is sent adjacent to ciphertext and is not reused. Empty AAD illegal. Keep generic `security.credential_invalid` on tag failure.

**Normative ACP 1.2 change?** No.
**Tests:** Golden ciphertext; transplant with wrong `attempt_id` in AAD.

---

### AT-M0-010 — HIGH — Install PoP unspecified

Without a specified signature input, a candidate can MAC `install_result` with the enrollment key and never prove the identity key. They cannot complete later mTLS, but the commissioner believes they enrolled and may publish policy for a key sitting in a staging slot that was rolled back.

**Remediation:** `install_result` carries a signature over `transcript_hash || credential_id` using the staged identity key, DER ECDSA, verified before Complete. No active credential without that check **and** read-back. Commissioner accepts install only once per `attempt_id`.

**Normative ACP 1.2 change?** No.

---

### AT-M0-011 — HIGH — X.509 roles and identity tuple

Authorization needs credential role constraints. Full-profile certs have none. Design identity tuple uses `credential_serial`; freeze uses `credential_id`. SDKs will key stores differently and fail rotation overlap.

**Remediation:** Add a critical custom extension or constrained EKU/policy OID for role constraints, **or** explicitly state Full-profile roles live only in local policy (then remove “credential role constraints” from the intersection for X.509). Unify the identity tuple on the freeze version. Freeze SPKI as RFC 5480 uncompressed P-256 in DER; compact `identity_public_key` = same SPKI bytes.

**Normative ACP 1.2 change?** No.

---

### AT-M0-012 — HIGH — SKI/AKI

“Required” without method. RFC 5280 SKI is SHA-1 of the SPKI bit string; some libraries hash SHA-256. Chain building will fail across SDKs.

**Remediation:** Name the method: either RFC 5280 4.2.1.2 method (1) SHA-1 of `subjectPublicKey` BIT STRING, or RFC 7093 SHA-256. AKI = keyIdentifier matching issuer SKI. Reject other methods in v1. Do not treat SKI SHA-1 as a forbidden “SHA-1 signature.”

**Normative ACP 1.2 change?** No.

---

### AT-M0-013 — HIGH — HELLO binding and SAN URI

Exporter label and 32-byte length are fine. Context hashing is not a closed semantic model. JSON peers that hash JSON bytes will never match CDE peers (already true: Python `json.dumps` is unsorted). Omit vs `null` vs empty bstr for `channel_binding` is unspecified.

Python/REMOTE.md identity is `acp://<uuid>`. Freeze URN includes trust domain. Shipping freeze certs **breaks** the only existing TLS bind.

**Remediation:** Closed HELLO subset for hashing (named fields, no extras). Always CDE, never JSON bytes. Explicit “key absent, not null.” Explicitly revise `REMOTE.md` SAN rule; implement extractors that require the URN and equal HELLO `node_id` **and** `trust_domain_id`. No CN fallback (already correct). Dual-accept window if `acp://` must remain during migration.

**Normative ACP 1.2 change?** **Yes** — `docs/REMOTE.md` TLS identity.
**Tests:** Valid cert/wrong node; both SAN forms; DNS-only cert; CN-only cert.

---

### AT-M0-014 — HIGH — Crockford encoding

16 bytes = 128 bits. Design example `A7KM-4QPF-9H2D-T6RX-3N8W-5CJV` is **24 chars = 120 bits**. Freeze forbids Crockford’s usual i/l→1, o→0 aliases except case-fold. No checksum policy, no padding-bit rule, no group size.

**Remediation:** Specify: no checksum; decode after removing ASCII hyphen/space; uppercase; alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`; 26-character encoding of 16 bytes with defined padding bits; display grouping is cosmetic. Vectors for encode/decode and rejection of ambiguous-character substitution.

**Normative ACP 1.2 change?** No.

---

### AT-M0-015 — HIGH — Pre-handshake legality

Enrollment messages are `malformed_envelope` on every current SDK before Established. Hardened mode cannot enroll on a “security-only” connection without a spec change. Using `trusted_lan` HELLO first recreates the downgrade the freeze forbids unless that session cannot receive show-control types.

**Remediation:** Explicit `STATE_MACHINES.md` + registry `legal_before_handshake` for `security.enrollment.*` **or** a dedicated enrollment port/profile whose admit() cannot reach control families. Restricted type allowlist, no application capabilities, no `AuthenticatedPrincipal`, no Remote control. Document it as a planned 1.2 additive revision.

**Normative ACP 1.2 change?** **Yes**.
**Tests:** Every non-enrollment type rejected in enrollment state; HELLO `trusted_lan` cannot authorize control; capability intersection empty except `security.enrollment`.

---

### AT-M0-016 — HIGH — Current stacks grant on claims; ignore peer auth

Not a freeze-math bug. It **is** why M5/M6 must not “add mTLS beside existing HELLO.” Concrete paths: claim `role: conductor` + overlapping default caps; strip Trust capability from ACK (Swift/Rust still establish); Rust `auth_mode="mutual_tls"` with no TLS; discovery `sec` omitted → plaintext.

**Remediation:** Treat as M2/M5/M6 invariants with tests: peer `auth.mode` must match evidence; missing Trust evidence in hardened mode → `security.downgrade_forbidden`; capabilities never grant; HELLO role never grants. Fix Rust `allow_plaintext` default to false before any Trust transport work.

**Normative ACP 1.2 change?** No, if non-Trust peers keep today’s behavior under explicit `allow_plaintext`.

---

### AT-M0-017 — MEDIUM — HKDF-Expand

Specify RFC 5869 Expand only: `info = UTF-8 label` with no NUL and no length prefix; `L = 32`; do not Extract again; forbid TLS HKDF-Expand-Label. Pin `K_shared` length 32. Pin a vector: fixed `K_shared` + `transcript_hash` → five keys. A negative vector using Expand-Label must not match.

**Normative ACP 1.2 change?** No.

---

### AT-M0-018 — MEDIUM — `skip_confirmation`

ACP profile: calling it is nonconforming except a future TLS-PAKE embedding that is not in v1. Approval and any `K_shared` use are illegal before both RFC MACs verify in constant time.

**Normative ACP 1.2 change?** No.
**Tests:** Missing/wrong/reflected `confirmP`/`confirmV`; no approval on the wire.

---

### AT-M0-019 — MEDIUM — Revocation encoding leftovers

Pin algorithm `ecdsa_p256_sha256`, strict DER, detached signature over body bstr, tag-0 timestamps, omit optional keys rather than `null`. Reject epoch ≠ expected+1 unless a full snapshot with epoch > local. Backups include revocation state; recovered authority must not sign a lower epoch.

**Normative ACP 1.2 change?** No.

---

### AT-M0-020 — MEDIUM — Compact credential encoding

`identity_public_key` = DER SPKI (same as Full key ID input). Critical extensions: explicit CBOR flag. `additionalProperties` false on the body.

**Normative ACP 1.2 change?** No.

---

### AT-M0-021 — MEDIUM — Codec bounds

Wire Lightweight limits into all three CBOR decoders before any Lightweight enrollment. Today 8 MiB / 1e6 items is a remote DoS even without Trust.

**Normative ACP 1.2 change?** No (enforcement of existing constants).

---

### AT-M0-022 — LOW — Design/freeze drift

Update design §7.2, §13.1, §14.1, §33 so implementers cannot follow the design instead of `SECURITY.md`. Keep SAS unadvertised; keeping `sas_key` in the schedule is fine for domain separation. Explicitly obsolete Ed25519, “length prefix or CBOR,” and SAS shipping for v1.

**Normative ACP 1.2 change?** No.

---

### AT-M0-023 — INFORMATIONAL — Headless enrollment limitation

Headless enrollment without a private bootstrap secret, local console, or prior identity cannot distinguish the device from a LAN impersonator. Do not claim otherwise in product copy.

---

### AT-M0-024 — INFORMATIONAL — Licenses pending owner approval

Botan Simplified BSD and Mbed TLS Apache-2.0 are technically compatible with many dual-license products. **Not owner-approved here.**

---

### AT-M0-025 — HIGH — Full-profile resumption / 0-RTT

**Where:** `SECURITY.md` §10 forbids 0-RTT and resumption only for Lightweight; §§8–9 do not.

**Issue:** Full-profile stacks that resume TLS can skip client-cert revalidation. A revoked node reconnects on a ticket.

**Remediation:** Forbid resumption and 0-RTT in v1 Full as well, or require full cert+revocation revalidation on resume. Isolate the ACP trust store; principal from ACP validator, not “TLS OK.”

**Normative ACP 1.2 change?** Transport policy, not envelope.
**Tests:** Ticket resume with revoked cert fails; 0-RTT rejected.

---

### AT-M0-026 — HIGH — `auth.mode=tls` is a downgrade

**Where:** `schema/common/defs.schema.json` `auth_mode` enum `trusted_lan|tls|mutual_tls`; freeze has no hardened-mode section.

**Issue:** Unilateral `tls` looks stronger than `trusted_lan` and is not mutual node authentication. Cert failure plus `allow_plaintext` is the other path.

**Remediation:** Normative hardened policy in `SECURITY.md`. Reject `tls` as an ACP principal in hardened mode. `trusted_lan` ⇒ `UnauthenticatedPrincipal` only. No automatic downgrade.

**Normative ACP 1.2 change?** Additive policy; default-auth documentation yes.

---

### AT-M0-027 — HIGH — Argon2id × concurrency is a memory DoS

**Where:** Design §27 concurrent Full enrollments = 8; Botan Argon2id 64 MiB.

**Issue:** Eight concurrent `begin` messages can cost 512 MiB. Lightweight “2 KiB preface” is the only numeric cap in the freeze.

**Attack/failure:** Flood `security.enrollment.begin`; candidate watchdog resets.

**Remediation:** Numeric caps in `SECURITY.md`; Lightweight concurrent attempts = 1; do not use 64 MiB Argon2id on device; cap revocation entries and snapshot bytes.

**Normative ACP 1.2 change?** No (limits may interact with `max_message_bytes`).

---

### AT-M0-028 — HIGH — PKIX defaults vs ACP revocation

**Where:** `SECURITY.md` §8, §11.

**Issue:** Freeze never says to ignore AIA/CRLDP/OCSP and use only ACP snapshots. Default OpenSSL/Apple verify will fail closed offline or fail open on the system store. A successful mTLS handshake with a **different trust domain’s** P-256 cert that the system store likes can become an ACP principal if adapters keep using OS verify.

**Remediation:** Isolated ACP trust store. Custom verify path: time, chain, SAN URI, EKU, KU, ACP revocation. Disable DNS-ID and OCSP for ACP principals.

**Normative ACP 1.2 change?** No.

---

### AT-M0-029 — MEDIUM — EKU, low-S, SKI-as-SHA-1

ACP nodes are usually both client and server; “EKU according to use” will be mis-issued. ECDSA “strict DER” without low-S leaves malleable signatures. SKI is often SHA-1 of the public key even when SHA-1 signatures are forbidden.

**Remediation:** Default both `clientAuth` and `serverAuth`. Require low-S. Name the SKI method (AT-M0-012) and do not treat it as a forbidden SHA-1 signature.

**Normative ACP 1.2 change?** No.

---

### AT-M0-030 — MEDIUM — Confirmation error oracle

Distinct `key_confirmation_failed` vs `transcript_mismatch` vs `credential_invalid` tells a LAN attacker “wrong password” versus “wrong context.”

**Remediation:** One generic external error for confirmation/transcript/tag failure; precise codes stay local and redacted.

**Normative ACP 1.2 change?** No (new error catalog, not frozen 1.2 messages).

---

### AT-M0-031 — MEDIUM — Clock stacking

Five-minute `notBefore` backdate plus two-minute tolerance is a seven-minute future-cert window. Numeric-code expiry is wall-clock, not monotonic. Pico enrollment that needs commissioner time to validate the credential it is about to install is circular.

**Attack/failure:** Set candidate clock back (or restore snapshot) to revive expired cert if checkpoint is not durable. Or roll clock forward to expire everyone.

**Remediation:** Numeric bounds; checkpoint contents and durability; enrollment uses monotonic attempt timers, not wall clock; credential validity evaluated only in `trusted_wall` or `authenticated_checkpoint`; never from discovery/HELLO.

**Normative ACP 1.2 change?** No.

---

## 20. Required remediation

Do **not** open M1 cryptography until Candidate Freeze 1 is amended and this review is re-run. Minimum amendment set:

1. Uncompressed P-256 shares; transcript split; forbid `skip_confirmation`.
2. Exact registration function, password as octet string, both identities, PBKDF parameters, context-not-in-PBKDF, or an explicit second suite for Lightweight. Never pass secrets through `const char *`.
3. Closed context map (`additionalProperties: false`), instance IDs on `begin`/`challenge`, `identity_key_id` in context/AAD, permission-digest schema or empty-only.
4. Closed approval plaintext; install PoP signature.
5. X.509 SKI/AKI method; both EKUs; low-S; role-constraint encoding or an explicit local-policy-only rule; SAN URI revision of `REMOTE.md`; isolated trust store; ACP-only revocation.
6. Closed HELLO subset for the exporter; CDE-only hashing; key absent not null.
7. Crockford encode/decode vectors (26 chars for 16 bytes).
8. Explicit pre-handshake enrollment legality.
9. Lightweight either specified to bytes **or** removed from the freeze.
10. Provider pin + RFC 9383 Appendix C **and** ACP registration vectors on every Full target.
11. Invariants tests for downgrade, peer `auth.mode`, `tls` rejected as principal, capabilities-are-not-grants, and Full-profile no-resumption.
12. Numeric enrollment/revocation/preface caps; no 64 MiB Argon2id on device; one generic external confirmation error.
13. Clock: monotonic attempt timers; stacked notBefore/tolerance bound; Pico enrollment not circular.

None of this is a reason to abandon SPAKE2+ / TLS 1.3 / local authorization. It is a reason not to encode the current text into three SDKs.

---

## 21. Remaining external / hardware evidence

**Pico (not performed, not claimed)**

Preserve: entropy source/quality; SPAKE2+ execution with the **amended** registration function; RAM high-water; flash footprint; RPK mutual authentication on the selected Mbed TLS config; transactional credential storage; power-loss recovery; handshake time; bounded concurrency. Desktop simulation does not satisfy these.

**Full-profile provider probes (not performed)**

RFC 9383 Appendix C; ACP vectors including NUL-containing secrets; AES-256-GCM; P-256 ECDSA strict DER + low-S; TLS 1.3 mTLS; exporter equality on macOS (Swift), iOS, Linux Swift, Python 3.11 Windows/macOS/Linux, Rust on macOS/Linux/Windows/Pi; peer certificate evidence APIs; no 0-RTT/resumption.

**Licensing**

Botan Simplified BSD and other licenses: technical notes only. **Project-owner approval pending.**

---

## 22. Final decision

# NO-GO

Candidate Freeze 1 must **not** be frozen.

The cryptographic *architecture* is not the problem. The freeze text is not a contract Swift, Python, and Rust can implement to identical bytes. The proposed Botan provider contradicts the freeze’s point encoding, truncates binary passwords at NUL, and cannot be the Lightweight registration function under the same suite ID. Lightweight’s authenticated channel is explicitly unfinished. Current ACP 1.2 stacks still treat HELLO roles and capability advertisements as grants and will silently stay on `trusted_lan` unless local fail-closed policy is tested into the SDKs.

CONDITIONAL GO would be appropriate **after** AT-M0-001 through AT-M0-016 and AT-M0-025 through AT-M0-028 are amended into `docs/SECURITY.md` (and the few frozen ACP docs that must change), with only provider probes, Pico HIL, and license approval left as bounded external evidence. That is not the present state.

GO would additionally require those probes to pass and no remaining HIGH findings.

This NO-GO is **not** a claim of formal cryptographic certification of any alternative, and it does **not** authorize M1.

Independent of Codex’s process gates (no reviewer artifact, no probes, no Pico HIL), **the document itself is not a freeze**. Do not start M1 schemas until `SECURITY.md` is amended so that a single Python reference encoder can emit one hex string per transcript field and Botan/Matter/pakery cannot legally disagree.
