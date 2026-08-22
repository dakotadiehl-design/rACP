# ACP Aurora Trust iOS Simulator Qualification Directive for Codex

## Purpose

Run the maximum meaningful **iOS Simulator-based Aurora Trust Full-profile qualification** that can be performed before physical iPhone/iPad hardware testing.

This is an M0 evidence task.

The goal is to determine whether the ACP security provider, protocol vectors, TLS/mTLS behavior, peer-identity evidence, channel binding, Keychain-facing abstractions, and related Full-profile functionality behave correctly in an Xcode iOS Simulator environment.

This work must **not** be represented as final physical `iOS arm64` hardware qualification.

---

# 1. Repository Boundary

Modify only the **AuroraCommunicationsProtocol** repository.

Do not modify:

- Aurora Remote
- Prism
- Lyric
- Conductor
- Bridge
- Any other Aurora-family repository

Do not integrate ACP Trust into an application as part of this task.

---

# 2. Milestone Boundary

Remain in M0.

Do not begin M1 merely because the simulator qualification passes.

At the end of this task, report the evidence back to the existing M0 gate.

The expected distinction is:

```text
iOS Simulator Full-profile functional qualification: PASS / FAIL
iOS physical-device Full-profile qualification: NOT RUN / DEFERRED
Secure Enclave hardware qualification: NOT RUN / DEFERRED
```

Never convert a Simulator result into a physical-device PASS.

---

# 3. Qualification Target

Create or extend an **ACP-local iOS security qualification target/harness** that can run under Xcode Simulator.

Design the harness so the same tests can later run on a physical iPhone/iPad with minimal or no test-code changes.

Prefer a dedicated test/qualification target over modifying production APIs solely for testing.

Do not create a dependency on Aurora Remote.

The qualification harness should emit:

- normal Xcode test results; and
- a machine-readable ACP provider/adapter qualification report suitable for inclusion in M0 evidence.

---

# 4. Build Qualification

First prove that the selected ACP Full-profile security/provider stack can build for the intended iOS Simulator target.

Record:

- Xcode version.
- Swift version.
- Simulator runtime/version.
- Simulated device model.
- Simulator architecture.
- macOS host architecture.
- Botan/provider version.
- Provider build configuration.
- Linkage mode.
- Any iOS-specific build flags.
- Any APIs unavailable in Simulator.

Do not silently substitute a macOS provider build for an iOS Simulator build.

The binary/library being tested must actually target the iOS Simulator environment.

---

# 5. Security Golden Vectors

Run the checked-in Aurora Trust security-vector corpus in the iOS Simulator environment.

At minimum validate all provider-independent vectors applicable to Full profile:

- Bootstrap-secret encoding/decoding.
- UUID representations.
- Registration/KDF inputs.
- `w0`, `w1`, and `L`.
- SPAKE2+ shares.
- SPAKE2+ confirmations.
- Shared secret.
- ACP context.
- Permission digest.
- Transcript.
- Key schedule.
- Approval AEAD.
- Installation proof-of-possession.
- P-256/SPKI/key IDs.
- X.509 profile fixtures.
- HELLO/channel-binding provider-independent inputs.
- Revocation fixtures.
- Negative vectors.

All applicable vectors must produce the same expected bytes as the repository's normative security vectors.

Do not create iOS-specific expected cryptographic bytes.

---

# 6. Botan / Cryptographic Provider Probes

Run all Full-profile provider probes that are meaningful in Simulator.

At minimum:

## SPAKE2+

Verify:

- Exact ACP registration vectors.
- 65-byte/uncompressed P-256 shares if required by Freeze 2.1.1.
- `shareP`.
- `shareV`.
- `confirmV`.
- `confirmP`.
- Shared-key equality.
- Both confirmations required.
- Bad confirmation rejected.
- Wrong bootstrap secret rejected.
- NUL-containing bootstrap-secret fixture works exactly as ACP specifies.
- ACP does not depend on provider-specific C-string password semantics.
- Confirmation-skip functionality is not used by conformant ACP flow.

## Hash/HMAC/HKDF

Verify:

- SHA-256.
- HMAC-SHA256.
- Frozen HKDF behavior.
- Exact ACP derived-key vectors.

## AEAD

Verify the frozen AEAD behavior:

- Encrypt/decrypt.
- Fixed vector.
- AAD mismatch rejection.
- Tag mismatch rejection.
- Nonce validation.

## P-256

Verify:

- Key generation.
- Public-key extraction.
- SPKI representation.
- Sign.
- Verify.
- Strict DER behavior.
- Low-S behavior if required.
- Wrong-key rejection.
- Malformed-signature rejection.

---

# 7. X.509 Qualification

Run ACP Full-profile X.509 tests under Simulator.

At minimum verify:

- ACP CA/trust-domain handling.
- Leaf certificate parsing.
- ACP SAN URI extraction.
- Node-ID binding.
- Trust-domain binding.
- Key Usage.
- Extended Key Usage.
- Basic Constraints.
- SKI.
- AKI.
- Validity checks.
- Credential ID derivation.
- Wrong node rejection.
- Wrong trust domain rejection.
- Wrong EKU rejection.
- Expired credential rejection.
- Future credential rejection.
- Invalid chain rejection.
- Revoked credential behavior according to ACP's isolated revocation model.

Do not rely on the general Apple/system trust store to establish ACP identity if Freeze 2.1.1 requires an isolated ACP trust model.

---

# 8. TLS 1.3 Mutual Authentication

Exercise an actual TLS 1.3 mutual-authentication flow inside the qualification environment where Simulator networking permits it.

The test may use:

- Simulator ↔ host ACP test peer;
- Simulator ↔ local test server;
- another deterministic ACP-local test endpoint;

provided the peer is part of ACP qualification tooling and no Aurora product repository is modified.

Verify:

- TLS 1.3 is used.
- Both peers authenticate as required.
- Wrong CA fails.
- Wrong trust domain fails.
- Wrong node identity fails.
- Missing client credential fails.
- Invalid/expired/revoked credential fails as required.
- Successful TLS alone does not automatically create an ACP authenticated principal without the required ACP identity validation.
- Authentication failure never falls back to `trusted_lan` or plaintext.

---

# 9. Peer Evidence

Determine whether the actual iOS Simulator transport/API path exposes all peer evidence required by ACP.

At minimum determine whether ACP can obtain:

- peer certificate/credential evidence;
- peer leaf DER where required;
- SAN identity;
- trust-domain identity;
- credential/key IDs where required;
- TLS protocol/cipher information needed by qualification;
- verification result needed to construct an immutable `AuthenticatedPrincipal`.

Do not infer availability from documentation alone.

Exercise the actual API.

If any required evidence cannot be obtained, mark the corresponding probe FAIL or NOT_SUPPORTED and explain exactly why.

---

# 10. TLS Exporter / Channel Binding

This is a mandatory Full-profile question.

Attempt the exact Freeze 2.1.1 TLS exporter/channel-binding construction using the actual iOS Simulator transport/provider path.

Verify:

- exact exporter label;
- exact context;
- exact output length;
- both peers derive identical exporter output;
- HELLO channel binding matches;
- wrong HELLO context fails;
- changed node/trust-domain identity changes/fails the binding as required.

If the iOS transport stack does **not** expose the required TLS exporter, do not fabricate a workaround and do not mark this PASS.

Report the limitation precisely.

If an ACP-controlled TLS implementation/provider rather than Apple's high-level transport API is necessary to expose the exporter, document that result and test the intended production path where possible.

---

# 11. TLS Resumption / 0-RTT

Verify Freeze 2.1.1 policy.

If Full-profile v1 forbids these:

- prove 0-RTT is disabled/rejected;
- prove session resumption is disabled, or that the implementation forces all required ACP certificate/revocation validation again;
- prove a revoked credential cannot reconnect using a cached session/ticket.

If Simulator cannot faithfully exercise a specific behavior, mark it NOT_RUN and explain why.

---

# 12. Keychain Qualification

Exercise the ACP-facing Keychain storage abstraction in Simulator where meaningful.

Verify:

- create/store identity reference;
- retrieve identity reference;
- persistence across normal app/test lifecycle where Simulator permits;
- deletion;
- access-control behavior available in Simulator;
- no accidental private-key logging/export;
- credential metadata storage;
- transactional ACP storage logic around Keychain references where applicable.

Clearly distinguish:

```text
Keychain API functional behavior in Simulator
```

from:

```text
hardware-backed Secure Enclave behavior
```

The latter must remain NOT_RUN/DEFERRED.

---

# 13. Secure Enclave

Do not claim Secure Enclave qualification from Simulator.

If the ACP design will eventually use Secure Enclave-backed keys on iOS, record:

```text
Secure Enclave physical-device qualification: DEFERRED
```

Preserve future physical-device tests for:

- hardware-backed key creation;
- non-exportability;
- signing;
- key persistence;
- deletion/reset;
- device-lock/access-control behavior where applicable;
- ACP identity recovery behavior;
- performance.

Simulator fallback/software behavior is not equivalent evidence.

---

# 14. Discovery / Bonjour

Where meaningful in Simulator, test ACP discovery/Bonjour behavior relevant to Trust:

- security-mode advertisement;
- profile advertisement;
- service discovery;
- TXT parsing;
- spoofed discovery remains untrusted;
- discovery metadata never creates an authenticated principal;
- missing/modified security metadata cannot silently downgrade a hardened session.

Simulator networking limitations must be documented rather than hidden.

---

# 15. Negative Security Cases

Run as many of the following as Simulator supports:

- wrong bootstrap secret;
- wrong node ID;
- wrong trust domain;
- wrong role/permission claims;
- wrong SPAKE2+ confirmation;
- transcript mutation;
- replayed enrollment material where applicable to qualification tooling;
- malformed certificate;
- wrong SAN;
- wrong EKU;
- expired certificate;
- future certificate;
- revoked certificate;
- invalid HELLO binding;
- stripped Trust capability;
- claimed `mutual_tls` without transport evidence;
- attempted `trusted_lan` downgrade;
- malformed CBOR/JSON security objects;
- oversized inputs within the provider-probe scope.

Do not implement M1 enrollment state machines merely to run cases that do not yet exist. Keep this an M0 provider/adapter qualification task.

---

# 16. Secret Leakage Review

Capture test logs/output and inspect them for:

- bootstrap secrets;
- `w0`;
- `w1`;
- private keys;
- shared secrets;
- derived approval keys;
- TLS secret material;
- exporter secret material beyond deliberately synthetic expected test fixtures;
- decrypted approval payloads if marked sensitive;
- unredacted credential secrets.

The machine-readable qualification report must contain only safe diagnostic identifiers/hashes.

---

# 17. Result Classification

Produce a machine-readable iOS Simulator qualification result using the existing provider-probe schema if possible.

At minimum classify each item as:

```text
PASS
FAIL
NOT_RUN
NOT_SUPPORTED
```

Do not collapse `NOT_RUN` into PASS.

Overall Simulator qualification may be PASS only if every mandatory **Simulator-applicable** probe passes.

Physical-device-only requirements remain separately deferred.

---

# 18. Required Final Status

Report these separately:

```text
iOS Simulator Full-profile functional qualification:
    PASS / FAIL

iOS physical-device Full-profile qualification:
    NOT RUN / DEFERRED

Secure Enclave hardware qualification:
    NOT RUN / DEFERRED
```

Do not label the Simulator result simply:

```text
iOS arm64: PASS
```

because that would falsely imply physical-device qualification.

---

# 19. Regression Gate

After implementing/running the Simulator qualification:

1. Run all iOS Simulator qualification tests.
2. Run the complete ACP regression suite.
3. Perform a thorough code review.
4. Review specifically for:
   - platform-specific hacks;
   - provider divergence from golden vectors;
   - macOS assumptions leaking into iOS;
   - TLS identity shortcuts;
   - trust-store mistakes;
   - exporter workarounds that violate Freeze 2.1.1;
   - secret leakage;
   - accidental production-code scaffolding for later milestones;
   - changes outside ACP.
5. Fix every issue found.
6. Run Simulator qualification again.
7. Run the complete ACP regression suite again.

Do not proceed based on the first green test run alone.

---

# 20. M0 Decision After Simulator Testing

After the review/regression gate, update the M0 evidence and conformance matrix.

If Simulator qualification passes, record it accurately.

Do not conditionally close M0 automatically unless the current project-owner milestone policy permits the remaining physical-device and Pico HIL gates to be deferred.

Return the exact remaining blockers after this work.

Expected shape if successful:

```text
Candidate Freeze 2.1.1                 PASS
Independent review                     PASS
Security vectors                       PASS
Botan crypto profile                   PASS
macOS arm64                            PASS
iOS Simulator functional qualification PASS
Rust 1.75                              PASS
Owner provider approval                PASS

iOS physical-device qualification      DEFERRED / NOT RUN
Other untested Full platforms          NOT RUN / per current project scope
Pico Lightweight HIL                   DEFERRED
Lightweight production qualification   NOT QUALIFIED
```

---

# 21. Final Deliverable

Provide a concise report containing:

- Xcode version.
- Simulator runtime.
- simulated device.
- architecture.
- provider/version.
- build result.
- security-vector results.
- SPAKE2+ results.
- AEAD/HKDF/P-256 results.
- X.509 results.
- TLS 1.3 mTLS results.
- peer-evidence results.
- exporter/channel-binding results.
- 0-RTT/resumption results.
- Keychain results.
- Bonjour/discovery results.
- negative-security results.
- secret-leakage review.
- first regression result.
- code-review findings and fixes.
- second regression result.
- exact remaining M0 blockers.

Do not claim physical-device or Secure Enclave qualification.

---

# 22. Completion Rule

The goal is to answer one precise question:

> **Does the ACP Aurora Trust Full-profile implementation/provider contract function correctly in an Xcode iOS Simulator environment, to the maximum extent that Simulator can validly demonstrate?**

Answer that question with evidence.

Do not modify Aurora Remote to obtain the answer.

Do not begin M1 as part of this task.

Do not turn unavailable hardware evidence into a simulated PASS.
