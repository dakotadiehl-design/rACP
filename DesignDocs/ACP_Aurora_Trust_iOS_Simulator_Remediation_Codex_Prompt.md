# ACP Aurora Trust iOS Simulator Qualification Remediation Directive for Codex

## Purpose

Remediate the failed iOS Simulator qualification for Aurora Trust M0 without reopening Candidate Freeze 2.1.1 and without beginning M1.

The current iOS Simulator qualification produced strong positive evidence for the cryptographic/provider core but failed because:

1. Keychain testing returned `errSecMissingEntitlement`, indicating the current harness is not running in a properly entitled app/XCTest host.
2. Two WebSocket loopback tests consistently fail under the Simulator environment.
3. Full ACP X.509 policy and network-negative cases were not run because the production-intended iOS adapter path is not yet exercised by the qualification harness.

The task is to determine whether these are harness/environment issues or genuine ACP/iOS defects, fix what is fixable inside the ACP repository, and rerun the full iOS Simulator qualification.

Do not modify Candidate Freeze 2.1.1 unless the remediation proves a normative contradiction.

Do not begin M1.

---

## 1. Repository Boundary

Modify only the **AuroraCommunicationsProtocol** repository.

Do not modify Prism, Aurora Remote, Lyric, Conductor, Bridge, or any other Aurora-family repository.

Do not use an Aurora product app as the qualification host.

---

## 2. Preserve Existing Evidence

Do not discard or overwrite the existing failed qualification evidence.

Preserve the current report, machine-readable result, the 73/75 package-test result, the successful Botan 3.13.0 Simulator build, and all existing PASS evidence.

Create a new remediation qualification report/result rather than rewriting history.

---

## 3. Create an ACP-Only iOS Qualification Host

Create a minimal ACP-local iOS qualification app and/or XCTest host inside the ACP repository.

Requirements:

- No dependency on Aurora Remote.
- No product UI or business logic.
- Minimum entitlements only.
- Reuse existing security-probe logic rather than duplicating cryptographic logic.
- The same qualification tests should later run on a physical iPhone/iPad with minimal or no changes.

Prefer an ACP qualification host + XCTest target.

---

## 4. Keychain Remediation

Investigate `errSecMissingEntitlement` in the hosted environment.

Test at minimum:

- storing ACP identity metadata;
- storing/retrieving a Keychain-backed key or key reference as required by the current M0 scope;
- persistence across normal hosted test lifecycle where Simulator permits;
- deletion;
- duplicate-item behavior;
- item-not-found behavior;
- access-group behavior if applicable;
- incorrect-entitlement failure behavior;
- no private-key logging/export;
- transactional ACP metadata behavior around stored references where applicable.

Report separately:

```text
Keychain functional qualification in Simulator: PASS / FAIL
Secure Enclave hardware qualification: DEFERRED
```

Do not claim Secure Enclave qualification from Simulator.

---

## 5. WebSocket Loopback Failure Investigation

Investigate the two failing Simulator WebSocket loopback tests thoroughly.

For each failure:

1. Identify the exact assertion.
2. Capture the transport/session sequence.
3. Determine whether the cause is Simulator networking, IPv4/IPv6 behavior, local-network policy, TLS setup, WebSocket implementation, timing/race, host-vs-Simulator topology, ACP transport logic, or harness error.
4. Reproduce independently if possible.
5. Add focused diagnostics/tests.
6. Fix any ACP or harness defect.
7. Do not weaken the test merely to make it pass.

If self-loopback is invalid in Simulator but a host-peer topology is representative, use:

```text
Simulator client ↔ ACP-local host test server
```

and document why the topology change is correct.

---

## 6. Exercise the Production-Intended iOS Adapter Path

Where possible without beginning M1, qualify the actual provider/transport adapter path intended for Full-profile iOS sessions rather than test-only shortcuts.

Exercise the same:

- TLS provider path;
- peer-certificate evidence path;
- exporter/channel-binding path;
- X.509 validation path;
- error/failure path.

Do not implement later product/session architecture just to satisfy this task.

If only an M0 qualification adapter is appropriate, keep it isolated and document that boundary.

---

## 7. Full ACP X.509 Policy Cases

Run the previously `NOT_RUN` policy cases if the hosted adapter permits:

- valid ACP chain;
- wrong trust domain;
- wrong node ID;
- wrong SAN;
- CN-only rejection;
- wrong EKU;
- wrong Key Usage;
- CA:TRUE leaf rejection;
- invalid chain;
- expired certificate;
- future certificate;
- malformed certificate;
- revoked credential;
- stale/rolled-back revocation state;
- wrong credential/key ID where applicable;
- isolated ACP trust-store behavior.

Do not silently use the general Apple/system trust store as ACP identity authority.

---

## 8. Network-Negative Cases

Run as many as the hosted harness permits:

- missing client credential;
- wrong CA;
- wrong trust domain;
- wrong node identity;
- peer claims `mutual_tls` without valid transport evidence;
- stripped/missing Trust capability;
- attempted `trusted_lan` fallback;
- invalid HELLO channel binding;
- altered HELLO node ID after TLS authentication;
- exporter mismatch;
- revoked credential reconnect;
- 0-RTT attempt if testable;
- resumption/ticket behavior according to Freeze 2.1.1.

Authentication failure must never silently downgrade.

---

## 9. Re-run Existing Positive Probes

After remediation, rerun every previously passing Simulator probe:

- all 31 security-vector hashes;
- SPAKE2+;
- SHA-256;
- HMAC;
- HKDF;
- AEAD;
- P-256;
- TLS 1.3 mTLS;
- peer-certificate evidence;
- exporter equality;
- resumption/0-RTT policy;
- secret redaction.

Any regression returns the overall qualification to FAIL until fixed.

---

## 10. Result Classification

Use:

```text
PASS
FAIL
NOT_RUN
NOT_SUPPORTED
```

Overall Simulator qualification may be PASS only if every mandatory Simulator-applicable probe passes.

Report physical-device-only requirements separately:

```text
iOS physical-device Full-profile qualification: NOT RUN / DEFERRED
Secure Enclave hardware qualification: NOT RUN / DEFERRED
```

Do not report `iOS arm64: PASS` based solely on Simulator.

---

## 11. Code Review Gate

After the first remediation run, perform a thorough review for:

- unnecessary entitlements;
- product coupling;
- test-only shortcuts leaking into production;
- Keychain misuse;
- raw private-key export;
- macOS assumptions;
- Simulator-only hacks;
- IPv4/IPv6 assumptions;
- race conditions;
- WebSocket lifecycle bugs;
- TLS validation shortcuts;
- exporter workarounds inconsistent with Freeze 2.1.1;
- system-trust-store misuse;
- downgrade paths;
- weak negative tests;
- secret leakage;
- skipped/disabled tests;
- changes outside ACP.

Fix every issue found.

---

## 12. Regression Gate

After fixes:

1. Run the complete iOS Simulator qualification suite again.
2. Run the complete ACP host regression suite.
3. Include Python, Rust/doc tests, Swift, vector freshness, schema/registry checks, JSON/CBOR interop, WebSocket/framed interop, macOS arm64 provider probes, Rust 1.75 qualification, and `git diff --check`.
4. Fix any failure.
5. Run the complete regression set again.

Do not declare completion after a single green run.

---

## 13. Required Final Report

Produce a new M0 iOS Simulator remediation report containing:

### Environment
- Xcode version
- Swift version
- macOS host
- Simulator runtime
- simulated device
- Simulator architecture
- provider/version
- qualification-host target details

### Keychain
- entitlement configuration
- tests
- result
- limitations

### WebSocket failures
For each original failure:
- original failure
- root cause
- fix/topology correction
- evidence
- final result

### X.509 policy
- cases run
- results
- remaining NOT_RUN items

### Network negative cases
- cases run
- results
- remaining NOT_RUN items

### Positive probes
- vectors
- SPAKE2+
- HMAC/HKDF
- AEAD
- P-256
- mTLS
- peer evidence
- exporter
- resumption/0-RTT
- redaction

### Regression
- first qualification result
- code-review findings
- fixes
- second qualification result
- full host regression counts/results

### Final status

Return exactly one:

```text
iOS Simulator Full-profile functional qualification: PASS
```

or

```text
iOS Simulator Full-profile functional qualification: FAIL
```

Then separately:

```text
iOS physical-device Full-profile qualification: NOT RUN / DEFERRED
Secure Enclave hardware qualification: NOT RUN / DEFERRED
```

Finally list the exact remaining M0 blockers.

---

## 14. M0 / M1 Rule

Do not begin M1 as part of this remediation task.

Once the work is complete, report the new M0 evidence state.

The project owner will decide whether remaining physical-device/platform/HIL gates may be deferred for conditional M0 closure.

---

## 15. Final Instruction

Treat the current iOS Simulator FAIL as a qualification-harness problem to investigate, not as an excuse to weaken tests and not as proof that Freeze 2.1.1 is wrong.

Build a realistic ACP-only iOS hosted qualification environment, fix the harness, prove Keychain and transport behavior, run the negative cases, and return evidence.
