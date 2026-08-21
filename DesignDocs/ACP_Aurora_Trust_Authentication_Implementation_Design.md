# Aurora Trust: ACP Authentication, Enrollment, and Credential Lifecycle

**Status:** Proposed implementation design  
**Target protocol:** Aurora Communications Protocol (ACP) 1.2 additive security extension  
**Target SDKs:** Swift, Python 3.11+, Rust 1.75+  
**Profiles:** Full and Lightweight  
**Audience:** Protocol maintainers, SDK implementers, product integrators, security reviewers, test engineers  
**Document intent:** Define a platform-independent, interoperable way to authenticate ACP nodes, enroll new nodes without requiring a physical button or display, authorize capabilities, and manage credentials throughout a node's lifecycle.

> **Implementation status (2026-08-20): design only.** No current ACP SDK
> implements this trust protocol. `trusted_lan` and `allow_plaintext` are
> explicit development/simulator modes and do not create an authenticated
> principal. Production Remote control must remain disabled until the relevant
> stages of this design are implemented and conformance-tested.

---

## 1. Executive summary

ACP 1.2 currently exposes authentication negotiation hooks but does not define a concrete authentication ceremony. `trusted_lan` identifies an operating assumption; it does not authenticate either endpoint. Discovery is informational and MUST NOT establish trust.

This design introduces **Aurora Trust**, an additive ACP security system with three distinct operations:

1. **Enrollment:** A new node and an authorized commissioner establish trust using a one-time bootstrap credential and a standardized password-authenticated key exchange.
2. **Authentication:** Enrolled nodes prove their persistent identities whenever they establish an ACP session.
3. **Authorization:** The accepting authority derives effective roles and capabilities from local policy bound to the authenticated identity. Self-advertised roles and capabilities never grant permission.

The design intentionally does not require:

- A physical pairing button.
- A display on both nodes.
- A camera or QR-code reader.
- Apple, Android, Windows, Linux, or vendor-specific key APIs.
- A cloud service or Internet connection.
- A hardware secure element.
- X.509 parsing on the smallest Lightweight implementations.

The same wire protocol can be implemented using CryptoKit or Security.framework on Apple platforms, OpenSSL or another audited provider on Linux and Windows, Java/Android Keystore on Android, and an embedded cryptographic/TLS provider on Raspberry Pi Pico-class devices. Platform-specific key storage is hidden behind a common SDK abstraction.

The recommended cryptographic construction is:

- SPAKE2+ for human- or installer-mediated bootstrap enrollment.
- SHA-256 and HKDF-SHA-256 for transcript hashing and derivation.
- TLS 1.3 for ordinary full-profile WebSocket sessions.
- Mutual node authentication using production-local credentials.
- P-256 ECDSA as the mandatory-to-implement identity/signature suite for broad platform compatibility.
- Ed25519 as an optional negotiated suite.
- A compact signed credential and pinned trust-domain key for constrained Lightweight nodes when full X.509 processing is impractical.

No ACP implementation may substitute an unauthenticated hash exchange, plaintext PIN, home-grown key agreement, or unauthenticated Diffie-Hellman for the mechanisms described here.

---

## 2. Relationship to existing ACP contracts

This document extends, rather than replaces, the existing ACP 1.2 contracts:

- `docs/WIRE_ENCODING.md` remains authoritative for JSON, deterministic CBOR, UUIDs, timestamps, and framing.
- `docs/STATE_MACHINES.md` remains authoritative for ACP version negotiation, connection sequencing, QoS, correlation, and idempotency.
- `schema/session/messages.schema.json` remains the schema location for HELLO and HELLO_ACK.
- `Sources/AuroraACP/Session/registry.json` remains a generated/runtime message-registry artifact.
- Discovery remains unauthenticated metadata. It may advertise enrollment availability and supported security modes, but never secrets or grants.
- Capability negotiation remains a compatibility mechanism. It does not grant authorization.
- ACP command acknowledgements remain dispositions, not authoritative operational state.

Aurora Trust should be introduced as an additive ACP 1.2 capability. Peers that do not negotiate it continue to use existing behavior according to deployment policy. A hardened deployment MUST be able to prohibit `trusted_lan` rather than silently downgrade to it.

Recommended capability identifiers:

| Capability | Version | Purpose |
|---|---:|---|
| `security.enrollment` | `1.0` | Enrollment state and SPAKE2+ ceremony |
| `security.identity` | `1.0` | Persistent ACP node identity |
| `security.mutual_tls` | `1.0` | Full-profile TLS 1.3 mutual authentication |
| `security.compact_credential` | `1.0` | Lightweight signed credential profile |
| `security.credential_rotation` | `1.0` | Credential renewal and key rotation |
| `security.revocation` | `1.0` | Revocation status and administrative revocation |
| `security.audit` | `1.0` | Structured security lifecycle events |
| `security.visual_fingerprint` | `1.0` | Optional human-verifiable short authentication string |

---

## 3. Design goals

### 3.1 Required goals

The implementation MUST:

1. Authenticate node identities independently of discovery metadata.
2. Work entirely on a private LAN with no Internet dependency.
3. Support headless and buttonless nodes.
4. Support full computers, Raspberry Pi-class systems, and constrained microcontrollers.
5. Use standard, reviewed cryptographic protocols and algorithms.
6. Prevent passive observers from learning reusable enrollment secrets.
7. Prevent offline guessing of short enrollment codes from recorded traffic.
8. Bind the enrolled identity to the exact ACP node ID, role constraints, trust domain, and key.
9. Separate authentication from authorization.
10. Prevent capability self-claims from becoming grants.
11. Fail closed on ambiguous identity, transcript, credential, or policy state.
12. Support credential expiration, renewal, rotation, revocation, reset, and audit.
13. Permit platform-native secure storage without making it mandatory.
14. Produce cross-language golden vectors and live interoperability tests.
15. Keep secrets out of discovery, logs, PCAP fixtures, diagnostics, and error text.

### 3.2 Usability goals

The implementation SHOULD:

- Provide QR scanning when a camera and visible code are available.
- Always provide an equivalent textual or file-based enrollment path.
- Allow enrollment through local UI, local web UI, CLI, serial console, configuration package, or an existing authenticated ACP administrator.
- Produce clear operator-visible identity, role, trust-domain, permission, and expiration information.
- Provide an optional word/color/shape fingerprint on nodes capable of displaying one.
- Make insecure `trusted_lan` sessions visually distinguishable from authenticated sessions.
- Support scripted fleet provisioning without weakening individual node identity.

### 3.3 Explicit non-goals

The first version does not attempt to provide:

- Global public Internet PKI.
- Manufacturer cloud enrollment.
- Remote attestation as a mandatory requirement.
- Byzantine consensus between multiple commissioners.
- A replacement for operating-system account authentication.
- Automatic authorization based solely on product role.
- Secret distribution through multicast discovery.
- A universal platform keystore implementation.

---

## 4. Terminology and roles

| Term | Meaning |
|---|---|
| **Node** | Any ACP participant with a stable `node_id` and current `instance_id`. |
| **Candidate** | A node that has not yet joined the target trust domain. |
| **Commissioner** | An authenticated authority permitted to enroll nodes and issue or approve credentials. Often Conductor, but not protocol-hard-coded to that product. |
| **Trust domain** | A locally administered Aurora security realm, such as one production, venue, or organization. |
| **Trust-domain authority** | Key and policy authority that signs node credentials. It may reside in Conductor, a dedicated tool, or managed infrastructure. |
| **Bootstrap credential** | A one-time secret or manufacturer/installer credential used only to establish initial trust. |
| **Enrollment session** | A short-lived, capability-restricted session used to claim and authorize a candidate. |
| **Node identity key** | Persistent asymmetric private key controlled by the node. |
| **Node credential** | Signed binding of node identity, trust domain, public key, validity, role constraints, and policy metadata. |
| **Principal** | The authenticated identity passed from transport/session security into authorization policy. |
| **Effective permissions** | Server-derived permissions for a principal. They are never copied from client claims. |
| **SAS** | Short authentication string used for optional visual comparison. |
| **Full profile** | TLS 1.3 and full certificate-capable implementation. |
| **Lightweight profile** | Constrained implementation using bounded memory and potentially compact credentials. |

The commissioner is a security role, not necessarily the ACP `conductor` product role. A tool may commission nodes. A Conductor instance without the applicable administrative credential may not.

---

## 5. Threat model

### 5.1 Adversary capabilities

Assume an attacker may:

- Join or monitor the show LAN.
- Send forged discovery advertisements.
- Open connections to ACP endpoints.
- Record, delay, replay, reorder, or modify enrollment traffic.
- Race the legitimate commissioner during enrollment.
- Guess short human-entered codes online.
- Present a valid-looking node name or copied `node_id`.
- Steal a node credential file from weak storage.
- Compromise an enrolled node and use its granted permissions.
- Restore an old filesystem or firmware image.
- Cause abrupt power loss during credential writes.

### 5.2 Security properties

Aurora Trust is designed to provide:

- Mutual proof that enrollment participants possess the same bootstrap secret.
- Fresh session keys for each enrollment.
- Transcript integrity and explicit key confirmation.
- Persistent identity authentication after enrollment.
- Confidentiality and integrity for normal ACP sessions.
- Protection against replay across sessions, nodes, trust domains, and protocol versions.
- Explicit, local authorization policy.
- Revocation and bounded credential lifetime.
- Atomic credential installation and rollback-safe persistence.

### 5.3 Inherent limitation of buttonless/headless enrollment

Secure first enrollment requires at least one trust anchor unavailable to an arbitrary LAN attacker. That anchor may be:

- A one-time random code printed on the node or packaging.
- A provisioning file delivered through a separate administrative channel.
- A local console or filesystem accessible to the installer.
- A manufacturer-installed device identity.
- An existing trusted administrator credential.

If a node has no physical control, no display, no private bootstrap credential, no local administrative channel, and no previously trusted identity, the commissioner cannot cryptographically distinguish it from an impersonator on the LAN. ACP MUST NOT claim secure enrollment in that configuration.

### 5.4 Threats outside the protocol boundary

Aurora Trust cannot protect a fully compromised endpoint, malicious firmware, stolen unlocked administrator session, exposed private key, or intentionally permissive authorization policy. Implementations must report storage posture and support revocation so operators can manage those risks.

---

## 6. Security architecture

Aurora Trust consists of six layers:

```text
Administrative UX / CLI / provisioning file
                  |
Enrollment policy and approval
                  |
SPAKE2+ enrollment state machine
                  |
Identity key + signed credential lifecycle
                  |
TLS 1.3 or compact authenticated channel
                  |
ACP HELLO, authenticated principal, authorization policy
```

Each layer has a narrow responsibility:

- The onboarding channel transports public metadata and bootstrap material to an authorized operator.
- SPAKE2+ proves shared bootstrap-secret possession and derives enrollment keys.
- The commissioner approves identity attributes and permissions.
- The trust-domain authority signs a persistent credential.
- The normal secure transport proves possession of the credential's private key.
- ACP session code binds the authenticated principal to HELLO identity and enforces policy.

No layer may infer the result of a later layer. Successful SPAKE2+ does not itself grant show-control permission. A valid certificate does not automatically grant every advertised capability.

---

## 7. Cryptographic profiles

### 7.1 General rule

Protocol code MUST call a narrow cryptographic-provider interface. It MUST NOT contain original implementations of elliptic-curve arithmetic, TLS, AEAD, or certificate parsing.

Libraries/providers must be independently reviewed for each supported platform. Algorithm availability must be verified in CI and on target hardware before a suite is declared mandatory for a product profile.

### 7.2 Mandatory base primitives

| Purpose | Mandatory algorithm |
|---|---|
| Transcript hash | SHA-256 |
| Key derivation | HKDF-SHA-256 |
| Enrollment PAKE | SPAKE2+ using the ACP-defined suite |
| Identity signature | ECDSA P-256 with SHA-256 |
| Random generation | Platform CSPRNG, minimum 128 bits for bootstrap secrets |
| Full transport | TLS 1.3 |
| Full transport AEAD | TLS-negotiated AES-GCM or ChaCha20-Poly1305 |

Ed25519 MAY be implemented as `identity.ed25519`. X25519 MAY be used by future negotiated suites. Optional algorithms may not change the mandatory suite's transcript format.

### 7.3 SPAKE2+ suite identifier

The initial suite identifier SHOULD be:

```text
ACP-SPAKE2PLUS-P256-SHA256-HKDFSHA256-v1
```

The exact SPAKE2+ ciphersuite parameters, point encoding, password-to-scalar preparation, confirmation MAC construction, and test vectors MUST be copied from or rigorously mapped to the selected standards-compliant library profile. This document does not authorize implementers to fill in missing cryptographic math from intuition.

SPAKE2+ is standardized in [RFC 9383](https://www.rfc-editor.org/rfc/rfc9383.html). TLS 1.3 behavior is standardized in [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html).

### 7.4 Algorithm negotiation

Enrollment advertisements list supported suite identifiers. The commissioner selects exactly one suite. Selection is included in the SPAKE2+ context and transcript.

Rules:

1. Suites are ordered local preferences, not numeric security rankings.
2. The selected suite must appear in both advertised sets.
3. No intersection fails with `security.no_common_suite`.
4. The candidate must reject a suite not present in its original offer.
5. Downgrade to `trusted_lan` is never an automatic negotiation result.
6. Unknown optional suites are ignored.
7. Disabled/deprecated suites remain rejected even if a peer advertises them.

### 7.5 Randomness

All nonces, keys, tokens, and bootstrap secrets MUST use the operating system or embedded platform's cryptographically secure random generator. `rand()`, timestamps, UUID text, MAC addresses, serial numbers, and PRNGs seeded only at boot are forbidden.

On constrained devices, failure to initialize the CSPRNG is a fatal security fault. The device may continue safe local operation but MUST NOT open enrollment or authenticated ACP control.

---

## 8. Trust-domain model

Each Aurora installation creates or imports a trust domain:

```json
{
  "trust_domain_id": "3e414666-724e-4ab0-98c7-f7af0cbcf173",
  "name": "Haywire Production",
  "authority_key_id": "sha256:...",
  "created_at": "2026-08-20T16:00:00.000Z",
  "policy_revision": 1
}
```

`trust_domain_id` is a random UUID. It is not derived from a human-readable show or organization name. Renaming the trust domain does not change its identity.

The authority signing key SHOULD be non-exportable when platform support exists. Backup and recovery are deployment concerns but must be explicit. Copying a trust-domain authority key into every node is forbidden.

A node may support membership in multiple trust domains if its product requires it, but each membership has distinct credentials, policy, revocation state, and key identifiers. Lightweight nodes MAY support exactly one trust domain.

---

## 9. Bootstrap credential formats

### 9.1 High-entropy enrollment secret

The preferred bootstrap secret is 128 uniformly random bits. Human formatting may add separators but does not alter the entropy.

Example display form:

```text
A7KM-4QPF-9H2D-T6RX-3N8W-5CJV
```

The encoded alphabet SHOULD omit visually ambiguous characters. The decoder may accept lowercase and separators but must normalize deterministically before PAKE input preparation.

### 9.2 Manual short code

A short numeric code is a fallback only. It MUST:

- Contain at least eight decimal digits unless a stronger word-list format is used.
- Expire within ten minutes by default.
- Permit at most five failed attempts per enrollment identifier.
- Trigger a fresh identifier and secret after lockout.
- Be processed only through SPAKE2+.
- Never be sent, hashed alone, or logged.

The protocol cannot prevent denial of service from deliberate lockouts. The node should retain safe local operation while enrollment is locked.

### 9.3 Enrollment URI

The canonical QR/text URI SHOULD be:

```text
aurora-enroll://v1/BASE64URL-CBOR
```

The CBOR body contains:

```json
{
  "version": 1,
  "enrollment_id": "UUID",
  "node_id": "UUID",
  "bootstrap_secret": "base64url-no-padding",
  "identity_key_hash": "sha256:lowercase-hex",
  "expires_at": "RFC3339 timestamp",
  "suite_hint": "ACP-SPAKE2PLUS-P256-SHA256-HKDFSHA256-v1"
}
```

The URI is confidential bootstrap material. It MUST NOT be placed in discovery, telemetry, crash reports, analytics, or ordinary ACP logs.

### 9.4 Signed enrollment package

Managed or headless installation may use a file with extension `.aurora-enroll`. The package is deterministic CBOR containing:

- Package version.
- Enrollment ID.
- Trust-domain public identity.
- Candidate node constraint or wildcard policy.
- Expiration.
- Requested role constraints.
- Maximum grantable permissions.
- One-time PAKE material or protected reference.
- Commissioner signature.

The package transport does not need confidentiality if it contains no reusable plaintext secret. If it embeds a bootstrap secret, it must be treated as secret material and delivered through an appropriate administrative channel.

Importing a package never silently completes enrollment. The candidate still validates expiry, signature, node constraint, replay state, and key confirmation.

---

## 10. Enrollment activation without mandatory hardware controls

ACP defines intent and state, not a universal local-control mechanism. Products may expose any of these activation methods:

- Automatic first-boot enrollment window.
- Local GUI action.
- Local web-admin action.
- CLI command.
- Configuration file or environment-specific launch setting.
- USB/serial administrative command.
- Signed enrollment package.
- Command from an already authenticated administrator.

Example local configuration:

```toml
[acp.security.enrollment]
mode = "open_once"
window_ms = 600000
max_attempts = 5
allow_manual_code = true
```

Example CLI:

```text
acp security enrollment open --duration 10m
acp security enrollment status
acp security enrollment close
```

Opening enrollment through an ACP message requires an already authenticated principal with `security.enrollment.manage`. An unauthenticated peer may query only public enrollment status and may not open, extend, reset, or reconfigure enrollment.

---

## 11. Enrollment state machine

### 11.1 Candidate state

```text
Unenrolled
  -> EnrollmentOpen
  -> Negotiating
  -> KeyConfirmed
  -> AwaitingApproval
  -> CredentialStaged
  -> Enrolled

Any nonterminal state
  -> Cancelled
  -> Expired
  -> Locked
  -> Failed
```

### 11.2 Commissioner state

```text
Idle
  -> CandidateSelected
  -> SecretAcquired
  -> Negotiating
  -> KeyConfirmed
  -> AwaitingOperatorApproval
  -> IssuingCredential
  -> AwaitingInstallReceipt
  -> Complete
```

### 11.3 State rules

- Enrollment state is keyed by `enrollment_id`, not by IP address or display name.
- A candidate allows only a small bounded number of concurrent negotiations; Lightweight default is one.
- Every transition has a monotonic local deadline.
- Wall-clock timestamps are recorded for audit but not used alone to enforce short handshake timeouts.
- Restart invalidates ephemeral PAKE state unless the device explicitly implements secure resumption.
- A used or failed one-time bootstrap secret is rotated according to policy.
- Credential installation is atomic: active credential, trust anchor, policy reference, and replay marker commit together.
- The candidate sends installation success only after durable commit and read-back validation.
- Failure leaves the previous valid trust configuration intact.

---

## 12. Enrollment message family

The following messages are proposed. They are ACP envelopes using existing encoding and QoS rules.

| Message | Direction | QoS | Purpose |
|---|---|---|---|
| `security.enrollment.status` | Candidate -> observer | `latest` | Public, nonsecret enrollment availability |
| `security.enrollment.begin` | Commissioner -> candidate | `reliable` | Select suite and begin a bounded attempt |
| `security.enrollment.challenge` | Candidate -> commissioner | `reliable` | Candidate PAKE value and nonce |
| `security.enrollment.response` | Commissioner -> candidate | `reliable` | Commissioner PAKE value and confirmation |
| `security.enrollment.confirm` | Candidate -> commissioner | `reliable` | Candidate key confirmation and identity request |
| `security.enrollment.approval` | Commissioner -> candidate | `reliable` | Approved attributes and encrypted credential offer |
| `security.enrollment.install_result` | Candidate -> commissioner | `reliable` | Durable installation result |
| `security.enrollment.cancel` | Either | `reliable` | Explicit termination |
| `security.credential.renew` | Node -> authority | `reliable` | Request credential renewal or key rotation |
| `security.credential.result` | Authority -> node | `reliable` | Renewal/rotation result |
| `security.credential.revoke` | Admin -> authority | `reliable` | Administrative revocation request |
| `security.credential.status` | Authority -> peer | `reliable` | Credential validity/revocation information |

Enrollment messages MUST be added to the language-neutral schema, message registry, capability catalog, error catalog, JSON/CBOR vectors, all three SDK model registries, Wireshark dissector, and inspector.

### 12.1 Public enrollment status

```json
{
  "type": "security.enrollment.status",
  "qos": "latest",
  "payload": {
    "enrollment_id": "UUID",
    "state": "open",
    "expires_at": "2026-08-20T16:10:00.000Z",
    "supported_suites": [
      "ACP-SPAKE2PLUS-P256-SHA256-HKDFSHA256-v1"
    ],
    "methods": ["manual_code", "qr", "provisioning_file"],
    "attempts_remaining": 5
  }
}
```

This message never includes the bootstrap secret, visual fingerprint, private key, credential body, or permissions grant.

### 12.2 Begin

```json
{
  "type": "security.enrollment.begin",
  "qos": "reliable",
  "flags": ["ack_required"],
  "payload": {
    "enrollment_id": "UUID",
    "attempt_id": "UUID",
    "commissioner_node_id": "UUID",
    "trust_domain_id": "UUID",
    "suite": "ACP-SPAKE2PLUS-P256-SHA256-HKDFSHA256-v1",
    "commissioner_nonce": "base64url",
    "requested_role": "bridge",
    "requested_permissions_digest": "sha256:..."
  }
}
```

The requested role and permissions digest are transcript-bound. The full permission request is transmitted only inside the protected phase or validated against the digest before approval.

### 12.3 Challenge and response

The PAKE messages contain opaque, suite-defined byte strings. Their internal points or scalars are not decomposed into generic ACP numeric fields.

```json
{
  "attempt_id": "UUID",
  "candidate_nonce": "base64url",
  "pake_message": "base64url",
  "candidate_identity_key": {
    "algorithm": "ecdsa_p256_sha256",
    "public_key": "base64url-subject-public-key-info"
  }
}
```

JSON encodes cryptographic bytes with unpadded base64url. CBOR uses byte strings. Semantic equality tests normalize the representation before comparison.

### 12.4 Protected approval

After explicit key confirmation, the commissioner sends an AEAD-protected approval payload derived from the enrollment shared secret. It contains:

- Trust-domain metadata.
- Issued node credential.
- Trust anchor or authority-key reference.
- Approved role constraints.
- Policy identifier and revision.
- Credential validity.
- Rotation deadline.
- Commissioner identity.
- Transcript hash.

Associated data includes message type, attempt ID, enrollment ID, candidate node ID, commissioner node ID, trust-domain ID, and protocol/suite versions.

### 12.5 Installation result

```json
{
  "attempt_id": "UUID",
  "status": "installed",
  "credential_id": "sha256:...",
  "identity_key_id": "sha256:...",
  "trust_domain_id": "UUID",
  "storage_posture": {
    "class": "os_protected",
    "hardware_backed": false,
    "private_key_exportable": false
  }
}
```

The result is authenticated using an enrollment-derived confirmation key and proves possession of the newly installed identity private key.

---

## 13. Transcript construction and channel binding

All three SDKs MUST construct byte-identical transcript hashes.

### 13.1 Context

The SPAKE2+ context is deterministic CBOR under ACP-CDE-1.2 containing:

```json
{
  "application": "Aurora Communications Protocol",
  "purpose": "security.enrollment",
  "extension_version": "1.0",
  "acp_version": "1.2",
  "suite": "...",
  "enrollment_id": "UUID",
  "attempt_id": "UUID",
  "candidate_node_id": "UUID",
  "candidate_instance_id": "UUID",
  "commissioner_node_id": "UUID",
  "commissioner_instance_id": "UUID",
  "trust_domain_id": "UUID",
  "requested_role": "bridge",
  "requested_permissions_digest": "sha256:..."
}
```

The transcript hash covers the context and every PAKE message in protocol order with explicit length prefixes or deterministic CBOR array framing. Concatenating ambiguous strings is forbidden.

### 13.2 Derived keys

The PAKE output is never used directly. HKDF derives independent keys:

```text
enrollment_root = HKDF-Extract(salt = transcript_hash, IKM = pake_shared_secret)

client_confirm = HKDF-Expand(enrollment_root, "ACP enrollment client confirm v1", 32)
server_confirm = HKDF-Expand(enrollment_root, "ACP enrollment server confirm v1", 32)
approval_key   = HKDF-Expand(enrollment_root, "ACP enrollment approval AEAD v1", 32)
sas_key        = HKDF-Expand(enrollment_root, "ACP enrollment SAS v1", 32)
audit_key      = HKDF-Expand(enrollment_root, "ACP enrollment audit binding v1", 32)
```

Exact labels, capitalization, encoding, and lengths are normative and must be frozen in vectors before implementation release.

### 13.3 Optional visual fingerprint

The SAS is derived from `HMAC-SHA256(sas_key, transcript_hash)`. The first sufficient number of unbiased bits maps to a versioned word list, color palette, and shape table.

The SAS is optional UX. Key confirmation is mandatory cryptography. A node without a display completes enrollment normally after commissioner approval and cryptographic confirmation.

The word list and mapping tables must be versioned assets shared by all SDKs. Localized display text may accompany the canonical words but cannot replace them during comparison.

---

## 14. Persistent identity and credential format

### 14.1 Stable identity

The persistent identity tuple is:

```text
(trust_domain_id, node_id, identity_public_key, credential_serial)
```

`instance_id` is intentionally excluded because it changes on boot.

The candidate generates its identity key locally before or during enrollment. The commissioner never generates or receives the candidate private key.

### 14.2 Full-profile credential

Full-profile implementations SHOULD use a short, locally issued X.509 chain suitable for mutual TLS:

- Trust-domain root or constrained intermediate.
- Node end-entity certificate.
- `digitalSignature` key usage.
- Client and/or server authentication extended key usage as required.
- SAN binding for ACP node identity using a defined URI form.
- Short bounded validity, recommended 30 to 90 days with automatic renewal.
- Certificate serial and authority key identifier.

Recommended SAN URI:

```text
urn:aurora:acp:node:<trust-domain-uuid>:<node-uuid>
```

The Common Name must not be used as the authenticated node identity. Service identity practices should follow [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525.html) where applicable.

### 14.3 Compact Lightweight credential

A Lightweight credential is a deterministic CBOR structure signed by the trust-domain authority:

```json
{
  "format": "acp-compact-credential-v1",
  "serial": 42,
  "trust_domain_id": "UUID",
  "node_id": "UUID",
  "identity_algorithm": "ecdsa_p256_sha256",
  "identity_public_key": "bytes",
  "role_constraints": ["bridge"],
  "permission_policy_id": "bridge-stage-left",
  "issued_at": "RFC3339",
  "not_before": "RFC3339",
  "expires_at": "RFC3339",
  "issuer_key_id": "sha256:...",
  "extensions": {}
}
```

The signature covers deterministic CBOR bytes of the credential body. Unknown critical extensions cause rejection. Unknown optional extensions are ignored.

The compact format is not permission to invent a custom unauthenticated transport. The Lightweight transport must still provide confidentiality, integrity, replay protection, peer authentication, and transcript binding. The exact embedded TLS/raw-public-key integration must be proven against target stacks before final wire freeze.

### 14.4 Credential status

Credential validation checks:

1. Supported format and signature algorithm.
2. Valid trust-domain authority chain or pinned authority key.
3. Signature validity.
4. Trust-domain match.
5. Current validity interval with defined clock policy.
6. Revocation status or locally cached revocation epoch.
7. Role constraint compatibility.
8. Proof of corresponding private-key possession.
9. HELLO `node_id` equality.
10. Local policy acceptance.

Failure at any step prevents an established authenticated ACP session.

---

## 15. Normal authenticated session establishment

### 15.1 Full-profile flow

```text
Client                                  Server
  |---- TLS 1.3 ClientHello ------------->|
  |<--- Server certificate + proof --------|
  |---- Client certificate + proof -------->|
  |<=========== encrypted channel =========>|
  |---- session.hello auth=mutual_tls ----->|
  |<--- session.hello_ack + binding --------|
  |<========== established ACP ============>|
```

Before accepting HELLO, transport code exposes an `AuthenticatedPrincipal` derived from the verified peer credential. Session code then validates that HELLO's source and node identity match that principal.

### 15.2 HELLO extension

```json
{
  "auth": {
    "mode": "mutual_tls",
    "trust_domain_id": "UUID",
    "credential_id": "sha256:...",
    "identity_key_id": "sha256:...",
    "channel_binding": "base64url",
    "security_capabilities": [
      {"id": "security.identity", "version": "1.0"},
      {"id": "security.credential_rotation", "version": "1.0"}
    ]
  }
}
```

`channel_binding` is derived from the authenticated transport and the canonical HELLO payload. For TLS 1.3, use a TLS exporter with an ACP-specific label where the selected platform exposes a correct exporter API. The exact exporter context and fallback policy must be specified and tested before marking channel binding mandatory on a platform.

TLS exporter construction is defined by [RFC 8446 section 7.5](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5).

### 15.3 Principal object

All SDK session engines should expose a logically equivalent immutable principal:

```text
AuthenticatedPrincipal
  trust_domain_id
  node_id
  credential_id
  identity_key_id
  credential_format
  authenticated_role_constraints
  transport_security
  storage_posture (reported, not blindly trusted)
  valid_from / valid_until
  revocation_status
  channel_binding_status
```

Application/profile authorization consumes this principal. It must not key policy solely on socket address, name, role claim, or session ID.

### 15.4 Authorization derivation

Effective permissions are the intersection of:

```text
credential role constraints
AND local trust-domain policy
AND negotiated protocol/profile capabilities
AND current operational safety policy
```

Capabilities describe what can be spoken. Permissions describe what may be done. Operational safety decides whether an otherwise permitted action is currently acceptable.

---

## 16. Authorization data model

Suggested policy record:

```json
{
  "policy_id": "bridge-stage-left",
  "revision": 7,
  "subject": {
    "trust_domain_id": "UUID",
    "node_id": "UUID",
    "identity_key_id": "sha256:..."
  },
  "role": "bridge",
  "allow": [
    "health.publish",
    "bridge.status.publish",
    "bridge.config.read",
    "bridge.config.write",
    "bridge.blackout.apply"
  ],
  "constraints": {
    "components": ["bridge.output.dmx.0"],
    "blackout_scope": ["local_outputs"],
    "requires_step_up": ["bridge.blackout.clear"]
  }
}
```

Client claims never mutate this record. Policy changes are revisioned, audited, and applied to new sessions immediately or according to a documented session-revalidation rule.

Security-sensitive handlers should receive both `AuthenticatedPrincipal` and `AuthorizationDecision`, avoiding repeated ad hoc policy lookups inside product code.

---

## 17. Revocation, renewal, rotation, and reset

### 17.1 Expiration and renewal

Credentials should be short enough to bound exposure but long enough to tolerate offline productions. Recommended defaults:

- Node credential validity: 90 days.
- Begin renewal: 30 days before expiry.
- Offline grace: deployment policy, never implicit.
- Enrollment bootstrap validity: 10 minutes.
- Enrollment PAKE attempt timeout: 60 seconds.

Renewal occurs over an already authenticated session. The node proves possession of its current key and, for rotation, a newly generated key. The authority signs the new credential only after policy and revocation checks.

### 17.2 Key rotation

Key rotation uses a two-phase commit:

1. Node generates a new private key.
2. Node requests a credential for the new public key, signed by its current identity.
3. Authority validates and issues a staged credential.
4. Node atomically installs and proves possession of the new key.
5. Authority activates the new credential and sets an overlap window.
6. Old credential expires or is revoked after confirmed migration.

Power loss at any stage must leave at least one usable, policy-valid credential or a documented recovery path.

### 17.3 Revocation

Revocation records include:

- Credential serial/ID.
- Node ID.
- Revocation timestamp.
- Stable reason code.
- Authority and audit event.
- Replacement credential ID, if any.
- Trust-domain revocation epoch.

Because ACP must operate offline, deployments cannot require an Internet OCSP service. A commissioner should publish signed revocation snapshots/deltas within the trust domain. Nodes cache the newest verified revocation epoch.

Critical revocation policy may terminate active sessions. Ordinary policy should fail closed for new sessions and explicitly define whether existing sessions receive a grace period.

### 17.4 Factory reset and unenrollment

Reset behavior is product-specific locally but protocol-visible afterward:

- Delete node private keys and credentials.
- Delete trust-domain anchors unless policy preserves factory roots.
- Invalidate cached enrollment secrets and replay markers.
- Generate a new `instance_id` on boot.
- Preserve or replace `node_id` according to installation identity policy; the choice must be documented.
- Previously issued credentials remain revoked or naturally expire; reset does not revoke them automatically unless an authority is contacted.

An unauthenticated ACP network command may never trigger trust reset.

---

## 18. Storage abstraction

All SDKs should expose the same conceptual interface:

```text
IdentityStore
  load_or_create_identity_key(algorithm)
  load_credentials(trust_domain_id)
  stage_credential(transaction_id, credential, trust_anchor, metadata)
  verify_staged(transaction_id)
  commit_staged(transaction_id)
  rollback_staged(transaction_id)
  delete_membership(trust_domain_id)
  mark_bootstrap_consumed(enrollment_id)
  load_revocation_state(trust_domain_id)
  store_revocation_state(snapshot)
  describe_storage_posture()
```

Requirements:

- Writes are atomic or journaled.
- Private keys are never returned as serializable bytes when a platform provider can sign internally.
- File permissions are restrictive by default.
- Secret buffers are minimized and cleared when supported.
- Logs contain key IDs, never private keys or bootstrap secrets.
- Backup behavior is explicit.
- Tests inject an in-memory store; production never defaults to it.

Storage posture values:

| Class | Meaning |
|---|---|
| `hardware_backed` | Private operations occur in a TPM, secure element, Secure Enclave, or equivalent. |
| `os_protected` | OS credential/key store protects the key. |
| `encrypted_file` | Application-encrypted file with separately protected wrapping key. |
| `protected_flash` | Embedded flash with platform access controls. |
| `plain_file` | Restricted-permission file only; allowed only by explicit policy and visibly degraded. |
| `ephemeral` | Test/simulator only; never production authority. |

---

## 19. Swift implementation design

### 19.1 Module placement

Add security code without coupling it to UI or product behavior:

```text
Sources/AuroraACP/Security/
  ACPAuthenticatedPrincipal.swift
  ACPAuthenticationMode.swift
  ACPEnrollmentModels.swift
  ACPEnrollmentStateMachine.swift
  ACPCredential.swift
  ACPCredentialValidator.swift
  ACPAuthorization.swift
  ACPSecurityErrors.swift
  Crypto/
    ACPCryptoProvider.swift
    ACPPlatformCryptoProvider.swift
    ACPTranscript.swift
  Storage/
    ACPIdentityStore.swift
    ACPKeychainIdentityStore.swift
    ACPFileIdentityStore.swift
```

Keep `ACPPlatformCryptoProvider` behind protocol interfaces. The core package must remain unit-testable without Keychain prompts, UI, network access, or hardware keys.

### 19.2 Core Swift protocols

```swift
public protocol ACPSigningKey: Sendable {
    var algorithm: ACPIdentityAlgorithm { get }
    var publicKeyRepresentation: Data { get }
    var keyID: String { get }
    func sign(_ message: Data) async throws -> Data
}

public protocol ACPCryptoProvider: Sendable {
    func randomBytes(count: Int) throws -> Data
    func sha256(_ data: Data) -> Data
    func hkdfSHA256(inputKeyMaterial: Data, salt: Data, info: Data, outputByteCount: Int) throws -> Data
    func makeIdentityKey(algorithm: ACPIdentityAlgorithm) async throws -> any ACPSigningKey
    func verify(signature: Data, message: Data, publicKey: ACPPublicKey) throws -> Bool
    func makeSPAKE2PlusClient(_ input: ACPSPAKE2PlusInput) throws -> any ACPSPAKE2PlusClient
    func makeSPAKE2PlusServer(_ input: ACPSPAKE2PlusInput) throws -> any ACPSPAKE2PlusServer
}
```

Do not expose raw private-key bytes in the protocol. Hardware-backed keys should conform by implementing `sign` internally.

### 19.3 Concurrency

Implement enrollment as an actor:

```swift
public actor ACPEnrollmentCoordinator {
    private var attempts: [UUID: Attempt]
    private let crypto: any ACPCryptoProvider
    private let store: any ACPIdentityStore
    private let clock: any ACPClock
    private let policy: any ACPEnrollmentPolicy
}
```

The actor owns attempt state, deadlines, retry counters, confirmation status, and durable installation. No URLSession callback or SwiftUI object may mutate enrollment state directly.

Cancellation must terminate PAKE state, remove derived keys, cancel timers, and emit a stable result. `deinit` is not a security cleanup strategy.

### 19.4 Apple storage adapter

On Apple platforms, prefer Security.framework/Keychain and Secure Enclave where the selected algorithm and device permit it. Do not make Secure Enclave mandatory because simulators, older devices, macOS configurations, and non-Apple SDK consumers may lack it.

Store metadata separately from private-key handles. Use transactional staging identifiers so a crash between certificate write and metadata write does not produce a partially active identity.

### 19.5 TLS integration

The transport layer must expose verified peer identity to `ACPSession`. `ACPWebSocket` should not merely return “TLS succeeded.” It should provide an immutable authentication result or fail connection establishment.

Required integration behavior:

- Configure TLS 1.3 minimum where the platform API allows it.
- Supply the node credential and private-key signing handle.
- Validate the trust-domain chain or pinned authority.
- Extract the ACP node identity from the defined SAN/credential field.
- Reject hostname/node identity ambiguity according to the chosen endpoint model.
- Disable user-click-through for invalid certificates in production mode.
- Expose channel-binding data if correctly available.
- Never fall back to plaintext after certificate failure.

If a platform WebSocket API cannot expose required mutual-TLS identity or exporter information, add a transport implementation capable of doing so rather than weakening session validation.

### 19.6 Swift models

Swift models should be `Codable` and `Sendable`, with explicit snake_case coding keys. Cryptographic byte strings require a dedicated base64url JSON / byte-string CBOR representation rather than default Foundation base64 behavior.

Enums receiving unknown optional values should preserve an `.unknown(String)` case where diagnostics require it. Unknown critical algorithms, credential formats, or extensions fail closed.

### 19.7 Swift tests

Add:

```text
tests/AuroraACPTests/Security/
  ACPTranscriptTests.swift
  ACPEnrollmentVectorTests.swift
  ACPEnrollmentStateMachineTests.swift
  ACPCredentialValidationTests.swift
  ACPIdentityStoreCrashTests.swift
  ACPAuthenticatedSessionTests.swift
  ACPAuthorizationTests.swift
```

Use deterministic injected randomness only in tests. Test concurrency cancellation, deadline races, duplicate messages, late confirmation, store failure, restart recovery, and credential mismatch.

---

## 20. Python implementation design

### 20.1 Package placement

```text
python/src/acp/security/
  __init__.py
  models.py
  principal.py
  transcript.py
  enrollment.py
  credentials.py
  authorization.py
  errors.py
  crypto.py
  storage.py
  tls.py
```

The core must not require a heavyweight web framework or GUI toolkit. CLI and simulator integration import the same library APIs.

### 20.2 Models

Use frozen, slotted dataclasses:

```python
@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    trust_domain_id: UUID
    node_id: UUID
    credential_id: str
    identity_key_id: str
    credential_format: CredentialFormat
    role_constraints: frozenset[str]
    valid_from: datetime
    valid_until: datetime
    transport_security: TransportSecurity
```

Avoid dictionaries at policy and cryptographic boundaries. Parse untrusted maps into validated typed models before use.

### 20.3 Crypto provider

Define a provider protocol and select one audited implementation for production. Python standard library alone does not provide SPAKE2+, general certificate issuance, or all required signing primitives. The dependency decision must be recorded, pinned, licensed, and exercised by vectors.

```python
class CryptoProvider(Protocol):
    def random_bytes(self, count: int) -> bytes: ...
    def sha256(self, data: bytes) -> bytes: ...
    def hkdf_sha256(self, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes: ...
    def generate_identity_key(self, algorithm: IdentityAlgorithm) -> SigningKey: ...
    def verify(self, public_key: PublicKey, message: bytes, signature: bytes) -> bool: ...
    def new_spake2plus_client(self, params: Spake2PlusInput) -> Spake2PlusClient: ...
    def new_spake2plus_server(self, params: Spake2PlusInput) -> Spake2PlusServer: ...
```

Never emulate missing PAKE support with a password hash plus ordinary Diffie-Hellman.

### 20.4 Async enrollment

`EnrollmentCoordinator` uses `asyncio`, but cryptographic state transitions remain explicit synchronous operations invoked by the coordinator. Use `asyncio.timeout` or injected clock/deadline helpers for network waiting. Keep attempt counts and derived secrets in bounded structures.

Cancellation handling must use `try/finally` to clear state and release resources. Do not catch `BaseException` broadly. Convert validation failures to stable ACP security errors without including secret material.

### 20.5 Python storage

Provide:

- `InMemoryIdentityStore` for tests only.
- `FileIdentityStore` with restrictive permissions, atomic replace, fsync policy, and journal/recovery behavior.
- Optional OS-specific adapters outside the protocol core.

On POSIX, validate directory/file ownership and permissions. On Windows, use an adapter capable of applying Windows ACLs or an OS credential facility rather than assuming POSIX mode bits provide protection.

Serialization must never use pickle for credentials, enrollment packages, or network inputs.

### 20.6 TLS and WebSockets

Python session transport should construct an `ssl.SSLContext` configured for TLS 1.3 where supported, load the local credential, require peer verification, and validate ACP identity after the TLS handshake.

The selected WebSocket library must allow access to the underlying TLS peer certificate and, if required, exporter material. If it does not, the adapter does not satisfy authenticated ACP conformance.

### 20.7 CLI integration

Extend the existing CLI shape with commands such as:

```text
acp security trust-domain create --name "Haywire Production"
acp security enrollment open --duration 10m
acp security enroll --code A7KM-...
acp security enroll --package stage-left.aurora-enroll
acp security nodes list
acp security credential rotate --node UUID
acp security revoke --node UUID --reason compromised
acp security audit verify
```

Commands must redact secrets by default. `--json` output must also redact them. Shell history warnings should be shown when a secret is supplied on the command line; interactive prompt, stdin, or protected file input is preferred.

### 20.8 Python tests

Use pytest and Hypothesis for:

- Schema/model round trips.
- Transcript determinism.
- State-machine event sequences.
- Malformed base64url and CBOR.
- Retry/lockout boundaries.
- Clock skew and expiry.
- Atomic store failure injection.
- Authorization intersection properties.
- Decoder fuzz/property tests.

Test logs using a capture handler and assert that bootstrap secrets, derived keys, private material, and full credential bodies never appear.

---

## 21. Rust implementation design

### 21.1 Crate boundaries

Recommended workspace additions:

```text
rust/
  acp-security-model/     # no networking; compact models; no Tokio
  acp-security-crypto/    # provider traits and selected implementations
  acp-security-session/   # enrollment machine and authenticated principal
  acp-security-storage/   # std storage adapters
```

Alternatively, model types may remain in `acp-model` if dependency layering stays clean. `acp-model` must not gain Tokio, filesystem, TLS, or platform-keystore dependencies.

### 21.2 Feature design

Suggested Cargo features:

```toml
[features]
default = ["std", "full-profile"]
std = []
full-profile = ["tls", "x509"]
lightweight = []
ed25519 = []
test-provider = []
```

Feature combinations must be CI-tested. `test-provider` may not be enabled by a production binary accidentally; guard it through crate visibility and build policy.

### 21.3 Traits

```rust
pub trait SigningKey: Send + Sync {
    fn algorithm(&self) -> IdentityAlgorithm;
    fn public_key(&self) -> PublicKey;
    fn key_id(&self) -> &KeyId;
    fn sign(&self, message: &[u8]) -> Result<Signature, SecurityError>;
}

pub trait CryptoProvider: Send + Sync {
    type Key: SigningKey;
    fn fill_random(&self, out: &mut [u8]) -> Result<(), SecurityError>;
    fn sha256(&self, data: &[u8]) -> [u8; 32];
    fn hkdf_sha256(&self, ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8])
        -> Result<(), SecurityError>;
    // SPAKE2+ constructors use opaque provider-owned state.
}
```

Provider-owned PAKE types must prevent calling state transitions out of order where practical. Secret-bearing types should avoid `Clone`, `Debug`, `Serialize`, and accidental equality derivations.

### 21.4 Typestate state machine

Rust can encode enrollment phases with typestate:

```rust
Enrollment<Open>
Enrollment<Negotiating>
Enrollment<KeyConfirmed>
Enrollment<CredentialStaged>
Enrollment<Enrolled>
```

Network dispatch may still require an enum wrapper, but cryptographic operations should consume the previous phase and return the next so confirmation cannot be skipped accidentally.

### 21.5 Memory bounds and Lightweight profile

The Lightweight implementation must define compile-time or negotiated bounds for:

- Concurrent attempts.
- Maximum credential size.
- Maximum enrollment message size.
- Transcript/context size.
- Certificate/credential chain length.
- Revocation entries or epoch representation.
- Pending outbound messages.

No unbounded `Vec`, channel, map, or recursive parser may be reachable from untrusted enrollment input on a constrained build. Where heap allocation is unavailable, use fixed-capacity buffers and return `security.resource_limit` on overflow.

Secret buffers should use a zeroization mechanism where supported. Zeroization is defense in depth and does not replace correct ownership or storage.

### 21.6 Embedded storage

Define a journaled two-slot credential store:

```text
slot A: generation, body, checksum/MAC, committed flag
slot B: generation, body, checksum/MAC, committed flag
selector: active generation
```

Update flow:

1. Write inactive slot.
2. Read back and validate.
3. Mark slot committed.
4. Atomically advance selector.
5. Retain prior slot until successful authenticated use or cleanup policy.

Power-loss tests should interrupt every write boundary and verify recovery chooses the newest complete valid generation.

### 21.7 TLS integration

Full Linux/Raspberry Pi Rust builds may use a mature TLS stack through an adapter. Embedded builds may use the platform's supported embedded TLS provider. The ACP crate must not assume that a desktop TLS crate is available under `no_std`.

The adapter returns `AuthenticatedPrincipal`, not just a boolean. Certificate/raw credential validation must be performed before session establishment.

### 21.8 Rust tests and fuzzing

Add:

- Golden transcript and PAKE vectors.
- `proptest` state-machine properties.
- Fuzz targets for credential, enrollment message, base64url, CBOR, and extension parsing.
- Loom or deterministic concurrency tests where shared session state warrants it.
- Embedded store power-failure simulation.
- `cargo test` feature matrix.
- Cross-compilation checks for representative ARM targets.

Malformed input must return an error and never panic, abort, allocate without bound, or reveal secret-derived diagnostics.

---

## 22. Cross-language parity requirements

Swift, Python, and Rust must agree on:

- Deterministic enrollment context bytes.
- Transcript hash.
- SPAKE2+ messages for fixed test randomness.
- Confirmation MACs.
- HKDF outputs.
- SAS result.
- Credential canonical bytes.
- Credential signature verification.
- Key identifiers and credential identifiers.
- JSON/base64url and CBOR/byte-string normalization.
- State-machine result for every event sequence.
- Stable error codes.

Golden vector structure:

```text
vectors/security/
  enrollment/
    success_p256/
      inputs.json
      context.cbor
      messages.json
      messages.cbor
      transcript.sha256
      derived_keys.json        # test-only synthetic material; never production secrets
      credential.cbor
      expected.json
    wrong_secret/
    expired/
    replay/
    tampered_context/
    role_downgrade/
  credentials/
    full_profile/
    compact_profile/
    expired/
    revoked/
    wrong_node/
    wrong_domain/
```

Vectors containing private/test secret material must be unmistakably marked synthetic and must never be copied into production defaults.

At least these live pairs must be exercised:

- Swift commissioner <-> Rust candidate.
- Python commissioner <-> Swift candidate.
- Rust commissioner <-> Python candidate.
- Full-profile commissioner <-> Lightweight candidate simulator.

Both directions should be tested where either implementation can act as commissioner.

---

## 23. Schema and registry changes

### 23.1 Common definitions

Add definitions for:

- `auth_mode`: include `enrollment_spake2plus`, `mutual_tls`, `compact_credential` while retaining `trusted_lan` policy behavior.
- `trust_domain_id`.
- `credential_id` and `identity_key_id`.
- Cryptographic algorithm/suite IDs.
- Base64url byte strings for JSON schemas.
- Enrollment states and methods.
- Credential format and status.
- Storage posture.
- Security error body.

### 23.2 Message schemas

Create `schema/security/messages.schema.json`. Keep public status separate from secret-bearing PAKE messages so accidental schema reuse cannot expose private fields.

Sensitive schemas should contain annotations consumed by logging/redaction tooling:

```json
{
  "bootstrap_secret": {
    "type": "string",
    "x-acp-sensitive": true,
    "x-acp-log-policy": "never"
  }
}
```

These annotations do not provide security by themselves. Runtime logging APIs must enforce redaction.

### 23.3 Registry metadata

Each security message registry row must specify:

- Minimum ACP and capability version.
- Valid sender and receiver roles/security states.
- Pre-HELLO or enrollment-session legality.
- QoS.
- Correlation behavior.
- Authorization permission.
- Rate-limit class.
- Security class.
- Sensitive-field policy.
- Expected response type.
- Terminal/nonterminal status.

Enrollment messages must not be accepted by the ordinary established-session router unless the state and permission metadata allow them.

---

## 24. Stable error codes

Add stable errors including:

| Code | Category | Retryable | Meaning |
|---|---|---:|---|
| `security.enrollment_closed` | authorization | false | Candidate is not accepting enrollment. |
| `security.enrollment_expired` | timeout | true | Enrollment window or attempt expired. |
| `security.enrollment_locked` | authorization | false | Attempt limit reached. |
| `security.enrollment_replayed` | conflict | false | Enrollment/attempt identifier already consumed. |
| `security.no_common_suite` | protocol | false | No mutually supported cryptographic suite. |
| `security.key_confirmation_failed` | authentication | false | PAKE confirmation did not verify. |
| `security.transcript_mismatch` | authentication | false | Bound context differs. |
| `security.identity_mismatch` | authentication | false | Credential identity and ACP identity differ. |
| `security.trust_domain_mismatch` | authentication | false | Credential belongs to another domain. |
| `security.credential_expired` | authentication | true | Credential is outside validity. |
| `security.credential_revoked` | authentication | false | Credential has been revoked. |
| `security.credential_invalid` | authentication | false | Signature/format/critical extension invalid. |
| `security.permission_denied` | authorization | false | Principal lacks required permission. |
| `security.downgrade_forbidden` | authentication | false | Policy prohibits weaker authentication. |
| `security.storage_failed` | internal | true | Durable credential operation failed. |
| `security.resource_limit` | unavailable | true | Bounded security resource exhausted. |
| `security.clock_untrusted` | unavailable | true | Credential time cannot be evaluated under policy. |

Externally returned authentication errors should avoid unnecessary oracle detail. Local structured logs may retain a more precise stable diagnostic code, subject to redaction policy.

---

## 25. Discovery changes

Discovery may add:

```json
{
  "security_modes": ["mutual_tls", "enrollment_spake2plus"],
  "enrollment": {
    "available": true,
    "enrollment_id": "UUID",
    "expires_at": "RFC3339",
    "methods": ["manual_code", "provisioning_file"]
  },
  "trust_domain_hint": "sha256:truncated-public-identifier"
}
```

Discovery MUST NOT include:

- Bootstrap secret or PIN.
- Full enrollment URI.
- Private key material.
- Credential bodies.
- Authorization grants.
- Operator/user identity.
- A claim that the sender is authenticated.

An application should render discovered nodes as `untrusted`, `known domain`, `authenticated`, or `identity conflict`, based on later verification—not on discovery labels.

---

## 26. Logging, observability, and Wireshark

### 26.1 Audit events

Security events use stable codes and structured fields:

- Enrollment opened/closed/expired.
- Attempt started/succeeded/failed/locked.
- Operator approval/denial.
- Credential issued/installed/renewed/rotated/revoked.
- Trust-domain created/imported/recovered.
- Authentication success/failure.
- Authorization denial.
- Downgrade attempt.
- Identity collision.

Audit entries should contain event ID, timestamp, monotonic ordering where available, actor principal, target node, trust domain, credential/key IDs, policy revision, result, and causation/correlation identifiers.

### 26.2 Prohibited log data

Never log:

- Bootstrap secrets or manual codes.
- PAKE password inputs.
- PAKE shared secrets.
- Derived enrollment keys.
- Private identity keys.
- Decrypted approval bodies unless separately redacted.
- Raw credential packages when they contain sensitive metadata.
- Full SAS before the ceremony completes.

### 26.3 Wireshark behavior

The dissector should decode public envelope fields and nonsensitive enrollment metadata. PAKE byte strings and ciphertext are displayed only as opaque length/hash summaries. It must not attempt to reconstruct secrets.

Suggested fields:

```text
acp.security.mode
acp.security.enrollment.state
acp.security.enrollment.id
acp.security.enrollment.attempt_id
acp.security.suite
acp.security.trust_domain_id
acp.security.credential_id
acp.security.identity_key_id
acp.security.result
acp.security.error_code
```

Sample PCAPs use synthetic credentials and secrets generated solely for fixtures.

---

## 27. Rate limits and resource bounds

Recommended defaults:

| Resource | Full profile | Lightweight profile |
|---|---:|---:|
| Concurrent enrollment attempts | 8 | 1 |
| Attempts per enrollment ID | 5 | 5 |
| Attempt timeout | 60 s | 60 s |
| Enrollment window | 10 min | 10 min |
| Maximum security message | 64 KiB within normal negotiated limit | 8 KiB |
| Maximum compact credential | 8 KiB | 2 KiB |
| Trust domains | implementation policy | 1 |
| Active node credentials/domain | 2 during rotation | 2 during rotation |
| Failed-attempt audit retention | policy | bounded counter + recent record |

Rate limits are applied by candidate identity/enrollment ID and by source network metadata as defense in depth. IP-based rate limiting is not identity and may not be the sole control.

---

## 28. Clock handling

Certificates require time evaluation, but some embedded devices may boot without trustworthy wall-clock time.

Policy options:

1. Hardware RTC or trusted local time: validate normally.
2. Previously authenticated secure-time checkpoint: accept only monotonic forward movement within policy.
3. Commissioner-provided time inside an authenticated handshake: use as a bounded session input, never before commissioner authentication.
4. No trustworthy time: fail authenticated production control or enter a narrowly defined degraded mode requiring operator policy.

Nodes must not set their system clock from unauthenticated discovery or HELLO fields.

Rollback detection should store the latest trusted time/credential epoch where durable storage permits it.

---

## 29. Migration from `trusted_lan`

Migration should be staged:

### Stage 1: Observe

- Add security schemas, models, principal abstraction, and reporting.
- Continue existing `trusted_lan` behavior only when explicitly enabled.
- Mark principals as unauthenticated.

### Stage 2: Enroll

- Add trust-domain creation and node enrollment.
- Allow authenticated and trusted-LAN sessions side by side under policy.
- Show prominent security state.

### Stage 3: Prefer authenticated

- Authenticated endpoints are preferred.
- Sensitive capabilities require authenticated principals.
- Plaintext access is limited to diagnostics or enrollment policy.

### Stage 4: Enforce

- Production policy disables `trusted_lan` control.
- No automatic downgrade.
- Discovery and enrollment remain available according to local policy.

Existing node IDs must be claimed explicitly. Seeing the same `node_id` during enrollment does not prove continuity. The operator must approve whether to bind the old installation identity to the new cryptographic identity.

---

## 30. Implementation phases

### Phase A: Design freeze and vectors

- Finalize cryptographic provider/library review.
- Freeze SPAKE2+ suite parameters and transcript encoding.
- Add schema, registry rows, capabilities, and errors.
- Create synthetic cross-language vectors.
- Perform external security review before production credentials exist.

### Phase B: Models and provider interfaces

- Implement models in Swift, Python, and Rust.
- Implement transcript, HKDF labels, identifiers, and credential parsing.
- Add in-memory test stores and deterministic test providers.
- No production enrollment yet.

### Phase C: Enrollment state machines

- Implement candidate and commissioner machines.
- Add deadlines, replay tracking, retry limits, cancellation, and audit.
- Achieve three-language vector parity.
- Add malformed and property tests.

### Phase D: Persistent credentials

- Add full credential issuer/validator.
- Add compact credential parser/validator.
- Implement atomic stores and crash recovery.
- Add renewal, rotation, and revocation model.

### Phase E: Authenticated transports

- Integrate TLS 1.3 mutual authentication for full profiles.
- Bind verified principals to ACP HELLO.
- Prototype and security-review the Lightweight authenticated transport profile.
- Run live cross-language sessions.

### Phase F: Authorization and product adapters

- Key policy on authenticated principal.
- Require explicit permissions for sensitive profile operations.
- Add security state to Conductor/Prism/Lyric/Bridge adapters.
- Retain application authority and existing ACP safety semantics.

### Phase G: Operational tooling

- Add CLI commissioning and revocation tools.
- Add optional QR/visual UX.
- Extend inspector, simulator, Wireshark, and audit verification.
- Add deployment and recovery documentation.

---

## 31. Testing matrix

### 31.1 Cryptographic tests

- Standard SPAKE2+ vectors from the selected profile/library.
- ACP transcript and derivation vectors.
- Wrong bootstrap secret.
- Modified suite/version/context.
- Modified node, role, permission digest, or trust domain.
- Missing or duplicate PAKE messages.
- Invalid curve points/encodings.
- Confirmation reflection and role reversal.
- Replayed attempt/enrollment IDs.
- Randomness-provider failure.

### 31.2 Credential tests

- Correct signature and identity.
- Wrong trust domain.
- Wrong node ID.
- Wrong public-key proof.
- Expired/not-yet-valid.
- Revoked.
- Unknown optional extension.
- Unknown critical extension.
- Malformed chain/compact CBOR.
- Rotation overlap and retirement.
- Clock unavailable/rollback.

### 31.3 State-machine tests

- Happy path for every onboarding method.
- Headless candidate with no display/button.
- Expiry at every state.
- Cancellation at every state.
- Duplicate messages.
- Out-of-order messages.
- Concurrent attempts and resource limits.
- Restart/power loss at every persistence boundary.
- Lockout and secret regeneration.
- Approval denied.
- Credential install fails but old identity survives.

### 31.4 Authorization tests

- Client role claim cannot grant access.
- Capability support cannot grant access.
- Credential constraint narrows local policy.
- Local policy narrows credential constraint.
- Dangerous operations require step-up policy where configured.
- Revocation removes authorization.
- Session replacement does not retain stale grants.

### 31.5 Platform tests

- macOS and iOS Swift.
- Linux Swift where supported by package requirements.
- Python on macOS, Linux, and Windows.
- Rust on macOS, Linux, and Windows.
- Rust cross-build/runtime test on Raspberry Pi architecture.
- Lightweight test on representative Pico-class target or hardware-in-loop fixture.
- Android integration adapter test when an Android product exists.

### 31.6 Operational tests

- Entire deployment works without Internet access.
- Discovery spoofing does not authenticate.
- LAN MITM cannot complete enrollment without bootstrap knowledge.
- Captures do not enable offline short-code guessing beyond the PAKE security model.
- Logs and crash reports contain no secrets.
- Revoked node cannot reconnect.
- Authority recovery does not silently create a new trust domain under the old name.
- `trusted_lan` downgrade is rejected under hardened policy.

---

## 32. Acceptance criteria

Aurora Trust is not complete until all of the following are true:

- [ ] The language-neutral schema defines every security type and message.
- [ ] Registry metadata defines state, QoS, capabilities, responses, authorization, rate limits, and redaction.
- [ ] Swift, Python, and Rust consume identical deterministic vectors.
- [ ] No SDK implements custom elliptic-curve or TLS primitives.
- [ ] A headless/buttonless node can enroll securely using a private bootstrap credential or signed package.
- [ ] A node with UI can optionally present the same cross-language SAS.
- [ ] The candidate private identity key never leaves the candidate.
- [ ] Credential installation is atomic and power-loss tested.
- [ ] Full-profile nodes mutually authenticate using TLS 1.3.
- [ ] The Lightweight profile meets equivalent identity, confidentiality, integrity, and replay goals within bounded resources.
- [ ] HELLO node identity is bound to the authenticated principal.
- [ ] Discovery metadata cannot create a principal.
- [ ] Advertised roles/capabilities cannot create permissions.
- [ ] Sensitive commands use server-derived authorization policy.
- [ ] Renewal, rotation, revocation, expiry, and reset are implemented and documented.
- [ ] No production mode silently falls back to `trusted_lan`.
- [ ] Enrollment secrets and private material are absent from logs, captures, fixtures, and error responses.
- [ ] Cross-language live enrollment and authenticated sessions pass.
- [ ] Malformed security input cannot crash or exhaust a process beyond declared bounds.
- [ ] The implementation receives an independent cryptographic/security review before show-critical deployment.

---

## 33. Decisions requiring explicit freeze before coding cryptography

The architecture is implementable, but the following details must be resolved in a normative ACP security profile before production code is accepted:

1. Exact SPAKE2+ ciphersuite parameters and audited library choices per language/platform.
2. Exact password normalization and registration-record rules.
3. Exact transcript framing and confirmation-MAC format.
4. Exact AEAD algorithm and nonce construction for the protected approval payload.
5. Mandatory identity algorithm after target-platform validation.
6. Full X.509 profile, SAN encoding, validity, and chain rules.
7. Lightweight credential transport and proof-of-possession mechanism.
8. TLS exporter availability and channel-binding requirement per transport implementation.
9. Revocation distribution format and offline policy.
10. Secure-time policy for constrained devices.
11. Authority backup/recovery and optional quorum design.
12. Word list, palette, and unbiased SAS mapping if visual fingerprints ship.

These are specification decisions, not details that individual SDKs may choose independently.

---

## 34. Final implementation guidance

The safest implementation is deliberately layered:

- Keep onboarding-channel UX outside protocol state machines.
- Keep cryptographic primitives behind audited providers.
- Keep key material behind storage/signing handles.
- Keep transport authentication separate from ACP message decoding.
- Convert verified transport identity into an immutable principal.
- Bind HELLO identity to that principal.
- Derive permissions from local policy, not peer claims.
- Keep profile/application safety checks after authorization.
- Make every security lifecycle transition observable without exposing secrets.
- Test behavior across languages before integrating product UI.

Aurora Trust should feel effortless to operators: scan a code, import a package, paste a one-time phrase, or approve a locally discovered candidate. Its security must not depend on that presentation. Underneath every onboarding method, ACP performs the same transcript-bound PAKE, installs the same persistent identity model, authenticates the same principal, and applies the same authorization rules on Swift, Python, Rust, Raspberry Pi, Pi Pico, Linux, Apple platforms, Windows, and Android.

That division—portable cryptographic contract, replaceable platform adapters, and explicit policy—is what makes the system both interesting to use and safe enough for live-show control.
