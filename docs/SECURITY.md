# ACP 1.2 Aurora Trust Security Profile

**Status:** Candidate Freeze 2.1.1 — independent document-level GO; execution qualification required
**Extension version:** 1.0
**Source design:** `DesignDocs/ACP_Aurora_Trust_Authentication_Implementation_Design.md`

This document is the proposed normative security profile for Aurora Trust. It resolves the wire-level choices that must be common to Swift, Python, and Rust. It MUST NOT be represented as production-approved until the review gates in the Milestone 0 decision record are closed.

## 1. Protocol separation

Discovery is untrusted metadata. Enrollment establishes a device credential. Authentication proves control of the credential's private key. Authorization derives effective permissions locally. Capabilities only describe protocol compatibility.

The authenticated device principal and current human/operator/participant assignment are separate identities. Credential lifecycle operations MUST NOT implicitly mutate cached layouts, show assets, or other asset-conformance state.

## 2. Mandatory algorithms

| Purpose | Candidate Freeze 2.1.1 choice |
|---|---|
| Enrollment PAKE | RFC 9383 SPAKE2+, `P256-SHA256-HKDF-HMAC-SHA256` |
| Identity signature | ECDSA P-256 with SHA-256 |
| Hash | SHA-256 |
| KDF | HKDF-SHA-256 |
| Confirmation MAC | HMAC-SHA-256 |
| Protected approval | AES-256-GCM with a 96-bit nonce and 128-bit tag |
| Full transport | TLS 1.3 only |
| TLS cipher suites | `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, or `TLS_CHACHA20_POLY1305_SHA256` |
| Certificate encoding | DER X.509 v3 |
| Compact encoding | Deterministic CBOR under ACP-CDE-1.2 |

The high-entropy suite identifier is `ACP-SPAKE2PLUS-P256-SHA256-HKDFSHA256-RAW128-v1`. The manual-code suite identifier is `ACP-SPAKE2PLUS-P256-SHA256-HKDFSHA256-PBKDF2-100K-v1`. They share the RFC 9383 P-256/SHA-256 online protocol but deliberately have distinct registration functions. Each enrollment ID advertises exactly one suite matching its bootstrap-secret form; dual advertisement and selecting a suite that does not match the candidate's stored secret form are forbidden. Lightweight targets advertise `...RAW128-v1` only and MUST NOT require the PBKDF2 suite.

Both suites use the RFC 9383 P-256 M and N points. M and N are published in compressed form by RFC 9383, but RFC transcript points and wire shares use uncompressed SEC1 form: `0x04 || X[32] || Y[32]`, exactly 65 bytes. `shareP` and `shareV` MUST match RFC 9383 Appendix C encoding. RFC transcript framing, key schedule, and explicit bidirectional key confirmation are unchanged.

No implementation may substitute balanced SPAKE2, ordinary ECDH plus a password hash, SRP, an unauthenticated hash exchange, or a provider-specific PAKE transcript under this suite identifier.

## 3. Bootstrap-secret preparation

The canonical high-entropy bootstrap secret is 16 uniformly random bytes. Its human form is the unsigned big-endian 128-bit integer encoded as exactly 26 Crockford Base32 characters using `0123456789ABCDEFGHJKMNPQRSTVWXYZ`. The first character MUST be `0` through `7`, making the two unused high bits zero. There is no checksum and no `=` padding. Display grouping is cosmetic. ASCII hyphens and ASCII whitespace are removed before decoding; lowercase is uppercased. `I`, `L`, `O`, `U`, Unicode normalization, aliases, substitution, nonzero padding bits, and any decoded length other than 16 bytes are rejected.

A manual numeric code is exactly 8 to 12 ASCII digits. It is encoded as its ASCII bytes. Numeric codes expire after 10 minutes, permit at most five attempts per enrollment ID, and MUST be protected by the same SPAKE2+ ceremony and online rate limits.

Registration uses octet strings and MUST NOT pass secret material through a NUL-terminated string API. UUID bytes in this section are the 16 RFC 4122 network-order bytes.

```text
idProver   = candidate_node_id_bytes
idVerifier = commissioner_node_id_bytes
salt       = SHA-256(
  UTF8("ACP SPAKE2+ registration salt v1") ||
  LE64(16) || enrollment_id_bytes ||
  LE64(16) || idProver ||
  LE64(16) || idVerifier
)

registration_input =
  LE64(len(password)) || password ||
  LE64(16) || idProver ||
  LE64(16) || idVerifier
```

For `...RAW128-v1`, `password` is the decoded 16-byte secret and:

```text
w_bytes = HKDF-SHA-256(
  IKM = registration_input,
  salt = salt,
  info = UTF8("ACP SPAKE2+ RAW128 registration v1"),
  L = 80
)
```

Here `HKDF-SHA-256` is RFC 5869 Extract followed by Expand with the displayed salt and info.

For `...PBKDF2-100K-v1`, `password` is the ASCII numeric-code bytes and:

```text
w_bytes = PBKDF2-HMAC-SHA-256(
  password = registration_input,
  salt = salt,
  iterations = 100000,
  L = 80
)
```

In both suites, `w0s = w_bytes[0..<40]`, `w1s = w_bytes[40..<80]`, and RFC 9383 `w0` and `w1` are obtained by interpreting each as an unsigned big-endian integer and reducing modulo the P-256 group order. `L = w1 * P`. Providers MUST accept the resulting precomputed values/registration record; provider-default password KDFs are forbidden. The online `context` is not a registration input.

The verifier registration record is ephemeral, scoped to one enrollment ID and commissioner identity, and destroyed on success, any confirmation failure, lockout, expiry, cancellation, restart, or reset. A provider that cannot reproduce RFC 9383 Appendix C and ACP registration vectors, including secrets containing `0x00`, `0xff`, and non-UTF-8 bytes, is nonconforming.

## 4. Enrollment context and transcript

The `context` input to RFC 9383 is deterministic ACP-CDE-1.2 CBOR encoding of the following closed map. No other key is legal; no value may be `null`.

```text
application                    "Aurora Communications Protocol"
purpose                        "security.enrollment"
extension_version              "1.0"
acp_version                    "1.2"
suite                          suite identifier
enrollment_id                  UUID
attempt_id                     UUID
candidate_node_id              UUID
candidate_instance_id          UUID
commissioner_node_id           UUID
commissioner_instance_id       UUID
trust_domain_id                UUID
requested_role                 text
requested_permissions_digest   "sha256:" + 64 lowercase hexadecimal digits
identity_algorithm             "ecdsa_p256_sha256"
identity_key_id                "sha256:" + 64 lowercase hexadecimal digits
```

UUID values are lowercase canonical UUID text under ACP-CDE-1.2. Version 1 permits only an empty requested-permissions map; `requested_permissions_digest` is therefore `sha256:` plus lowercase hexadecimal SHA-256 of deterministic CBOR `{}`. Nonempty requested permissions fail with `security.permission_denied`; later versions require a closed schema before enabling them. Requested role and permissions are requests, never grants.

`security.enrollment.begin` carries commissioner node/instance IDs, candidate node ID, enrollment ID, attempt ID, trust-domain ID, suite, requested role, and permission digest. `security.enrollment.challenge` echoes those fields, adds the candidate instance ID, identity algorithm, identity key ID, canonical DER SPKI, and `shareP`. The candidate constructs the final context before generating `shareP`; the commissioner constructs it after validating the challenge fields and recomputing `identity_key_id` from the SPKI. Discovery values are never substituted for missing fields.

`idProver` is the 16 raw bytes of `candidate_node_id`. `idVerifier` is the 16 raw bytes of `commissioner_node_id`. RFC 9383 constructs `TT` exactly as specified, including its eight-byte little-endian length prefixes.

The message mapping is fixed: challenge contains `shareP` (65 bytes); response contains two separate fields, `shareV` (65 bytes) and `confirmV` (32 bytes); confirm contains `confirmP` (32 bytes). A provider's `shareV || confirmV` output is split at 65 bytes. The ACP enrollment transcript hash is:

```text
SHA-256(ACP-CDE-1.2([
  context_bstr,
  shareP_bstr,
  shareV_bstr,
  confirmV_bstr,
  confirmP_bstr
]))
```

No approval is sent before both RFC 9383 confirmations succeed in constant time. Provider APIs that skip Prover/candidate confirmation are forbidden. `K_shared` is exactly the 32-byte RFC 9383 output and is used as IKM for the application schedule; RFC 9383 internal keys are not reused.

## 5. Application key schedule

```text
enrollment_root = HKDF-Extract(
  salt = transcript_hash,
  IKM = K_shared
)

candidate_confirm = HKDF-Expand(enrollment_root,
  "ACP enrollment candidate confirm v1", 32)
commissioner_confirm = HKDF-Expand(enrollment_root,
  "ACP enrollment commissioner confirm v1", 32)
approval_key = HKDF-Expand(enrollment_root,
  "ACP enrollment approval AEAD v1", 32)
sas_key = HKDF-Expand(enrollment_root,
  "ACP enrollment SAS v1", 32)
audit_key = HKDF-Expand(enrollment_root,
  "ACP enrollment audit binding v1", 32)
```

`HKDF-Extract` and `HKDF-Expand` mean RFC 5869 operations. Expand uses the UTF-8 label directly as `info`, without NUL or length prefix, and `L=32`; TLS `HKDF-Expand-Label` and a second Extract are forbidden. The two ACP confirmation keys authenticate later ACP ceremony messages after RFC confirmation; they do not replace it.

`candidate_confirm` authenticates the closed deterministic-CBOR `security.enrollment.install_result` payload defined in section 6, excluding its `confirmation` field: `confirmation = HMAC-SHA-256(candidate_confirm, install_result_cbor_without_confirmation)`. The ECDSA proof remains mandatory. `commissioner_confirm` is reserved for a future reviewed extension and MUST NOT authenticate or cause any wire message in version 1. There is no commissioner receipt in version 1; enrollment completes after the commissioner verifies install result, HMAC, proof of possession, and one-time attempt state. Neither key may be reused for another message or an ad hoc extension.

## 6. Protected approval

Approval uses AES-256-GCM. Each approval key encrypts at most one approval. The nonce is 12 fresh CSPRNG bytes and is sent in the envelope. Nonce reuse with a key is fatal and consumes the enrollment attempt.

Plaintext is deterministic CBOR for this closed map; no value may be null and no extra key is legal:

```text
trust_domain_id       UUID text
trust_domain_name     text, 1..128 UTF-8 bytes
credential            byte string, 1..8192 bytes Full or 1..2048 Lightweight
credential_format     "x509_der" or "acp-compact-credential-v1"
authority_key_id      sha256 identifier
trust_anchor          byte string, 1..8192 bytes
role_constraints      sorted unique array of 0..16 role strings
policy_id             text, 1..128 UTF-8 bytes
policy_revision       uint64
not_before            CBOR tag 0 RFC3339 UTC
expires_at            CBOR tag 0 RFC3339 UTC
rotation_deadline     CBOR tag 0 RFC3339 UTC
commissioner_node_id  UUID text
transcript_hash       32-byte byte string
```

Associated data is deterministic CBOR for this closed map. `message_type` is the literal `security.enrollment.approval`:

```text
message_type, attempt_id, enrollment_id,
candidate_node_id, commissioner_node_id, trust_domain_id,
acp_version, extension_version, suite, identity_algorithm,
identity_key_id, transcript_hash
```

UUIDs in plaintext/AAD are canonical text and `transcript_hash` is a 32-byte byte string. The envelope carries `nonce` and `ciphertext` as byte strings in CBOR or unpadded base64url in JSON.

Confirmation, transcript, decryption, or tag failure returns the same externally generic `security.authentication_failed`, consumes the attempt, and records a locally precise redacted audit code.

`credential_id_ascii` is UTF-8 encoding of exactly `sha256:` followed by 64 lowercase hexadecimal digits. `security.enrollment.install_result` is a closed deterministic-CBOR map with no extra or null fields:

```text
attempt_id             canonical lowercase UUID text
status                 literal "installed"
credential_id          sha256 identifier
identity_key_id        sha256 identifier
trust_domain_id        canonical lowercase UUID text
storage_posture        closed map described below
proof_of_possession    byte string containing low-S strict DER ECDSA
confirmation           32-byte HMAC byte string
```

`storage_posture` contains exactly `class`, `hardware_backed`, and `private_key_exportable`. `class` is one of `hardware_backed`, `os_protected`, `encrypted_file`, `protected_flash`, `plain_file`, or `ephemeral`; the other fields are booleans. The HMAC input is deterministic CBOR of the install-result map with `confirmation` absent, not null or empty. `proof_of_possession` is ECDSA-P256-SHA256 over `SHA-256(UTF8("ACP enrollment install proof v1") || transcript_hash || credential_id_ascii)`. The commissioner verifies HMAC and signature with the exact staged identity key and accepts the map once per attempt only after the candidate durably commits and reads back the credential. Any other status uses an externally generic authenticated failure response, not this success map.

## 7. Persistent identifiers

Public-key input is canonical RFC 5480 DER SubjectPublicKeyInfo using `id-ecPublicKey`, `prime256v1`, and an uncompressed 65-byte ECPoint in the BIT STRING. `identity_key_id` is `sha256:` followed by lowercase hexadecimal SHA-256 of that DER. `credential_id` is `sha256:` followed by lowercase hexadecimal SHA-256 of the complete canonical credential bytes (DER leaf certificate for Full profile; signed compact-credential object for Lightweight).

The stable device identity tuple is `(trust_domain_id, node_id, identity_key_id, credential_id)`. `instance_id` and operator/participant assignment are excluded.

## 8. Full-profile X.509

- Root and intermediate CA keys and leaf keys use P-256 ECDSA.
- Signatures use ECDSA with SHA-256, strict DER encoding, and low-S normalization/rejection.
- Root CA `basicConstraints` is critical, `CA:TRUE`; path length is at most 1.
- Intermediate CA `basicConstraints` is critical, `CA:TRUE`, `pathLenConstraint:0`.
- Leaf `basicConstraints` is critical, `CA:FALSE`.
- Leaf `keyUsage` is critical and contains only `digitalSignature`.
- Leaf EKU contains both `clientAuth` and `serverAuth` in version 1.
- Leaf SAN contains exactly one ACP identity URI: `urn:aurora:acp:node:<trust-domain-uuid>:<node-uuid>` using lowercase canonical UUID text.
- Common Name is never used for ACP identity.
- Subject Key Identifier is RFC 7093 method 1: the leftmost 160 bits of SHA-256 over the `subjectPublicKey` BIT STRING contents. Authority Key Identifier contains only a `keyIdentifier` equal to the issuer SKI.
- Full-profile version 1 encodes no role constraints in X.509. Its credential-constraint term is the universal set, so local trust-domain policy provides all role/permission narrowing. A future credential extension requires an assigned OID, closed DER schema, vectors, and reviewed profile version.
- Certificate serials are positive, nonzero, unpredictable 128-bit values with DER sign-padding as needed.
- Leaf validity defaults to 90 days and MUST NOT exceed 397 days. Issuers backdate `notBefore` by at most two minutes for operational skew.
- SHA-1, RSA, DSA, P-384/P-521 leaf keys, wildcard identity, name fallback, unknown critical extensions, and chains longer than three certificates are rejected in version 1.

TLS endpoints require TLS 1.3, mutual certificate authentication, verified chain/domain/SAN/EKU/time/revocation status, and proof of the leaf private key before creating an `AuthenticatedPrincipal`. ACP uses an isolated trust-domain anchor store, not the OS public Web PKI. AIA fetching, DNS-ID, CRLDP, OCSP, CN fallback, and system-root fallback are disabled; ACP signed revocation state is authoritative. TLS 1.3 0-RTT and session resumption are disabled in version 1. Certificate failure never falls back to plaintext.

## 9. HELLO channel binding

The TLS exporter label is the ASCII string `EXPORTER-Aurora-ACP-1.2-HELLO`. The exporter context is SHA-256 of deterministic ACP-CDE-1.2 encoding of the received HELLO after projection into this closed semantic structure:

- top level: exactly `node`, `protocol`, `encodings`, `profiles`, `capabilities`, and `auth`;
- `node`: exactly `node_id`, `instance_id`, `role`, and `name`;
- `protocol`: exactly `min` and `max`;
- each capability/security-capability: exactly `id` and `version`;
- `auth`: exactly `mode`, `trust_domain_id`, `credential_id`, `identity_key_id`, and `security_capabilities`; and
- `auth.channel_binding`, `node.product_version`, and all unknown fields are absent from the projection, never null or empty placeholders.

The receiver preserves the sender's array order for `encodings`, `profiles`, `capabilities`, and `security_capabilities` after field projection; it MUST NOT sort, deduplicate, or reconstruct them from a set. Empty required arrays remain empty; optional projected fields are omitted and never null. The receiver hashes the received projected semantic model, never local capability state or JSON bytes. Exporter output length is 32 bytes.

A transport that cannot expose a correct TLS 1.3 exporter is not Full-profile conformant. There is no exporter fallback in hardened mode.

## 10. Lightweight authenticated channel

Lightweight uses TLS 1.3 mutual Raw Public Key authentication under RFC 7250 with a bounded, signed compact-credential preface. The transport sequence is byte-exact:

1. The client sends `uint16_be credential_length || signed_compact_credential`, then the server sends the same structure. Each length is `1..2048`. No other pre-TLS application bytes are legal.
2. Each side validates the credential and retains its canonical bytes and SPKI before TLS begins.
3. TLS negotiates `RawPublicKey` for both certificate types and proves possession of the exact P-256 SPKI in the validated credential.
4. After TLS Finished and before HELLO, each side sends one encrypted `security.lightweight.finished` envelope. Its payload is a closed map containing `sender_credential_id`, `receiver_credential_id`, `sender_node_id`, `receiver_node_id`, `trust_domain_id`, and `binding`.
5. `binding = HMAC-SHA-256(finished_key, finished_context)`, where `finished_key` is 32-byte TLS exporter output using label `EXPORTER-Aurora-ACP-1.2-LIGHTWEIGHT-FINISHED` and context `SHA-256(finished_context)`. `finished_context` is deterministic CBOR of `[UTF8("ACP lightweight finished v1"), client_credential_bytes, server_credential_bytes, client_der_spki, server_der_spki, client_node_id, server_node_id, trust_domain_id]` in TLS client/server order. SPKIs are the canonical DER SubjectPublicKeyInfo bytes used by `identity_public_key`; IDs are canonical lowercase UUID text.
6. Each peer verifies the HMAC in constant time and requires payload credential IDs, node IDs, trust-domain ID, compact-credential bodies, TLS RPKs, and finished-context values to agree exactly. Any mismatch is `security.authentication_failed`. Later HELLO must repeat the same node/domain/key/credential identity. Ordinary ACP messages are illegal until both finished messages succeed.

The compact credential is a signed deterministic-CBOR object `{body, algorithm, signature}` with no extra or null fields. `body` is a nested closed map, not a byte string. It contains `format`, `serial`, `trust_domain_id`, `node_id`, `identity_algorithm`, `identity_public_key`, `role_constraints`, `permission_policy_id`, `issued_at`, `not_before`, `expires_at`, `issuer_key_id`, and `extensions`. `format` is the literal `acp-compact-credential-v1`; `serial` is uint64; `role_constraints` is a sorted, unique array of 0..16 UTF-8 strings of 1..64 bytes, sorted by encoded UTF-8 bytes. `identity_public_key` is canonical DER SPKI. Times use CBOR tag 0. `extensions` is a map from text OID/name to `{critical: bool, value: bstr}`; unknown critical entries reject. Signature algorithm is `ecdsa_p256_sha256`; signature is low-S strict DER ECDSA over `SHA-256(UTF8("ACP compact credential v1") || body_cbor)`. `credential_id` hashes deterministic CDE of the complete outer object containing the nested body, algorithm, and signature.

TLS 1.3 0-RTT and resumption are disabled. Maximum preface/credential size is 2 KiB; maximum security message is 8 KiB; nesting is 8; collection elements are 64; concurrent enrollment attempts are 1; active credentials are 2 during rotation. If Raw Public Key support or these bounds cannot be demonstrated on the target stack, that target is nonconforming and may not substitute a custom or unauthenticated channel.

This byte contract remains Candidate Freeze 2.1.1 until representative Pico-class hardware demonstrates CSPRNG readiness, bounded RAM/flash/time, Raw Public Key mutual authentication, and transactional protected storage, and an independent reviewer approves the composition.

## 11. Revocation

Revocation state is a deterministic CBOR body signed by the trust-domain authority:

```text
format                    "acp-revocation-snapshot-v1"
trust_domain_id           UUID
epoch                     uint64, strictly increasing
issued_at                 CBOR tag 0 RFC3339 UTC
next_update               CBOR tag 0 RFC3339 UTC
entries                   bounded array sorted by credential_id bytes
previous_snapshot_hash    optional sha256 identifier
issuer_key_id             sha256 identifier
```

Each entry is a closed map containing credential ID, node ID, tag-0 revocation time, stable reason, and an optional replacement credential ID that is omitted rather than null. The signed object is `{body, algorithm, signature}` with `algorithm = "ecdsa_p256_sha256"` and a low-S strict DER signature over `SHA-256(UTF8("ACP revocation state v1") || body_cbor)`. `previous_snapshot_hash` is omitted rather than null. Deltas use `acp-revocation-delta-v1`, identify base and resulting epochs, and MUST produce the same canonical snapshot as a full update.

Nodes persist only a valid increasing epoch. A delta requires `base_epoch == local_epoch` and `result_epoch == local_epoch + 1`. A verified full snapshot may jump to any greater epoch. Rollback, wrong domain, invalid signature, duplicate credential ID, unsorted input, or resource overflow fails closed for new authenticated sessions. Full snapshots are capped at 64 KiB Full/8 KiB Lightweight and 4096/128 entries respectively. Offline policy specifies a maximum snapshot age; there is no implicit grace.

Revocation always prevents the affected credential from establishing future sessions. Active sessions use one frozen version-1 ACP policy: `hardened_terminate` terminates a session when authenticated fresh revocation state identifies its credential, while `explicit_audited_grace` retains that already-authenticated session only under an explicitly configured and audited grace policy. Missing, corrupt, or unknown policy configuration fails closed to `hardened_terminate`. Swift, Rust, and Python MUST implement these exact semantics; a host integration cannot choose different behavior implicitly.

## 12. Clock policy

Clock state is one of `trusted_wall`, `authenticated_checkpoint`, or `untrusted`. A durable checkpoint contains the greatest authenticated UTC time, monotonic counter/boot metadata where available, credential epoch, and revocation epoch. Time may move forward but never behind the checkpoint beyond a two-minute measurement tolerance. Certificate `notBefore` backdating is limited to two minutes, so total acceptance skew is at most four minutes.

Enrollment-window and PAKE-attempt expiry use monotonic deadlines. Commissioner time is accepted only after PAKE confirmation inside protected approval and may initialize an authenticated checkpoint before evaluating the newly issued credential; it never comes from discovery/HELLO and does not silently set the system clock. Production control fails closed when credential validity cannot be evaluated. Degraded behavior is limited to discovery, locally authorized enrollment, and view-only diagnostics.

## 13. Hardened policy and enrollment legality

`trusted_lan` and unilateral `tls` create only an unauthenticated principal. In hardened mode either is rejected with `security.downgrade_forbidden`; absent or stripped Trust capabilities/auth evidence also fail. Peer `auth.mode` must match verified transport evidence. Roles, node IDs, discovery fields, and capabilities are claims/compatibility data and never permission grants.

Enrollment uses a dedicated restricted pre-session state on the ACP endpoint. The ACP 1.2 additive revision MUST mark only `security.enrollment.status`, `begin`, `challenge`, `response`, `confirm`, `approval`, `install_result`, `cancel`, and generic `error.report` legal before ordinary HELLO. The router exposes no Remote/control/resource family and negotiates only `security.enrollment`. A `trusted_lan` HELLO cannot escape this restricted state or authorize control.

Normal Full enrollment concurrency is capped at 2, not 8, because password processing is attacker-triggerable. Each enrollment ID permits five total failed attempts; attempt IDs are globally unique within the candidate's replay-retention window and are consumed on success or any cryptographic failure. Full security messages are capped at 64 KiB, credentials/anchors at 8 KiB, nesting at 16, and collection elements at 4096.

## 14. Authority recovery

Trust-domain identity is the tuple `(trust_domain_id, authority_key_id)`. Recovery must restore both. A newly generated authority key is a new trust domain even if the display name is reused. Authority backups are encrypted, integrity-protected, versioned, and require explicit operator restoration. Quorum signing is out of scope for version 1.

## 15. Compatibility revisions

Aurora Trust requires explicit additive revisions rather than silent reinterpretation:

- `docs/REMOTE.md` changes the authenticated node SAN from legacy `acp://<node-uuid>` to the trust-domain URN in section 8. Legacy `acp://` may be recognized only as unauthenticated migration metadata and never creates an Aurora Trust principal.
- `docs/STATE_MACHINES.md` and registry metadata gain the restricted enrollment pre-session allowlist above.
- Existing `trusted_lan` HELLO vectors remain valid but unauthenticated; hardened policy rejects them.
- `auth.mode = tls` remains decodable for compatibility but never means mutual ACP authentication.
- Security fields remain nested under `auth`; no unknown top-level HELLO field participates in channel binding.

## 16. Provider requirements

Providers must expose opaque signing handles, CSPRNG failure, RFC 9383 SPAKE2+ state, SHA-256, HMAC, HKDF, AES-GCM, P-256 ECDSA, X.509, TLS 1.3 peer evidence, and TLS exporter data as applicable. Production code must not receive raw private-key bytes when the platform can sign internally.

Every provider/version/profile combination requires:

- RFC and ACP vectors;
- malformed point/signature/certificate rejection;
- constant-time and side-channel posture review;
- supported-version/security-advisory policy;
- license and redistribution review;
- target build/run proof; and
- independent security approval.

See `DesignDocs/ACP_Aurora_Trust_M0_Decision_Record.md` for current qualification status and blockers.
