# ACP 1.2 Aurora Trust Security Profile

**Status:** Candidate Freeze 1 — independent security review and target-provider qualification required
**Extension version:** 1.0
**Source design:** `DesignDocs/ACP_Aurora_Trust_Authentication_Implementation_Design.md`

This document is the proposed normative security profile for Aurora Trust. It resolves the wire-level choices that must be common to Swift, Python, and Rust. It MUST NOT be represented as production-approved until the review gates in the Milestone 0 decision record are closed.

## 1. Protocol separation

Discovery is untrusted metadata. Enrollment establishes a device credential. Authentication proves control of the credential's private key. Authorization derives effective permissions locally. Capabilities only describe protocol compatibility.

The authenticated device principal and current human/operator/participant assignment are separate identities. Credential lifecycle operations MUST NOT implicitly mutate cached layouts, show assets, or other asset-conformance state.

## 2. Mandatory algorithms

| Purpose | Candidate Freeze 1 choice |
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

The ACP suite identifier is `ACP-SPAKE2PLUS-P256-SHA256-HKDFSHA256-v1`. Implementations MUST use the RFC 9383 P-256 M and N points, compressed SEC1 point encoding, transcript framing, key schedule, and explicit key-confirmation construction without modification.

No implementation may substitute balanced SPAKE2, ordinary ECDH plus a password hash, SRP, an unauthenticated hash exchange, or a provider-specific PAKE transcript under this suite identifier.

## 3. Bootstrap-secret preparation

The canonical bootstrap secret is 16 uniformly random bytes. Its human form uses uppercase Crockford Base32 without `I`, `L`, `O`, or `U`; ASCII hyphens and ASCII whitespace are presentation-only and are removed before decoding. Decoders accept ASCII lowercase by uppercasing it. All other Unicode normalization, character substitution, and ambiguous-character acceptance are forbidden.

A manual numeric code is exactly 8 to 12 ASCII digits. It is encoded as its ASCII bytes. Numeric codes expire after 10 minutes, permit at most five attempts per enrollment ID, and MUST be protected by the same SPAKE2+ ceremony and online rate limits.

For both forms, the SPAKE2+ ProverSecret is computed using the selected provider's RFC 9383 registration API with:

- `identity` = the 16 raw UUID bytes of the candidate `node_id`;
- `salt` = `SHA-256("ACP SPAKE2+ registration salt v1" || enrollment_id_bytes || candidate_node_id_bytes)`;
- `password` = the decoded 16-byte random secret or ASCII numeric-code bytes; and
- `context` = the ACP enrollment context defined below.

The verifier registration record is ephemeral, scoped to one enrollment ID, and destroyed on consumption, lockout, expiry, or reset. A provider that cannot reproduce the RFC 9383 Appendix C vectors and the future ACP vectors is nonconforming.

## 4. Enrollment context and transcript

The `context` input to RFC 9383 is the deterministic ACP-CDE-1.2 CBOR encoding of this map:

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
```

UUID values follow ACP-CDE-1.2 UUID encoding. The requested-permissions digest is SHA-256 over deterministic CBOR for the complete requested permission object. Empty or absent permission requests use the digest of an empty deterministic CBOR map; they are not encoded as an empty string.

`idProver` is the 16 raw bytes of `candidate_node_id`. `idVerifier` is the 16 raw bytes of `commissioner_node_id`. RFC 9383 constructs `TT` exactly as specified, including its eight-byte little-endian length prefixes.

The ACP enrollment transcript hash is:

```text
SHA-256(ACP-CDE-1.2([
  context_bstr,
  shareP_bstr,
  shareV_bstr,
  confirmV_bstr,
  confirmP_bstr
]))
```

No approval is sent before both RFC 9383 confirmations succeed. `K_shared` is the PAKE output used as IKM for the application schedule; RFC 9383 internal keys are not reused.

## 5. Application key schedule

```text
enrollment_root = HKDF-Extract(
  salt = transcript_hash,
  IKM = K_shared
)

client_confirm = HKDF-Expand(enrollment_root,
  "ACP enrollment client confirm v1", 32)
server_confirm = HKDF-Expand(enrollment_root,
  "ACP enrollment server confirm v1", 32)
approval_key = HKDF-Expand(enrollment_root,
  "ACP enrollment approval AEAD v1", 32)
sas_key = HKDF-Expand(enrollment_root,
  "ACP enrollment SAS v1", 32)
audit_key = HKDF-Expand(enrollment_root,
  "ACP enrollment audit binding v1", 32)
```

All label literals are UTF-8 bytes without a trailing NUL. The two ACP confirmation keys authenticate ACP ceremony messages after RFC 9383 confirmation; they do not replace RFC 9383 confirmation.

## 6. Protected approval

Approval uses AES-256-GCM. Each approval key encrypts at most one approval. The nonce is 12 fresh CSPRNG bytes and is sent in the envelope. Nonce reuse with a key is fatal and consumes the enrollment attempt.

Plaintext is deterministic CBOR containing the fields required by design section 12.4. Associated data is deterministic CBOR containing:

```text
message_type, attempt_id, enrollment_id,
candidate_node_id, commissioner_node_id, trust_domain_id,
acp_version, extension_version, suite, transcript_hash
```

Decryption or tag failure returns the externally generic `security.credential_invalid`, consumes the attempt, and records a locally precise redacted audit code.

## 7. Persistent identifiers

Public-key input is the canonical DER SubjectPublicKeyInfo. `identity_key_id` is `sha256:` followed by lowercase hexadecimal SHA-256 of that DER. `credential_id` is `sha256:` followed by lowercase hexadecimal SHA-256 of the complete canonical credential bytes (DER leaf certificate for Full profile; signed compact-credential object for Lightweight).

The stable device identity tuple is `(trust_domain_id, node_id, identity_key_id, credential_id)`. `instance_id` and operator/participant assignment are excluded.

## 8. Full-profile X.509

- Root and intermediate CA keys and leaf keys use P-256 ECDSA.
- Signatures use ECDSA with SHA-256 and strict DER encoding.
- Root CA `basicConstraints` is critical, `CA:TRUE`; path length is at most 1.
- Intermediate CA `basicConstraints` is critical, `CA:TRUE`, `pathLenConstraint:0`.
- Leaf `basicConstraints` is critical, `CA:FALSE`.
- Leaf `keyUsage` is critical and contains only `digitalSignature`.
- Leaf EKU contains `clientAuth` and/or `serverAuth` according to the issued node use; unexpected use fails validation.
- Leaf SAN contains exactly one ACP identity URI: `urn:aurora:acp:node:<trust-domain-uuid>:<node-uuid>` using lowercase canonical UUID text.
- Common Name is never used for ACP identity.
- Authority Key Identifier and Subject Key Identifier are required.
- Certificate serials are positive, nonzero, unpredictable 128-bit values with DER sign-padding as needed.
- Leaf validity defaults to 90 days and MUST NOT exceed 397 days. Issuers backdate `notBefore` by at most five minutes for operational skew.
- SHA-1, RSA, DSA, P-384/P-521 leaf keys, wildcard identity, name fallback, unknown critical extensions, and chains longer than three certificates are rejected in version 1.

TLS endpoints require TLS 1.3, mutual certificate authentication, verified chain/domain/SAN/EKU/time/revocation status, and proof of the leaf private key before creating an `AuthenticatedPrincipal`. Certificate failure never falls back to plaintext.

## 9. HELLO channel binding

The TLS exporter label is the ASCII string `EXPORTER-Aurora-ACP-1.2-HELLO`. The exporter context is SHA-256 of the canonical ACP-CDE-1.2 HELLO payload with `auth.channel_binding` omitted. The requested exporter length is 32 bytes. JSON peers canonicalize through the same semantic model and deterministic CBOR before hashing.

A transport that cannot expose a correct TLS 1.3 exporter is not Full-profile conformant. There is no exporter fallback in hardened mode.

## 10. Lightweight authenticated channel

Candidate Freeze 1 selects TLS 1.3 mutual Raw Public Key authentication under RFC 7250, preceded by a bounded compact-credential exchange:

1. Each peer sends its signed compact credential in an ACP security preface capped at 2 KiB per credential.
2. Each peer validates authority signature, trust domain, time/clock policy, revocation epoch, role constraints, and critical extensions.
3. TLS 1.3 negotiates `RawPublicKey` for client and server certificate type and proves possession of the exact P-256 key in the validated credential.
4. The peer rejects any mismatch between the preface credential key, TLS Raw Public Key, and later HELLO node ID.
5. The transcript binds `SHA-256(compact_credential_bytes)` for both peers into the first encrypted ACP security-finished exchange. Ordinary ACP messages are illegal before that exchange succeeds.

TLS 1.3 0-RTT is forbidden. Resumption is disabled in version 1 unless a later additive profile specifies credential/revocation revalidation. Maximum handshake/preface buffers and chain/credential counts follow the Lightweight limits in the source design.

This section remains blocked from production freeze until representative Pico-class hardware demonstrates bounded memory/time behavior and an independent reviewer validates the preface-to-TLS binding. If Raw Public Key support is unavailable on a target stack, that target is nonconforming; it may not substitute an unauthenticated or custom channel.

## 11. Revocation

Revocation state is a deterministic CBOR body signed by the trust-domain authority:

```text
format                    "acp-revocation-snapshot-v1"
trust_domain_id           UUID
epoch                     uint64, strictly increasing
issued_at                 RFC3339 UTC
next_update               RFC3339 UTC
entries                   bounded array sorted by credential_id bytes
previous_snapshot_hash    optional sha256 identifier
issuer_key_id             sha256 identifier
```

Each entry contains credential ID, node ID, revocation time, stable reason, and optional replacement credential ID. The signature object contains the body bytes, algorithm ID, and signature. Deltas use `acp-revocation-delta-v1`, identify base and resulting epochs, and MUST produce the same canonical snapshot as a full update.

Nodes persist only a valid increasing epoch. Rollback, wrong domain, invalid signature, duplicate credential ID, unsorted input, or resource overflow fails closed for new authenticated sessions. Offline policy specifies a maximum snapshot age; there is no implicit grace. Critical revocation may terminate active sessions according to local policy.

## 12. Clock policy

Clock state is one of `trusted_wall`, `authenticated_checkpoint`, or `untrusted`. A durable checkpoint contains the greatest authenticated UTC time, monotonic counter/boot metadata where available, credential epoch, and revocation epoch. Time may move forward but never behind the checkpoint beyond a configured two-minute measurement tolerance.

Commissioner time is accepted only inside an authenticated enrollment or session and only as a bounded input; it does not silently set the system clock. Production control fails closed when credential validity cannot be evaluated. Degraded behavior is limited to discovery, enrollment allowed by local physical/administrative policy, and view-only diagnostics.

## 13. Authority recovery

Trust-domain identity is the tuple `(trust_domain_id, authority_key_id)`. Recovery must restore both. A newly generated authority key is a new trust domain even if the display name is reused. Authority backups are encrypted, integrity-protected, versioned, and require explicit operator restoration. Quorum signing is out of scope for version 1.

## 14. Provider requirements

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
