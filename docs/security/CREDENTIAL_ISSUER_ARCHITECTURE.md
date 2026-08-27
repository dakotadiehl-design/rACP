# ACP Credential Issuer and Trust-Domain Authority Architecture

Status: architecture revision complete; implementation impact identified  
Scope: ACP Full-profile credential issuance across all applications and language families  
Baseline reviewed: `834d78542aaeba2cc3d38f8a331bbe5b8f7d5d24` plus the uncommitted issuer work present on 2026-08-27  
Decision date: 2026-08-27

This record is normative for ACP version 1 credential issuance. It replaces the earlier assumption that production ACP requires an external HSM, dedicated macOS authority host, separately signed authority daemon, recoverable identical CA private key, or Prism-owned certificate authority. Those remain possible host-hardening choices; none is an ACP interoperability requirement.

This revision changes architecture and qualification requirements only. It authorizes no wire change and makes no claim that the implementation-impact items in section 28 are complete.

## 1. Security objective

ACP establishes a trust domain whose cryptographic authority is independent of the application or platform hosting it:

```text
ACP trust domain
    |
    +-- Trust-domain authority
    |     owns credential-signing capability
    |
    +-- Commissioner(s)
    |     conduct authorized enrollment
    |
    +-- Candidate(s)
    |     request enrollment
    |
    +-- Authenticated/trusted peers
          Prism
          Remote
          Conductor
          Bridge
          Lyric
          future ACP nodes
```

One application may perform several roles in a deployment, but the roles remain distinct in protocol models, persisted state, authorization decisions, and evidence:

```text
Commissioner != Authority
Authenticated peer != Commissioner
Enrolled controller != Issuer
Human approval != Authentication != Trust
```

Trust remains:

```text
valid confirmed enrollment
+ same-ceremony, unexpired, one-shot approval when required
+ policy-controlled credential issuance
+ durable transactional installation and reload
+ authenticated installation confirmation and possession proof
```

Approval, credential issuance, local storage, or possession of an enrolled controller credential is never independently sufficient to create an authenticated principal, production session, trusted peer, or issuance capability.

## 2. Application-neutral authority model

An ACP trust-domain authority is the logical owner of:

- one trust-domain identifier and its public trust anchor;
- the corresponding credential-signing capability;
- fixed credential policy;
- authorization consumption and serial reservation;
- issuance and revocation journals;
- authoritative revocation state.

ACP does not prescribe which product hosts this role, which process owns it, or how its private key is protected. The authority may be embedded in an application, isolated in a helper, hosted by another ACP application, or backed by platform hardware, a TPM, an HSM, or a managed service. Those choices must not alter portable artifacts or validation semantics.

The first Apple deployment may co-locate roles:

```text
Prism
+-- ACP node
+-- commissioner
+-- trust-domain authority host
```

This is a deployment choice. `Prism == authority` is not a protocol invariant, and portable names and structures must not encode that equivalence.

Every API and persisted model must preserve separate commissioner and authority identities. Conceptually:

```text
ACPCommissionerIdentity
    nodeID
    credential
    enrollment authorization

ACPTrustDomainAuthorityIdentity
    authorityKeyID
    trustDomainID
    publicAnchor
    host-private signingProviderReference
```

The provider reference is host-private and is never portable evidence or a wire field.

## 3. Frozen version-1 protocol constraints

This revision preserves the existing frozen security behavior:

- A trust domain is cryptographically identified by `(trust_domain_id, authority_key_id)`. A display name does not preserve identity.
- Enrollment binds enrollment and attempt identifiers, both node and instance identifiers, trust domain, suite, requested role/permissions digest, candidate P-256 algorithm, identity-key identifier, canonical SPKI, and SPAKE2+ share.
- Protected approval binds the transcript hash and repeats the ceremony, parties, domain, suite, algorithm, and key identifiers in AEAD associated data.
- Approval transports one `x509_der` credential and one trust anchor. AIA, CRLDP, OCSP, public-Web-PKI fallback, and system-root fallback remain disabled.
- Installation succeeds only after durable commit/readback, an HMAC under `candidate_confirm`, and a P-256 possession proof made by the staged candidate key.
- `commissioner_confirm` remains reserved; version 1 has no commissioner receipt message.
- At most two Full-profile credentials overlap during rotation.
- Revocation state is signed, authority-bound, and monotonically increasing.
- Existing transcript, key-schedule, canonical CBOR, and canonical JSON rules remain unchanged.

No host key-custody choice may weaken these rules.

## 4. Portable cryptographic artifacts

Wire-level ACP security artifacts are platform-neutral data:

- Canonical P-256 public keys use RFC 5480 SubjectPublicKeyInfo.
- X.509 certificates and trust anchors use DER.
- Signatures use standard ECDSA with SHA-256, strict DER parsing, and low-S enforcement.
- Identifier text is lowercase `sha256:` followed by 64 lowercase hexadecimal characters.
- `identity_key_id` is SHA-256 of canonical SPKI.
- `credential_id` is SHA-256 of the complete credential bytes.
- ACP objects use the frozen canonical CBOR and JSON representations.
- SPAKE2+, approval, installation-confirmation, possession-proof, revocation, and transcript contexts use their frozen byte strings and projections.

No `SecKey`, Keychain reference, Secure Enclave handle, Swift object, Rust ownership token, Python object identity, PKCS#11 handle, HSM object identifier, filesystem path, daemon endpoint, or cloud resource name may appear in portable evidence or wire semantics.

## 5. Certificate profile

The Full-profile version-1 node credential is an X.509 v3 end-entity certificate:

- Chain: leaf plus the isolated self-signed trust-domain anchor. The version-1 approval has no intermediate-chain field.
- Keys: anchor and leaf use P-256 ECDSA.
- Signature: ECDSA-SHA256, strict DER, low-S.
- Leaf Basic Constraints: critical, exactly `CA:FALSE`.
- Leaf Key Usage: critical, exactly `digitalSignature`.
- Leaf EKU: exactly `clientAuth` and `serverAuth`.
- SAN: exactly one URI, `urn:aurora:acp:node:<trust-domain-uuid>:<node-uuid>`, using canonical lowercase UUIDs.
- Subject: fixed non-identifying `O=Aurora ACP Node`; CN is not an identity source.
- Stable node identity tuple: `(trust_domain_id, node_id, identity_key_id, credential_id)`.
- Serial: positive, nonzero, unpredictable 128-bit value. DER sign padding is not part of those 128 bits.
- SKI: RFC 7093 method 1, the leftmost 160 bits of SHA-256 over subjectPublicKey BIT STRING contents.
- AKI: only `keyIdentifier`, exactly equal to the anchor SKI.
- Validity: default 90 days, never over 397 days, capped by anchor expiry; backdating is at most two minutes.
- Extensions: only Basic Constraints, Key Usage, EKU, SAN, SKI, and AKI.
- Rejection includes unknown critical extensions, SHA-1, RSA, DSA, non-P-256 keys, wildcard identity, malformed/high-S signatures, and wrong chain/domain/time/KU/EKU/SKI/AKI/revocation state.

Version 1 uses a one-tier hierarchy because it transports only a leaf and one anchor and forbids chain discovery. Intermediates, delegation, cross-signing, and authority continuity certificates require a separately reviewed wire revision.

## 6. Certificates identify nodes, not permissions

Certificates establish cryptographic node identity and trust-domain membership. They do not grant Prism control, cue or blackout control, commissioner status, administrative status, Conductor authority, Remote permissions, fixture control, or issuance authority.

Requested role and permissions digest may be retained as enrollment audit and local-policy inputs where already frozen, but no application permission or controller role is added to the certificate. Runtime permissions are the intersection of authenticated identity, credential state, local policy, negotiated capability, and safety policy.

An enrolled controller receives no signing capability merely because its credential is valid.

## 7. Authority hierarchy and provisioning

Each version-1 trust domain has one self-signed P-256 anchor that directly signs node credentials and revocation state. It is scoped to a deliberately created trust domain, not implicitly to an application, show, commissioner, installation, operating system, or language.

The anchor is transported inside the PAKE-protected approval and accepted only when its computed authority-key ID equals the authority identity bound into the confirmed ceremony. Candidates learn authority through that ceremony, not discovery, TOFU, public PKI, or application callbacks.

The host chooses how a domain is provisioned. The default deployment should generate the domain automatically without requiring external hardware, a cloud account, an authority daemon, or an operator-managed PKI ceremony.

## 8. Host key-custody policy

Key custody is host policy rather than protocol behavior. A conforming host must:

- use P-256 and produce conforming ECDSA-SHA256 signatures;
- prevent signing before authority identity and policy are validated;
- expose no private-key bytes through portable or application-facing APIs;
- verify returned signatures and reject malformed or high-S results;
- fail closed on missing, locked, mismatched, corrupt, or unsupported key state;
- record the actual storage posture for local diagnostics and qualification;
- never silently claim a stronger posture than it provides.

Valid host choices include Secure Enclave, a non-exportable Keychain key, another OS-protected key store, TPM, external HSM, managed HSM, or a separately reviewed protected software store. HSMs and separate daemons are optional hardening choices, not baseline requirements.

### Initial Apple policy

The automatic Prism-hosted deployment uses this closed, ordered selection:

```text
Secure Enclave available + supported + qualified
        -> Secure Enclave non-exportable P-256 key

Secure Enclave unavailable or unsupported
        -> non-exportable Keychain-backed P-256 key

Neither secure custody path available
        -> FAIL CLOSED
```

Qualification records the mechanism actually selected. Apple version 1 has no fallback to an exportable software key, file-backed key, ephemeral key, or any other weaker custody mechanism. Keychain fallback is automatic and observable and does not require show-time hardware provisioning. The authority signing capability remains behind a narrow package-owned provider interface even when the commissioner and authority are in one process.

Candidate keys follow the same host-policy principle: the candidate owns its key, only canonical SPKI leaves it, and cancellation or failed installation removes an uncommitted pending key.

## 9. Accepted recovery tradeoff

ACP version 1 does not require restoration of the same private authority key after catastrophic host loss:

```text
non-exportable authority key lost
        |
        v
old authority cannot be reconstructed
        |
        v
new authority key created
        |
        v
new trust-domain identity
        |
        v
nodes deliberately re-enrolled
```

This is intentional. ACP does not add key export, backup, transfer, cross-signing, or continuity semantics merely to avoid re-enrollment. A host may provide protected backup or redundant HSM custody, but restoring the same domain is valid only when the exact authority public key and anchor are recovered. A newly generated key always creates a new trust domain.

If loss might be compromise, the old domain is treated as compromised and rejected through local reset/deny policy. A signature made by the lost or compromised authority is not trusted to announce its own replacement.

## 10. Conductor and future authority hosts

The initial Conductor relationship is:

```text
existing trust domain
authority host = Prism

Conductor
    -> enrolls as an ACP peer/controller
    -> receives a normal node credential
    -> receives no issuer authority
```

Conductor permissions are local application policy, not certificate extensions. It may commission enrollment only if explicitly authorized as a commissioner; authentication alone does not confer that role.

A later deployment may choose Conductor as its authority host without changing portable certificate or revocation semantics. Under version 1, changing from a non-exportable Prism authority key to a newly generated Conductor authority key creates a new trust domain and requires explicit re-enrollment.

Version 1 does not define authority transfer, delegated intermediate CAs, cross-signing, trust-domain handoff, or proprietary continuity certificates. Any such mechanism is a protocol revision with separate threat analysis and cross-language vectors.

Conductor can therefore join an existing domain as an authenticated peer/controller without changing existing certificates or resetting that domain. It cannot inherit ownership of Prism's non-exportable authority key. Unless a future separately reviewed authority-transfer protocol exists, making Conductor the authority means creating a new trust domain and explicitly re-enrolling its members.

## 10.1 Frozen active-session revocation policy

Revocation always prevents the revoked credential from establishing a future authenticated session. The version-1 hardened policy identifier is `hardened_terminate`: after authenticated, fresh revocation state identifies the credential used by an active session as revoked, that session is terminated. The only version-1 alternative is `explicit_audited_grace`; it retains the already-authenticated session for the explicitly configured and audited grace policy but still rejects every future session using that credential.

This is ACP policy, not a Swift callback choice. A deployment must select the policy explicitly, persist and audit any selection other than `hardened_terminate`, and apply the same semantics in Swift, Rust, and Python. Absence, corruption, or an unknown policy value fails closed to `hardened_terminate`.

## 11. Issuance authorization and request model

Issuance accepts only sealed evidence created by validated enrollment machinery. The authority consumes closed facts including:

- opaque authorization, enrollment, and globally unique attempt IDs;
- transcript hash;
- candidate and commissioner node and instance identities kept separately;
- trust-domain ID and expected authority-key ID;
- canonical candidate SPKI and recomputed identity-key ID;
- fixed credential profile;
- approved requested role/permissions digest for audit and local policy only;
- approval ID, time, expiry, and cancellation generation;
- initial, renewal, or key-rotation purpose and replacement credential ID where applicable.

The request contains no arbitrary SAN, subject, issuer, validity, serial, extension, KU, EKU, algorithm, anchor, application permission, or signing-provider handle.

The commissioner may carry authorization evidence but cannot manufacture it. Authority identity is not inferred from commissioner identity. Durable consumption and authority-scoped serial reservation occur as one logical transaction before signing; exact retry may return only the previously journaled result.

## 12. Issuance and identifier rules

The issuer constructs every security-critical certificate field from fixed policy and validated facts. It draws 16 unconstrained random bytes for the serial, rejects all-zero and authority-local collisions, and encodes a leading DER sign octet when required without reducing randomness.

After construction it reparses and independently validates the leaf, chain, identifiers, policy, signature, and authorization bindings before journaling success. Language-specific certificate libraries are implementation choices; generated DER must match the portable profile and shared fixtures.

The issued package is immutable, non-secret validated evidence containing leaf DER, anchor DER, IDs, serial, validity, transcript, authorization and ceremony bindings, and replacement metadata. It contains no private key, password, provider handle, storage locator, mutable extension description, or public success constructor.

## 13. Secure delivery, installation, and trust commitment

The leaf maps to approval `credential`; the self-signed anchor maps to `trust_anchor`. Delivery uses the frozen one-shot AES-256-GCM approval protection derived from the confirmed SPAKE2+ ceremony. The coordinator cannot substitute bytes after issuance.

Candidate installation is:

```text
decrypt and validate exact approval/package
-> reload pending key for the attempt
-> compare SPKI and identity-key ID
-> validate leaf and isolated anchor
-> durably install certificate/key locator
-> reload and validate the identity
-> sign and verify the frozen possession proof
-> return sealed durable-install evidence
```

The commissioner commits trust only after validating the live one-shot attempt, exact install-result fields, `candidate_confirm` HMAC, possession proof, certificate, domain, node, and credential. Issuance, delivery, Keychain/filesystem writes, and human approval are not trust.

Evidence-fabrication resistance is semantic across languages: downstream code must not be able to construct issuance success, installation success, possession success, revocation success, authenticated principals, authenticated connections, or trust commitment without validated machinery.

## 14. Journaling and crash recovery

The authority journal uses monotonic states such as `reserved`, `signed`, `delivered`, `installed-receipt-verified`, `closed`, and `revoked`. It is an issuance/idempotency ledger, not a peer-trust database.

- Authorization consumption and serial reservation are durable before signing.
- The same authorization never signs two different packages.
- Unused reservations are never reassigned.
- A crash after issuance permits only exact redelivery while the attempt remains safely recoverable; otherwise the orphan credential is revoked and enrollment restarts.
- Candidate recovery removes uncommitted artifacts and reloads committed identities before producing evidence.
- Commissioner recovery observes durable peer trust before closing the matching journal entry.

Persisting PAKE-derived keys is a separately qualified host choice. Version 1 may instead fail and re-enroll; it must not serialize confirmation capabilities through public APIs.

## 15. Revocation, renewal, and replacement

The authority maintains one durable, authority-bound revocation epoch/log. Consumers accept only valid increasing epochs for the correct domain and authority, persist before exposure, and fail closed for rollback, staleness, malformed state, or invalid signatures. Hardened deployments terminate affected active sessions.

Renewal requires an authenticated, non-revoked current credential and current-key proof. Key rotation additionally binds the requested new SPKI. Node and domain IDs remain stable within the domain; credential and possibly identity-key IDs change. At most two credentials overlap, and failure before activation leaves the old credential active.

Replacement relationships are ACP metadata and revocation state, not X.509 permission extensions. Renewal or replacement under a different authority is cross-domain and rejected unless a future protocol revision explicitly defines otherwise.

## 16. Normative classification: protocol versus host policy

| Concern | ACP wire/protocol requirement | Host implementation/key-custody policy |
|---|---|---|
| Trust-domain identity | `(trust_domain_id, authority_key_id)` and bound anchor | Where domain metadata is stored |
| Public keys | Canonical RFC 5480 P-256 SPKI | Key generation API and provider handle |
| Certificates | Frozen X.509 fields and DER transport | Certificate library and process layout |
| Signatures | ECDSA-SHA256, strict DER, low-S | Secure Enclave, Keychain, TPM, HSM, cloud service |
| Identifiers | Frozen lowercase SHA-256 derivations | Local indexes and display names |
| Enrollment | Frozen SPAKE2+, transcript, approval, and attempt bindings | UI and operator workflow |
| Installation | Frozen result, confirmation, and possession contexts | Key store, transaction mechanism, storage posture |
| Revocation | Representation, signature context, authority binding, increasing epoch | Publication transport, polling, storage backend |
| Renewal/replacement | Identity and overlap semantics | Scheduling and user presentation |
| Encodings | Canonical CBOR/JSON and DER | Codec library |
| Evidence boundary | Success only from validated machinery | Swift/Rust/Python sealing technique |
| Availability | Fail closed when required security state is unavailable | Redundancy, daemon, connector, retry policy |
| Recovery | New key means new domain; explicit re-enrollment | Backup, hardware redundancy, custody procedure |
| Audit | Security-relevant outcomes must be attributable | Sink, retention, OS logging, HSM audit |

Host policy must never silently become an interoperability condition.

## 17. Cross-language conformance rule

ACP security artifacts produced by one conforming implementation must be consumable and validated by another conforming implementation without platform-specific translation.

Swift, Rust, Python, and future language families must interoperate for canonical SPKI, authority/node/credential identities, anchors, leaf certificates, chains, issuance metadata, approval projection, installation confirmation, possession proof, revocation snapshots and epoch chains, renewal, replacement, and cross-domain rejection.

No implementation receives a conformance PASS solely by round-tripping its own output. Every production language family must consume positive and negative artifacts from at least one other independent producer. Where a family cannot generate an artifact, it must still validate externally produced fixtures.

## 18. Compatibility matrix

| Concern | Swift | Rust | Python | Future Conductor/other hosts |
|---|---|---|---|---|
| Portable models | Reference implementation currently strongest | Must add equivalent issuance/revocation models | Must add equivalent issuance/revocation models | Use the same schemas and identifiers |
| Artifact production | May produce SPKI, certificates, approval/install, revocation | Must produce designated non-Apple fixture families or document consumer-only scope | Must produce designated independent fixture families | May produce once implementation qualifies |
| Artifact consumption | Must validate Rust/Python-produced artifacts | Must validate Swift/Python-produced artifacts | Must validate Swift/Rust-produced artifacts | Must validate shared fixtures before authority hosting |
| Key custody | Apple provider policy; Secure Enclave/Keychain preferred | Host-specific protected provider | Host-specific protected provider | Host/platform-specific; never encoded on wire |
| Certificate validation | Strict Apple validator plus portable vectors | Strict independent DER/X.509 validator required | Strict independent DER/X.509 validator required | Same portable profile and negatives |
| Signing | Package-owned provider, fixed policy | Abstract provider with sealed issuance result | Opaque provider/factory boundary | Required only when hosting authority |
| Revocation | Produce and consume authority-bound epochs | Consume and eventually produce shared format | Consume and eventually produce shared format | Consume always; produce only as authority |
| Evidence sealing | Visibility and non-Codable/non-forgeable capabilities | Private modules, ownership, non-cloneable evidence | Opaque runtime objects and guarded factories | Equivalent language mechanism |
| Fixture duty | Cross-consume and publish provenance | Cross-consume and publish provenance | Cross-consume and publish provenance | Cross-consume before production qualification |
| Authority-host capability | Initial Prism-hosted implementation | Optional future host | Reference/tooling or optional host | Conductor may host a new domain without wire changes |

Language support levels may differ temporarily, but unsupported generation never permits relaxed validation.

## 19. Shared conformance fixture layout

Portable artifacts belong with existing vectors; qualification reports remain under `qualification/`:

```text
vectors/security/conformance/
+-- manifest.schema.json
+-- manifest.json
+-- authorities/
+-- spki/
+-- certificates/
+-- credentials/
+-- issuance/
+-- approval/
+-- installation/
+-- possession/
+-- revocation/
+-- renewal/
+-- replacement/
+-- trust-domains/
+-- negatives/
+-- generation/
    +-- README.md
    +-- deterministic-inputs/

qualification/security-conformance/
+-- swift-<version>.json
+-- rust-<version>.json
+-- python-<version>.json
+-- future-host-<version>.json
```

Artifacts may use `.der`, `.spki.der`, `.cbor`, `.json`, `.sig.der`, or another explicitly registered canonical encoding. The manifest is authoritative; filenames carry no security meaning.

The full corpus is a later implementation task. Existing `vectors/security/` fixtures remain valid and are referenced rather than silently duplicated.

## 20. Fixture manifest schema

`manifest.json` is canonical UTF-8 JSON with sorted object keys and no insignificant rewriting. Its conceptual schema is:

```json
{
  "fixture_set_version": "1.0.0",
  "acp_protocol_version": "1.2",
  "acp_security_version": "1.0",
  "schema": "manifest.schema.json",
  "fixtures": [
    {
      "id": "x509.leaf.swift.primary",
      "artifact_type": "x509_leaf_der",
      "path": "certificates/leaf-swift-primary.der",
      "producer": {
        "implementation": "aurora-acp-swift",
        "language": "swift",
        "version": "<version>",
        "source_commit": "<commit>"
      },
      "provenance": {
        "method": "generated",
        "tool": "<tool-and-version>",
        "source": "<source-or-script>",
        "deterministic_inputs": ["generation/input-primary.json"]
      },
      "canonical_encoding": "x509_der",
      "sha256": "<64-lowercase-hex>",
      "dependencies": ["authority.swift.primary", "spki.rust.node-primary"],
      "expectation": {
        "result": "accept",
        "error_category": null
      },
      "identities": {
        "trust_domain_id": "<canonical-uuid>",
        "authority_key_id": "sha256:<digest>",
        "node_id": "<canonical-uuid>",
        "identity_key_id": "sha256:<digest>",
        "credential_id": "sha256:<digest>"
      },
      "compatibility_notes": []
    }
  ]
}
```

Required top-level fields are fixture-set version, ACP protocol/security versions, schema reference, and fixtures. Required fixture fields are ID, artifact type, producer implementation/language, producer version or source commit where applicable, path, canonical encoding, SHA-256, dependencies, expected result, provenance, relevant identities, and compatibility notes. Negative fixtures require a stable expected ACP error category; they must not depend on platform-native error text.

Private keys and live secrets are forbidden. Synthetic private material needed for deterministic frozen vectors must be clearly marked non-production, isolated under deterministic inputs, excluded from production packages, and referenced only where an existing frozen vector or reviewed generation procedure requires it.

## 21. Provenance and independence

Every fixture states whether it was generated, derived, or hand-authored; what tool and implementation produced it; the source version/commit; deterministic inputs where applicable; and expected consumer behavior.

Hand-authored binary cryptographic artifacts require an explanation and independent structural verification. Derived mutations identify their positive parent and exact mutation operation. A fixture producer and consumer using the same underlying library do not by themselves establish independent conformance; qualification reports disclose shared dependencies.

The manifest dependency graph must be acyclic and resolve every referenced fixture. Consumers verify file hashes before interpretation.

## 22. Cross-producer assignment

The initial minimum assignment is:

```text
Swift-produced certificate and installation artifacts
    -> Rust validates
    -> Python validates

Rust-produced canonical model/issuance artifacts
    -> Swift validates
    -> Python validates

Python-produced revocation and negative mutations
    -> Swift validates
    -> Rust validates
```

Final producer assignments may change based on library capability, but each production family must consume another producer and the overall graph must contain more than one independent producer. A future Conductor implementation must pass the shared consumer suite before it can host an authority.

## 23. Required positive fixture families

The shared corpus must cover:

- self-signed root/authority certificate and authority-key ID;
- leaf/node certificate and complete chain;
- canonical P-256 SPKI and node identity-key ID;
- credential ID over exact DER;
- issuance facts/request projection and issued-package metadata;
- approval plaintext/AAD projection;
- installation-result HMAC;
- possession-proof digest and signature;
- revocation snapshot and multi-epoch hash chain;
- non-rotation renewal;
- key rotation and credential replacement;
- two distinct trust domains proving separation.

## 24. Required negative fixture families

The shared corpus must reject:

- malformed DER and noncanonical SPKI;
- wrong curve;
- malformed and high-S ECDSA signatures;
- wrong anchor, trust domain, or cross-domain credential;
- wrong node binding or malformed SAN;
- wrong KU, EKU, or Basic Constraints;
- invalid SKI or AKI;
- expired, not-yet-valid, or revoked credentials;
- wrong approval projection;
- wrong installation confirmation or possession proof;
- malformed revocation chain or stale epoch;
- renewal under the wrong authority;
- replacement bound to the wrong node or identity.

Mutations must target one intended invariant where practical and must not introduce new wire semantics.

## 25. Determinism and versioning

Fixture generation uses fixed synthetic timestamps, canonical UUIDs, fixed deterministic inputs, stable field ordering, and documented serial inputs. Deterministic ECDSA generation may be used by tooling, but deterministic signing is not a wire requirement. Expected artifacts are immutable once frozen.

Changing bytes, expected outcomes, identifier derivation, canonical encoding, or fixture semantics requires a fixture-set version change and review. Additive fixtures may use a compatible minor version; breaking reinterpretation requires a major version. Editorial manifest notes may use a patch version when artifact hashes and expectations do not change.

Generators write candidate output to a review location and never overwrite frozen fixtures automatically. A mismatch triggers implementation or specification review. Regeneration is not an acceptable test update by itself.

Qualification reports record every fixture, consumer implementation/version, result, error category for negatives, dependency versions, and execution platform. Frozen manifests and reports are included in release provenance.

## 26. Cross-language evidence-boundary qualification

Each language demonstrates that untrusted downstream callers cannot fabricate successful security evidence:

- Swift: package/private initializers, sealed reference capabilities, no serialization of one-shot secrets.
- Rust: private fields/modules, ownership consumption, non-cloneable evidence where replay matters.
- Python: opaque runtime objects, provenance sentinels, guarded factories, and no release test escape hatch.
- Future languages: an equivalent reviewed construction boundary.

Static checks alone are insufficient. Negative tests must attempt direct construction, replay, serialization, mutation, cross-domain substitution, and bypass of validated factories. Semantic results and error categories must align even when language mechanisms differ.

## 27. Threat model after this revision

| Threat | Required mitigation |
|---|---|
| Application-name coupling | Authority and commissioner roles use ACP identities, never Prism/Conductor identity as protocol authority |
| Enrolled controller becomes issuer | Credentials carry no issuance permission; signing capability is separately provisioned |
| Cross-language drift | Shared manifest, independent producers, cross-consumer qualification |
| Platform type leaks onto wire | Portable artifact classification and fixture validation |
| Approval or ceremony replay | Sealed one-shot authorization and durable journal binding |
| CSR/SAN/key substitution | Closed issuance facts and issuer-constructed certificate fields |
| Installation fabrication | Durable reload, HMAC confirmation, exact possession proof, sealed evidence |
| Revocation rollback | Authority/domain binding, increasing epoch, durable acceptance |
| Authority-key loss | New domain and explicit re-enrollment; no continuity fiction |
| Authority-key compromise | Stop issuance, locally reject old domain, create new domain and re-enroll |
| Weaker host custody | Honest storage posture, qualification, fail-closed provider behavior |
| Fixture monoculture | Cross-producer graph and shared-dependency disclosure |

## 28. Current implementation-impact report

The following committed and uncommitted AuroraACP work was inspected. No implementation is changed by this revision.

| File/type | Current assumption or gap | Required follow-up |
|---|---|---|
| `Sources/AuroraACP/Security/ACPCredentialIssuance.swift` — `ACPIssuanceCeremonyFacts`, `ACPIssuanceAuthorization`, `ACPIssuedCredentialPackage`, `ACPCredentialIssuing`, `ACPIssuanceJournal` | Names are application-neutral and commissioner/authority IDs are separate. Models and sealed evidence exist only in Swift; the gate currently accepts validated booleans/closure from package code. | Freeze a portable semantic model; ensure production enrollment machinery is the only authorization producer; define Rust/Python equivalents and fixture projections without serializing capabilities. |
| Same file — `ACPEnrollmentInstallVerifier`, `ACPVerifiedEnrollmentInstallResult` | Correctly seals confirmation in Swift but has no cross-language conformance model. | Add shared install-confirmation fixtures and equivalent non-forgeable consumer boundaries. |
| `Sources/AuroraACP/Security/ACPRevocationPublisher.swift` — `ACPRevocationPublisher` | Core format is application-neutral but publisher/journal implementation and tests are Swift-only. | Specify portable issuance/revocation metadata and add Rust/Python consumers/producers with epoch-chain fixtures. |
| `Sources/AuroraACPAppleSecurity/ACPAppleCredentialIssuer.swift` — `ACPAppleProtectedSigningKey` | The provider now exposes the selected non-exportable Apple custody posture without implying an external hardware requirement; concrete `SecKey`/Swift Certificates behavior remains Apple-host-specific. | Add the automatic, fail-closed Secure Enclave/Keychain selector and qualification record. |
| Same file — `ACPAppleCredentialIssuer` | Certificate construction is coupled to the Apple implementation, which is acceptable for a host adapter, but it is currently the only issuer producer. | Keep it behind application-neutral semantics and prove DER compatibility through independent fixtures; do not make Swift Certificates an ACP requirement. |
| `Sources/AuroraACPAppleSecurity/ACPAppleEnrollmentCoordinator.swift` — `ACPAppleEnrollmentCoordinator` | Issuer injection keeps authority separate from commissioner conceptually; current in-process shape must not become a wire or daemon requirement. | Integrate only after portable authority/commissioner models are frozen; keep co-location optional and evidence sealed. |
| `Sources/AuroraACPAppleSecurity/ACPAppleIdentityStore.swift` — pending/install evidence types | Apple Keychain and `SecKey` remain in the host adapter and do not leak onto wire. PKCS#12 scaffolding remains broader than the selected candidate-owned key path. | Retain host isolation, qualify transactional recovery, and keep PKCS#12 outside the production enrollment path. |
| `Sources/AuroraACP/Security/ACPSecurityModels.swift` — `ACPStoragePosture` | Storage posture is a portable report, while its realization is host policy. | Keep values semantic and cross-language; prohibit interpreting an Apple class or provider name as wire authority. |
| `Sources/AuroraACP/Security/ACPCredentialLifecycle.swift` — `ACPCredentialAuthority` | Generic compact-credential signer is application-neutral but separate from the sealed X.509 issuance path. | Review naming and evidence boundaries when portable authority models are frozen; enrolled peers must not obtain the signing handle. |
| `Sources/AuroraACP/Security/ACPSecurityProviders.swift` — `ACPSigningKeyHandle` | Generic signing handle is language-neutral in concept but does not yet express authority-provider lifecycle/health semantics. | Define abstract provider semantics only after portable models and fixture requirements; keep handles host-private. |
| `scripts/check_security_api_boundary.py` | Checks Swift issuance sealing and existing Swift/Rust/Python transport evidence, but not cross-language issuance/install/revocation parity. | Extend after equivalent models exist; require all language families and reject product/platform names in portable declarations. |
| `tests/AuroraACPTests/ACPCredentialIssuanceTests.swift` and `tests/AuroraACPAppleSecurityTests/ACPAppleCredentialIssuerTests.swift` | Useful Swift tests, including Apple hardware behavior, but primarily self-produced/self-consumed. | Consume shared foreign-produced positives/negatives and separate Apple host qualification from ACP conformance. |
| `Package.swift` / `Package.resolved` | Swift Certificates and Swift ASN.1 are pinned only for the Apple target, which is appropriate, but no portable fixture tooling target exists. | Keep dependencies host-scoped; later add language-neutral fixture validation tooling without making Apple libraries normative. |
| `rust/acp-security/src/credential.rs` — `X509IssuanceProvider`, `CredentialAuthority.issue_x509` | The reviewed working tree still exposed a raw caller-controlled X.509 issuance callback that Swift had removed. | Remove this surface before qualification; use sealed authorization and fixed issuer policy only. |
| `rust/acp-security/src/*` | Transport/authorization evidence exists; no equivalent sealed credential issuer, strict X.509 profile consumer, install evidence, or revocation publisher conformance layer exists. | Add consumer-first models and independent validation after fixture schema freeze. |
| `python/src/acp/security*.py` | Context and opaque transport evidence exist; issuance/X.509/revocation conformance is incomplete. | Add consumer-first validation and designated independent fixture production after schema freeze. |
| `vectors/security/*` and `qualification/*` | Frozen contexts and some X.509/revocation vectors exist, but there is no provenance-rich cross-producer manifest or result matrix. | Introduce the layout and manifest described here without silently regenerating existing vectors. |

No current type is Prism-specific, and no certificate field currently encodes application permissions. The principal architectural conflicts are the mandatory-HSM language/documentation, the Apple signer’s hardware-specific name, Swift-only issuance evidence, and absent cross-language fixture infrastructure.

## 29. Implementation sequence and qualification gates

Implementation resumes only in this order:

1. Freeze portable trust-domain authority, commissioner, issuance metadata, and revocation semantics.
2. Review those models against existing schemas and confirm that no wire change is required.
3. Freeze `manifest.schema.json`, provenance vocabulary, stable error categories, and producer assignments.
4. Add the shared positive/negative fixture corpus without replacing existing frozen vectors.
5. Implement Swift, Rust, and Python consumers and cross-producer qualification reports.
6. Define abstract authority-signing-provider lifecycle and health semantics; keep provider references host-private.
7. Implement the Apple non-exportable-key provider with Secure Enclave preference and Keychain fallback.
8. Complete the application-neutral issuer and Apple host adapter against shared fixtures.
9. Integrate `ACPAppleEnrollmentCoordinator` with live enrollment authorization and delivery.
10. Complete candidate transactional installation, restart recovery, renewal, and replacement.
11. Run cross-language issuance/revocation qualification and security-boundary bypass tests.
12. Run full process-restart enrollment qualification, then resume S10 closeout.

Qualification gates are:

- **Portable-model gate:** no application/platform types, commissioner/authority conflation, or unresolved wire projection.
- **Fixture gate:** schema reviewed, hashes frozen, provenance complete, negative error categories stable.
- **Cross-language gate:** every production language consumes a foreign producer; no self-round-trip-only PASS.
- **Provider gate:** key identity, lifecycle, failure, low-S, non-exportability claim, and storage posture qualified independently of wire semantics.
- **Issuer gate:** exact certificate profile and package bindings pass independent consumers.
- **Enrollment gate:** confirmation, installation, trust commitment, crash recovery, renewal, and revocation pass end-to-end.
- **Release gate:** boundary checks, dependency provenance, platform qualification, and frozen fixture reports are clean.

## 30. Unresolved decisions

These are implementation or qualification decisions and do not block the application-neutral version-1 architecture:

1. Which independent X.509 libraries will serve as the Rust and Python strict validators.
2. Which producer owns each final fixture family after capability spikes.
3. The exact JSON Schema dialect and stable ACP error-category registry used by the fixture manifest.
4. Which local diagnostics and reset UX communicate authority-key loss and required re-enrollment.
5. Whether a future non-Apple host will initially be consumer-only or qualify as an authority producer.

The following are explicitly not version-1 open questions: authority transfer, cross-signing, delegated intermediates, trust-domain handoff, or continuity certificates. They require a future protocol revision.

## 31. Decision summary

1. ACP owns an application-neutral trust-domain authority model.
2. Authority, commissioner, candidate, authenticated peer, and trusted peer remain separate roles.
3. Prism is the first Apple authority host, not the protocol-defined authority.
4. Conductor initially enrolls as an ordinary credentialed controller and receives no issuer capability.
5. Conductor or another host may later create and host a new trust domain without changing portable semantics.
6. Apple selects a qualified Secure Enclave key first, automatically falls back only to a non-exportable Keychain-backed key, records the selection, and fails closed if neither is available.
7. Loss of a non-exportable authority key creates a new trust domain and deliberate re-enrollment.
8. Certificates identify nodes and domain membership, not application permissions.
9. Wire artifacts and identifiers are portable across Swift, Rust, Python, and future languages.
10. Cross-producer fixtures and foreign-consumer validation are mandatory release evidence.
11. Existing sealed issuance, confirmation, installation, journaling, revocation, and trust boundaries remain required.
12. Version 1 adds no authority migration or delegation wire mechanism.
13. Revoked credentials never establish future sessions; active sessions follow the frozen `hardened_terminate` or explicitly configured `explicit_audited_grace` policy identically in every language.

**ARCHITECTURE REVISION COMPLETE — READY FOR IMPLEMENTATION PLANNING**
