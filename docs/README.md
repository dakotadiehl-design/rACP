# ACP documentation

Status: **Current documentation index**  
Baseline: **ACP 1.2 / Aurora Trust extension 1.0**  
Last verified: **2026-08-27**

This page identifies the documentation that describes ACP as implemented today. Historical plans and review records remain available, but they do not override the current protocol, schemas, or code.

## Authority order

When sources disagree, use this order:

1. Frozen wire schemas, `schema/registry.json`, `schema/constants.json`, and security policy schemas.
2. Normative documents in this directory.
3. Cross-language conformance vectors and executable tests.
4. Current implementation guides.
5. Qualification evidence, which proves only the target and revision it names.
6. Historical material in `DesignDocs/`.

No implementation may silently change a frozen wire rule. Resolve discrepancies through a reviewed protocol revision, updated vectors, and cross-language tests.

## Current normative documents

| Document | Purpose |
|---|---|
| [ACP_SPEC.md](ACP_SPEC.md) | Protocol overview and authority rules |
| [WIRE_ENCODING.md](WIRE_ENCODING.md) | JSON and ACP-CDE-1.2 encoding |
| [STATE_MACHINES.md](STATE_MACHINES.md) | Session, enrollment, sequencing, and recovery |
| [SECURITY.md](SECURITY.md) | Aurora Trust security profile |
| [REMOTE.md](REMOTE.md) | Aurora Remote profile |
| [CAPABILITIES.md](CAPABILITIES.md) | Capability negotiation |
| [ERROR_CODES.md](ERROR_CODES.md) | Stable error and disposition semantics |
| [CONSTANTS.md](CONSTANTS.md) | Canonical catalog ownership |

## Current implementation guides

| Guide | Audience |
|---|---|
| [integration/PRISM.md](integration/PRISM.md) | Prism host integration |
| [integration/REMOTE.md](integration/REMOTE.md) | Aurora Remote client integration |
| [integration/APPLE_SECURITY_QUALIFICATION.md](integration/APPLE_SECURITY_QUALIFICATION.md) | Signed Apple target qualification |
| [integration/MIGRATION_FROM_TRUSTED_LAN.md](integration/MIGRATION_FROM_TRUSTED_LAN.md) | Removal of plaintext/claimed identity |
| [integration/CONDUCTOR_FUTURE.md](integration/CONDUCTOR_FUTURE.md) | Future Conductor participation |
| [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) | Language-family feature matrix |
| [TRACEABILITY.md](TRACEABILITY.md) | Requirement-to-code/test evidence |

## Historical and qualification material

- [DesignDocs/README.md](../DesignDocs/README.md) indexes historical plans, decisions, prompts, and completion reports.
- `qualification/` contains dated evidence. A PASS does not generalize to another binary, entitlement set, target, provider version, or source revision.
- `docs/security/` contains detailed current architecture and provider-boundary material.

## Status labels

- **Normative:** defines required interoperable behavior.
- **Current implementation guide:** describes supported integration APIs and procedures.
- **Qualification evidence:** dated proof for a specific artifact or environment.
- **Historical decision record:** preserves the context and decision at that time.
- **Superseded:** retained for history and linked to its replacement.

