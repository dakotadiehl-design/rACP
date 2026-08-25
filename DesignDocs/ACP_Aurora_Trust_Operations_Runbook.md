# ACP Aurora Trust Offline Operations Runbook

Aurora Trust is designed to operate without Internet access. The operator CLI is `acp-security`; set `--state-dir` to restricted, backed-up local storage. Its state file is atomically replaced with mode `0600`, contains public operational metadata rather than private keys or bootstrap secrets, and maintains a verifiable hash-chained audit history.

## Commissioning and headless enrollment

1. Create a trust domain with `acp-security domain create --name SHOW` or import a previously exported public domain package with `domain import PACKAGE`.
2. Open enrollment with `enrollment open DOMAIN_ID`. Enter the one-time bootstrap secret at the hidden prompt, or use `--secret-file` with a file accessible only to its owner. Never place bootstrap or PAKE secrets in command arguments or shell history.
3. Advance the candidate with `enrollment candidate ENROLLMENT_ID` and complete commissioner installation with `enrollment commissioner ENROLLMENT_ID [--node-id UUID]`.
4. Confirm `node list`, `node inspect NODE_ID`, `diagnostics`, and `audit verify` before enabling authenticated preference or enforcement.

The current contract supports text identifiers and protected provisioning input. It does not freeze QR visual semantics or a signed portable enrollment-package format, so M7 does not invent either mechanism.

## Renewal, rotation, revocation, and reset

- `node renew NODE_ID` replaces the credential while retaining the device identity key.
- `node rotate NODE_ID` transactionally advances both credential and identity-key metadata.
- `node revoke NODE_ID` advances the revocation epoch. Hardened active sessions must terminate on revalidation.
- `node reset NODE_ID` unenrolls trust metadata but does not delete Remote layouts, show assets, or cached content.
- `node recover NODE_ID` records recovery of a retained non-reset identity. Authority recovery must use an independently protected authority backup and must preserve the trust-domain ID.

For lost or stolen nodes, revoke first, propagate and verify the new revocation epoch, terminate active sessions, then rotate affected authority/operator credentials if compromise is suspected. For authority compromise, stop enrollment and production control, preserve audit evidence, restore a known-good offline authority backup, and re-enroll rather than bypass identity checks.

## Clock and offline failure handling

If wall-clock trust or the authenticated checkpoint is unavailable, credential validation fails closed. Restore a trustworthy clock/checkpoint; do not extend credentials locally or disable expiry checks. Offline operation requires no protocol-runtime Internet access.

## Migration

Stages are explicit: `observe`, `enroll`, `prefer_authenticated`, and `enforce`. Configure them with `migration set STAGE`. `trusted_lan` requires `--allow-trusted-lan`, is always unauthenticated/view-only, and is forbidden in `enforce`. A failed stronger authentication attempt never falls back. Production Remote control always requires an authenticated and authorized principal.

## Backup, audit, and qualification evidence

Back up the restricted state directory and separately back up provider-managed authority/key handles using the platform's protected mechanism. Test restoration offline. `audit verify` validates event ordering and hash-chain integrity; copy incident evidence before remediation.

Production qualification additionally requires frozen-vector agreement, all mandatory provider and platform probes, live cross-language exporter equality, hardware qualification where applicable, complete regression/interoperability evidence, and independent final security review. A software PASS is not a substitute for platform, hardware, or external-review evidence.
