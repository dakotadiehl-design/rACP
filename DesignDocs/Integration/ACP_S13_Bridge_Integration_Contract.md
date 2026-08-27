# S13 Bridge integration contract

> **Historical record.** This document preserves the plan, review, or evidence at the time it was written. For current normative and integration guidance, start at [`docs/README.md`](../../docs/README.md).

No matching Bridge repository was present under `/Users/dakota/code` during inspection on 2026-08-26. No repository was modified.

## Required future analysis and migration

A later Bridge-writable job must first record repository path, branch, HEAD, dirty state, target operating systems/boards, and whether each target uses Full or Lightweight ACP. It must identify service startup, raw transports, identity storage, trust anchors, revocation state, clock/rollback checkpoints, bootstrap/reset paths, and privileged command dispatch.

Linux/Raspberry Pi targets must consume the qualified ACP Rust/native connection factory. Embedded targets may consume Lightweight only after the selected provider and representative HIL pass. Service startup must fail closed when the provider, protected key, anchors, current revocation state, or secure clock/checkpoint is unavailable. Bootstrap requires a private secret or explicit physical/local ceremony. Reset must revoke the prior credential, preserve append-only revocation history, avoid silent reenrollment, and remain separate from cached assets. Storage must be labelled honestly: Raspberry Pi does not imply hardware-backed storage; TPM/secure-element claims require real hardware proof.

Mandatory negatives include fabricated evidence, wrong root/domain/node, exporter mixup, replay/downgrade, revoked/expired credentials, missing/locked/corrupt storage, symlinks and ownership/mode faults, clock rollback, TPM absence/policy mismatch, reset/reenrollment abuse, power interruption, and trusted-LAN control attempts. Lightweight additionally requires entropy failure, malformed points/credentials, flood/watchdog, flash interruption, brownout, and Full-commissioner interoperability.

Completion requires a separate Bridge-writable job with ACP read-only and exact-target Linux/Raspberry Pi or embedded HIL qualification. Current status: `BLOCKED — Bridge repository unavailable and product integration not performed`.
