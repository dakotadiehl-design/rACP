# Aurora Remote ACP security integration

Status: **Current implementation guide — product integration pending**

Remote is an authenticated client and expression-of-intent surface. It never becomes the authority for show, cue, lighting, or transport state.

## Required integration sequence

1. Link the ACP Swift products into the signed Remote target.
2. Generate the candidate identity only through `ACPAppleIdentityStore`.
3. Select Secure Enclave when available, supported, and qualified; otherwise require a demonstrably non-exportable Keychain key. Fail closed if neither path qualifies.
4. Run enrollment only through the restricted enrollment connection and provider-owned SPAKE2+ state.
5. Activate credentials only after durable install/readback and proof verification.
6. Connect through the Apple Full connection factory and create a session from its authenticated capability.
7. Treat discovery as endpoint metadata only and verify that authenticated identity matches the selected trust domain/node.
8. Remain non-interactive until layout and authoritative-state synchronization are acknowledged.
9. On disconnect, gaps, authority change, or revocation, mark state stale and stop privileged interaction.

Remote must never fall back to an exportable software/file key, ephemeral identity, plaintext `trusted_lan`, unilateral TLS, or a cached claimed node identity.

## Exit tests

- First enrollment, cancellation, wrong code, replay, expiry, reinstall, and process restart.
- Credential rotation retains the previous active identity until the new identity commits.
- Revoked credentials cannot reconnect.
- Reconnect requires fresh authoritative state before control.
- GO remains live-ephemeral and idempotent; momentary END/expiry is safe.
- Trust reset removes trust/credentials without silently deleting unrelated cached assets.

