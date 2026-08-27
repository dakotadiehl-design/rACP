# Migration from `trusted_lan`

Status: **Current implementation guide**

`trusted_lan`, discovery identity, and unilateral TLS do not authenticate an ACP peer. They may remain decodable for migration and diagnostics but cannot authorize production control.

1. Inventory every listener, connector, `allowPlaintext`, WebSocket URL, and node-ID allowlist.
2. Introduce trust-domain bootstrap/enrollment and persistent identity stores.
3. Replace raw transports with provider-created authenticated connections.
4. Replace claimed-node principals with authenticated device identity.
5. Move permissions into server-owned policy and atomic authorization consumption.
6. Preserve existing action routing, idempotency, safety, and state-recovery behavior behind the new boundary.
7. Add negative tests proving every legacy route fails before mutation.
8. Remove the production migration switch only after signed-target all-up qualification.

Never operate plaintext and authenticated control as equivalent modes. A staged migration may keep plaintext observation on a separate endpoint, but it must have no route to privileged actions.

