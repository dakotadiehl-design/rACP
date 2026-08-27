# Future Conductor participation

Status: **Current architecture constraint; implementation future**

Conductor may join an existing ACP trust domain as an enrolled authenticated peer/controller without certificate replacement or domain reset. Its permissions remain server-owned and independently revocable.

Conductor cannot inherit Prism’s authority ownership in v1. The authority private key is non-exportable, and ACP v1 defines no authority-transfer, delegation, intermediate, cross-signing, or quorum protocol. If a future Conductor becomes an authority without a separately reviewed transfer protocol, it creates a new trust domain and every peer explicitly re-enrolls.

Future integration must preserve application-neutral identities and policies: no certificate field or trust-domain rule may assume that Prism is permanently the only controller. Conductor support must use the same schemas, credential semantics, revocation behavior, and cross-language fixtures.

