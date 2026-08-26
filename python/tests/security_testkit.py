"""Security fabrication helpers confined to the pytest source tree."""

from __future__ import annotations

from dataclasses import fields
from typing import Any, cast

from acp.security import (
    AuthenticatedPrincipal,
    TransportEvidence,
    _admitted_principal,
    _verified_transport_evidence,
)
from acp.security_transport import FullTLSHandshake, _verified_full_tls_handshake


def unsafe_transport_evidence_for_testing(**values: object) -> TransportEvidence:
    return _verified_transport_evidence(**values)


def unsafe_authenticated_principal_for_testing(**values: object) -> AuthenticatedPrincipal:
    return _admitted_principal(**values)


def unsafe_full_tls_handshake_for_testing(**values: object) -> FullTLSHandshake:
    return _verified_full_tls_handshake(**values)


def unsafe_replace_security_value_for_testing(value: object, **changes: object) -> object:
    values = {field.name: getattr(value, field.name) for field in fields(cast(Any, value))} | changes
    if isinstance(value, TransportEvidence):
        return unsafe_transport_evidence_for_testing(**values)
    if isinstance(value, FullTLSHandshake):
        return unsafe_full_tls_handshake_for_testing(**values)
    raise TypeError("unsupported sealed security value")
