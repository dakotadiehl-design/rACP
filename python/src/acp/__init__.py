"""Aurora Communications Protocol — Python reference SDK."""

from importlib.metadata import PackageNotFoundError, version

from .codec import decode_cbor, decode_json, encode_cbor, encode_json
from .envelope import Envelope, make_envelope
from .negotiate import select_version
from .remote import (
    ActionContext,
    ActionResult,
    Enrollment,
    MemoryActionRouter,
    RemoteAuthority,
    RemoteClient,
    RemoteHost,
    RemoteIdentity,
)
from .types import Capability, Endpoint, NodeIdentity, QoS, Role

try:
    __version__ = version("aurora-acp")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "1.2.0"

__all__ = [
    "__version__",
    "Envelope",
    "make_envelope",
    "encode_cbor",
    "encode_json",
    "decode_cbor",
    "decode_json",
    "select_version",
    "Capability",
    "Endpoint",
    "NodeIdentity",
    "QoS",
    "Role",
    "ActionContext",
    "ActionResult",
    "Enrollment",
    "MemoryActionRouter",
    "RemoteAuthority",
    "RemoteClient",
    "RemoteHost",
    "RemoteIdentity",
]
