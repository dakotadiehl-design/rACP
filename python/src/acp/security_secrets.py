"""Opaque secret containers; raw bytes are available only through an explicit callback."""

from __future__ import annotations

import hmac
from collections.abc import Callable
from typing import Never, TypeVar

T = TypeVar("T")


class SecretBytes:
    __slots__ = ("__value",)

    def __init__(self, value: bytes | bytearray, *, label: str = "secret") -> None:
        if not value:
            raise ValueError("secret must not be empty")
        self.__value = bytearray(value)
        del label

    def __repr__(self) -> str:
        return f"SecretBytes(redacted=True, length={len(self.__value)})"

    __str__ = __repr__

    def __reduce__(self) -> Never:
        raise TypeError("SecretBytes cannot be serialized")

    def use(self, operation: Callable[[memoryview], T]) -> T:
        return operation(memoryview(self.__value).toreadonly())

    def constant_time_equals(self, other: SecretBytes) -> bool:
        return self.use(lambda left: other.use(lambda right: hmac.compare_digest(left, right)))

    def clear(self) -> None:
        self.__value[:] = b"\x00" * len(self.__value)

    def __del__(self) -> None:
        try:
            self.clear()
        except Exception:
            pass
