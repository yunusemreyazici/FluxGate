"""Small standard-library compatibility helpers for supported Python runtimes."""

from enum import Enum


class StrEnum(str, Enum):
    """Python 3.10-compatible subset of enum.StrEnum used by FluxGate."""

    def __str__(self) -> str:
        return str(self.value)
