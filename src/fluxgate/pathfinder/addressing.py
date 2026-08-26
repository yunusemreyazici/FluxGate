"""Pure normalization for independently authorized Pathfinder addresses."""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence

MAX_AUTHORIZED_SERVER_ADDRESSES = 16


def normalize_authorized_addresses(addresses: Sequence[str]) -> tuple[str, ...]:
    """Return a bounded, canonical, deterministic set of IP-literal address pins."""
    if isinstance(addresses, (str, bytes)):
        raise ValueError("authorized server addresses must be a list of IP literals")
    if len(addresses) > MAX_AUTHORIZED_SERVER_ADDRESSES:
        raise ValueError(
            f"at most {MAX_AUTHORIZED_SERVER_ADDRESSES} authorized server addresses are allowed"
        )
    normalized: dict[tuple[int, int], str] = {}
    for value in addresses:
        if not isinstance(value, str):
            raise ValueError("authorized server addresses must be IPv4 or IPv6 literals")
        if "%" in value:
            raise ValueError("authorized server addresses must not contain IPv6 scope identifiers")
        try:
            address = ipaddress.ip_address(value)
        except ValueError as error:
            raise ValueError("authorized server addresses must be IPv4 or IPv6 literals") from error
        key = (address.version, int(address))
        if key in normalized:
            raise ValueError("authorized server addresses must not contain duplicates")
        normalized[key] = str(address)
    return tuple(normalized[key] for key in sorted(normalized))
