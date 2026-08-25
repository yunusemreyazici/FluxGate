"""Secret-free server capability manifest."""

from __future__ import annotations

import json

from fluxgate.core.config import AppConfig
from fluxgate.core.state import StateStore
from fluxgate.profiles import protocol_spec


def render_manifest(config: AppConfig, state: StateStore) -> bytes:
    profiles: list[dict[str, object]] = []
    for profile in sorted(state.load().profiles, key=lambda item: str(item.id)):
        if not profile.enabled:
            continue
        capabilities = protocol_spec(profile.protocol).capabilities
        profiles.append(
            {
                "id": str(profile.id),
                "name": profile.name,
                "provider": profile.provider,
                "protocol": profile.protocol.value,
                "transport": profile.transport.value,
                "security": profile.security.value,
                "host": config.server.domain,
                "port": profile.listen_port,
                "ip_families": ["ipv4"]
                if profile.listen_address == "0.0.0.0"  # noqa: S104
                else ["ipv6"],
                "socket_protocol": capabilities.socket_protocol.value,
                "requires_tls": capabilities.requires_tls,
                "requires_ip_forwarding": capabilities.requires_ip_forwarding,
                "requires_nat": capabilities.requires_nat,
            }
        )
    document = {
        "schema_version": 1,
        "server": {"identity": config.server.domain},
        "profiles": profiles,
    }
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
