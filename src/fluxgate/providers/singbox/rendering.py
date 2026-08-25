"""Deterministic sing-box server and standalone client rendering."""

from __future__ import annotations

import json
from pathlib import Path

from fluxgate.core.errors import ProviderError
from fluxgate.core.models import Client, FluxGateState, ProfileDefinition, ProtocolName


def _credential(client: Client, profile: ProfileDefinition) -> dict[str, object]:
    value = client.profile_credentials.get(str(profile.id))
    if not isinstance(value, dict):
        raise ProviderError(f"missing profile credential mapping for {client.name}/{profile.name}")
    if profile.protocol == ProtocolName.VLESS:
        uuid = value.get("uuid")
        if not isinstance(uuid, str):
            raise ProviderError("invalid VLESS credential")
        return {"name": client.name, "uuid": uuid}
    password = value.get("password")
    if not isinstance(password, str):
        raise ProviderError(f"invalid {profile.protocol.value} credential")
    return {"name": client.name, "password": password}


def render_server(
    state: FluxGateState, certificate_path: Path, key_path: Path, server_name: str
) -> bytes:
    inbounds: list[dict[str, object]] = []
    for profile in sorted(
        (item for item in state.profiles if item.provider == "singbox" and item.enabled),
        key=lambda item: str(item.id),
    ):
        users = [
            _credential(client, profile)
            for client in sorted(state.clients, key=lambda item: str(item.id))
            if str(profile.id) in client.profile_credentials
        ]
        inbound: dict[str, object] = {
            "type": profile.protocol.value,
            "tag": f"fluxgate-{profile.id.hex}",
            "listen": profile.listen_address,
            "listen_port": profile.listen_port,
            "users": users,
            "tls": {
                "enabled": True,
                "server_name": server_name,
                "certificate_path": str(certificate_path),
                "key_path": str(key_path),
            },
        }
        inbounds.append(inbound)
    document = {
        "log": {"level": "info", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
    }
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


def render_client(
    client: Client,
    profile: ProfileDefinition,
    endpoint: str,
    ca_certificate: str,
) -> str:
    credential = _credential(client, profile)
    outbound: dict[str, object] = {
        "type": profile.protocol.value,
        "tag": "fluxgate-remote",
        "server": endpoint,
        "server_port": profile.listen_port,
        "tls": {
            "enabled": True,
            "server_name": endpoint,
            "certificate": [ca_certificate],
        },
    }
    if profile.protocol == ProtocolName.VLESS:
        outbound["uuid"] = credential["uuid"]
        outbound["network"] = "tcp"
    else:
        outbound["password"] = credential["password"]
    document = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "socks",
                "tag": "local-socks",
                "listen": "127.0.0.1",
                "listen_port": 2080,
            }
        ],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {"final": "fluxgate-remote"},
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"
