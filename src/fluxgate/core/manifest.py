"""Typed, deterministic and secret-free server capability manifest."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field, ValidationError

from fluxgate.core.config import AppConfig
from fluxgate.core.errors import StateError
from fluxgate.core.models import FluxGateState, StrictModel
from fluxgate.core.state import StateStore
from fluxgate.pathfinder.models import (
    ConnectionCandidate,
    ConnectionMode,
    FeatureCapability,
    IPFamily,
    PathfinderProtocol,
    PathfinderProvider,
    PathfinderSecurity,
    PathfinderTransport,
)
from fluxgate.profiles import protocol_spec
from fluxgate.providers.amneziawg.models import AmneziaWGProviderState


class ManifestServer(StrictModel):
    identity: str
    server_id: UUID | None = None


class ManifestProfile(StrictModel):
    id: UUID
    name: str
    provider: Literal["singbox"]
    protocol: Literal["vless", "trojan", "hysteria2"]
    transport: Literal["tcp", "quic"]
    security: Literal["tls"]
    host: str
    port: int = Field(ge=1, le=65535)
    ip_families: tuple[Literal["ipv4", "ipv6"], ...]
    socket_protocol: Literal["tcp", "udp"]
    requires_tls: bool
    requires_ip_forwarding: bool
    requires_nat: bool


class ServerManifest(StrictModel):
    schema_version: Literal[1] = 1
    server: ManifestServer
    generated_at: datetime | None = None
    profiles: tuple[ManifestProfile, ...] = ()
    candidates: tuple[ConnectionCandidate, ...] = ()

    def render(self) -> bytes:
        return (
            json.dumps(self.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False)
            + "\n"
        ).encode()


def build_manifest(
    config: AppConfig,
    state: FluxGateState,
    *,
    server_id: UUID | None = None,
    generated_at: datetime | None = None,
) -> ServerManifest:
    profiles: list[ManifestProfile] = []
    candidates: list[ConnectionCandidate] = []
    endpoint = config.server.domain

    def provider_enabled(name: str, configured: bool) -> bool:
        value = state.providers.get(name, {}).get("enabled", configured)
        if not isinstance(value, bool):
            raise StateError(f"invalid {name} provider state: enabled must be a boolean")
        return value

    wireguard_enabled = provider_enabled("wireguard", config.cores.wireguard.enabled)
    amneziawg_enabled = provider_enabled("amneziawg", config.cores.amneziawg.enabled)
    openvpn_enabled = provider_enabled("openvpn", config.cores.openvpn.enabled)
    singbox_enabled = provider_enabled("singbox", config.cores.singbox.enabled)
    if not endpoint and (
        wireguard_enabled
        or amneziawg_enabled
        or openvpn_enabled
        or (singbox_enabled and any(profile.enabled for profile in state.profiles))
    ):
        raise StateError(
            "cannot generate connectable manifest: server.domain is required when a candidate "
            "is enabled"
        )
    if wireguard_enabled:
        candidates.append(
            ConnectionCandidate(
                candidate_id="provider:wireguard",
                provider=PathfinderProvider.WIREGUARD,
                protocol=PathfinderProtocol.WIREGUARD,
                transport=PathfinderTransport.UDP,
                security=PathfinderSecurity.WIREGUARD,
                connection_mode=ConnectionMode.SYSTEM_TUNNEL,
                endpoint=endpoint,
                port=config.cores.wireguard.listen_port,
                socket_protocol="udp",
                ip_families=(IPFamily.IPV4,),
                required_features=(FeatureCapability.UDP,),
            )
        )
    if amneziawg_enabled:
        try:
            awg_state = AmneziaWGProviderState.model_validate_json(
                json.dumps(state.providers["amneziawg"])
            )
        except (KeyError, ValidationError) as error:
            raise StateError("enabled AmneziaWG provider has invalid profile state") from error
        candidates.append(
            ConnectionCandidate(
                candidate_id="provider:amneziawg",
                provider=PathfinderProvider.AMNEZIAWG,
                profile_id=awg_state.profile.id,
                protocol=PathfinderProtocol.AMNEZIAWG,
                transport=PathfinderTransport.UDP,
                security=PathfinderSecurity.WIREGUARD,
                connection_mode=ConnectionMode.SYSTEM_TUNNEL,
                endpoint=endpoint,
                port=config.cores.amneziawg.listen_port,
                socket_protocol="udp",
                ip_families=(IPFamily.IPV4,),
                required_features=(
                    FeatureCapability.UDP,
                    FeatureCapability.AMNEZIAWG_3_1,
                ),
            )
        )
    if openvpn_enabled:
        candidates.append(
            ConnectionCandidate(
                candidate_id="provider:openvpn",
                provider=PathfinderProvider.OPENVPN,
                protocol=PathfinderProtocol.OPENVPN,
                transport=PathfinderTransport.UDP,
                security=PathfinderSecurity.TLS,
                connection_mode=ConnectionMode.SYSTEM_TUNNEL,
                endpoint=endpoint,
                port=config.cores.openvpn.listen_port,
                socket_protocol="udp",
                ip_families=(IPFamily.IPV4,),
                required_features=(FeatureCapability.UDP,),
            )
        )
    for profile in sorted(state.profiles, key=lambda item: str(item.id)):
        if not profile.enabled:
            continue
        capabilities = protocol_spec(profile.protocol).capabilities
        profiles.append(
            ManifestProfile(
                id=profile.id,
                name=profile.name,
                provider=profile.provider,
                protocol=profile.protocol.value,
                transport=profile.transport.value,
                security=profile.security.value,
                host=endpoint,
                port=profile.listen_port,
                ip_families=("ipv4",)
                if profile.listen_address == "0.0.0.0"  # noqa: S104
                else ("ipv6",),
                socket_protocol=capabilities.socket_protocol.value,
                requires_tls=capabilities.requires_tls,
                requires_ip_forwarding=capabilities.requires_ip_forwarding,
                requires_nat=capabilities.requires_nat,
            )
        )
        transport = PathfinderTransport(profile.transport.value)
        features = (
            (FeatureCapability.UDP, FeatureCapability.QUIC)
            if transport == PathfinderTransport.QUIC
            else ()
        )
        candidates.append(
            ConnectionCandidate(
                candidate_id=f"profile:{profile.id}",
                provider=PathfinderProvider.SINGBOX,
                profile_id=profile.id,
                protocol=PathfinderProtocol(profile.protocol.value),
                transport=transport,
                security=PathfinderSecurity.TLS,
                connection_mode=ConnectionMode.LOCAL_PROXY,
                endpoint=endpoint,
                port=profile.listen_port,
                socket_protocol=capabilities.socket_protocol.value,
                ip_families=(
                    (IPFamily.IPV4,)
                    if profile.listen_address == "0.0.0.0"  # noqa: S104
                    else (IPFamily.IPV6,)
                ),
                required_features=features,
                enabled=singbox_enabled,
            )
        )
    return ServerManifest(
        server=ManifestServer(identity=endpoint, server_id=server_id),
        generated_at=generated_at,
        profiles=tuple(profiles),
        candidates=tuple(sorted(candidates, key=lambda item: item.candidate_id)),
    )


def render_manifest(config: AppConfig, state: StateStore) -> bytes:
    return build_manifest(config, state.load()).render()
