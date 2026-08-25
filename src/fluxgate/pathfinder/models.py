"""Typed, secret-free Pathfinder inputs and results."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator

from fluxgate.core.compat import StrEnum
from fluxgate.core.models import StrictModel


class PathfinderProvider(StrEnum):
    WIREGUARD = "wireguard"
    OPENVPN = "openvpn"
    SINGBOX = "singbox"


class PathfinderProtocol(StrEnum):
    WIREGUARD = "wireguard"
    OPENVPN = "openvpn"
    VLESS = "vless"
    TROJAN = "trojan"
    HYSTERIA2 = "hysteria2"


class PathfinderTransport(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    QUIC = "quic"


class PathfinderSecurity(StrEnum):
    WIREGUARD = "wireguard"
    TLS = "tls"


class ConnectionMode(StrEnum):
    SYSTEM_TUNNEL = "system_tunnel"
    LOCAL_PROXY = "local_proxy"


class IPFamily(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"


class FeatureCapability(StrEnum):
    UDP = "udp"
    QUIC = "quic"
    MANAGED_CA = "managed_ca"


class ConnectionCandidate(StrictModel):
    candidate_id: str
    provider: PathfinderProvider
    profile_id: UUID | None = None
    protocol: PathfinderProtocol
    transport: PathfinderTransport
    security: PathfinderSecurity
    connection_mode: ConnectionMode
    endpoint: str
    port: int = Field(ge=1, le=65535)
    socket_protocol: Literal["tcp", "udp"]
    ip_families: tuple[IPFamily, ...]
    required_features: tuple[FeatureCapability, ...] = ()
    enabled: bool = True

    @field_validator("candidate_id")
    @classmethod
    def stable_candidate_id(cls, value: str) -> str:
        if (
            not value
            or len(value) > 128
            or any(ord(character) < 33 or ord(character) > 126 for character in value)
        ):
            raise ValueError("candidate ID must be printable ASCII")
        return value

    @field_validator("ip_families", "required_features")
    @classmethod
    def unique_requirements(cls, value: tuple[object, ...]) -> tuple[object, ...]:
        if len(value) != len(set(value)):
            raise ValueError("candidate requirements must not contain duplicates")
        return value


class ClientCapabilities(StrictModel):
    schema_version: Literal[1] = 1
    supported_providers: tuple[PathfinderProvider, ...]
    supported_protocols: tuple[PathfinderProtocol, ...]
    supported_transports: tuple[PathfinderTransport, ...]
    supported_security: tuple[PathfinderSecurity, ...]
    supported_connection_modes: tuple[ConnectionMode, ...]
    supported_ip_families: tuple[IPFamily, ...]
    supported_features: tuple[FeatureCapability, ...] = ()

    @field_validator("*")
    @classmethod
    def unique_values(cls, value: object) -> object:
        if isinstance(value, tuple) and len(value) != len(set(value)):
            raise ValueError("client capability lists must not contain duplicates")
        return value


class CandidateAssessment(StrictModel):
    candidate_id: str
    compatible: bool
    rejection_reasons: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...]


class PathfinderPlan(StrictModel):
    schema_version: Literal[1] = 1
    assessments: tuple[CandidateAssessment, ...]
