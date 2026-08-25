"""Provider-independent domain models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from fluxgate.core.compat import StrEnum


class StrictModel(BaseModel):
    """Base model rejecting misspelled or unknown input fields."""

    model_config = ConfigDict(extra="forbid", strict=True)


class ProviderStateName(StrEnum):
    DISABLED = "disabled"
    NOT_INSTALLED = "not-installed"
    STOPPED = "stopped"
    RUNNING = "running"
    DEGRADED = "degraded"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


class ProviderCapability(StrEnum):
    ADD_CLIENTS = "add-clients"
    EXPORT_CONFIG = "export-config"
    RELOAD = "reload"
    ROTATE_KEYS = "rotate-keys"
    MANAGE_PROFILES = "manage-profiles"
    PROFILE_CLIENTS = "profile-clients"
    PROFILE_EXPORT = "profile-export"


class ProtocolName(StrEnum):
    VLESS = "vless"
    TROJAN = "trojan"
    HYSTERIA2 = "hysteria2"


class TransportName(StrEnum):
    TCP = "tcp"
    QUIC = "quic"


class SecurityName(StrEnum):
    TLS = "tls"


class SocketProtocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"


class ProfileCapabilities(StrictModel):
    socket_protocol: SocketProtocol
    requires_tls: bool
    requires_ip_forwarding: bool = False
    requires_nat: bool = False
    per_client_credentials: bool = True
    multiple_clients: bool = True


class ProtocolSpec(StrictModel):
    protocol: ProtocolName
    provider: Literal["singbox"] = "singbox"
    transports: tuple[TransportName, ...]
    security_modes: tuple[SecurityName, ...]
    capabilities: ProfileCapabilities


class ProfileDefinition(StrictModel):
    """A stable connectable endpoint, distinct from its implementing core."""

    id: UUID = Field(default_factory=uuid4)
    name: str
    provider: Literal["singbox"] = "singbox"
    protocol: ProtocolName
    transport: TransportName
    security: SecurityName
    listen_address: Literal["0.0.0.0", "::"] = "0.0.0.0"  # noqa: S104
    listen_port: int = Field(ge=1, le=65535)
    enabled: bool = False
    provider_options: dict[str, str | int | bool] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("name")
    @classmethod
    def safe_name(cls, value: str) -> str:
        if (
            not (1 <= len(value) <= 64)
            or not value[0].isalnum()
            or any(not (character.isalnum() or character in {"-", "_", "."}) for character in value)
        ):
            raise ValueError("profile name may contain letters, digits, '.', '_' and '-'")
        if value in {".", ".."}:
            raise ValueError("invalid profile name")
        return value

    @model_validator(mode="after")
    def supported_combination(self) -> ProfileDefinition:
        combinations = {
            (ProtocolName.VLESS, TransportName.TCP, SecurityName.TLS),
            (ProtocolName.TROJAN, TransportName.TCP, SecurityName.TLS),
            (ProtocolName.HYSTERIA2, TransportName.QUIC, SecurityName.TLS),
        }
        if (self.protocol, self.transport, self.security) not in combinations:
            raise ValueError("unsupported protocol/transport/security combination")
        if self.provider_options:
            raise ValueError("provider options are not supported in FluxGate 0.3")
        return self

    @property
    def socket_protocol(self) -> SocketProtocol:
        return SocketProtocol.UDP if self.transport == TransportName.QUIC else SocketProtocol.TCP


class HealthLevel(StrEnum):
    SUCCESS = "pass"
    INFO = "info"
    WARNING = "warning"
    FAILURE = "failure"


class HealthResult(StrictModel):
    name: str
    level: HealthLevel
    message: str


class ProviderDetection(StrictModel):
    available: bool
    binaries: dict[str, bool] = Field(default_factory=dict)
    detail: str = ""


class ProviderStatus(StrictModel):
    name: str
    state: ProviderStateName
    enabled: bool = False
    installed: bool = False
    detail: str = ""


class OperationResult(StrictModel):
    changed: bool
    message: str
    actions: list[str] = Field(default_factory=list)


class ExportArtifact(StrictModel):
    name: str
    media_type: str
    content: str
    secret: bool = True

    @field_validator("name")
    @classmethod
    def safe_name(cls, value: str) -> str:
        if (
            not value
            or len(value) > 128
            or value in {".", ".."}
            or "/" in value
            or "\\" in value
            or any(ord(character) < 32 for character in value)
        ):
            raise ValueError("export artifact name must be a safe filename")
        return value


class ClientArtifact(StrictModel):
    provider: str
    credentials: dict[str, Any]
    exports: list[ExportArtifact] = Field(default_factory=list)


class Client(StrictModel):
    id: UUID = Field(default_factory=uuid4)
    name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    enabled: bool = True
    expires_at: datetime | None = None
    metadata: dict[str, str] = Field(default_factory=dict)
    provider_credentials: dict[str, dict[str, Any]] = Field(default_factory=dict)
    profile_credentials: dict[str, dict[str, Any]] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def safe_name(cls, value: str) -> str:
        if not (1 <= len(value) <= 64):
            raise ValueError("client name must contain between 1 and 64 characters")
        if not value[0].isalnum() or any(
            not (character.isalnum() or character in {"-", "_", "."}) for character in value
        ):
            raise ValueError("client name may contain letters, digits, '.', '_' and '-'")
        if value in {".", ".."}:
            raise ValueError("invalid client name")
        return value


class FluxGateState(StrictModel):
    schema_version: Literal[2] = 2
    clients: list[Client] = Field(default_factory=list)
    providers: dict[str, dict[str, Any]] = Field(default_factory=dict)
    profiles: list[ProfileDefinition] = Field(default_factory=list)
