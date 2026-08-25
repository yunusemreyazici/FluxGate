"""Provider-independent domain models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

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
    schema_version: Literal[1] = 1
    clients: list[Client] = Field(default_factory=list)
    providers: dict[str, dict[str, Any]] = Field(default_factory=dict)
