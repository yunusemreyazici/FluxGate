"""Strict bootstrap inventory and secret-free verification result models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import field_validator, model_validator

from fluxgate.core.models import StrictModel
from fluxgate.core.publication import safe_relative_path
from fluxgate.pathfinder.models import ConnectionMode, PathfinderProvider


class BootstrapArtifact(StrictModel):
    path: str
    provider: PathfinderProvider
    candidate_id: str
    media_type: str
    sha256: str
    connection_mode: ConnectionMode

    @field_validator("path")
    @classmethod
    def safe_path(cls, value: str) -> str:
        safe_relative_path(value)
        return value

    @field_validator("sha256")
    @classmethod
    def digest_shape(cls, value: str) -> str:
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise ValueError("artifact SHA-256 must be lowercase hexadecimal")
        return value


class BootstrapDescriptor(StrictModel):
    schema_version: Literal[1] = 1
    server_id: UUID
    client_id: UUID
    client_name: str
    created_at: datetime
    manifest_path: Literal["manifest.json"] = "manifest.json"
    artifacts: tuple[BootstrapArtifact, ...]

    @model_validator(mode="after")
    def unique_artifact_paths(self) -> BootstrapDescriptor:
        paths = [safe_relative_path(item.path) for item in self.artifacts]
        if len(paths) != len(set(paths)):
            raise ValueError("bootstrap artifact paths must be unique")
        return self


class BootstrapVerification(StrictModel):
    schema_version: Literal[1] = 1
    valid: Literal[True] = True
    trust_mode: Literal["initial-offline", "pinned"]
    server_id: UUID
    client_id: UUID
    client_name: str
    artifact_count: int
