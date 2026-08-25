"""Typed public and protected signing-identity models."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import field_validator, model_validator

from fluxgate.core.compat import StrEnum
from fluxgate.core.errors import IdentityError, VerificationError
from fluxgate.core.models import StrictModel


class SigningAlgorithm(StrEnum):
    ED25519 = "ed25519"


def encode_base64(value: bytes) -> str:
    """RFC 4648 standard Base64 with required padding."""
    return base64.b64encode(value).decode("ascii")


def decode_base64(value: str, *, expected_length: int, label: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise VerificationError(f"invalid Base64 {label}") from error
    if len(decoded) != expected_length:
        raise VerificationError(f"invalid {label} length")
    return decoded


def fingerprint_for(public_key: bytes) -> str:
    return f"sha256:{hashlib.sha256(public_key).hexdigest()}"


def key_id_for(public_key: bytes) -> str:
    digest = hashlib.sha256(public_key).digest()
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"ed25519:{encoded}"


class StoredIdentityMetadata(StrictModel):
    schema_version: Literal[1] = 1
    server_id: UUID
    algorithm: Literal[SigningAlgorithm.ED25519] = SigningAlgorithm.ED25519
    key_id: str
    fingerprint: str
    created_at: datetime


class TrustDescriptor(StrictModel):
    schema_version: Literal[1] = 1
    server_id: UUID
    algorithm: Literal[SigningAlgorithm.ED25519] = SigningAlgorithm.ED25519
    key_id: str
    public_key: str
    fingerprint: str

    @field_validator("key_id")
    @classmethod
    def key_id_shape(cls, value: str) -> str:
        if not value.startswith("ed25519:") or len(value) > 128:
            raise ValueError("invalid Ed25519 key ID")
        return value

    @field_validator("fingerprint")
    @classmethod
    def fingerprint_shape(cls, value: str) -> str:
        if not value.startswith("sha256:") or len(value) != 71:
            raise ValueError("invalid SHA-256 fingerprint")
        return value

    @model_validator(mode="after")
    def key_metadata_matches(self) -> TrustDescriptor:
        try:
            public = decode_base64(self.public_key, expected_length=32, label="public key")
        except VerificationError as error:
            raise ValueError(str(error)) from error
        if self.key_id != key_id_for(public):
            raise ValueError("public key does not match key ID")
        if self.fingerprint != fingerprint_for(public):
            raise ValueError("public key does not match fingerprint")
        return self

    def raw_public_key(self) -> bytes:
        return decode_base64(self.public_key, expected_length=32, label="public key")

    def render(self) -> bytes:
        return json.dumps(self.model_dump(mode="json"), indent=2, sort_keys=True).encode() + b"\n"


class SignatureEnvelope(StrictModel):
    schema_version: Literal[1] = 1
    algorithm: Literal[SigningAlgorithm.ED25519] = SigningAlgorithm.ED25519
    key_id: str
    signature: str

    @field_validator("key_id")
    @classmethod
    def key_id_shape(cls, value: str) -> str:
        if not value.startswith("ed25519:") or len(value) > 128:
            raise ValueError("invalid Ed25519 key ID")
        return value

    def raw_signature(self) -> bytes:
        return decode_base64(self.signature, expected_length=64, label="signature")

    def render(self) -> bytes:
        return json.dumps(self.model_dump(mode="json"), indent=2, sort_keys=True).encode() + b"\n"


@dataclass(frozen=True, slots=True)
class ServerIdentity:
    metadata: StoredIdentityMetadata
    public_key: bytes
    private_key: bytes

    @property
    def trust(self) -> TrustDescriptor:
        return TrustDescriptor(
            server_id=self.metadata.server_id,
            key_id=self.metadata.key_id,
            public_key=encode_base64(self.public_key),
            fingerprint=self.metadata.fingerprint,
        )

    def assert_consistent(self) -> None:
        if self.metadata.key_id != key_id_for(self.public_key):
            raise IdentityError("server signing identity key ID is inconsistent")
        if self.metadata.fingerprint != fingerprint_for(self.public_key):
            raise IdentityError("server signing identity fingerprint is inconsistent")
