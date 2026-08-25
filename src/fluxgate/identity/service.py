"""Protected Ed25519 identity lifecycle and exact-byte detached signatures."""

from __future__ import annotations

import fcntl
import json
import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import ValidationError

from fluxgate.core.errors import IdentityError, VerificationError
from fluxgate.core.paths import PathLayout
from fluxgate.core.state import atomic_write
from fluxgate.identity.models import (
    ServerIdentity,
    SignatureEnvelope,
    StoredIdentityMetadata,
    TrustDescriptor,
    encode_base64,
    fingerprint_for,
    key_id_for,
)


class ServerIdentityManager:
    OWNER = b"Managed by FluxGate server signing identity\n"
    EXPECTED_FILES = frozenset({".fluxgate-owner", "identity.json", "private.key", "public.key"})

    def __init__(self, paths: PathLayout) -> None:
        self.paths = paths
        self.root = paths.server_identity_dir

    @property
    def marker(self) -> Path:
        return self.root / ".fluxgate-owner"

    @property
    def metadata_path(self) -> Path:
        return self.root / "identity.json"

    @property
    def private_path(self) -> Path:
        return self.root / "private.key"

    @property
    def public_path(self) -> Path:
        return self.root / "public.key"

    def _assert_safe_ancestors(self, path: Path) -> None:
        checked_anchor = False
        for candidate in (path, *path.parents):
            if candidate.is_symlink():
                raise IdentityError(f"refusing symlinked server identity path: {candidate}")
            if candidate.exists() and not checked_anchor:
                checked_anchor = True
                if not candidate.is_dir():
                    raise IdentityError(f"server identity ancestor is not a directory: {candidate}")
                metadata = candidate.stat()
                if os.geteuid() == 0 and metadata.st_uid != 0:
                    raise IdentityError(f"server identity path is not root-owned: {candidate}")
                if stat.S_IMODE(metadata.st_mode) & 0o022:
                    raise IdentityError(
                        f"server identity path is group/world-writable: {candidate}"
                    )

    @staticmethod
    def _safe_file(path: Path, mode: int) -> bool:
        if path.is_symlink() or not path.is_file():
            return False
        metadata = path.stat()
        return metadata.st_nlink == 1 and stat.S_IMODE(metadata.st_mode) == mode

    @contextmanager
    def _lock(self) -> Iterator[None]:
        path = self.paths.server_identity_lock_file
        self._assert_safe_ancestors(path.parent)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.parent.chmod(0o700)
        if path.is_symlink():
            raise IdentityError(f"refusing server identity lock symlink: {path}")
        descriptor: int | None = None
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            os.fchmod(descriptor, 0o600)
            if os.fstat(descriptor).st_nlink != 1:
                raise IdentityError("server identity lock file has unsafe hard links")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError as error:
            if descriptor is not None:
                os.close(descriptor)
            raise IdentityError(f"cannot lock server signing identity: {error}") from error
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            raise
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _validate_root(self) -> None:
        self._assert_safe_ancestors(self.root)
        if self.root.is_symlink() or not self.root.is_dir():
            raise IdentityError(f"server signing identity is not a safe directory: {self.root}")
        metadata = self.root.stat()
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise IdentityError("server signing identity directory must have mode 0700")
        if os.geteuid() == 0 and metadata.st_uid != 0:
            raise IdentityError("server signing identity directory must be root-owned")
        if {path.name for path in self.root.iterdir()} != self.EXPECTED_FILES:
            raise IdentityError("server signing identity directory contains unexpected files")
        if not self._safe_file(self.marker, 0o600) or self.marker.read_bytes() != self.OWNER:
            raise IdentityError("server signing identity ownership marker is invalid")
        if not self._safe_file(self.metadata_path, 0o644):
            raise IdentityError("server signing identity metadata is unsafe")
        if not self._safe_file(self.private_path, 0o600):
            raise IdentityError("server signing private key is unsafe")
        if not self._safe_file(self.public_path, 0o644):
            raise IdentityError("server signing public key is unsafe")

    def load(self) -> ServerIdentity:
        if self.root.is_symlink():
            raise IdentityError(f"refusing symlinked server identity path: {self.root}")
        if not self.root.exists():
            raise IdentityError("server signing identity is not initialized")
        try:
            self._validate_root()
            metadata = StoredIdentityMetadata.model_validate_json(self.metadata_path.read_bytes())
            private_raw = self.private_path.read_bytes()
            public_raw = self.public_path.read_bytes()
            if len(private_raw) != 32 or len(public_raw) != 32:
                raise IdentityError("server signing key length is invalid")
            private = Ed25519PrivateKey.from_private_bytes(private_raw)
            derived_public = private.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            if derived_public != public_raw:
                raise IdentityError("server signing public/private keys do not match")
            identity = ServerIdentity(metadata, public_raw, private_raw)
            identity.assert_consistent()
            payload = b"FluxGate server signing identity self-test\n"
            signature = private.sign(payload)
            Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, payload)
            return identity
        except IdentityError:
            raise
        except (OSError, ValueError, ValidationError, InvalidSignature) as error:
            raise IdentityError("server signing identity is corrupt or inconsistent") from error

    def load_optional(self) -> ServerIdentity | None:
        if self.root.is_symlink():
            raise IdentityError(f"refusing symlinked server identity path: {self.root}")
        if not self.root.exists():
            return None
        return self.load()

    def ensure(self) -> ServerIdentity:
        with self._lock():
            if self.root.is_symlink():
                raise IdentityError(f"refusing symlinked server identity path: {self.root}")
            if self.root.exists():
                return self.load()
            self._assert_safe_ancestors(self.root.parent)
            self.root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.root.parent.chmod(0o700)
            private = Ed25519PrivateKey.generate()
            private_raw = private.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            public_raw = private.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            metadata = StoredIdentityMetadata(
                server_id=uuid4(),
                key_id=key_id_for(public_raw),
                fingerprint=fingerprint_for(public_raw),
                created_at=datetime.now(timezone.utc),
            )
            stage = Path(tempfile.mkdtemp(prefix=".server-identity.", dir=self.root.parent))
            stage.chmod(0o700)
            try:
                atomic_write(stage / ".fluxgate-owner", self.OWNER, 0o600)
                atomic_write(
                    stage / "identity.json",
                    json.dumps(metadata.model_dump(mode="json"), indent=2, sort_keys=True).encode()
                    + b"\n",
                    0o644,
                )
                atomic_write(stage / "private.key", private_raw, 0o600)
                atomic_write(stage / "public.key", public_raw, 0o644)
                os.rename(stage, self.root)
                directory_fd = os.open(self.root.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except BaseException:
                self._remove_stage(stage)
                raise
            return self.load()

    @staticmethod
    def _remove_stage(stage: Path) -> None:
        if not stage.exists():
            return
        for path in stage.iterdir():
            if path.is_symlink() or not path.is_file():
                raise IdentityError(f"refusing unsafe identity staging artifact: {path}")
            path.unlink()
        stage.rmdir()

    def sign(self, payload: bytes, identity: ServerIdentity | None = None) -> bytes:
        value = identity or self.load()
        private = Ed25519PrivateKey.from_private_bytes(value.private_key)
        envelope = SignatureEnvelope(
            key_id=value.metadata.key_id,
            signature=encode_base64(private.sign(payload)),
        )
        return envelope.render()

    @staticmethod
    def verify(payload: bytes, envelope_bytes: bytes, trust: TrustDescriptor) -> None:
        try:
            envelope = SignatureEnvelope.model_validate_json(envelope_bytes)
            if envelope.key_id != trust.key_id:
                raise VerificationError("signature key ID does not match pinned trust")
            public = Ed25519PublicKey.from_public_bytes(trust.raw_public_key())
            public.verify(envelope.raw_signature(), payload)
        except VerificationError:
            raise
        except InvalidSignature as error:
            raise VerificationError("detached signature is invalid") from error
        except (ValueError, ValidationError) as error:
            raise VerificationError("signature envelope is malformed or unsupported") from error
