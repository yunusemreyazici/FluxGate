"""Crash-safe state persistence."""

from __future__ import annotations

import fcntl
import json
import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from pydantic import ValidationError

from fluxgate.core.errors import StateError
from fluxgate.core.models import FluxGateState


def atomic_write(path: Path, content: bytes, mode: int = 0o600) -> None:
    """Write a regular file atomically, refusing symlink destinations."""
    for parent in (path.parent, *path.parent.parents):
        if parent.is_symlink():
            raise StateError(f"refusing to write through symlinked directory: {parent}")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise StateError(f"refusing to replace symlink: {path}")
    if path.exists() and not stat.S_ISREG(path.lstat().st_mode):
        raise StateError(f"refusing to replace non-regular file: {path}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


class StateStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> FluxGateState:
        if self.path.is_symlink():
            raise StateError(f"refusing to read state through symlink: {self.path}")
        if not self.path.exists():
            return FluxGateState()
        try:
            return FluxGateState.model_validate_json(self.path.read_bytes())
        except (OSError, ValidationError) as error:
            raise StateError(f"invalid state at {self.path}: {error}") from error

    def save(self, state: FluxGateState) -> None:
        payload = (
            json.dumps(
                state.model_dump(mode="json"), sort_keys=True, indent=2, ensure_ascii=False
            ).encode()
            + b"\n"
        )
        try:
            atomic_write(self.path, payload)
        except StateError:
            raise
        except OSError as error:
            raise StateError(f"cannot save state at {self.path}: {error}") from error

    @property
    def exists(self) -> bool:
        return self.path.exists() and not self.path.is_symlink()

    @contextmanager
    def lock(self) -> Iterator[None]:
        """Serialize read-modify-write operations across FluxGate processes."""
        for parent in (self.path.parent, *self.path.parent.parents):
            if parent.is_symlink():
                raise StateError(f"refusing to lock through symlinked directory: {parent}")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock_path = self.path.with_suffix(f"{self.path.suffix}.lock")
        if lock_path.is_symlink():
            raise StateError(f"refusing to use symlink lock file: {lock_path}")
        descriptor: int | None = None
        try:
            descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError as error:
            if descriptor is not None:
                os.close(descriptor)
            raise StateError(f"cannot acquire state lock at {lock_path}: {error}") from error
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
