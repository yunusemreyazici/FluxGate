"""Whole-directory atomic publication for managed signed artifacts."""

from __future__ import annotations

import os
import stat
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path, PurePosixPath

from fluxgate.core.errors import FluxGateError
from fluxgate.core.state import atomic_write

PublishedFile = tuple[bytes, int]


def safe_relative_path(value: str) -> PurePosixPath:
    if (
        not value
        or len(value) > 512
        or value.startswith("/")
        or "\\" in value
        or any(ord(character) < 32 or ord(character) > 126 for character in value)
    ):
        raise FluxGateError(f"unsafe bundle path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise FluxGateError(f"unsafe bundle path: {value!r}")
    if path.as_posix() != value:
        raise FluxGateError(f"bundle path is not normalized: {value!r}")
    return path


def _preflight(destination: Path) -> None:
    checked_anchor = False
    for candidate in (destination, *destination.parents):
        if candidate.is_symlink():
            raise FluxGateError(f"refusing publication through symlinked path: {candidate}")
        if candidate.exists() and not checked_anchor:
            checked_anchor = True
            if candidate != destination and not candidate.is_dir():
                raise FluxGateError(f"publication ancestor is not a directory: {candidate}")
            metadata = candidate.stat()
            if stat.S_IMODE(metadata.st_mode) & 0o022:
                raise FluxGateError(
                    f"refusing publication through group/world-writable path: {candidate}"
                )
            if os.geteuid() == 0 and metadata.st_uid != 0:
                raise FluxGateError(f"publication path is not root-owned: {candidate}")
    if destination.exists() and not destination.is_dir():
        raise FluxGateError(f"publication destination is not a directory: {destination}")


def _remove_owned_tree(root: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        raise FluxGateError(f"refusing to remove unsafe managed tree: {root}")
    for entry in os.scandir(root):
        path = Path(entry.path)
        metadata = entry.stat(follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode):
            raise FluxGateError(f"refusing symlink in managed tree: {path}")
        if stat.S_ISDIR(metadata.st_mode):
            _remove_owned_tree(path)
        elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
            path.unlink()
        else:
            raise FluxGateError(f"refusing unsafe entry in managed tree: {path}")
    root.rmdir()


def publish_tree(
    destination: Path,
    files: Mapping[str, PublishedFile],
    verify: Callable[[Path], object],
) -> None:
    """Publish a complete tree or restore the exact previously verified tree."""
    _preflight(destination)
    normalized = [safe_relative_path(value) for value in files]
    if len(normalized) != len(set(normalized)):
        raise FluxGateError("publication contains duplicate normalized paths")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if destination.exists():
        verify(destination)
    stage = Path(tempfile.mkdtemp(prefix=f".{destination.name}.stage.", dir=destination.parent))
    stage.chmod(0o700)
    backup: Path | None = None
    published = False
    try:
        for relative, (content, mode) in files.items():
            target = stage.joinpath(*safe_relative_path(relative).parts)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.parent.chmod(0o700)
            atomic_write(target, content, mode)
        verify(stage)
        if destination.exists():
            backup = Path(
                tempfile.mkdtemp(prefix=f".{destination.name}.backup.", dir=destination.parent)
            )
            backup.rmdir()
            os.rename(destination, backup)
        os.rename(stage, destination)
        published = True
        verify(destination)
        if backup is not None:
            _remove_owned_tree(backup)
            backup = None
        directory_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException as error:
        try:
            if published and destination.exists():
                _remove_owned_tree(destination)
            elif stage.exists():
                _remove_owned_tree(stage)
            if backup is not None and backup.exists():
                os.rename(backup, destination)
        except BaseException as rollback_error:
            raise FluxGateError(
                f"managed publication failed: {error}; rollback failed: {rollback_error}"
            ) from error
        raise
