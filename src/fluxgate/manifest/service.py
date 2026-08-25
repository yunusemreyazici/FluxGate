"""Exact-byte signed public manifest lifecycle."""

from __future__ import annotations

import stat
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from fluxgate.core.config import AppConfig
from fluxgate.core.errors import VerificationError
from fluxgate.core.manifest import ServerManifest, build_manifest
from fluxgate.core.publication import publish_tree
from fluxgate.core.state import StateStore
from fluxgate.identity import ServerIdentityManager, TrustDescriptor


def load_trust(path: Path) -> TrustDescriptor:
    try:
        for candidate in (path, *path.parents):
            if candidate.is_symlink():
                raise VerificationError(f"trust descriptor path uses a symlink: {candidate}")
        if path.is_symlink() or not path.is_file():
            raise VerificationError(f"trust descriptor is not a regular file: {path}")
        return TrustDescriptor.model_validate_json(path.read_bytes())
    except VerificationError:
        raise
    except (OSError, ValidationError) as error:
        raise VerificationError("trust descriptor is malformed or unsupported") from error


def _verify_signed_manifest(
    root: Path, pinned_trust: TrustDescriptor | None = None
) -> ServerManifest:
    required = {"manifest.json", "manifest.sig", "trust.json"}
    for candidate in (root, *root.parents):
        if candidate.is_symlink():
            raise VerificationError(f"signed manifest path uses a symlink: {candidate}")
    if root.is_symlink() or not root.is_dir():
        raise VerificationError(f"signed manifest path is not a safe directory: {root}")
    if stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise VerificationError("signed manifest directory must have mode 0700")
    if {path.name for path in root.iterdir()} != required:
        raise VerificationError("signed manifest directory has missing or unexpected files")
    for name in required:
        path = root / name
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            raise VerificationError(f"unsafe signed manifest file: {name}")
        if stat.S_IMODE(path.stat().st_mode) != 0o644:
            raise VerificationError(f"signed manifest file has unsafe permissions: {name}")
    bundled_trust = load_trust(root / "trust.json")
    trust = pinned_trust or bundled_trust
    if pinned_trust is not None and bundled_trust != pinned_trust:
        raise VerificationError("bundled trust does not match pinned trust")
    manifest_bytes = (root / "manifest.json").read_bytes()
    ServerIdentityManager.verify(manifest_bytes, (root / "manifest.sig").read_bytes(), trust)
    try:
        manifest = ServerManifest.model_validate_json(manifest_bytes)
    except ValidationError as error:
        raise VerificationError("manifest schema is malformed or unsupported") from error
    if manifest.server.server_id != trust.server_id:
        raise VerificationError("manifest server ID does not match pinned trust")
    return manifest


def verify_signed_manifest(
    root: Path, pinned_trust: TrustDescriptor | None = None
) -> ServerManifest:
    try:
        return _verify_signed_manifest(root, pinned_trust)
    except VerificationError:
        raise
    except OSError as error:
        raise VerificationError(f"cannot safely read signed manifest: {error}") from error


class SignedManifestService:
    def __init__(
        self, config: AppConfig, state: StateStore, identity: ServerIdentityManager
    ) -> None:
        self.config = config
        self.state = state
        self.identity = identity

    def export(self, destination: Path, *, dry_run: bool = False) -> tuple[Path, ...]:
        if dry_run:
            names = ("manifest.json", "manifest.sig", "trust.json")
            return tuple(destination / name for name in names)
        with self.state.lock():
            identity = self.identity.ensure()
            manifest = build_manifest(
                self.config,
                self.state.load(),
                server_id=identity.metadata.server_id,
                generated_at=datetime.now(timezone.utc),
            ).render()
            files = {
                "manifest.json": (manifest, 0o644),
                "manifest.sig": (self.identity.sign(manifest, identity), 0o644),
                "trust.json": (identity.trust.render(), 0o644),
            }
            publish_tree(
                destination,
                files,
                lambda root: verify_signed_manifest(root, identity.trust),
            )
        return tuple(destination / name for name in files)
