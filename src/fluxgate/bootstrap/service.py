"""Transactional multi-provider bootstrap generation and verification."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from fluxgate.bootstrap.models import (
    BootstrapArtifact,
    BootstrapDescriptor,
    BootstrapVerification,
)
from fluxgate.clients import ClientService
from fluxgate.core.config import AppConfig
from fluxgate.core.errors import FluxGateError, VerificationError
from fluxgate.core.manifest import ServerManifest, build_manifest
from fluxgate.core.models import ProviderCapability
from fluxgate.core.publication import publish_tree, safe_relative_path
from fluxgate.core.registry import ProviderRegistry
from fluxgate.core.state import StateStore
from fluxgate.identity import ServerIdentityManager, TrustDescriptor
from fluxgate.manifest.service import load_trust
from fluxgate.pathfinder.models import ConnectionMode, PathfinderProvider

STANDARD_FILES = frozenset(
    {"trust.json", "manifest.json", "manifest.sig", "bootstrap.json", "bootstrap.sig"}
)


def _regular_file(path: Path, expected_mode: int) -> None:
    if path.is_symlink() or not path.is_file():
        raise VerificationError(f"bundle entry is not a regular file: {path.name}")
    metadata = path.stat()
    if metadata.st_nlink != 1:
        raise VerificationError(f"bundle entry has unsafe hard links: {path.name}")
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise VerificationError(f"bundle entry has unsafe permissions: {path.name}")


def _assert_safe_root(root: Path) -> None:
    for candidate in (root, *root.parents):
        if candidate.is_symlink():
            raise VerificationError(f"bundle path uses a symlink: {candidate}")
    if not root.is_dir() or stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise VerificationError("bootstrap bundle root must be a mode-0700 directory")


def _assert_safe_tree(root: Path) -> None:
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        if stat.S_IMODE(current_path.stat().st_mode) != 0o700:
            raise VerificationError(f"bundle directory has unsafe permissions: {current_path}")
        for name in (*directories, *filenames):
            path = current_path / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise VerificationError(f"bundle contains a symlink: {path.relative_to(root)}")
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
                raise VerificationError(f"bundle entry has unsafe hard links: {path}")
            if not stat.S_ISREG(metadata.st_mode):
                raise VerificationError(f"bundle contains an unsafe entry: {path}")


def _verify_bootstrap(
    root: Path, *, pinned_trust: TrustDescriptor | None = None
) -> BootstrapVerification:
    _assert_safe_root(root)
    _assert_safe_tree(root)
    for name in STANDARD_FILES:
        _regular_file(root / name, 0o600 if name.startswith("bootstrap") else 0o644)
    bundled_trust = load_trust(root / "trust.json")
    trust = pinned_trust or bundled_trust
    if pinned_trust is not None and bundled_trust != pinned_trust:
        raise VerificationError("bundled trust does not match pinned trust")

    manifest_bytes = (root / "manifest.json").read_bytes()
    ServerIdentityManager.verify(manifest_bytes, (root / "manifest.sig").read_bytes(), trust)
    bootstrap_bytes = (root / "bootstrap.json").read_bytes()
    ServerIdentityManager.verify(bootstrap_bytes, (root / "bootstrap.sig").read_bytes(), trust)
    try:
        manifest = ServerManifest.model_validate_json(manifest_bytes)
        descriptor = BootstrapDescriptor.model_validate_json(bootstrap_bytes)
    except ValidationError as error:
        raise VerificationError(
            "bootstrap or manifest schema is malformed or unsupported"
        ) from error
    if manifest.server.server_id != trust.server_id or descriptor.server_id != trust.server_id:
        raise VerificationError("bundle server IDs do not match trusted server identity")

    declared: set[Path] = set()
    for artifact in descriptor.artifacts:
        relative = safe_relative_path(artifact.path)
        path = root.joinpath(*relative.parts)
        _regular_file(path, 0o600)
        if hashlib.sha256(path.read_bytes()).hexdigest() != artifact.sha256:
            raise VerificationError(f"artifact digest mismatch: {artifact.path}")
        declared.add(path)
    actual = {
        path
        for path in root.rglob("*")
        if path.is_file() and path.relative_to(root).as_posix() not in STANDARD_FILES
    }
    if actual != declared:
        raise VerificationError("bundle contains undeclared or missing provider artifacts")
    expected_directories = {path.parent for path in declared if path.parent != root}
    actual_directories = {path for path in root.rglob("*") if path.is_dir()}
    if actual_directories != expected_directories:
        raise VerificationError("bundle contains unexpected provider directories")
    return BootstrapVerification(
        trust_mode="pinned" if pinned_trust is not None else "initial-offline",
        server_id=descriptor.server_id,
        client_id=descriptor.client_id,
        client_name=descriptor.client_name,
        artifact_count=len(descriptor.artifacts),
    )


def verify_bootstrap(
    root: Path, *, pinned_trust: TrustDescriptor | None = None
) -> BootstrapVerification:
    try:
        return _verify_bootstrap(root, pinned_trust=pinned_trust)
    except VerificationError:
        raise
    except OSError as error:
        raise VerificationError(f"cannot safely read bootstrap bundle: {error}") from error


class BootstrapService:
    def __init__(
        self,
        config: AppConfig,
        state: StateStore,
        providers: ProviderRegistry,
        clients: ClientService,
        identity: ServerIdentityManager,
    ) -> None:
        self.config = config
        self.state = state
        self.providers = providers
        self.clients = clients
        self.identity = identity

    @staticmethod
    def _mode(provider_name: str, providers: ProviderRegistry) -> ConnectionMode:
        mode = providers.get(provider_name).connection_mode
        if mode is None:
            raise FluxGateError(f"provider does not declare a connection mode: {provider_name}")
        return mode

    def export(self, identity_value: str, destination: Path, *, dry_run: bool = False) -> Path:
        if dry_run:
            client = self.clients.find(identity_value)
            return destination / client.name
        with self.state.lock():
            signing_identity = self.identity.ensure()
            state = self.state.load()
            client = ClientService._find(state.clients, identity_value)
            created_at = datetime.now(timezone.utc)
            manifest_bytes = build_manifest(
                self.config,
                state,
                server_id=signing_identity.metadata.server_id,
                generated_at=created_at,
            ).render()
            files: dict[str, tuple[bytes, int]] = {
                "trust.json": (signing_identity.trust.render(), 0o644),
                "manifest.json": (manifest_bytes, 0o644),
                "manifest.sig": (self.identity.sign(manifest_bytes, signing_identity), 0o644),
            }
            inventory: list[BootstrapArtifact] = []
            for provider_name in sorted(client.provider_credentials):
                provider = self.providers.get(provider_name)
                if ProviderCapability.EXPORT_CONFIG not in provider.capabilities:
                    raise FluxGateError(f"provider does not support exports: {provider_name}")
                for exported in provider.export_client(client):
                    path = f"{provider_name}/{exported.name}"
                    content = exported.content.encode()
                    if path in files:
                        raise FluxGateError(f"duplicate bootstrap artifact: {path}")
                    files[path] = (content, 0o600)
                    inventory.append(
                        BootstrapArtifact(
                            path=path,
                            provider=PathfinderProvider(provider_name),
                            candidate_id=f"provider:{provider_name}",
                            media_type=exported.media_type,
                            sha256=hashlib.sha256(content).hexdigest(),
                            connection_mode=self._mode(provider_name, self.providers),
                        )
                    )
            for profile in sorted(state.profiles, key=lambda item: str(item.id)):
                profile_key = str(profile.id)
                if not profile.enabled or profile_key not in client.profile_credentials:
                    continue
                provider = self.providers.get(profile.provider)
                if ProviderCapability.PROFILE_EXPORT not in provider.capabilities:
                    raise FluxGateError(
                        f"provider does not support profile exports: {profile.provider}"
                    )
                exported = provider.export_profile(client, profile)
                path = f"{profile.provider}/{exported.name}"
                content = exported.content.encode()
                if path in files:
                    raise FluxGateError(f"duplicate bootstrap artifact: {path}")
                files[path] = (content, 0o600)
                inventory.append(
                    BootstrapArtifact(
                        path=path,
                        provider=PathfinderProvider(profile.provider),
                        candidate_id=f"profile:{profile.id}",
                        media_type=exported.media_type,
                        sha256=hashlib.sha256(content).hexdigest(),
                        connection_mode=self._mode(profile.provider, self.providers),
                    )
                )
            if not inventory:
                raise FluxGateError(f"client {client.name} has no provisioned credentials")
            descriptor = BootstrapDescriptor(
                server_id=signing_identity.metadata.server_id,
                client_id=client.id,
                client_name=client.name,
                created_at=created_at,
                artifacts=tuple(sorted(inventory, key=lambda item: item.path)),
            )
            bootstrap_bytes = (
                json.dumps(
                    descriptor.model_dump(mode="json"),
                    indent=2,
                    sort_keys=True,
                    ensure_ascii=False,
                ).encode()
                + b"\n"
            )
            files["bootstrap.json"] = (bootstrap_bytes, 0o600)
            files["bootstrap.sig"] = (
                self.identity.sign(bootstrap_bytes, signing_identity),
                0o600,
            )
            root = destination / client.name
            publish_tree(
                root,
                files,
                lambda path: verify_bootstrap(path, pinned_trust=signing_identity.trust),
            )
            directory_fd = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            return root
