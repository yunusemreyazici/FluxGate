"""Client orchestration through provider capabilities."""

from __future__ import annotations

import json
import stat
from builtins import list as list_type
from collections.abc import Sequence
from contextlib import nullcontext
from pathlib import Path
from uuid import UUID

from fluxgate.core.errors import FluxGateError
from fluxgate.core.models import Client, ProviderCapability, ProviderStateName
from fluxgate.core.registry import ProviderRegistry
from fluxgate.core.state import StateStore, atomic_write


class ClientService:
    def __init__(self, state: StateStore, providers: ProviderRegistry) -> None:
        self.state = state
        self.providers = providers

    def list(self) -> list_type[Client]:
        return self.state.load().clients

    def find(self, identity: str) -> Client:
        state = self.state.load()
        return self._find(state.clients, identity)

    @staticmethod
    def _find(clients: Sequence[Client], identity: str) -> Client:
        for client in clients:
            if client.name == identity or str(client.id) == identity:
                return client
        raise FluxGateError(f"client not found: {identity}")

    def add(self, name: str) -> Client:
        with self.state.lock():
            state = self.state.load()
            if any(client.name == name for client in state.clients):
                raise FluxGateError(f"client name already exists: {name}")
            client = Client(name=name, enabled=False)
            state.clients.append(client)
            self.state.save(state)
            return client

    def enable_provider(self, identity: str, provider_name: str) -> Client:
        with self.state.lock():
            state = self.state.load()
            client = self._find(state.clients, identity)
            core_provider = self.providers.get(provider_name)
            if ProviderCapability.ADD_CLIENTS not in core_provider.capabilities:
                raise FluxGateError(f"provider does not support clients: {provider_name}")
            if provider_name in client.provider_credentials:
                raise FluxGateError(
                    f"client {client.name} already has {core_provider.display_name} credentials"
                )
            if core_provider.status().state != ProviderStateName.RUNNING:
                raise FluxGateError(f"provider is not running: {provider_name}")
            configured = False
            try:
                artifact = core_provider.add_client(client)
                configured = True
                if artifact.provider != core_provider.name:
                    raise FluxGateError(
                        f"provider returned mismatched client artifact: {artifact.provider}"
                    )
                client.provider_credentials[core_provider.name] = artifact.credentials
                client.enabled = True
                self._replace(state.clients, client)
                self.state.save(state)
            except BaseException as error:
                if configured:
                    try:
                        core_provider.revoke_client(client)
                    except BaseException as rollback_error:
                        raise FluxGateError(
                            f"client provider enable failed: {error}; rollback failed: "
                            f"{rollback_error}"
                        ) from error
                raise
            return client

    def enable_profile(
        self, identity: str, profile_identity: str, *, dry_run: bool = False
    ) -> Client:
        with nullcontext() if dry_run else self.state.lock():
            state = self.state.load()
            client = self._find(state.clients, identity)
            profile = next(
                (
                    item
                    for item in state.profiles
                    if item.name == profile_identity or str(item.id) == profile_identity
                ),
                None,
            )
            if profile is None:
                raise FluxGateError(f"profile not found: {profile_identity}")
            key = str(profile.id)
            if key in client.profile_credentials:
                if not dry_run:
                    provider = self.providers.get(profile.provider)
                    if provider.status().state != ProviderStateName.RUNNING:
                        raise FluxGateError(f"provider is not running: {profile.provider}")
                    provider.reconcile_profiles(state)
                return client
            if not profile.enabled:
                raise FluxGateError(f"profile is not enabled: {profile.name}")
            provider = self.providers.get(profile.provider)
            if ProviderCapability.PROFILE_CLIENTS not in provider.capabilities:
                raise FluxGateError(
                    f"provider does not support profile clients: {profile.provider}"
                )
            if dry_run:
                return client
            if provider.status().state != ProviderStateName.RUNNING:
                raise FluxGateError(f"provider is not running: {profile.provider}")
            desired = state.model_copy(deep=True)
            desired_client = self._find(desired.clients, identity)
            desired_client.profile_credentials[key] = provider.generate_profile_credential(profile)
            desired_client.enabled = True
            self.state.save(desired)
            try:
                provider.reconcile_profiles(desired)
            except BaseException as error:
                try:
                    self.state.save(state)
                    provider.reconcile_profiles(state)
                except BaseException as rollback_error:
                    raise FluxGateError(
                        f"profile provisioning failed: {error}; rollback failed: {rollback_error}; "
                        "retry the same command to reconcile durable state"
                    ) from error
                raise
            return desired_client

    def disable_profile(
        self, identity: str, profile_identity: str, *, dry_run: bool = False
    ) -> Client:
        with nullcontext() if dry_run else self.state.lock():
            state = self.state.load()
            client = self._find(state.clients, identity)
            profile = next(
                (
                    item
                    for item in state.profiles
                    if item.name == profile_identity or str(item.id) == profile_identity
                ),
                None,
            )
            if profile is None:
                raise FluxGateError(f"profile not found: {profile_identity}")
            key = str(profile.id)
            if key not in client.profile_credentials:
                raise FluxGateError(f"client {client.name} has no credentials for {profile.name}")
            if dry_run:
                return client
            desired = state.model_copy(deep=True)
            desired_client = self._find(desired.clients, identity)
            desired_client.profile_credentials.pop(key)
            desired_client.enabled = bool(
                desired_client.provider_credentials or desired_client.profile_credentials
            )
            provider = self.providers.get(profile.provider)
            provider.reconcile_profiles(desired)
            try:
                self.state.save(desired)
            except BaseException as error:
                raise FluxGateError(
                    f"profile credential was revoked but state update failed: {error}; retry safely"
                ) from error
            return desired_client

    def disable_provider(self, identity: str, provider_name: str) -> Client:
        with self.state.lock():
            state = self.state.load()
            client = self._find(state.clients, identity)
            core_provider = self.providers.get(provider_name)
            if provider_name not in client.provider_credentials:
                raise FluxGateError(
                    f"client {client.name} has no {core_provider.display_name} credentials"
                )
            original = client.model_copy(deep=True)
            core_provider.revoke_client(original)
            client.provider_credentials.pop(provider_name, None)
            client.enabled = bool(client.provider_credentials or client.profile_credentials)
            self._replace(state.clients, client)
            try:
                self.state.save(state)
            except BaseException as error:
                raise FluxGateError(
                    f"{core_provider.display_name} was revoked but state update failed: {error}; "
                    "rerun the command to reconcile state"
                ) from error
            return client

    @staticmethod
    def _replace(clients: list_type[Client], client: Client) -> None:
        for index, stored in enumerate(clients):
            if stored.id == client.id:
                clients[index] = client
                return
        raise FluxGateError(f"client record disappeared during mutation: {client.id}")

    def revoke(self, identity: str) -> Client:
        with self.state.lock():
            state = self.state.load()
            client = self._find(state.clients, identity)
            if client.profile_credentials:
                desired = state.model_copy(deep=True)
                desired_client = self._find(desired.clients, identity)
                affected = {
                    profile.provider
                    for profile in state.profiles
                    if str(profile.id) in desired_client.profile_credentials
                }
                desired_client.profile_credentials.clear()
                desired_client.enabled = bool(desired_client.provider_credentials)
                for provider_name in sorted(affected):
                    self.providers.get(provider_name).reconcile_profiles(desired)
                self.state.save(desired)
                state = desired
                client = desired_client
            for core_provider in self.providers.all():
                if core_provider.name not in client.provider_credentials:
                    continue
                original = client.model_copy(deep=True)
                core_provider.revoke_client(original)
                client.provider_credentials.pop(core_provider.name, None)
                client.enabled = bool(client.provider_credentials or client.profile_credentials)
                self._replace(state.clients, client)
                try:
                    self.state.save(state)
                except BaseException as error:
                    raise FluxGateError(
                        f"{core_provider.display_name} was revoked but state update failed: "
                        f"{error}; rerun the command to reconcile state"
                    ) from error
            return client

    def export(
        self,
        identity: str,
        destination: Path,
        provider_name: str | None = None,
        profile_identity: str | None = None,
    ) -> list_type[Path]:
        for candidate in (destination, *destination.parents):
            if candidate.is_symlink():
                raise FluxGateError(f"refusing export through symlinked directory: {candidate}")
        if destination.exists() and not destination.is_dir():
            raise FluxGateError(f"export parent is not a directory: {destination}")
        with self.state.lock():
            state = self.state.load()
            client = self._find(state.clients, identity)
            provider_names = (
                [provider_name]
                if provider_name is not None
                else sorted(client.provider_credentials)
            )
            selected_profiles = [
                profile
                for profile in state.profiles
                if str(profile.id) in client.profile_credentials
                and provider_name is None
                and (
                    profile_identity is None
                    or profile.name == profile_identity
                    or str(profile.id) == profile_identity
                )
            ]
            if profile_identity is not None and not selected_profiles:
                raise FluxGateError(
                    f"client {client.name} has no credentials for profile {profile_identity}"
                )
            if profile_identity is not None:
                provider_names = []
            if not provider_names and not selected_profiles:
                raise FluxGateError(f"client {client.name} has no provisioned providers")
            artifacts: list_type[tuple[str, str, bytes]] = []
            for name in provider_names:
                provider = self.providers.get(name)
                if name not in client.provider_credentials:
                    raise FluxGateError(
                        f"client {client.name} has no {provider.display_name} credentials"
                    )
                if ProviderCapability.EXPORT_CONFIG not in provider.capabilities:
                    raise FluxGateError(f"provider does not support exports: {name}")
                for artifact in provider.export_client(client):
                    artifacts.append((name, artifact.name, artifact.content.encode()))
            for profile in selected_profiles:
                provider = self.providers.get(profile.provider)
                if ProviderCapability.PROFILE_EXPORT not in provider.capabilities:
                    raise FluxGateError(
                        f"provider does not support profile exports: {profile.provider}"
                    )
                artifact = provider.export_profile(client, profile)
                artifacts.append((profile.provider, artifact.name, artifact.content.encode()))

            root = destination / client.name
            marker = root / ".fluxgate-export.json"
            marker_content = (
                json.dumps(
                    {
                        "schema_version": 1,
                        "client_id": str(client.id),
                        "client_name": client.name,
                    },
                    sort_keys=True,
                ).encode()
                + b"\n"
            )
            if root.is_symlink() or (root.exists() and not root.is_dir()):
                raise FluxGateError(f"unsafe export destination: {root}")
            if root.exists() and stat.S_IMODE(root.stat().st_mode) & 0o077:
                raise FluxGateError(
                    f"export destination must not be group/world accessible: {root}"
                )
            if (
                root.exists()
                and any(root.iterdir())
                and (
                    marker.is_symlink()
                    or not marker.is_file()
                    or marker.read_bytes() != marker_content
                )
            ):
                raise FluxGateError(f"refusing to overwrite unmanaged export directory: {root}")

            # Validate the complete managed tree before the first mutation so an unsafe stale
            # entry cannot leave an otherwise valid export partially reconciled.
            if root.exists():
                for existing in root.iterdir():
                    if existing == marker:
                        continue
                    if existing.is_symlink() or not existing.is_dir():
                        raise FluxGateError(f"unsafe provider export path: {existing}")
                    if stat.S_IMODE(existing.stat().st_mode) & 0o077:
                        raise FluxGateError(
                            "provider export directory must not be group/world accessible: "
                            f"{existing}"
                        )
                    for path in existing.iterdir():
                        if path.is_symlink() or not path.is_file():
                            raise FluxGateError(f"unsafe provider export artifact: {path}")

            root_existed = root.exists()
            root_mode = stat.S_IMODE(root.stat().st_mode) if root_existed else 0o700
            checkpoint_files = (
                {
                    path.relative_to(root): (
                        path.read_bytes(),
                        stat.S_IMODE(path.stat().st_mode),
                    )
                    for path in root.rglob("*")
                    if path.is_file()
                }
                if root_existed
                else {}
            )
            checkpoint_directories = (
                {
                    path.relative_to(root): stat.S_IMODE(path.stat().st_mode)
                    for path in root.rglob("*")
                    if path.is_dir()
                }
                if root_existed
                else {}
            )

            def restore_export() -> None:
                if not root.exists():
                    if not root_existed:
                        return
                    root.mkdir(parents=True, mode=root_mode)
                for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
                    if path.is_symlink():
                        raise FluxGateError(f"cannot roll back export containing symlink: {path}")
                    relative = path.relative_to(root)
                    if path.is_file() and relative not in checkpoint_files:
                        path.unlink()
                    elif path.is_dir() and relative not in checkpoint_directories:
                        if any(path.iterdir()):
                            raise FluxGateError(
                                f"cannot roll back non-empty unexpected export directory: {path}"
                            )
                        path.rmdir()
                if not root_existed:
                    root.rmdir()
                    return
                root.chmod(root_mode)
                for relative, mode in sorted(
                    checkpoint_directories.items(), key=lambda item: len(item[0].parts)
                ):
                    directory = root / relative
                    directory.mkdir(mode=mode, exist_ok=True)
                    directory.chmod(mode)
                for relative, (content, mode) in checkpoint_files.items():
                    atomic_write(root / relative, content, mode)

            try:
                root.mkdir(parents=True, exist_ok=True, mode=0o700)
                atomic_write(marker, marker_content, 0o600)
                for existing in root.iterdir():
                    managed_providers = set(client.provider_credentials) | {
                        profile.provider
                        for profile in state.profiles
                        if str(profile.id) in client.profile_credentials
                    }
                    if existing == marker or existing.name in managed_providers:
                        continue
                    for path in existing.iterdir():
                        path.unlink()
                    existing.rmdir()
                written: list_type[Path] = []
                for artifact_provider, filename, content in artifacts:
                    provider_dir = root / artifact_provider
                    provider_dir.mkdir(mode=0o700, exist_ok=True)
                    expected = {
                        artifact_filename
                        for selected_provider, artifact_filename, _ in artifacts
                        if selected_provider == artifact_provider
                    }
                    if artifact_provider == "singbox":
                        expected.update(
                            f"{profile.name}.json"
                            for profile in state.profiles
                            if str(profile.id) in client.profile_credentials
                        )
                    for existing in provider_dir.iterdir():
                        if existing.name in expected:
                            continue
                        existing.unlink()
                    path = provider_dir / filename
                    atomic_write(path, content, 0o600)
                    written.append(path)
                return written
            except BaseException as error:
                try:
                    restore_export()
                except BaseException as rollback_error:
                    raise FluxGateError(
                        f"client export failed: {error}; rollback failed: {rollback_error}"
                    ) from error
                raise

    def delete(self, identity: str) -> UUID:
        with self.state.lock():
            state = self.state.load()
            client = self._find(state.clients, identity)
            if client.profile_credentials:
                desired = state.model_copy(deep=True)
                desired_client = self._find(desired.clients, identity)
                affected = {
                    profile.provider
                    for profile in state.profiles
                    if str(profile.id) in desired_client.profile_credentials
                }
                desired_client.profile_credentials.clear()
                desired_client.enabled = bool(desired_client.provider_credentials)
                for provider_name in sorted(affected):
                    self.providers.get(provider_name).reconcile_profiles(desired)
                self.state.save(desired)
                state = desired
                client = desired_client
            for core_provider in self.providers.all():
                if core_provider.name not in client.provider_credentials:
                    continue
                original = client.model_copy(deep=True)
                core_provider.revoke_client(original)
                client.provider_credentials.pop(core_provider.name, None)
                client.enabled = bool(client.provider_credentials or client.profile_credentials)
                self._replace(state.clients, client)
                try:
                    self.state.save(state)
                except BaseException as error:
                    raise FluxGateError(
                        f"{core_provider.display_name} was revoked but state update failed: "
                        f"{error}; rerun the command to reconcile state"
                    ) from error
            state.clients = [stored for stored in state.clients if stored.id != client.id]
            self.state.save(state)
            return client.id
