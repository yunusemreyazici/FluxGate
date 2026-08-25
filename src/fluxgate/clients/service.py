"""Client orchestration through provider capabilities."""

from __future__ import annotations

import json
import stat
from builtins import list as list_type
from collections.abc import Sequence
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
            client.provider_credentials.pop(provider_name, None)
            client.enabled = bool(client.provider_credentials)
            self._replace(state.clients, client)
            self.state.save(state)
            try:
                core_provider.revoke_client(original)
            except BaseException as error:
                self._replace(state.clients, original)
                try:
                    self.state.save(state)
                except BaseException as rollback_error:
                    raise FluxGateError(
                        f"client provider disable failed: {error}; state rollback failed: "
                        f"{rollback_error}"
                    ) from error
                raise
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
            for core_provider in self.providers.all():
                if core_provider.name not in client.provider_credentials:
                    continue
                original = client.model_copy(deep=True)
                client.provider_credentials.pop(core_provider.name, None)
                client.enabled = bool(client.provider_credentials)
                self._replace(state.clients, client)
                self.state.save(state)
                try:
                    core_provider.revoke_client(original)
                except BaseException:
                    self._replace(state.clients, original)
                    self.state.save(state)
                    raise
            return client

    def export(
        self, identity: str, destination: Path, provider_name: str | None = None
    ) -> list_type[Path]:
        with self.state.lock():
            client = self._find(self.state.load().clients, identity)
            provider_names = (
                [provider_name]
                if provider_name is not None
                else sorted(client.provider_credentials)
            )
            if not provider_names:
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

        root = destination / client.name
        marker = root / ".fluxgate-export.json"
        marker_content = (
            json.dumps(
                {"schema_version": 1, "client_id": str(client.id), "client_name": client.name},
                sort_keys=True,
            ).encode()
            + b"\n"
        )
        if root.is_symlink() or (root.exists() and not root.is_dir()):
            raise FluxGateError(f"unsafe export destination: {root}")
        if root.exists() and stat.S_IMODE(root.stat().st_mode) & 0o077:
            raise FluxGateError(f"export destination must not be group/world accessible: {root}")
        if (
            root.exists()
            and any(root.iterdir())
            and (
                marker.is_symlink() or not marker.is_file() or marker.read_bytes() != marker_content
            )
        ):
            raise FluxGateError(f"refusing to overwrite unmanaged export directory: {root}")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_write(marker, marker_content, 0o600)
        for existing in root.iterdir():
            if existing == marker or existing.name in client.provider_credentials:
                continue
            if existing.is_symlink() or not existing.is_dir():
                raise FluxGateError(f"unsafe stale provider export path: {existing}")
            for path in existing.iterdir():
                if path.is_symlink() or not path.is_file():
                    raise FluxGateError(f"unsafe stale provider export artifact: {path}")
            for path in existing.iterdir():
                path.unlink()
            existing.rmdir()
        written: list_type[Path] = []
        for artifact_provider, filename, content in artifacts:
            provider_dir = root / artifact_provider
            if provider_dir.is_symlink() or (provider_dir.exists() and not provider_dir.is_dir()):
                raise FluxGateError(f"unsafe provider export destination: {provider_dir}")
            provider_dir.mkdir(mode=0o700, exist_ok=True)
            if stat.S_IMODE(provider_dir.stat().st_mode) & 0o077:
                raise FluxGateError(
                    f"provider export directory must not be group/world accessible: {provider_dir}"
                )
            expected = {
                artifact_filename
                for provider_name, artifact_filename, _ in artifacts
                if provider_name == artifact_provider
            }
            for existing in provider_dir.iterdir():
                if existing.name in expected:
                    continue
                if existing.is_symlink() or not existing.is_file():
                    raise FluxGateError(f"unsafe stale provider export artifact: {existing}")
                existing.unlink()
            path = provider_dir / filename
            atomic_write(path, content, 0o600)
            written.append(path)
        return written

    def delete(self, identity: str) -> UUID:
        with self.state.lock():
            state = self.state.load()
            client = self._find(state.clients, identity)
            for core_provider in self.providers.all():
                if core_provider.name not in client.provider_credentials:
                    continue
                original = client.model_copy(deep=True)
                client.provider_credentials.pop(core_provider.name, None)
                client.enabled = bool(client.provider_credentials)
                self._replace(state.clients, client)
                self.state.save(state)
                try:
                    core_provider.revoke_client(original)
                except BaseException:
                    self._replace(state.clients, original)
                    self.state.save(state)
                    raise
            state.clients = [stored for stored in state.clients if stored.id != client.id]
            self.state.save(state)
            return client.id
