"""Profile and profile-scoped client orchestration."""

from __future__ import annotations

from collections.abc import Sequence
from contextlib import nullcontext
from uuid import UUID

from fluxgate.core.errors import FluxGateError
from fluxgate.core.models import (
    Client,
    FluxGateState,
    OperationResult,
    ProfileDefinition,
    ProtocolName,
    ProviderCapability,
    ProviderStateName,
    SecurityName,
    TransportName,
)
from fluxgate.core.registry import ProviderRegistry
from fluxgate.core.state import StateStore


class ProfileService:
    def __init__(self, state: StateStore, providers: ProviderRegistry) -> None:
        self.state = state
        self.providers = providers

    def list(self) -> list[ProfileDefinition]:
        return self.state.load().profiles

    def find(self, identity: str) -> ProfileDefinition:
        return self._find(self.state.load().profiles, identity)

    @staticmethod
    def _find(profiles: Sequence[ProfileDefinition], identity: str) -> ProfileDefinition:
        for profile in profiles:
            if profile.name == identity or str(profile.id) == identity:
                return profile
        raise FluxGateError(f"profile not found: {identity}")

    def create(
        self,
        *,
        name: str,
        provider: str,
        protocol: ProtocolName,
        transport: TransportName,
        security: SecurityName,
        port: int,
        listen_address: str = "0.0.0.0",  # noqa: S104
        dry_run: bool = False,
    ) -> ProfileDefinition:
        profile = ProfileDefinition.model_validate(
            {
                "name": name,
                "provider": provider,
                "protocol": protocol,
                "transport": transport,
                "security": security,
                "listen_address": listen_address,
                "listen_port": port,
            }
        )
        with nullcontext() if dry_run else self.state.lock():
            state = self.state.load()
            if any(item.name == name for item in state.profiles):
                raise FluxGateError(f"profile name already exists: {name}")
            if any(
                item.listen_address == profile.listen_address
                and item.listen_port == profile.listen_port
                and item.socket_protocol == profile.socket_protocol
                for item in state.profiles
            ):
                raise FluxGateError("profile endpoint already exists")
            provider_core = self.providers.get(provider)
            if ProviderCapability.MANAGE_PROFILES not in provider_core.capabilities:
                raise FluxGateError(f"provider does not support profiles: {provider}")
            provider_core.validate_profile(profile, state)
            if not dry_run:
                state.profiles.append(profile)
                self.state.save(state)
            return profile

    def set_enabled(
        self, identity: str, enabled: bool, *, dry_run: bool = False
    ) -> OperationResult:
        with nullcontext() if dry_run else self.state.lock():
            current = self.state.load()
            profile = self._find(current.profiles, identity)
            if profile.enabled == enabled:
                if enabled and not dry_run:
                    self.providers.get(profile.provider).reconcile_profiles(current)
                return OperationResult(changed=False, message="Profile already converged")
            desired = current.model_copy(deep=True)
            changed = self._find(desired.profiles, identity)
            changed.enabled = enabled
            provider = self.providers.get(profile.provider)
            if enabled and not dry_run and provider.status().state != ProviderStateName.RUNNING:
                raise FluxGateError(f"provider is not running: {profile.provider}")
            if dry_run:
                return OperationResult(
                    changed=True,
                    message="Profile enable plan" if enabled else "Profile disable plan",
                    actions=[f"Would {'enable' if enabled else 'disable'} profile {profile.name}"],
                )
            if enabled:
                self.state.save(desired)
                try:
                    provider.reconcile_profiles(desired)
                except BaseException as error:
                    try:
                        self.state.save(current)
                        provider.reconcile_profiles(current)
                    except BaseException as rollback_error:
                        raise FluxGateError(
                            f"profile enable failed: {error}; rollback failed: {rollback_error}; "
                            "retry to reconcile durable state"
                        ) from error
                    raise
            else:
                provider.reconcile_profiles(desired)
                try:
                    self.state.save(desired)
                except BaseException as error:
                    raise FluxGateError(
                        "profile was disabled on the host but state update failed: "
                        f"{error}; retry safely"
                    ) from error
            return OperationResult(
                changed=True,
                message=f"Profile {'enabled' if enabled else 'disabled'}: {profile.name}",
            )

    def delete(self, identity: str, *, dry_run: bool = False) -> UUID:
        with nullcontext() if dry_run else self.state.lock():
            state = self.state.load()
            profile = self._find(state.profiles, identity)
            if profile.enabled:
                raise FluxGateError("disable the profile before deleting it")
            if any(str(profile.id) in client.profile_credentials for client in state.clients):
                raise FluxGateError("profile has provisioned clients; revoke them before deletion")
            if not dry_run:
                state.profiles = [item for item in state.profiles if item.id != profile.id]
                self.state.save(state)
            return profile.id

    @staticmethod
    def replace_client(state: FluxGateState, client: Client) -> None:
        for index, item in enumerate(state.clients):
            if item.id == client.id:
                state.clients[index] = client
                return
        raise FluxGateError("client record disappeared during profile mutation")
