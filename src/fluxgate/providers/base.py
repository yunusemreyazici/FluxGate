"""Provider contract and injected operation context."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from fluxgate.core.commands import CommandRunner
from fluxgate.core.config import AppConfig
from fluxgate.core.models import (
    Client,
    ClientArtifact,
    ExportArtifact,
    FluxGateState,
    HealthLevel,
    HealthResult,
    OperationResult,
    ProfileDefinition,
    ProviderCapability,
    ProviderDetection,
    ProviderStatus,
)
from fluxgate.core.paths import PathLayout
from fluxgate.core.state import StateStore
from fluxgate.pathfinder.models import ConnectionMode
from fluxgate.system.firewall import FirewallManager
from fluxgate.system.forwarding import ForwardingManager
from fluxgate.system.networking import NetworkInspector
from fluxgate.system.packages import PackageManager
from fluxgate.system.services import ServiceManager


@dataclass(slots=True)
class OperationContext:
    config: AppConfig
    paths: PathLayout
    state: StateStore
    runner: CommandRunner
    packages: PackageManager
    services: ServiceManager
    firewall: FirewallManager
    forwarding: ForwardingManager
    network: NetworkInspector
    dry_run: bool = False


class CoreProvider(ABC):
    name: str
    display_name: str
    capabilities: frozenset[ProviderCapability] = frozenset()
    connection_mode: ConnectionMode | None = None

    def __init__(self, context: OperationContext) -> None:
        self.context = context

    @abstractmethod
    def detect(self) -> ProviderDetection: ...

    @abstractmethod
    def status(self) -> ProviderStatus: ...

    @abstractmethod
    def enable(self) -> OperationResult: ...

    @abstractmethod
    def disable(self) -> OperationResult: ...

    def add_client(self, client: Client) -> ClientArtifact:
        from fluxgate.core.errors import UnsupportedProviderError

        raise UnsupportedProviderError(f"{self.display_name} does not support adding clients")

    def revoke_client(self, client: Client) -> OperationResult:
        from fluxgate.core.errors import UnsupportedProviderError

        raise UnsupportedProviderError(f"{self.display_name} does not support revoking clients")

    def export_client(self, client: Client) -> list[ExportArtifact]:
        from fluxgate.core.errors import UnsupportedProviderError

        raise UnsupportedProviderError(f"{self.display_name} does not support client exports")

    def healthcheck(self) -> list[HealthResult]:
        status = self.status()
        if status.state.value == "running":
            level = HealthLevel.SUCCESS
        elif status.state.value in {"disabled", "unsupported"}:
            level = HealthLevel.INFO
        else:
            level = HealthLevel.FAILURE
        return [HealthResult(name="provider-status", level=level, message=status.detail)]

    def reconcile_profiles(self, desired: FluxGateState) -> OperationResult:
        from fluxgate.core.errors import UnsupportedProviderError

        raise UnsupportedProviderError(f"{self.display_name} does not support profiles")

    def validate_profile(self, profile: ProfileDefinition, state: FluxGateState) -> None:
        from fluxgate.core.errors import UnsupportedProviderError

        raise UnsupportedProviderError(f"{self.display_name} does not support profiles")

    def generate_profile_credential(self, profile: ProfileDefinition) -> dict[str, object]:
        from fluxgate.core.errors import UnsupportedProviderError

        raise UnsupportedProviderError(f"{self.display_name} does not support profile clients")

    def export_profile(self, client: Client, profile: ProfileDefinition) -> ExportArtifact:
        from fluxgate.core.errors import UnsupportedProviderError

        raise UnsupportedProviderError(f"{self.display_name} does not support profile exports")

    def profile_export_artifact_name(self, profile: ProfileDefinition) -> str:
        from fluxgate.core.errors import UnsupportedProviderError

        raise UnsupportedProviderError(f"{self.display_name} does not support profile exports")
