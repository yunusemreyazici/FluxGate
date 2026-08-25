"""Production WireGuard provider and configuration management."""

from __future__ import annotations

import shutil
from ipaddress import IPv4Network
from pathlib import Path

from fluxgate.core.config import WireGuardConfig
from fluxgate.core.errors import ProviderError
from fluxgate.core.models import (
    Client,
    ClientArtifact,
    ExportArtifact,
    HealthResult,
    OperationResult,
    ProviderCapability,
    ProviderDetection,
    ProviderStateName,
    ProviderStatus,
)
from fluxgate.core.operations import OperationPlan
from fluxgate.core.state import atomic_write
from fluxgate.providers.base import CoreProvider
from fluxgate.providers.wireguard.health import wireguard_health
from fluxgate.providers.wireguard.keys import WireGuardKeys
from fluxgate.providers.wireguard.rendering import (
    allocate_address,
    credential,
    render_client,
    render_server,
    tunnel_network,
)


class WireGuardProvider(CoreProvider):
    name = "wireguard"
    display_name = "WireGuard"
    capabilities = frozenset(
        {
            ProviderCapability.ADD_CLIENTS,
            ProviderCapability.EXPORT_CONFIG,
            ProviderCapability.RELOAD,
        }
    )

    @property
    def settings(self) -> WireGuardConfig:
        return self.context.config.cores.wireguard

    @property
    def unit(self) -> str:
        return f"wg-quick@{self.settings.interface}.service"

    @property
    def config_path(self) -> Path:
        return self.context.paths.wireguard_dir / f"{self.settings.interface}.conf"

    @property
    def private_key_path(self) -> Path:
        return WireGuardKeys(self.context).private_path

    @property
    def public_key_path(self) -> Path:
        return WireGuardKeys(self.context).public_path

    def detect(self) -> ProviderDetection:
        binaries = {name: shutil.which(name) is not None for name in ("wg", "wg-quick", "nft")}
        available = binaries["wg"] and binaries["wg-quick"]
        return ProviderDetection(
            available=available,
            binaries=binaries,
            detail="WireGuard tools available" if available else "WireGuard tools missing",
        )

    def _enabled_in_state(self) -> bool:
        return bool(
            self.context.state.load()
            .providers.get(self.name, {})
            .get("enabled", self.settings.enabled)
        )

    def status(self) -> ProviderStatus:
        detection = self.detect()
        enabled = self._enabled_in_state()
        active = enabled and detection.available and self.context.services.is_active(self.unit)
        if active:
            state = ProviderStateName.RUNNING
        elif enabled and detection.available:
            state = ProviderStateName.STOPPED
        elif enabled:
            state = ProviderStateName.NOT_INSTALLED
        else:
            state = ProviderStateName.DISABLED
        return ProviderStatus(
            name=self.name,
            state=state,
            enabled=enabled,
            installed=detection.available,
            detail=detection.detail,
        )

    def _keypair(self) -> tuple[str, str]:
        return WireGuardKeys(self.context).keypair()

    def _ensure_server_keys(self) -> bool:
        return WireGuardKeys(self.context).ensure_server()

    def _provider_clients(
        self, extra: Client | None = None, exclude: Client | None = None
    ) -> list[Client]:
        clients = [
            client
            for client in self.context.state.load().clients
            if self.name in client.provider_credentials
            and (exclude is None or client.id != exclude.id)
        ]
        if extra is not None:
            clients.append(extra)
        return clients

    def _server_config(self, clients: list[Client]) -> bytes:
        return render_server(self.settings, WireGuardKeys(self.context).read_private(), clients)

    def _credential(self, client: Client) -> dict[str, object]:
        return credential(client, self._network())

    def _network(self) -> IPv4Network:
        return tunnel_network(self.settings)

    def _allocate_address(self) -> str:
        return allocate_address(self.settings, self._provider_clients())

    def _set_enabled_state(self, enabled: bool) -> None:
        state = self.context.state.load()
        provider_state = dict(state.providers.get(self.name, {}))
        provider_state["enabled"] = enabled
        state.providers[self.name] = provider_state
        self.context.state.save(state)

    def _is_converged(self, detection: ProviderDetection, active: bool) -> bool:
        if not (
            self._enabled_in_state()
            and detection.available
            and detection.binaries.get("nft", False)
            and active
            and self.private_key_path.exists()
            and self.public_key_path.exists()
            and self.config_path.exists()
            and not self.config_path.is_symlink()
        ):
            return False
        if self.config_path.read_bytes() != self._server_config(self._provider_clients()):
            return False
        network = str(self._network())
        outbound = self.context.config.network.outbound_interface
        return (
            self.context.forwarding.enabled()
            and self.context.forwarding.configured()
            and self.context.firewall.configured(network, outbound)
        )

    def configuration_valid(self) -> bool:
        try:
            return (
                self.config_path.exists()
                and not self.config_path.is_symlink()
                and self.config_path.read_bytes() == self._server_config(self._provider_clients())
            )
        except (OSError, ProviderError):
            return False

    def enable(self) -> OperationResult:
        detection = self.detect()
        active = self.context.services.is_active(self.unit) if detection.available else False
        if self._is_converged(detection, active):
            return OperationResult(changed=False, message="WireGuard is already enabled")
        plan = OperationPlan()
        packages: list[str] = []
        if not detection.available:
            packages.append("wireguard-tools")
        if not detection.binaries.get("nft", False):
            packages.append("nftables")
        if packages:
            plan.add(
                f"Would install: {', '.join(packages)}",
                lambda: self.context.packages.install(packages),
            )
        private_existed = self.private_key_path.exists()
        public_existed = self.public_key_path.exists()
        keys_exist = private_existed and public_existed
        if not keys_exist:

            def remove_new_keys() -> None:
                if not private_existed:
                    self.private_key_path.unlink(missing_ok=True)
                if not public_existed:
                    self.public_key_path.unlink(missing_ok=True)

            plan.add(
                "Would generate or repair server WireGuard keys",
                lambda: self._ensure_server_keys(),
                remove_new_keys,
            )
        if self.config_path.is_symlink():
            raise ProviderError(
                f"refusing to replace WireGuard configuration symlink: {self.config_path}"
            )
        old_config = self.config_path.read_bytes() if self.config_path.exists() else None

        def write_config() -> None:
            atomic_write(self.config_path, self._server_config(self._provider_clients()), 0o600)

        def restore_config() -> None:
            if old_config is None:
                self.config_path.unlink(missing_ok=True)
            else:
                atomic_write(self.config_path, old_config, 0o600)

        plan.add(f"Would converge: {self.config_path}", write_config, restore_config)
        if not self.context.forwarding.enabled() or not self.context.forwarding.configured():
            plan.add(
                "Would enable: IPv4 forwarding",
                lambda: self.context.forwarding.ensure(),
                lambda: self.context.forwarding.remove(),
            )
        network = str(self._network())
        outbound = self.context.config.network.outbound_interface
        if not self.context.firewall.configured(network, outbound):
            plan.add(
                "Would configure: persistent FluxGate nftables NAT rules",
                lambda: self.context.firewall.ensure_nat(network, outbound),
                lambda: self.context.firewall.remove(),
            )
        if not active:
            plan.add(
                f"Would enable: {self.unit}",
                lambda: self.context.services.enable_now(self.unit),
                lambda: self.context.services.disable_now(self.unit),
            )
        if not self._enabled_in_state():
            plan.add("Would update: FluxGate provider state", lambda: self._set_enabled_state(True))
        actions = plan.execute(dry_run=self.context.dry_run)
        return OperationResult(
            changed=True,
            message="WireGuard enable plan" if self.context.dry_run else "WireGuard enabled",
            actions=actions,
        )

    def disable(self) -> OperationResult:
        if not self._enabled_in_state():
            return OperationResult(changed=False, message="WireGuard is already disabled")
        plan = OperationPlan()
        plan.add(
            f"Would disable: {self.unit}", lambda: self.context.services.disable_now(self.unit)
        )
        plan.add("Would remove: FluxGate nftables table", lambda: self.context.firewall.remove())
        plan.add(
            "Would remove: FluxGate forwarding persistence",
            lambda: self.context.forwarding.remove(),
        )
        plan.add("Would update: FluxGate provider state", lambda: self._set_enabled_state(False))
        actions = plan.execute(dry_run=self.context.dry_run)
        return OperationResult(
            changed=True,
            message="WireGuard disable plan" if self.context.dry_run else "WireGuard disabled",
            actions=actions,
        )

    def _client_private_path(self, client: Client) -> Path:
        return self.context.paths.secrets_dir / "clients" / f"{client.id}.wireguard.key"

    def _client_config_path(self, client: Client) -> Path:
        return self.context.paths.clients_dir / f"{client.id}.wireguard.conf"

    def _export_content(self, client: Client, private: str) -> str:
        return render_client(
            self.settings,
            self.context.config.server.domain,
            WireGuardKeys(self.context).read_public(),
            client,
            private,
        )

    def add_client(self, client: Client) -> ClientArtifact:
        if not self._enabled_in_state():
            raise ProviderError("WireGuard must be enabled before adding a peer")
        if self.name in client.provider_credentials:
            raise ProviderError(f"client {client.name} already has WireGuard credentials")
        private, public = self._keypair()
        address = self._allocate_address()
        client.provider_credentials[self.name] = {"public_key": public, "address": address}
        export = self._export_content(client, private)
        private_path = self._client_private_path(client)
        export_path = self._client_config_path(client)
        if self.config_path.is_symlink():
            raise ProviderError("WireGuard configuration is a symlink")
        old_server = self.config_path.read_bytes() if self.config_path.exists() else None
        plan = OperationPlan()
        plan.add(
            f"Store private material for {client.name}",
            lambda: atomic_write(private_path, f"{private}\n".encode(), 0o600),
            lambda: private_path.unlink(missing_ok=True),
        )
        plan.add(
            f"Create WireGuard export for {client.name}",
            lambda: atomic_write(export_path, export.encode(), 0o600),
            lambda: export_path.unlink(missing_ok=True),
        )

        def restore_server() -> None:
            if old_server is None:
                self.config_path.unlink(missing_ok=True)
            else:
                atomic_write(self.config_path, old_server, 0o600)
                self.context.services.reload(self.unit)

        plan.add(
            f"Add WireGuard peer {client.name}",
            lambda: atomic_write(
                self.config_path, self._server_config(self._provider_clients(extra=client)), 0o600
            ),
            restore_server,
        )
        plan.add(f"Reload {self.unit}", lambda: self.context.services.reload(self.unit))
        plan.execute(dry_run=self.context.dry_run)
        return ClientArtifact(
            provider=self.name,
            credentials={"public_key": public, "address": address},
            exports=[
                ExportArtifact(
                    name=f"{client.name}.conf", media_type="text/plain", content=export, secret=True
                )
            ],
        )

    def revoke_client(self, client: Client) -> OperationResult:
        if self.name not in client.provider_credentials:
            return OperationResult(changed=False, message="client has no WireGuard peer")
        if self.config_path.is_symlink():
            raise ProviderError("WireGuard configuration is a symlink")
        old_config = self.config_path.read_bytes()
        try:
            atomic_write(
                self.config_path,
                self._server_config(self._provider_clients(exclude=client)),
                0o600,
            )
            self.context.services.reload(self.unit)
        except BaseException:
            atomic_write(self.config_path, old_config, 0o600)
            self.context.services.reload(self.unit)
            raise
        self._client_private_path(client).unlink(missing_ok=True)
        self._client_config_path(client).unlink(missing_ok=True)
        return OperationResult(changed=True, message=f"revoked WireGuard peer for {client.name}")

    def export_client(self, client: Client) -> list[ExportArtifact]:
        path = self._client_config_path(client)
        if not path.exists() or path.is_symlink():
            raise ProviderError(f"WireGuard export for {client.name} is unavailable")
        return [
            ExportArtifact(
                name=f"{client.name}.conf",
                media_type="text/plain",
                content=path.read_text(),
                secret=True,
            )
        ]

    def healthcheck(self) -> list[HealthResult]:
        return wireguard_health(self)
