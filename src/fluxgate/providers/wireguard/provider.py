"""Production WireGuard provider and configuration management."""

from __future__ import annotations

import shutil
from ipaddress import IPv4Network
from pathlib import Path

from fluxgate.core.config import WireGuardConfig
from fluxgate.core.errors import ProviderError, StateError
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
    CONFIG_HEADER = b"# Managed by FluxGate;"

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
        value = (
            self.context.state.load()
            .providers.get(self.name, {})
            .get("enabled", self.settings.enabled)
        )
        if not isinstance(value, bool):
            raise StateError("invalid WireGuard provider state: enabled must be a boolean")
        return value

    def status(self) -> ProviderStatus:
        detection = self.detect()
        enabled = self._enabled_in_state()
        active = (
            enabled
            and detection.available
            and self.context.services.is_active(self.unit)
            and self._interface_exists()
        )
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

    def _config_owned(self) -> bool:
        if self.config_path.is_symlink():
            raise ProviderError(
                f"refusing to use WireGuard configuration symlink: {self.config_path}"
            )
        return self.config_path.exists() and self.config_path.read_bytes().startswith(
            self.CONFIG_HEADER
        )

    def _assert_config_ownership(self) -> None:
        if self.config_path.is_symlink():
            raise ProviderError(
                f"refusing to use WireGuard configuration symlink: {self.config_path}"
            )
        if self.config_path.exists() and not self._config_owned():
            raise ProviderError(
                f"refusing to replace unmanaged WireGuard configuration: {self.config_path}"
            )

    def _require_owned_config(self) -> None:
        if not self._config_owned():
            raise ProviderError(f"managed WireGuard configuration is missing: {self.config_path}")

    def _interface_exists(self) -> bool:
        if self.context.dry_run:
            return False
        return self.context.network.interface_exists(self.settings.interface)

    def _reload_peers(self) -> None:
        stripped = self.context.runner.run(["wg-quick", "strip", str(self.config_path)]).stdout
        self.context.runner.run(
            ["wg", "syncconf", self.settings.interface, "/dev/stdin"],
            input_text=stripped,
            mutate=True,
        )

    def _is_converged(self, detection: ProviderDetection, active: bool) -> bool:
        if not (
            self._enabled_in_state()
            and detection.available
            and detection.binaries.get("nft", False)
            and active
            and self._interface_exists()
            and self.context.services.is_enabled(self.unit)
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
            and self.context.forwarding.configured(self.name)
            and self.context.firewall.configured(self.name, network, outbound)
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
        if self.context.dry_run:
            return self._enable_locked()
        with self.context.state.lock():
            return self._enable_locked()

    def _enable_locked(self) -> OperationResult:
        self._assert_config_ownership()
        if not self.context.config.network.ipv4:
            raise ProviderError("WireGuard 0.1 requires network.ipv4 to be enabled")
        state_missing = not self.context.state.exists
        if state_missing and self._config_owned() and b"[Peer]" in self.config_path.read_bytes():
            raise ProviderError(
                "FluxGate state is missing while the managed WireGuard configuration contains "
                "peers; restore state before reconciling to avoid peer loss"
            )
        detection = self.detect()
        service_active = (
            self.context.services.is_active(self.unit)
            if detection.available and not self.context.dry_run
            else False
        )
        service_enabled = (
            self.context.services.is_enabled(self.unit)
            if detection.available and not self.context.dry_run
            else False
        )
        interface_present = self._interface_exists()
        if interface_present and not service_active:
            raise ProviderError(
                f"network interface {self.settings.interface} already exists and is not managed "
                "by FluxGate"
            )
        if not self.context.dry_run:
            outbound = self.context.config.network.outbound_interface
            if outbound is not None and not self.context.network.interface_exists(outbound):
                raise ProviderError(f"outbound network interface does not exist: {outbound}")
            if not service_active and not self.context.network.udp_port_available(
                self.settings.listen_port
            ):
                raise ProviderError(
                    f"UDP listen port is already in use: {self.settings.listen_port}"
                )
            route_conflict = self.context.network.conflicting_route(
                self._network(), self.settings.interface
            )
            if route_conflict is not None and not service_active:
                raise ProviderError(
                    f"WireGuard tunnel network {self._network()} overlaps existing route: "
                    f"{route_conflict}"
                )
        if self._is_converged(detection, service_active):
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
        config_current = keys_exist and self.configuration_valid()
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
        old_config = self.config_path.read_bytes() if self.config_path.exists() else None

        def write_config() -> None:
            atomic_write(self.config_path, self._server_config(self._provider_clients()), 0o600)

        def restore_config() -> None:
            if old_config is None:
                self.config_path.unlink(missing_ok=True)
            else:
                atomic_write(self.config_path, old_config, 0o600)
            if service_active:
                self.context.services.restart(self.unit)

        if not config_current:
            plan.add(f"Would converge: {self.config_path}", write_config, restore_config)
        forwarding_checkpoint = self.context.forwarding.checkpoint()
        if not self.context.forwarding.enabled() or not self.context.forwarding.configured(
            self.name
        ):
            plan.add(
                "Would enable: IPv4 forwarding",
                lambda: self.context.forwarding.acquire(self.name),
                lambda: self.context.forwarding.restore(forwarding_checkpoint),
            )
        network = str(self._network())
        outbound = self.context.config.network.outbound_interface
        firewall_checkpoint = (
            object() if self.context.dry_run else self.context.firewall.checkpoint()
        )
        firewall_configured = (
            False
            if self.context.dry_run
            else self.context.firewall.configured(self.name, network, outbound)
        )
        if not firewall_configured:
            plan.add(
                "Would configure: persistent FluxGate nftables NAT rules",
                lambda: self.context.firewall.ensure_nat(self.name, network, outbound),
                lambda: self.context.firewall.restore(firewall_checkpoint),
            )
        service_was_active, service_was_enabled = service_active, service_enabled
        if not service_active or not service_enabled:
            plan.add(
                f"Would enable: {self.unit}",
                lambda: self.context.services.enable_now(self.unit),
                lambda: self.context.services.restore(
                    self.unit, enabled=service_was_enabled, active=service_was_active
                ),
            )
        if service_active and (not interface_present or not config_current):
            plan.add(
                f"Would restart: {self.unit} to recover live state",
                lambda: self.context.services.restart(self.unit),
            )
        if state_missing or not self._enabled_in_state():
            plan.add("Would update: FluxGate provider state", lambda: self._set_enabled_state(True))
        actions = plan.execute(dry_run=self.context.dry_run)
        return OperationResult(
            changed=True,
            message="WireGuard enable plan" if self.context.dry_run else "WireGuard enabled",
            actions=actions,
        )

    def disable(self) -> OperationResult:
        if self.context.dry_run:
            return self._disable_locked()
        with self.context.state.lock():
            return self._disable_locked()

    def _disable_locked(self) -> OperationResult:
        self._assert_config_ownership()
        enabled_in_state = self._enabled_in_state()
        service_active = (
            enabled_in_state if self.context.dry_run else self.context.services.is_active(self.unit)
        )
        service_enabled = (
            enabled_in_state
            if self.context.dry_run
            else self.context.services.is_enabled(self.unit)
        )
        firewall_managed = (
            enabled_in_state if self.context.dry_run else self.context.firewall.managed(self.name)
        )
        forwarding_managed = self.context.forwarding.configured(self.name)
        if not (
            enabled_in_state
            or service_active
            or service_enabled
            or firewall_managed
            or forwarding_managed
        ):
            return OperationResult(changed=False, message="WireGuard is already disabled")
        plan = OperationPlan()
        if service_active or service_enabled:
            plan.add(
                f"Would disable: {self.unit}",
                lambda: self.context.services.disable_now(self.unit),
                lambda: self.context.services.restore(
                    self.unit, enabled=service_enabled, active=service_active
                ),
            )
        if firewall_managed:
            firewall_checkpoint = self.context.firewall.checkpoint()
            plan.add(
                "Would remove: WireGuard nftables NAT rule",
                lambda: self.context.firewall.remove_nat(self.name),
                lambda: self.context.firewall.restore(firewall_checkpoint),
            )
        if forwarding_managed:
            forwarding_checkpoint = self.context.forwarding.checkpoint()
            plan.add(
                "Would release: WireGuard forwarding lease",
                lambda: self.context.forwarding.release(self.name),
                lambda: self.context.forwarding.restore(forwarding_checkpoint),
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
        self._require_owned_config()
        private, public = self._keypair()
        address = self._allocate_address()
        client.provider_credentials[self.name] = {"public_key": public, "address": address}
        export = self._export_content(client, private)
        private_path = self._client_private_path(client)
        export_path = self._client_config_path(client)
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
                self._reload_peers()

        plan.add(
            f"Add WireGuard peer {client.name}",
            lambda: atomic_write(
                self.config_path, self._server_config(self._provider_clients(extra=client)), 0o600
            ),
            restore_server,
        )
        plan.add(f"Reload {self.unit}", self._reload_peers)
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
        self._require_owned_config()
        old_config = self.config_path.read_bytes()
        try:
            atomic_write(
                self.config_path,
                self._server_config(self._provider_clients(exclude=client)),
                0o600,
            )
            self._reload_peers()
        except BaseException:
            atomic_write(self.config_path, old_config, 0o600)
            self._reload_peers()
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
