"""Production OpenVPN provider and owned server lifecycle."""

from __future__ import annotations

import shutil
import stat
from dataclasses import dataclass
from ipaddress import IPv4Network
from pathlib import Path

from fluxgate.core.config import OpenVPNConfig
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
from fluxgate.pathfinder.models import ConnectionMode
from fluxgate.providers.base import CoreProvider
from fluxgate.providers.openvpn.health import openvpn_health
from fluxgate.providers.openvpn.pki import IssuedCertificate, OpenVPNPKI
from fluxgate.providers.openvpn.rendering import (
    allocate_address,
    common_name,
    credential,
    render_ccd,
    render_client,
    render_server,
    tunnel_network,
)


@dataclass(frozen=True, slots=True)
class DirectoryCheckpoint:
    existed: bool
    files: dict[str, tuple[bytes, int]]


class OpenVPNProvider(CoreProvider):
    name = "openvpn"
    display_name = "OpenVPN"
    connection_mode = ConnectionMode.SYSTEM_TUNNEL
    capabilities = frozenset(
        {
            ProviderCapability.ADD_CLIENTS,
            ProviderCapability.EXPORT_CONFIG,
            ProviderCapability.RELOAD,
        }
    )
    CONFIG_HEADER = b"# Managed by FluxGate;"
    OWNER = b"Managed by FluxGate OpenVPN server artifacts\n"

    @property
    def settings(self) -> OpenVPNConfig:
        return self.context.config.cores.openvpn

    @property
    def unit(self) -> str:
        return "openvpn-server@fluxgate.service"

    @property
    def config_path(self) -> Path:
        return self.context.paths.openvpn_config_file

    @property
    def ccd_dir(self) -> Path:
        return self.context.paths.openvpn_ccd_dir

    @property
    def ccd_marker(self) -> Path:
        return self.ccd_dir / ".fluxgate-owner"

    @property
    def crl_path(self) -> Path:
        return self.context.paths.openvpn_crl_file

    @property
    def crl_marker(self) -> Path:
        return self.crl_path.with_suffix(".pem.owner")

    @property
    def pki(self) -> OpenVPNPKI:
        return OpenVPNPKI(self.context)

    def detect(self) -> ProviderDetection:
        binaries = {name: shutil.which(name) is not None for name in ("openvpn", "openssl", "nft")}
        available = binaries["openvpn"] and binaries["openssl"]
        return ProviderDetection(
            available=available,
            binaries=binaries,
            detail="OpenVPN tools available" if available else "OpenVPN tools missing",
        )

    def _enabled_in_state(self) -> bool:
        value = (
            self.context.state.load()
            .providers.get(self.name, {})
            .get("enabled", self.settings.enabled)
        )
        if not isinstance(value, bool):
            raise StateError("invalid OpenVPN provider state: enabled must be a boolean")
        return value

    def _set_enabled_state(self, enabled: bool) -> None:
        state = self.context.state.load()
        provider_state = dict(state.providers.get(self.name, {}))
        provider_state["enabled"] = enabled
        state.providers[self.name] = provider_state
        self.context.state.save(state)

    def _interface_exists(self) -> bool:
        if self.context.dry_run:
            return False
        return self.context.network.interface_exists(self.settings.interface)

    def _listener_present(self) -> bool:
        if self.context.dry_run:
            return False
        return self.context.network.udp_listener_present(self.settings.listen_port)

    def status(self) -> ProviderStatus:
        detection = self.detect()
        enabled = self._enabled_in_state()
        active = (
            enabled
            and detection.available
            and self.context.services.is_active(self.unit)
            and self._interface_exists()
            and self._listener_present()
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

    def _network(self) -> IPv4Network:
        return tunnel_network(self.settings)

    def _credential(self, client: Client) -> dict[str, object]:
        return credential(client, self._network())

    def _server_config(self) -> bytes:
        return render_server(
            self.settings,
            pki_dir=self.context.paths.openvpn_pki_dir,
            ccd_dir=self.ccd_dir,
            crl_path=self.crl_path,
        )

    def _assert_config_ownership(self) -> None:
        if self.config_path.is_symlink():
            raise ProviderError(f"refusing OpenVPN configuration symlink: {self.config_path}")
        if self.config_path.exists() and not self.config_path.read_bytes().startswith(
            self.CONFIG_HEADER
        ):
            raise ProviderError(
                f"refusing to replace unmanaged OpenVPN configuration: {self.config_path}"
            )

    def _assert_public_crl_ownership(self) -> None:
        for path in (self.crl_path, self.crl_marker):
            if path.is_symlink():
                raise ProviderError(f"refusing OpenVPN CRL symlink: {path}")
        if self.crl_path.exists() and (
            not self.crl_marker.is_file() or self.crl_marker.read_bytes() != self.OWNER
        ):
            raise ProviderError(f"refusing to replace unmanaged OpenVPN CRL: {self.crl_path}")
        if self.crl_marker.exists() and self.crl_marker.read_bytes() != self.OWNER:
            raise ProviderError(f"invalid OpenVPN CRL ownership marker: {self.crl_marker}")

    def _assert_ccd_ownership(self, *, allow_empty: bool = True) -> None:
        if self.ccd_dir.is_symlink():
            raise ProviderError(f"refusing OpenVPN CCD symlink: {self.ccd_dir}")
        if not self.ccd_dir.exists():
            return
        if not self.ccd_dir.is_dir():
            raise ProviderError(f"OpenVPN CCD path is not a directory: {self.ccd_dir}")
        entries = list(self.ccd_dir.iterdir())
        if entries and (
            not self.ccd_marker.is_file() or self.ccd_marker.read_bytes() != self.OWNER
        ):
            raise ProviderError(f"refusing to modify unmanaged OpenVPN CCD: {self.ccd_dir}")
        if not entries and allow_empty:
            return
        for path in entries:
            if path.is_symlink() or (path != self.ccd_marker and not path.is_file()):
                raise ProviderError(f"unsafe OpenVPN CCD artifact: {path}")
            if path != self.ccd_marker and not path.name.startswith("fluxgate-client-"):
                raise ProviderError(f"unexpected OpenVPN CCD artifact: {path}")

    def _directory_checkpoint(self, directory: Path) -> DirectoryCheckpoint:
        if directory == self.ccd_dir:
            self._assert_ccd_ownership()
        if not directory.exists():
            return DirectoryCheckpoint(existed=False, files={})
        files = {
            path.name: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
            for path in directory.iterdir()
            if path.is_file()
        }
        return DirectoryCheckpoint(existed=True, files=files)

    def _restore_directory(self, directory: Path, checkpoint: DirectoryCheckpoint) -> None:
        if not checkpoint.existed:
            if directory.exists():
                if directory == self.ccd_dir:
                    self._assert_ccd_ownership()
                for path in directory.iterdir():
                    path.unlink()
                directory.rmdir()
            return
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        for path in directory.iterdir():
            if path.name not in checkpoint.files:
                path.unlink()
        for name, (content, mode) in checkpoint.files.items():
            atomic_write(directory / name, content, mode)

    def _converge_ccd(self) -> None:
        self._assert_ccd_ownership()
        self.ccd_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
        self.ccd_dir.chmod(0o755)
        atomic_write(self.ccd_marker, self.OWNER, 0o600)
        expected: dict[str, bytes] = {}
        for client in self._provider_clients():
            name = str(self._credential(client)["common_name"])
            expected[name] = render_ccd(self.settings, client)
        for path in self.ccd_dir.iterdir():
            if path == self.ccd_marker:
                continue
            if path.name not in expected:
                path.unlink()
        for name, content in expected.items():
            atomic_write(self.ccd_dir / name, content, 0o644)

    def _ccd_valid(self) -> bool:
        try:
            self._assert_ccd_ownership(allow_empty=False)
            expected = {
                str(self._credential(client)["common_name"]): render_ccd(self.settings, client)
                for client in self._provider_clients()
            }
            actual = {
                path.name: path.read_bytes()
                for path in self.ccd_dir.iterdir()
                if path != self.ccd_marker
            }
            return (
                stat.S_IMODE(self.ccd_dir.stat().st_mode) == 0o755
                and self.ccd_marker.read_bytes() == self.OWNER
                and stat.S_IMODE(self.ccd_marker.stat().st_mode) == 0o600
                and all(
                    stat.S_IMODE(path.stat().st_mode) == 0o644
                    for path in self.ccd_dir.iterdir()
                    if path != self.ccd_marker
                )
                and actual == expected
            )
        except (OSError, ProviderError):
            return False

    def _write_public_crl(self, content: bytes) -> None:
        self._assert_public_crl_ownership()
        old_crl = self.crl_path.read_bytes() if self.crl_path.exists() else None
        old_marker = self.crl_marker.read_bytes() if self.crl_marker.exists() else None
        try:
            atomic_write(self.crl_path, content, 0o644)
            atomic_write(self.crl_marker, self.OWNER, 0o600)
        except BaseException as error:
            try:
                if old_crl is None:
                    self.crl_path.unlink(missing_ok=True)
                else:
                    atomic_write(self.crl_path, old_crl, 0o644)
                if old_marker is None:
                    self.crl_marker.unlink(missing_ok=True)
                else:
                    atomic_write(self.crl_marker, old_marker, 0o600)
            except BaseException as rollback_error:
                raise ProviderError(
                    f"OpenVPN CRL publication failed: {error}; rollback failed: {rollback_error}"
                ) from error
            raise

    def configuration_valid(self) -> bool:
        try:
            self._assert_config_ownership()
            self._assert_public_crl_ownership()
            return (
                self.config_path.is_file()
                and self.config_path.read_bytes() == self._server_config()
                and self.pki.complete()
                and self.crl_path.is_file()
                and self.crl_path.read_bytes() == self.pki.crl_path.read_bytes()
                and self.crl_marker.read_bytes() == self.OWNER
                and self.crl_valid()
                and self._ccd_valid()
            )
        except (OSError, ProviderError):
            return False

    def crl_valid(self) -> bool:
        try:
            self._assert_public_crl_ownership()
            return (
                self.pki.complete()
                and self.crl_path.is_file()
                and self.crl_path.read_bytes() == self.pki.crl_path.read_bytes()
                and self.pki.crl_valid(self.crl_path, renewal_window=self.pki.CRL_RENEWAL_WINDOW)
            )
        except (OSError, ProviderError):
            return False

    def _is_converged(self, detection: ProviderDetection, service_active: bool) -> bool:
        network = str(self._network())
        outbound = self.context.config.network.outbound_interface
        return (
            self._enabled_in_state()
            and detection.available
            and detection.binaries.get("nft", False)
            and service_active
            and self.context.services.is_enabled(self.unit)
            and self._interface_exists()
            and self._listener_present()
            and self.configuration_valid()
            and self.client_artifacts_valid()
            and self.context.forwarding.enabled()
            and self.context.forwarding.configured(self.name)
            and self.context.firewall.configured(self.name, network, outbound)
        )

    def enable(self) -> OperationResult:
        if self.context.dry_run:
            return self._enable_locked()
        with self.context.state.lock():
            return self._enable_locked()

    def _enable_locked(self) -> OperationResult:
        self._assert_config_ownership()
        self._assert_public_crl_ownership()
        self._assert_ccd_ownership()
        self.pki.assert_owned()
        try:
            client_files_valid = self._client_file_sets_valid()
        except ProviderError as error:
            raise ProviderError(f"invalid OpenVPN client state: {error}") from error
        if not client_files_valid:
            raise ProviderError(
                "OpenVPN client files do not match state; restore state or client artifacts "
                "before reconciling"
            )
        if not self.context.config.network.ipv4:
            raise ProviderError("OpenVPN requires network.ipv4 to be enabled")
        state_missing = not self.context.state.exists
        if (
            state_missing
            and self.ccd_dir.exists()
            and any(path != self.ccd_marker for path in self.ccd_dir.iterdir())
        ):
            raise ProviderError(
                "FluxGate state is missing while managed OpenVPN client assignments exist; "
                "restore state before reconciling"
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
                    f"OpenVPN tunnel network {self._network()} overlaps existing route: "
                    f"{route_conflict}"
                )
        if self._is_converged(detection, service_active):
            return OperationResult(changed=False, message="OpenVPN is already enabled")

        plan = OperationPlan()
        packages: list[str] = []
        if not detection.binaries.get("openvpn", False):
            packages.append("openvpn")
        if not detection.binaries.get("openssl", False):
            packages.append("openssl")
        if not detection.binaries.get("nft", False):
            packages.append("nftables")
        if packages:
            plan.add(
                f"Would install: {', '.join(packages)}",
                lambda: self.context.packages.install(packages),
            )

        pki_checkpoint = self.pki.checkpoint()
        if not self.pki.complete():
            plan.add(
                "Would create: FluxGate OpenVPN PKI",
                lambda: self.pki.ensure(has_clients=bool(self._provider_clients())),
                lambda: self.pki.restore(pki_checkpoint),
            )

        crl_refresh_needed = self.pki.complete() and not self.pki.crl_valid(
            self.pki.crl_path, renewal_window=self.pki.CRL_RENEWAL_WINDOW
        )
        if crl_refresh_needed:
            plan.add(
                "Would refresh: OpenVPN certificate revocation list",
                self.pki.refresh_crl,
                lambda: self.pki.restore(pki_checkpoint),
            )

        ccd_checkpoint = self._directory_checkpoint(self.ccd_dir)
        if not self._ccd_valid():

            def converge_ccd() -> None:
                try:
                    self._converge_ccd()
                except BaseException:
                    self._restore_directory(self.ccd_dir, ccd_checkpoint)
                    raise

            plan.add(
                "Would converge: OpenVPN client assignments",
                converge_ccd,
                lambda: self._restore_directory(self.ccd_dir, ccd_checkpoint),
            )

        old_crl = self.crl_path.read_bytes() if self.crl_path.exists() else None
        old_crl_marker = self.crl_marker.read_bytes() if self.crl_marker.exists() else None

        def restore_crl() -> None:
            if old_crl is None:
                self.crl_path.unlink(missing_ok=True)
            else:
                atomic_write(self.crl_path, old_crl, 0o644)
            if old_crl_marker is None:
                self.crl_marker.unlink(missing_ok=True)
            else:
                atomic_write(self.crl_marker, old_crl_marker, 0o600)

        if (
            crl_refresh_needed
            or not self.crl_path.exists()
            or (
                self.pki.complete() and self.crl_path.read_bytes() != self.pki.crl_path.read_bytes()
            )
        ):
            plan.add(
                "Would publish: OpenVPN certificate revocation list",
                lambda: self._write_public_crl(self.pki.crl_path.read_bytes()),
                restore_crl,
            )

        old_config = self.config_path.read_bytes() if self.config_path.exists() else None

        def restore_config() -> None:
            if old_config is None:
                self.config_path.unlink(missing_ok=True)
            else:
                atomic_write(self.config_path, old_config, 0o600)
            if service_active:
                self.context.services.restart(self.unit)

        if not self.config_path.exists() or self.config_path.read_bytes() != self._server_config():
            plan.add(
                f"Would converge: {self.config_path}",
                lambda: atomic_write(self.config_path, self._server_config(), 0o600),
                restore_config,
            )

        client_export_checkpoint = {
            self._client_export_path(client): (
                self._client_export_path(client).read_bytes(),
                stat.S_IMODE(self._client_export_path(client).stat().st_mode),
            )
            for client in self._provider_clients()
        }

        def restore_client_exports() -> None:
            for path, (content, mode) in client_export_checkpoint.items():
                atomic_write(path, content, mode)

        if self._provider_clients() and self.pki.complete() and not self.client_artifacts_valid():

            def converge_client_exports() -> None:
                try:
                    self._converge_client_exports()
                except BaseException:
                    restore_client_exports()
                    raise

            plan.add(
                "Would converge: stored OpenVPN client exports",
                converge_client_exports,
                restore_client_exports,
            )

        forwarding_checkpoint = self.context.forwarding.checkpoint()
        if not self.context.forwarding.enabled() or not self.context.forwarding.configured(
            self.name
        ):
            plan.add(
                "Would acquire: OpenVPN IPv4 forwarding lease",
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
                "Would configure: OpenVPN nftables NAT rule",
                lambda: self.context.firewall.ensure_nat(self.name, network, outbound),
                lambda: self.context.firewall.restore(firewall_checkpoint),
            )

        service_was_active, service_was_enabled = service_active, service_enabled

        def require_live_service() -> None:
            if not self._interface_exists() or not self._listener_present():
                raise ProviderError(
                    "OpenVPN service started without its interface and UDP listener"
                )
            if not self.client_artifacts_valid():
                raise ProviderError("OpenVPN client artifacts failed their postcondition")

        if not service_active or not service_enabled:
            plan.add(
                f"Would enable: {self.unit}",
                lambda: self.context.services.enable_now(self.unit),
                lambda: self.context.services.restore(
                    self.unit, enabled=service_was_enabled, active=service_was_active
                ),
            )
        elif (
            not self.configuration_valid() or not interface_present or not self._listener_present()
        ):
            plan.add(
                f"Would restart: {self.unit} to recover live state",
                lambda: self.context.services.restart(self.unit),
            )
        plan.add("Would verify: live OpenVPN interface and UDP listener", require_live_service)
        if state_missing or not self._enabled_in_state():
            plan.add("Would update: FluxGate provider state", lambda: self._set_enabled_state(True))
        actions = plan.execute(dry_run=self.context.dry_run)
        return OperationResult(
            changed=True,
            message="OpenVPN enable plan" if self.context.dry_run else "OpenVPN enabled",
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
            return OperationResult(changed=False, message="OpenVPN is already disabled")
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
                "Would remove: OpenVPN nftables NAT rule",
                lambda: self.context.firewall.remove_nat(self.name),
                lambda: self.context.firewall.restore(firewall_checkpoint),
            )
        if forwarding_managed:
            forwarding_checkpoint = self.context.forwarding.checkpoint()
            plan.add(
                "Would release: OpenVPN forwarding lease",
                lambda: self.context.forwarding.release(self.name),
                lambda: self.context.forwarding.restore(forwarding_checkpoint),
            )
        plan.add("Would update: FluxGate provider state", lambda: self._set_enabled_state(False))
        actions = plan.execute(dry_run=self.context.dry_run)
        return OperationResult(
            changed=True,
            message="OpenVPN disable plan" if self.context.dry_run else "OpenVPN disabled",
            actions=actions,
        )

    def _client_private_path(self, client: Client) -> Path:
        return self.context.paths.secrets_dir / "clients" / f"{client.id}.openvpn.key"

    def _client_certificate_path(self, client: Client) -> Path:
        return self.context.paths.secrets_dir / "clients" / f"{client.id}.openvpn.crt"

    def _client_export_path(self, client: Client) -> Path:
        return self.context.paths.clients_dir / f"{client.id}.openvpn.ovpn"

    def _client_ccd_path(self, client: Client) -> Path:
        return self.ccd_dir / str(self._credential(client)["common_name"])

    def _client_file_sets_valid(self) -> bool:
        expected_secrets: set[Path] = set()
        expected_exports: set[Path] = set()
        for client in self._provider_clients():
            self._credential(client)
            expected_secrets.update(
                {self._client_private_path(client), self._client_certificate_path(client)}
            )
            expected_exports.add(self._client_export_path(client))
        secret_dir = self.context.paths.secrets_dir / "clients"
        actual_secrets = (
            {
                path
                for path in secret_dir.iterdir()
                if path.name.endswith((".openvpn.key", ".openvpn.crt"))
            }
            if secret_dir.is_dir()
            else set()
        )
        client_dir = self.context.paths.clients_dir
        actual_exports = (
            {path for path in client_dir.iterdir() if path.name.endswith(".openvpn.ovpn")}
            if client_dir.is_dir()
            else set()
        )
        return actual_secrets == expected_secrets and actual_exports == expected_exports

    def _expected_client_export(self, client: Client) -> str:
        return render_client(
            self.settings,
            self.context.config.server.domain,
            ca_certificate=self.pki.read_ca_certificate(),
            client_certificate=self._client_certificate_path(client).read_text(),
            client_key=self._client_private_path(client).read_text(),
            tls_crypt_key=self.pki.read_tls_crypt_key(),
        )

    def _converge_client_exports(self) -> None:
        for client in self._provider_clients():
            atomic_write(
                self._client_export_path(client),
                self._expected_client_export(client).encode(),
                0o600,
            )

    def add_client(self, client: Client) -> ClientArtifact:
        if not self._enabled_in_state():
            raise ProviderError("OpenVPN must be enabled before adding a client")
        if self.name in client.provider_credentials:
            raise ProviderError(f"client {client.name} already has OpenVPN credentials")
        self._assert_config_ownership()
        if not self.configuration_valid():
            raise ProviderError("managed OpenVPN configuration is incomplete")
        assigned_address = allocate_address(self.settings, self._provider_clients())
        assigned_name = common_name(client)
        pki_checkpoint = self.pki.checkpoint()
        issued: list[IssuedCertificate] = []

        def issue() -> None:
            material = self.pki.issue_client(assigned_name)
            issued.append(material)
            client.provider_credentials[self.name] = {
                "common_name": assigned_name,
                "serial": material.serial,
                "address": assigned_address,
            }

        def rollback_issue() -> None:
            client.provider_credentials.pop(self.name, None)
            self.pki.restore(pki_checkpoint)

        def material() -> IssuedCertificate:
            if not issued:
                raise ProviderError("OpenVPN client certificate was not generated")
            return issued[0]

        private_path = self._client_private_path(client)
        certificate_path = self._client_certificate_path(client)
        export_path = self._client_export_path(client)
        ccd_path = self.ccd_dir / assigned_name
        plan = OperationPlan()
        plan.add(f"Issue OpenVPN certificate for {client.name}", issue, rollback_issue)
        plan.add(
            f"Store OpenVPN private material for {client.name}",
            lambda: atomic_write(private_path, material().private_key, 0o600),
            lambda: private_path.unlink(missing_ok=True),
        )
        plan.add(
            f"Store OpenVPN certificate for {client.name}",
            lambda: atomic_write(certificate_path, material().certificate, 0o600),
            lambda: certificate_path.unlink(missing_ok=True),
        )

        def export_content() -> str:
            return render_client(
                self.settings,
                self.context.config.server.domain,
                ca_certificate=self.pki.read_ca_certificate(),
                client_certificate=material().certificate.decode(),
                client_key=material().private_key.decode(),
                tls_crypt_key=self.pki.read_tls_crypt_key(),
            )

        plan.add(
            f"Create OpenVPN export for {client.name}",
            lambda: atomic_write(export_path, export_content().encode(), 0o600),
            lambda: export_path.unlink(missing_ok=True),
        )
        plan.add(
            f"Assign OpenVPN address for {client.name}",
            lambda: atomic_write(ccd_path, render_ccd(self.settings, client), 0o644),
            lambda: ccd_path.unlink(missing_ok=True),
        )
        old_crl = self.crl_path.read_bytes()
        plan.add(
            "Publish updated OpenVPN certificate revocation list",
            lambda: self._write_public_crl(material().crl),
            lambda: self._write_public_crl(old_crl),
        )
        plan.execute(dry_run=self.context.dry_run)
        return ClientArtifact(
            provider=self.name,
            credentials=dict(client.provider_credentials[self.name]),
            exports=[
                ExportArtifact(
                    name=f"{client.name}.ovpn",
                    media_type="application/x-openvpn-profile",
                    content=export_path.read_text(),
                    secret=True,
                )
            ],
        )

    def revoke_client(self, client: Client) -> OperationResult:
        if self.name not in client.provider_credentials:
            return OperationResult(changed=False, message="client has no OpenVPN credentials")
        self._assert_config_ownership()
        certificate_path = self._client_certificate_path(client)
        private_path = self._client_private_path(client)
        export_path = self._client_export_path(client)
        ccd_path = self._client_ccd_path(client)
        pki_checkpoint = self.pki.checkpoint()
        old_crl = self.crl_path.read_bytes()
        old_files = {
            path: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
            for path in (certificate_path, private_path, export_path, ccd_path)
            if path.exists()
        }
        revoked_crl: list[bytes] = []

        def revoke() -> None:
            serial = str(self._credential(client)["serial"])
            revoked_crl.append(self.pki.revoke_client(certificate_path, serial))

        def restore_files() -> None:
            for path, (content, mode) in old_files.items():
                atomic_write(path, content, mode)

        plan = OperationPlan()
        plan.add(
            f"Revoke OpenVPN certificate for {client.name}",
            revoke,
            lambda: self.pki.restore(pki_checkpoint),
        )
        plan.add(
            "Publish updated OpenVPN certificate revocation list",
            lambda: self._write_public_crl(revoked_crl[0]),
            lambda: self._write_public_crl(old_crl),
        )

        def remove_files() -> None:
            try:
                for path in (private_path, certificate_path, export_path, ccd_path):
                    path.unlink(missing_ok=True)
            except BaseException:
                restore_files()
                raise

        plan.add(f"Remove OpenVPN artifacts for {client.name}", remove_files, restore_files)
        if self.context.services.is_active(self.unit):
            plan.add(
                f"Restart {self.unit} to enforce revocation",
                lambda: self.context.services.restart(self.unit),
            )
        plan.execute(dry_run=self.context.dry_run)
        return OperationResult(
            changed=True, message=f"revoked OpenVPN certificate for {client.name}"
        )

    def export_client(self, client: Client) -> list[ExportArtifact]:
        path = self._client_export_path(client)
        if path.is_symlink() or not path.is_file():
            raise ProviderError(f"OpenVPN export for {client.name} is unavailable")
        return [
            ExportArtifact(
                name=f"{client.name}.ovpn",
                media_type="application/x-openvpn-profile",
                content=path.read_text(),
                secret=True,
            )
        ]

    def client_artifacts_valid(self) -> bool:
        try:
            if not self._client_file_sets_valid():
                return False
            for client in self._provider_clients():
                self._credential(client)
                private = self._client_private_path(client)
                certificate = self._client_certificate_path(client)
                export = self._client_export_path(client)
                ccd = self._client_ccd_path(client)
                for path in (private, certificate, export, ccd):
                    if path.is_symlink() or not path.is_file():
                        return False
                if (
                    any(
                        stat.S_IMODE(path.stat().st_mode) != 0o600
                        for path in (private, certificate, export)
                    )
                    or stat.S_IMODE(ccd.stat().st_mode) != 0o644
                ):
                    return False
                if not self.pki.certificate_valid(certificate):
                    return False
                if export.read_text() != self._expected_client_export(client):
                    return False
            return True
        except (OSError, ProviderError):
            return False

    def healthcheck(self) -> list[HealthResult]:
        return openvpn_health(self)
