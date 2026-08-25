"""FluxGate-owned AmneziaWG 3.1 userspace provider lifecycle."""

from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
import time
from ipaddress import IPv4Network
from pathlib import Path

from pydantic import ValidationError

from fluxgate.core.config import AmneziaWGConfig
from fluxgate.core.errors import FluxGateError, ProviderError, StateError
from fluxgate.core.models import (
    Client,
    ClientArtifact,
    ExportArtifact,
    HealthLevel,
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
from fluxgate.providers.amneziawg.keys import AmneziaWGKeys
from fluxgate.providers.amneziawg.models import (
    AmneziaWGProviderState,
    ResiliencePreset,
    ResilienceProfile,
)
from fluxgate.providers.amneziawg.rendering import (
    allocate_address,
    credential,
    render_client,
    render_server,
    tunnel_network,
)
from fluxgate.providers.base import CoreProvider
from fluxgate.system.packages import (
    AWG_GO_COMMIT,
    AWG_GO_VERSION,
    AWG_TOOLS_COMMIT,
    AWG_TOOLS_VERSION,
)


class AmneziaWGProvider(CoreProvider):
    name = "amneziawg"
    display_name = "AmneziaWG"
    connection_mode = ConnectionMode.SYSTEM_TUNNEL
    capabilities = frozenset(
        {
            ProviderCapability.ADD_CLIENTS,
            ProviderCapability.EXPORT_CONFIG,
            ProviderCapability.RELOAD,
        }
    )
    unit = "fluxgate-amneziawg.service"
    OWNER = b"Managed by FluxGate AmneziaWG 3.1 artifacts\n"
    UNIT_HEADER = "# Managed by FluxGate AmneziaWG 3.1\n"
    BINARY_OWNER = (
        "Managed by FluxGate AmneziaWG 3.1 binaries\n"
        f"tools_tag=v{AWG_TOOLS_VERSION}\n"
        f"tools_commit={AWG_TOOLS_COMMIT}\n"
        f"go_tag=v{AWG_GO_VERSION}\n"
        f"go_commit={AWG_GO_COMMIT}\n"
    ).encode()
    EMBEDDED_GO_VERSION = "0.0.20250522"
    WAIT_HELPER = b"""#!/usr/bin/python3
import stat
import sys
import time
from pathlib import Path

if len(sys.argv) != 3:
    raise SystemExit(2)
path = Path(sys.argv[1])
deadline = time.monotonic() + float(sys.argv[2])
while time.monotonic() < deadline:
    try:
        if stat.S_ISSOCK(path.lstat().st_mode):
            raise SystemExit(0)
    except FileNotFoundError:
        pass
    time.sleep(0.05)
raise SystemExit(1)
"""

    @property
    def settings(self) -> AmneziaWGConfig:
        return self.context.config.cores.amneziawg

    @property
    def config_path(self) -> Path:
        return self.context.paths.amneziawg_config_file

    @property
    def runtime_config_path(self) -> Path:
        return self.context.paths.amneziawg_runtime_config_file

    @property
    def unit_path(self) -> Path:
        return self.context.paths.amneziawg_unit_file

    @property
    def marker(self) -> Path:
        return self.context.paths.amneziawg_dir / ".fluxgate-owner"

    @property
    def binary_marker(self) -> Path:
        return self.context.paths.amneziawg_binary_dir / ".fluxgate-owner"

    @property
    def private_key_path(self) -> Path:
        return AmneziaWGKeys(self.context).private_path

    @property
    def public_key_path(self) -> Path:
        return AmneziaWGKeys(self.context).public_path

    def _owned_file(self, path: Path, content: bytes, mode: int) -> bool:
        return (
            path.is_file()
            and not path.is_symlink()
            and path.stat().st_nlink == 1
            and stat.S_IMODE(path.stat().st_mode) == mode
            and path.read_bytes() == content
        )

    def _owned(self) -> bool:
        return self._owned_file(self.marker, self.OWNER, 0o600)

    def _binaries_owned(self) -> bool:
        return self._owned_file(self.binary_marker, self.BINARY_OWNER, 0o600)

    def _assert_ownership(self) -> None:
        for root, label in (
            (self.context.paths.amneziawg_dir, "configuration"),
            (self.context.paths.amneziawg_binary_dir, "binary"),
        ):
            checked_anchor = False
            for candidate in (root, *root.parents):
                if candidate.is_symlink():
                    raise ProviderError(f"refusing symlinked AmneziaWG {label} path: {candidate}")
                if candidate.exists() and not checked_anchor:
                    checked_anchor = True
                    if not candidate.is_dir():
                        raise ProviderError(
                            f"AmneziaWG {label} path is not a directory: {candidate}"
                        )
                    metadata = candidate.stat()
                    if os.geteuid() == 0 and metadata.st_uid != 0:
                        raise ProviderError(
                            f"AmneziaWG {label} path is not root-owned: {candidate}"
                        )
                    if stat.S_IMODE(metadata.st_mode) & 0o022:
                        raise ProviderError(
                            f"AmneziaWG {label} path is group/world-writable: {candidate}"
                        )
        config_root = self.context.paths.amneziawg_dir
        if config_root.exists() and any(config_root.iterdir()) and not self._owned():
            raise ProviderError(f"refusing unmanaged AmneziaWG config location: {config_root}")
        binary_root = self.context.paths.amneziawg_binary_dir
        if binary_root.exists() and any(binary_root.iterdir()) and not self._binaries_owned():
            raise ProviderError(f"refusing unmanaged AmneziaWG binary location: {binary_root}")
        if self.unit_path.exists() and (
            self.unit_path.is_symlink()
            or not self.unit_path.read_text().startswith(self.UNIT_HEADER)
        ):
            raise ProviderError(f"refusing unmanaged systemd unit: {self.unit_path}")

    def _binary_safe(self, path: Path) -> bool:
        return (
            path.is_file()
            and not path.is_symlink()
            and path.stat().st_nlink == 1
            and stat.S_IMODE(path.stat().st_mode) == 0o755
        )

    def _verify_binaries(self) -> None:
        if not self._binaries_owned():
            raise ProviderError("AmneziaWG managed binary provenance marker is missing")
        for path in (
            self.context.paths.awg_binary,
            self.context.paths.awg_quick_binary,
            self.context.paths.amneziawg_go_binary,
            self.context.paths.amneziawg_wait_helper,
        ):
            if not self._binary_safe(path):
                raise ProviderError(f"AmneziaWG managed binary is missing or unsafe: {path}")
        tools = self.context.runner.run(
            [str(self.context.paths.awg_binary), "--version"], check=False
        )
        userspace = self.context.runner.run(
            [str(self.context.paths.amneziawg_go_binary), "--version"], check=False
        )
        if tools.returncode != 0 or AWG_TOOLS_VERSION not in tools.stdout:
            raise ProviderError(f"AmneziaWG tools must be the pinned v{AWG_TOOLS_VERSION}")
        if (
            userspace.returncode != 0
            or f"amneziawg-go {self.EMBEDDED_GO_VERSION}" not in userspace.stdout
        ):
            raise ProviderError(f"amneziawg-go does not match pinned source v{AWG_GO_VERSION}")
        if self.context.paths.amneziawg_wait_helper.read_bytes() != self.WAIT_HELPER:
            raise ProviderError("AmneziaWG UAPI readiness helper is stale or unmanaged")

    def detect(self) -> ProviderDetection:
        files = {
            "awg": self._binary_safe(self.context.paths.awg_binary),
            "awg-quick": self._binary_safe(self.context.paths.awg_quick_binary),
            "amneziawg-go": self._binary_safe(self.context.paths.amneziawg_go_binary),
            "uapi-wait-helper": self._binary_safe(self.context.paths.amneziawg_wait_helper),
            "nft": shutil.which("nft") is not None,
        }
        available = all(
            files[name] for name in ("awg", "awg-quick", "amneziawg-go", "uapi-wait-helper")
        )
        if available and not self.context.dry_run:
            try:
                self._verify_binaries()
            except ProviderError:
                available = False
        detail = (
            f"AmneziaWG tools v{AWG_TOOLS_VERSION}; userspace v{AWG_GO_VERSION}"
            if available
            else "managed AmneziaWG 3.1 userspace dependencies missing or invalid"
        )
        return ProviderDetection(available=available, binaries=files, detail=detail)

    def _provider_state(self) -> AmneziaWGProviderState | None:
        value = self.context.state.load().providers.get(self.name)
        if value is None:
            return None
        try:
            return AmneziaWGProviderState.model_validate_json(json.dumps(value))
        except ValidationError as error:
            raise StateError("invalid AmneziaWG provider state") from error

    def _profile(self) -> ResilienceProfile:
        state = self._provider_state()
        if state is None:
            raise StateError("AmneziaWG resilience profile is not initialized")
        return state.profile

    def _desired_profile(self) -> ResilienceProfile:
        preset = ResiliencePreset(self.settings.resilience.preset)
        existing = self._provider_state()
        if existing is None:
            return ResilienceProfile.from_preset(self.settings.resilience.name, preset)
        if existing.profile.preset_origin != preset:
            raise ProviderError(
                "AmneziaWG resilience parameters are immutable; create a new profile in a "
                "future profile-rotation workflow instead of changing the configured preset"
            )
        profile = existing.profile.model_copy(deep=True)
        profile.name = self.settings.resilience.name
        return ResilienceProfile.model_validate(profile.model_dump(mode="python"))

    def _set_state(self, enabled: bool, profile: ResilienceProfile) -> None:
        state = self.context.state.load()
        state.providers[self.name] = AmneziaWGProviderState(
            enabled=enabled, profile=profile
        ).model_dump(mode="json")
        self.context.state.save(state)

    def _enabled_in_state(self) -> bool:
        state = self._provider_state()
        return self.settings.enabled if state is None else state.enabled

    def _network(self) -> IPv4Network:
        return tunnel_network(self.settings)

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

    def _server_configs(
        self, clients: list[Client], profile: ResilienceProfile
    ) -> tuple[bytes, bytes]:
        private = AmneziaWGKeys(self.context).read_private()
        return (
            render_server(self.settings, private, clients, profile),
            render_server(self.settings, private, clients, profile, runtime=True),
        )

    def _unit_content(self) -> bytes:
        text = (
            self.UNIT_HEADER
            + "[Unit]\nDescription=FluxGate managed AmneziaWG 3.1 userspace tunnel\n"
            + "After=network-online.target fluxgate-firewall.service\n"
            + "Wants=network-online.target\n\n"
            + "[Service]\nType=simple\n"
            + f"ExecStart={self.context.paths.amneziawg_go_binary} --foreground "
            + f"{self.settings.interface}\n"
            + f"ExecStartPost=/usr/bin/python3 {self.context.paths.amneziawg_wait_helper} "
            + f"/run/amneziawg/{self.settings.interface}.sock 5\n"
            + f"ExecStartPost={self.context.paths.awg_binary} setconf "
            + f"{self.settings.interface} {self.runtime_config_path}\n"
            + f"ExecStartPost=/usr/sbin/ip address replace {self.settings.address} dev "
            + f"{self.settings.interface}\n"
            + f"ExecStartPost=/usr/sbin/ip link set up dev {self.settings.interface}\n"
            + f"ExecStopPost=-/usr/sbin/ip link delete dev {self.settings.interface}\n"
            + "Restart=on-failure\nRestartSec=2s\nUMask=0077\n"
            + "NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\n"
            + "ProtectHome=true\nProtectKernelTunables=true\nProtectKernelModules=true\n"
            + "ProtectControlGroups=true\nRestrictSUIDSGID=true\nLockPersonality=true\n"
            + "DevicePolicy=closed\nDeviceAllow=/dev/net/tun rw\n"
            + "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE\n"
            + "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE\n"
            + "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n\n"
            + "[Install]\nWantedBy=multi-user.target\n"
        )
        return text.encode()

    def _validate_config(self, content: bytes) -> None:
        self.context.paths.amneziawg_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, name = tempfile.mkstemp(
            prefix="fgv", suffix=".conf", dir=self.context.paths.amneziawg_dir
        )
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as file:
                file.write(content)
            temporary.chmod(0o600)
            self.context.runner.run(
                [str(self.context.paths.awg_quick_binary), "strip", str(temporary)]
            )
        finally:
            temporary.unlink(missing_ok=True)

    def _interface_exists(self) -> bool:
        return (
            False
            if self.context.dry_run
            else self.context.network.interface_exists(self.settings.interface)
        )

    def _reload_peers(self) -> None:
        stripped = self.context.runner.run(
            [str(self.context.paths.awg_quick_binary), "strip", str(self.config_path)]
        ).stdout
        self.context.runner.run(
            [str(self.context.paths.awg_binary), "syncconf", self.settings.interface, "/dev/stdin"],
            input_text=stripped,
            mutate=True,
        )

    def _wait_healthy(self, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            if (
                self.context.services.is_active(self.unit)
                and self._interface_exists()
                and self.context.network.udp_listener_present(self.settings.listen_port)
            ):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.1)

    def configuration_valid(self) -> bool:
        try:
            profile = self._profile()
            full, runtime = self._server_configs(self._provider_clients(), profile)
            return (
                self._owned()
                and self.config_path.is_file()
                and not self.config_path.is_symlink()
                and stat.S_IMODE(self.config_path.stat().st_mode) == 0o600
                and self.config_path.read_bytes() == full
                and self.runtime_config_path.is_file()
                and not self.runtime_config_path.is_symlink()
                and stat.S_IMODE(self.runtime_config_path.stat().st_mode) == 0o600
                and self.runtime_config_path.read_bytes() == runtime
                and self.unit_path.is_file()
                and not self.unit_path.is_symlink()
                and self.unit_path.read_bytes() == self._unit_content()
            )
        except (OSError, FluxGateError):
            return False

    def status(self) -> ProviderStatus:
        enabled = self._enabled_in_state()
        detection = self.detect()
        try:
            active = self.context.services.is_active(self.unit)
            service_enabled = self.context.services.is_enabled(self.unit)
            interface_present = self._interface_exists()
        except FluxGateError:
            active = False
            service_enabled = False
            interface_present = False
        if not enabled:
            state = (
                ProviderStateName.DEGRADED
                if active or service_enabled or interface_present
                else ProviderStateName.DISABLED
            )
        elif not detection.available:
            state = ProviderStateName.NOT_INSTALLED
        else:
            healthy = (
                active
                and service_enabled
                and interface_present
                and self.context.network.udp_listener_present(self.settings.listen_port)
                and self.configuration_valid()
                and self.context.forwarding.enabled()
                and self.context.forwarding.configured(self.name)
                and self.context.firewall.configured(
                    self.name,
                    str(self._network()),
                    self.context.config.network.outbound_interface,
                )
            )
            state = ProviderStateName.RUNNING if healthy else ProviderStateName.DEGRADED
        return ProviderStatus(
            name=self.name,
            state=state,
            enabled=enabled,
            installed=detection.available,
            detail=(
                f"{detection.detail}; backend=userspace; interface={self.settings.interface}; "
                f"profiles={1 if self._provider_state() is not None else 0}"
            ),
        )

    def enable(self) -> OperationResult:
        if self.settings.backend == "kernel":
            raise ProviderError(
                "AmneziaWG kernel backend is deferred due to upstream compatibility issues; "
                "set backend = 'userspace'"
            )
        if not self.context.config.network.ipv4:
            raise ProviderError("AmneziaWG v0.5 requires network.ipv4 to be enabled")
        if self.context.dry_run:
            return OperationResult(
                changed=True,
                message="AmneziaWG enable plan",
                actions=[
                    f"Would acquire pinned AmneziaWG tools v{AWG_TOOLS_VERSION}",
                    f"Would build pinned amneziawg-go v{AWG_GO_VERSION}",
                    "Would create one immutable resilience profile from configured preset",
                    "Would generate independent AmneziaWG server keys",
                    "Would validate and converge managed config and systemd unit",
                    "Would acquire shared forwarding and nftables NAT leases",
                    f"Would enable and verify {self.unit}",
                    "Would update FluxGate provider state",
                ],
            )
        with self.context.state.lock():
            return self._enable_locked()

    def _enable_locked(self) -> OperationResult:
        self._assert_ownership()
        desired_profile = self._desired_profile()
        state_missing = not self.context.state.exists
        if (
            state_missing
            and self._owned()
            and self.config_path.exists()
            and b"[Peer]" in self.config_path.read_bytes()
        ):
            raise ProviderError(
                "FluxGate state is missing while managed AmneziaWG config contains peers; "
                "restore state before reconciliation"
            )
        service_active = self.context.services.is_active(self.unit)
        service_enabled = self.context.services.is_enabled(self.unit)
        interface_present = self._interface_exists()
        if interface_present and not service_active:
            raise ProviderError(
                f"network interface {self.settings.interface} exists but is not owned by "
                "the FluxGate service"
            )
        outbound = self.context.config.network.outbound_interface
        if outbound is not None and not self.context.network.interface_exists(outbound):
            raise ProviderError(f"outbound network interface does not exist: {outbound}")
        if not service_active and not self.context.network.udp_port_available(
            self.settings.listen_port
        ):
            raise ProviderError(f"UDP listen port is already in use: {self.settings.listen_port}")
        conflict = self.context.network.conflicting_route(self._network(), self.settings.interface)
        if conflict is not None and not service_active:
            raise ProviderError(
                f"AmneziaWG tunnel network {self._network()} overlaps existing route: {conflict}"
            )
        detection = self.detect()
        if (
            self._enabled_in_state()
            and service_active
            and service_enabled
            and detection.available
            and self.configuration_valid()
            and self._wait_healthy(timeout=0.0)
            and self.context.forwarding.configured(self.name)
            and self.context.firewall.configured(self.name, str(self._network()), outbound)
            and self._profile().name == desired_profile.name
        ):
            return OperationResult(changed=False, message="AmneziaWG is already enabled")

        plan = OperationPlan()
        if not detection.binaries.get("nft", False):
            plan.add("Would install nftables", lambda: self.context.packages.install(["nftables"]))
        binaries_existed = self.context.paths.amneziawg_binary_dir.exists()
        if not detection.available:

            def acquire() -> None:
                try:
                    self.context.paths.amneziawg_binary_dir.mkdir(
                        parents=True, exist_ok=True, mode=0o755
                    )
                    self.context.packages.acquire_amneziawg(
                        self.context.paths.awg_binary,
                        self.context.paths.awg_quick_binary,
                        self.context.paths.amneziawg_go_binary,
                    )
                    atomic_write(self.context.paths.amneziawg_wait_helper, self.WAIT_HELPER, 0o755)
                    atomic_write(self.binary_marker, self.BINARY_OWNER, 0o600)
                    self.context.paths.amneziawg_binary_dir.chmod(0o755)
                except BaseException:
                    remove_binaries()
                    raise

            def remove_binaries() -> None:
                for path in (
                    self.context.paths.awg_binary,
                    self.context.paths.awg_quick_binary,
                    self.context.paths.amneziawg_go_binary,
                    self.context.paths.amneziawg_wait_helper,
                    self.binary_marker,
                ):
                    path.unlink(missing_ok=True)
                if not binaries_existed:
                    self.context.paths.amneziawg_binary_dir.rmdir()

            plan.add(
                "Would acquire pinned AmneziaWG userspace dependencies", acquire, remove_binaries
            )
        plan.add("Would verify AmneziaWG binary versions and provenance", self._verify_binaries)

        private_existed = self.private_key_path.exists()
        public_existed = self.public_key_path.exists()

        def remove_new_keys() -> None:
            if not private_existed:
                self.private_key_path.unlink(missing_ok=True)
            if not public_existed:
                self.public_key_path.unlink(missing_ok=True)

        plan.add(
            "Would ensure independent AmneziaWG server keys",
            lambda: AmneziaWGKeys(self.context).ensure_server(),
            remove_new_keys,
        )
        old_config = self.config_path.read_bytes() if self.config_path.exists() else None
        old_runtime = (
            self.runtime_config_path.read_bytes() if self.runtime_config_path.exists() else None
        )
        old_unit = self.unit_path.read_bytes() if self.unit_path.exists() else None
        old_marker = self.marker.read_bytes() if self.marker.exists() else None

        def converge_files() -> None:
            try:
                self.context.paths.amneziawg_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                self.context.paths.amneziawg_dir.chmod(0o700)
                full, runtime = self._server_configs(self._provider_clients(), desired_profile)
                self._validate_config(full)
                atomic_write(self.marker, self.OWNER, 0o600)
                atomic_write(self.config_path, full, 0o600)
                atomic_write(self.runtime_config_path, runtime, 0o600)
                atomic_write(self.unit_path, self._unit_content(), 0o644)
                self.context.services.daemon_reload()
            except BaseException:
                restore_files()
                raise

        def restore_files() -> None:
            for path, previous, mode in (
                (self.config_path, old_config, 0o600),
                (self.runtime_config_path, old_runtime, 0o600),
                (self.unit_path, old_unit, 0o644),
                (self.marker, old_marker, 0o600),
            ):
                if previous is None:
                    path.unlink(missing_ok=True)
                else:
                    atomic_write(path, previous, mode)
            self.context.services.daemon_reload()

        plan.add("Would converge owned AmneziaWG config and unit", converge_files, restore_files)
        forwarding_checkpoint = self.context.forwarding.checkpoint()
        plan.add(
            "Would acquire AmneziaWG forwarding lease",
            lambda: self.context.forwarding.acquire(self.name),
            lambda: self.context.forwarding.restore(forwarding_checkpoint),
        )
        firewall_checkpoint = self.context.firewall.checkpoint()
        plan.add(
            "Would converge AmneziaWG nftables NAT lease",
            lambda: self.context.firewall.ensure_nat(self.name, str(self._network()), outbound),
            lambda: self.context.firewall.restore(firewall_checkpoint),
        )

        def converge_service() -> None:
            self.context.services.enable_now(self.unit)
            if service_active:
                self.context.services.restart(self.unit)

        plan.add(
            f"Would enable {self.unit}",
            converge_service,
            lambda: self.context.services.restore(
                self.unit, enabled=service_enabled, active=service_active
            ),
        )

        def verify() -> None:
            if not self._wait_healthy():
                raise ProviderError("AmneziaWG service failed postcondition verification")

        plan.add("Would verify AmneziaWG interface and listener", verify)
        plan.add(
            "Would persist AmneziaWG profile and provider state",
            lambda: self._set_state(True, desired_profile),
        )
        actions = plan.execute()
        return OperationResult(changed=True, message="AmneziaWG enabled", actions=actions)

    def disable(self) -> OperationResult:
        if self.context.dry_run:
            return OperationResult(
                changed=True,
                message="AmneziaWG disable plan",
                actions=[
                    f"Would disable {self.unit}",
                    "Would release only AmneziaWG nftables and forwarding leases",
                    "Would retain managed dependencies, keys and immutable profile",
                    "Would update FluxGate provider state",
                ],
            )
        with self.context.state.lock():
            self._assert_ownership()
            provider_state = self._provider_state()
            if provider_state is None:
                if self.context.services.is_active(self.unit) or self._interface_exists():
                    raise ProviderError(
                        "AmneziaWG runtime exists without authoritative state; refusing cleanup"
                    )
                return OperationResult(changed=False, message="AmneziaWG is already disabled")
            active = self.context.services.is_active(self.unit)
            service_enabled = self.context.services.is_enabled(self.unit)
            firewall_managed = self.context.firewall.managed(self.name)
            forwarding_managed = self.context.forwarding.configured(self.name)
            if not (
                provider_state.enabled
                or active
                or service_enabled
                or firewall_managed
                or forwarding_managed
            ):
                return OperationResult(changed=False, message="AmneziaWG is already disabled")
            plan = OperationPlan()
            if active or service_enabled:
                plan.add(
                    f"Would disable {self.unit}",
                    lambda: self.context.services.disable_now(self.unit),
                    lambda: self.context.services.restore(
                        self.unit, enabled=service_enabled, active=active
                    ),
                )
            if firewall_managed:
                checkpoint = self.context.firewall.checkpoint()
                plan.add(
                    "Would remove only the AmneziaWG nftables NAT lease",
                    lambda: self.context.firewall.remove_nat(self.name),
                    lambda: self.context.firewall.restore(checkpoint),
                )
            if forwarding_managed:
                checkpoint = self.context.forwarding.checkpoint()
                plan.add(
                    "Would release only the AmneziaWG forwarding lease",
                    lambda: self.context.forwarding.release(self.name),
                    lambda: self.context.forwarding.restore(checkpoint),
                )
            plan.add(
                "Would update FluxGate provider state",
                lambda: self._set_state(False, provider_state.profile),
            )
            actions = plan.execute()
            return OperationResult(changed=True, message="AmneziaWG disabled", actions=actions)

    def _client_private_path(self, client: Client) -> Path:
        return self.context.paths.secrets_dir / "clients" / f"{client.id}.amneziawg.key"

    def _client_config_path(self, client: Client) -> Path:
        return self.context.paths.clients_dir / f"{client.id}.amneziawg.conf"

    def _export_content(self, client: Client, private: str, profile: ResilienceProfile) -> str:
        return render_client(
            self.settings,
            self.context.config.server.domain,
            AmneziaWGKeys(self.context).read_public(),
            client,
            private,
            profile,
        )

    def add_client(self, client: Client) -> ClientArtifact:
        if not self._enabled_in_state():
            raise ProviderError("AmneziaWG must be enabled before adding a peer")
        if self.name in client.provider_credentials:
            raise ProviderError(f"client {client.name} already has AmneziaWG credentials")
        if not self.configuration_valid():
            raise ProviderError("managed AmneziaWG configuration is unavailable or drifted")
        profile = self._profile()
        private, public = AmneziaWGKeys(self.context).keypair()
        address = allocate_address(self.settings, self._provider_clients(), profile)
        credentials: dict[str, object] = {
            "public_key": public,
            "address": address,
            "profile_id": str(profile.id),
        }
        client.provider_credentials[self.name] = credentials
        export = self._export_content(client, private, profile)
        self._validate_config(export.encode())
        private_path = self._client_private_path(client)
        export_path = self._client_config_path(client)
        old_full = self.config_path.read_bytes()
        old_runtime = self.runtime_config_path.read_bytes()
        plan = OperationPlan()
        plan.add(
            f"Store AmneziaWG private material for {client.name}",
            lambda: atomic_write(private_path, f"{private}\n".encode(), 0o600),
            lambda: private_path.unlink(missing_ok=True),
        )
        plan.add(
            f"Create AmneziaWG export for {client.name}",
            lambda: atomic_write(export_path, export.encode(), 0o600),
            lambda: export_path.unlink(missing_ok=True),
        )

        def add_peer() -> None:
            full, runtime = self._server_configs(self._provider_clients(extra=client), profile)
            self._validate_config(full)
            try:
                atomic_write(self.config_path, full, 0o600)
                atomic_write(self.runtime_config_path, runtime, 0o600)
            except BaseException:
                atomic_write(self.config_path, old_full, 0o600)
                atomic_write(self.runtime_config_path, old_runtime, 0o600)
                raise

        def restore_peer() -> None:
            atomic_write(self.config_path, old_full, 0o600)
            atomic_write(self.runtime_config_path, old_runtime, 0o600)
            self._reload_peers()

        plan.add(f"Add AmneziaWG peer {client.name}", add_peer, restore_peer)
        plan.add(f"Reload {self.unit}", self._reload_peers)
        plan.execute(dry_run=self.context.dry_run)
        return ClientArtifact(
            provider=self.name,
            credentials=credentials,
            exports=[
                ExportArtifact(
                    name=f"{client.name}.conf",
                    media_type="text/plain",
                    content=export,
                    secret=True,
                )
            ],
        )

    def revoke_client(self, client: Client) -> OperationResult:
        if self.name not in client.provider_credentials:
            return OperationResult(changed=False, message="client has no AmneziaWG peer")
        self._assert_ownership()
        if not self._owned() or not self._binaries_owned():
            raise ProviderError("managed AmneziaWG ownership metadata is unavailable")
        for path, mode in (
            (self.config_path, 0o600),
            (self.runtime_config_path, 0o600),
            (self.unit_path, 0o644),
        ):
            if (
                not path.is_file()
                or path.is_symlink()
                or path.stat().st_nlink != 1
                or stat.S_IMODE(path.stat().st_mode) != mode
            ):
                raise ProviderError(f"managed AmneziaWG runtime file is unsafe: {path}")
        profile = self._profile()
        credential(client, self._network(), profile)
        old_full = self.config_path.read_bytes()
        old_runtime = self.runtime_config_path.read_bytes()
        desired_full, desired_runtime = self._server_configs(
            self._provider_clients(exclude=client), profile
        )
        self._validate_config(desired_full)
        artifact_checkpoints: list[tuple[Path, bytes]] = []
        for path in (self._client_private_path(client), self._client_config_path(client)):
            if not path.exists():
                continue
            if (
                path.is_symlink()
                or not path.is_file()
                or path.stat().st_nlink != 1
                or stat.S_IMODE(path.stat().st_mode) != 0o600
            ):
                raise ProviderError(f"refusing unsafe AmneziaWG client artifact: {path}")
            artifact_checkpoints.append((path, path.read_bytes()))

        plan = OperationPlan()

        def remove_artifacts() -> None:
            try:
                for path, _ in artifact_checkpoints:
                    path.unlink()
            except BaseException:
                restore_artifacts()
                raise

        def restore_artifacts() -> None:
            for path, content in artifact_checkpoints:
                atomic_write(path, content, 0o600)

        if artifact_checkpoints:
            plan.add(
                f"Remove AmneziaWG private artifacts for {client.name}",
                remove_artifacts,
                restore_artifacts,
            )

        def remove_peer() -> None:
            try:
                atomic_write(self.config_path, desired_full, 0o600)
                atomic_write(self.runtime_config_path, desired_runtime, 0o600)
                self._reload_peers()
            except BaseException:
                restore_peer()
                raise

        def restore_peer() -> None:
            atomic_write(self.config_path, old_full, 0o600)
            atomic_write(self.runtime_config_path, old_runtime, 0o600)
            self._reload_peers()

        if old_full != desired_full or old_runtime != desired_runtime:
            plan.add(f"Remove AmneziaWG peer {client.name}", remove_peer, restore_peer)
        plan.execute(dry_run=self.context.dry_run)
        if not self.context.dry_run and (
            self.config_path.read_bytes() != desired_full
            or self.runtime_config_path.read_bytes() != desired_runtime
        ):
            raise ProviderError("AmneziaWG peer revoke did not converge managed configuration")
        return OperationResult(changed=True, message=f"revoked AmneziaWG peer for {client.name}")

    def export_client(self, client: Client) -> list[ExportArtifact]:
        profile = self._profile()
        credential(client, self._network(), profile)
        path = self._client_config_path(client)
        if path.is_symlink() or not path.is_file():
            raise ProviderError(f"AmneziaWG export for {client.name} is unavailable")
        if path.stat().st_nlink != 1 or stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise ProviderError(f"AmneziaWG export for {client.name} is unsafe")
        return [
            ExportArtifact(
                name=f"{client.name}.conf",
                media_type="text/plain",
                content=path.read_text(),
                secret=True,
            )
        ]

    def healthcheck(self) -> list[HealthResult]:
        status = self.status()
        if not status.enabled:
            return [
                HealthResult(
                    name="provider-status",
                    level=HealthLevel.INFO,
                    message="AmneziaWG disabled",
                )
            ]
        results = [
            HealthResult(
                name="provider-status",
                level=(
                    HealthLevel.SUCCESS
                    if status.state == ProviderStateName.RUNNING
                    else HealthLevel.FAILURE
                ),
                message=status.detail,
            )
        ]
        for binary, present in self.detect().binaries.items():
            results.append(
                HealthResult(
                    name=f"binary:{binary}",
                    level=HealthLevel.SUCCESS if present else HealthLevel.FAILURE,
                    message=f"{binary} {'available' if present else 'missing or invalid'}",
                )
            )
        checks = (
            ("configuration", self.configuration_valid(), "owned config and unit are converged"),
            (
                "forwarding",
                self.context.forwarding.enabled() and self.context.forwarding.configured(self.name),
                "AmneziaWG forwarding lease is active",
            ),
            (
                "firewall",
                self.context.firewall.configured(
                    self.name,
                    str(self._network()),
                    self.context.config.network.outbound_interface,
                ),
                "AmneziaWG nftables NAT lease is active",
            ),
        )
        for name, passed, message in checks:
            results.append(
                HealthResult(
                    name=name,
                    level=HealthLevel.SUCCESS if passed else HealthLevel.FAILURE,
                    message=message if passed else f"{name} is missing, unsafe, or drifted",
                )
            )
        return results
