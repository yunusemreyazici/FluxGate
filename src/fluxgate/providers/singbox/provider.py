"""FluxGate-owned sing-box core lifecycle."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import stat
import tempfile
import time
from pathlib import Path
from uuid import uuid4

from fluxgate.core.errors import ProviderError, StateError
from fluxgate.core.models import (
    Client,
    ExportArtifact,
    FluxGateState,
    HealthLevel,
    HealthResult,
    OperationResult,
    ProfileDefinition,
    ProtocolName,
    ProviderCapability,
    ProviderDetection,
    ProviderStateName,
    ProviderStatus,
    SocketProtocol,
)
from fluxgate.core.operations import OperationPlan
from fluxgate.core.state import atomic_write
from fluxgate.providers.base import CoreProvider
from fluxgate.providers.singbox.rendering import render_client, render_server
from fluxgate.providers.singbox.tls import ManagedTLSIdentityManager, TLSIdentity
from fluxgate.system.packages import SING_BOX_VERSION


class SingBoxProvider(CoreProvider):
    name = "singbox"
    display_name = "sing-box"
    capabilities = frozenset(
        {
            ProviderCapability.MANAGE_PROFILES,
            ProviderCapability.PROFILE_CLIENTS,
            ProviderCapability.PROFILE_EXPORT,
            ProviderCapability.RELOAD,
        }
    )
    unit = "fluxgate-singbox.service"
    OWNER = b"Managed by FluxGate sing-box artifacts\n"
    UNIT_HEADER = "# Managed by FluxGate sing-box\n"
    BINARY_OWNER = b"Managed by FluxGate sing-box binary\n"

    @property
    def binary(self) -> Path:
        if self.context.config.cores.singbox.binary_source == "managed":
            return self.context.paths.singbox_binary
        found = shutil.which("sing-box")
        return Path(found) if found else Path("/nonexistent/fluxgate-sing-box")

    @property
    def config_path(self) -> Path:
        return self.context.paths.singbox_config_file

    @property
    def binary_marker(self) -> Path:
        return self.binary.parent / ".fluxgate-owner"

    @property
    def marker(self) -> Path:
        return self.context.paths.singbox_dir / ".fluxgate-owner"

    @property
    def unit_path(self) -> Path:
        return self.context.paths.singbox_unit_file

    @property
    def tls(self) -> ManagedTLSIdentityManager:
        return ManagedTLSIdentityManager(self.context)

    def detect(self) -> ProviderDetection:
        available = self.binary.is_file() and not self.binary.is_symlink()
        version_ok = False
        if available and not self.context.dry_run:
            result = self.context.runner.run([str(self.binary), "version"], check=False)
            version_ok = result.returncode == 0 and SING_BOX_VERSION in result.stdout
        return ProviderDetection(
            available=available and version_ok,
            binaries={"sing-box": available, "openssl": shutil.which("openssl") is not None},
            detail=(
                f"managed sing-box {SING_BOX_VERSION} available"
                if available and version_ok
                else "sing-box missing or version does not match the managed release"
            ),
        )

    def _verify_binary(self) -> None:
        if self.binary.is_symlink() or not self.binary.is_file():
            raise ProviderError("sing-box binary is missing or unsafe")
        if self.context.config.cores.singbox.binary_source == "managed" and (
            self.binary_marker.is_symlink()
            or not self.binary_marker.is_file()
            or self.binary_marker.read_bytes() != self.BINARY_OWNER
        ):
            raise ProviderError(f"refusing unmanaged binary at {self.binary}")
        result = self.context.runner.run([str(self.binary), "version"], check=False)
        if result.returncode != 0 or SING_BOX_VERSION not in result.stdout:
            raise ProviderError(
                f"sing-box binary must be the verified supported version {SING_BOX_VERSION}"
            )

    def _enabled_in_state(self, state: FluxGateState | None = None) -> bool:
        source = state or self.context.state.load()
        value = source.providers.get(self.name, {}).get(
            "enabled", self.context.config.cores.singbox.enabled
        )
        if not isinstance(value, bool):
            raise StateError("invalid sing-box provider state")
        return value

    def _set_enabled(self, enabled: bool) -> None:
        state = self.context.state.load()
        provider = dict(state.providers.get(self.name, {}))
        provider["enabled"] = enabled
        state.providers[self.name] = provider
        self.context.state.save(state)

    def _owned(self) -> bool:
        return (
            self.marker.is_file()
            and not self.marker.is_symlink()
            and self.marker.read_bytes() == self.OWNER
        )

    def _assert_ownership(self) -> None:
        if self.context.paths.singbox_dir.is_symlink():
            raise ProviderError(
                f"refusing symlinked sing-box config location: {self.context.paths.singbox_dir}"
            )
        if (
            self.context.paths.singbox_dir.exists()
            and any(self.context.paths.singbox_dir.iterdir())
            and not self._owned()
        ):
            raise ProviderError(
                f"refusing unmanaged sing-box config location: {self.context.paths.singbox_dir}"
            )
        if self.unit_path.exists() and (
            self.unit_path.is_symlink()
            or not self.unit_path.read_text().startswith(self.UNIT_HEADER)
        ):
            raise ProviderError(f"refusing unmanaged systemd unit: {self.unit_path}")

    def _unit_content(self) -> bytes:
        text = (
            self.UNIT_HEADER
            + "[Unit]\nDescription=FluxGate managed sing-box core\nAfter=network-online.target\n"
            + "Wants=network-online.target\n\n[Service]\nType=simple\n"
            + f"ExecStartPre={self.binary} check -c {self.config_path}\n"
            + f"ExecStart={self.binary} run -c {self.config_path}\n"
            + "Restart=on-failure\nRestartSec=2s\nNoNewPrivileges=true\nPrivateTmp=true\n"
            + "PrivateDevices=true\nProtectSystem=strict\nProtectHome=true\n"
            + "ProtectKernelTunables=true\nProtectKernelModules=true\n"
            + "ProtectControlGroups=true\nRestrictSUIDSGID=true\nLockPersonality=true\n"
            + "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"
            + "AmbientCapabilities=CAP_NET_BIND_SERVICE\n"
            + "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n\n"
            + "[Install]\nWantedBy=multi-user.target\n"
        )
        return text.encode()

    def _validate(self, content: bytes) -> None:
        self.context.paths.singbox_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".config.validate.", dir=self.context.paths.singbox_dir
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as file:
                file.write(content)
            temporary.chmod(0o600)
            self.context.runner.run([str(self.binary), "check", "-c", str(temporary)])
        finally:
            temporary.unlink(missing_ok=True)

    def _render(self, state: FluxGateState, identity: TLSIdentity) -> bytes:
        return render_server(
            state,
            identity.certificate,
            identity.private_key,
            self.context.config.server.domain,
        )

    def _listeners_healthy(self, state: FluxGateState) -> bool:
        for profile in state.profiles:
            if profile.provider != self.name or not profile.enabled:
                continue
            if profile.socket_protocol == SocketProtocol.TCP:
                if not self.context.network.tcp_listener_present(profile.listen_port):
                    return False
            elif not self.context.network.udp_listener_present(profile.listen_port):
                return False
        return True

    def _wait_listeners(self, state: FluxGateState, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            if not self.context.services.is_active(self.unit):
                return False
            if self._listeners_healthy(state):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.1)

    def status(self) -> ProviderStatus:
        state = self.context.state.load()
        enabled = self._enabled_in_state(state)
        detection = self.detect()
        active = (
            enabled
            and detection.available
            and self.context.services.is_active(self.unit)
            and self.context.services.is_enabled(self.unit)
        )
        healthy = (
            active
            and self._owned()
            and self.config_path.is_file()
            and self._listeners_healthy(state)
        )
        if healthy:
            value = ProviderStateName.RUNNING
        elif enabled and detection.available:
            value = ProviderStateName.DEGRADED
        elif enabled:
            value = ProviderStateName.NOT_INSTALLED
        else:
            value = ProviderStateName.DISABLED
        return ProviderStatus(
            name=self.name,
            state=value,
            enabled=enabled,
            installed=detection.available,
            detail=detection.detail,
        )

    def _check_profile_conflicts(
        self, desired: FluxGateState, *, inspect_live: bool = True
    ) -> None:
        existing = self._managed_live_endpoints()
        seen: set[tuple[int, SocketProtocol]] = set()
        for profile in desired.profiles:
            if profile.provider != self.name or not profile.enabled:
                continue
            endpoint = (profile.listen_port, profile.socket_protocol)
            if endpoint in seen:
                raise ProviderError(
                    f"duplicate profile endpoint: {profile.listen_port}/{profile.socket_protocol}"
                )
            seen.add(endpoint)
            if profile.socket_protocol == SocketProtocol.UDP and profile.listen_port in {
                self.context.config.cores.wireguard.listen_port,
                self.context.config.cores.openvpn.listen_port,
            }:
                raise ProviderError(
                    f"UDP port conflicts with an existing VPN provider: {profile.listen_port}"
                )
            if endpoint in existing:
                continue
            if not inspect_live:
                continue
            available = (
                self.context.network.tcp_port_available(profile.listen_port)
                if profile.socket_protocol == SocketProtocol.TCP
                else self.context.network.udp_port_available(profile.listen_port)
            )
            if not available:
                raise ProviderError(
                    "port is occupied by a foreign listener: "
                    f"{profile.listen_port}/{profile.socket_protocol.value}"
                )

    def _managed_live_endpoints(self) -> set[tuple[int, SocketProtocol]]:
        if (
            not self._owned()
            or not self.config_path.is_file()
            or not self.context.services.is_active(self.unit)
        ):
            return set()
        try:
            document = json.loads(self.config_path.read_bytes())
            inbounds = document["inbounds"]
            if not isinstance(inbounds, list):
                return set()
            endpoints: set[tuple[int, SocketProtocol]] = set()
            for inbound in inbounds:
                if not isinstance(inbound, dict) or not str(inbound.get("tag", "")).startswith(
                    "fluxgate-"
                ):
                    continue
                port = inbound.get("listen_port")
                protocol = inbound.get("type")
                if type(port) is not int:
                    continue
                socket_protocol = (
                    SocketProtocol.UDP
                    if protocol == ProtocolName.HYSTERIA2.value
                    else SocketProtocol.TCP
                )
                endpoints.add((port, socket_protocol))
            return endpoints
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            return set()

    def _publish_config(self, desired: FluxGateState, identity: TLSIdentity) -> bool:
        content = self._render(desired, identity)
        self._validate(content)
        previous = self.config_path.read_bytes() if self.config_path.exists() else None
        active = self.context.services.is_active(self.unit)
        atomic_write(self.config_path, content, 0o600)
        try:
            if active:
                self.context.services.restart(self.unit)
                if not self._wait_listeners(desired):
                    raise ProviderError("sing-box restart did not expose all expected listeners")
        except BaseException:
            if previous is None:
                self.config_path.unlink(missing_ok=True)
            else:
                atomic_write(self.config_path, previous, 0o600)
                self.context.services.restart(self.unit)
            raise
        return previous != content

    def enable(self) -> OperationResult:
        if self.context.dry_run:
            return OperationResult(
                changed=True,
                message="sing-box enable plan",
                actions=[
                    f"Would acquire verified sing-box {SING_BOX_VERSION}",
                    "Would ensure FluxGate managed TLS identity",
                    f"Would validate and converge {self.config_path}",
                    f"Would converge and enable {self.unit}",
                    "Would update FluxGate provider state",
                ],
            )
        with self.context.state.lock():
            self._assert_ownership()
            state = self.context.state.load()
            was_enabled = self._enabled_in_state(state)
            service_active = self.context.services.is_active(self.unit)
            service_enabled = self.context.services.is_enabled(self.unit)
            identity = self.tls._load_current()
            already_converged = (
                was_enabled
                and service_active
                and service_enabled
                and self.detect().available
                and identity is not None
                and self.tls.valid(identity, self.context.config.server.domain)
                and self._owned()
                and self.config_path.is_file()
                and self.config_path.read_bytes() == self._render(state, identity)
                and self.unit_path.is_file()
                and self.unit_path.read_bytes() == self._unit_content()
                and self._listeners_healthy(state)
            )
            if already_converged:
                return OperationResult(changed=False, message="sing-box is already enabled")
            plan = OperationPlan()
            if not self.binary.exists():
                if self.context.config.cores.singbox.binary_source == "system":
                    raise ProviderError("system sing-box binary is not available")

                def acquire_binary() -> None:
                    self.context.packages.acquire_sing_box(self.binary)
                    atomic_write(self.binary_marker, self.BINARY_OWNER, 0o600)
                    self.binary.parent.chmod(0o755)

                def remove_binary() -> None:
                    self.binary.unlink(missing_ok=True)
                    self.binary_marker.unlink(missing_ok=True)

                plan.add(
                    f"Would acquire verified sing-box {SING_BOX_VERSION}",
                    acquire_binary,
                    remove_binary,
                )
            plan.add("Would verify the sing-box binary version", self._verify_binary)
            identity_box: list[TLSIdentity] = []
            plan.add(
                "Would ensure FluxGate managed TLS identity",
                lambda: identity_box.append(self.tls.ensure(self.context.config.server.domain)),
            )

            def converge_files() -> None:
                identity = identity_box[0]
                self._check_profile_conflicts(state)
                self.context.paths.singbox_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                self.context.paths.singbox_dir.chmod(0o700)
                atomic_write(self.marker, self.OWNER, 0o600)
                content = self._render(state, identity)
                self._validate(content)
                atomic_write(self.config_path, content, 0o600)
                atomic_write(self.unit_path, self._unit_content(), 0o644)
                self.context.services.daemon_reload()

            old_config = self.config_path.read_bytes() if self.config_path.exists() else None
            old_unit = self.unit_path.read_bytes() if self.unit_path.exists() else None

            def restore_files() -> None:
                if old_config is None:
                    self.config_path.unlink(missing_ok=True)
                    self.marker.unlink(missing_ok=True)
                else:
                    atomic_write(self.config_path, old_config, 0o600)
                if old_unit is None:
                    self.unit_path.unlink(missing_ok=True)
                else:
                    atomic_write(self.unit_path, old_unit, 0o644)
                self.context.services.daemon_reload()
                if service_active:
                    self.context.services.restart(self.unit)

            plan.add(
                "Would converge FluxGate sing-box config and unit", converge_files, restore_files
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
                if not self._wait_listeners(state):
                    raise ProviderError("sing-box failed postcondition verification")

            plan.add("Would verify sing-box postconditions", verify)
            if not was_enabled:
                plan.add("Would update FluxGate provider state", lambda: self._set_enabled(True))
            actions = plan.execute()
            return OperationResult(changed=True, message="sing-box enabled", actions=actions)

    def disable(self) -> OperationResult:
        if self.context.dry_run:
            return OperationResult(
                changed=True,
                message="sing-box disable plan",
                actions=[f"Would disable {self.unit}", "Would update FluxGate provider state"],
            )
        with self.context.state.lock():
            self._assert_ownership()
            enabled = self._enabled_in_state()
            active = self.context.services.is_active(self.unit)
            service_enabled = self.context.services.is_enabled(self.unit)
            if not enabled and not active and not service_enabled:
                return OperationResult(changed=False, message="sing-box is already disabled")
            if active or service_enabled:
                self.context.services.disable_now(self.unit)
            try:
                self._set_enabled(False)
            except BaseException:
                self.context.services.restore(self.unit, enabled=service_enabled, active=active)
                raise
            return OperationResult(changed=True, message="sing-box disabled")

    def reconcile_profiles(self, desired: FluxGateState) -> OperationResult:
        self._assert_ownership()
        if not self._enabled_in_state():
            raise ProviderError("sing-box provider is not enabled")
        self._check_profile_conflicts(desired, inspect_live=not self.context.dry_run)
        identity = self.tls.ensure(self.context.config.server.domain)
        changed = self._publish_config(desired, identity)
        return OperationResult(changed=changed, message="sing-box profiles reconciled")

    def validate_profile(self, profile: ProfileDefinition, state: FluxGateState) -> None:
        desired = state.model_copy(deep=True)
        candidate = profile.model_copy(deep=True)
        candidate.enabled = True
        desired.profiles.append(candidate)
        self._check_profile_conflicts(desired, inspect_live=not self.context.dry_run)

    def generate_profile_credential(self, profile: ProfileDefinition) -> dict[str, object]:
        if profile.protocol == ProtocolName.VLESS:
            return {"schema_version": 1, "uuid": str(uuid4())}
        return {"schema_version": 1, "password": secrets.token_urlsafe(32)}

    def export_profile(self, client: Client, profile: ProfileDefinition) -> ExportArtifact:
        identity = self.tls._load_current()
        endpoint = self.context.config.server.domain
        if identity is None or not endpoint:
            raise ProviderError("managed sing-box TLS identity is unavailable")
        content = render_client(client, profile, endpoint, identity.ca_certificate.read_text())
        return ExportArtifact(
            name=f"{profile.name}.json", media_type="application/json", content=content
        )

    def healthcheck(self) -> list[HealthResult]:
        status = self.status()
        results = [
            HealthResult(
                name="provider-status",
                level=(
                    HealthLevel.SUCCESS
                    if status.state == ProviderStateName.RUNNING
                    else HealthLevel.INFO
                    if status.state == ProviderStateName.DISABLED
                    else HealthLevel.FAILURE
                ),
                message=status.detail,
            )
        ]
        if not status.enabled:
            return results
        state = self.context.state.load()
        config_secure = (
            self.config_path.is_file()
            and not self.config_path.is_symlink()
            and stat.S_IMODE(self.config_path.stat().st_mode) == 0o600
        )
        ownership_ok = self._owned() and config_secure
        results.append(
            HealthResult(
                name="config-ownership",
                level=HealthLevel.SUCCESS if ownership_ok else HealthLevel.FAILURE,
                message=(
                    "managed config ownership and mode valid"
                    if ownership_ok
                    else "managed config ownership or mode invalid"
                ),
            )
        )
        unit_ok = (
            self.unit_path.is_file()
            and not self.unit_path.is_symlink()
            and self.unit_path.read_bytes() == self._unit_content()
            and self.context.services.is_enabled(self.unit)
        )
        results.append(
            HealthResult(
                name="systemd-unit",
                level=HealthLevel.SUCCESS if unit_ok else HealthLevel.FAILURE,
                message="owned unit enabled and current"
                if unit_ok
                else "owned unit missing, stale, or disabled",
            )
        )
        identity = self.tls._load_current()
        tls_valid = identity is not None and self.tls.valid(
            identity, self.context.config.server.domain
        )
        results.append(
            HealthResult(
                name="tls-identity",
                level=HealthLevel.SUCCESS if tls_valid else HealthLevel.FAILURE,
                message=(
                    "managed TLS identity valid"
                    if tls_valid
                    else "managed TLS identity invalid or near expiry"
                ),
            )
        )
        listeners_ok = self._listeners_healthy(state)
        results.append(
            HealthResult(
                name="listeners",
                level=HealthLevel.SUCCESS if listeners_ok else HealthLevel.FAILURE,
                message=(
                    "all expected profile listeners present"
                    if listeners_ok
                    else "one or more profile listeners missing"
                ),
            )
        )
        convergence_ok = False
        if identity is not None and self.config_path.is_file():
            try:
                convergence_ok = self.config_path.read_bytes() == self._render(state, identity)
            except ProviderError:
                convergence_ok = False
        results.append(
            HealthResult(
                name="state-convergence",
                level=HealthLevel.SUCCESS if convergence_ok else HealthLevel.FAILURE,
                message=(
                    "state and managed config converge"
                    if convergence_ok
                    else "state and managed config differ or credentials are invalid"
                ),
            )
        )
        if self.config_path.is_file():
            check = self.context.runner.run(
                [str(self.binary), "check", "-c", str(self.config_path)], check=False
            )
            results.append(
                HealthResult(
                    name="config-syntax",
                    level=HealthLevel.SUCCESS if check.returncode == 0 else HealthLevel.FAILURE,
                    message=(
                        "sing-box config valid"
                        if check.returncode == 0
                        else "sing-box config validation failed"
                    ),
                )
            )
        return results
