"""Doctor aggregation, independent of presentation."""

from __future__ import annotations

import os
import shutil
import socket
from typing import Literal

from pydantic import Field

from fluxgate.core.compat import StrEnum
from fluxgate.core.config import load_config
from fluxgate.core.errors import IdentityError
from fluxgate.core.models import HealthLevel, StrictModel
from fluxgate.core.paths import PathLayout
from fluxgate.core.registry import ProviderRegistry
from fluxgate.core.state import StateStore
from fluxgate.identity import ServerIdentityManager
from fluxgate.system.forwarding import ForwardingManager
from fluxgate.system.os import OperatingSystem


class HealthSeverity(StrEnum):
    SUCCESS = "pass"
    INFO = "info"
    WARNING = "warning"
    FAILURE = "failure"


class HealthCheck(StrictModel):
    section: str
    name: str
    severity: HealthSeverity
    message: str


class HealthReport(StrictModel):
    schema_version: Literal[1] = 1
    checks: list[HealthCheck] = Field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return not any(check.severity == HealthSeverity.FAILURE for check in self.checks)


class Doctor:
    def __init__(
        self,
        paths: PathLayout,
        state: StateStore,
        providers: ProviderRegistry,
        operating_system: OperatingSystem,
        forwarding: ForwardingManager,
        identity: ServerIdentityManager | None = None,
    ) -> None:
        self.paths = paths
        self.state = state
        self.providers = providers
        self.os = operating_system
        self.forwarding = forwarding
        self.identity = identity or ServerIdentityManager(paths)

    def run(self) -> HealthReport:
        checks: list[HealthCheck] = []
        checks.append(
            HealthCheck(
                section="System",
                name="operating-system",
                severity=HealthSeverity.SUCCESS if self.os.supported else HealthSeverity.FAILURE,
                message=(
                    f"{self.os.pretty_name} supported"
                    if self.os.supported
                    else f"{self.os.pretty_name} is not supported"
                ),
            )
        )
        checks.append(
            HealthCheck(
                section="System",
                name="architecture",
                severity=HealthSeverity.INFO,
                message=self.os.architecture,
            )
        )
        checks.extend(
            [
                HealthCheck(
                    section="Network",
                    name="ipv4-support",
                    severity=HealthSeverity.SUCCESS,
                    message="IPv4 supported",
                ),
                HealthCheck(
                    section="Network",
                    name="ipv6-support",
                    severity=HealthSeverity.SUCCESS if socket.has_ipv6 else HealthSeverity.WARNING,
                    message=f"IPv6 {'supported' if socket.has_ipv6 else 'unavailable'}",
                ),
            ]
        )
        checks.append(
            HealthCheck(
                section="System",
                name="privileges",
                severity=HealthSeverity.SUCCESS if os.geteuid() == 0 else HealthSeverity.INFO,
                message="running as root"
                if os.geteuid() == 0
                else "read-only checks; mutations require root",
            )
        )
        for binary in ("systemctl", "nft"):
            available = shutil.which(binary) is not None
            checks.append(
                HealthCheck(
                    section="System",
                    name=binary,
                    severity=HealthSeverity.SUCCESS if available else HealthSeverity.WARNING,
                    message=f"{binary} {'available' if available else 'not found'}",
                )
            )
        checks.append(
            HealthCheck(
                section="Network",
                name="ipv4-forwarding",
                severity=HealthSeverity.SUCCESS
                if self.forwarding.enabled()
                else HealthSeverity.WARNING,
                message=f"IPv4 forwarding {'enabled' if self.forwarding.enabled() else 'disabled'}",
            )
        )
        try:
            socket.getaddrinfo("localhost", None)
            dns_ok = True
        except OSError:
            dns_ok = False
        checks.append(
            HealthCheck(
                section="Network",
                name="dns",
                severity=HealthSeverity.SUCCESS if dns_ok else HealthSeverity.FAILURE,
                message=f"DNS resolution {'works' if dns_ok else 'failed'}",
            )
        )
        for name, operation in (
            ("configuration", lambda: load_config(self.paths.config_file)),
            ("state", self.state.load),
        ):
            try:
                operation()
                severity, message = HealthSeverity.SUCCESS, f"{name} valid"
            except Exception as error:  # doctor must aggregate independent failures
                severity, message = HealthSeverity.FAILURE, str(error)
            checks.append(
                HealthCheck(section="FluxGate", name=name, severity=severity, message=message)
            )
        for directory in (self.paths.config_dir, self.paths.data_dir):
            exists = directory.is_dir()
            checks.append(
                HealthCheck(
                    section="FluxGate",
                    name=f"directory:{directory}",
                    severity=HealthSeverity.SUCCESS if exists else HealthSeverity.INFO,
                    message=f"{directory} {'exists' if exists else 'will be created when needed'}",
                )
            )
        for path in (self.paths.state_file, self.paths.secrets_dir, self.paths.clients_dir):
            if not path.exists():
                continue
            mode = path.stat().st_mode & 0o777
            secure = mode & 0o077 == 0
            owner_ok = os.geteuid() != 0 or path.stat().st_uid == 0
            checks.append(
                HealthCheck(
                    section="FluxGate",
                    name=f"permissions:{path}",
                    severity=HealthSeverity.SUCCESS
                    if secure and owner_ok
                    else HealthSeverity.FAILURE,
                    message=f"{path} mode {mode:04o}; owner "
                    f"{'accepted' if owner_ok else 'must be root'}",
                )
            )
        try:
            identity = self.identity.load_optional()
            if identity is None:
                identity_severity = HealthSeverity.INFO
                identity_message = "server signing identity not initialized"
            else:
                identity_severity = HealthSeverity.SUCCESS
                identity_message = (
                    f"server signing identity healthy; key ID {identity.metadata.key_id}"
                )
        except IdentityError as error:
            identity_severity = HealthSeverity.FAILURE
            identity_message = f"server signing identity invalid: {error}"
        checks.append(
            HealthCheck(
                section="FluxGate",
                name="server-signing-identity",
                severity=identity_severity,
                message=identity_message,
            )
        )
        for provider in self.providers.all():
            severity_map = {
                HealthLevel.SUCCESS: HealthSeverity.SUCCESS,
                HealthLevel.INFO: HealthSeverity.INFO,
                HealthLevel.WARNING: HealthSeverity.WARNING,
                HealthLevel.FAILURE: HealthSeverity.FAILURE,
            }
            for result in provider.healthcheck():
                checks.append(
                    HealthCheck(
                        section=provider.display_name,
                        name=result.name,
                        severity=severity_map[result.level],
                        message=result.message,
                    )
                )
        return HealthReport(checks=checks)
