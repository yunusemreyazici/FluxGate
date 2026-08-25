"""WireGuard-specific structured health checks."""

import socket
from pathlib import Path
from typing import Protocol

from fluxgate.core.config import WireGuardConfig
from fluxgate.core.models import (
    HealthLevel,
    HealthResult,
    ProviderDetection,
    ProviderStateName,
    ProviderStatus,
)


class HealthTarget(Protocol):
    @property
    def unit(self) -> str: ...

    @property
    def config_path(self) -> Path: ...

    @property
    def private_key_path(self) -> Path: ...

    @property
    def settings(self) -> WireGuardConfig: ...

    def status(self) -> ProviderStatus: ...

    def detect(self) -> ProviderDetection: ...

    def configuration_valid(self) -> bool: ...


def wireguard_health(target: HealthTarget) -> list[HealthResult]:
    status = target.status()
    if not status.enabled:
        return [
            HealthResult(
                name="provider-status", level=HealthLevel.INFO, message="WireGuard disabled"
            )
        ]
    results: list[HealthResult] = []
    for binary, found in target.detect().binaries.items():
        results.append(
            HealthResult(
                name=f"binary:{binary}",
                level=HealthLevel.SUCCESS if found else HealthLevel.FAILURE,
                message=f"{binary} {'available' if found else 'not found'}",
            )
        )
    results.append(
        HealthResult(
            name="service",
            level=HealthLevel.SUCCESS
            if status.state == ProviderStateName.RUNNING
            else HealthLevel.FAILURE,
            message=f"{target.unit} is {status.state.value}",
        )
    )
    config_valid = target.configuration_valid()
    results.append(
        HealthResult(
            name="configuration",
            level=HealthLevel.SUCCESS if config_valid else HealthLevel.FAILURE,
            message="configuration present" if config_valid else "configuration or key missing",
        )
    )
    if status.state != ProviderStateName.RUNNING:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            try:
                probe.bind(("0.0.0.0", target.settings.listen_port))  # noqa: S104
                available = True
            except OSError:
                available = False
        results.append(
            HealthResult(
                name="listen-port",
                level=HealthLevel.SUCCESS if available else HealthLevel.FAILURE,
                message=f"UDP port {target.settings.listen_port} "
                f"{'available' if available else 'in use'}",
            )
        )
    return results
