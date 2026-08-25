"""OpenVPN-specific structured health checks."""

from __future__ import annotations

from typing import Protocol

from fluxgate.core.config import OpenVPNConfig
from fluxgate.core.models import (
    HealthLevel,
    HealthResult,
    ProviderDetection,
    ProviderStateName,
    ProviderStatus,
)
from fluxgate.providers.base import OperationContext
from fluxgate.providers.openvpn.pki import OpenVPNPKI
from fluxgate.providers.openvpn.rendering import tunnel_network


class HealthTarget(Protocol):
    name: str
    context: OperationContext

    @property
    def unit(self) -> str: ...

    @property
    def settings(self) -> OpenVPNConfig: ...

    @property
    def pki(self) -> OpenVPNPKI: ...

    def status(self) -> ProviderStatus: ...

    def detect(self) -> ProviderDetection: ...

    def configuration_valid(self) -> bool: ...

    def crl_valid(self) -> bool: ...

    def client_artifacts_valid(self) -> bool: ...


def _result(name: str, passed: bool, success: str, failure: str) -> HealthResult:
    return HealthResult(
        name=name,
        level=HealthLevel.SUCCESS if passed else HealthLevel.FAILURE,
        message=success if passed else failure,
    )


def openvpn_health(target: HealthTarget) -> list[HealthResult]:
    status = target.status()
    if not status.enabled:
        return [
            HealthResult(name="provider-status", level=HealthLevel.INFO, message="OpenVPN disabled")
        ]
    results: list[HealthResult] = []
    for binary, found in target.detect().binaries.items():
        results.append(
            _result(
                f"binary:{binary}",
                found,
                f"{binary} available",
                f"{binary} not found",
            )
        )
    results.append(
        _result(
            "service",
            status.state == ProviderStateName.RUNNING,
            f"{target.unit} is running with interface and listener",
            f"{target.unit} is {status.state.value}",
        )
    )
    results.append(
        _result(
            "configuration",
            target.configuration_valid(),
            "owned OpenVPN configuration is converged",
            "OpenVPN configuration, CRL, PKI, or client assignments are inconsistent",
        )
    )
    pki_complete = target.pki.complete()
    results.append(
        _result(
            "pki",
            pki_complete,
            "FluxGate OpenVPN PKI is complete with restrictive permissions",
            "FluxGate OpenVPN PKI is missing, unsafe, or incomplete",
        )
    )
    results.append(
        _result(
            "crl",
            target.crl_valid(),
            "OpenVPN certificate revocation list is valid and synchronized",
            "OpenVPN certificate revocation list is missing, invalid, or stale",
        )
    )
    certificate_valid = pki_complete and target.pki.certificate_valid(
        target.pki.server_certificate_path
    )
    results.append(
        _result(
            "server-certificate",
            certificate_valid,
            "OpenVPN server certificate is valid",
            "OpenVPN server certificate is missing or expired",
        )
    )
    results.append(
        _result(
            "client-state",
            target.client_artifacts_valid(),
            "OpenVPN client state and artifacts are consistent",
            "OpenVPN client state or artifacts are inconsistent",
        )
    )
    forwarding = target.context.forwarding.enabled() and target.context.forwarding.configured(
        target.name
    )
    results.append(
        _result(
            "forwarding",
            forwarding,
            "OpenVPN forwarding lease is active",
            "OpenVPN forwarding lease is missing",
        )
    )
    network = str(tunnel_network(target.settings))
    firewall = target.context.firewall.configured(
        target.name, network, target.context.config.network.outbound_interface
    )
    results.append(
        _result(
            "firewall",
            firewall,
            "OpenVPN nftables NAT rule is active",
            "OpenVPN nftables NAT rule is missing or drifted",
        )
    )
    conflict = target.context.network.conflicting_route(
        tunnel_network(target.settings), target.settings.interface
    )
    results.append(
        _result(
            "route-conflict",
            conflict is None,
            "OpenVPN tunnel network has no conflicting route",
            f"OpenVPN tunnel network conflicts with route: {conflict}",
        )
    )
    return results
