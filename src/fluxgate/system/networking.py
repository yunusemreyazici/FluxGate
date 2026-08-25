"""Read-only host network conflict inspection."""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Protocol

from fluxgate.core.commands import CommandRunner


class NetworkInspector(Protocol):
    def interface_exists(self, interface: str) -> bool: ...

    def conflicting_route(self, network: ipaddress.IPv4Network, interface: str) -> str | None: ...

    def udp_port_available(self, port: int, address: str = "0.0.0.0") -> bool: ...  # noqa: S104

    def udp_listener_present(self, port: int) -> bool: ...

    def tcp_port_available(self, port: int, address: str = "0.0.0.0") -> bool: ...  # noqa: S104

    def tcp_listener_present(self, port: int) -> bool: ...


class LinuxNetworkInspector:
    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner

    def interface_exists(self, interface: str) -> bool:
        return (
            self.runner.run(["ip", "link", "show", "dev", interface], check=False).returncode == 0
        )

    def conflicting_route(self, network: ipaddress.IPv4Network, interface: str) -> str | None:
        result = self.runner.run(["ip", "-4", "route", "show"])
        for line in result.stdout.splitlines():
            parts = line.split()
            route_target = parts[0] if parts else ""
            if not route_target or route_target == "default":
                continue
            try:
                route = ipaddress.ip_network(route_target, strict=False)
            except ValueError:
                continue
            if route.overlaps(network) and f"dev {interface}" not in line:
                return line
        return None

    def udp_port_available(
        self,
        port: int,
        address: str = "0.0.0.0",  # noqa: S104
    ) -> bool:
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as probe:
            try:
                probe.bind((address, port))
            except OSError:
                return False
        return True

    def udp_listener_present(self, port: int) -> bool:
        result = self.runner.run(["ss", "-H", "-lun"], check=False)
        if result.returncode != 0:
            return False
        endpoint = re.compile(rf"(?:^|[\s\]])[^\s]*:{port}(?:\s|$)")
        return any(endpoint.search(line) for line in result.stdout.splitlines())

    def tcp_port_available(
        self,
        port: int,
        address: str = "0.0.0.0",  # noqa: S104
    ) -> bool:
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind((address, port))
            except OSError:
                return False
        return True

    def tcp_listener_present(self, port: int) -> bool:
        result = self.runner.run(["ss", "-H", "-ltn"], check=False)
        if result.returncode != 0:
            return False
        endpoint = re.compile(rf"(?:^|[\s\]])[^\s]*:{port}(?:\s|$)")
        return any(endpoint.search(line) for line in result.stdout.splitlines())
