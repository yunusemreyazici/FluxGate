"""Persistent, identifiable nftables rules owned only by FluxGate."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Protocol

from fluxgate.core.commands import CommandRunner
from fluxgate.core.errors import StateError
from fluxgate.core.state import atomic_write


class FirewallManager(Protocol):
    def ensure_nat(self, source_cidr: str, outbound_interface: str | None) -> bool: ...

    def configured(self, source_cidr: str, outbound_interface: str | None) -> bool: ...

    def remove(self) -> bool: ...


class NftablesFirewallManager:
    TABLE = "fluxgate"
    UNIT = "fluxgate-firewall.service"
    INTERFACE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")

    def __init__(self, runner: CommandRunner, config_path: Path, unit_path: Path) -> None:
        self.runner = runner
        self.config_path = config_path
        self.unit_path = unit_path

    def _exists(self) -> bool:
        return (
            self.runner.run(["nft", "list", "table", "inet", self.TABLE], check=False).returncode
            == 0
        )

    def _rules(self, source_cidr: str, outbound_interface: str | None) -> bytes:
        try:
            network = ipaddress.ip_network(source_cidr)
        except ValueError as error:
            raise StateError("invalid firewall source network") from error
        if network.version != 4:
            raise StateError("the initial NAT backend requires an IPv4 source network")
        source_cidr = str(network)
        if outbound_interface is not None and not self.INTERFACE.fullmatch(outbound_interface):
            raise StateError("invalid firewall outbound interface")
        output = f' oifname "{outbound_interface}"' if outbound_interface else ""
        return (
            "# Managed by FluxGate.\n"
            "table inet fluxgate {\n"
            "  chain postrouting {\n"
            "    type nat hook postrouting priority srcnat; policy accept;\n"
            f"    ip saddr {source_cidr}{output} counter masquerade "
            'comment "fluxgate-managed"\n'
            "  }\n"
            "}\n"
        ).encode()

    def _unit(self) -> bytes:
        return (
            "# Managed by FluxGate.\n"
            "[Unit]\n"
            "Description=FluxGate firewall rules\n"
            "After=network-pre.target\n"
            "Before=network.target\n\n"
            "[Service]\n"
            "Type=oneshot\n"
            "RemainAfterExit=yes\n"
            f"ExecStartPre=-/usr/sbin/nft delete table inet {self.TABLE}\n"
            f"ExecStart=/usr/sbin/nft -f {self.config_path}\n"
            f"ExecStop=-/usr/sbin/nft delete table inet {self.TABLE}\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        ).encode()

    def configured(self, source_cidr: str, outbound_interface: str | None) -> bool:
        files_match = (
            self.config_path.exists()
            and not self.config_path.is_symlink()
            and self.config_path.read_bytes() == self._rules(source_cidr, outbound_interface)
            and self.unit_path.exists()
            and not self.unit_path.is_symlink()
            and self.unit_path.read_bytes() == self._unit()
        )
        if not files_match:
            return False
        live = self.runner.run(["nft", "list", "table", "inet", self.TABLE], check=False)
        return (
            live.returncode == 0
            and "fluxgate-managed" in live.stdout
            and str(ipaddress.ip_network(source_cidr)) in live.stdout
            and (outbound_interface is None or outbound_interface in live.stdout)
        )

    def ensure_nat(self, source_cidr: str, outbound_interface: str | None) -> bool:
        if self.configured(source_cidr, outbound_interface):
            return False
        for path in (self.config_path, self.unit_path):
            if path.is_symlink():
                raise StateError(f"refusing to replace symlink: {path}")
            if path.exists() and not path.read_bytes().startswith(b"# Managed by FluxGate."):
                raise StateError(f"refusing to replace unmanaged file: {path}")
        old_config = self.config_path.read_bytes() if self.config_path.exists() else None
        old_unit = self.unit_path.read_bytes() if self.unit_path.exists() else None
        atomic_write(self.config_path, self._rules(source_cidr, outbound_interface), 0o644)
        atomic_write(self.unit_path, self._unit(), 0o644)
        try:
            self.runner.run(["systemctl", "daemon-reload"], mutate=True)
            self.runner.run(["systemctl", "enable", self.UNIT], mutate=True)
            self.runner.run(["systemctl", "restart", self.UNIT], mutate=True)
        except BaseException:
            if old_config is None:
                self.config_path.unlink(missing_ok=True)
            else:
                atomic_write(self.config_path, old_config, 0o644)
            if old_unit is None:
                self.unit_path.unlink(missing_ok=True)
            else:
                atomic_write(self.unit_path, old_unit, 0o644)
            self.runner.run(["systemctl", "daemon-reload"], check=False, mutate=True)
            if old_config is not None and old_unit is not None:
                self.runner.run(["systemctl", "restart", self.UNIT], check=False, mutate=True)
            raise
        return True

    def remove(self) -> bool:
        managed = self.config_path.exists() or self.unit_path.exists() or self._exists()
        if not managed:
            return False
        self.runner.run(["systemctl", "disable", "--now", self.UNIT], check=False, mutate=True)
        if self._exists():
            self.runner.run(["nft", "delete", "table", "inet", self.TABLE], mutate=True)
        self.config_path.unlink(missing_ok=True)
        self.unit_path.unlink(missing_ok=True)
        self.runner.run(["systemctl", "daemon-reload"], mutate=True)
        return True
