"""Persistent, strictly owned nftables rules for FluxGate."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from fluxgate.core.commands import CommandResult, CommandRunner
from fluxgate.core.errors import StateError
from fluxgate.core.state import atomic_write


class FirewallManager(Protocol):
    def ensure_nat(self, owner: str, source_cidr: str, outbound_interface: str | None) -> bool: ...

    def configured(self, owner: str, source_cidr: str, outbound_interface: str | None) -> bool: ...

    def checkpoint(self) -> object: ...

    def restore(self, checkpoint: object) -> None: ...

    def managed(self, owner: str | None = None) -> bool: ...

    def remove_nat(self, owner: str) -> bool: ...

    def remove(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class FirewallCheckpoint:
    config: bytes | None
    unit: bytes | None
    live_rules: str | None
    service_enabled: bool
    service_active: bool


class NftablesFirewallManager:
    TABLE = "fluxgate"
    UNIT = "fluxgate-firewall.service"
    MARKER = "fluxgate-managed"
    FILE_HEADER = b"# Managed by FluxGate.\n"
    INTERFACE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
    OWNER = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
    RULE = re.compile(
        r'^    ip saddr (?P<network>\S+)(?: oifname "(?P<interface>[A-Za-z0-9_.-]+)")? '
        r'counter masquerade comment "fluxgate-managed:(?P<owner>[a-z][a-z0-9-]{0,31})"$'
    )
    LEGACY_RULE = re.compile(
        r'^    ip saddr (?P<network>\S+)(?: oifname "(?P<interface>[A-Za-z0-9_.-]+)")? '
        r'counter masquerade comment "fluxgate-managed"$'
    )

    def __init__(self, runner: CommandRunner, config_path: Path, unit_path: Path) -> None:
        self.runner = runner
        self.config_path = config_path
        self.unit_path = unit_path

    def _live(self) -> CommandResult:
        return self.runner.run(["nft", "list", "table", "inet", self.TABLE], check=False)

    def _owned_live(self, result: CommandResult | None = None) -> bool:
        live = self._live() if result is None else result
        return (
            live.returncode == 0
            and live.stdout.count(self.MARKER) >= 2
            and "chain postrouting" in live.stdout
        )

    def _assert_owned_files(self) -> None:
        for path in (self.config_path, self.unit_path):
            if path.is_symlink():
                raise StateError(f"refusing to use symlink: {path}")
            if path.exists() and not path.read_bytes().startswith(self.FILE_HEADER):
                raise StateError(f"refusing to replace unmanaged file: {path}")

    def _validated_network(self, source_cidr: str) -> ipaddress.IPv4Network:
        try:
            network = ipaddress.ip_network(source_cidr)
        except ValueError as error:
            raise StateError("invalid firewall source network") from error
        if network.version != 4:
            raise StateError("the initial NAT backend requires an IPv4 source network")
        return network

    def _validated_owner(self, owner: str) -> str:
        if not self.OWNER.fullmatch(owner):
            raise StateError(f"invalid firewall owner: {owner}")
        return owner

    def _validated_rule(
        self, source_cidr: str, outbound_interface: str | None
    ) -> tuple[str, str | None]:
        network = str(self._validated_network(source_cidr))
        if outbound_interface is not None and not self.INTERFACE.fullmatch(outbound_interface):
            raise StateError("invalid firewall outbound interface")
        return network, outbound_interface

    def _rules(self, rules: dict[str, tuple[str, str | None]]) -> bytes:
        rendered_rules: list[str] = []
        for owner in sorted(rules):
            self._validated_owner(owner)
            network, outbound_interface = self._validated_rule(*rules[owner])
            output = f' oifname "{outbound_interface}"' if outbound_interface else ""
            rendered_rules.append(
                f'    ip saddr {network}{output} counter masquerade comment "{self.MARKER}:{owner}"'
            )
        return (
            self.FILE_HEADER
            + (
                "table inet fluxgate {\n"
                f'  comment "{self.MARKER}"\n'
                "  chain postrouting {\n"
                "    type nat hook postrouting priority srcnat; policy accept;\n"
                + ("\n".join(rendered_rules) + "\n" if rendered_rules else "")
                + "  }\n"
                "}\n"
            ).encode()
        )

    def _legacy_rules(self, source_cidr: str, outbound_interface: str | None) -> bytes:
        network, outbound_interface = self._validated_rule(source_cidr, outbound_interface)
        output = f' oifname "{outbound_interface}"' if outbound_interface else ""
        return (
            self.FILE_HEADER
            + (
                "table inet fluxgate {\n"
                f'  comment "{self.MARKER}"\n'
                "  chain postrouting {\n"
                "    type nat hook postrouting priority srcnat; policy accept;\n"
                f"    ip saddr {network}{output} counter masquerade "
                f'comment "{self.MARKER}"\n'
                "  }\n"
                "}\n"
            ).encode()
        )

    def _configured_rules(self) -> dict[str, tuple[str, str | None]]:
        self._assert_owned_files()
        if not self.config_path.exists():
            return {}
        if self.config_path.read_bytes() == self.FILE_HEADER:
            return {}
        try:
            lines = self.config_path.read_text().splitlines()
        except UnicodeDecodeError as error:
            raise StateError(
                f"invalid FluxGate firewall configuration: {self.config_path}"
            ) from error
        rules: dict[str, tuple[str, str | None]] = {}
        legacy: tuple[str, str | None] | None = None
        for line in lines:
            match = self.RULE.fullmatch(line)
            if match:
                owner = match.group("owner")
                if owner in rules:
                    raise StateError(f"duplicate FluxGate firewall owner: {owner}")
                rules[owner] = self._validated_rule(
                    match.group("network"), match.group("interface")
                )
                continue
            legacy_match = self.LEGACY_RULE.fullmatch(line)
            if legacy_match:
                legacy = self._validated_rule(
                    legacy_match.group("network"), legacy_match.group("interface")
                )
        if legacy is not None:
            if rules or self.config_path.read_bytes() != self._legacy_rules(*legacy):
                raise StateError(f"invalid legacy FluxGate firewall file: {self.config_path}")
            return {"wireguard": legacy}
        if self.config_path.read_bytes() != self._rules(rules):
            raise StateError(f"non-canonical FluxGate firewall file: {self.config_path}")
        return rules

    def _unit(self) -> bytes:
        ownership_guard = (
            '/bin/sh -ec "if rules=$$(/usr/sbin/nft list table inet fluxgate '
            '2>/dev/null); then case \\"$$rules\\" in '
            "*fluxgate-managed*chain*postrouting*fluxgate-managed*) "
            "/usr/sbin/nft delete table inet fluxgate ;; "
            '*) echo refusing-to-delete-unmanaged-inet-fluxgate >&2; exit 1 ;; esac; fi"'
        )
        return (
            self.FILE_HEADER
            + (
                "[Unit]\n"
                "Description=FluxGate firewall rules\n"
                "After=nftables.service network-pre.target\n"
                "Before=network.target\n\n"
                "[Service]\n"
                "Type=oneshot\n"
                "RemainAfterExit=yes\n"
                f"ExecStartPre={ownership_guard}\n"
                f"ExecStart=/usr/sbin/nft -f {self.config_path}\n"
                f"ExecStop={ownership_guard}\n\n"
                "[Install]\n"
                "WantedBy=multi-user.target\n"
            ).encode()
        )

    def _is_enabled(self) -> bool:
        return (
            self.runner.run(
                ["systemctl", "is-enabled", "--quiet", self.UNIT], check=False
            ).returncode
            == 0
        )

    def _is_active(self) -> bool:
        return (
            self.runner.run(
                ["systemctl", "is-active", "--quiet", self.UNIT], check=False
            ).returncode
            == 0
        )

    def configured(self, owner: str, source_cidr: str, outbound_interface: str | None) -> bool:
        owner = self._validated_owner(owner)
        expected = self._validated_rule(source_cidr, outbound_interface)
        rules = self._configured_rules()
        files_match = (
            self.config_path.exists()
            and rules.get(owner) == expected
            and self.unit_path.exists()
            and self.unit_path.read_bytes() == self._unit()
        )
        if not files_match:
            return False
        live = self._live()
        network, outbound_interface = expected
        return (
            self._owned_live(live)
            and network in live.stdout
            and (outbound_interface is None or outbound_interface in live.stdout)
            and self._is_enabled()
            and self._is_active()
        )

    def _snapshot(self) -> FirewallCheckpoint:
        self._configured_rules()
        live = self._live()
        if live.returncode == 0 and not self._owned_live(live):
            raise StateError(f"refusing to modify unmanaged nftables table: inet {self.TABLE}")
        return FirewallCheckpoint(
            config=self.config_path.read_bytes() if self.config_path.exists() else None,
            unit=self.unit_path.read_bytes() if self.unit_path.exists() else None,
            live_rules=live.stdout if live.returncode == 0 else None,
            service_enabled=self._is_enabled(),
            service_active=self._is_active(),
        )

    def checkpoint(self) -> object:
        return self._snapshot()

    def managed(self, owner: str | None = None) -> bool:
        rules = self._configured_rules()
        if owner is not None:
            return self._validated_owner(owner) in rules
        checkpoint = self._snapshot()
        return (
            checkpoint.config is not None
            or checkpoint.unit is not None
            or checkpoint.live_rules is not None
        )

    def _delete_owned_live(self) -> None:
        live = self._live()
        if live.returncode == 0:
            if not self._owned_live(live):
                raise StateError(f"refusing to delete unmanaged nftables table: inet {self.TABLE}")
            self.runner.run(["nft", "delete", "table", "inet", self.TABLE], mutate=True)

    def restore(self, checkpoint: object) -> None:
        if not isinstance(checkpoint, FirewallCheckpoint):
            raise TypeError("invalid firewall checkpoint")
        self._assert_owned_files()
        if self.unit_path.exists() or self._is_enabled() or self._is_active():
            self.runner.run(["systemctl", "disable", "--now", self.UNIT], mutate=True)
        self._delete_owned_live()
        if checkpoint.config is None:
            self.config_path.unlink(missing_ok=True)
        else:
            atomic_write(self.config_path, checkpoint.config, 0o644)
        if checkpoint.unit is None:
            self.unit_path.unlink(missing_ok=True)
        else:
            atomic_write(self.unit_path, checkpoint.unit, 0o644)
        self.runner.run(["systemctl", "daemon-reload"], mutate=True)
        if checkpoint.service_enabled:
            self.runner.run(["systemctl", "enable", self.UNIT], mutate=True)
        if (
            checkpoint.service_active
            and checkpoint.config is not None
            and checkpoint.unit is not None
        ):
            self.runner.run(["systemctl", "start", self.UNIT], mutate=True)
        elif checkpoint.live_rules is not None:
            self.runner.run(["nft", "-f", "-"], input_text=checkpoint.live_rules, mutate=True)

    def ensure_nat(self, owner: str, source_cidr: str, outbound_interface: str | None) -> bool:
        owner = self._validated_owner(owner)
        desired_rule = self._validated_rule(source_cidr, outbound_interface)
        if self.configured(owner, source_cidr, outbound_interface):
            return False
        checkpoint = self._snapshot()
        rules = self._configured_rules()
        rules[owner] = desired_rule
        try:
            self._delete_owned_live()
            atomic_write(self.config_path, self._rules(rules), 0o644)
            atomic_write(self.unit_path, self._unit(), 0o644)
            self.runner.run(["systemctl", "daemon-reload"], mutate=True)
            self.runner.run(["systemctl", "enable", self.UNIT], mutate=True)
            self.runner.run(["systemctl", "restart", self.UNIT], mutate=True)
        except BaseException as error:
            try:
                self.restore(checkpoint)
            except BaseException as rollback_error:
                raise StateError(
                    f"firewall update failed: {error}; rollback failed: {rollback_error}"
                ) from error
            raise
        return True

    def remove_nat(self, owner: str) -> bool:
        owner = self._validated_owner(owner)
        rules = self._configured_rules()
        if owner not in rules:
            return False
        checkpoint = self._snapshot()
        del rules[owner]
        try:
            self.runner.run(["systemctl", "disable", "--now", self.UNIT], mutate=True)
            self._delete_owned_live()
            if rules:
                atomic_write(self.config_path, self._rules(rules), 0o644)
                atomic_write(self.unit_path, self._unit(), 0o644)
                self.runner.run(["systemctl", "daemon-reload"], mutate=True)
                self.runner.run(["systemctl", "enable", "--now", self.UNIT], mutate=True)
            else:
                self.config_path.unlink(missing_ok=True)
                self.unit_path.unlink(missing_ok=True)
                self.runner.run(["systemctl", "daemon-reload"], mutate=True)
        except BaseException as error:
            try:
                self.restore(checkpoint)
            except BaseException as rollback_error:
                raise StateError(
                    f"firewall rule removal failed: {error}; rollback failed: {rollback_error}"
                ) from error
            raise
        return True

    def remove(self) -> bool:
        checkpoint = self._snapshot()
        owned_files = checkpoint.config is not None or checkpoint.unit is not None
        if not owned_files and checkpoint.live_rules is None:
            return False
        try:
            if owned_files or checkpoint.live_rules is not None:
                self.runner.run(["systemctl", "disable", "--now", self.UNIT], mutate=True)
            self._delete_owned_live()
            if checkpoint.config is not None:
                self.config_path.unlink()
            if checkpoint.unit is not None:
                self.unit_path.unlink()
            self.runner.run(["systemctl", "daemon-reload"], mutate=True)
        except BaseException as error:
            try:
                self.restore(checkpoint)
            except BaseException as rollback_error:
                raise StateError(
                    f"firewall removal failed: {error}; rollback failed: {rollback_error}"
                ) from error
            raise
        return True
