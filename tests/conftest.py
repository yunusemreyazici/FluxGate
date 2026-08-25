from pathlib import Path

import pytest

from fluxgate.core.commands import CommandResult
from fluxgate.core.config import AppConfig
from fluxgate.core.paths import PathLayout
from fluxgate.core.state import StateStore
from fluxgate.providers.base import OperationContext


class FakeRunner:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.key_number = 0

    def run(self, args, **kwargs):
        command = tuple(args)
        self.commands.append(command)
        if command[:4] == ("ip", "link", "show", "dev"):
            return CommandResult(command, 0 if command[-1] == "eth0" else 1)
        if command == ("wg", "genkey"):
            self.key_number += 1
            return CommandResult(command, 0, f"private-{self.key_number}\n")
        if command == ("wg", "pubkey"):
            return CommandResult(command, 0, f"public-{self.key_number}\n")
        if len(command) == 2 and command[1] == "version" and "sing-box" in command[0]:
            return CommandResult(command, 0, "sing-box version 1.13.19\n")
        return CommandResult(command, 0)


class FakePackages:
    def __init__(self) -> None:
        self.installs: list[list[str]] = []

    def install(self, packages: list[str]) -> bool:
        self.installs.append(packages)
        return True

    def acquire_sing_box(self, destination: Path) -> bool:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"fake sing-box")
        destination.chmod(0o755)
        return True


class FakeServices:
    def __init__(self, network) -> None:
        self.network = network
        self.active_units: set[str] = set()
        self.enabled_units: set[str] = set()
        self.events: list[str] = []

    @property
    def active(self) -> bool:
        return "wg-quick@fg0.service" in self.active_units

    @active.setter
    def active(self, value: bool) -> None:
        self._set_active("wg-quick@fg0.service", value)

    @property
    def enabled(self) -> bool:
        return "wg-quick@fg0.service" in self.enabled_units

    @enabled.setter
    def enabled(self, value: bool) -> None:
        if value:
            self.enabled_units.add("wg-quick@fg0.service")
        else:
            self.enabled_units.discard("wg-quick@fg0.service")

    def _interface(self, unit: str) -> str:
        return "fgovpn0" if unit == "openvpn-server@fluxgate.service" else "fg0"

    def _set_active(self, unit: str, active: bool) -> None:
        interface = self._interface(unit)
        if active:
            self.active_units.add(unit)
            self.network.interfaces.add(interface)
            if unit == "openvpn-server@fluxgate.service":
                self.network.listening_ports.add(1194)
        else:
            self.active_units.discard(unit)
            self.network.interfaces.discard(interface)
            if unit == "openvpn-server@fluxgate.service":
                self.network.listening_ports.discard(1194)

    def is_active(self, unit: str) -> bool:
        return unit in self.active_units

    def is_enabled(self, unit: str) -> bool:
        return unit in self.enabled_units

    def enable_now(self, unit: str) -> None:
        self.events.append(f"enable:{unit}")
        self._set_active(unit, True)
        self.enabled_units.add(unit)

    def disable_now(self, unit: str) -> None:
        self.events.append(f"disable:{unit}")
        self._set_active(unit, False)
        self.enabled_units.discard(unit)

    def reload(self, unit: str) -> None:
        self.events.append(f"reload:{unit}")

    def restart(self, unit: str) -> None:
        self.events.append(f"restart:{unit}")
        self._set_active(unit, True)

    def restore(self, unit: str, *, enabled: bool, active: bool) -> None:
        self.events.append(f"restore:{unit}:{enabled}:{active}")
        if enabled:
            self.enabled_units.add(unit)
        else:
            self.enabled_units.discard(unit)
        self._set_active(unit, active)

    def daemon_reload(self) -> None:
        self.events.append("daemon-reload")


class FakeFirewall:
    def __init__(self) -> None:
        self.rules: dict[str, tuple[str, str | None]] = {}

    @property
    def present(self) -> bool:
        return bool(self.rules)

    @present.setter
    def present(self, value: bool) -> None:
        self.rules = {"wireguard": ("10.77.0.0/24", "eth0")} if value else {}

    def ensure_nat(self, owner: str, source_cidr: str, outbound_interface: str | None) -> bool:
        rule = (source_cidr, outbound_interface)
        changed = self.rules.get(owner) != rule
        self.rules[owner] = rule
        return changed

    def configured(self, owner: str, source_cidr: str, outbound_interface: str | None) -> bool:
        return self.rules.get(owner) == (source_cidr, outbound_interface)

    def checkpoint(self) -> object:
        return dict(self.rules)

    def restore(self, checkpoint: object) -> None:
        self.rules = dict(checkpoint)  # type: ignore[arg-type]

    def managed(self, owner: str | None = None) -> bool:
        return bool(self.rules) if owner is None else owner in self.rules

    def remove_nat(self, owner: str) -> bool:
        return self.rules.pop(owner, None) is not None

    def remove(self) -> bool:
        changed = self.present
        self.rules.clear()
        return changed


class FakeForwarding:
    def __init__(self) -> None:
        self.consumers: set[str] = set()

    @property
    def present(self) -> bool:
        return bool(self.consumers)

    @present.setter
    def present(self, value: bool) -> None:
        self.consumers = {"wireguard"} if value else set()

    def enabled(self) -> bool:
        return self.present

    def configured(self, owner: str | None = None) -> bool:
        return bool(self.consumers) if owner is None else owner in self.consumers

    def acquire(self, owner: str) -> bool:
        changed = owner not in self.consumers
        self.consumers.add(owner)
        return changed

    def ensure(self) -> bool:
        return self.acquire("wireguard")

    def checkpoint(self):
        return set(self.consumers)

    def restore(self, checkpoint) -> None:
        self.consumers = set(checkpoint)

    def release(self, owner: str) -> bool:
        if owner not in self.consumers:
            return False
        self.consumers.remove(owner)
        return True

    def remove(self) -> bool:
        return self.release("wireguard")


class FakeNetwork:
    def __init__(self) -> None:
        self.interfaces = {"eth0"}
        self.route_conflict: str | None = None
        self.occupied_ports: set[int] = set()
        self.listening_ports: set[int] = set()

    def interface_exists(self, interface: str) -> bool:
        return interface in self.interfaces

    def conflicting_route(self, network, interface: str) -> str | None:
        return self.route_conflict

    def udp_port_available(
        self,
        port: int,
        address: str = "0.0.0.0",  # noqa: S104
    ) -> bool:
        return port not in self.occupied_ports and port not in self.listening_ports

    def udp_listener_present(self, port: int) -> bool:
        return port in self.listening_ports

    def tcp_port_available(
        self,
        port: int,
        address: str = "0.0.0.0",  # noqa: S104
    ) -> bool:
        return port not in self.occupied_ports and port not in self.listening_ports

    def tcp_listener_present(self, port: int) -> bool:
        return port in self.listening_ports


@pytest.fixture
def provider_context(tmp_path: Path) -> OperationContext:
    paths = PathLayout(
        config_dir=tmp_path / "etc-fluxgate",
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "log",
        wireguard_dir=tmp_path / "wireguard",
        openvpn_dir=tmp_path / "openvpn",
        sysctl_dir=tmp_path / "sysctl",
        nftables_dir=tmp_path / "nftables",
        systemd_dir=tmp_path / "systemd",
        local_lib_dir=tmp_path / "local-lib",
    )
    config = AppConfig.model_validate(
        {"server": {"domain": "vpn.example.com"}, "network": {"outbound_interface": "eth0"}}
    )
    network = FakeNetwork()
    return OperationContext(
        config=config,
        paths=paths,
        state=StateStore(paths.state_file),
        runner=FakeRunner(),  # type: ignore[arg-type]
        packages=FakePackages(),
        services=FakeServices(network),
        firewall=FakeFirewall(),
        forwarding=FakeForwarding(),  # type: ignore[arg-type]
        network=network,
    )
