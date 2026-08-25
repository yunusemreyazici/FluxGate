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
        return CommandResult(command, 0)


class FakePackages:
    def __init__(self) -> None:
        self.installs: list[list[str]] = []

    def install(self, packages: list[str]) -> bool:
        self.installs.append(packages)
        return True


class FakeServices:
    def __init__(self, network) -> None:
        self.network = network
        self.active = False
        self.enabled = False
        self.events: list[str] = []

    def is_active(self, unit: str) -> bool:
        return self.active

    def is_enabled(self, unit: str) -> bool:
        return self.enabled

    def enable_now(self, unit: str) -> None:
        self.events.append(f"enable:{unit}")
        self.active = True
        self.enabled = True
        self.network.interfaces.add("fg0")

    def disable_now(self, unit: str) -> None:
        self.events.append(f"disable:{unit}")
        self.active = False
        self.enabled = False
        self.network.interfaces.discard("fg0")

    def reload(self, unit: str) -> None:
        self.events.append(f"reload:{unit}")

    def restart(self, unit: str) -> None:
        self.events.append(f"restart:{unit}")
        self.active = True
        self.network.interfaces.add("fg0")

    def restore(self, unit: str, *, enabled: bool, active: bool) -> None:
        self.events.append(f"restore:{unit}:{enabled}:{active}")
        self.enabled = enabled
        self.active = active
        if active:
            self.network.interfaces.add("fg0")
        else:
            self.network.interfaces.discard("fg0")


class FakeFirewall:
    def __init__(self) -> None:
        self.present = False

    def ensure_nat(self, source_cidr: str, outbound_interface: str | None) -> bool:
        changed = not self.present
        self.present = True
        return changed

    def configured(self, source_cidr: str, outbound_interface: str | None) -> bool:
        return self.present

    def checkpoint(self) -> object:
        return self.present

    def restore(self, checkpoint: object) -> None:
        self.present = bool(checkpoint)

    def managed(self) -> bool:
        return self.present

    def remove(self) -> bool:
        changed = self.present
        self.present = False
        return changed


class FakeForwarding:
    def __init__(self) -> None:
        self.present = False

    def enabled(self) -> bool:
        return self.present

    def configured(self) -> bool:
        return self.present

    def ensure(self) -> bool:
        changed = not self.present
        self.present = True
        return changed

    def checkpoint(self):
        return self.present

    def restore(self, checkpoint) -> None:
        self.present = bool(checkpoint)

    def remove(self) -> bool:
        changed = self.present
        self.present = False
        return changed


class FakeNetwork:
    def __init__(self) -> None:
        self.interfaces = {"eth0"}
        self.route_conflict: str | None = None
        self.occupied_ports: set[int] = set()

    def interface_exists(self, interface: str) -> bool:
        return interface in self.interfaces

    def conflicting_route(self, network, interface: str) -> str | None:
        return self.route_conflict

    def udp_port_available(self, port: int) -> bool:
        return port not in self.occupied_ports


@pytest.fixture
def provider_context(tmp_path: Path) -> OperationContext:
    paths = PathLayout(
        config_dir=tmp_path / "etc-fluxgate",
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "log",
        wireguard_dir=tmp_path / "wireguard",
        sysctl_dir=tmp_path / "sysctl",
        nftables_dir=tmp_path / "nftables",
        systemd_dir=tmp_path / "systemd",
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
