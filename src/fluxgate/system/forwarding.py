"""Controlled IP forwarding configuration."""

import re
from dataclasses import dataclass
from pathlib import Path

from fluxgate.core.commands import CommandRunner
from fluxgate.core.errors import StateError
from fluxgate.core.state import atomic_write


@dataclass(frozen=True, slots=True)
class ForwardingCheckpoint:
    config: bytes | None
    enabled: bool


class ForwardingManager:
    LEGACY_CONFIG = b"# Managed by FluxGate\nnet.ipv4.ip_forward = 1\n"
    OWNER = re.compile(r"^[a-z][a-z0-9-]{0,31}$")

    def __init__(
        self,
        config_path: Path,
        runner: CommandRunner,
        proc_path: Path = Path("/proc/sys/net/ipv4/ip_forward"),
    ) -> None:
        self.config_path = config_path
        self.runner = runner
        self.proc_path = proc_path

    def enabled(self) -> bool:
        try:
            return self.proc_path.read_text().strip() == "1"
        except OSError:
            return False

    def _validate_owner(self, owner: str) -> None:
        if not self.OWNER.fullmatch(owner):
            raise StateError(f"invalid forwarding owner: {owner}")

    def _desired(self, consumers: set[str]) -> bytes:
        return (
            "# Managed by FluxGate\n"
            f"# Consumers: {', '.join(sorted(consumers))}\n"
            "net.ipv4.ip_forward = 1\n"
        ).encode()

    def _consumers(self) -> set[str]:
        if self.config_path.is_symlink():
            raise StateError(f"refusing to use symlink forwarding file: {self.config_path}")
        if not self.config_path.exists():
            return set()
        existing = self.config_path.read_bytes()
        if existing == self.LEGACY_CONFIG:
            return {"wireguard"}
        try:
            lines = existing.decode().splitlines()
        except UnicodeDecodeError as error:
            raise StateError(
                f"refusing to parse unmanaged forwarding file: {self.config_path}"
            ) from error
        if (
            len(lines) != 3
            or lines[0] != "# Managed by FluxGate"
            or not lines[1].startswith("# Consumers: ")
            or lines[2] != "net.ipv4.ip_forward = 1"
        ):
            raise StateError(f"refusing to replace unmanaged forwarding file: {self.config_path}")
        raw_consumers = lines[1].removeprefix("# Consumers: ")
        consumers = set(raw_consumers.split(", ")) if raw_consumers else set()
        if not consumers or any(not self.OWNER.fullmatch(owner) for owner in consumers):
            raise StateError(f"invalid FluxGate forwarding consumers: {self.config_path}")
        if existing != self._desired(consumers):
            raise StateError(f"non-canonical FluxGate forwarding file: {self.config_path}")
        return consumers

    def configured(self, owner: str | None = None) -> bool:
        consumers = self._consumers()
        if owner is None:
            return bool(consumers)
        self._validate_owner(owner)
        return owner in consumers

    def acquire(self, owner: str) -> bool:
        self._validate_owner(owner)
        consumers = self._consumers()
        if owner in consumers and self.enabled():
            return False
        existing = self.config_path.read_bytes() if self.config_path.exists() else None
        consumers.add(owner)
        atomic_write(self.config_path, self._desired(consumers), mode=0o644)
        if self.enabled():
            return True
        try:
            self.runner.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], mutate=True)
        except BaseException:
            if existing is None:
                self.config_path.unlink(missing_ok=True)
            else:
                atomic_write(self.config_path, existing, 0o644)
            raise
        return True

    def ensure(self) -> bool:
        """Compatibility wrapper for the v0.1 WireGuard consumer."""
        return self.acquire("wireguard")

    def checkpoint(self) -> ForwardingCheckpoint:
        self._consumers()
        config = self.config_path.read_bytes() if self.config_path.exists() else None
        return ForwardingCheckpoint(config=config, enabled=self.enabled())

    def restore(self, checkpoint: ForwardingCheckpoint) -> None:
        if checkpoint.config is None:
            self.config_path.unlink(missing_ok=True)
        else:
            atomic_write(self.config_path, checkpoint.config, 0o644)
        if self.enabled() != checkpoint.enabled:
            value = "1" if checkpoint.enabled else "0"
            self.runner.run(["sysctl", "-w", f"net.ipv4.ip_forward={value}"], mutate=True)

    def release(self, owner: str) -> bool:
        self._validate_owner(owner)
        consumers = self._consumers()
        if owner not in consumers:
            return False
        consumers.remove(owner)
        if consumers:
            atomic_write(self.config_path, self._desired(consumers), 0o644)
        else:
            self.config_path.unlink(missing_ok=True)
        return True

    def remove(self) -> bool:
        """Compatibility wrapper for the v0.1 WireGuard consumer."""
        return self.release("wireguard")
