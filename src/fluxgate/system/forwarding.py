"""Controlled IP forwarding configuration."""

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

    def configured(self) -> bool:
        desired = b"# Managed by FluxGate\nnet.ipv4.ip_forward = 1\n"
        return (
            self.config_path.exists()
            and not self.config_path.is_symlink()
            and self.config_path.read_bytes() == desired
        )

    def ensure(self) -> bool:
        desired = b"# Managed by FluxGate\nnet.ipv4.ip_forward = 1\n"
        if self.config_path.is_symlink():
            raise StateError(f"refusing to use symlink forwarding file: {self.config_path}")
        existing = self.config_path.read_bytes() if self.config_path.exists() else None
        if existing is not None and existing != desired:
            raise StateError(f"refusing to replace unmanaged forwarding file: {self.config_path}")
        if existing == desired and self.enabled():
            return False
        atomic_write(self.config_path, desired, mode=0o644)
        if self.enabled():
            return True
        try:
            self.runner.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], mutate=True)
        except BaseException:
            if existing is None:
                self.config_path.unlink(missing_ok=True)
            raise
        return True

    def checkpoint(self) -> ForwardingCheckpoint:
        if self.config_path.is_symlink():
            raise StateError(f"refusing to use symlink forwarding file: {self.config_path}")
        config = self.config_path.read_bytes() if self.config_path.exists() else None
        desired = b"# Managed by FluxGate\nnet.ipv4.ip_forward = 1\n"
        if config is not None and config != desired:
            raise StateError(f"refusing to modify unmanaged forwarding file: {self.config_path}")
        return ForwardingCheckpoint(config=config, enabled=self.enabled())

    def restore(self, checkpoint: ForwardingCheckpoint) -> None:
        if checkpoint.config is None:
            self.config_path.unlink(missing_ok=True)
        else:
            atomic_write(self.config_path, checkpoint.config, 0o644)
        if self.enabled() != checkpoint.enabled:
            value = "1" if checkpoint.enabled else "0"
            self.runner.run(["sysctl", "-w", f"net.ipv4.ip_forward={value}"], mutate=True)

    def remove(self) -> bool:
        desired = b"# Managed by FluxGate\nnet.ipv4.ip_forward = 1\n"
        if self.config_path.is_symlink():
            raise StateError(f"refusing to remove symlink forwarding file: {self.config_path}")
        if not self.config_path.exists():
            return False
        if self.config_path.read_bytes() != desired:
            raise StateError(f"refusing to remove unmanaged forwarding file: {self.config_path}")
        self.config_path.unlink()
        return True
