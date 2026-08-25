"""Controlled IP forwarding configuration."""

from pathlib import Path

from fluxgate.core.commands import CommandRunner
from fluxgate.core.errors import StateError
from fluxgate.core.state import atomic_write


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

    def remove(self) -> bool:
        desired = b"# Managed by FluxGate\nnet.ipv4.ip_forward = 1\n"
        if not self.config_path.exists() or self.config_path.read_bytes() != desired:
            return False
        self.config_path.unlink()
        return True
