"""Service manager abstraction."""

from __future__ import annotations

from typing import Protocol

from fluxgate.core.commands import CommandRunner


class ServiceManager(Protocol):
    def is_active(self, unit: str) -> bool: ...

    def enable_now(self, unit: str) -> None: ...

    def disable_now(self, unit: str) -> None: ...

    def reload(self, unit: str) -> None: ...


class SystemdServiceManager:
    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner

    def is_active(self, unit: str) -> bool:
        return (
            self.runner.run(["systemctl", "is-active", "--quiet", unit], check=False).returncode
            == 0
        )

    def enable_now(self, unit: str) -> None:
        self.runner.run(["systemctl", "enable", "--now", unit], mutate=True)

    def disable_now(self, unit: str) -> None:
        self.runner.run(["systemctl", "disable", "--now", unit], mutate=True)

    def reload(self, unit: str) -> None:
        self.runner.run(["systemctl", "reload-or-restart", unit], mutate=True)
