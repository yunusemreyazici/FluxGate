"""Service manager abstraction."""

from __future__ import annotations

from typing import Protocol

from fluxgate.core.commands import CommandRunner
from fluxgate.core.errors import StateError


class ServiceManager(Protocol):
    def is_active(self, unit: str) -> bool: ...

    def is_enabled(self, unit: str) -> bool: ...

    def enable_now(self, unit: str) -> None: ...

    def disable_now(self, unit: str) -> None: ...

    def reload(self, unit: str) -> None: ...

    def restart(self, unit: str) -> None: ...

    def restore(self, unit: str, *, enabled: bool, active: bool) -> None: ...

    def daemon_reload(self) -> None: ...


class SystemdServiceManager:
    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner

    def is_active(self, unit: str) -> bool:
        return (
            self.runner.run(["systemctl", "is-active", "--quiet", unit], check=False).returncode
            == 0
        )

    def is_enabled(self, unit: str) -> bool:
        return (
            self.runner.run(["systemctl", "is-enabled", "--quiet", unit], check=False).returncode
            == 0
        )

    def restore(self, unit: str, *, enabled: bool, active: bool) -> None:
        self.runner.run(
            ["systemctl", "enable" if enabled else "disable", unit],
            mutate=True,
        )
        self.runner.run(
            ["systemctl", "start" if active else "stop", unit],
            mutate=True,
        )

    def enable_now(self, unit: str) -> None:
        enabled, active = self.is_enabled(unit), self.is_active(unit)
        try:
            self.runner.run(["systemctl", "enable", "--now", unit], mutate=True)
            if not self.is_enabled(unit) or not self.is_active(unit):
                raise StateError(f"{unit} did not become enabled and active")
        except BaseException as error:
            try:
                self.restore(unit, enabled=enabled, active=active)
            except BaseException as rollback_error:
                raise StateError(
                    f"failed to enable {unit}: {error}; rollback failed: {rollback_error}"
                ) from error
            raise

    def disable_now(self, unit: str) -> None:
        enabled, active = self.is_enabled(unit), self.is_active(unit)
        try:
            self.runner.run(["systemctl", "disable", "--now", unit], mutate=True)
            if self.is_enabled(unit) or self.is_active(unit):
                raise StateError(f"{unit} did not become disabled and inactive")
        except BaseException as error:
            try:
                self.restore(unit, enabled=enabled, active=active)
            except BaseException as rollback_error:
                raise StateError(
                    f"failed to disable {unit}: {error}; rollback failed: {rollback_error}"
                ) from error
            raise

    def reload(self, unit: str) -> None:
        self.runner.run(["systemctl", "reload-or-restart", unit], mutate=True)

    def restart(self, unit: str) -> None:
        # Rapid reconciliations and a failed start can exhaust systemd's StartLimitBurst.
        # Clearing only this managed unit's counter keeps retry and rollback deterministic.
        self.runner.run(["systemctl", "reset-failed", unit], mutate=True)
        self.runner.run(["systemctl", "restart", unit], mutate=True)
        if not self.is_active(unit):
            raise StateError(f"{unit} did not become active after restart")

    def daemon_reload(self) -> None:
        self.runner.run(["systemctl", "daemon-reload"], mutate=True)
