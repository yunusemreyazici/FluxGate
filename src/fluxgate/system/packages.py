"""Package manager abstraction."""

from __future__ import annotations

from typing import Protocol

from fluxgate.core.commands import CommandRunner


class PackageManager(Protocol):
    def install(self, packages: list[str]) -> bool: ...


class AptPackageManager:
    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner

    def install(self, packages: list[str]) -> bool:
        if not packages:
            return False
        self.runner.run(["apt-get", "update"], mutate=True, timeout=300.0)
        self.runner.run(
            ["apt-get", "install", "-y", "--no-install-recommends", *packages],
            mutate=True,
            timeout=300.0,
        )
        return True
