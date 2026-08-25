"""Package manager abstraction."""

from __future__ import annotations

import hashlib
import io
import platform
import tarfile
import urllib.request
from pathlib import Path
from typing import Protocol

from fluxgate.core.commands import CommandRunner
from fluxgate.core.errors import ProviderError
from fluxgate.core.state import atomic_write

SING_BOX_VERSION = "1.13.19"
SING_BOX_ASSETS = {
    "x86_64": (
        "amd64",
        "ef88a9e577d474210867bd708933d042e9b70106529df2656182c9db90106aa1",
    ),
    "aarch64": (
        "arm64",
        "7fe3597a95a3c5ad67477b1d7653b9ce097e0be7c676758eba1fcf558f353d57",
    ),
}


class PackageManager(Protocol):
    def install(self, packages: list[str]) -> bool: ...

    def acquire_sing_box(self, destination: Path) -> bool: ...


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

    def acquire_sing_box(self, destination: Path) -> bool:
        """Install a pinned official release artifact after GitHub-published SHA-256 check."""
        if destination.exists():
            return False
        machine = platform.machine().lower()
        if machine not in SING_BOX_ASSETS:
            raise ProviderError(f"unsupported sing-box architecture: {machine}")
        architecture, expected = SING_BOX_ASSETS[machine]
        filename = f"sing-box-{SING_BOX_VERSION}-linux-{architecture}.tar.gz"
        url = (
            f"https://github.com/SagerNet/sing-box/releases/download/v{SING_BOX_VERSION}/{filename}"
        )
        try:
            # The URL is a constant official HTTPS origin assembled only from pinned constants.
            with urllib.request.urlopen(url, timeout=120) as response:
                archive = response.read(100 * 1024 * 1024 + 1)
        except OSError as error:
            raise ProviderError(
                "unable to download the pinned official sing-box release"
            ) from error
        if len(archive) > 100 * 1024 * 1024:
            raise ProviderError("sing-box release artifact exceeds the safety limit")
        actual = hashlib.sha256(archive).hexdigest()
        if actual != expected:
            raise ProviderError("sing-box release checksum verification failed")
        try:
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
                expected_member = f"sing-box-{SING_BOX_VERSION}-linux-{architecture}/sing-box"
                member = bundle.getmember(expected_member)
                if not member.isfile() or member.size > 100 * 1024 * 1024:
                    raise ProviderError("invalid sing-box release archive member")
                source = bundle.extractfile(member)
                if source is None:
                    raise ProviderError("sing-box release archive has no executable")
                executable = source.read(100 * 1024 * 1024 + 1)
        except (KeyError, tarfile.TarError, OSError) as error:
            raise ProviderError("invalid sing-box release archive") from error
        if len(executable) > 100 * 1024 * 1024:
            raise ProviderError("sing-box executable exceeds the safety limit")
        atomic_write(destination, executable, 0o755)
        return True
