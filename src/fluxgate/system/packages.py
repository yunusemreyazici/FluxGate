"""Package manager abstraction."""

from __future__ import annotations

import hashlib
import io
import os
import platform
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Protocol, cast
from urllib.parse import urlparse

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

AWG_TOOLS_VERSION = "3.1.20260812"
AWG_TOOLS_COMMIT = "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"
AWG_GO_VERSION = "3.1.20260814"
AWG_GO_COMMIT = "1b86b2ae0e493e7ea93f8c1a0f0cb6735b1551f1"
AWG_TOOLS_LINUX_AMD64_SHA256 = "919e9d0a367c7c72f9c16b7d0a9e4840b943628353b2210a33cb4b582785ba56"
GO_VERSION = "1.25.0"
GO_ARCHIVES = {
    "x86_64": (
        "amd64",
        "2852af0cb20a13139b3448992e69b868e50ed0f8a1e5940ee1de9e19a123b613",
    ),
    "aarch64": (
        "arm64",
        "05de75d6994a2783699815ee553bd5a9327d8b79991de36e38b66862782f54ae",
    ),
}
DOWNLOAD_LIMIT = 160 * 1024 * 1024


def _download(url: str, *, limit: int = DOWNLOAD_LIMIT) -> bytes:
    if urlparse(url).scheme != "https":
        raise ProviderError("release download URL must use HTTPS")
    try:
        with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310
            if urlparse(response.geturl()).scheme != "https":
                raise ProviderError("release download redirected away from HTTPS")
            content = cast(bytes, response.read(limit + 1))
    except OSError as error:
        raise ProviderError(f"unable to download pinned release object: {url}") from error
    if len(content) > limit:
        raise ProviderError("release artifact exceeds the safety limit")
    return content


def _safe_tar_extract(archive: bytes, destination: Path, *, expected_root: str) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
            members = bundle.getmembers()
            if len(members) > 20_000 or sum(member.size for member in members) > 750 * 1024 * 1024:
                raise ProviderError("release archive expands beyond the safety limit")
            for member in members:
                relative = Path(member.name)
                if (
                    not relative.parts
                    or relative.parts[0] != expected_root
                    or relative.is_absolute()
                    or ".." in relative.parts
                    or member.issym()
                    or member.islnk()
                    or not (member.isdir() or member.isfile())
                ):
                    raise ProviderError("release archive contains an unsafe member")
                target = destination / relative
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    target.chmod(0o755)
                    continue
                source = bundle.extractfile(member)
                if source is None or member.size > DOWNLOAD_LIMIT:
                    raise ProviderError("release archive member is invalid")
                target.parent.mkdir(parents=True, exist_ok=True)
                content = source.read(DOWNLOAD_LIMIT + 1)
                if len(content) != member.size:
                    raise ProviderError("release archive member size does not match metadata")
                target.write_bytes(content)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
    except (OSError, tarfile.TarError) as error:
        raise ProviderError("invalid release archive") from error


class PackageManager(Protocol):
    def install(self, packages: list[str]) -> bool: ...

    def acquire_sing_box(self, destination: Path) -> bool: ...

    def acquire_amneziawg(self, awg: Path, awg_quick: Path, userspace: Path) -> bool: ...


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
                final_url = response.geturl()
                if urlparse(final_url).scheme != "https":
                    raise ProviderError("sing-box release download redirected away from HTTPS")
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

    def acquire_amneziawg(self, awg: Path, awg_quick: Path, userspace: Path) -> bool:
        """Acquire pinned AWG 3.1 tools and build its pinned userspace backend."""
        destinations = (awg, awg_quick, userspace)
        if all(path.exists() for path in destinations):
            return False
        if any(path.exists() or path.is_symlink() for path in destinations):
            raise ProviderError("refusing a partial or foreign managed AmneziaWG installation")
        machine = platform.machine().lower()
        if machine not in GO_ARCHIVES:
            raise ProviderError(f"unsupported AmneziaWG architecture: {machine}")
        if machine != "x86_64":
            raise ProviderError(
                "official AmneziaWG tools 3.1 release has no reviewed arm64 artifact; "
                "arm64 support is deferred"
            )

        tools_name = "ubuntu-22.04-amneziawg-tools.zip"
        tools_url = (
            "https://github.com/amnezia-vpn/amneziawg-tools/releases/download/"
            f"v{AWG_TOOLS_VERSION}/{tools_name}"
        )
        tools_archive = _download(tools_url)
        if hashlib.sha256(tools_archive).hexdigest() != AWG_TOOLS_LINUX_AMD64_SHA256:
            raise ProviderError("AmneziaWG tools release checksum verification failed")
        try:
            with zipfile.ZipFile(io.BytesIO(tools_archive)) as bundle:
                root = "ubuntu-22.04-amneziawg-tools"
                names = set(bundle.namelist())
                expected_names = {
                    f"{root}/",
                    f"{root}/awg",
                    f"{root}/awg.sha256",
                    f"{root}/awg-quick",
                    f"{root}/awg-quick.sha256",
                }
                if names != expected_names:
                    raise ProviderError("unexpected AmneziaWG tools archive inventory")
                awg_content = bundle.read(f"{root}/awg")
                quick_content = bundle.read(f"{root}/awg-quick")
        except (KeyError, OSError, zipfile.BadZipFile) as error:
            raise ProviderError("invalid AmneziaWG tools release archive") from error

        go_arch, go_checksum = GO_ARCHIVES[machine]
        go_name = f"go{GO_VERSION}.linux-{go_arch}.tar.gz"
        go_archive = _download(f"https://go.dev/dl/{go_name}")
        if hashlib.sha256(go_archive).hexdigest() != go_checksum:
            raise ProviderError("official Go toolchain checksum verification failed")

        source_url = f"https://codeload.github.com/amnezia-vpn/amneziawg-go/tar.gz/{AWG_GO_COMMIT}"
        source_archive = _download(source_url)
        source_root = f"amneziawg-go-{AWG_GO_COMMIT}"
        with tempfile.TemporaryDirectory(prefix="fluxgate-amneziawg-build-") as temporary_name:
            temporary = Path(temporary_name)
            _safe_tar_extract(go_archive, temporary, expected_root="go")
            _safe_tar_extract(source_archive, temporary, expected_root=source_root)
            built = temporary / "amneziawg-go"
            go_cache = temporary / "go-build-cache"
            module_cache = temporary / "go-module-cache"
            go_path = temporary / "go-path"
            for directory in (go_cache, module_cache, go_path):
                directory.mkdir(mode=0o700)
            environment = dict(os.environ)
            environment.update(
                {
                    "CGO_ENABLED": "0",
                    "GOCACHE": str(go_cache),
                    "GOMODCACHE": str(module_cache),
                    "GOPATH": str(go_path),
                    "GOTOOLCHAIN": "local",
                    "GOSUMDB": "sum.golang.org",
                    "GOPROXY": "https://proxy.golang.org,direct",
                }
            )
            self.runner.run(
                [
                    str(temporary / "go" / "bin" / "go"),
                    "-C",
                    str(temporary / source_root),
                    "build",
                    "-mod=readonly",
                    "-trimpath",
                    "-buildvcs=false",
                    "-o",
                    str(built),
                    ".",
                ],
                timeout=600.0,
                mutate=True,
                environment=environment,
            )
            if not built.is_file() or built.is_symlink() or built.stat().st_size == 0:
                raise ProviderError("AmneziaWG userspace build produced no safe executable")
            userspace_content = built.read_bytes()

        installed: list[Path] = []
        try:
            for destination, content in (
                (awg, awg_content),
                (awg_quick, quick_content),
                (userspace, userspace_content),
            ):
                atomic_write(destination, content, 0o755)
                installed.append(destination)
        except BaseException:
            for destination in installed:
                destination.unlink(missing_ok=True)
            raise
        return True
