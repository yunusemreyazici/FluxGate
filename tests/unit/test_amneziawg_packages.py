from __future__ import annotations

import hashlib
import io
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

from fluxgate.core.commands import CommandResult
from fluxgate.core.errors import ProviderError
from fluxgate.system import packages as package_module
from fluxgate.system.packages import AptPackageManager


class Response(io.BytesIO):
    def __init__(self, content: bytes, url: str) -> None:
        super().__init__(content)
        self.url = url

    def geturl(self) -> str:
        return self.url

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class BuildRunner:
    def __init__(self) -> None:
        self.environment: dict[str, str] = {}

    def run(self, args, **kwargs):
        command = tuple(args)
        self.environment = dict(kwargs["environment"])
        destination = Path(command[command.index("-o") + 1])
        destination.write_bytes(b"built-amneziawg-go")
        return CommandResult(command, 0)


def _tools_zip() -> bytes:
    output = io.BytesIO()
    root = "ubuntu-22.04-amneziawg-tools"
    with zipfile.ZipFile(output, mode="w") as bundle:
        bundle.writestr(f"{root}/", b"")
        bundle.writestr(f"{root}/awg", b"awg")
        bundle.writestr(f"{root}/awg.sha256", b"x")
        bundle.writestr(f"{root}/awg-quick", b"awg-quick")
        bundle.writestr(f"{root}/awg-quick.sha256", b"y")
    return output.getvalue()


def _tar(root: str, files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as bundle:
        directory = tarfile.TarInfo(root)
        directory.type = tarfile.DIRTYPE
        bundle.addfile(directory)
        for name, content in files.items():
            member = tarfile.TarInfo(f"{root}/{name}")
            member.size = len(content)
            bundle.addfile(member, io.BytesIO(content))
    return output.getvalue()


def test_pinned_amneziawg_acquisition_is_atomic_and_build_cache_is_isolated(
    tmp_path: Path, monkeypatch
) -> None:
    tools = _tools_zip()
    go = _tar("go", {"bin/go": b"go"})
    source_root = f"amneziawg-go-{package_module.AWG_GO_COMMIT}"
    source = _tar(source_root, {"go.mod": b"module test\n", "main.go": b"package main\n"})
    responses = iter(
        (
            Response(tools, "https://github.com/amnezia/tools.zip"),
            Response(go, "https://go.dev/go.tar.gz"),
            Response(source, "https://codeload.github.com/amnezia/go.tar.gz"),
        )
    )
    monkeypatch.setattr(package_module.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(
        package_module, "AWG_TOOLS_LINUX_AMD64_SHA256", hashlib.sha256(tools).hexdigest()
    )
    monkeypatch.setitem(
        package_module.GO_ARCHIVES,
        "x86_64",
        ("amd64", hashlib.sha256(go).hexdigest()),
    )
    monkeypatch.setattr(
        package_module.urllib.request, "urlopen", lambda url, timeout: next(responses)
    )
    runner = BuildRunner()
    manager = AptPackageManager(runner)  # type: ignore[arg-type]
    awg = tmp_path / "managed" / "awg"
    quick = tmp_path / "managed" / "awg-quick"
    userspace = tmp_path / "managed" / "amneziawg-go"
    assert manager.acquire_amneziawg(awg, quick, userspace)
    assert awg.read_bytes() == b"awg"
    assert quick.read_bytes() == b"awg-quick"
    assert userspace.read_bytes() == b"built-amneziawg-go"
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o755 for path in (awg, quick, userspace))
    assert "fluxgate-amneziawg-build-" in runner.environment["GOCACHE"]
    assert "fluxgate-amneziawg-build-" in runner.environment["GOMODCACHE"]
    assert runner.environment["GOTOOLCHAIN"] == "local"


def test_amneziawg_acquisition_rejects_partial_foreign_install(
    tmp_path: Path,
) -> None:
    awg = tmp_path / "awg"
    awg.write_bytes(b"foreign")
    with pytest.raises(ProviderError, match="partial or foreign"):
        AptPackageManager(BuildRunner()).acquire_amneziawg(
            awg, tmp_path / "awg-quick", tmp_path / "amneziawg-go"
        )


def test_safe_tar_rejects_links_and_traversal(tmp_path: Path) -> None:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as bundle:
        member = tarfile.TarInfo("go/../escape")
        member.size = 1
        bundle.addfile(member, io.BytesIO(b"x"))
    with pytest.raises(ProviderError, match="unsafe member"):
        package_module._safe_tar_extract(output.getvalue(), tmp_path, expected_root="go")


def test_safe_tar_preserves_only_executable_mode(tmp_path: Path) -> None:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as bundle:
        root = tarfile.TarInfo("go")
        root.type = tarfile.DIRTYPE
        root.mode = 0o775
        bundle.addfile(root)
        for name, mode in (("bin/go", 0o755), ("VERSION", 0o664)):
            content = name.encode()
            member = tarfile.TarInfo(f"go/{name}")
            member.mode = mode
            member.size = len(content)
            bundle.addfile(member, io.BytesIO(content))

    package_module._safe_tar_extract(output.getvalue(), tmp_path, expected_root="go")

    assert stat.S_IMODE((tmp_path / "go").stat().st_mode) == 0o755
    assert stat.S_IMODE((tmp_path / "go/bin/go").stat().st_mode) == 0o755
    assert stat.S_IMODE((tmp_path / "go/VERSION").stat().st_mode) == 0o644
