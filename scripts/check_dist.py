"""Validate that local distribution artifacts have the intended safe shape."""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path


def assert_safe(names: set[str]) -> None:
    forbidden_parts = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".git"}
    forbidden_suffixes = {".key", ".pem", ".ovpn", ".conf.lock"}
    for name in names:
        path = Path(name)
        assert not forbidden_parts.intersection(path.parts), f"local artifact included: {name}"
        assert path.suffix not in forbidden_suffixes, f"secret-like artifact included: {name}"


def main() -> None:
    dist = Path("dist")
    wheels = list(dist.glob("fluxgate-*.whl"))
    sdists = list(dist.glob("fluxgate-*.tar.gz"))
    assert len(wheels) == 1, f"expected one wheel, found {len(wheels)}"
    assert len(sdists) == 1, f"expected one sdist, found {len(sdists)}"

    with zipfile.ZipFile(wheels[0]) as archive:
        wheel_names = set(archive.namelist())
        assert_safe(wheel_names)
        assert "fluxgate/cli/app.py" in wheel_names
        assert not any(name.startswith("tests/") for name in wheel_names)
        metadata_name = next(name for name in wheel_names if name.endswith(".dist-info/METADATA"))
        entry_name = next(
            name for name in wheel_names if name.endswith(".dist-info/entry_points.txt")
        )
        metadata = archive.read(metadata_name).decode()
        entries = archive.read(entry_name).decode()
        assert "License-File: LICENSE" in metadata
        assert "Project-URL: Repository, https://github.com/yunusemreyazici/FluxGate" in metadata
        assert "fluxgate = fluxgate.cli.app:app" in entries

    with tarfile.open(sdists[0], "r:gz") as archive:
        sdist_names = {member.name for member in archive.getmembers()}
        assert_safe(sdist_names)
        assert any(name.endswith("/README.md") for name in sdist_names)
        assert any(name.endswith("/LICENSE") for name in sdist_names)
        assert any(name.endswith("/pyproject.toml") for name in sdist_names)
        assert any(name.endswith("/src/fluxgate/cli/app.py") for name in sdist_names)
        assert any(name.endswith("/tests/unit/test_openvpn.py") for name in sdist_names)

    print(f"Validated {wheels[0].name} and {sdists[0].name}")


if __name__ == "__main__":
    main()
