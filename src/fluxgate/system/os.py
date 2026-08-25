"""Supported operating-system detection."""

from __future__ import annotations

import platform
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class OperatingSystem:
    identifier: str
    version: str
    pretty_name: str
    architecture: str
    supported: bool


SUPPORTED = {("ubuntu", "22.04"), ("ubuntu", "24.04"), ("debian", "12")}


def detect_os(path: Path = Path("/etc/os-release")) -> OperatingSystem:
    values: dict[str, str] = {}
    try:
        for line in path.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
    except OSError:
        return OperatingSystem(
            identifier=platform.system().lower(),
            version=platform.release(),
            pretty_name=f"{platform.system()} {platform.release()}",
            architecture=platform.machine(),
            supported=False,
        )
    identifier = values.get("ID", "unknown").lower()
    version = values.get("VERSION_ID", "unknown")
    return OperatingSystem(
        identifier=identifier,
        version=version,
        pretty_name=values.get("PRETTY_NAME", f"{identifier} {version}"),
        architecture=platform.machine(),
        supported=(identifier, version) in SUPPORTED,
    )
