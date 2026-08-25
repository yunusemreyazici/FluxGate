"""Shared CLI-boundary helpers."""

from __future__ import annotations

import os
from typing import Any, NoReturn

import typer

from fluxgate.application import Application
from fluxgate.core.errors import FluxGateError
from fluxgate.core.models import Client
from fluxgate.system.os import detect_os


def fail(error: Exception) -> NoReturn:
    typer.echo(f"Error: {error}", err=True)
    raise typer.Exit(1)


def require_root(application: Application, *, dry_run: bool = False) -> None:
    if (
        not dry_run
        and os.geteuid() != 0
        and application.paths.config_dir.as_posix() == "/etc/fluxgate"
    ):
        raise FluxGateError("this operation modifies the host and must be run as root")


def require_supported_host(*, dry_run: bool = False) -> None:
    operating_system = detect_os()
    if not dry_run and not operating_system.supported:
        raise FluxGateError(
            f"unsupported operating system: {operating_system.pretty_name}; "
            "supported: Ubuntu 22.04/24.04 and Debian 12"
        )


def safe_client(client: Client) -> dict[str, Any]:
    return {
        "id": str(client.id),
        "name": client.name,
        "created_at": client.created_at.isoformat(),
        "enabled": client.enabled,
        "expires_at": client.expires_at.isoformat() if client.expires_at else None,
        "metadata": client.metadata,
        "providers": sorted(client.provider_credentials),
    }
