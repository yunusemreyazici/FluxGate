"""Client lifecycle commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from fluxgate.application import build_application
from fluxgate.cli.common import fail, require_root, safe_client
from fluxgate.core.errors import FluxGateError

client_app = typer.Typer(help="Manage provider-independent clients.", no_args_is_help=True)


@client_app.command("list")
def client_list() -> None:
    """List clients without credential material."""
    try:
        clients = build_application().clients.list()
        if not clients:
            typer.echo("No clients.")
        for client in clients:
            state = "enabled" if client.provider_credentials else "unprovisioned"
            typer.echo(f"{client.id}  {client.name:<20} {state}")
    except FluxGateError as error:
        fail(error)


@client_app.command("add")
def client_add(name: Annotated[str, typer.Argument(help="Unique display name.")]) -> None:
    """Create a provider-independent client identity."""
    try:
        application = build_application()
        require_root(application)
        client = application.clients.add(name)
        typer.echo(json.dumps(safe_client(client), indent=2))
    except (FluxGateError, ValueError) as error:
        fail(error)


@client_app.command("enable")
def client_enable(
    identity: Annotated[str, typer.Argument(help="Client name or UUID.")],
    provider: Annotated[str, typer.Argument(help="Provider to provision.")],
) -> None:
    """Provision one provider for an existing client identity."""
    try:
        application = build_application()
        require_root(application)
        client = application.clients.enable_provider(identity, provider)
        typer.echo(json.dumps(safe_client(client), indent=2))
    except FluxGateError as error:
        fail(error)


@client_app.command("disable")
def client_disable(
    identity: Annotated[str, typer.Argument(help="Client name or UUID.")],
    provider: Annotated[str, typer.Argument(help="Provider to revoke.")],
) -> None:
    """Revoke one provider without changing the client's other providers."""
    try:
        application = build_application()
        require_root(application)
        client = application.clients.disable_provider(identity, provider)
        typer.echo(json.dumps(safe_client(client), indent=2))
    except FluxGateError as error:
        fail(error)


@client_app.command("export")
def client_export(
    identity: Annotated[str, typer.Argument(help="Client name or UUID.")],
    provider: Annotated[
        str | None, typer.Option("--provider", help="Export only one provisioned provider.")
    ] = None,
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Parent directory for the client export tree.")
    ] = Path("."),
) -> None:
    """Write provider exports without printing credential material."""
    try:
        application = build_application()
        require_root(application)
        paths = application.clients.export(identity, output, provider)
        for path in paths:
            typer.echo(f"Exported {path}")
    except FluxGateError as error:
        fail(error)


@client_app.command("show")
def client_show(identity: Annotated[str, typer.Argument(help="Client name or UUID.")]) -> None:
    """Show a client without secrets."""
    try:
        typer.echo(json.dumps(safe_client(build_application().clients.find(identity)), indent=2))
    except FluxGateError as error:
        fail(error)


@client_app.command("revoke")
def client_revoke(identity: Annotated[str, typer.Argument(help="Client name or UUID.")]) -> None:
    """Revoke all provider credentials for a client."""
    try:
        application = build_application()
        require_root(application)
        client = application.clients.revoke(identity)
        typer.echo(f"Revoked {client.name}")
    except FluxGateError as error:
        fail(error)


@client_app.command("delete")
def client_delete(identity: Annotated[str, typer.Argument(help="Client name or UUID.")]) -> None:
    """Revoke and permanently delete a client record."""
    try:
        application = build_application()
        require_root(application)
        deleted = application.clients.delete(identity)
        typer.echo(f"Deleted {deleted}")
    except FluxGateError as error:
        fail(error)
