"""Client lifecycle commands."""

from __future__ import annotations

import json
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
            state = "enabled" if client.enabled else "revoked"
            typer.echo(f"{client.id}  {client.name:<20} {state}")
    except FluxGateError as error:
        fail(error)


@client_app.command("add")
def client_add(name: Annotated[str, typer.Argument(help="Unique display name.")]) -> None:
    """Create a client and credentials for active capable providers."""
    try:
        application = build_application()
        require_root(application)
        client = application.clients.add(name)
        typer.echo(json.dumps(safe_client(client), indent=2))
    except (FluxGateError, ValueError) as error:
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
