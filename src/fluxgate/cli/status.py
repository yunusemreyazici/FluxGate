"""Top-level version and status commands."""

import typer

from fluxgate import __version__
from fluxgate.application import build_application
from fluxgate.cli.common import fail
from fluxgate.core.errors import FluxGateError
from fluxgate.system.os import detect_os


def version_command() -> None:
    """Print the FluxGate version."""
    typer.echo(__version__)


def status_command() -> None:
    """Show a secret-free system summary."""
    try:
        application = build_application()
        operating_system = detect_os()
        clients = application.clients.list()
        statuses = [provider.status() for provider in application.providers.all()]
        overall = (
            "degraded"
            if any(status.state.value in {"stopped", "degraded"} for status in statuses)
            else "healthy"
        )
        typer.echo("FluxGate\n")
        typer.echo(f"Version      {__version__}")
        typer.echo(f"Host         {application.config.server.domain or '(not configured)'}")
        typer.echo(f"OS           {operating_system.pretty_name}")
        typer.echo(f"State        {overall}")
        typer.echo("\nCORES")
        for provider, status in zip(application.providers.all(), statuses, strict=True):
            typer.echo(f"{provider.display_name:<13}{status.state.value}")
        typer.echo("\nCLIENTS")
        typer.echo(f"Total        {len(clients)}")
        typer.echo(f"Enabled      {sum(client.enabled for client in clients)}")
    except FluxGateError as error:
        fail(error)
