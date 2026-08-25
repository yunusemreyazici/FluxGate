"""Top-level version and status commands."""

import typer

from fluxgate import __version__
from fluxgate.application import build_application
from fluxgate.cli.common import fail
from fluxgate.core.errors import FluxGateError
from fluxgate.core.models import ProviderStatus
from fluxgate.system.os import detect_os


def version_command() -> None:
    """Print the FluxGate version."""
    typer.echo(__version__)


def overall_state(statuses: list[ProviderStatus]) -> str:
    return (
        "degraded"
        if any(
            status.state.value not in {"disabled", "running", "unsupported"} for status in statuses
        )
        else "healthy"
    )


def status_command() -> None:
    """Show a secret-free system summary."""
    try:
        application = build_application()
        operating_system = detect_os()
        clients = application.clients.list()
        statuses = [provider.status() for provider in application.providers.all()]
        overall = overall_state(statuses)
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
        typer.echo("\nPROFILES")
        profiles = application.profiles.list()
        typer.echo(f"Total        {len(profiles)}")
        typer.echo(f"Enabled      {sum(profile.enabled for profile in profiles)}")
    except FluxGateError as error:
        fail(error)
