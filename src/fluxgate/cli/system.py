"""Host information commands."""

import typer

from fluxgate.system.os import detect_os

system_app = typer.Typer(help="Inspect the host system.", no_args_is_help=True)


@system_app.command("info")
def system_info() -> None:
    """Show detected operating-system support."""
    operating_system = detect_os()
    typer.echo(f"OS: {operating_system.pretty_name}")
    typer.echo(f"Architecture: {operating_system.architecture}")
    typer.echo(f"Supported: {'yes' if operating_system.supported else 'no'}")
