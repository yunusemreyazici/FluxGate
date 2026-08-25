"""Configuration commands."""

import typer

from fluxgate.application import build_application
from fluxgate.cli.common import fail
from fluxgate.core.errors import FluxGateError

config_app = typer.Typer(help="Inspect and validate FluxGate configuration.", no_args_is_help=True)


@config_app.command("show")
def config_show() -> None:
    """Show effective, secret-free configuration."""
    try:
        typer.echo(build_application().config.as_toml(), nl=False)
    except FluxGateError as error:
        fail(error)


@config_app.command("validate")
def config_validate() -> None:
    """Strictly validate the configured TOML file."""
    try:
        application = build_application()
        typer.echo(f"Valid: {application.paths.config_file}")
    except FluxGateError as error:
        fail(error)
