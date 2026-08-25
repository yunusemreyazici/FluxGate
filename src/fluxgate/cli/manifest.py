"""Capability manifest commands."""

from pathlib import Path
from typing import Annotated

import typer

from fluxgate.application import build_application
from fluxgate.cli.common import fail
from fluxgate.core.errors import FluxGateError
from fluxgate.core.manifest import render_manifest
from fluxgate.core.state import atomic_write

manifest_app = typer.Typer(
    help="Inspect the secret-free capability manifest.", no_args_is_help=True
)


@manifest_app.command("show")
def manifest_show() -> None:
    """Print the secret-free manifest as stable JSON."""
    try:
        application = build_application()
        typer.echo(render_manifest(application.config, application.state).decode(), nl=False)
    except FluxGateError as error:
        fail(error)


@manifest_app.command("export")
def manifest_export(
    output: Annotated[Path, typer.Option("--output", "-o", help="Manifest destination.")],
) -> None:
    """Atomically export the secret-free manifest."""
    try:
        application = build_application()
        atomic_write(output, render_manifest(application.config, application.state), 0o644)
        typer.echo(f"Exported {output}")
    except FluxGateError as error:
        fail(error)
