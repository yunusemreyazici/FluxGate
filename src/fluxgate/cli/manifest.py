"""Capability manifest commands."""

from pathlib import Path
from typing import Annotated

import typer

from fluxgate.application import build_application
from fluxgate.cli.common import fail, require_root
from fluxgate.core.errors import FluxGateError
from fluxgate.core.manifest import render_manifest
from fluxgate.core.state import atomic_write
from fluxgate.manifest import verify_signed_manifest
from fluxgate.manifest.service import load_trust

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


@manifest_app.command("export-signed")
def manifest_export_signed(
    output: Annotated[Path, typer.Option("--output", "-o", help="Managed output directory.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Export manifest.json, manifest.sig and public trust.json atomically."""
    try:
        application = build_application(dry_run=dry_run)
        require_root(application, dry_run=dry_run)
        paths = application.signed_manifests.export(output, dry_run=dry_run)
        prefix = "Dry-run: would create" if dry_run else "Created"
        typer.echo(f"{prefix} signed manifest directory {output} ({len(paths)} files)")
    except FluxGateError as error:
        fail(error)


@manifest_app.command("verify")
def manifest_verify(
    directory: Annotated[Path, typer.Argument(help="Signed manifest directory.")],
    pinned_trust: Annotated[
        Path | None,
        typer.Option("--pinned-trust", help="Previously pinned trust.json descriptor."),
    ] = None,
) -> None:
    """Verify signed metadata using bundled initial or explicitly pinned trust."""
    try:
        trust = load_trust(pinned_trust) if pinned_trust is not None else None
        manifest = verify_signed_manifest(directory, trust)
        typer.echo(
            f"Manifest verified ({'pinned' if trust is not None else 'initial-offline'}): "
            f"{len(manifest.candidates)} candidates"
        )
    except FluxGateError as error:
        fail(error)
