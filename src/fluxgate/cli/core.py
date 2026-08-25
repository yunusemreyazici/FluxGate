"""Core-provider commands."""

from typing import Annotated

import typer

from fluxgate.application import build_application
from fluxgate.cli.common import fail, require_root, require_supported_host
from fluxgate.core.errors import FluxGateError

core_app = typer.Typer(help="Manage connectivity cores.", no_args_is_help=True)


@core_app.command("list")
def core_list() -> None:
    """List registered providers and implementation status."""
    try:
        for provider in build_application().providers.all():
            status = provider.status()
            typer.echo(f"{provider.name:<12} {status.state.value:<14} {status.detail}")
    except FluxGateError as error:
        fail(error)


@core_app.command("status")
def core_status(name: Annotated[str | None, typer.Argument(help="Core name.")] = None) -> None:
    """Show status for one core or all cores."""
    try:
        registry = build_application().providers
        providers = (registry.get(name),) if name else registry.all()
        for provider in providers:
            status = provider.status()
            typer.echo(f"{provider.display_name}: {status.state.value} ({status.detail})")
    except FluxGateError as error:
        fail(error)


@core_app.command("enable")
def core_enable(
    name: Annotated[str, typer.Argument(help="Core name.")],
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show intended changes only.")] = False,
) -> None:
    """Converge a core to its enabled state."""
    try:
        application = build_application(dry_run=dry_run)
        require_root(application, dry_run=dry_run)
        require_supported_host(dry_run=dry_run)
        result = application.providers.get(name).enable()
        typer.echo(result.message)
        for action in result.actions:
            typer.echo(f"  {action}")
    except FluxGateError as error:
        fail(error)


@core_app.command("disable")
def core_disable(
    name: Annotated[str, typer.Argument(help="Core name.")],
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show intended changes only.")] = False,
) -> None:
    """Disable a core without deleting client identities."""
    try:
        application = build_application(dry_run=dry_run)
        require_root(application, dry_run=dry_run)
        require_supported_host(dry_run=dry_run)
        result = application.providers.get(name).disable()
        typer.echo(result.message)
        for action in result.actions:
            typer.echo(f"  {action}")
    except FluxGateError as error:
        fail(error)
