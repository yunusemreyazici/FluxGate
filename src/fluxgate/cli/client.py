"""Client lifecycle commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from fluxgate.application import build_application
from fluxgate.bootstrap import verify_bootstrap
from fluxgate.cli.common import fail, require_root, safe_client
from fluxgate.core.errors import FluxGateError
from fluxgate.manifest.service import load_trust

client_app = typer.Typer(help="Manage provider-independent clients.", no_args_is_help=True)


@client_app.command("bootstrap")
def client_bootstrap(
    identity: Annotated[str, typer.Argument(help="Client name or UUID.")],
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Parent directory for the bootstrap bundle.")
    ] = Path("."),
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Create an authenticated, transactional multi-provider bootstrap bundle."""
    try:
        application = build_application(dry_run=dry_run)
        require_root(application, dry_run=dry_run)
        path = application.bootstrap.export(identity, output, dry_run=dry_run)
        prefix = "Dry-run: would create" if dry_run else "Created"
        typer.echo(f"{prefix} bootstrap bundle {path}")
    except FluxGateError as error:
        fail(error)


@client_app.command("bootstrap-verify")
def client_bootstrap_verify(
    bundle: Annotated[Path, typer.Argument(help="Bootstrap bundle directory.")],
    pinned_trust: Annotated[
        Path | None,
        typer.Option("--pinned-trust", help="Previously pinned trust.json descriptor."),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit secret-free JSON.")] = False,
) -> None:
    """Verify exact signatures and every declared provider artifact."""
    try:
        trust = load_trust(pinned_trust) if pinned_trust is not None else None
        result = verify_bootstrap(bundle, pinned_trust=trust)
        if json_output:
            typer.echo(result.model_dump_json(indent=2))
        else:
            typer.echo(
                f"Bootstrap verified ({result.trust_mode}): "
                f"{result.client_name}, {result.artifact_count} artifacts"
            )
    except FluxGateError as error:
        fail(error)


@client_app.command("list")
def client_list() -> None:
    """List clients without credential material."""
    try:
        clients = build_application().clients.list()
        if not clients:
            typer.echo("No clients.")
        for client in clients:
            state = (
                "enabled"
                if client.provider_credentials or client.profile_credentials
                else "unprovisioned"
            )
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
    provider: Annotated[str | None, typer.Argument(help="Provider to provision.")] = None,
    profile: Annotated[
        str | None, typer.Option("--profile", help="Profile to provision instead of a provider.")
    ] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Provision one provider for an existing client identity."""
    try:
        if (provider is None) == (profile is None):
            raise FluxGateError("specify exactly one provider argument or --profile")
        application = build_application(dry_run=dry_run)
        require_root(application, dry_run=dry_run)
        if dry_run and provider is not None:
            application.clients.find(identity)
            application.providers.get(provider)
            typer.echo("Dry-run: would provision provider credentials without generating them")
            return
        client = (
            application.clients.enable_profile(identity, profile, dry_run=dry_run)
            if profile is not None
            else application.clients.enable_provider(identity, provider or "")
        )
        if dry_run:
            typer.echo("Dry-run: would provision credentials without generating them")
            return
        typer.echo(json.dumps(safe_client(client), indent=2))
    except FluxGateError as error:
        fail(error)


@client_app.command("disable")
def client_disable(
    identity: Annotated[str, typer.Argument(help="Client name or UUID.")],
    provider: Annotated[str | None, typer.Argument(help="Provider to revoke.")] = None,
    profile: Annotated[
        str | None, typer.Option("--profile", help="Profile to revoke instead of a provider.")
    ] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Revoke one provider without changing the client's other providers."""
    try:
        if (provider is None) == (profile is None):
            raise FluxGateError("specify exactly one provider argument or --profile")
        application = build_application(dry_run=dry_run)
        require_root(application, dry_run=dry_run)
        if dry_run and provider is not None:
            client = application.clients.find(identity)
            if provider not in client.provider_credentials:
                raise FluxGateError(f"client {client.name} has no credentials for {provider}")
            typer.echo("Dry-run: would revoke the selected provider credential")
            return
        client = (
            application.clients.disable_profile(identity, profile, dry_run=dry_run)
            if profile is not None
            else application.clients.disable_provider(identity, provider or "")
        )
        if dry_run:
            typer.echo("Dry-run: would revoke the selected credential")
            return
        typer.echo(json.dumps(safe_client(client), indent=2))
    except FluxGateError as error:
        fail(error)


@client_app.command("export")
def client_export(
    identity: Annotated[str, typer.Argument(help="Client name or UUID.")],
    provider: Annotated[
        str | None, typer.Option("--provider", help="Export only one provisioned provider.")
    ] = None,
    profile: Annotated[
        str | None, typer.Option("--profile", help="Export only one provisioned profile.")
    ] = None,
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Parent directory for the client export tree.")
    ] = Path("."),
) -> None:
    """Write provider exports without printing credential material."""
    try:
        application = build_application()
        require_root(application)
        if provider is not None and profile is not None:
            raise FluxGateError("--provider and --profile are mutually exclusive")
        paths = application.clients.export(identity, output, provider, profile)
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
