"""Connectable profile lifecycle commands."""

from __future__ import annotations

import json
from typing import Annotated

import typer

from fluxgate.application import build_application
from fluxgate.cli.common import fail, require_root, require_supported_host
from fluxgate.core.errors import FluxGateError
from fluxgate.core.models import ProfileDefinition, ProtocolName, SecurityName, TransportName

profile_app = typer.Typer(help="Manage connectable protocol profiles.", no_args_is_help=True)


def safe_profile(profile: ProfileDefinition) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "id": str(profile.id),
            "name": profile.name,
            "provider": profile.provider,
            "protocol": profile.protocol.value,
            "transport": profile.transport.value,
            "security": profile.security.value,
            "listen_address": profile.listen_address,
            "listen_port": profile.listen_port,
            "enabled": profile.enabled,
        },
        indent=2,
    )


@profile_app.command("list")
def profile_list() -> None:
    """List persisted profiles without client credentials."""
    try:
        profiles = build_application().profiles.list()
        if not profiles:
            typer.echo("No profiles.")
        for profile in profiles:
            state = "enabled" if profile.enabled else "disabled"
            typer.echo(
                f"{profile.id}  {profile.name:<20} {profile.provider}/"
                f"{profile.protocol.value}-{profile.transport.value}-{profile.security.value} "
                f"{profile.listen_port}/{profile.socket_protocol.value} {state}"
            )
    except FluxGateError as error:
        fail(error)


@profile_app.command("show")
def profile_show(identity: Annotated[str, typer.Argument(help="Profile name or UUID.")]) -> None:
    """Show secret-free profile metadata."""
    try:
        typer.echo(safe_profile(build_application().profiles.find(identity)))
    except FluxGateError as error:
        fail(error)


@profile_app.command("create")
def profile_create(
    name: Annotated[str, typer.Argument(help="Unique profile name.")],
    provider: Annotated[str, typer.Option("--provider")] = "singbox",
    protocol: Annotated[ProtocolName, typer.Option("--protocol")] = ProtocolName.VLESS,
    transport: Annotated[TransportName, typer.Option("--transport")] = TransportName.TCP,
    security: Annotated[SecurityName, typer.Option("--security")] = SecurityName.TLS,
    port: Annotated[int, typer.Option("--port", min=1, max=65535)] = 8443,
    listen_address: Annotated[str, typer.Option("--listen-address")] = "0.0.0.0",  # noqa: S104
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Create a disabled, strictly validated profile."""
    try:
        application = build_application(dry_run=dry_run)
        require_root(application, dry_run=dry_run)
        require_supported_host(dry_run=dry_run)
        profile = application.profiles.create(
            name=name,
            provider=provider,
            protocol=protocol,
            transport=transport,
            security=security,
            port=port,
            listen_address=listen_address,
            dry_run=dry_run,
        )
        prefix = "Dry-run: would create profile\n" if dry_run else ""
        typer.echo(prefix + safe_profile(profile))
    except (FluxGateError, ValueError) as error:
        fail(error)


def _set(identity: str, enabled: bool, dry_run: bool) -> None:
    try:
        application = build_application(dry_run=dry_run)
        require_root(application, dry_run=dry_run)
        require_supported_host(dry_run=dry_run)
        result = application.profiles.set_enabled(identity, enabled, dry_run=dry_run)
        typer.echo(result.message)
        for action in result.actions:
            typer.echo(f"  {action}")
    except FluxGateError as error:
        fail(error)


@profile_app.command("enable")
def profile_enable(
    identity: Annotated[str, typer.Argument(help="Profile name or UUID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    _set(identity, True, dry_run)


@profile_app.command("disable")
def profile_disable(
    identity: Annotated[str, typer.Argument(help="Profile name or UUID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    _set(identity, False, dry_run)


@profile_app.command("delete")
def profile_delete(
    identity: Annotated[str, typer.Argument(help="Profile name or UUID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Delete a disabled profile with no provisioned clients."""
    try:
        application = build_application(dry_run=dry_run)
        require_root(application, dry_run=dry_run)
        deleted = application.profiles.delete(identity, dry_run=dry_run)
        typer.echo(f"{'Would delete' if dry_run else 'Deleted'} {deleted}")
    except FluxGateError as error:
        fail(error)
