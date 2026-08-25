"""Structured doctor command presentation."""

from typing import Annotated

import typer

from fluxgate.application import build_application
from fluxgate.cli.common import fail
from fluxgate.core.errors import FluxGateError
from fluxgate.health import Doctor, HealthSeverity
from fluxgate.system.os import detect_os


def doctor_command(
    json_output: Annotated[bool, typer.Option("--json", help="Emit structured JSON.")] = False,
) -> None:
    """Run system and provider diagnostics."""
    try:
        application = build_application()
        report = Doctor(
            application.paths,
            application.state,
            application.providers,
            detect_os(),
            application.context.forwarding,
            application.identity,
        ).run()
        if json_output:
            typer.echo(report.model_dump_json(indent=2))
        else:
            typer.echo("FluxGate Doctor\n")
            symbols = {
                HealthSeverity.SUCCESS: "✓",
                HealthSeverity.INFO: "○",
                HealthSeverity.WARNING: "!",
                HealthSeverity.FAILURE: "✗",
            }
            section = ""
            for check in report.checks:
                if check.section != section:
                    section = check.section
                    typer.echo(f"\n{section}")
                typer.echo(f"  {symbols[check.severity]} {check.message}")
            typer.echo(f"\nResult: {'HEALTHY' if report.healthy else 'UNHEALTHY'}")
        if not report.healthy:
            raise typer.Exit(1)
    except FluxGateError as error:
        fail(error)
