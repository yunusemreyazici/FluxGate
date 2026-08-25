"""Offline Pathfinder compatibility evaluation CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from fluxgate.cli.common import fail
from fluxgate.core.errors import FluxGateError, VerificationError
from fluxgate.core.manifest import ServerManifest
from fluxgate.identity import ServerIdentityManager
from fluxgate.manifest.service import load_trust
from fluxgate.pathfinder import ClientCapabilities, evaluate_candidates

pathfinder_app = typer.Typer(help="Evaluate candidates offline without network probing.")


@pathfinder_app.command("evaluate")
def pathfinder_evaluate(
    manifest: Annotated[Path, typer.Option("--manifest", help="Capability manifest JSON.")],
    capabilities: Annotated[Path, typer.Option("--capabilities", help="Client capability JSON.")],
    signature: Annotated[
        Path | None, typer.Option("--signature", help="Detached signature envelope.")
    ] = None,
    trust: Annotated[Path | None, typer.Option("--trust", help="Pinned trust descriptor.")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Return deterministic compatibility and explicit rejection reasons."""
    try:
        if (signature is None) != (trust is None):
            raise VerificationError("--signature and --trust must be supplied together")
        manifest_bytes = manifest.read_bytes()
        if signature is not None and trust is not None:
            pinned = load_trust(trust)
            ServerIdentityManager.verify(manifest_bytes, signature.read_bytes(), pinned)
        document = ServerManifest.model_validate_json(manifest_bytes)
        if (
            signature is not None
            and trust is not None
            and document.server.server_id != pinned.server_id
        ):
            raise VerificationError("manifest server ID does not match pinned trust")
        client = ClientCapabilities.model_validate_json(capabilities.read_bytes())
        result = evaluate_candidates(document.candidates, client)
        if json_output:
            typer.echo(result.model_dump_json(indent=2))
            return
        for assessment in result.assessments:
            status = "compatible" if assessment.compatible else "incompatible"
            typer.echo(f"{assessment.candidate_id}: {status}")
            for reason in assessment.rejection_reasons:
                typer.echo(f"  - {reason}")
    except (FluxGateError, OSError, ValidationError) as error:
        fail(error)
