"""Offline compatibility and bounded active Pathfinder CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from fluxgate.cli.common import fail
from fluxgate.core.config import PathfinderProbeConfig, load_config
from fluxgate.core.errors import FluxGateError, PathfinderError, VerificationError
from fluxgate.core.manifest import ServerManifest, build_manifest
from fluxgate.core.paths import PathLayout
from fluxgate.core.state import StateStore
from fluxgate.identity import ServerIdentityManager
from fluxgate.manifest.service import load_trust
from fluxgate.pathfinder import ClientCapabilities, evaluate_candidates
from fluxgate.pathfinder.active import ActivePathfinder
from fluxgate.pathfinder.active_models import (
    ActivePathfinderReport,
    AuthorizationSource,
    FailoverContext,
)
from fluxgate.pathfinder.authorization import AuthorizedCandidateInventory, authorize_manifest
from fluxgate.pathfinder.failover import decide_failover
from fluxgate.pathfinder.scoring import score_candidate
from fluxgate.pathfinder.selection import rank_candidates, select_candidate

pathfinder_app = typer.Typer(
    help="Evaluate compatibility or actively probe authorized candidates.", no_args_is_help=True
)


def _load_active_inventory(
    *,
    local_inventory: bool,
    manifest: Path | None,
    signature: Path | None,
    trust: Path | None,
    expected_server: str | None,
    expected_addresses: tuple[str, ...],
) -> tuple[AuthorizedCandidateInventory, PathfinderProbeConfig]:
    paths = PathLayout.from_environment()
    config = load_config(paths.config_file)
    if local_inventory:
        if any(item is not None for item in (manifest, signature, trust, expected_server)) or (
            expected_addresses
        ):
            raise VerificationError(
                "--local cannot be combined with signed-manifest authorization options"
            )
        document = build_manifest(config, StateStore(paths.state_file).load())
        return (
            authorize_manifest(
                document,
                source=AuthorizationSource.LOCAL_STATE,
                trusted_addresses=config.pathfinder.probe.authorized_server_addresses,
            ),
            config.pathfinder.probe,
        )
    if manifest is None or signature is None or trust is None or expected_server is None:
        raise VerificationError(
            "active probing requires --local or --manifest, --signature, --trust and "
            "--expected-server"
        )
    manifest_bytes = manifest.read_bytes()
    pinned = load_trust(trust)
    ServerIdentityManager.verify(manifest_bytes, signature.read_bytes(), pinned)
    document = ServerManifest.model_validate_json(manifest_bytes)
    return (
        authorize_manifest(
            document,
            source=AuthorizationSource.SIGNED_MANIFEST,
            trusted_server_id=pinned.server_id,
            trusted_endpoint=expected_server,
            trusted_addresses=expected_addresses,
        ),
        config.pathfinder.probe,
    )


def _load_report(path: Path) -> ActivePathfinderReport:
    try:
        report = ActivePathfinderReport.model_validate_json(path.read_bytes())
    except ValidationError as error:
        raise PathfinderError("active Pathfinder report is malformed or unsupported") from error
    observations = {item.candidate_id: item for item in report.observations}
    scores = tuple(
        score_candidate(assessment, observations[assessment.candidate_id])
        for assessment in report.assessments
    )
    ranked = rank_candidates(scores)
    return ActivePathfinderReport(
        assessments=report.assessments,
        observations=report.observations,
        ranked_candidates=ranked,
        selection=select_candidate(ranked),
    )


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


@pathfinder_app.command("probe")
def pathfinder_probe(
    capabilities: Annotated[Path, typer.Option("--capabilities", help="Client capability JSON.")],
    manifest: Annotated[
        Path | None, typer.Option("--manifest", help="Signed capability manifest JSON.")
    ] = None,
    signature: Annotated[
        Path | None, typer.Option("--signature", help="Detached manifest signature.")
    ] = None,
    trust: Annotated[Path | None, typer.Option("--trust", help="Pinned trust descriptor.")] = None,
    expected_server: Annotated[
        str | None,
        typer.Option(
            "--expected-server",
            help="Separately pinned server hostname or IP expected in the signed manifest.",
        ),
    ] = None,
    expected_address: Annotated[
        list[str] | None,
        typer.Option(
            "--expected-address",
            help=(
                "Repeatable independently pinned IPv4/IPv6 address for the expected server. "
                "Required when the expected server is a hostname."
            ),
        ),
    ] = None,
    local_inventory: Annotated[
        bool, typer.Option("--local", help="Use authoritative local FluxGate config and state.")
    ] = False,
    tls_ca: Annotated[
        Path | None,
        typer.Option("--tls-ca", help="Optional CA bundle for verified TLS probes."),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Perform bounded network probes against authorized compatible candidates."""
    try:
        inventory, probe_config = _load_active_inventory(
            local_inventory=local_inventory,
            manifest=manifest,
            signature=signature,
            trust=trust,
            expected_server=expected_server,
            expected_addresses=tuple(expected_address or ()),
        )
        client = ClientCapabilities.model_validate_json(capabilities.read_bytes())
        result = ActivePathfinder().probe(
            inventory,
            client,
            probe_config,
            tls_ca_file=tls_ca,
        )
        if json_output:
            typer.echo(result.model_dump_json(indent=2))
            return
        typer.echo("Active Pathfinder probe (network I/O performed)")
        for score in result.ranked_candidates:
            status = "eligible" if score.eligible else score.observation.verification.value
            typer.echo(
                f"{score.candidate_id}: {score.observation.outcome.value} "
                f"score={score.score} {status}"
            )
            typer.echo(f"  - {score.observation.summary}")
        typer.echo(f"selected: {result.selection.selected_candidate_id or 'none'}")
    except (FluxGateError, OSError, ValidationError) as error:
        fail(error)


@pathfinder_app.command("rank")
def pathfinder_rank(
    report: Annotated[Path, typer.Option("--report", help="Active probe report JSON.")],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Rank an existing ephemeral probe report without network I/O."""
    try:
        document = _load_report(report)
        if json_output:
            typer.echo(document.model_dump_json(indent=2))
            return
        for index, score in enumerate(document.ranked_candidates, start=1):
            status = "eligible" if score.eligible else score.observation.verification.value
            typer.echo(f"{index}. {score.candidate_id} score={score.score} {status}")
            for component in score.components:
                typer.echo(f"  {component.points:+d} {component.reason}")
    except (FluxGateError, OSError) as error:
        fail(error)


@pathfinder_app.command("select")
def pathfinder_select(
    report: Annotated[Path, typer.Option("--report", help="Active probe report JSON.")],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Explain the selected candidate and preserved alternatives without network I/O."""
    try:
        decision = _load_report(report).selection
        if json_output:
            typer.echo(decision.model_dump_json(indent=2))
            return
        typer.echo(f"selected: {decision.selected_candidate_id or 'none'}")
        typer.echo(f"reason: {decision.reason}")
        if decision.alternatives:
            typer.echo("alternatives:")
            for candidate_id in decision.alternatives:
                typer.echo(f"  - {candidate_id}")
    except (FluxGateError, OSError) as error:
        fail(error)


@pathfinder_app.command("failover")
def pathfinder_failover(
    report: Annotated[Path, typer.Option("--report", help="Active probe report JSON.")],
    current: Annotated[
        str | None, typer.Option("--current", help="Current candidate ID, if selected.")
    ] = None,
    consecutive_failures: Annotated[int, typer.Option("--consecutive-failures", min=0)] = 0,
    seconds_since_switch: Annotated[float, typer.Option("--seconds-since-switch", min=0.0)] = 0.0,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Plan stay/switch/no-verified/no-viable behavior without network mutation."""
    try:
        paths = PathLayout.from_environment()
        policy = load_config(paths.config_file).pathfinder.failover
        decision = decide_failover(
            _load_report(report),
            FailoverContext(
                current_candidate_id=current,
                consecutive_failures=consecutive_failures,
                seconds_since_switch=seconds_since_switch,
            ),
            policy,
        )
        if json_output:
            typer.echo(decision.model_dump_json(indent=2))
            return
        typer.echo(f"action: {decision.action.value}")
        typer.echo(f"target: {decision.target_candidate_id or 'none'}")
        typer.echo(f"reason: {decision.reason}")
    except (FluxGateError, OSError, ValidationError) as error:
        fail(error)
