"""Explicit failover execution planning and foreground sing-box CLI."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import stat
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any
from uuid import UUID

import typer
from pydantic import ValidationError

from fluxgate.bootstrap import BootstrapDescriptor, verify_bootstrap
from fluxgate.cli.common import fail
from fluxgate.core.errors import FluxGateError, PathfinderError, VerificationError
from fluxgate.core.manifest import ServerManifest
from fluxgate.identity import ServerIdentityManager, TrustDescriptor
from fluxgate.pathfinder.active_models import AuthorizationSource, FailoverDecision
from fluxgate.pathfinder.authorization import AuthorizedCandidateInventory, authorize_manifest
from fluxgate.pathfinder.execution import (
    ExecutionAdapterError,
    ExecutionCancellation,
    FailoverExecutor,
)
from fluxgate.pathfinder.execution_models import (
    ExecutionPlanStatus,
    ExecutionPolicy,
    ExecutionStatus,
    FailoverExecutionPlan,
    FailoverExecutionResult,
)
from fluxgate.pathfinder.execution_planning import plan_failover_execution
from fluxgate.pathfinder.singbox_adapter import (
    SingBoxLocalProxyAccess,
    SingBoxLocalProxyAdapter,
    VerifiedBootstrapSingBoxMaterialSource,
    discover_singbox_binary,
    singbox_local_proxy_capability,
    validate_private_bootstrap_root,
)

_SUCCESSFUL_EXECUTION_STATUSES = {
    ExecutionStatus.NO_ACTION,
    ExecutionStatus.ALREADY_CONVERGED,
    ExecutionStatus.COMMITTED,
}
_MAX_OPERATOR_JSON_BYTES = 1024 * 1024
_MAX_TRUST_BYTES = 64 * 1024
_MAX_PATH_BYTES = 4096


def _read_bounded_regular_file(path: Path, *, label: str, limit: int) -> bytes:
    """Read a stable regular file without following its final symlink."""
    if len(os.fsencode(path)) > _MAX_PATH_BYTES:
        raise VerificationError(f"{label} path exceeds the safety limit")
    for ancestor in path.parents:
        if ancestor.is_symlink():
            raise VerificationError(f"{label} path contains a symlink")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise VerificationError(f"{label} is unavailable or unsafe") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise VerificationError(f"{label} must be a regular file without hard links")
        if before.st_size > limit:
            raise VerificationError(f"{label} exceeds the safety limit")
        content = bytearray()
        while chunk := os.read(descriptor, min(65536, limit + 1 - len(content))):
            content.extend(chunk)
            if len(content) > limit:
                raise VerificationError(f"{label} exceeds the safety limit")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise VerificationError(f"{label} changed while being read")
        return bytes(content)
    finally:
        os.close(descriptor)


def _reject_duplicate_json(raw: bytes, *, label: str) -> None:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate JSON object keys")
            result[key] = value
        return result

    def invalid_constant(_value: str) -> None:
        raise ValueError(f"{label} contains a non-finite JSON number")

    try:
        json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise PathfinderError(f"{label} is malformed or unsupported") from error


def _load_pinned_trust(path: Path) -> TrustDescriptor:
    raw = _read_bounded_regular_file(path, label="pinned trust descriptor", limit=_MAX_TRUST_BYTES)
    _reject_duplicate_json(raw, label="pinned trust descriptor")
    try:
        return TrustDescriptor.model_validate_json(raw)
    except ValidationError as error:
        raise VerificationError("pinned trust descriptor is malformed or unsupported") from error


def _validate_bootstrap_digest(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise VerificationError("expected bootstrap digest must be lowercase SHA-256")


def _load_bootstrap_inventory(
    *,
    bootstrap: Path,
    pinned_trust: Path,
    expected_client_id: UUID,
    expected_bootstrap_sha256: str,
    expected_server: str,
    expected_addresses: tuple[str, ...],
) -> AuthorizedCandidateInventory:
    """Rebuild execution authority from independently pinned bootstrap inputs."""
    _validate_bootstrap_digest(expected_bootstrap_sha256)
    validate_private_bootstrap_root(bootstrap)
    trust = _load_pinned_trust(pinned_trust)
    verification = verify_bootstrap(bootstrap, pinned_trust=trust)
    validate_private_bootstrap_root(bootstrap)
    bootstrap_bytes = _read_bounded_regular_file(
        bootstrap / "bootstrap.json", label="bootstrap descriptor", limit=2 * 1024 * 1024
    )
    ServerIdentityManager.verify(
        bootstrap_bytes,
        _read_bounded_regular_file(
            bootstrap / "bootstrap.sig", label="bootstrap signature", limit=2 * 1024 * 1024
        ),
        trust,
    )
    if hashlib.sha256(bootstrap_bytes).hexdigest() != expected_bootstrap_sha256:
        raise VerificationError("client bootstrap generation does not match its pin")
    descriptor = BootstrapDescriptor.model_validate_json(bootstrap_bytes)
    if verification.client_id != expected_client_id or descriptor.client_id != expected_client_id:
        raise VerificationError("client bootstrap identity does not match expected client")
    manifest_bytes = _read_bounded_regular_file(
        bootstrap / "manifest.json", label="signed manifest", limit=2 * 1024 * 1024
    )
    ServerIdentityManager.verify(
        manifest_bytes,
        _read_bounded_regular_file(
            bootstrap / "manifest.sig", label="manifest signature", limit=2 * 1024 * 1024
        ),
        trust,
    )
    if descriptor.manifest_sha256 != hashlib.sha256(manifest_bytes).hexdigest():
        raise VerificationError("client bootstrap manifest generation changed")
    document = ServerManifest.model_validate_json(manifest_bytes)
    return authorize_manifest(
        document,
        source=AuthorizationSource.SIGNED_MANIFEST,
        trusted_server_id=trust.server_id,
        trusted_endpoint=expected_server,
        trusted_addresses=expected_addresses,
    )


def _execution_inventory_loader(
    *,
    bootstrap: Path,
    pinned_trust: Path,
    expected_client_id: UUID,
    expected_bootstrap_sha256: str,
    expected_server: str,
    expected_addresses: tuple[str, ...],
) -> Callable[[], AuthorizedCandidateInventory]:
    def load() -> AuthorizedCandidateInventory:
        return _load_bootstrap_inventory(
            bootstrap=bootstrap,
            pinned_trust=pinned_trust,
            expected_client_id=expected_client_id,
            expected_bootstrap_sha256=expected_bootstrap_sha256,
            expected_server=expected_server,
            expected_addresses=expected_addresses,
        )

    return load


def _execution_scope(server_id: UUID, client_id: UUID) -> str:
    return f"server:{server_id}:client:{client_id}:singbox-local-proxy"


def _inventory_execution_scope(inventory: AuthorizedCandidateInventory, client_id: UUID) -> str:
    if inventory.server_id is None:
        raise VerificationError("execution inventory has no server identity")
    return _execution_scope(inventory.server_id, client_id)


def _load_failover_decision(path: Path) -> FailoverDecision:
    raw = _read_bounded_regular_file(
        path, label="failover decision", limit=_MAX_OPERATOR_JSON_BYTES
    )
    _reject_duplicate_json(raw, label="failover decision")
    try:
        return FailoverDecision.model_validate_json(raw)
    except ValidationError as error:
        raise PathfinderError("failover decision is malformed or unsupported") from error


def _load_execution_plan(path: Path) -> FailoverExecutionPlan:
    raw = _read_bounded_regular_file(
        path, label="failover execution plan", limit=_MAX_OPERATOR_JSON_BYTES
    )
    _reject_duplicate_json(raw, label="failover execution plan")
    try:
        return FailoverExecutionPlan.model_validate_json(raw)
    except ValidationError as error:
        raise PathfinderError("failover execution plan is malformed or unsupported") from error


def _assert_private_access_parent(path: Path) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise VerificationError("proxy access file must use an absolute, traversal-free path")
    if (
        len(os.fsencode(path)) > _MAX_PATH_BYTES
        or len(os.fsencode(path.name)) > 255
        or any(ord(character) < 32 or ord(character) == 127 for character in str(path))
    ):
        raise VerificationError("proxy access file path exceeds the safety limit")
    parent = path.parent
    for candidate in (parent, *parent.parents):
        if candidate.is_symlink():
            raise VerificationError("proxy access file path contains a symlink")
    try:
        metadata = parent.stat()
    except OSError as error:
        raise VerificationError("proxy access file parent is unavailable") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise VerificationError("proxy access file parent must be a private owned directory")
    if path.exists() or path.is_symlink():
        raise VerificationError("proxy access file already exists")


def _write_proxy_access_file(
    path: Path,
    result: FailoverExecutionResult,
    access: SingBoxLocalProxyAccess,
) -> tuple[int, int]:
    _assert_private_access_parent(path)
    payload = {
        "schema_version": 1,
        "execution_id": result.execution_id,
        "candidate_id": result.target_candidate_id,
        "host": access.host,
        "port": access.port,
        "username": access.username,
        "password": access.password,
    }
    content = json.dumps(payload, sort_keys=True, indent=2).encode() + b"\n"
    descriptor, temporary_name = tempfile.mkstemp(prefix=".fluxgate-access-", dir=path.parent)
    temporary = Path(temporary_name)
    published = False
    complete = False
    identity: tuple[int, int] | None = None
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        metadata = os.fstat(descriptor)
        identity = (metadata.st_dev, metadata.st_ino)
        os.link(temporary, path, follow_symlinks=False)
        published = True
        temporary.unlink()
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or (metadata.st_dev, metadata.st_ino) != identity
        ):
            raise VerificationError("proxy access file is unsafe")
        complete = True
        return identity
    except FileExistsError as error:
        raise VerificationError("proxy access file already exists") from error
    finally:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        if published and not complete and identity is not None:
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                pass
            else:
                if (metadata.st_dev, metadata.st_ino) == identity:
                    path.unlink()


def _remove_proxy_access_file(path: Path, identity: tuple[int, int]) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_nlink == 1
        and (metadata.st_dev, metadata.st_ino) == identity
    ):
        path.unlink()
        return
    raise VerificationError("proxy access file changed while execution was active")


def _register_execution_signal_handlers(
    cancellation: ExecutionCancellation,
    stopped: asyncio.Event,
) -> tuple[tuple[signal.Signals, Any], ...]:
    loop = asyncio.get_running_loop()
    registered: list[tuple[signal.Signals, Any]] = []

    def request_shutdown() -> None:
        cancellation.cancel()
        stopped.set()

    for item in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        previous = signal.getsignal(item)
        try:
            loop.add_signal_handler(item, request_shutdown)
        except (NotImplementedError, RuntimeError):
            continue
        registered.append((item, previous))
    return tuple(registered)


async def _wait_for_execution_shutdown(stopped: asyncio.Event) -> None:
    await stopped.wait()


async def _hold_active_runtime(
    adapter: SingBoxLocalProxyAdapter,
    scope: str,
    stopped: asyncio.Event,
) -> None:
    shutdown = asyncio.create_task(_wait_for_execution_shutdown(stopped))
    runtime_stopped = asyncio.create_task(adapter.wait_until_stopped(scope))
    try:
        done, _ = await asyncio.wait(
            {shutdown, runtime_stopped},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if shutdown not in done:
            try:
                await runtime_stopped
            except ExecutionAdapterError as error:
                raise PathfinderError("owned sing-box runtime state became unavailable") from error
            raise PathfinderError("owned sing-box runtime stopped unexpectedly")
    finally:
        for task in (shutdown, runtime_stopped):
            if not task.done():
                task.cancel()
        await asyncio.gather(shutdown, runtime_stopped, return_exceptions=True)


def _echo_execution_result(
    result: FailoverExecutionResult,
    *,
    json_output: bool,
    access_file: Path | None = None,
) -> None:
    if json_output:
        typer.echo(
            json.dumps(
                {
                    "schema_version": 1,
                    "execution": result.model_dump(mode="json"),
                    "proxy_access_file": str(access_file) if access_file is not None else None,
                    "foreground": access_file is not None,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    typer.echo(f"status: {result.status.value}")
    typer.echo(f"target: {result.target_candidate_id or 'none'}")
    typer.echo(f"reason: {result.reason}")
    typer.echo(f"verification: {result.verification.value}")
    typer.echo(f"rollback: {result.rollback.value}")
    typer.echo(f"cleanup: {result.cleanup.value}")
    if access_file is not None:
        typer.echo(f"proxy access: {access_file} (private mode 0600)")
        typer.echo("runtime: active in the foreground; interrupt this command to stop it")


def pathfinder_plan_execution(
    decision: Annotated[Path, typer.Option("--decision", help="Saved failover decision JSON.")],
    bootstrap: Annotated[
        Path, typer.Option("--bootstrap", help="Private client bootstrap bundle directory.")
    ],
    pinned_trust: Annotated[
        Path,
        typer.Option("--pinned-trust", help="Independently pinned server trust descriptor."),
    ],
    expected_client_id: Annotated[
        UUID,
        typer.Option("--expected-client", help="Independently expected bootstrap client UUID."),
    ],
    expected_bootstrap_sha256: Annotated[
        str,
        typer.Option(
            "--expected-bootstrap-sha256",
            help="Independently recorded SHA-256 of the exact bootstrap.json generation.",
        ),
    ],
    expected_server: Annotated[
        str,
        typer.Option(
            "--expected-server",
            help="Independently pinned server hostname or IP.",
        ),
    ],
    expected_address: Annotated[
        list[str] | None,
        typer.Option(
            "--expected-address",
            help=(
                "Repeatable independently pinned IPv4/IPv6 server destination; required for "
                "hostname endpoints."
            ),
        ),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Build a deterministic execution plan without network or host mutation."""
    try:
        inventory = _load_bootstrap_inventory(
            bootstrap=bootstrap,
            pinned_trust=pinned_trust,
            expected_client_id=expected_client_id,
            expected_bootstrap_sha256=expected_bootstrap_sha256,
            expected_server=expected_server,
            expected_addresses=tuple(expected_address or ()),
        )
        plan = plan_failover_execution(
            inventory,
            _load_failover_decision(decision),
            (singbox_local_proxy_capability(),),
            ExecutionPolicy(),
            execution_scope=_inventory_execution_scope(inventory, expected_client_id),
        )
        if json_output:
            typer.echo(plan.model_dump_json(indent=2))
            return
        typer.echo(f"status: {plan.status.value}")
        typer.echo(f"plan: {plan.plan_id}")
        typer.echo(
            f"target: {plan.target.candidate.candidate_id if plan.target is not None else 'none'}"
        )
        typer.echo(f"adapter: {plan.adapter.adapter_id if plan.adapter is not None else 'none'}")
        typer.echo(f"reason: {plan.reason}")
        if plan.preconditions:
            typer.echo("preconditions:")
            for precondition in plan.preconditions:
                typer.echo(f"  - {precondition}")
    except (FluxGateError, OSError, ValidationError, ValueError) as error:
        fail(error)


async def _execute_singbox_foreground(
    *,
    plan: FailoverExecutionPlan,
    bootstrap: Path,
    pinned_trust: Path,
    expected_client_id: UUID,
    expected_bootstrap_sha256: str,
    expected_server: str,
    expected_addresses: tuple[str, ...],
    binary: Path | None,
    runtime_root: Path,
    access_file: Path,
    json_output: bool,
) -> bool:
    cancellation = ExecutionCancellation()
    stopped = asyncio.Event()
    registered = _register_execution_signal_handlers(cancellation, stopped)
    try:
        inventory_loader = _execution_inventory_loader(
            bootstrap=bootstrap,
            pinned_trust=pinned_trust,
            expected_client_id=expected_client_id,
            expected_bootstrap_sha256=expected_bootstrap_sha256,
            expected_server=expected_server,
            expected_addresses=expected_addresses,
        )
        inventory = inventory_loader()
        expected_scope = _inventory_execution_scope(inventory, expected_client_id)
        if plan.execution_scope != expected_scope:
            raise VerificationError(
                "execution plan scope does not match expected server and client"
            )
        if plan.status != ExecutionPlanStatus.READY:
            result = await FailoverExecutor(inventory_loader).execute(
                plan,
                None,
                cancellation=cancellation,
            )
            _echo_execution_result(result, json_output=json_output)
            return result.status in _SUCCESSFUL_EXECUTION_STATUSES
        discovered_binary = discover_singbox_binary(binary)
        if discovered_binary is None:
            raise PathfinderError("supported sing-box executable was not found")
        trust = _load_pinned_trust(pinned_trust)
        material_source = VerifiedBootstrapSingBoxMaterialSource(
            bootstrap,
            pinned_trust=trust,
            expected_client_id=expected_client_id,
            expected_bootstrap_sha256=expected_bootstrap_sha256,
        )
        adapter = SingBoxLocalProxyAdapter(
            inventory_loader,
            material_source,
            binary=discovered_binary,
            runtime_root=runtime_root,
        )
        async with adapter:
            result = await FailoverExecutor(inventory_loader).execute(
                plan,
                adapter,
                cancellation=cancellation,
            )
            if result.status != ExecutionStatus.COMMITTED:
                _echo_execution_result(result, json_output=json_output)
                return result.status in _SUCCESSFUL_EXECUTION_STATUSES
            access = adapter.active_proxies.get(plan.execution_scope)
            if access is None:
                raise PathfinderError(
                    "committed sing-box runtime has no authenticated proxy access"
                )
            identity = _write_proxy_access_file(access_file, result, access)
            try:
                _echo_execution_result(
                    result,
                    json_output=json_output,
                    access_file=access_file,
                )
                await _hold_active_runtime(adapter, plan.execution_scope, stopped)
            finally:
                _remove_proxy_access_file(access_file, identity)
        return True
    finally:
        loop = asyncio.get_running_loop()
        for item, previous in registered:
            loop.remove_signal_handler(item)
            signal.signal(item, previous)


def pathfinder_execute(
    plan_path: Annotated[Path, typer.Option("--plan", help="Saved failover execution plan JSON.")],
    bootstrap: Annotated[
        Path, typer.Option("--bootstrap", help="Private client bootstrap bundle directory.")
    ],
    pinned_trust: Annotated[
        Path,
        typer.Option("--pinned-trust", help="Independently pinned server trust descriptor."),
    ],
    expected_client_id: Annotated[
        UUID,
        typer.Option("--expected-client", help="Independently expected bootstrap client UUID."),
    ],
    expected_bootstrap_sha256: Annotated[
        str,
        typer.Option(
            "--expected-bootstrap-sha256",
            help="Independently recorded SHA-256 of the exact bootstrap.json generation.",
        ),
    ],
    expected_server: Annotated[
        str,
        typer.Option("--expected-server", help="Independently pinned server hostname or IP."),
    ],
    runtime_root: Annotated[
        Path,
        typer.Option(
            "--runtime-root",
            help="Absolute private directory for owned ephemeral sing-box runtimes.",
        ),
    ],
    access_file: Annotated[
        Path,
        typer.Option(
            "--access-file",
            help="New file receiving ephemeral authenticated SOCKS access at mode 0600.",
        ),
    ],
    expected_address: Annotated[
        list[str] | None,
        typer.Option(
            "--expected-address",
            help=(
                "Repeatable independently pinned IPv4/IPv6 server destination; required for "
                "hostname endpoints."
            ),
        ),
    ] = None,
    singbox_binary: Annotated[
        Path | None,
        typer.Option(
            "--sing-box-binary",
            help="Absolute supported sing-box executable; otherwise discover it from PATH.",
        ),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Explicitly run one planned local sing-box proxy in the foreground."""
    try:
        plan = _load_execution_plan(plan_path)
        _assert_private_access_parent(access_file)
        successful = asyncio.run(
            _execute_singbox_foreground(
                plan=plan,
                bootstrap=bootstrap,
                pinned_trust=pinned_trust,
                expected_client_id=expected_client_id,
                expected_bootstrap_sha256=expected_bootstrap_sha256,
                expected_server=expected_server,
                expected_addresses=tuple(expected_address or ()),
                binary=singbox_binary,
                runtime_root=runtime_root,
                access_file=access_file,
                json_output=json_output,
            )
        )
        if not successful:
            raise typer.Exit(1)
    except typer.Exit:
        raise
    except (FluxGateError, OSError, ValidationError, ValueError) as error:
        fail(error)
