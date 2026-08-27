"""Local sing-box SOCKS runtime adapter for authorized TCP/TLS candidates."""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import ipaddress
import json
import os
import secrets
import shutil
import signal
import socket
import stat
import sys
import tempfile
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Protocol
from uuid import UUID

from pydantic import ValidationError

from fluxgate.bootstrap import BootstrapDescriptor, verify_bootstrap
from fluxgate.core.errors import FluxGateError, VerificationError
from fluxgate.core.manifest import ServerManifest
from fluxgate.core.publication import safe_relative_path
from fluxgate.core.state import atomic_write
from fluxgate.identity import ServerIdentityManager, TrustDescriptor
from fluxgate.pathfinder.authorization import AuthorizedCandidateInventory
from fluxgate.pathfinder.execution import ExecutionAdapterError, InventoryLoader
from fluxgate.pathfinder.execution_models import (
    ExecutionCapability,
    ExecutionStrategy,
    FailoverExecutionPlan,
)
from fluxgate.pathfinder.execution_planning import candidate_fingerprint
from fluxgate.pathfinder.models import (
    ConnectionMode,
    IPFamily,
    PathfinderProtocol,
    PathfinderProvider,
    PathfinderSecurity,
    PathfinderTransport,
)
from fluxgate.system.packages import SING_BOX_VERSION

_OWNER = b"Managed by FluxGate local sing-box adapter\n"
_MAX_VERSION_OUTPUT = 4096
_MAX_CLIENT_CONFIG_BYTES = 1024 * 1024
_MAX_AUTHORITY_FILE_BYTES = 2 * 1024 * 1024
_MAX_AUTHORITY_FILES = 512
_MAX_AUTHORITY_TREE_BYTES = 32 * 1024 * 1024
_MAX_BINARY_BYTES = 128 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class _BinaryIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    sha256: str


def _assert_private_authority_root(root: Path) -> None:
    for candidate in (root, *root.parents):
        if candidate.is_symlink():
            raise VerificationError("client bootstrap path contains a symlink")
        if candidate.exists():
            metadata = candidate.stat()
            mode = stat.S_IMODE(metadata.st_mode)
            if not stat.S_ISDIR(metadata.st_mode) or (mode & 0o022 and not mode & stat.S_ISVTX):
                raise VerificationError("client bootstrap ancestor is unsafely writable")
    try:
        metadata = root.lstat()
    except OSError as error:
        raise VerificationError("client bootstrap root is unavailable") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise VerificationError("client bootstrap root is not private and owned")

    entries = 0
    total_bytes = 0
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in (*directories, *filenames):
            path = current_path / name
            metadata = path.lstat()
            entries += 1
            if entries > _MAX_AUTHORITY_FILES:
                raise VerificationError("client bootstrap tree exceeds the entry limit")
            if stat.S_ISREG(metadata.st_mode):
                if metadata.st_size > _MAX_AUTHORITY_FILE_BYTES:
                    raise VerificationError("client bootstrap entry exceeds the safety limit")
                total_bytes += metadata.st_size
                if total_bytes > _MAX_AUTHORITY_TREE_BYTES:
                    raise VerificationError("client bootstrap tree exceeds the safety limit")
            elif not stat.S_ISDIR(metadata.st_mode):
                raise VerificationError("client bootstrap tree contains an unsafe entry")


def validate_private_bootstrap_root(root: Path) -> None:
    """Bound a private bootstrap tree before signature verification reads it."""
    _assert_private_authority_root(root)


def _read_private_authority_file(path: Path, expected_mode: int) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise VerificationError("client bootstrap entry is unavailable") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != expected_mode
        ):
            raise VerificationError("client bootstrap entry is unsafe")
        content = bytearray()
        while chunk := os.read(
            descriptor, min(65536, _MAX_AUTHORITY_FILE_BYTES + 1 - len(content))
        ):
            content.extend(chunk)
            if len(content) > _MAX_AUTHORITY_FILE_BYTES:
                raise VerificationError("client bootstrap entry exceeds the safety limit")
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
            raise VerificationError("client bootstrap entry changed while being read")
        return bytes(content)
    finally:
        os.close(descriptor)


@dataclass(frozen=True, slots=True, repr=False)
class SingBoxRuntimeMaterial:
    """Authenticated private client material; repr is intentionally disabled."""

    client_id: UUID
    profile_id: UUID
    candidate_id: str
    protocol: PathfinderProtocol
    endpoint: str
    port: int
    outbound: dict[str, object] = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class SingBoxLocalProxyAccess:
    """Ephemeral authenticated access to one owned loopback proxy."""

    host: str
    port: int
    username: str = field(repr=False)
    password: str = field(repr=False)


class SingBoxMaterialSource(Protocol):
    """Load private runtime material from an independently authenticated authority."""

    def load(
        self,
        plan: FailoverExecutionPlan,
        inventory: AuthorizedCandidateInventory,
    ) -> SingBoxRuntimeMaterial: ...


class VerifiedBootstrapSingBoxMaterialSource:
    """Resolve one candidate only from a signature-verified, client-bound bootstrap."""

    def __init__(
        self,
        root: Path,
        *,
        pinned_trust: TrustDescriptor,
        expected_client_id: UUID,
        expected_bootstrap_sha256: str,
    ) -> None:
        if len(expected_bootstrap_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in expected_bootstrap_sha256
        ):
            raise ValueError("expected bootstrap digest must be lowercase SHA-256")
        self._root = root
        self._trust = pinned_trust
        self._expected_client_id = expected_client_id
        self._expected_bootstrap_sha256 = expected_bootstrap_sha256

    def load(
        self,
        plan: FailoverExecutionPlan,
        inventory: AuthorizedCandidateInventory,
    ) -> SingBoxRuntimeMaterial:
        target_binding = plan.target
        if target_binding is None:
            raise ExecutionAdapterError("execution target is unavailable")
        target = target_binding.candidate
        try:
            _assert_private_authority_root(self._root)
            verification = verify_bootstrap(self._root, pinned_trust=self._trust)
            _assert_private_authority_root(self._root)
            bootstrap_bytes = _read_private_authority_file(self._root / "bootstrap.json", 0o600)
            if hashlib.sha256(bootstrap_bytes).hexdigest() != self._expected_bootstrap_sha256:
                raise VerificationError("client bootstrap generation does not match its pin")
            ServerIdentityManager.verify(
                bootstrap_bytes,
                _read_private_authority_file(self._root / "bootstrap.sig", 0o600),
                self._trust,
            )
            manifest_bytes = _read_private_authority_file(self._root / "manifest.json", 0o644)
            ServerIdentityManager.verify(
                manifest_bytes,
                _read_private_authority_file(self._root / "manifest.sig", 0o644),
                self._trust,
            )
            descriptor = BootstrapDescriptor.model_validate_json(bootstrap_bytes)
            manifest = ServerManifest.model_validate_json(manifest_bytes)
        except (OSError, ValidationError, VerificationError) as error:
            raise ExecutionAdapterError("authenticated client bootstrap is unavailable") from error
        if (
            verification.client_id != self._expected_client_id
            or descriptor.client_id != self._expected_client_id
        ):
            raise ExecutionAdapterError("client bootstrap identity does not match execution scope")
        if (
            inventory.server_id is None
            or descriptor.server_id != inventory.server_id
            or manifest.server.server_id != inventory.server_id
            or descriptor.manifest_sha256 != hashlib.sha256(manifest_bytes).hexdigest()
        ):
            raise ExecutionAdapterError("client bootstrap server authority does not match target")
        matches = [item for item in manifest.candidates if item.candidate_id == target.candidate_id]
        if len(matches) != 1 or matches[0] != target:
            raise ExecutionAdapterError(
                "client bootstrap candidate does not match execution target"
            )
        artifacts = [
            item
            for item in descriptor.artifacts
            if item.candidate_id == target.candidate_id
            and item.provider == PathfinderProvider.SINGBOX
            and item.connection_mode == ConnectionMode.LOCAL_PROXY
            and item.media_type == "application/json"
        ]
        if len(artifacts) != 1:
            raise ExecutionAdapterError("client bootstrap has no unique target artifact")
        artifact = artifacts[0]
        try:
            relative = safe_relative_path(artifact.path)
            artifact_path = self._root.joinpath(*relative.parts)
            content = _read_private_authority_file(artifact_path, 0o600)
        except (OSError, FluxGateError, VerificationError) as error:
            raise ExecutionAdapterError("client bootstrap artifact is unavailable") from error
        if hashlib.sha256(content).hexdigest() != artifact.sha256:
            raise ExecutionAdapterError("client bootstrap artifact integrity changed")
        if len(content) > _MAX_CLIENT_CONFIG_BYTES:
            raise ExecutionAdapterError("client bootstrap artifact exceeds the safety limit")
        if target.profile_id is None:
            raise ExecutionAdapterError("sing-box execution target has no profile identity")
        if target.candidate_id != f"profile:{target.profile_id}":
            raise ExecutionAdapterError("sing-box candidate and profile identities do not match")
        if artifact.path != f"singbox/profile-{target.profile_id.hex}.json":
            raise ExecutionAdapterError("client artifact path does not match target profile")
        outbound = _validated_exported_outbound(
            content, target.protocol, target.endpoint, target.port
        )
        return SingBoxRuntimeMaterial(
            client_id=descriptor.client_id,
            profile_id=target.profile_id,
            candidate_id=target.candidate_id,
            protocol=target.protocol,
            endpoint=target.endpoint,
            port=target.port,
            outbound=outbound,
        )


def _validated_exported_outbound(
    content: bytes,
    protocol: PathfinderProtocol,
    endpoint: str,
    port: int,
) -> dict[str, object]:
    """Extract only the exact client outbound shape emitted by FluxGate v0.4."""
    try:
        document = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ExecutionAdapterError("client artifact is not valid JSON") from error
    if not isinstance(document, dict) or set(document) != {"log", "inbounds", "outbounds", "route"}:
        raise ExecutionAdapterError("client artifact has an unsupported document shape")
    inbounds = document.get("inbounds")
    outbounds = document.get("outbounds")
    route = document.get("route")
    if (
        not isinstance(inbounds, list)
        or len(inbounds) != 1
        or inbounds[0]
        != {
            "type": "socks",
            "tag": "local-socks",
            "listen": "127.0.0.1",
            "listen_port": 2080,
        }
        or not isinstance(outbounds, list)
        or len(outbounds) != 2
        or outbounds[1] != {"type": "direct", "tag": "direct"}
        or route != {"final": "fluxgate-remote"}
    ):
        raise ExecutionAdapterError("client artifact is not a FluxGate standalone client config")
    remote = outbounds[0]
    if not isinstance(remote, dict):
        raise ExecutionAdapterError("client artifact remote outbound is malformed")
    return _validated_outbound(remote, protocol, endpoint, port)


def _validated_outbound(
    remote: dict[str, object],
    protocol: PathfinderProtocol,
    endpoint: str,
    port: int,
) -> dict[str, object]:
    """Validate and copy the only private outbound shape this adapter may execute."""
    expected_keys = {"type", "tag", "server", "server_port", "tls", "uuid", "network"}
    if protocol == PathfinderProtocol.TROJAN:
        expected_keys = {"type", "tag", "server", "server_port", "tls", "password"}
    if protocol not in {PathfinderProtocol.VLESS, PathfinderProtocol.TROJAN}:
        raise ExecutionAdapterError("candidate protocol is not executable by this adapter")
    if set(remote) != expected_keys:
        raise ExecutionAdapterError("client artifact outbound contains unsupported options")
    if (
        remote.get("type") != protocol.value
        or remote.get("tag") != "fluxgate-remote"
        or remote.get("server") != endpoint
        or remote.get("server_port") != port
    ):
        raise ExecutionAdapterError("client artifact outbound does not match target candidate")
    tls = remote.get("tls")
    if (
        not isinstance(tls, dict)
        or set(tls) != {"enabled", "server_name", "certificate"}
        or tls.get("enabled") is not True
        or tls.get("server_name") != endpoint
        or not isinstance(tls.get("certificate"), list)
        or len(tls["certificate"]) != 1
        or not isinstance(tls["certificate"][0], str)
        or not tls["certificate"][0]
    ):
        raise ExecutionAdapterError("client artifact TLS identity is malformed or insecure")
    if protocol == PathfinderProtocol.VLESS:
        credential = remote.get("uuid")
        if not isinstance(credential, str):
            raise ExecutionAdapterError("client artifact VLESS credential is malformed")
        try:
            UUID(credential)
        except ValueError as error:
            raise ExecutionAdapterError("client artifact VLESS credential is malformed") from error
        if remote.get("network") != "tcp":
            raise ExecutionAdapterError("client artifact VLESS transport is not TCP")
    else:
        password = remote.get("password")
        if not isinstance(password, str) or not password:
            raise ExecutionAdapterError("client artifact Trojan credential is malformed")
        credential = password
    validated: dict[str, object] = {
        "type": protocol.value,
        "tag": "fluxgate-remote",
        "server": endpoint,
        "server_port": port,
        "tls": {
            "enabled": True,
            "server_name": endpoint,
            "certificate": [tls["certificate"][0]],
        },
    }
    if protocol == PathfinderProtocol.VLESS:
        validated["uuid"] = credential
        validated["network"] = "tcp"
    else:
        validated["password"] = credential
    return validated


@dataclass(slots=True, repr=False)
class _OwnedRuntime:
    candidate_fingerprint: str
    directory: Path
    config_path: Path
    config_sha256: str
    binary_identity: _BinaryIdentity
    port: int
    local_username: str = field(repr=False)
    local_password: str = field(repr=False)
    reservation: socket.socket | None
    process: asyncio.subprocess.Process | None = None
    control_fd: int | None = None


@dataclass(slots=True)
class _ScopeState:
    lock_fd: int
    directory: Path
    active: _OwnedRuntime | None = None
    staged: _OwnedRuntime | None = None
    fallbacks: list[_OwnedRuntime] = field(default_factory=list)
    previous: _OwnedRuntime | None = None
    committed_plan_id: str | None = None


class SingBoxLocalProxyAdapter:
    """Run eligible sing-box TCP/TLS candidates behind a loopback SOCKS5 listener."""

    def __init__(
        self,
        inventory_loader: InventoryLoader,
        material_source: SingBoxMaterialSource,
        *,
        binary: Path,
        runtime_root: Path,
        port_range: tuple[int, int] = (20000, 60999),
        port_attempts: int = 4,
        lock_timeout_seconds: float = 2.0,
        port_selection_seed: int | None = None,
    ) -> None:
        if not runtime_root.is_absolute() or ".." in runtime_root.parts:
            raise ValueError("sing-box runtime root must be absolute and traversal-free")
        if not binary.is_absolute() or ".." in binary.parts:
            raise ValueError("sing-box binary path must be absolute and traversal-free")
        low, high = port_range
        if type(low) is not int or type(high) is not int or not 1024 <= low <= high <= 65535:
            raise ValueError("sing-box port range must contain unprivileged TCP ports")
        if type(port_attempts) is not int or not 1 <= port_attempts <= 16:
            raise ValueError("sing-box port attempts must be between 1 and 16")
        if not 0.05 <= lock_timeout_seconds <= 30.0:
            raise ValueError("sing-box lock timeout must be between 0.05 and 30 seconds")
        if port_selection_seed is not None and type(port_selection_seed) is not int:
            raise ValueError("sing-box port selection seed must be an integer")
        self._inventory_loader = inventory_loader
        self._material_source = material_source
        self._binary = binary
        self._runtime_root = runtime_root
        self._port_range = port_range
        self._port_attempts = port_attempts
        self._lock_timeout_seconds = lock_timeout_seconds
        port_count = high - low + 1
        self._port_cursor = (
            secrets.randbelow(port_count)
            if port_selection_seed is None
            else port_selection_seed % port_count
        )
        self._scopes: dict[str, _ScopeState] = {}

    @property
    def capability(self) -> ExecutionCapability:
        return singbox_local_proxy_capability()

    @property
    def active_endpoints(self) -> dict[str, tuple[str, int]]:
        """Return only public loopback endpoints for operator integration."""
        return {
            scope: ("127.0.0.1", state.active.port)
            for scope, state in self._scopes.items()
            if state.active is not None
        }

    @property
    def active_proxies(self) -> dict[str, SingBoxLocalProxyAccess]:
        """Return ephemeral authenticated proxy access without repr-visible credentials."""
        return {
            scope: SingBoxLocalProxyAccess(
                host="127.0.0.1",
                port=state.active.port,
                username=state.active.local_username,
                password=state.active.local_password,
            )
            for scope, state in self._scopes.items()
            if state.active is not None
        }

    async def wait_until_stopped(self, scope: str) -> None:
        """Wait for the owned foreground runtime guardian to exit."""
        state = self._scopes.get(scope)
        if state is None or state.active is None or state.active.process is None:
            raise ExecutionAdapterError("sing-box execution scope has no active runtime")
        await state.active.process.wait()

    async def __aenter__(self) -> SingBoxLocalProxyAdapter:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        await self.close()

    def _scope_hash(self, scope: str) -> str:
        return hashlib.sha256(scope.encode("ascii")).hexdigest()

    def _assert_runtime_root(self) -> None:
        for candidate in (self._runtime_root, *self._runtime_root.parents):
            if candidate.is_symlink():
                raise ExecutionAdapterError("sing-box runtime path contains a symlink")
            if candidate.exists():
                metadata = candidate.stat()
                if not stat.S_ISDIR(metadata.st_mode):
                    raise ExecutionAdapterError("sing-box runtime ancestor is not a directory")
                mode = stat.S_IMODE(metadata.st_mode)
                if mode & 0o022 and not mode & stat.S_ISVTX:
                    raise ExecutionAdapterError("sing-box runtime ancestor is unsafely writable")
        try:
            self._runtime_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            metadata = self._runtime_root.stat()
        except OSError as error:
            raise ExecutionAdapterError("sing-box runtime root is unavailable") from error
        for candidate in (self._runtime_root, *self._runtime_root.parents):
            if candidate.is_symlink():
                raise ExecutionAdapterError("sing-box runtime path contains a symlink")
            candidate_metadata = candidate.stat()
            mode = stat.S_IMODE(candidate_metadata.st_mode)
            if not stat.S_ISDIR(candidate_metadata.st_mode) or (
                mode & 0o022 and not mode & stat.S_ISVTX
            ):
                raise ExecutionAdapterError("sing-box runtime ancestor is unsafely writable")
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ExecutionAdapterError("sing-box runtime root is not private and owned")

    async def _acquire_scope(self, scope: str) -> _ScopeState:
        current = self._scopes.get(scope)
        if current is not None:
            return current
        self._assert_runtime_root()
        locks = self._runtime_root / "locks"
        scopes = self._runtime_root / "scopes"
        for directory in (locks, scopes):
            if directory.exists() or directory.is_symlink():
                metadata = directory.lstat()
            else:
                directory.mkdir(mode=0o700)
                metadata = directory.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise ExecutionAdapterError("sing-box runtime subdirectory is unsafe")
        digest = self._scope_hash(scope)
        lock_path = locks / f"{digest}.lock"
        try:
            descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise OSError("unsafe lock file")
        except OSError as error:
            raise ExecutionAdapterError("sing-box runtime lock is unsafe") from error
        deadline = asyncio.get_running_loop().time() + self._lock_timeout_seconds
        try:
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if asyncio.get_running_loop().time() >= deadline:
                        raise ExecutionAdapterError("sing-box runtime scope is busy") from None
                    await asyncio.sleep(0.05)
            scope_directory = scopes / digest
            self._reconcile_scope_directory(scope_directory)
            state = _ScopeState(lock_fd=descriptor, directory=scope_directory)
            self._scopes[scope] = state
            return state
        except BaseException:
            os.close(descriptor)
            raise

    def _reconcile_scope_directory(self, directory: Path) -> None:
        marker = directory / ".owner"
        if directory.exists():
            if (
                directory.is_symlink()
                or not directory.is_dir()
                or stat.S_IMODE(directory.stat().st_mode) != 0o700
                or directory.stat().st_uid != os.geteuid()
                or marker.is_symlink()
                or not marker.is_file()
                or marker.stat().st_nlink != 1
                or stat.S_IMODE(marker.stat().st_mode) != 0o600
                or marker.read_bytes() != _OWNER
            ):
                raise ExecutionAdapterError("sing-box runtime scope is foreign or unsafe")
            for child in directory.iterdir():
                if child != marker:
                    self._remove_runtime_directory(child)
            return
        directory.mkdir(mode=0o700)
        atomic_write(marker, _OWNER, 0o600)

    def _binary_identity(self) -> _BinaryIdentity:
        for candidate in self._binary.parents:
            if candidate.is_symlink():
                raise ExecutionAdapterError("sing-box binary path contains a symlink")
            if candidate.exists():
                metadata = candidate.stat()
                mode = stat.S_IMODE(metadata.st_mode)
                if not stat.S_ISDIR(metadata.st_mode) or (mode & 0o022 and not mode & stat.S_ISVTX):
                    raise ExecutionAdapterError("sing-box binary ancestor is unsafely writable")
        try:
            descriptor = os.open(self._binary, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as error:
            raise ExecutionAdapterError("sing-box binary is unavailable") from error
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_uid not in {0, os.geteuid()}
                or before.st_size > _MAX_BINARY_BYTES
                or stat.S_IMODE(before.st_mode) & 0o022
                or not before.st_mode & 0o111
                or not os.access(self._binary, os.X_OK)
            ):
                raise ExecutionAdapterError("sing-box binary is not a safe executable")
            digest = hashlib.sha256()
            while chunk := os.read(descriptor, 1024 * 1024):
                digest.update(chunk)
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
                raise ExecutionAdapterError("sing-box binary changed during validation")
            return _BinaryIdentity(
                device=after.st_dev,
                inode=after.st_ino,
                size=after.st_size,
                modified_ns=after.st_mtime_ns,
                sha256=digest.hexdigest(),
            )
        finally:
            os.close(descriptor)

    async def _create_owned_subprocess(
        self,
        *arguments: str,
        stdout: int,
        pass_fds: tuple[int, ...] = (),
        cwd: str | None = None,
        graceful_cancel: bool = False,
        start_new_session: bool = False,
    ) -> asyncio.subprocess.Process:
        spawn = asyncio.create_task(
            asyncio.create_subprocess_exec(
                *arguments,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=stdout,
                stderr=asyncio.subprocess.DEVNULL,
                pass_fds=pass_fds,
                cwd=cwd,
                env=self._subprocess_environment(),
                start_new_session=start_new_session,
            )
        )
        try:
            return await asyncio.shield(spawn)
        except asyncio.CancelledError as cancellation:
            while not spawn.done():
                try:
                    await asyncio.shield(spawn)
                except asyncio.CancelledError:
                    continue
            try:
                process = spawn.result()
            except BaseException:
                raise cancellation from None
            stop = asyncio.create_task(
                self._terminate_process_group(process)
                if start_new_session
                else self._terminate_process(process, graceful_wait=graceful_cancel)
            )
            while not stop.done():
                try:
                    await asyncio.shield(stop)
                except asyncio.CancelledError:
                    continue
            stop.result()
            raise cancellation

    async def _verify_binary_version(self) -> _BinaryIdentity:
        identity = self._binary_identity()
        try:
            process = await self._create_owned_subprocess(
                str(self._binary),
                "version",
                stdout=asyncio.subprocess.PIPE,
            )
        except OSError as error:
            raise ExecutionAdapterError("sing-box version check could not start") from error
        try:
            assert process.stdout is not None
            output = await process.stdout.read(_MAX_VERSION_OUTPUT + 1)
            if len(output) > _MAX_VERSION_OUTPUT:
                await self._terminate_process(process)
                raise ExecutionAdapterError("sing-box version output exceeded the safety limit")
            returncode = await process.wait()
        except asyncio.CancelledError:
            await self._terminate_process(process)
            raise
        expected_version = f"sing-box version {SING_BOX_VERSION}".encode()
        if (
            returncode != 0
            or not output.splitlines()
            or output.splitlines()[0] != expected_version
            or self._binary_identity() != identity
        ):
            raise ExecutionAdapterError("sing-box binary version is unsupported")
        return identity

    def _load_authority(
        self, plan: FailoverExecutionPlan
    ) -> tuple[AuthorizedCandidateInventory, SingBoxRuntimeMaterial, str]:
        target_binding = plan.target
        if target_binding is None:
            raise ExecutionAdapterError("execution target is unavailable")
        try:
            inventory = self._inventory_loader()
        except Exception as error:
            raise ExecutionAdapterError(
                "authoritative candidate inventory is unavailable"
            ) from error
        candidates = [
            item
            for item in inventory.candidates
            if item.candidate_id == target_binding.candidate.candidate_id
        ]
        if len(candidates) != 1 or not candidates[0].enabled:
            raise ExecutionAdapterError("execution target is no longer uniquely authorized")
        fingerprint = candidate_fingerprint(inventory, candidates[0])
        if fingerprint != target_binding.fingerprint or candidates[0] != target_binding.candidate:
            raise ExecutionAdapterError("execution target authorization changed")
        material = self._material_source.load(plan, inventory)
        if (
            material.candidate_id != candidates[0].candidate_id
            or material.profile_id != candidates[0].profile_id
            or material.protocol != candidates[0].protocol
            or material.endpoint != candidates[0].endpoint
            or material.port != candidates[0].port
        ):
            raise ExecutionAdapterError("client material does not bind to execution target")
        outbound = _validated_outbound(
            material.outbound,
            material.protocol,
            material.endpoint,
            material.port,
        )
        material = SingBoxRuntimeMaterial(
            client_id=material.client_id,
            profile_id=material.profile_id,
            candidate_id=material.candidate_id,
            protocol=material.protocol,
            endpoint=material.endpoint,
            port=material.port,
            outbound=outbound,
        )
        return inventory, material, fingerprint

    @staticmethod
    def _authorized_address(
        inventory: AuthorizedCandidateInventory, plan: FailoverExecutionPlan
    ) -> str:
        assert plan.target is not None
        candidate = plan.target.candidate
        allowed_versions = {4 if family == IPFamily.IPV4 else 6 for family in candidate.ip_families}
        addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for value in inventory.authorized_addresses:
            try:
                address = ipaddress.ip_address(value)
            except ValueError as error:
                raise ExecutionAdapterError("authorized runtime address is malformed") from error
            if address.version in allowed_versions:
                addresses.append(address)
        try:
            endpoint_literal = ipaddress.ip_address(candidate.endpoint)
        except ValueError:
            endpoint_literal = None
        if endpoint_literal is not None:
            addresses = [item for item in addresses if item == endpoint_literal]
        if not addresses:
            raise ExecutionAdapterError("target has no independently authorized runtime address")
        return str(sorted(addresses, key=lambda item: (item.version, int(item)))[0])

    def _reserve_port(self, plan_id: str, ordinal: int) -> socket.socket:
        low, high = self._port_range
        count = high - low + 1
        start = int(plan_id[:16], 16) % count
        port = low + ((start + ordinal) % count)
        reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            reservation.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            reservation.bind(("127.0.0.1", port))
            reservation.listen(1)
            return reservation
        except OSError:
            reservation.close()
            raise

    def _runtime_config(
        self,
        material: SingBoxRuntimeMaterial,
        authorized_address: str,
        port: int,
        local_username: str,
        local_password: str,
    ) -> bytes:
        outbound = dict(material.outbound)
        outbound["server"] = authorized_address
        document = {
            "log": {"level": "warn", "timestamp": True},
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "local-socks",
                    "listen": "127.0.0.1",
                    "listen_port": port,
                    "users": [
                        {
                            "username": local_username,
                            "password": local_password,
                        }
                    ],
                }
            ],
            "outbounds": [outbound],
            "route": {"final": "fluxgate-remote"},
        }
        return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()

    async def _check_config(self, path: Path, binary_identity: _BinaryIdentity) -> None:
        if self._binary_identity() != binary_identity:
            raise ExecutionAdapterError("sing-box binary changed before config validation")
        try:
            process = await self._create_owned_subprocess(
                str(self._binary),
                "check",
                "-c",
                str(path),
                stdout=asyncio.subprocess.DEVNULL,
            )
        except OSError as error:
            raise ExecutionAdapterError("sing-box config validation could not start") from error
        try:
            returncode = await process.wait()
        except asyncio.CancelledError:
            await self._terminate_process(process)
            raise
        if returncode != 0:
            raise ExecutionAdapterError("sing-box rejected the private runtime config")
        if self._binary_identity() != binary_identity:
            raise ExecutionAdapterError("sing-box binary changed during config validation")

    async def _stage_runtime(
        self,
        state: _ScopeState,
        plan: FailoverExecutionPlan,
        material: SingBoxRuntimeMaterial,
        fingerprint: str,
        authorized_address: str,
        binary_identity: _BinaryIdentity,
        ordinal: int,
    ) -> _OwnedRuntime:
        reservation: socket.socket | None = None
        directory: Path | None = None
        try:
            reservation = self._reserve_port(plan.plan_id, ordinal)
        except OSError as error:
            raise ExecutionAdapterError("local SOCKS port is unavailable") from error
        try:
            directory = Path(tempfile.mkdtemp(prefix="runtime-", dir=state.directory))
            directory.chmod(0o700)
            config_path = directory / "config.json"
            local_username = secrets.token_urlsafe(24)
            local_password = secrets.token_urlsafe(32)
            content = self._runtime_config(
                material,
                authorized_address,
                reservation.getsockname()[1],
                local_username,
                local_password,
            )
            atomic_write(config_path, content, 0o600)
            runtime = _OwnedRuntime(
                candidate_fingerprint=fingerprint,
                directory=directory,
                config_path=config_path,
                config_sha256=hashlib.sha256(content).hexdigest(),
                binary_identity=binary_identity,
                port=reservation.getsockname()[1],
                local_username=local_username,
                local_password=local_password,
                reservation=reservation,
            )
            await self._check_config(config_path, binary_identity)
            if not self._runtime_files_valid(runtime):
                raise ExecutionAdapterError("sing-box runtime config changed after validation")
            return runtime
        except BaseException:
            reservation.close()
            if directory is not None and directory.exists():
                self._remove_runtime_directory(directory)
            raise

    async def is_active_and_verified(self, plan: FailoverExecutionPlan) -> bool:
        state = self._scopes.get(plan.execution_scope)
        if state is None or state.active is None or plan.target is None:
            return False
        runtime = state.active
        try:
            inventory, material, fingerprint = self._load_authority(plan)
            authorized_address = self._authorized_address(inventory, plan)
            expected_config = self._runtime_config(
                material,
                authorized_address,
                runtime.port,
                runtime.local_username,
                runtime.local_password,
            )
            binary_identity = self._binary_identity()
        except ExecutionAdapterError:
            return False
        if (
            runtime.candidate_fingerprint != plan.target.fingerprint
            or runtime.candidate_fingerprint != fingerprint
            or hashlib.sha256(expected_config).hexdigest() != runtime.config_sha256
            or binary_identity != runtime.binary_identity
        ):
            return False
        if not self._runtime_files_valid(runtime):
            return False
        return await self._socks_handshake(runtime)

    async def prepare(self, plan: FailoverExecutionPlan) -> None:
        inventory, material, fingerprint = self._load_authority(plan)
        authorized_address = self._authorized_address(inventory, plan)
        binary_identity = await self._verify_binary_version()
        state = await self._acquire_scope(plan.execution_scope)
        if (
            state.active is not None
            and state.active.process is not None
            and state.active.process.returncode is not None
        ):
            await self._stop_runtime(state.active)
            state.active = None
        if state.staged is not None:
            raise ExecutionAdapterError("sing-box execution scope already has a staged runtime")
        prepared: list[_OwnedRuntime] = []
        last_error: ExecutionAdapterError | None = None
        allocation_start = self._port_cursor
        port_count = self._port_range[1] - self._port_range[0] + 1
        self._port_cursor = (self._port_cursor + self._port_attempts) % port_count
        try:
            for ordinal in range(self._port_attempts):
                try:
                    prepared.append(
                        await self._stage_runtime(
                            state,
                            plan,
                            material,
                            fingerprint,
                            authorized_address,
                            binary_identity,
                            allocation_start + ordinal,
                        )
                    )
                except ExecutionAdapterError as error:
                    last_error = error
                    continue
        except BaseException:
            for runtime in prepared:
                await self._stop_runtime(runtime)
            raise
        if not prepared:
            raise last_error or ExecutionAdapterError("no local SOCKS port could be reserved")
        state.staged, *state.fallbacks = prepared

    async def _start_guardian(self, state: _ScopeState, runtime: _OwnedRuntime) -> None:
        if runtime.reservation is None:
            raise ExecutionAdapterError("local SOCKS port reservation is missing")
        if (
            not self._runtime_files_valid(runtime)
            or self._binary_identity() != runtime.binary_identity
        ):
            raise ExecutionAdapterError("validated sing-box runtime changed before activation")
        runtime.reservation.close()
        runtime.reservation = None
        read_fd, write_fd = os.pipe()
        os.set_inheritable(read_fd, True)
        guardian = Path(__file__).with_name("_singbox_guardian.py")
        try:
            guardian_metadata = guardian.lstat()
        except OSError as error:
            os.close(read_fd)
            os.close(write_fd)
            raise ExecutionAdapterError("sing-box guardian is unavailable") from error
        if (
            not stat.S_ISREG(guardian_metadata.st_mode)
            or stat.S_ISLNK(guardian_metadata.st_mode)
            or guardian_metadata.st_nlink != 1
            or guardian_metadata.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(guardian_metadata.st_mode) & 0o022
        ):
            os.close(read_fd)
            os.close(write_fd)
            raise ExecutionAdapterError("sing-box guardian is unsafe")
        try:
            process = await self._create_owned_subprocess(
                sys.executable,
                str(guardian),
                str(read_fd),
                str(state.lock_fd),
                str(self._binary),
                str(runtime.config_path),
                stdout=asyncio.subprocess.DEVNULL,
                pass_fds=(read_fd, state.lock_fd),
                cwd=str(runtime.directory),
                start_new_session=True,
            )
        except asyncio.CancelledError:
            os.close(read_fd)
            os.close(write_fd)
            raise
        except OSError as error:
            os.close(read_fd)
            os.close(write_fd)
            raise ExecutionAdapterError("sing-box guardian could not start") from error
        except BaseException:
            os.close(read_fd)
            os.close(write_fd)
            raise
        os.close(read_fd)
        runtime.process = process
        runtime.control_fd = write_fd
        if (
            not self._runtime_files_valid(runtime)
            or self._binary_identity() != runtime.binary_identity
        ):
            raise ExecutionAdapterError("sing-box runtime changed during activation")

    @staticmethod
    def _subprocess_environment() -> dict[str, str]:
        return {
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.defpath,
            "PYTHONNOUSERSITE": "1",
        }

    async def activate(self, plan: FailoverExecutionPlan) -> None:
        state = self._scopes.get(plan.execution_scope)
        if state is None or state.staged is None:
            raise ExecutionAdapterError("sing-box target runtime was not prepared")
        while state.staged is not None:
            runtime = state.staged
            await self._start_guardian(state, runtime)
            process = runtime.process
            assert process is not None
            for _ in range(10):
                if process.returncode is not None:
                    break
                if await self._listener_accepts(runtime.port):
                    return
                await asyncio.sleep(0.02)
            if process.returncode is None:
                return
            await self._stop_runtime(runtime)
            state.staged = state.fallbacks.pop(0) if state.fallbacks else None
        raise ExecutionAdapterError("sing-box target process exited during bounded startup retries")

    async def verify(self, plan: FailoverExecutionPlan) -> bool:
        state = self._scopes.get(plan.execution_scope)
        if state is None or state.staged is None:
            return False
        runtime = state.staged
        if not self._runtime_files_valid(runtime):
            return False
        for _ in range(50):
            if runtime.process is None or runtime.process.returncode is not None:
                return False
            if await self._socks_handshake(runtime):
                return True
            await asyncio.sleep(0.02)
        return False

    async def commit(self, plan: FailoverExecutionPlan) -> None:
        state = self._scopes.get(plan.execution_scope)
        if state is None or state.staged is None:
            raise ExecutionAdapterError("sing-box target runtime is unavailable for commit")
        state.previous = state.active
        state.active = state.staged
        state.staged = None
        state.committed_plan_id = plan.plan_id

    async def rollback(self, plan: FailoverExecutionPlan) -> None:
        state = self._scopes.get(plan.execution_scope)
        if state is None:
            return
        if state.staged is not None:
            await self._stop_runtime(state.staged)
            state.staged = None
        for fallback in state.fallbacks:
            await self._stop_runtime(fallback)
        state.fallbacks.clear()
        if state.committed_plan_id == plan.plan_id and state.active is not None:
            await self._stop_runtime(state.active)
            state.active = state.previous
            state.previous = None
            state.committed_plan_id = None

    async def cleanup(self, plan: FailoverExecutionPlan) -> None:
        state = self._scopes.get(plan.execution_scope)
        if state is None:
            return
        if state.committed_plan_id == plan.plan_id:
            if state.previous is not None:
                await self._stop_runtime(state.previous)
                state.previous = None
            state.committed_plan_id = None
        if state.staged is not None:
            await self._stop_runtime(state.staged)
            state.staged = None
        for fallback in state.fallbacks:
            await self._stop_runtime(fallback)
        state.fallbacks.clear()
        if state.active is None:
            self._release_scope(plan.execution_scope, state)

    async def close(self) -> None:
        """Stop every runtime owned by this adapter and release host scope locks."""
        for scope, state in tuple(self._scopes.items()):
            seen: set[int] = set()
            for runtime in (
                state.staged,
                *state.fallbacks,
                state.previous,
                state.active,
            ):
                if runtime is not None and id(runtime) not in seen:
                    seen.add(id(runtime))
                    await self._stop_runtime(runtime)
            self._release_scope(scope, state)

    async def _listener_accepts(self, port: int) -> bool:
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            return False
        writer.close()
        with suppress(OSError):
            await writer.wait_closed()
        return True

    async def _socks_handshake(self, runtime: _OwnedRuntime) -> bool:
        if runtime.process is None or runtime.process.returncode is not None:
            return False
        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", runtime.port)
            writer.write(b"\x05\x01\x02")
            await writer.drain()
            response = await reader.readexactly(2)
            if response != b"\x05\x02":
                return False
            username = runtime.local_username.encode("ascii")
            password = runtime.local_password.encode("ascii")
            writer.write(
                b"\x01" + bytes((len(username),)) + username + bytes((len(password),)) + password
            )
            await writer.drain()
            return await reader.readexactly(2) == b"\x01\x00"
        except (OSError, asyncio.IncompleteReadError):
            return False
        finally:
            if writer is not None:
                writer.close()
                with suppress(OSError):
                    await writer.wait_closed()

    @staticmethod
    def _runtime_files_valid(runtime: _OwnedRuntime) -> bool:
        try:
            metadata = runtime.config_path.lstat()
            directory_metadata = runtime.directory.lstat()
            return (
                stat.S_ISDIR(directory_metadata.st_mode)
                and not stat.S_ISLNK(directory_metadata.st_mode)
                and directory_metadata.st_uid == os.geteuid()
                and stat.S_IMODE(directory_metadata.st_mode) == 0o700
                and stat.S_ISREG(metadata.st_mode)
                and not stat.S_ISLNK(metadata.st_mode)
                and metadata.st_uid == os.geteuid()
                and metadata.st_nlink == 1
                and stat.S_IMODE(metadata.st_mode) == 0o600
                and hashlib.sha256(runtime.config_path.read_bytes()).hexdigest()
                == runtime.config_sha256
            )
        except OSError:
            return False

    async def _stop_runtime(self, runtime: _OwnedRuntime) -> None:
        if runtime.reservation is not None:
            runtime.reservation.close()
            runtime.reservation = None
        if runtime.control_fd is not None:
            with suppress(OSError):
                os.close(runtime.control_fd)
            runtime.control_fd = None
        if runtime.process is not None:
            process = runtime.process
            await self._terminate_process_group(process)
            runtime.process = None
        self._remove_runtime_directory(runtime.directory)

    @staticmethod
    async def _terminate_process(
        process: asyncio.subprocess.Process, *, graceful_wait: bool = False
    ) -> None:
        if process.returncode is not None:
            return
        if graceful_wait:
            try:
                await asyncio.wait_for(process.wait(), timeout=2.5)
                return
            except asyncio.TimeoutError:
                pass
        with suppress(ProcessLookupError):
            process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=1.0)
        except asyncio.TimeoutError:
            with suppress(ProcessLookupError):
                process.kill()
            await process.wait()

    @staticmethod
    async def _terminate_process_group(process: asyncio.subprocess.Process) -> None:
        group = process.pid
        with suppress(ProcessLookupError, PermissionError):
            os.killpg(group, signal.SIGTERM)
        if process.returncode is None:
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(process.wait(), timeout=1.0)
        await asyncio.sleep(0)
        try:
            os.killpg(group, 0)
        except (ProcessLookupError, PermissionError):
            return
        with suppress(ProcessLookupError, PermissionError):
            os.killpg(group, signal.SIGKILL)
        if process.returncode is None:
            await process.wait()

    @classmethod
    def _remove_runtime_directory(cls, directory: Path) -> None:
        if directory.is_symlink() or not directory.is_dir():
            raise ExecutionAdapterError("refusing to remove unsafe sing-box runtime")
        for entry in os.scandir(directory):
            path = Path(entry.path)
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                cls._remove_runtime_directory(path)
            elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                path.unlink()
            else:
                raise ExecutionAdapterError("sing-box runtime contains an unsafe entry")
        directory.rmdir()

    def _release_scope(self, scope: str, state: _ScopeState) -> None:
        if self._scopes.get(scope) is not state:
            return
        marker = state.directory / ".owner"
        try:
            if marker.is_file() and not marker.is_symlink() and marker.read_bytes() == _OWNER:
                marker.unlink()
                state.directory.rmdir()
        finally:
            fcntl.flock(state.lock_fd, fcntl.LOCK_UN)
            os.close(state.lock_fd)
            del self._scopes[scope]


def discover_singbox_binary(explicit: Path | None = None) -> Path | None:
    """Discover an already-installed executable without downloading or mutating the host."""
    if explicit is not None:
        return explicit
    found = shutil.which("sing-box")
    if found is None:
        return None
    try:
        return Path(found).resolve(strict=True)
    except OSError:
        return None


def singbox_local_proxy_capability() -> ExecutionCapability:
    """Return the adapter declaration without constructing or mutating a runtime."""
    return ExecutionCapability(
        adapter_id="singbox-local-proxy-v1",
        strategy=ExecutionStrategy.MAKE_BEFORE_BREAK,
        supported_providers=(PathfinderProvider.SINGBOX,),
        supported_protocols=(PathfinderProtocol.VLESS, PathfinderProtocol.TROJAN),
        supported_transports=(PathfinderTransport.TCP,),
        supported_security=(PathfinderSecurity.TLS,),
        supported_connection_modes=(ConnectionMode.LOCAL_PROXY,),
        verification=(
            "local sing-box process and SOCKS5 protocol verified; remote connectivity not verified"
        ),
    )
