from __future__ import annotations

import asyncio
import hashlib
import json
import multiprocessing
import os
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

import pytest
from typer.main import get_command
from typer.testing import CliRunner

import fluxgate.cli.pathfinder_execution as pathfinder_execution_cli
from fluxgate.bootstrap import verify_bootstrap
from fluxgate.bootstrap.models import BootstrapArtifact, BootstrapDescriptor
from fluxgate.cli.app import app
from fluxgate.core.commands import CommandRunner
from fluxgate.core.errors import PathfinderError, VerificationError
from fluxgate.core.manifest import ManifestServer, ServerManifest
from fluxgate.core.models import (
    Client,
    ProfileDefinition,
    ProtocolName,
    SecurityName,
    TransportName,
)
from fluxgate.core.state import atomic_write
from fluxgate.identity import ServerIdentityManager
from fluxgate.manifest.service import load_trust
from fluxgate.pathfinder.active_models import AuthorizationSource, FailoverAction, FailoverDecision
from fluxgate.pathfinder.authorization import AuthorizedCandidateInventory, authorize_manifest
from fluxgate.pathfinder.execution import (
    ExecutionAdapterError,
    ExecutionCancellation,
    FailoverExecutor,
)
from fluxgate.pathfinder.execution_models import (
    ExecutionPolicy,
    ExecutionStatus,
    FailoverExecutionPlan,
)
from fluxgate.pathfinder.execution_planning import plan_failover_execution
from fluxgate.pathfinder.models import (
    ConnectionCandidate,
    ConnectionMode,
    IPFamily,
    PathfinderProtocol,
    PathfinderProvider,
    PathfinderSecurity,
    PathfinderTransport,
)
from fluxgate.pathfinder.singbox_adapter import (
    SingBoxLocalProxyAdapter,
    SingBoxRuntimeMaterial,
    VerifiedBootstrapSingBoxMaterialSource,
    discover_singbox_binary,
)
from fluxgate.providers.singbox.rendering import render_client
from fluxgate.providers.singbox.tls import ManagedTLSIdentityManager

CLIENT_ID = UUID("10000000-0000-0000-0000-000000000001")
PROFILE_ID = UUID("20000000-0000-0000-0000-000000000002")
SENTINEL_UUID = "12345678-1234-5678-1234-567812345678"
SENTINEL_PASSWORD = "TROJAN-PASSWORD-SENTINEL"  # noqa: S105
SENTINEL_TLS = "-----BEGIN PRIVATE KEY-----\nTLS-SENTINEL\n-----END PRIVATE KEY-----"


def _bootstrap_digest(root: Path) -> str:
    return hashlib.sha256((root / "bootstrap.json").read_bytes()).hexdigest()


@dataclass(frozen=True)
class Scenario:
    root: Path
    trust_path: Path
    inventory: AuthorizedCandidateInventory
    plan: FailoverExecutionPlan
    adapter: SingBoxLocalProxyAdapter
    binary: Path
    mode_path: Path
    runtime_root: Path


def _fake_singbox(tmp_path: Path) -> tuple[Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    binary = tmp_path / "fake-sing-box"
    mode_path = tmp_path / "fake-sing-box.mode"
    script = f"""#!{sys.executable}
import json
import os
import pathlib
import signal
import socket
import sys
import time

mode_path = pathlib.Path(__file__).with_suffix('.mode')
mode = mode_path.read_text().strip() if mode_path.exists() else 'success'
if len(sys.argv) == 2 and sys.argv[1] == 'version':
    if mode == 'version_fail':
        raise SystemExit(3)
    if mode == 'version_flood':
        print('x' * 10000)
        raise SystemExit(0)
    if mode == 'version_impostor':
        print('sing-box version 1.13.190')
        raise SystemExit(0)
    print('sing-box version 1.13.19')
    if mode == 'credential_output':
        print({SENTINEL_UUID!r})
        print({SENTINEL_PASSWORD!r}, file=sys.stderr)
        print({SENTINEL_TLS!r}, file=sys.stderr)
    raise SystemExit(0)
if len(sys.argv) != 4 or sys.argv[2] != '-c':
    raise SystemExit(64)
config = json.loads(pathlib.Path(sys.argv[3]).read_text())
if sys.argv[1] == 'check':
    if mode == 'check_fail':
        print('{SENTINEL_PASSWORD}', file=sys.stderr)
        raise SystemExit(4)
    if mode == 'second_check_hang':
        count_path = mode_path.with_suffix('.count')
        count = int(count_path.read_text()) if count_path.exists() else 0
        count_path.write_text(str(count + 1))
        if count >= 1:
            while True:
                time.sleep(1)
    remote = config['outbounds'][0]
    if mode == 'credential_output':
        print({SENTINEL_UUID!r})
        print({SENTINEL_PASSWORD!r}, file=sys.stderr)
        print({SENTINEL_TLS!r}, file=sys.stderr)
    family = socket.AF_INET6 if ':' in remote['server'] else socket.AF_INET
    socket.inet_pton(family, remote['server'])
    assert remote['tls']['enabled'] is True
    assert 'insecure' not in remote['tls']
    raise SystemExit(0)
if sys.argv[1] != 'run' or mode == 'immediate_exit':
    print('{SENTINEL_UUID}', file=sys.stderr)
    raise SystemExit(5)
mode_path.with_suffix('.started').write_text('started')
mode_path.with_suffix('.pid').write_text(str(os.getpid()))
if mode == 'ignore_term':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
if mode == 'credential_output':
    print('{SENTINEL_UUID}')
    print('{SENTINEL_PASSWORD}', file=sys.stderr)
if mode == 'no_listener':
    while True:
        time.sleep(1)
if mode == 'delayed_start':
    time.sleep(0.3)
inbound = config['inbounds'][0]
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((inbound['listen'], inbound['listen_port']))
server.listen()

def receive_exact(connection, size):
    content = b''
    while len(content) < size:
        chunk = connection.recv(size - len(content))
        if not chunk:
            break
        content += chunk
    return content

while True:
    connection, _ = server.accept()
    with connection:
        request = connection.recv(3)
        if request:
            if mode == 'malformed_socks' or request != b'\\x05\\x01\\x02':
                connection.sendall(b'\\x05\\xff')
                continue
            connection.sendall(b'\\x05\\x02')
            header = receive_exact(connection, 2)
            if len(header) != 2 or header[0] != 1:
                continue
            username = receive_exact(connection, header[1]).decode()
            password_length = receive_exact(connection, 1)
            if not password_length:
                continue
            password = receive_exact(connection, password_length[0]).decode()
            user = inbound['users'][0]
            accepted = username == user['username'] and password == user['password']
            connection.sendall(b'\\x01\\x00' if accepted else b'\\x01\\x01')
"""
    binary.write_text(script)
    binary.chmod(0o755)
    return binary, mode_path


def _profile(protocol: PathfinderProtocol) -> ProfileDefinition:
    return ProfileDefinition(
        id=PROFILE_ID,
        name=protocol.value,
        protocol=ProtocolName(protocol.value),
        transport=TransportName.TCP,
        security=SecurityName.TLS,
        listen_port=8443,
        enabled=True,
    )


def _candidate(
    protocol: PathfinderProtocol = PathfinderProtocol.VLESS,
    *,
    endpoint: str = "vpn.example.test",
) -> ConnectionCandidate:
    return ConnectionCandidate(
        candidate_id=f"profile:{PROFILE_ID}",
        provider=PathfinderProvider.SINGBOX,
        profile_id=PROFILE_ID,
        protocol=protocol,
        transport=PathfinderTransport.TCP,
        security=PathfinderSecurity.TLS,
        connection_mode=ConnectionMode.LOCAL_PROXY,
        endpoint=endpoint,
        port=8443,
        socket_protocol="tcp",
        ip_families=(IPFamily.IPV4, IPFamily.IPV6),
    )


def _write_bundle(
    provider_context,
    root: Path,
    candidate: ConnectionCandidate,
    *,
    client_id: UUID = CLIENT_ID,
    artifact_candidate_id: str | None = None,
    artifact_profile_id: UUID = PROFILE_ID,
) -> Path:
    identity_manager = ServerIdentityManager(provider_context.paths)
    identity = identity_manager.ensure()
    manifest = ServerManifest(
        server=ManifestServer(
            identity=candidate.endpoint,
            server_id=identity.metadata.server_id,
        ),
        candidates=(candidate,),
    )
    manifest_bytes = manifest.render()
    profile = _profile(candidate.protocol)
    credential = (
        {"schema_version": 1, "uuid": SENTINEL_UUID}
        if candidate.protocol == PathfinderProtocol.VLESS
        else {"schema_version": 1, "password": SENTINEL_PASSWORD}
    )
    client = Client(
        id=client_id,
        name="alice",
        profile_credentials={str(PROFILE_ID): credential},
    )
    artifact_content = render_client(client, profile, candidate.endpoint, SENTINEL_TLS).encode()
    artifact_path = f"singbox/profile-{artifact_profile_id.hex}.json"
    descriptor = BootstrapDescriptor(
        server_id=identity.metadata.server_id,
        client_id=client_id,
        client_name=client.name,
        created_at=identity.metadata.created_at,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        artifacts=(
            BootstrapArtifact(
                path=artifact_path,
                provider=PathfinderProvider.SINGBOX,
                candidate_id=artifact_candidate_id or candidate.candidate_id,
                media_type="application/json",
                sha256=hashlib.sha256(artifact_content).hexdigest(),
                connection_mode=ConnectionMode.LOCAL_PROXY,
            ),
        ),
    )
    bootstrap_bytes = (
        json.dumps(descriptor.model_dump(mode="json"), indent=2, sort_keys=True).encode() + b"\n"
    )
    root.mkdir(mode=0o700)
    (root / "singbox").mkdir(mode=0o700)
    files = {
        "trust.json": (identity.trust.render(), 0o644),
        "manifest.json": (manifest_bytes, 0o644),
        "manifest.sig": (identity_manager.sign(manifest_bytes, identity), 0o644),
        "bootstrap.json": (bootstrap_bytes, 0o600),
        "bootstrap.sig": (identity_manager.sign(bootstrap_bytes, identity), 0o600),
        artifact_path: (artifact_content, 0o600),
    }
    for name, (content, mode) in files.items():
        atomic_write(root / name, content, mode)
    assert verify_bootstrap(root, pinned_trust=identity.trust).valid
    return root / "trust.json"


def _rotate_bundle_credential(provider_context, scenario: Scenario, credential: str) -> None:
    artifact_path = next((scenario.root / "singbox").glob("*.json"))
    document = json.loads(artifact_path.read_bytes())
    remote = document["outbounds"][0]
    key = "uuid" if remote["type"] == "vless" else "password"
    remote[key] = credential
    content = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    descriptor = BootstrapDescriptor.model_validate_json(
        (scenario.root / "bootstrap.json").read_bytes()
    )
    artifacts = tuple(
        item.model_copy(update={"sha256": hashlib.sha256(content).hexdigest()})
        if item.path == artifact_path.relative_to(scenario.root).as_posix()
        else item
        for item in descriptor.artifacts
    )
    descriptor = descriptor.model_copy(update={"artifacts": artifacts})
    bootstrap_bytes = (
        json.dumps(descriptor.model_dump(mode="json"), indent=2, sort_keys=True).encode() + b"\n"
    )
    identity_manager = ServerIdentityManager(provider_context.paths)
    identity = identity_manager.ensure()
    atomic_write(artifact_path, content, 0o600)
    atomic_write(scenario.root / "bootstrap.json", bootstrap_bytes, 0o600)
    atomic_write(
        scenario.root / "bootstrap.sig",
        identity_manager.sign(bootstrap_bytes, identity),
        0o600,
    )
    assert verify_bootstrap(scenario.root, pinned_trust=identity.trust).valid


def _scenario(
    provider_context,
    tmp_path: Path,
    *,
    protocol: PathfinderProtocol = PathfinderProtocol.VLESS,
    endpoint: str = "vpn.example.test",
    pins: tuple[str, ...] = ("192.0.2.10", "2001:db8::1"),
    port_range: tuple[int, int] = (20000, 60999),
    port_attempts: int = 4,
    expected_client_id: UUID = CLIENT_ID,
    artifact_candidate_id: str | None = None,
    artifact_profile_id: UUID = PROFILE_ID,
) -> Scenario:
    binary, mode_path = _fake_singbox(tmp_path)
    candidate = _candidate(protocol, endpoint=endpoint)
    root = tmp_path / "bundle"
    trust_path = _write_bundle(
        provider_context,
        root,
        candidate,
        artifact_candidate_id=artifact_candidate_id,
        artifact_profile_id=artifact_profile_id,
    )
    trust = load_trust(trust_path)
    manifest = ServerManifest.model_validate_json((root / "manifest.json").read_bytes())
    inventory = authorize_manifest(
        manifest,
        source=AuthorizationSource.SIGNED_MANIFEST,
        trusted_server_id=trust.server_id,
        trusted_endpoint=endpoint,
        trusted_addresses=pins,
    )
    runtime_root = tmp_path / "runtime"
    material = VerifiedBootstrapSingBoxMaterialSource(
        root,
        pinned_trust=trust,
        expected_client_id=expected_client_id,
        expected_bootstrap_sha256=_bootstrap_digest(root),
    )
    adapter = SingBoxLocalProxyAdapter(
        lambda: inventory,
        material,
        binary=binary,
        runtime_root=runtime_root,
        port_range=port_range,
        port_attempts=port_attempts,
        lock_timeout_seconds=0.2,
        port_selection_seed=0,
    )
    plan = plan_failover_execution(
        inventory,
        FailoverDecision(
            action=FailoverAction.SWITCH,
            current_candidate_id=None,
            target_candidate_id=candidate.candidate_id,
            reason="verified target selected",
        ),
        (adapter.capability,),
        ExecutionPolicy(),
        execution_scope="client-a:local-proxy",
    )
    return Scenario(
        root=root,
        trust_path=trust_path,
        inventory=inventory,
        plan=plan,
        adapter=adapter,
        binary=binary,
        mode_path=mode_path,
        runtime_root=runtime_root,
    )


async def _execute(scenario: Scenario):
    executor = FailoverExecutor(lambda: scenario.inventory)
    return await executor.execute(scenario.plan, scenario.adapter)


@pytest.mark.parametrize("protocol", [PathfinderProtocol.VLESS, PathfinderProtocol.TROJAN])
def test_real_subprocess_executes_supported_candidate_with_pinned_destination(
    provider_context, tmp_path: Path, protocol: PathfinderProtocol
) -> None:
    scenario = _scenario(provider_context, tmp_path, protocol=protocol)

    async def run() -> tuple[object, dict[str, object], tuple[str, int]]:
        result = await _execute(scenario)
        assert result.status == ExecutionStatus.COMMITTED, result
        endpoint = scenario.adapter.active_endpoints[scenario.plan.execution_scope]
        config_path = next(scenario.runtime_root.rglob("config.json"))
        document = json.loads(config_path.read_bytes())
        await scenario.adapter.close()
        return result, document, endpoint

    result, document, endpoint = asyncio.run(run())
    assert result.status == ExecutionStatus.COMMITTED  # type: ignore[union-attr]
    assert endpoint[0] == "127.0.0.1"
    assert document["inbounds"][0]["listen"] == "127.0.0.1"  # type: ignore[index]
    remote = document["outbounds"][0]  # type: ignore[index]
    assert remote["server"] == "192.0.2.10"
    assert remote["tls"]["server_name"] == "vpn.example.test"
    assert remote["tls"]["enabled"] is True
    assert "insecure" not in remote["tls"]
    assert not list(scenario.runtime_root.rglob("config.json"))


def test_literal_ip_stays_literal_and_uses_ip_tls_identity(
    provider_context, tmp_path: Path
) -> None:
    scenario = _scenario(
        provider_context,
        tmp_path,
        endpoint="192.0.2.25",
        pins=("192.0.2.25",),
    )

    async def run() -> dict[str, object]:
        result = await _execute(scenario)
        assert result.status == ExecutionStatus.COMMITTED
        document = json.loads(next(scenario.runtime_root.rglob("config.json")).read_bytes())
        await scenario.adapter.close()
        return document

    document = asyncio.run(run())
    remote = document["outbounds"][0]  # type: ignore[index]
    assert remote["server"] == "192.0.2.25"
    assert remote["tls"]["server_name"] == "192.0.2.25"


def test_loopback_proxy_requires_ephemeral_authentication(provider_context, tmp_path: Path) -> None:
    scenario = _scenario(provider_context, tmp_path)

    async def run() -> tuple[object, str, str, str, str]:
        result = await _execute(scenario)
        access = scenario.adapter.active_proxies[scenario.plan.execution_scope]
        assert scenario.adapter.active_endpoints[scenario.plan.execution_scope] == (
            access.host,
            access.port,
        )
        reader, writer = await asyncio.open_connection(access.host, access.port)
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        response = await reader.readexactly(2)
        writer.close()
        await writer.wait_closed()
        await scenario.adapter.close()
        return result, response.hex(), repr(access), access.username, access.password

    result, response, access_repr, username, password = asyncio.run(run())
    assert result.status == ExecutionStatus.COMMITTED  # type: ignore[union-attr]
    assert response == "05ff"
    assert username not in access_repr and password not in access_repr
    assert "username" not in access_repr and "password" not in access_repr


def test_hostname_runtime_can_use_only_authorized_ipv6_without_live_dns(
    provider_context, tmp_path: Path
) -> None:
    scenario = _scenario(provider_context, tmp_path, pins=("2001:db8::1",))

    async def run() -> dict[str, object]:
        result = await _execute(scenario)
        assert result.status == ExecutionStatus.COMMITTED
        document = json.loads(next(scenario.runtime_root.rglob("config.json")).read_bytes())
        await scenario.adapter.close()
        return document

    document = asyncio.run(run())
    remote = document["outbounds"][0]  # type: ignore[index]
    assert remote["server"] == "2001:db8::1"
    assert remote["tls"]["server_name"] == "vpn.example.test"


def test_real_singbox_parser_accepts_ipv4_and_ipv6_pinned_runtime_configs(
    provider_context, tmp_path: Path
) -> None:
    binary = os.environ.get("SING_BOX_TEST_BINARY")
    if binary is None:
        pytest.skip("set SING_BOX_TEST_BINARY for pinned runtime parser validation")
    provider_context.runner = CommandRunner()
    identity = ManagedTLSIdentityManager(provider_context).ensure("vpn.example.test")
    scenario = _scenario(provider_context, tmp_path / "scenario")
    client = Client(name="parser-client")
    runner = CommandRunner()
    for protocol, credential in (
        (PathfinderProtocol.VLESS, {"schema_version": 1, "uuid": SENTINEL_UUID}),
        (
            PathfinderProtocol.TROJAN,
            {"schema_version": 1, "password": SENTINEL_PASSWORD},
        ),
    ):
        profile = _profile(protocol)
        client.profile_credentials = {str(PROFILE_ID): credential}
        exported = json.loads(
            render_client(
                client,
                profile,
                "vpn.example.test",
                identity.ca_certificate.read_text(),
            )
        )
        material = SingBoxRuntimeMaterial(
            client_id=CLIENT_ID,
            profile_id=PROFILE_ID,
            candidate_id=f"profile:{PROFILE_ID}",
            protocol=protocol,
            endpoint="vpn.example.test",
            port=8443,
            outbound=exported["outbounds"][0],
        )
        for index, address in enumerate(("192.0.2.10", "2001:db8::1")):
            config = tmp_path / f"{protocol.value}-{index}.json"
            config.write_bytes(
                scenario.adapter._runtime_config(
                    material,
                    address,
                    35000 + index,
                    "parser-user",
                    "parser-password",
                )
            )
            document = json.loads(config.read_bytes())
            assert document["outbounds"][0]["server"] == address
            assert document["outbounds"][0]["tls"]["server_name"] == "vpn.example.test"
            runner.run([binary, "check", "-c", str(config)])


def test_already_converged_reuses_process_port_and_config(provider_context, tmp_path: Path) -> None:
    scenario = _scenario(provider_context, tmp_path)

    async def run() -> tuple[object, object, tuple[str, int], tuple[str, int], int]:
        first = await _execute(scenario)
        before = scenario.adapter.active_endpoints[scenario.plan.execution_scope]
        configs_before = len(list(scenario.runtime_root.rglob("config.json")))
        second = await _execute(scenario)
        after = scenario.adapter.active_endpoints[scenario.plan.execution_scope]
        await scenario.adapter.close()
        return first, second, before, after, configs_before

    first, second, before, after, configs = asyncio.run(run())
    assert first.status == ExecutionStatus.COMMITTED  # type: ignore[union-attr]
    assert second.status == ExecutionStatus.ALREADY_CONVERGED  # type: ignore[union-attr]
    assert before == after and configs == 1


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("version_fail", ExecutionStatus.ROLLED_BACK),
        ("version_flood", ExecutionStatus.ROLLED_BACK),
        ("version_impostor", ExecutionStatus.ROLLED_BACK),
        ("check_fail", ExecutionStatus.ROLLED_BACK),
        ("immediate_exit", ExecutionStatus.ROLLED_BACK),
        ("no_listener", ExecutionStatus.ROLLED_BACK),
        ("malformed_socks", ExecutionStatus.ROLLED_BACK),
        ("delayed_start", ExecutionStatus.COMMITTED),
    ],
)
def test_binary_startup_and_socks_failures_are_bounded_and_recovered(
    provider_context, tmp_path: Path, mode: str, expected: ExecutionStatus
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    scenario.mode_path.write_text(mode)

    async def run():
        result = await _execute(scenario)
        await scenario.adapter.close()
        return result

    result = asyncio.run(run())
    assert result.status == expected
    assert not list(scenario.runtime_root.rglob("config.json"))


def test_missing_nonexecutable_writable_and_symlinked_binary_fail_closed(
    provider_context, tmp_path: Path
) -> None:
    for case in ("missing", "nonexec", "writable", "symlink", "oversized"):
        case_root = tmp_path / case
        case_root.mkdir()
        scenario = _scenario(provider_context, case_root)
        if case == "missing":
            scenario.binary.unlink()
        elif case == "nonexec":
            scenario.binary.chmod(0o600)
        elif case == "writable":
            scenario.binary.chmod(0o777)
        else:
            if case == "symlink":
                real = case_root / "real-binary"
                scenario.binary.rename(real)
                scenario.binary.symlink_to(real)
            else:
                with scenario.binary.open("ab") as stream:
                    stream.truncate(129 * 1024 * 1024)

        async def run(selected: Scenario = scenario):
            result = await _execute(selected)
            await selected.adapter.close()
            return result

        result = asyncio.run(run())
        assert result.status == ExecutionStatus.ROLLED_BACK

    scenario = _scenario(provider_context, tmp_path / "unsafe-parent-case")
    unsafe_parent = tmp_path / "unsafe-binary-parent"
    unsafe_parent.mkdir(mode=0o777)
    unsafe_parent.chmod(0o777)
    unsafe_binary = unsafe_parent / "sing-box"
    unsafe_binary.write_bytes(scenario.binary.read_bytes())
    unsafe_binary.chmod(0o755)
    adapter = SingBoxLocalProxyAdapter(
        lambda: scenario.inventory,
        VerifiedBootstrapSingBoxMaterialSource(
            scenario.root,
            pinned_trust=load_trust(scenario.trust_path),
            expected_client_id=CLIENT_ID,
            expected_bootstrap_sha256=_bootstrap_digest(scenario.root),
        ),
        binary=unsafe_binary,
        runtime_root=scenario.runtime_root,
    )

    async def reject_unsafe_parent() -> object:
        result = await FailoverExecutor(lambda: scenario.inventory).execute(
            scenario.plan,
            adapter,
        )
        await adapter.close()
        return result

    assert asyncio.run(reject_unsafe_parent()).status == ExecutionStatus.ROLLED_BACK


def test_private_runtime_permissions_and_secret_safe_process_output(
    provider_context, tmp_path: Path
) -> None:
    scenario = _scenario(provider_context, tmp_path, protocol=PathfinderProtocol.TROJAN)
    scenario.mode_path.write_text("credential_output")

    async def run() -> tuple[object, str, int, int]:
        result = await _execute(scenario)
        config = next(scenario.runtime_root.rglob("config.json"))
        modes = (stat.S_IMODE(config.parent.stat().st_mode), stat.S_IMODE(config.stat().st_mode))
        access = scenario.adapter.active_proxies[scenario.plan.execution_scope]
        payload = result.model_dump_json() + repr(result) + repr(scenario.adapter) + repr(access)
        assert access.username not in payload and access.password not in payload
        await scenario.adapter.close()
        return result, payload, *modes

    result, payload, directory_mode, config_mode = asyncio.run(run())
    assert result.status == ExecutionStatus.COMMITTED
    assert directory_mode == 0o700 and config_mode == 0o600
    for sentinel in (SENTINEL_UUID, SENTINEL_PASSWORD, SENTINEL_TLS):
        assert sentinel not in payload


def test_bootstrap_client_candidate_and_artifact_tampering_fail_closed(
    provider_context, tmp_path: Path
) -> None:
    wrong_client = _scenario(
        provider_context,
        tmp_path / "wrong-client",
        expected_client_id=UUID("30000000-0000-0000-0000-000000000003"),
    )
    wrong_artifact = _scenario(
        provider_context,
        tmp_path / "wrong-artifact",
        artifact_candidate_id="profile:ffffffff-ffff-ffff-ffff-ffffffffffff",
    )
    wrong_profile = _scenario(
        provider_context,
        tmp_path / "wrong-profile",
        artifact_profile_id=UUID("40000000-0000-0000-0000-000000000004"),
    )
    tampered = _scenario(provider_context, tmp_path / "tampered")
    artifact = next((tampered.root / "singbox").glob("*.json"))
    artifact.write_bytes(artifact.read_bytes().replace(SENTINEL_UUID.encode(), b"x" * 36))
    oversized = _scenario(provider_context, tmp_path / "oversized")
    oversized_artifact = next((oversized.root / "singbox").glob("*.json"))
    with oversized_artifact.open("ab") as stream:
        stream.truncate(2 * 1024 * 1024 + 1)

    for scenario in (wrong_client, wrong_artifact, wrong_profile, tampered, oversized):

        async def run(selected: Scenario = scenario):
            result = await _execute(selected)
            await selected.adapter.close()
            return result

        result = asyncio.run(run())
        assert result.status == ExecutionStatus.ROLLED_BACK
        assert all(
            sentinel not in result.model_dump_json()
            for sentinel in (SENTINEL_UUID, SENTINEL_PASSWORD, SENTINEL_TLS)
        )


def test_runtime_requires_concrete_authorized_address(provider_context, tmp_path: Path) -> None:
    scenario = _scenario(provider_context, tmp_path)
    inventory = AuthorizedCandidateInventory(
        source=scenario.inventory.source,
        endpoint=scenario.inventory.endpoint,
        server_id=scenario.inventory.server_id,
        authorized_addresses=(),
        candidates=scenario.inventory.candidates,
    )
    adapter = SingBoxLocalProxyAdapter(
        lambda: inventory,
        VerifiedBootstrapSingBoxMaterialSource(
            scenario.root,
            pinned_trust=load_trust(scenario.trust_path),
            expected_client_id=CLIENT_ID,
            expected_bootstrap_sha256=_bootstrap_digest(scenario.root),
        ),
        binary=scenario.binary,
        runtime_root=scenario.runtime_root,
    )
    plan = plan_failover_execution(
        inventory,
        FailoverDecision(
            action=FailoverAction.SWITCH,
            current_candidate_id=None,
            target_candidate_id=inventory.candidates[0].candidate_id,
            reason="test",
        ),
        (adapter.capability,),
        ExecutionPolicy(),
        execution_scope="client-a:local-proxy",
    )

    async def run():
        result = await FailoverExecutor(lambda: inventory).execute(plan, adapter)
        await adapter.close()
        return result

    assert asyncio.run(run()).status == ExecutionStatus.ROLLED_BACK


def test_injected_material_cannot_weaken_tls_or_add_outbound_options(
    provider_context, tmp_path: Path
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    trusted = VerifiedBootstrapSingBoxMaterialSource(
        scenario.root,
        pinned_trust=load_trust(scenario.trust_path),
        expected_client_id=CLIENT_ID,
        expected_bootstrap_sha256=_bootstrap_digest(scenario.root),
    )

    class InsecureMaterialSource:
        def load(
            self,
            plan: FailoverExecutionPlan,
            inventory: AuthorizedCandidateInventory,
        ) -> SingBoxRuntimeMaterial:
            material = trusted.load(plan, inventory)
            outbound = dict(material.outbound)
            outbound["tls"] = {
                "enabled": True,
                "server_name": material.endpoint,
                "certificate": [SENTINEL_TLS],
                "insecure": True,
            }
            return SingBoxRuntimeMaterial(
                client_id=material.client_id,
                profile_id=material.profile_id,
                candidate_id=material.candidate_id,
                protocol=material.protocol,
                endpoint=material.endpoint,
                port=material.port,
                outbound=outbound,
            )

    adapter = SingBoxLocalProxyAdapter(
        lambda: scenario.inventory,
        InsecureMaterialSource(),
        binary=scenario.binary,
        runtime_root=tmp_path / "insecure-runtime",
    )

    async def run() -> object:
        result = await FailoverExecutor(lambda: scenario.inventory).execute(
            scenario.plan,
            adapter,
        )
        await adapter.close()
        return result

    result = asyncio.run(run())
    assert result.status == ExecutionStatus.ROLLED_BACK  # type: ignore[union-attr]
    assert not list((tmp_path / "insecure-runtime").rglob("config.json"))


def test_hysteria_and_non_singbox_candidates_are_not_execution_supported(
    provider_context, tmp_path: Path
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    capability = scenario.adapter.capability
    assert PathfinderProtocol.HYSTERIA2 not in capability.supported_protocols
    assert PathfinderProvider.WIREGUARD not in capability.supported_providers
    assert PathfinderProvider.OPENVPN not in capability.supported_providers
    assert PathfinderProvider.AMNEZIAWG not in capability.supported_providers
    assert capability.supported_protocols == (
        PathfinderProtocol.VLESS,
        PathfinderProtocol.TROJAN,
    )


def test_port_collision_uses_bounded_reserved_fallback(provider_context, tmp_path: Path) -> None:
    scenario = _scenario(
        provider_context,
        tmp_path,
        port_range=(32000, 32001),
        port_attempts=2,
    )
    first = 32000 + (int(scenario.plan.plan_id[:16], 16) % 2)
    occupied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    occupied.bind(("127.0.0.1", first))
    occupied.listen()
    try:

        async def run() -> tuple[object, int]:
            result = await _execute(scenario)
            port = scenario.adapter.active_endpoints[scenario.plan.execution_scope][1]
            await scenario.adapter.close()
            return result, port

        result, port = asyncio.run(run())
    finally:
        occupied.close()
    assert result.status == ExecutionStatus.COMMITTED  # type: ignore[union-attr]
    assert port != first


def test_stale_runtime_health_never_reports_already_converged(
    provider_context, tmp_path: Path
) -> None:
    scenario = _scenario(provider_context, tmp_path)

    async def run() -> tuple[object, object]:
        first = await _execute(scenario)
        config = next(scenario.runtime_root.rglob("config.json"))
        config.write_text("{}")
        second = await _execute(scenario)
        await scenario.adapter.close()
        return first, second

    first, second = asyncio.run(run())
    assert first.status == ExecutionStatus.COMMITTED  # type: ignore[union-attr]
    assert second.status != ExecutionStatus.ALREADY_CONVERGED  # type: ignore[union-attr]


def test_authenticated_bootstrap_rotation_never_reports_already_converged(
    provider_context, tmp_path: Path
) -> None:
    scenario = _scenario(provider_context, tmp_path)

    async def run() -> tuple[object, object, int, int, str]:
        first = await _execute(scenario)
        first_port = scenario.adapter.active_endpoints[scenario.plan.execution_scope][1]
        rotated_uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        _rotate_bundle_credential(provider_context, scenario, rotated_uuid)
        second = await _execute(scenario)
        second_port = scenario.adapter.active_endpoints[scenario.plan.execution_scope][1]
        config = json.loads(next(scenario.runtime_root.rglob("config.json")).read_bytes())
        active_uuid = config["outbounds"][0]["uuid"]
        await scenario.adapter.close()
        return first, second, first_port, second_port, active_uuid

    first, second, first_port, second_port, active_uuid = asyncio.run(run())
    assert first.status == ExecutionStatus.COMMITTED  # type: ignore[union-attr]
    assert second.status == ExecutionStatus.ROLLED_BACK  # type: ignore[union-attr]
    assert first_port == second_port
    assert active_uuid == SENTINEL_UUID


def test_previous_valid_signed_bootstrap_generation_cannot_be_replayed(
    provider_context, tmp_path: Path
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    artifact = next((scenario.root / "singbox").glob("*.json"))
    old_generation = {
        path: path.read_bytes()
        for path in (artifact, scenario.root / "bootstrap.json", scenario.root / "bootstrap.sig")
    }
    _rotate_bundle_credential(
        provider_context,
        scenario,
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    )
    expected_generation = _bootstrap_digest(scenario.root)
    for path, content in old_generation.items():
        atomic_write(path, content, 0o600)
    assert verify_bootstrap(
        scenario.root,
        pinned_trust=load_trust(scenario.trust_path),
    ).valid
    adapter = SingBoxLocalProxyAdapter(
        lambda: scenario.inventory,
        VerifiedBootstrapSingBoxMaterialSource(
            scenario.root,
            pinned_trust=load_trust(scenario.trust_path),
            expected_client_id=CLIENT_ID,
            expected_bootstrap_sha256=expected_generation,
        ),
        binary=scenario.binary,
        runtime_root=tmp_path / "replay-runtime",
    )

    async def run() -> object:
        result = await FailoverExecutor(lambda: scenario.inventory).execute(
            scenario.plan,
            adapter,
        )
        await adapter.close()
        return result

    result = asyncio.run(run())
    assert result.status == ExecutionStatus.ROLLED_BACK  # type: ignore[union-attr]
    assert not list((tmp_path / "replay-runtime").rglob("config.json"))


def test_changed_binary_never_reports_already_converged(provider_context, tmp_path: Path) -> None:
    scenario = _scenario(provider_context, tmp_path)

    async def run() -> tuple[object, object, int, int]:
        first = await _execute(scenario)
        first_port = scenario.adapter.active_endpoints[scenario.plan.execution_scope][1]
        scenario.binary.write_text(scenario.binary.read_text() + "\n# replacement generation\n")
        second = await _execute(scenario)
        second_port = scenario.adapter.active_endpoints[scenario.plan.execution_scope][1]
        await scenario.adapter.close()
        return first, second, first_port, second_port

    first, second, first_port, second_port = asyncio.run(run())
    assert first.status == ExecutionStatus.COMMITTED  # type: ignore[union-attr]
    assert second.status == ExecutionStatus.COMMITTED  # type: ignore[union-attr]
    assert first_port != second_port


def test_config_changed_after_check_is_never_started(provider_context, tmp_path: Path) -> None:
    scenario = _scenario(provider_context, tmp_path)

    async def run() -> None:
        await scenario.adapter.prepare(scenario.plan)
        for config in scenario.runtime_root.rglob("config.json"):
            config.write_text("{}")
            config.chmod(0o600)
        with pytest.raises(ExecutionAdapterError, match="changed before activation"):
            await scenario.adapter.activate(scenario.plan)
        await scenario.adapter.rollback(scenario.plan)
        await scenario.adapter.cleanup(scenario.plan)
        await scenario.adapter.close()

    asyncio.run(run())
    assert not scenario.mode_path.with_suffix(".started").exists()


def test_failed_replacement_preserves_previous_runtime_then_success_retires_it(
    provider_context, tmp_path: Path
) -> None:
    scenario = _scenario(provider_context, tmp_path)

    async def run() -> tuple[object, object, object, int, int, int, int]:
        first = await _execute(scenario)
        assert first.status == ExecutionStatus.COMMITTED, first
        old_endpoint = scenario.adapter.active_endpoints[scenario.plan.execution_scope]
        old_config = next(scenario.runtime_root.rglob("config.json"))
        old_config.write_text("{}")
        scenario.mode_path.write_text("malformed_socks")
        failed = await _execute(scenario)
        preserved_endpoint = scenario.adapter.active_endpoints[scenario.plan.execution_scope]
        _, writer = await asyncio.open_connection(*preserved_endpoint)
        writer.close()
        await writer.wait_closed()
        scenario.mode_path.write_text("success")
        committed = await _execute(scenario)
        replacement_endpoint = scenario.adapter.active_endpoints[scenario.plan.execution_scope]
        config_count = len(list(scenario.runtime_root.rglob("config.json")))
        await scenario.adapter.close()
        return (
            first,
            failed,
            committed,
            old_endpoint[1],
            preserved_endpoint[1],
            replacement_endpoint[1],
            config_count,
        )

    first, failed, committed, old, preserved, replacement, config_count = asyncio.run(run())
    assert first.status == ExecutionStatus.COMMITTED  # type: ignore[union-attr]
    assert failed.status == ExecutionStatus.ROLLED_BACK  # type: ignore[union-attr]
    assert committed.status == ExecutionStatus.COMMITTED, committed  # type: ignore[union-attr]
    assert old == preserved
    assert replacement != old
    assert config_count == 1


def test_cancellation_rolls_back_child_and_private_runtime(
    provider_context, tmp_path: Path
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    scenario.mode_path.write_text("no_listener")

    async def run() -> object:
        cancellation = ExecutionCancellation()
        task = asyncio.create_task(
            FailoverExecutor(lambda: scenario.inventory).execute(
                scenario.plan,
                scenario.adapter,
                cancellation=cancellation,
            )
        )
        await asyncio.sleep(0.25)
        cancellation.cancel()
        result = await task
        await scenario.adapter.close()
        return result

    result = asyncio.run(run())
    assert result.status == ExecutionStatus.CANCELLED  # type: ignore[union-attr]
    assert not list(scenario.runtime_root.rglob("config.json"))


def test_cancellation_during_guardian_spawn_owns_and_stops_late_process(
    provider_context,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    real_spawn = asyncio.create_subprocess_exec

    async def run() -> object:
        guardian_spawn_started = asyncio.Event()

        async def delayed_guardian(*args, **kwargs):
            if len(args) > 1 and str(args[1]).endswith("_singbox_guardian.py"):
                guardian_spawn_started.set()
                await asyncio.sleep(0.05)
            return await real_spawn(*args, **kwargs)

        monkeypatch.setattr(asyncio, "create_subprocess_exec", delayed_guardian)
        cancellation = ExecutionCancellation()
        task = asyncio.create_task(
            FailoverExecutor(lambda: scenario.inventory).execute(
                scenario.plan,
                scenario.adapter,
                cancellation=cancellation,
            )
        )
        await asyncio.wait_for(guardian_spawn_started.wait(), timeout=5)
        cancellation.cancel()
        result = await task
        await scenario.adapter.close()
        return result

    result = asyncio.run(run())
    assert result.status == ExecutionStatus.CANCELLED  # type: ignore[union-attr]
    assert not list(scenario.runtime_root.rglob("config.json"))
    pid_path = scenario.mode_path.with_suffix(".pid")
    if pid_path.exists():
        with pytest.raises(ProcessLookupError):
            os.kill(int(pid_path.read_text()), 0)


def test_prepare_cancellation_cleans_already_reserved_fallbacks(
    provider_context, tmp_path: Path
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    scenario.mode_path.write_text("second_check_hang")

    async def run() -> tuple[object, object]:
        cancellation = ExecutionCancellation()
        task = asyncio.create_task(
            FailoverExecutor(lambda: scenario.inventory).execute(
                scenario.plan,
                scenario.adapter,
                cancellation=cancellation,
            )
        )
        await asyncio.sleep(0.3)
        cancellation.cancel()
        cancelled = await task
        assert not list(scenario.runtime_root.rglob("config.json"))
        scenario.mode_path.write_text("success")
        committed = await _execute(scenario)
        await scenario.adapter.close()
        return cancelled, committed

    cancelled, committed = asyncio.run(run())
    assert cancelled.status == ExecutionStatus.CANCELLED  # type: ignore[union-attr]
    assert committed.status == ExecutionStatus.COMMITTED  # type: ignore[union-attr]


def test_child_ignoring_sigterm_is_forcibly_stopped_by_owned_guardian(
    provider_context, tmp_path: Path
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    scenario.mode_path.write_text("ignore_term")

    async def run() -> tuple[object, int]:
        result = await _execute(scenario)
        child_pid = int(scenario.mode_path.with_suffix(".pid").read_text())
        await scenario.adapter.close()
        return result, child_pid

    result, child_pid = asyncio.run(run())
    assert result.status == ExecutionStatus.COMMITTED  # type: ignore[union-attr]
    assert not list(scenario.runtime_root.rglob("config.json"))
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)


def test_full_bounded_port_attempt_set_exhaustion_releases_every_resource(
    provider_context, tmp_path: Path
) -> None:
    scenario = _scenario(
        provider_context,
        tmp_path,
        port_range=(32100, 32101),
        port_attempts=2,
    )
    occupied = []
    for port in (32100, 32101):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", port))
        listener.listen()
        occupied.append(listener)

    async def run() -> tuple[object, object]:
        failed = await _execute(scenario)
        for listener in occupied:
            listener.close()
        committed = await _execute(scenario)
        await scenario.adapter.close()
        return failed, committed

    failed, committed = asyncio.run(run())
    assert failed.status == ExecutionStatus.ROLLED_BACK  # type: ignore[union-attr]
    assert committed.status == ExecutionStatus.COMMITTED  # type: ignore[union-attr]


def test_symlinked_runtime_subdirectory_is_rejected_without_touching_target(
    provider_context, tmp_path: Path
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    scenario.runtime_root.mkdir(mode=0o700)
    foreign = tmp_path / "foreign"
    foreign.mkdir(mode=0o755)
    (scenario.runtime_root / "locks").symlink_to(foreign, target_is_directory=True)

    async def run() -> object:
        result = await _execute(scenario)
        await scenario.adapter.close()
        return result

    result = asyncio.run(run())
    assert result.status == ExecutionStatus.ROLLED_BACK  # type: ignore[union-attr]
    assert stat.S_IMODE(foreign.stat().st_mode) == 0o755


def test_writable_runtime_ancestor_and_hard_linked_lock_fail_closed(
    provider_context, tmp_path: Path
) -> None:
    unsafe_scenario = _scenario(provider_context, tmp_path / "unsafe-case")
    unsafe = tmp_path / "unsafe-ancestor"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    material = VerifiedBootstrapSingBoxMaterialSource(
        unsafe_scenario.root,
        pinned_trust=load_trust(unsafe_scenario.trust_path),
        expected_client_id=CLIENT_ID,
        expected_bootstrap_sha256=_bootstrap_digest(unsafe_scenario.root),
    )
    unsafe_adapter = SingBoxLocalProxyAdapter(
        lambda: unsafe_scenario.inventory,
        material,
        binary=unsafe_scenario.binary,
        runtime_root=unsafe / "private-root",
    )

    async def reject_unsafe() -> object:
        result = await FailoverExecutor(lambda: unsafe_scenario.inventory).execute(
            unsafe_scenario.plan,
            unsafe_adapter,
        )
        await unsafe_adapter.close()
        return result

    assert asyncio.run(reject_unsafe()).status == ExecutionStatus.ROLLED_BACK
    assert not (unsafe / "private-root").exists()

    linked_scenario = _scenario(provider_context, tmp_path / "linked-case")
    locks = linked_scenario.runtime_root / "locks"
    scopes = linked_scenario.runtime_root / "scopes"
    locks.mkdir(parents=True, mode=0o700)
    scopes.mkdir(mode=0o700)
    foreign_lock = tmp_path / "foreign-lock-target"
    foreign_lock.write_text("foreign")
    foreign_lock.chmod(0o600)
    digest = hashlib.sha256(linked_scenario.plan.execution_scope.encode("ascii")).hexdigest()
    os.link(foreign_lock, locks / f"{digest}.lock")

    async def reject_link() -> object:
        result = await _execute(linked_scenario)
        await linked_scenario.adapter.close()
        return result

    assert asyncio.run(reject_link()).status == ExecutionStatus.ROLLED_BACK
    assert foreign_lock.read_text() == "foreign"
    assert stat.S_IMODE(foreign_lock.stat().st_mode) == 0o600


def _cross_process_prepare(
    bundle: str,
    trust_path: str,
    expected_client_id: str,
    binary: str,
    runtime_root: str,
    plan_json: str,
    queue: multiprocessing.Queue,
) -> None:
    trust = load_trust(Path(trust_path))
    manifest = ServerManifest.model_validate_json((Path(bundle) / "manifest.json").read_bytes())
    inventory = authorize_manifest(
        manifest,
        source=AuthorizationSource.SIGNED_MANIFEST,
        trusted_server_id=trust.server_id,
        trusted_endpoint=manifest.server.identity,
        trusted_addresses=("192.0.2.10", "2001:db8::1"),
    )
    adapter = SingBoxLocalProxyAdapter(
        lambda: inventory,
        VerifiedBootstrapSingBoxMaterialSource(
            Path(bundle),
            pinned_trust=trust,
            expected_client_id=UUID(expected_client_id),
            expected_bootstrap_sha256=_bootstrap_digest(Path(bundle)),
        ),
        binary=Path(binary),
        runtime_root=Path(runtime_root),
        lock_timeout_seconds=0.15,
    )
    plan = FailoverExecutionPlan.model_validate_json(plan_json)

    async def run() -> None:
        try:
            await adapter.prepare(plan)
        except ExecutionAdapterError:
            queue.put("busy")
        else:
            queue.put("acquired")
        finally:
            await adapter.close()

    asyncio.run(run())


def _crash_after_commit(
    bundle: str,
    trust_path: str,
    binary: str,
    runtime_root: str,
    plan_json: str,
    ready_path: str,
) -> None:
    trust = load_trust(Path(trust_path))
    manifest = ServerManifest.model_validate_json((Path(bundle) / "manifest.json").read_bytes())
    inventory = authorize_manifest(
        manifest,
        source=AuthorizationSource.SIGNED_MANIFEST,
        trusted_server_id=trust.server_id,
        trusted_endpoint=manifest.server.identity,
        trusted_addresses=("192.0.2.10", "2001:db8::1"),
    )
    adapter = SingBoxLocalProxyAdapter(
        lambda: inventory,
        VerifiedBootstrapSingBoxMaterialSource(
            Path(bundle),
            pinned_trust=trust,
            expected_client_id=CLIENT_ID,
            expected_bootstrap_sha256=_bootstrap_digest(Path(bundle)),
        ),
        binary=Path(binary),
        runtime_root=Path(runtime_root),
    )
    plan = FailoverExecutionPlan.model_validate_json(plan_json)

    async def run() -> None:
        result = await FailoverExecutor(lambda: inventory).execute(plan, adapter)
        if result.status != ExecutionStatus.COMMITTED:
            os._exit(2)
        _, port = adapter.active_endpoints[plan.execution_scope]
        Path(ready_path).write_text(str(port))
        while True:
            time.sleep(1)

    asyncio.run(run())


def test_cross_process_scope_lock_blocks_second_adapter(provider_context, tmp_path: Path) -> None:
    scenario = _scenario(provider_context, tmp_path)
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()

    async def run() -> tuple[object, int | None, str]:
        result = await _execute(scenario)
        process = context.Process(
            target=_cross_process_prepare,
            args=(
                str(scenario.root),
                str(scenario.trust_path),
                str(CLIENT_ID),
                str(scenario.binary),
                str(scenario.runtime_root),
                scenario.plan.model_dump_json(),
                queue,
            ),
        )
        process.start()
        await asyncio.to_thread(process.join, 10)
        outcome = await asyncio.to_thread(queue.get, True, 2)
        await scenario.adapter.close()
        return result, process.exitcode, outcome

    result, exitcode, outcome = asyncio.run(run())
    assert result.status == ExecutionStatus.COMMITTED  # type: ignore[union-attr]
    assert exitcode == 0
    assert outcome == "busy"


def test_independent_runtime_scopes_progress_concurrently(provider_context, tmp_path: Path) -> None:
    first = _scenario(provider_context, tmp_path)
    trust = load_trust(first.trust_path)
    second_adapter = SingBoxLocalProxyAdapter(
        lambda: first.inventory,
        VerifiedBootstrapSingBoxMaterialSource(
            first.root,
            pinned_trust=trust,
            expected_client_id=CLIENT_ID,
            expected_bootstrap_sha256=_bootstrap_digest(first.root),
        ),
        binary=first.binary,
        runtime_root=first.runtime_root,
        port_range=(31000, 31100),
    )
    second_plan = plan_failover_execution(
        first.inventory,
        FailoverDecision(
            action=FailoverAction.SWITCH,
            current_candidate_id=None,
            target_candidate_id=first.inventory.candidates[0].candidate_id,
            reason="verified target selected",
        ),
        (second_adapter.capability,),
        ExecutionPolicy(),
        execution_scope="client-b:local-proxy",
    )

    async def run() -> tuple[object, object, int, int]:
        first_result, second_result = await asyncio.gather(
            FailoverExecutor(lambda: first.inventory).execute(first.plan, first.adapter),
            FailoverExecutor(lambda: first.inventory).execute(second_plan, second_adapter),
        )
        first_port = first.adapter.active_endpoints[first.plan.execution_scope][1]
        second_port = second_adapter.active_endpoints[second_plan.execution_scope][1]
        await asyncio.gather(first.adapter.close(), second_adapter.close())
        return first_result, second_result, first_port, second_port

    first_result, second_result, first_port, second_port = asyncio.run(run())
    assert first_result.status == ExecutionStatus.COMMITTED  # type: ignore[union-attr]
    assert second_result.status == ExecutionStatus.COMMITTED  # type: ignore[union-attr]
    assert first_port != second_port


def test_parent_crash_guardian_stops_child_before_scope_lock_releases(
    provider_context, tmp_path: Path
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    ready = tmp_path / "crash-ready"
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_crash_after_commit,
        args=(
            str(scenario.root),
            str(scenario.trust_path),
            str(scenario.binary),
            str(scenario.runtime_root),
            scenario.plan.model_dump_json(),
            str(ready),
        ),
    )
    process.start()
    deadline = time.monotonic() + 10
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert ready.exists()
    port = int(ready.read_text())
    os.kill(process.pid, signal.SIGKILL)
    process.join(timeout=10)
    assert process.exitcode == -signal.SIGKILL
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                pass
        except OSError:
            break
        time.sleep(0.05)
    else:
        pytest.fail("parent-death guardian left the sing-box child listening")

    async def reconcile() -> object:
        result = await _execute(scenario)
        await scenario.adapter.close()
        return result

    assert asyncio.run(reconcile()).status == ExecutionStatus.COMMITTED


def test_guardian_crash_cannot_release_lock_while_child_survives_or_block_recovery(
    provider_context, tmp_path: Path
) -> None:
    scenario = _scenario(provider_context, tmp_path)

    async def run() -> tuple[object, object, int]:
        first = await _execute(scenario)
        assert first.status == ExecutionStatus.COMMITTED, first
        state = scenario.adapter._scopes[scenario.plan.execution_scope]
        assert state.active is not None and state.active.process is not None
        guardian = state.active.process
        child_pid = int(scenario.mode_path.with_suffix(".pid").read_text())
        os.kill(guardian.pid, signal.SIGKILL)
        await guardian.wait()

        context = multiprocessing.get_context("spawn")
        queue = context.Queue()
        competitor = context.Process(
            target=_cross_process_prepare,
            args=(
                str(scenario.root),
                str(scenario.trust_path),
                str(CLIENT_ID),
                str(scenario.binary),
                str(scenario.runtime_root),
                scenario.plan.model_dump_json(),
                queue,
            ),
        )
        competitor.start()
        await asyncio.to_thread(competitor.join, 10)
        assert await asyncio.to_thread(queue.get, True, 2) == "busy"
        assert competitor.exitcode == 0

        recovered = await _execute(scenario)
        await scenario.adapter.close()
        return first, recovered, child_pid

    first, recovered, old_child_pid = asyncio.run(run())
    assert first.status == ExecutionStatus.COMMITTED  # type: ignore[union-attr]
    assert recovered.status == ExecutionStatus.COMMITTED  # type: ignore[union-attr]
    with pytest.raises(ProcessLookupError):
        os.kill(old_child_pid, 0)


def test_discovery_never_downloads_and_explicit_path_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    explicit = tmp_path / "sing-box"
    assert discover_singbox_binary(explicit) == explicit
    target = tmp_path / "sing-box-real"
    target.write_text("binary")
    target.chmod(0o755)
    explicit.symlink_to(target)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert discover_singbox_binary() == target


def test_adapter_configuration_is_strict(provider_context, tmp_path: Path) -> None:
    scenario = _scenario(provider_context, tmp_path)
    material = VerifiedBootstrapSingBoxMaterialSource(
        scenario.root,
        pinned_trust=load_trust(scenario.trust_path),
        expected_client_id=CLIENT_ID,
        expected_bootstrap_sha256=_bootstrap_digest(scenario.root),
    )
    with pytest.raises(ValueError):
        SingBoxLocalProxyAdapter(
            lambda: scenario.inventory,
            material,
            binary=Path("relative"),
            runtime_root=scenario.runtime_root,
        )
    with pytest.raises(ValueError):
        SingBoxLocalProxyAdapter(
            lambda: scenario.inventory,
            material,
            binary=scenario.binary,
            runtime_root=scenario.runtime_root,
            port_range=(1, 80),
        )


def test_default_adapter_scenarios_do_not_share_a_narrow_time_wait_port_band(
    provider_context, tmp_path: Path
) -> None:
    scenario = _scenario(provider_context, tmp_path)

    assert scenario.adapter._port_range == (20000, 60999)
    assert scenario.adapter._port_attempts == 4


def _write_cli_decision(scenario: Scenario, path: Path) -> None:
    decision = FailoverDecision(
        action=FailoverAction.SWITCH,
        current_candidate_id=None,
        target_candidate_id=scenario.inventory.candidates[0].candidate_id,
        reason="operator approved verified failover",
    )
    path.write_text(decision.model_dump_json(indent=2))


def _cli_authority_arguments(scenario: Scenario) -> list[str]:
    return [
        "--bootstrap",
        str(scenario.root),
        "--pinned-trust",
        str(scenario.trust_path),
        "--expected-client",
        str(CLIENT_ID),
        "--expected-bootstrap-sha256",
        _bootstrap_digest(scenario.root),
        "--expected-server",
        scenario.inventory.endpoint,
        "--expected-address",
        "2001:0db8:0:0:0:0:0:1",
        "--expected-address",
        "192.0.2.10",
    ]


def _write_cli_plan(scenario: Scenario, path: Path) -> FailoverExecutionPlan:
    assert scenario.inventory.server_id is not None
    plan = plan_failover_execution(
        scenario.inventory,
        FailoverDecision(
            action=FailoverAction.SWITCH,
            current_candidate_id=None,
            target_candidate_id=scenario.inventory.candidates[0].candidate_id,
            reason="operator approved verified failover",
        ),
        (scenario.adapter.capability,),
        ExecutionPolicy(),
        execution_scope=(
            f"server:{scenario.inventory.server_id}:client:{CLIENT_ID}:singbox-local-proxy"
        ),
    )
    path.write_text(plan.model_dump_json(indent=2))
    return plan


def test_execution_cli_commands_register_required_security_options() -> None:
    pathfinder = get_command(app).commands["pathfinder"]
    expected = {
        "plan-execution": {
            "--decision",
            "--bootstrap",
            "--pinned-trust",
            "--expected-client",
            "--expected-bootstrap-sha256",
            "--expected-server",
            "--expected-address",
        },
        "execute": {
            "--plan",
            "--bootstrap",
            "--pinned-trust",
            "--expected-client",
            "--expected-bootstrap-sha256",
            "--expected-server",
            "--expected-address",
            "--runtime-root",
            "--access-file",
            "--sing-box-binary",
        },
    }
    for command_name, expected_options in expected.items():
        command = pathfinder.commands[command_name]
        registered = {
            option for parameter in command.params for option in getattr(parameter, "opts", ())
        }
        assert expected_options <= registered
        expected_address = next(
            parameter
            for parameter in command.params
            if "--expected-address" in getattr(parameter, "opts", ())
        )
        assert expected_address.multiple
        help_result = CliRunner().invoke(
            app,
            ["pathfinder", command_name, "--help"],
            color=True,
        )
        assert help_result.exit_code == 0


def test_plan_execution_cli_is_network_free_and_binds_exact_authority(
    provider_context,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    decision = tmp_path / "decision.json"
    _write_cli_decision(scenario, decision)

    def forbidden_network(*args, **kwargs):
        raise AssertionError("planning must not perform network I/O")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden_network)
    result = CliRunner().invoke(
        app,
        [
            "pathfinder",
            "plan-execution",
            "--decision",
            str(decision),
            *_cli_authority_arguments(scenario),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    plan = FailoverExecutionPlan.model_validate_json(result.output)
    assert plan.execution_scope == (
        f"server:{scenario.inventory.server_id}:client:{CLIENT_ID}:singbox-local-proxy"
    )
    assert plan.target is not None
    assert plan.target.candidate == scenario.inventory.candidates[0]
    assert plan.adapter == scenario.adapter.capability
    assert plan.execution_supported
    assert SENTINEL_UUID not in result.output
    assert SENTINEL_PASSWORD not in result.output
    assert SENTINEL_TLS not in result.output


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        ("0" * 64, "generation does not match its pin"),
        ("f" * 64, "generation does not match its pin"),
    ],
)
def test_plan_execution_cli_rejects_wrong_bootstrap_generation_before_planning(
    provider_context,
    tmp_path: Path,
    replacement: str,
    message: str,
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    decision = tmp_path / "decision.json"
    _write_cli_decision(scenario, decision)
    arguments = _cli_authority_arguments(scenario)
    digest_index = arguments.index("--expected-bootstrap-sha256") + 1
    arguments[digest_index] = replacement

    result = CliRunner().invoke(
        app,
        [
            "pathfinder",
            "plan-execution",
            "--decision",
            str(decision),
            *arguments,
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert message in result.output
    assert "plan_id" not in result.output


def test_execute_cli_runs_authenticated_proxy_only_while_foreground(
    provider_context,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    scenario.mode_path.write_text("credential_output")
    plan_path = tmp_path / "plan.json"
    plan = _write_cli_plan(scenario, plan_path)
    access_parent = tmp_path / "private-access"
    access_parent.mkdir(mode=0o700)
    access_file = access_parent / "proxy.json"
    observed: dict[str, object] = {}

    async def observe_then_stop(_stopped: asyncio.Event) -> None:
        metadata = access_file.stat()
        observed["mode"] = stat.S_IMODE(metadata.st_mode)
        observed["document"] = json.loads(access_file.read_bytes())
        observed["pid"] = int(scenario.mode_path.with_suffix(".pid").read_text())

    monkeypatch.setattr(
        pathfinder_execution_cli,
        "_wait_for_execution_shutdown",
        observe_then_stop,
    )
    result = CliRunner().invoke(
        app,
        [
            "pathfinder",
            "execute",
            "--plan",
            str(plan_path),
            *_cli_authority_arguments(scenario),
            "--runtime-root",
            str(scenario.runtime_root),
            "--access-file",
            str(access_file),
            "--sing-box-binary",
            str(scenario.binary),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    public = json.loads(result.output)
    assert public["execution"]["status"] == ExecutionStatus.COMMITTED
    assert public["proxy_access_file"] == str(access_file)
    assert public["foreground"] is True
    access = observed["document"]
    assert isinstance(access, dict)
    assert access["execution_id"] == plan.plan_id
    assert access["candidate_id"] == scenario.inventory.candidates[0].candidate_id
    assert access["host"] == "127.0.0.1"
    assert isinstance(access["username"], str) and access["username"]
    assert isinstance(access["password"], str) and access["password"]
    assert observed["mode"] == 0o600
    assert not access_file.exists()
    assert SENTINEL_UUID not in result.output
    assert SENTINEL_PASSWORD not in result.output
    assert SENTINEL_TLS not in result.output
    with pytest.raises(ProcessLookupError):
        os.kill(int(observed["pid"]), 0)


def test_execute_cli_rejects_plan_scope_not_bound_to_expected_client(
    provider_context,
    tmp_path: Path,
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(scenario.plan.model_dump_json(indent=2))
    access_parent = tmp_path / "private-access"
    access_parent.mkdir(mode=0o700)
    access_file = access_parent / "proxy.json"

    result = CliRunner().invoke(
        app,
        [
            "pathfinder",
            "execute",
            "--plan",
            str(plan_path),
            *_cli_authority_arguments(scenario),
            "--runtime-root",
            str(scenario.runtime_root),
            "--access-file",
            str(access_file),
            "--sing-box-binary",
            str(scenario.binary),
        ],
    )

    assert result.exit_code == 1
    assert "plan scope does not match expected server and client" in result.output
    assert not scenario.runtime_root.exists()
    assert not access_file.exists()


def test_execute_cli_rejects_changed_destination_authority_before_runtime_mutation(
    provider_context,
    tmp_path: Path,
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    plan_path = tmp_path / "plan.json"
    _write_cli_plan(scenario, plan_path)
    access_parent = tmp_path / "private-access"
    access_parent.mkdir(mode=0o700)
    access_file = access_parent / "proxy.json"
    authority = _cli_authority_arguments(scenario)
    while "--expected-address" in authority:
        address_index = authority.index("--expected-address")
        del authority[address_index : address_index + 2]
    authority.extend(("--expected-address", "192.0.2.99"))

    result = CliRunner().invoke(
        app,
        [
            "pathfinder",
            "execute",
            "--plan",
            str(plan_path),
            *authority,
            "--runtime-root",
            str(scenario.runtime_root),
            "--access-file",
            str(access_file),
            "--sing-box-binary",
            str(scenario.binary),
            "--json",
        ],
    )

    assert result.exit_code == 1
    public = json.loads(result.output)
    assert public["execution"]["status"] == ExecutionStatus.REJECTED
    assert public["execution"]["failure_type"] == "stale_decision"
    assert not scenario.mode_path.with_suffix(".started").exists()
    assert not access_file.exists()


def test_execute_cli_revalidates_bootstrap_even_for_no_action_plan(
    provider_context,
    tmp_path: Path,
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    assert scenario.inventory.server_id is not None
    plan = plan_failover_execution(
        scenario.inventory,
        FailoverDecision(
            action=FailoverAction.STAY,
            current_candidate_id=scenario.inventory.candidates[0].candidate_id,
            target_candidate_id=None,
            reason="current candidate remains preferred",
        ),
        (scenario.adapter.capability,),
        ExecutionPolicy(),
        execution_scope=(
            f"server:{scenario.inventory.server_id}:client:{CLIENT_ID}:singbox-local-proxy"
        ),
    )
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(plan.model_dump_json(indent=2))
    access_parent = tmp_path / "private-access"
    access_parent.mkdir(mode=0o700)
    access_file = access_parent / "proxy.json"
    authority = _cli_authority_arguments(scenario)
    digest_index = authority.index("--expected-bootstrap-sha256") + 1
    authority[digest_index] = "0" * 64

    result = CliRunner().invoke(
        app,
        [
            "pathfinder",
            "execute",
            "--plan",
            str(plan_path),
            *authority,
            "--runtime-root",
            str(scenario.runtime_root),
            "--access-file",
            str(access_file),
            "--sing-box-binary",
            str(scenario.binary),
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert "generation does not match its pin" in result.output
    assert not scenario.runtime_root.exists()
    assert not access_file.exists()


def test_execute_cli_refuses_existing_access_file_before_runtime_mutation(
    provider_context,
    tmp_path: Path,
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    plan_path = tmp_path / "plan.json"
    _write_cli_plan(scenario, plan_path)
    access_parent = tmp_path / "private-access"
    access_parent.mkdir(mode=0o700)
    access_file = access_parent / "proxy.json"
    access_file.write_text("operator-owned\n")
    access_file.chmod(0o600)

    result = CliRunner().invoke(
        app,
        [
            "pathfinder",
            "execute",
            "--plan",
            str(plan_path),
            *_cli_authority_arguments(scenario),
            "--runtime-root",
            str(scenario.runtime_root),
            "--access-file",
            str(access_file),
            "--sing-box-binary",
            str(scenario.binary),
        ],
    )

    assert result.exit_code == 1
    assert "proxy access file already exists" in result.output
    assert access_file.read_text() == "operator-owned\n"
    assert not scenario.mode_path.with_suffix(".started").exists()
    assert not scenario.runtime_root.exists()


def test_execute_cli_removes_access_when_owned_runtime_exits(
    provider_context,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    plan_path = tmp_path / "plan.json"
    _write_cli_plan(scenario, plan_path)
    access_parent = tmp_path / "private-access"
    access_parent.mkdir(mode=0o700)
    access_file = access_parent / "proxy.json"

    async def terminate_runtime_instead_of_shutdown(_stopped: asyncio.Event) -> None:
        child_pid = int(scenario.mode_path.with_suffix(".pid").read_text())
        os.kill(child_pid, signal.SIGTERM)
        await asyncio.Event().wait()

    monkeypatch.setattr(
        pathfinder_execution_cli,
        "_wait_for_execution_shutdown",
        terminate_runtime_instead_of_shutdown,
    )
    result = CliRunner().invoke(
        app,
        [
            "pathfinder",
            "execute",
            "--plan",
            str(plan_path),
            *_cli_authority_arguments(scenario),
            "--runtime-root",
            str(scenario.runtime_root),
            "--access-file",
            str(access_file),
            "--sing-box-binary",
            str(scenario.binary),
        ],
    )

    assert result.exit_code == 1
    assert "owned sing-box runtime stopped unexpectedly" in result.output
    assert not access_file.exists()


def test_execute_cli_sigterm_cleans_access_runtime_and_child(
    provider_context,
    tmp_path: Path,
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    plan_path = tmp_path / "plan.json"
    _write_cli_plan(scenario, plan_path)
    access_parent = tmp_path / "private-access"
    access_parent.mkdir(mode=0o700)
    access_file = access_parent / "proxy.json"
    command = [
        sys.executable,
        "-m",
        "fluxgate.cli.app",
        "pathfinder",
        "execute",
        "--plan",
        str(plan_path),
        *_cli_authority_arguments(scenario),
        "--runtime-root",
        str(scenario.runtime_root),
        "--access-file",
        str(access_file),
        "--sing-box-binary",
        str(scenario.binary),
        "--json",
    ]
    process = subprocess.Popen(  # noqa: S603 - controlled interpreter and fixture paths
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 10.0
        while not access_file.exists() and process.poll() is None:
            if time.monotonic() >= deadline:
                raise AssertionError("execution CLI did not publish proxy access")
            time.sleep(0.02)
        assert process.poll() is None
        assert stat.S_IMODE(access_file.stat().st_mode) == 0o600
        child_pid = int(scenario.mode_path.with_suffix(".pid").read_text())
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=10)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)

    assert process.returncode == 0, stderr
    public = json.loads(stdout)
    assert public["execution"]["status"] == ExecutionStatus.COMMITTED
    assert not access_file.exists()
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)


def test_forged_decision_can_choose_only_another_currently_authorized_candidate(
    provider_context,
    tmp_path: Path,
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    alternate_profile = UUID("20000000-0000-0000-0000-000000000003")
    alternate = scenario.inventory.candidates[0].model_copy(
        update={
            "candidate_id": f"profile:{alternate_profile}",
            "profile_id": alternate_profile,
            "port": 9443,
        }
    )
    inventory = AuthorizedCandidateInventory(
        source=scenario.inventory.source,
        endpoint=scenario.inventory.endpoint,
        server_id=scenario.inventory.server_id,
        authorized_addresses=scenario.inventory.authorized_addresses,
        candidates=(*scenario.inventory.candidates, alternate),
    )
    assert inventory.server_id is not None
    forged_operator_intent = FailoverDecision(
        action=FailoverAction.SWITCH,
        current_candidate_id=None,
        target_candidate_id=alternate.candidate_id,
        reason="operator explicitly requested an authorized alternative",
    )

    plan = plan_failover_execution(
        inventory,
        forged_operator_intent,
        (scenario.adapter.capability,),
        ExecutionPolicy(),
        execution_scope=(f"server:{inventory.server_id}:client:{CLIENT_ID}:singbox-local-proxy"),
    )
    unauthorized = forged_operator_intent.model_copy(
        update={"target_candidate_id": "profile:ffffffff-ffff-ffff-ffff-ffffffffffff"}
    )
    rejected = plan_failover_execution(
        inventory,
        unauthorized,
        (scenario.adapter.capability,),
        ExecutionPolicy(),
        execution_scope=plan.execution_scope,
    )

    assert plan.status.value == "ready"
    assert plan.target is not None and plan.target.candidate == alternate
    assert rejected.status.value == "invalid"


def test_operator_json_inputs_reject_special_linked_oversized_and_ambiguous_files(
    provider_context,
    tmp_path: Path,
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    plan_path = tmp_path / "plan.json"
    _write_cli_plan(scenario, plan_path)
    symbolic = tmp_path / "plan-link.json"
    symbolic.symlink_to(plan_path)
    hard = tmp_path / "plan-hard.json"
    os.link(plan_path, hard)
    fifo = tmp_path / "plan.fifo"
    os.mkfifo(fifo)
    giant = tmp_path / "plan-giant.json"
    giant.write_bytes(b" " * (1024 * 1024 + 1))

    for unsafe in (symbolic, hard, fifo, giant):
        with pytest.raises(VerificationError):
            pathfinder_execution_cli._load_execution_plan(unsafe)

    duplicate = tmp_path / "decision-duplicate.json"
    duplicate.write_text(
        '{"action":"stay","action":"switch","current_candidate_id":null,'
        '"target_candidate_id":null,"reason":"ambiguous"}'
    )
    malformed_utf8 = tmp_path / "decision-utf8.json"
    malformed_utf8.write_bytes(b"\xff")
    for unsafe in (duplicate, malformed_utf8):
        with pytest.raises(PathfinderError):
            pathfinder_execution_cli._load_failover_decision(unsafe)


def test_access_file_publication_never_clobbers_a_racing_regular_file(
    provider_context,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    access_parent = tmp_path / "private-access"
    access_parent.mkdir(mode=0o700)
    access_path = access_parent / "proxy.json"
    real_link = os.link

    async def run() -> None:
        result = await _execute(scenario)
        assert result.status == ExecutionStatus.COMMITTED
        access = scenario.adapter.active_proxies[scenario.plan.execution_scope]

        def race_link(source, destination, *, follow_symlinks=True):
            Path(destination).write_text("operator-owned\n")
            return real_link(source, destination, follow_symlinks=follow_symlinks)

        monkeypatch.setattr(os, "link", race_link)
        with pytest.raises(VerificationError, match="already exists"):
            pathfinder_execution_cli._write_proxy_access_file(access_path, result, access)
        await scenario.adapter.close()

    asyncio.run(run())
    assert access_path.read_text() == "operator-owned\n"


def test_access_cleanup_refuses_path_replacement_and_reports_original_left_behind(
    provider_context,
    tmp_path: Path,
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    access_parent = tmp_path / "private-access"
    access_parent.mkdir(mode=0o700)
    access_path = access_parent / "proxy.json"
    moved_original = access_parent / "moved-original.json"

    async def run() -> None:
        result = await _execute(scenario)
        assert result.status == ExecutionStatus.COMMITTED
        access = scenario.adapter.active_proxies[scenario.plan.execution_scope]
        identity = pathfinder_execution_cli._write_proxy_access_file(access_path, result, access)
        access_path.rename(moved_original)
        access_path.write_text("replacement\n")
        with pytest.raises(VerificationError, match="changed while execution was active"):
            pathfinder_execution_cli._remove_proxy_access_file(access_path, identity)
        await scenario.adapter.close()

    asyncio.run(run())
    assert access_path.read_text() == "replacement\n"
    assert moved_original.exists()


def test_no_action_cli_revalidates_authority_without_creating_runtime_or_access(
    provider_context,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    assert scenario.inventory.server_id is not None
    plan = plan_failover_execution(
        scenario.inventory,
        FailoverDecision(
            action=FailoverAction.STAY,
            current_candidate_id=scenario.inventory.candidates[0].candidate_id,
            target_candidate_id=None,
            reason="operator chose to stay",
        ),
        (scenario.adapter.capability,),
        ExecutionPolicy(),
        execution_scope=(
            f"server:{scenario.inventory.server_id}:client:{CLIENT_ID}:singbox-local-proxy"
        ),
    )
    plan_path = tmp_path / "stay-plan.json"
    plan_path.write_text(plan.model_dump_json())
    access_parent = tmp_path / "private-access"
    access_parent.mkdir(mode=0o700)
    access_file = access_parent / "proxy.json"

    def forbidden_binary_discovery(_explicit=None):
        raise AssertionError("no-action must not discover a runtime binary")

    monkeypatch.setattr(
        pathfinder_execution_cli,
        "discover_singbox_binary",
        forbidden_binary_discovery,
    )

    result = CliRunner().invoke(
        app,
        [
            "pathfinder",
            "execute",
            "--plan",
            str(plan_path),
            *_cli_authority_arguments(scenario),
            "--runtime-root",
            str(scenario.runtime_root),
            "--access-file",
            str(access_file),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["execution"]["status"] == "no_action"
    assert not scenario.runtime_root.exists()
    assert not access_file.exists()
    assert not scenario.mode_path.with_suffix(".started").exists()


def test_execute_cli_restores_preexisting_signal_handlers(
    provider_context,
    tmp_path: Path,
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    assert scenario.inventory.server_id is not None
    plan = plan_failover_execution(
        scenario.inventory,
        FailoverDecision(
            action=FailoverAction.STAY,
            current_candidate_id=scenario.inventory.candidates[0].candidate_id,
            target_candidate_id=None,
            reason="stay",
        ),
        (),
        ExecutionPolicy(),
        execution_scope=(
            f"server:{scenario.inventory.server_id}:client:{CLIENT_ID}:singbox-local-proxy"
        ),
    )
    plan_path = tmp_path / "stay-plan.json"
    plan_path.write_text(plan.model_dump_json())
    access_parent = tmp_path / "private-access"
    access_parent.mkdir(mode=0o700)

    def previous_handler(_signum, _frame) -> None:
        return None

    originals = {item: signal.getsignal(item) for item in (signal.SIGTERM, signal.SIGHUP)}
    try:
        for item in originals:
            signal.signal(item, previous_handler)
        result = CliRunner().invoke(
            app,
            [
                "pathfinder",
                "execute",
                "--plan",
                str(plan_path),
                *_cli_authority_arguments(scenario),
                "--runtime-root",
                str(scenario.runtime_root),
                "--access-file",
                str(access_parent / "proxy.json"),
                "--sing-box-binary",
                str(scenario.binary),
            ],
        )
        assert result.exit_code == 0, result.output
        assert signal.getsignal(signal.SIGTERM) is previous_handler
        assert signal.getsignal(signal.SIGHUP) is previous_handler
    finally:
        for item, handler in originals.items():
            signal.signal(item, handler)


def test_execution_signal_registration_outside_main_thread_is_local_and_safe() -> None:
    observed: list[tuple[tuple[signal.Signals, object], ...]] = []

    def worker() -> None:
        async def run() -> None:
            registered = pathfinder_execution_cli._register_execution_signal_handlers(
                ExecutionCancellation(), asyncio.Event()
            )
            observed.append(registered)

        asyncio.run(run())

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert observed == [()]


def test_actual_cli_processes_exclude_same_scope_and_allow_independent_client_scope(
    provider_context,
    tmp_path: Path,
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    first_plan_path = tmp_path / "first-plan.json"
    _write_cli_plan(scenario, first_plan_path)
    access_parent = tmp_path / "private-access"
    access_parent.mkdir(mode=0o700)

    def command(
        plan_path: Path,
        bundle: Path,
        trust_path: Path,
        client_id: UUID,
        access_path: Path,
    ) -> list[str]:
        return [
            sys.executable,
            "-m",
            "fluxgate.cli.app",
            "pathfinder",
            "execute",
            "--plan",
            str(plan_path),
            "--bootstrap",
            str(bundle),
            "--pinned-trust",
            str(trust_path),
            "--expected-client",
            str(client_id),
            "--expected-bootstrap-sha256",
            _bootstrap_digest(bundle),
            "--expected-server",
            scenario.inventory.endpoint,
            "--expected-address",
            "192.0.2.10",
            "--expected-address",
            "2001:db8::1",
            "--runtime-root",
            str(scenario.runtime_root),
            "--access-file",
            str(access_path),
            "--sing-box-binary",
            str(scenario.binary),
            "--json",
        ]

    first_access = access_parent / "first.json"
    first = subprocess.Popen(  # noqa: S603 - controlled interpreter and fixture paths
        command(first_plan_path, scenario.root, scenario.trust_path, CLIENT_ID, first_access),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    independent: subprocess.Popen[str] | None = None
    try:
        deadline = time.monotonic() + 10
        while not first_access.exists() and first.poll() is None:
            if time.monotonic() >= deadline:
                raise AssertionError("first CLI process did not publish access")
            time.sleep(0.02)
        assert first.poll() is None

        conflicting_access = access_parent / "conflicting.json"
        conflicting = subprocess.run(  # noqa: S603 - controlled interpreter and fixture paths
            command(
                first_plan_path,
                scenario.root,
                scenario.trust_path,
                CLIENT_ID,
                conflicting_access,
            ),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert conflicting.returncode == 1
        assert json.loads(conflicting.stdout)["execution"]["status"] == "rolled_back"
        assert not conflicting_access.exists()

        second_client = UUID("10000000-0000-0000-0000-000000000002")
        second_bundle = tmp_path / "second-bundle"
        second_trust = _write_bundle(
            provider_context,
            second_bundle,
            scenario.inventory.candidates[0],
            client_id=second_client,
        )
        second_manifest = ServerManifest.model_validate_json(
            (second_bundle / "manifest.json").read_bytes()
        )
        second_inventory = authorize_manifest(
            second_manifest,
            source=AuthorizationSource.SIGNED_MANIFEST,
            trusted_server_id=scenario.inventory.server_id,
            trusted_endpoint=scenario.inventory.endpoint,
            trusted_addresses=scenario.inventory.authorized_addresses,
        )
        assert second_inventory.server_id is not None
        second_plan = plan_failover_execution(
            second_inventory,
            FailoverDecision(
                action=FailoverAction.SWITCH,
                current_candidate_id=None,
                target_candidate_id=second_inventory.candidates[0].candidate_id,
                reason="independent client",
            ),
            (scenario.adapter.capability,),
            ExecutionPolicy(),
            execution_scope=(
                f"server:{second_inventory.server_id}:client:{second_client}:singbox-local-proxy"
            ),
        )
        second_plan_path = tmp_path / "second-plan.json"
        second_plan_path.write_text(second_plan.model_dump_json())
        second_access = access_parent / "second.json"
        independent = subprocess.Popen(  # noqa: S603 - controlled paths
            command(
                second_plan_path,
                second_bundle,
                second_trust,
                second_client,
                second_access,
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 10
        while not second_access.exists() and independent.poll() is None:
            if time.monotonic() >= deadline:
                raise AssertionError("independent CLI process did not publish access")
            time.sleep(0.02)
        assert independent.poll() is None
        assert first.poll() is None
    finally:
        for process in (first, independent):
            if process is not None and process.poll() is None:
                process.send_signal(signal.SIGTERM)
        for process in (first, independent):
            if process is not None and process.poll() is None:
                process.communicate(timeout=10)
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)

    assert first.returncode == 0
    assert independent is not None and independent.returncode == 0
    assert not any(access_parent.iterdir())


def test_execute_cli_sigterm_during_activation_rolls_back(
    provider_context,
    tmp_path: Path,
) -> None:
    scenario = _scenario(provider_context, tmp_path)
    scenario.mode_path.write_text("delayed_start")
    plan_path = tmp_path / "plan.json"
    _write_cli_plan(scenario, plan_path)
    access_parent = tmp_path / "private-access"
    access_parent.mkdir(mode=0o700)
    access_file = access_parent / "proxy.json"
    process = subprocess.Popen(  # noqa: S603 - controlled interpreter and fixture paths
        [
            sys.executable,
            "-m",
            "fluxgate.cli.app",
            "pathfinder",
            "execute",
            "--plan",
            str(plan_path),
            *_cli_authority_arguments(scenario),
            "--runtime-root",
            str(scenario.runtime_root),
            "--access-file",
            str(access_file),
            "--sing-box-binary",
            str(scenario.binary),
            "--json",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    started = scenario.mode_path.with_suffix(".started")
    try:
        deadline = time.monotonic() + 10.0
        while not started.exists() and process.poll() is None:
            if time.monotonic() >= deadline:
                raise AssertionError("execution CLI did not begin activation")
            time.sleep(0.01)
        assert process.poll() is None
        child_pid = int(scenario.mode_path.with_suffix(".pid").read_text())
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=10)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)

    assert process.returncode == 1, stderr
    public = json.loads(stdout)
    assert public["execution"]["status"] == ExecutionStatus.CANCELLED
    assert public["execution"]["failure_type"] == "cancellation"
    assert public["execution"]["rollback"] == "succeeded"
    assert public["execution"]["cleanup"] == "succeeded"
    assert not access_file.exists()
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)
