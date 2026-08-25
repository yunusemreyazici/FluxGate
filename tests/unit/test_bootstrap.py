from __future__ import annotations

import json
import shutil
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from fluxgate.application import build_application
from fluxgate.bootstrap import BootstrapDescriptor, BootstrapService, verify_bootstrap
from fluxgate.cli.app import app
from fluxgate.clients import ClientService
from fluxgate.core.config import AppConfig
from fluxgate.core.errors import FluxGateError, VerificationError
from fluxgate.core.models import (
    Client,
    ExportArtifact,
    FluxGateState,
    OperationResult,
    ProfileDefinition,
    ProtocolName,
    ProviderCapability,
    ProviderDetection,
    ProviderStateName,
    ProviderStatus,
    SecurityName,
    TransportName,
)
from fluxgate.core.registry import ProviderRegistry
from fluxgate.identity import ServerIdentityManager
from fluxgate.manifest.service import load_trust
from fluxgate.pathfinder.models import ConnectionMode
from fluxgate.providers.base import CoreProvider


class ExportProvider(CoreProvider):
    capabilities = frozenset(
        {
            ProviderCapability.EXPORT_CONFIG,
            ProviderCapability.PROFILE_EXPORT,
        }
    )

    def __init__(self, name: str) -> None:
        self.name = name
        self.display_name = name
        self.connection_mode = (
            ConnectionMode.LOCAL_PROXY if name == "singbox" else ConnectionMode.SYSTEM_TUNNEL
        )

    def detect(self) -> ProviderDetection:
        return ProviderDetection(available=True)

    def status(self) -> ProviderStatus:
        return ProviderStatus(
            name=self.name,
            state=ProviderStateName.RUNNING,
            enabled=True,
            installed=True,
        )

    def enable(self) -> OperationResult:
        return OperationResult(changed=False, message="test")

    def disable(self) -> OperationResult:
        return OperationResult(changed=False, message="test")

    def export_client(self, client: Client) -> list[ExportArtifact]:
        extension = "conf" if self.name == "wireguard" else "ovpn"
        return [
            ExportArtifact(
                name=f"{client.name}.{extension}",
                media_type="text/plain",
                content=f"test-only-{self.name}-{client.id}",
            )
        ]

    def export_profile(self, client: Client, profile: ProfileDefinition) -> ExportArtifact:
        return ExportArtifact(
            name=f"{profile.name}.json",
            media_type="application/json",
            content=json.dumps(
                {
                    "test": True,
                    "profile": str(profile.id),
                    "client": str(client.id),
                    "credential": client.profile_credentials[str(profile.id)]["value"],
                }
            ),
        )


def _config() -> AppConfig:
    return AppConfig.model_validate(
        {
            "server": {"domain": "vpn.example.test"},
            "cores": {
                "wireguard": {"enabled": True},
                "openvpn": {"enabled": True},
                "singbox": {"enabled": True},
            },
        }
    )


def _profiles() -> list[ProfileDefinition]:
    values = (
        ("vless", ProtocolName.VLESS, TransportName.TCP, 443),
        ("trojan", ProtocolName.TROJAN, TransportName.TCP, 444),
        ("hysteria2", ProtocolName.HYSTERIA2, TransportName.QUIC, 8443),
    )
    return [
        ProfileDefinition(
            id=UUID(f"00000000-0000-0000-0000-{index:012d}"),
            name=name,
            protocol=protocol,
            transport=transport,
            security=SecurityName.TLS,
            listen_port=port,
            enabled=True,
        )
        for index, (name, protocol, transport, port) in enumerate(values, 1)
    ]


def _service(
    provider_context,
    enabled: tuple[str, ...],
    *,
    client_name: str = "alice",
    profile_names: tuple[str, str, str] | None = None,
) -> tuple[BootstrapService, Client]:
    profiles = _profiles()
    if profile_names is not None:
        for profile, name in zip(profiles, profile_names, strict=True):
            profile.name = name
    client = Client(
        id=UUID("10000000-0000-0000-0000-000000000001"),
        name=client_name,
        provider_credentials={name: {"test": True} for name in enabled if name != "singbox"},
        profile_credentials=(
            {str(profile.id): {"value": f"test-only-{profile.name}"} for profile in profiles}
            if "singbox" in enabled
            else {}
        ),
    )
    provider_context.state.save(FluxGateState(clients=[client], profiles=profiles))
    registry = ProviderRegistry(
        ExportProvider(name) for name in ("wireguard", "openvpn", "singbox")
    )
    clients = ClientService(provider_context.state, registry)
    identity = ServerIdentityManager(provider_context.paths)
    return (
        BootstrapService(_config(), provider_context.state, registry, clients, identity),
        client,
    )


@pytest.mark.parametrize(
    "providers,expected",
    [
        (("wireguard",), 1),
        (("openvpn",), 1),
        (("singbox",), 3),
        (("wireguard", "openvpn"), 2),
        (("wireguard", "singbox"), 4),
        (("openvpn", "singbox"), 4),
        (("wireguard", "openvpn", "singbox"), 5),
    ],
)
def test_all_provider_combinations(provider_context, tmp_path: Path, providers, expected) -> None:
    service, _ = _service(provider_context, providers)
    root = service.export("alice", tmp_path / "out")
    result = verify_bootstrap(root)
    assert result.artifact_count == expected
    assert result.trust_mode == "initial-offline"
    assert verify_bootstrap(root, pinned_trust=load_trust(root / "trust.json")).valid
    assert not (root / "private.key").exists()


def test_disabled_and_unprovisioned_profiles_are_excluded(provider_context, tmp_path: Path) -> None:
    service, client = _service(provider_context, ("singbox",))
    state = provider_context.state.load()
    state.profiles[0].enabled = False
    client_in_state = state.clients[0]
    client_in_state.profile_credentials.pop(str(state.profiles[1].id))
    provider_context.state.save(state)
    root = service.export(client.name, tmp_path / "out")
    descriptor = json.loads((root / "bootstrap.json").read_bytes())
    assert [item["path"] for item in descriptor["artifacts"]] == [
        f"singbox/profile-{state.profiles[2].id.hex}.json"
    ]


def test_bootstrap_binds_exact_manifest_generation(provider_context, tmp_path: Path) -> None:
    service, _ = _service(provider_context, ("wireguard", "openvpn"))
    live = service.export("alice", tmp_path / "out")
    generation_a = tmp_path / "generation-a"
    shutil.copytree(live, generation_a)
    live = service.export("alice", tmp_path / "out")
    generation_b = tmp_path / "generation-b"
    shutil.copytree(live, generation_b)
    pinned = load_trust(generation_a / "trust.json")
    assert verify_bootstrap(generation_a, pinned_trust=pinned).valid
    assert verify_bootstrap(generation_b, pinned_trust=pinned).valid

    mixed_a_manifest = tmp_path / "mixed-a-manifest"
    shutil.copytree(generation_b, mixed_a_manifest)
    for name in ("manifest.json", "manifest.sig"):
        shutil.copy2(generation_a / name, mixed_a_manifest / name)
    with pytest.raises(VerificationError, match="manifest digest"):
        verify_bootstrap(mixed_a_manifest, pinned_trust=pinned)

    mixed_b_manifest = tmp_path / "mixed-b-manifest"
    shutil.copytree(generation_a, mixed_b_manifest)
    for name in ("manifest.json", "manifest.sig"):
        shutil.copy2(generation_b / name, mixed_b_manifest / name)
    with pytest.raises(VerificationError, match="manifest digest"):
        verify_bootstrap(mixed_b_manifest, pinned_trust=pinned)

    resigned = tmp_path / "resigned-different-generation"
    shutil.copytree(generation_b, resigned)
    manifest = json.loads((resigned / "manifest.json").read_bytes())
    manifest["generated_at"] = datetime(2030, 1, 1, tzinfo=timezone.utc).isoformat()
    manifest_bytes = (
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False).encode() + b"\n"
    )
    (resigned / "manifest.json").write_bytes(manifest_bytes)
    (resigned / "manifest.sig").write_bytes(service.identity.sign(manifest_bytes))
    with pytest.raises(VerificationError, match="manifest digest"):
        verify_bootstrap(resigned, pinned_trust=pinned)


def test_every_signed_file_and_provider_artifact_tamper_is_detected(
    provider_context, tmp_path: Path
) -> None:
    service, _ = _service(provider_context, ("wireguard", "openvpn", "singbox"))
    root = service.export("alice", tmp_path / "out")
    descriptor = json.loads((root / "bootstrap.json").read_bytes())
    targets = [
        "manifest.json",
        "manifest.sig",
        "bootstrap.json",
        "bootstrap.sig",
        "trust.json",
        *(item["path"] for item in descriptor["artifacts"]),
    ]
    pinned = load_trust(root / "trust.json")
    for index, relative in enumerate(targets):
        copy = tmp_path / f"tampered-{index}"
        shutil.copytree(root, copy)
        path = copy / relative
        path.write_bytes(path.read_bytes() + b"tamper")
        with pytest.raises((VerificationError, OSError)):
            verify_bootstrap(copy, pinned_trust=pinned)


def test_replaced_bundle_trust_fails_pinned_verification(provider_context, tmp_path: Path) -> None:
    service, _ = _service(provider_context, ("wireguard",))
    root = service.export("alice", tmp_path / "out")
    pinned = load_trust(root / "trust.json")

    other_context_root = tmp_path / "other"
    other_paths = provider_context.paths.__class__(
        config_dir=other_context_root / "config",
        data_dir=other_context_root / "data",
        log_dir=other_context_root / "log",
        wireguard_dir=other_context_root / "wg",
        openvpn_dir=other_context_root / "ovpn",
        sysctl_dir=other_context_root / "sysctl",
        nftables_dir=other_context_root / "nft",
        systemd_dir=other_context_root / "systemd",
        local_lib_dir=other_context_root / "lib",
    )
    other = ServerIdentityManager(other_paths).ensure()
    (root / "trust.json").write_bytes(other.trust.render())
    with pytest.raises(VerificationError, match="pinned trust"):
        verify_bootstrap(root, pinned_trust=pinned)


def test_atomic_replacement_preserves_previous_bundle_on_provider_failure(
    provider_context, tmp_path: Path, monkeypatch
) -> None:
    service, _ = _service(provider_context, ("wireguard", "openvpn"))
    root = service.export("alice", tmp_path / "out")
    before = {
        path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }

    provider = service.providers.get("openvpn")
    monkeypatch.setattr(
        provider,
        "export_client",
        lambda _client: (_ for _ in ()).throw(FluxGateError("injected provider failure")),
    )
    with pytest.raises(FluxGateError, match="injected"):
        service.export("alice", tmp_path / "out")
    after = {
        path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }
    assert after == before
    assert verify_bootstrap(root)


def test_dry_run_creates_no_identity_lock_or_output(provider_context, tmp_path: Path) -> None:
    service, client = _service(provider_context, ("wireguard",))
    root = service.export("alice", tmp_path / "out", dry_run=True)
    assert root == tmp_path / "out" / f"client-{client.id.hex}"
    assert not root.exists()
    assert not service.identity.root.exists()
    assert not service.identity.paths.server_identity_lock_file.exists()


@pytest.mark.parametrize(
    "path",
    ["/absolute", "../escape", "a/../escape", "a\\escape", "é/config", "a//config"],
)
def test_artifact_paths_fail_closed(path: str) -> None:
    from fluxgate.core.publication import safe_relative_path

    with pytest.raises(FluxGateError, match="path"):
        safe_relative_path(path)


def test_unmanaged_destination_is_not_deleted(provider_context, tmp_path: Path) -> None:
    service, client = _service(provider_context, ("wireguard",))
    root = tmp_path / "out" / f"client-{client.id.hex}"
    root.mkdir(parents=True, mode=0o700)
    foreign = root / "foreign.txt"
    foreign.write_text("keep")
    foreign.chmod(0o600)
    with pytest.raises(VerificationError):
        service.export("alice", tmp_path / "out")
    assert foreign.read_text() == "keep"


def test_symlink_and_hardlink_artifacts_fail_closed(provider_context, tmp_path: Path) -> None:
    service, _ = _service(provider_context, ("wireguard",))
    root = service.export("alice", tmp_path / "out")
    client = provider_context.state.load().clients[0]
    artifact = root / "wireguard" / f"client-{client.id.hex}.conf"
    original = artifact.read_bytes()
    artifact.unlink()
    artifact.symlink_to(root / "manifest.json")
    with pytest.raises(VerificationError, match="symlink"):
        verify_bootstrap(root)
    artifact.unlink()
    artifact.write_bytes(original)
    artifact.chmod(0o600)
    hardlink = tmp_path / "hardlink"
    __import__("os").link(artifact, hardlink)
    with pytest.raises(VerificationError, match="hard links"):
        verify_bootstrap(root)


def test_simultaneous_bootstrap_replacements_leave_one_valid_generation(
    provider_context, tmp_path: Path
) -> None:
    service, _ = _service(provider_context, ("wireguard", "openvpn", "singbox"))
    with ThreadPoolExecutor(max_workers=4) as pool:
        roots = list(pool.map(lambda _: service.export("alice", tmp_path / "out"), range(8)))
    assert len(set(roots)) == 1
    assert verify_bootstrap(roots[0]).artifact_count == 5
    assert not list((tmp_path / "out").glob(f".{roots[0].name}.*"))


def test_verifier_during_atomic_replacement_never_accepts_a_partial_bundle(
    provider_context, tmp_path: Path
) -> None:
    service, _ = _service(provider_context, ("wireguard", "openvpn", "singbox"))
    root = service.export("alice", tmp_path / "out")
    pinned = load_trust(root / "trust.json")

    def replace_repeatedly() -> None:
        for _ in range(30):
            service.export("alice", tmp_path / "out")

    def verify_repeatedly() -> int:
        valid = 0
        for _ in range(300):
            try:
                result = verify_bootstrap(root, pinned_trust=pinned)
            except VerificationError:
                continue
            assert result.client_id == UUID("10000000-0000-0000-0000-000000000001")
            assert result.artifact_count == 5
            valid += 1
        return valid

    with ThreadPoolExecutor(max_workers=2) as pool:
        writer = pool.submit(replace_repeatedly)
        reader = pool.submit(verify_repeatedly)
        writer.result()
        successful_reads = reader.result()
    assert successful_reads > 0
    assert verify_bootstrap(root, pinned_trust=pinned).artifact_count == 5


def test_bootstrap_paths_use_stable_ascii_ids_not_display_names(
    provider_context, tmp_path: Path
) -> None:
    service, client = _service(
        provider_context,
        ("wireguard", "openvpn", "singbox"),
        client_name="用户",
        profile_names=("Test", "test", "é"),
    )
    first = service.export(client.name, tmp_path / "out")
    descriptor = BootstrapDescriptor.model_validate_json((first / "bootstrap.json").read_bytes())
    first_paths = tuple(item.path for item in descriptor.artifacts)
    assert first.name == f"client-{client.id.hex}"
    assert all(path.isascii() and path == path.casefold() for path in first_paths)
    assert len(first_paths) == len(set(first_paths))
    assert any(f"profile-{_profiles()[0].id.hex}.json" in path for path in first_paths)
    assert any(f"profile-{_profiles()[1].id.hex}.json" in path for path in first_paths)
    second = service.export(client.name, tmp_path / "out")
    second_descriptor = BootstrapDescriptor.model_validate_json(
        (second / "bootstrap.json").read_bytes()
    )
    assert tuple(item.path for item in second_descriptor.artifacts) == first_paths


@pytest.mark.parametrize("client_name", ["é", "İphone", "用户", "a" * 64])
def test_v03_valid_display_names_bootstrap_with_ascii_paths(
    provider_context, tmp_path: Path, client_name: str
) -> None:
    service, client = _service(provider_context, ("wireguard",), client_name=client_name)
    root = service.export(client.name, tmp_path / "out")
    descriptor = BootstrapDescriptor.model_validate_json((root / "bootstrap.json").read_bytes())
    assert descriptor.client_name == client_name
    assert all(item.path.isascii() for item in descriptor.artifacts)


def test_casefold_colliding_descriptor_paths_are_rejected(provider_context, tmp_path: Path) -> None:
    service, _ = _service(provider_context, ("wireguard",))
    root = service.export("alice", tmp_path / "out")
    payload = json.loads((root / "bootstrap.json").read_bytes())
    duplicate = dict(payload["artifacts"][0])
    duplicate["path"] = duplicate["path"].upper()
    payload["artifacts"].append(duplicate)
    with pytest.raises(ValidationError, match="paths must be unique"):
        BootstrapDescriptor.model_validate_json(json.dumps(payload))


def test_decomposed_or_traversal_display_names_remain_invalid() -> None:
    with pytest.raises(ValidationError):
        Client(name="e\N{COMBINING ACUTE ACCENT}")
    with pytest.raises(ValidationError):
        Client(name="../alice")


def test_cross_client_bundles_remain_isolated_through_state_changes_and_concurrency(
    provider_context, tmp_path: Path
) -> None:
    profiles = _profiles()
    clients = [
        Client(
            id=UUID("20000000-0000-0000-0000-000000000001"),
            name="client-a",
            provider_credentials={
                "wireguard": {"marker": "a-wireguard-secret"},
                "openvpn": {"marker": "a-openvpn-secret"},
            },
            profile_credentials={
                str(profile.id): {"value": f"a-{profile.name}-secret"} for profile in profiles
            },
        ),
        Client(
            id=UUID("20000000-0000-0000-0000-000000000002"),
            name="client-b",
            provider_credentials={
                "wireguard": {"marker": "b-wireguard-secret"},
                "openvpn": {"marker": "b-openvpn-secret"},
            },
            profile_credentials={
                str(profile.id): {"value": f"b-{profile.name}-secret"} for profile in profiles
            },
        ),
    ]
    provider_context.state.save(FluxGateState(clients=clients, profiles=profiles))
    registry = ProviderRegistry(
        ExportProvider(name) for name in ("wireguard", "openvpn", "singbox")
    )
    service = BootstrapService(
        _config(),
        provider_context.state,
        registry,
        ClientService(provider_context.state, registry),
        ServerIdentityManager(provider_context.paths),
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        bundle_a, bundle_b = list(
            pool.map(
                lambda item: service.export(item[0], item[1]),
                (("client-a", tmp_path / "a"), ("client-b", tmp_path / "b")),
            )
        )
    bytes_a = b"\n".join(path.read_bytes() for path in bundle_a.rglob("*") if path.is_file())
    bytes_b = b"\n".join(path.read_bytes() for path in bundle_b.rglob("*") if path.is_file())
    assert str(clients[1].id).encode() not in bytes_a
    assert str(clients[0].id).encode() not in bytes_b
    assert b"b-vless-secret" not in bytes_a
    assert b"a-vless-secret" not in bytes_b

    state = provider_context.state.load()
    state.clients[0].provider_credentials.clear()
    state.clients[0].profile_credentials.clear()
    provider_context.state.save(state)
    with pytest.raises(FluxGateError, match="no provisioned credentials"):
        service.export("client-a", tmp_path / "revoked-a")
    assert verify_bootstrap(service.export("client-b", tmp_path / "b")).artifact_count == 5

    state = provider_context.state.load()
    state.clients[0].provider_credentials["wireguard"] = {"marker": "a-reprovisioned"}
    provider_context.state.save(state)
    reprovisioned_a = service.export("client-a", tmp_path / "reprovisioned-a")
    assert verify_bootstrap(reprovisioned_a).artifact_count == 1
    assert str(clients[1].id).encode() not in b"\n".join(
        path.read_bytes() for path in reprovisioned_a.rglob("*") if path.is_file()
    )

    state = provider_context.state.load()
    removed = state.profiles.pop(0)
    provider_context.state.save(state)
    without_profile = service.export("client-b", tmp_path / "b")
    without_paths = {
        item.path
        for item in BootstrapDescriptor.model_validate_json(
            (without_profile / "bootstrap.json").read_bytes()
        ).artifacts
    }
    assert f"singbox/profile-{removed.id.hex}.json" not in without_paths

    replacement = removed.model_copy(update={"id": UUID("30000000-0000-0000-0000-000000000001")})
    state = provider_context.state.load()
    state.profiles.append(replacement)
    state.clients[1].profile_credentials[str(replacement.id)] = {"value": "b-recreated-secret"}
    provider_context.state.save(state)
    recreated = service.export("client-b", tmp_path / "b")
    recreated_paths = {
        item.path
        for item in BootstrapDescriptor.model_validate_json(
            (recreated / "bootstrap.json").read_bytes()
        ).artifacts
    }
    assert f"singbox/profile-{replacement.id.hex}.json" in recreated_paths
    assert f"singbox/profile-{removed.id.hex}.json" not in recreated_paths


@pytest.mark.parametrize("failure_write", [1, 3, 6, 8])
def test_staging_write_failures_restore_exact_previous_bundle(
    provider_context, tmp_path: Path, monkeypatch, failure_write: int
) -> None:
    import fluxgate.core.publication as publication

    service, _ = _service(provider_context, ("wireguard", "openvpn", "singbox"))
    root = service.export("alice", tmp_path / "out")
    before = {
        path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }
    real_write = publication.atomic_write
    calls = 0

    def failing_write(path, content, mode):
        nonlocal calls
        calls += 1
        if calls == failure_write:
            raise OSError("injected staging write failure")
        return real_write(path, content, mode)

    monkeypatch.setattr(publication, "atomic_write", failing_write)
    with pytest.raises(OSError, match="injected"):
        service.export("alice", tmp_path / "out")
    after = {
        path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }
    assert after == before
    assert verify_bootstrap(root)


def test_final_swap_and_post_publish_verification_failures_restore_previous_bundle(
    provider_context, tmp_path: Path, monkeypatch
) -> None:
    import fluxgate.bootstrap.service as bootstrap_module
    import fluxgate.core.publication as publication

    service, _ = _service(provider_context, ("wireguard", "openvpn"))
    root = service.export("alice", tmp_path / "out")
    before = {
        path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }
    real_rename = publication.os.rename
    rename_calls = 0

    def failing_rename(source, destination):
        nonlocal rename_calls
        rename_calls += 1
        if rename_calls == 2:
            raise OSError("injected final swap failure")
        return real_rename(source, destination)

    monkeypatch.setattr(publication.os, "rename", failing_rename)
    with pytest.raises(OSError, match="final swap"):
        service.export("alice", tmp_path / "out")
    assert {
        path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()
    } == before
    monkeypatch.setattr(publication.os, "rename", real_rename)

    real_verify = bootstrap_module.verify_bootstrap
    verify_calls = 0

    def failing_verify(path, *, pinned_trust=None):
        nonlocal verify_calls
        verify_calls += 1
        if verify_calls == 3:
            raise VerificationError("injected post-publication verification failure")
        return real_verify(path, pinned_trust=pinned_trust)

    monkeypatch.setattr(bootstrap_module, "verify_bootstrap", failing_verify)
    with pytest.raises(VerificationError, match="post-publication"):
        service.export("alice", tmp_path / "out")
    assert {
        path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()
    } == before


def test_bootstrap_verification_cli_is_noninteractive_json_and_secret_free(
    provider_context, tmp_path: Path
) -> None:
    service, _ = _service(provider_context, ("wireguard", "openvpn", "singbox"))
    root = service.export("alice", tmp_path / "out")
    result = CliRunner().invoke(
        app,
        [
            "client",
            "bootstrap-verify",
            str(root),
            "--pinned-trust",
            str(root / "trust.json"),
            "--json",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1
    assert payload["valid"] is True
    assert payload["trust_mode"] == "pinned"
    assert "credential" not in result.stdout
    (root / "manifest.json").write_bytes((root / "manifest.json").read_bytes() + b" ")
    failed = CliRunner().invoke(app, ["client", "bootstrap-verify", str(root)])
    assert failed.exit_code == 1
    assert "Error:" in failed.stderr


def test_bootstrap_cli_dry_run_creates_no_identity_lock_or_bundle(
    tmp_path: Path, monkeypatch
) -> None:
    config_dir = tmp_path / "config"
    data_dir = tmp_path / "data"
    output = tmp_path / "output"
    monkeypatch.setenv("FLUXGATE_CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("FLUXGATE_DATA_DIR", str(data_dir))
    application = build_application()
    application.state.save(FluxGateState(clients=[Client(name="dry-client")]))
    result = CliRunner().invoke(
        app,
        ["client", "bootstrap", "dry-client", "--output", str(output), "--dry-run"],
    )
    assert result.exit_code == 0
    assert "would create bootstrap bundle" in result.stdout
    assert not output.exists()
    assert not (config_dir / "secrets" / "server-identity").exists()
    assert not (data_dir / "server-identity.lock").exists()
