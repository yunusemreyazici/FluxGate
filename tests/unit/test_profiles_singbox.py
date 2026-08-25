from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import tarfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from fluxgate.clients import ClientService
from fluxgate.core.commands import CommandRunner
from fluxgate.core.errors import FluxGateError, ProviderError, StateError
from fluxgate.core.manifest import render_manifest
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
from fluxgate.core.state import StateStore
from fluxgate.profiles import ProfileService, protocol_spec
from fluxgate.providers.base import CoreProvider
from fluxgate.providers.singbox import SingBoxProvider
from fluxgate.providers.singbox import provider as singbox_provider_module
from fluxgate.providers.singbox.rendering import render_client, render_server
from fluxgate.providers.singbox.tls import ManagedTLSIdentityManager, TLSIdentity
from fluxgate.system import packages as package_module
from fluxgate.system.packages import AptPackageManager


class ProfileProvider(CoreProvider):
    name = "singbox"
    display_name = "sing-box"
    capabilities = frozenset(
        {
            ProviderCapability.MANAGE_PROFILES,
            ProviderCapability.PROFILE_CLIENTS,
            ProviderCapability.PROFILE_EXPORT,
        }
    )

    def __init__(self, context) -> None:
        super().__init__(context)
        self.reconciliations: list[FluxGateState] = []

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
        return OperationResult(changed=False, message="running")

    def disable(self) -> OperationResult:
        return OperationResult(changed=False, message="running")

    def reconcile_profiles(self, desired: FluxGateState) -> OperationResult:
        self.reconciliations.append(desired.model_copy(deep=True))
        return OperationResult(changed=True, message="reconciled")

    def validate_profile(self, profile: ProfileDefinition, state: FluxGateState) -> None:
        return None

    def generate_profile_credential(self, profile: ProfileDefinition) -> dict[str, object]:
        return (
            {"schema_version": 1, "uuid": "12345678-1234-5678-1234-567812345678"}
            if profile.protocol == ProtocolName.VLESS
            else {"schema_version": 1, "password": "test-only-secret"}
        )

    def export_profile(self, client: Client, profile: ProfileDefinition) -> ExportArtifact:
        return ExportArtifact(
            name=f"{profile.name}.json", media_type="application/json", content="{}\n"
        )


def profile(
    name: str = "primary-vless",
    protocol: ProtocolName = ProtocolName.VLESS,
    transport: TransportName = TransportName.TCP,
    port: int = 8443,
    enabled: bool = True,
) -> ProfileDefinition:
    return ProfileDefinition(
        name=name,
        protocol=protocol,
        transport=transport,
        security=SecurityName.TLS,
        listen_port=port,
        enabled=enabled,
    )


@pytest.mark.parametrize(
    ("protocol", "transport"),
    [
        (ProtocolName.VLESS, TransportName.TCP),
        (ProtocolName.TROJAN, TransportName.TCP),
        (ProtocolName.HYSTERIA2, TransportName.QUIC),
    ],
)
def test_supported_profile_combinations(protocol: ProtocolName, transport: TransportName) -> None:
    item = profile(protocol=protocol, transport=transport)
    assert item.protocol == protocol
    assert protocol_spec(protocol).capabilities.requires_nat is False
    assert protocol_spec(protocol).capabilities.requires_ip_forwarding is False


def test_invalid_combinations_unknown_fields_and_unsafe_names_fail_closed() -> None:
    with pytest.raises(ValidationError, match="unsupported"):
        profile(protocol=ProtocolName.HYSTERIA2, transport=TransportName.TCP)
    with pytest.raises(ValidationError, match="profile name"):
        profile(name="../unsafe")
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ProfileDefinition.model_validate(
            {
                "name": "valid",
                "protocol": "vless",
                "transport": "tcp",
                "security": "tls",
                "listen_port": 8443,
                "raw_json": {},
            }
        )


def test_profile_service_persists_stable_id_and_blocks_duplicate_endpoint(provider_context) -> None:
    provider = ProfileProvider(provider_context)
    service = ProfileService(provider_context.state, ProviderRegistry([provider]))
    created = service.create(
        name="primary",
        provider="singbox",
        protocol=ProtocolName.VLESS,
        transport=TransportName.TCP,
        security=SecurityName.TLS,
        port=8443,
    )
    assert service.find(str(created.id)).id == created.id
    with pytest.raises(FluxGateError, match="endpoint already exists"):
        service.create(
            name="duplicate",
            provider="singbox",
            protocol=ProtocolName.TROJAN,
            transport=TransportName.TCP,
            security=SecurityName.TLS,
            port=8443,
        )


def test_profile_enable_disable_delete_and_dry_run(provider_context) -> None:
    provider = ProfileProvider(provider_context)
    service = ProfileService(provider_context.state, ProviderRegistry([provider]))
    dry = service.create(
        name="dry",
        provider="singbox",
        protocol=ProtocolName.VLESS,
        transport=TransportName.TCP,
        security=SecurityName.TLS,
        port=9443,
        dry_run=True,
    )
    assert dry.name == "dry" and service.list() == []
    assert not provider_context.state.path.with_suffix(".json.lock").exists()
    created = service.create(
        name="primary",
        provider="singbox",
        protocol=ProtocolName.VLESS,
        transport=TransportName.TCP,
        security=SecurityName.TLS,
        port=8443,
    )
    assert service.set_enabled(created.name, True).changed
    assert provider.reconciliations[-1].profiles[0].enabled
    assert service.set_enabled(created.name, False).changed
    assert service.delete(created.name) == created.id


def test_profile_client_provision_is_scoped_idempotent_and_selectively_revoked(
    provider_context, tmp_path: Path
) -> None:
    provider = ProfileProvider(provider_context)
    registry = ProviderRegistry([provider])
    profiles = ProfileService(provider_context.state, registry)
    clients = ClientService(provider_context.state, registry)
    first = profiles.create(
        name="vless",
        provider="singbox",
        protocol=ProtocolName.VLESS,
        transport=TransportName.TCP,
        security=SecurityName.TLS,
        port=8443,
    )
    second = profiles.create(
        name="trojan",
        provider="singbox",
        protocol=ProtocolName.TROJAN,
        transport=TransportName.TCP,
        security=SecurityName.TLS,
        port=8444,
    )
    profiles.set_enabled(first.name, True)
    profiles.set_enabled(second.name, True)
    clients.add("alice")
    enabled = clients.enable_profile("alice", first.name)
    assert set(enabled.profile_credentials) == {str(first.id)}
    assert clients.enable_profile("alice", first.name).profile_credentials == (
        enabled.profile_credentials
    )
    clients.enable_profile("alice", second.name)
    clients.disable_profile("alice", first.name)
    remaining = clients.find("alice")
    assert set(remaining.profile_credentials) == {str(second.id)}
    written = clients.export("alice", tmp_path)
    assert written == [tmp_path / "alice" / "singbox" / "trojan.json"]
    assert stat.S_IMODE(written[0].stat().st_mode) == 0o600


def test_profile_delete_refuses_active_credentials(provider_context) -> None:
    provider = ProfileProvider(provider_context)
    registry = ProviderRegistry([provider])
    profiles = ProfileService(provider_context.state, registry)
    clients = ClientService(provider_context.state, registry)
    created = profiles.create(
        name="primary",
        provider="singbox",
        protocol=ProtocolName.VLESS,
        transport=TransportName.TCP,
        security=SecurityName.TLS,
        port=8443,
    )
    profiles.set_enabled(created.name, True)
    clients.add("alice")
    clients.enable_profile("alice", created.name)
    profiles.set_enabled(created.name, False)
    with pytest.raises(FluxGateError, match="provisioned clients"):
        profiles.delete(created.name)


def test_individual_profile_export_preserves_other_current_profile_artifacts(
    provider_context, tmp_path: Path
) -> None:
    provider = ProfileProvider(provider_context)
    registry = ProviderRegistry([provider])
    profiles = ProfileService(provider_context.state, registry)
    clients = ClientService(provider_context.state, registry)
    created = []
    for name, protocol, port in (
        ("vless", ProtocolName.VLESS, 8443),
        ("trojan", ProtocolName.TROJAN, 8444),
    ):
        item = profiles.create(
            name=name,
            provider="singbox",
            protocol=protocol,
            transport=TransportName.TCP,
            security=SecurityName.TLS,
            port=port,
        )
        profiles.set_enabled(item.name, True)
        created.append(item)
    clients.add("alice")
    for item in created:
        clients.enable_profile("alice", item.name)
    clients.export("alice", tmp_path)
    clients.export("alice", tmp_path, profile_identity="vless")
    assert {path.name for path in (tmp_path / "alice" / "singbox").glob("*.json")} == {
        "vless.json",
        "trojan.json",
    }


def test_server_and_client_render_all_protocols_without_insecure() -> None:
    profiles = [
        profile("vless", ProtocolName.VLESS, TransportName.TCP, 8443),
        profile("trojan", ProtocolName.TROJAN, TransportName.TCP, 8444),
        profile("hy2", ProtocolName.HYSTERIA2, TransportName.QUIC, 8445),
    ]
    alice = Client(name="alice")
    alice.profile_credentials = {
        str(profiles[0].id): {"schema_version": 1, "uuid": "12345678-1234-5678-1234-567812345678"},
        str(profiles[1].id): {"schema_version": 1, "password": "trojan-secret"},
        str(profiles[2].id): {"schema_version": 1, "password": "hy2-secret"},
    }
    state = FluxGateState(clients=[alice], profiles=profiles)
    server = json.loads(
        render_server(state, Path("/cert.pem"), Path("/key.pem"), "vpn.example.com")
    )
    assert [item["type"] for item in server["inbounds"]] == ["trojan", "vless", "hysteria2"] or {
        item["type"] for item in server["inbounds"]
    } == {"vless", "trojan", "hysteria2"}
    exported = render_client(alice, profiles[0], "vpn.example.com", "CA PEM")
    assert '"insecure"' not in exported
    assert "CA PEM" in exported
    assert '"listen": "127.0.0.1"' in exported


def test_manifest_is_deterministic_enabled_only_and_secret_free(provider_context) -> None:
    enabled = profile("enabled", enabled=True)
    disabled = profile("disabled", port=8444, enabled=False)
    client = Client(name="alice")
    client.profile_credentials[str(enabled.id)] = {"password": "must-not-leak"}
    provider_context.state.save(FluxGateState(clients=[client], profiles=[disabled, enabled]))
    first = render_manifest(provider_context.config, provider_context.state)
    assert first == render_manifest(provider_context.config, provider_context.state)
    document = json.loads(first)
    assert [item["name"] for item in document["profiles"]] == ["enabled"]
    assert b"must-not-leak" not in first and b"alice" not in first
    assert document["profiles"][0]["requires_nat"] is False


def test_v02_state_migration_preserves_credentials_and_fails_future(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "clients": [
                    {
                        "id": "12345678-1234-5678-1234-567812345678",
                        "name": "bob",
                        "created_at": "2026-01-01T00:00:00Z",
                        "enabled": True,
                        "expires_at": None,
                        "metadata": {},
                        "provider_credentials": {
                            "wireguard": {"private_key": "preserved"},
                            "openvpn": {"serial": "01"},
                        },
                    }
                ],
                "providers": {"wireguard": {"enabled": True}},
            }
        )
    )
    loaded = StateStore(path).load()
    assert loaded.schema_version == 2
    assert loaded.clients[0].provider_credentials["wireguard"]["private_key"] == "preserved"
    assert loaded.clients[0].profile_credentials == {}
    assert json.loads(path.read_text())["schema_version"] == 1
    path.write_text('{"schema_version": 99}')
    with pytest.raises(StateError, match="schema_version"):
        StateStore(path).load()
    path.write_text('{"schema_version": true}')
    with pytest.raises(StateError, match="schema_version"):
        StateStore(path).load()


def test_managed_tls_identity_has_san_private_modes_and_reuses_valid_identity(
    provider_context,
) -> None:
    provider_context.runner = CommandRunner()
    manager = ManagedTLSIdentityManager(provider_context)
    identity = manager.ensure("vpn.example.com")
    assert stat.S_IMODE(identity.private_key.stat().st_mode) == 0o600
    assert stat.S_IMODE(manager.ca_key.stat().st_mode) == 0o600
    assert manager.valid(identity, "vpn.example.com")
    assert manager.ensure("vpn.example.com") == identity
    manager.ca_key.chmod(0o644)
    assert manager.valid(identity, "vpn.example.com") is False
    with pytest.raises(ProviderError, match="CA private key is unsafe"):
        manager.ensure("vpn.example.com")


def test_singbox_conflicts_model_tcp_and_udp_separately(provider_context) -> None:
    provider = SingBoxProvider(provider_context)
    provider_context.network.occupied_ports.add(8443)
    with pytest.raises(ProviderError, match="foreign listener"):
        provider._check_profile_conflicts(FluxGateState(profiles=[profile(port=8443)]))
    udp = profile(
        "hy2",
        ProtocolName.HYSTERIA2,
        TransportName.QUIC,
        provider_context.config.cores.wireguard.listen_port,
    )
    with pytest.raises(ProviderError, match="VPN provider"):
        provider._check_profile_conflicts(FluxGateState(profiles=[udp]))


def prepared_provider(provider_context, monkeypatch) -> tuple[SingBoxProvider, TLSIdentity]:
    provider = SingBoxProvider(provider_context)
    provider.binary.parent.mkdir(parents=True, exist_ok=True)
    provider.binary.write_bytes(b"test binary")
    provider.binary.chmod(0o755)
    provider.binary_marker.write_bytes(provider.BINARY_OWNER)
    provider.binary_marker.chmod(0o600)
    tls_dir = provider_context.paths.singbox_tls_dir
    tls_dir.mkdir(parents=True)
    ca = tls_dir / "ca.pem"
    cert = tls_dir / "cert.pem"
    key = tls_dir / "key.pem"
    ca.write_text("test CA")
    cert.write_text("test cert")
    key.write_text("test key")
    ca.chmod(0o644)
    cert.chmod(0o644)
    key.chmod(0o600)
    identity = TLSIdentity(ca, cert, key)
    monkeypatch.setattr(ManagedTLSIdentityManager, "ensure", lambda self, host: identity)
    monkeypatch.setattr(ManagedTLSIdentityManager, "valid", lambda self, value, host: True)
    monkeypatch.setattr(ManagedTLSIdentityManager, "_load_current", lambda self: identity)
    monkeypatch.setattr(provider, "_listeners_healthy", lambda state: True)
    return provider, identity


def test_singbox_enable_repeat_drift_disable_and_shared_resource_independence(
    provider_context, monkeypatch
) -> None:
    provider, _ = prepared_provider(provider_context, monkeypatch)
    assert provider.enable().changed
    assert provider_context.state.load().providers["singbox"]["enabled"] is True
    assert provider_context.services.is_active(provider.unit)
    assert provider_context.services.is_enabled(provider.unit)
    assert provider.config_path.stat().st_mode & 0o777 == 0o600
    assert provider.unit_path.read_text().startswith(provider.UNIT_HEADER)
    assert provider_context.forwarding.consumers == set()
    assert provider_context.firewall.rules == {}
    assert provider.enable().changed is False
    provider.config_path.write_text("drift")
    assert provider.enable().changed
    assert f"restart:{provider.unit}" in provider_context.services.events
    assert b'"outbounds"' in provider.config_path.read_bytes()
    assert provider.disable().changed
    assert provider_context.state.load().providers["singbox"]["enabled"] is False
    assert provider.disable().changed is False


def test_singbox_dry_run_has_no_files_state_secrets_or_service_mutation(
    provider_context,
) -> None:
    provider_context.dry_run = True
    provider = SingBoxProvider(provider_context)
    result = provider.enable()
    assert result.changed and "verified" in " ".join(result.actions)
    assert not provider.config_path.exists()
    assert not provider_context.paths.state_file.exists()
    assert not provider_context.paths.singbox_tls_dir.exists()
    assert provider_context.services.events == []


def test_singbox_refuses_foreign_config_and_unit(provider_context) -> None:
    provider = SingBoxProvider(provider_context)
    provider.config_path.parent.mkdir(parents=True)
    provider.config_path.write_text("foreign")
    with pytest.raises(ProviderError, match="unmanaged sing-box config"):
        provider.enable()
    provider.config_path.unlink()
    provider.unit_path.parent.mkdir(parents=True, exist_ok=True)
    provider.unit_path.write_text("[Unit]\nDescription=foreign\n")
    with pytest.raises(ProviderError, match="unmanaged systemd unit"):
        provider.enable()


def test_singbox_refuses_symlinked_config_and_tls_roots(provider_context, tmp_path: Path) -> None:
    provider = SingBoxProvider(provider_context)
    foreign_config = tmp_path / "foreign-config"
    foreign_config.mkdir()
    provider.config_path.parent.parent.mkdir(parents=True, exist_ok=True)
    provider.config_path.parent.symlink_to(foreign_config, target_is_directory=True)
    with pytest.raises(ProviderError, match="symlinked sing-box config"):
        provider.enable()

    provider.config_path.parent.unlink()
    foreign_tls = tmp_path / "foreign-tls"
    foreign_tls.mkdir()
    provider_context.paths.secrets_dir.mkdir(parents=True, exist_ok=True)
    provider_context.paths.singbox_tls_dir.symlink_to(foreign_tls, target_is_directory=True)
    with pytest.raises(ProviderError, match="symlinked TLS identity"):
        ManagedTLSIdentityManager(provider_context).ensure("vpn.example.com")


def test_singbox_validation_and_service_false_success_roll_back_owned_files(
    provider_context, monkeypatch
) -> None:
    provider, _ = prepared_provider(provider_context, monkeypatch)
    monkeypatch.setattr(
        provider, "_validate", lambda content: (_ for _ in ()).throw(ProviderError("bad config"))
    )
    with pytest.raises(FluxGateError, match="bad config"):
        provider.enable()
    assert not provider.config_path.exists()
    assert not provider.unit_path.exists()
    monkeypatch.setattr(provider, "_validate", lambda content: None)
    monkeypatch.setattr(provider_context.services, "enable_now", lambda unit: None)
    with pytest.raises(FluxGateError, match="postcondition"):
        provider.enable()
    assert not provider.config_path.exists()
    assert not provider.unit_path.exists()


def test_singbox_restart_waits_for_listener_startup_race(provider_context, monkeypatch) -> None:
    provider, identity = prepared_provider(provider_context, monkeypatch)
    provider.enable()
    desired = provider_context.state.load()
    desired.profiles.append(profile())
    checks = iter((False, False, True))
    monkeypatch.setattr(provider, "_listeners_healthy", lambda state: next(checks))
    monkeypatch.setattr(singbox_provider_module.time, "sleep", lambda seconds: None)
    assert provider._publish_config(desired, identity)


def test_profile_state_failure_does_not_mutate_server(provider_context, monkeypatch) -> None:
    provider = ProfileProvider(provider_context)
    service = ProfileService(provider_context.state, ProviderRegistry([provider]))
    created = service.create(
        name="primary",
        provider="singbox",
        protocol=ProtocolName.VLESS,
        transport=TransportName.TCP,
        security=SecurityName.TLS,
        port=8443,
    )
    monkeypatch.setattr(
        provider_context.state,
        "save",
        lambda state: (_ for _ in ()).throw(StateError("injected save failure")),
    )
    with pytest.raises(StateError, match="injected save failure"):
        service.set_enabled(created.name, True)
    assert provider.reconciliations == []
    assert provider_context.state.load().profiles[0].enabled is False


def test_client_profile_save_failure_removes_generated_credential_from_server_and_state(
    provider_context, monkeypatch
) -> None:
    provider = ProfileProvider(provider_context)
    registry = ProviderRegistry([provider])
    profiles = ProfileService(provider_context.state, registry)
    clients = ClientService(provider_context.state, registry)
    created = profiles.create(
        name="primary",
        provider="singbox",
        protocol=ProtocolName.VLESS,
        transport=TransportName.TCP,
        security=SecurityName.TLS,
        port=8443,
    )
    profiles.set_enabled(created.name, True)
    clients.add("alice")
    reconciliations_before = len(provider.reconciliations)
    monkeypatch.setattr(
        provider_context.state,
        "save",
        lambda state: (_ for _ in ()).throw(StateError("injected save failure")),
    )
    with pytest.raises(StateError, match="injected save failure"):
        clients.enable_profile("alice", created.name)
    assert len(provider.reconciliations) == reconciliations_before
    assert provider_context.state.load().clients[0].profile_credentials == {}


def test_profile_and_credential_apply_failures_restore_durable_desired_state(
    provider_context, monkeypatch
) -> None:
    provider = ProfileProvider(provider_context)
    registry = ProviderRegistry([provider])
    profiles = ProfileService(provider_context.state, registry)
    clients = ClientService(provider_context.state, registry)
    created = profiles.create(
        name="primary",
        provider="singbox",
        protocol=ProtocolName.VLESS,
        transport=TransportName.TCP,
        security=SecurityName.TLS,
        port=8443,
    )
    calls = 0

    def fail_enabled(desired: FluxGateState) -> OperationResult:
        nonlocal calls
        calls += 1
        if desired.profiles[0].enabled:
            raise ProviderError("injected host apply failure")
        return OperationResult(changed=True, message="rolled back")

    monkeypatch.setattr(provider, "reconcile_profiles", fail_enabled)
    with pytest.raises(ProviderError, match="host apply failure"):
        profiles.set_enabled(created.name, True)
    assert calls == 2
    assert provider_context.state.load().profiles[0].enabled is False

    monkeypatch.setattr(
        provider, "reconcile_profiles", ProfileProvider.reconcile_profiles.__get__(provider)
    )
    profiles.set_enabled(created.name, True)
    clients.add("alice")
    calls = 0

    def fail_credential(desired: FluxGateState) -> OperationResult:
        nonlocal calls
        calls += 1
        if desired.clients[0].profile_credentials:
            raise ProviderError("injected credential apply failure")
        return OperationResult(changed=True, message="rolled back")

    monkeypatch.setattr(provider, "reconcile_profiles", fail_credential)
    with pytest.raises(ProviderError, match="credential apply failure"):
        clients.enable_profile("alice", created.name)
    assert calls == 2
    assert provider_context.state.load().clients[0].profile_credentials == {}


def test_verified_release_acquisition_is_atomic_and_rejects_bad_checksum(
    tmp_path: Path, monkeypatch
) -> None:
    member_name = "sing-box-1.13.19-linux-amd64/sing-box"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        data = b"executable"
        member = tarfile.TarInfo(member_name)
        member.size = len(data)
        bundle.addfile(member, io.BytesIO(data))
    archive = buffer.getvalue()

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args) -> None:
            self.close()

    monkeypatch.setattr(package_module.platform, "machine", lambda: "x86_64")
    monkeypatch.setitem(
        package_module.SING_BOX_ASSETS,
        "x86_64",
        ("amd64", hashlib.sha256(archive).hexdigest()),
    )
    monkeypatch.setattr(
        package_module.urllib.request, "urlopen", lambda url, timeout: Response(archive)
    )
    destination = tmp_path / "managed" / "sing-box"
    assert AptPackageManager(CommandRunner()).acquire_sing_box(destination)
    assert destination.read_bytes() == b"executable"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o755
    destination.unlink()
    monkeypatch.setitem(package_module.SING_BOX_ASSETS, "x86_64", ("amd64", "0" * 64))
    with pytest.raises(ProviderError, match="checksum"):
        AptPackageManager(CommandRunner()).acquire_sing_box(destination)
    assert not destination.exists()


def test_generated_configs_pass_real_singbox_check_when_binary_is_supplied(
    provider_context, tmp_path: Path
) -> None:
    binary = os.environ.get("SING_BOX_TEST_BINARY")
    if binary is None:
        pytest.skip("set SING_BOX_TEST_BINARY for upstream parser validation")
    provider_context.runner = CommandRunner()
    identity = ManagedTLSIdentityManager(provider_context).ensure("vpn.example.com")
    profiles = [
        profile("vless", ProtocolName.VLESS, TransportName.TCP, 18443),
        profile("trojan", ProtocolName.TROJAN, TransportName.TCP, 18444),
        profile("hy2", ProtocolName.HYSTERIA2, TransportName.QUIC, 18445),
    ]
    client = Client(name="parser-test")
    client.profile_credentials = {
        str(profiles[0].id): {
            "schema_version": 1,
            "uuid": "12345678-1234-5678-1234-567812345678",
        },
        str(profiles[1].id): {"schema_version": 1, "password": "trojan-secret"},
        str(profiles[2].id): {"schema_version": 1, "password": "hy2-secret"},
    }
    state = FluxGateState(clients=[client], profiles=profiles)
    server = tmp_path / "server.json"
    server.write_bytes(
        render_server(state, identity.certificate, identity.private_key, "vpn.example.com")
    )
    CommandRunner().run([binary, "check", "-c", str(server)])
    for item in profiles:
        exported = tmp_path / f"{item.name}.json"
        exported.write_text(
            render_client(client, item, "vpn.example.com", identity.ca_certificate.read_text())
        )
        CommandRunner().run([binary, "check", "-c", str(exported)])
