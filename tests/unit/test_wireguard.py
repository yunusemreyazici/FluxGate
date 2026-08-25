import pytest

from fluxgate.clients import ClientService
from fluxgate.core.errors import FluxGateError
from fluxgate.core.models import Client, ProviderDetection
from fluxgate.core.registry import ProviderRegistry
from fluxgate.providers.wireguard import WireGuardProvider


def available() -> ProviderDetection:
    return ProviderDetection(available=True, binaries={"wg": True, "wg-quick": True, "nft": True})


def test_enable_is_idempotent_and_preserves_keys(provider_context, monkeypatch) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    first = provider.enable()
    private = provider.private_key_path.read_text()
    second = provider.enable()
    assert first.changed
    assert not second.changed
    assert provider.private_key_path.read_text() == private
    assert provider.config_path.stat().st_mode & 0o777 == 0o600
    assert provider_context.firewall.present
    assert provider_context.services.events.count(f"enable:{provider.unit}") == 1


def test_enable_repairs_configuration_drift_without_rotating_keys(
    provider_context, monkeypatch
) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider.enable()
    private = provider.private_key_path.read_text()
    provider.config_path.write_text("drifted\n")
    result = provider.enable()
    assert result.changed
    assert provider.private_key_path.read_text() == private
    assert "Managed by FluxGate" in provider.config_path.read_text()


def test_missing_public_key_is_derived_without_private_key_rotation(
    provider_context, monkeypatch
) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider.private_key_path.parent.mkdir(parents=True)
    provider.private_key_path.write_text("existing-private\n")
    provider.enable()
    assert provider.private_key_path.read_text() == "existing-private\n"
    assert ("wg", "genkey") not in provider_context.runner.commands
    assert provider.public_key_path.exists()


def test_dry_run_does_not_generate_keys_or_mutate_state(provider_context, monkeypatch) -> None:
    provider_context.dry_run = True
    provider_context.runner.dry_run = True
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(
        provider,
        "detect",
        lambda: ProviderDetection(available=False, binaries={"wg": False, "wg-quick": False}),
    )
    result = provider.enable()
    assert result.changed
    assert any("wireguard-tools" in action for action in result.actions)
    assert not provider.private_key_path.exists()
    assert not provider_context.state.path.exists()
    assert not provider_context.services.active


def test_clients_get_unique_deterministic_addresses_and_configs(
    provider_context, monkeypatch
) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider.enable()
    service = ClientService(provider_context.state, ProviderRegistry([provider]))
    alice = service.add("alice")
    bob = service.add("bob")
    assert alice.provider_credentials["wireguard"]["address"] == "10.77.0.2/32"
    assert bob.provider_credentials["wireguard"]["address"] == "10.77.0.3/32"
    server_config = provider.config_path.read_text()
    assert "private-1" in server_config
    assert "public-2" in server_config
    assert "public-3" in server_config
    export = provider.export_client(alice)[0]
    assert "PrivateKey = private-2" in export.content
    assert "Endpoint = vpn.example.com:51820" in export.content


def test_revoke_removes_peer_and_secret_files(provider_context, monkeypatch) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider.enable()
    service = ClientService(provider_context.state, ProviderRegistry([provider]))
    alice = service.add("alice")
    secret = provider_context.paths.secrets_dir / "clients" / f"{alice.id}.wireguard.key"
    assert secret.exists()
    service.revoke("alice")
    assert not secret.exists()
    assert "Client alice" not in provider.config_path.read_text()
    stored = service.find("alice")
    assert not stored.enabled
    assert stored.provider_credentials == {}


def test_duplicate_client_does_not_allocate_another_peer(provider_context, monkeypatch) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider.enable()
    service = ClientService(provider_context.state, ProviderRegistry([provider]))
    service.add("alice")
    with pytest.raises(FluxGateError, match="already exists"):
        service.add("alice")
    assert provider.config_path.read_text().count("# Client alice") == 1


def test_missing_domain_does_not_leave_client_key(provider_context, monkeypatch) -> None:
    provider_context.config.server.domain = ""
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider.enable()
    client = Client(name="alice")
    with pytest.raises(FluxGateError, match=r"server\.domain"):
        provider.add_client(client)
    assert not list((provider_context.paths.secrets_dir / "clients").glob("*"))
