from contextlib import contextmanager

import pytest

from fluxgate.clients import ClientService
from fluxgate.core.errors import FluxGateError, StateError
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
    assert provider_context.packages.installs == []
    assert provider_context.services.events.count(f"enable:{provider.unit}") == 1


def test_fresh_enable_persists_state_when_config_default_is_enabled(
    provider_context, monkeypatch
) -> None:
    provider_context.config.cores.wireguard.enabled = True
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider.enable()
    assert provider_context.state.path.exists()
    assert provider_context.state.load().providers[provider.name]["enabled"] is True


def test_enable_repairs_configuration_drift_without_rotating_keys(
    provider_context, monkeypatch
) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider.enable()
    private = provider.private_key_path.read_text()
    provider.config_path.write_text(
        provider.config_path.read_text().replace("ListenPort = 51820", "ListenPort = 51999")
    )
    result = provider.enable()
    assert result.changed
    assert provider.private_key_path.read_text() == private
    assert "Managed by FluxGate" in provider.config_path.read_text()
    assert f"restart:{provider.unit}" in provider_context.services.events


def test_missing_public_key_is_derived_without_private_key_rotation(
    provider_context, monkeypatch
) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider.private_key_path.parent.mkdir(parents=True)
    provider.private_key_path.write_text("existing-private\n")
    provider.private_key_path.chmod(0o600)
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
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in export.content
    private_path = provider_context.paths.secrets_dir / "clients" / f"{alice.id}.wireguard.key"
    export_path = provider_context.paths.clients_dir / f"{alice.id}.wireguard.conf"
    assert private_path.stat().st_mode & 0o777 == 0o600
    assert export_path.stat().st_mode & 0o777 == 0o600


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


def test_revoke_and_delete_hold_the_state_mutation_lock(provider_context, monkeypatch) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider.enable()
    service = ClientService(provider_context.state, ProviderRegistry([provider]))
    service.add("alice")
    lock_entries = 0
    real_lock = provider_context.state.lock

    @contextmanager
    def counted_lock():
        nonlocal lock_entries
        lock_entries += 1
        with real_lock():
            yield

    monkeypatch.setattr(provider_context.state, "lock", counted_lock)
    service.revoke("alice")
    service.delete("alice")
    assert lock_entries == 2


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


def test_disable_and_reenable_preserve_keys_and_restore_managed_host_state(
    provider_context, monkeypatch
) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider.enable()
    private = provider.private_key_path.read_text()
    disabled = provider.disable()
    assert disabled.changed
    assert not provider_context.services.active
    assert not provider_context.services.enabled
    assert not provider_context.firewall.present
    assert not provider_context.forwarding.present
    assert provider.config_path.exists()

    enabled = provider.enable()
    assert enabled.changed
    assert provider.private_key_path.read_text() == private
    assert provider_context.services.active
    assert provider_context.services.enabled
    assert provider_context.firewall.present
    assert provider_context.forwarding.present


def test_enable_recovers_a_stopped_or_boot_disabled_service(provider_context, monkeypatch) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider.enable()
    provider_context.services.active = False
    provider_context.services.enabled = False
    result = provider.enable()
    assert result.changed
    assert provider_context.services.active
    assert provider_context.services.enabled


def test_enable_refuses_existing_unmanaged_wireguard_configuration(
    provider_context, monkeypatch
) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider.config_path.parent.mkdir(parents=True)
    provider.config_path.write_text("[Interface]\nPrivateKey = user-owned\n")
    with pytest.raises(FluxGateError, match="unmanaged WireGuard configuration"):
        provider.enable()
    assert provider.config_path.read_text() == "[Interface]\nPrivateKey = user-owned\n"
    assert not provider.private_key_path.exists()


def test_enable_refuses_broken_wireguard_configuration_symlink(
    provider_context, monkeypatch
) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider.config_path.parent.mkdir(parents=True)
    provider.config_path.symlink_to(provider.config_path.parent / "missing.conf")
    with pytest.raises(FluxGateError, match="configuration symlink"):
        provider.enable()
    assert provider.config_path.is_symlink()


def test_client_mutations_refuse_configuration_replaced_after_enable(
    provider_context, monkeypatch
) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider.enable()
    service = ClientService(provider_context.state, ProviderRegistry([provider]))
    alice = service.add("alice")
    provider.config_path.write_text("[Interface]\nPrivateKey = user-owned\n")

    with pytest.raises(FluxGateError, match="managed WireGuard configuration is missing"):
        service.add("bob")
    with pytest.raises(FluxGateError, match="managed WireGuard configuration is missing"):
        service.revoke(str(alice.id))

    assert provider.config_path.read_text() == "[Interface]\nPrivateKey = user-owned\n"
    assert service.find("alice").enabled


def test_missing_state_never_silently_drops_managed_peers(provider_context, monkeypatch) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider.enable()
    service = ClientService(provider_context.state, ProviderRegistry([provider]))
    service.add("alice")
    peer_config = provider.config_path.read_bytes()
    provider_context.state.path.unlink()
    with pytest.raises(FluxGateError, match="state is missing"):
        provider.enable()
    assert provider.config_path.read_bytes() == peer_config


def test_invalid_provider_enabled_state_fails_before_host_mutation(
    provider_context, monkeypatch
) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    state = provider_context.state.load()
    state.providers[provider.name] = {"enabled": "false"}
    provider_context.state.save(state)
    with pytest.raises(StateError, match="enabled must be a boolean"):
        provider.enable()
    assert not provider.config_path.exists()


def test_client_state_save_failure_rolls_back_live_peer_and_secrets(
    provider_context, monkeypatch
) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider.enable()
    config_before = provider.config_path.read_bytes()
    service = ClientService(provider_context.state, ProviderRegistry([provider]))

    def fail_save(state) -> None:
        raise StateError("injected state failure")

    monkeypatch.setattr(provider_context.state, "save", fail_save)
    with pytest.raises(StateError, match="injected state failure"):
        service.add("alice")
    assert provider.config_path.read_bytes() == config_before
    assert not list(provider_context.paths.clients_dir.glob("*"))
    assert not list((provider_context.paths.secrets_dir / "clients").glob("*"))


def test_enable_rejects_interface_route_and_port_conflicts(provider_context, monkeypatch) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider_context.network.interfaces.add("fg0")
    with pytest.raises(FluxGateError, match="already exists"):
        provider.enable()


def test_enable_rejects_overlapping_host_route(provider_context, monkeypatch) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider_context.network.route_conflict = "10.0.0.0/8 dev eth0"
    with pytest.raises(FluxGateError, match="overlaps existing route"):
        provider.enable()


def test_enable_rejects_udp_listen_port_conflict(provider_context, monkeypatch) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available)
    provider_context.network.occupied_ports.add(51820)
    with pytest.raises(FluxGateError, match="listen port is already in use"):
        provider.enable()
