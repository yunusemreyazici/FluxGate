from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from fluxgate.bootstrap import BootstrapService, verify_bootstrap
from fluxgate.clients import ClientService
from fluxgate.core.config import AppConfig
from fluxgate.core.errors import FluxGateError, ProviderError
from fluxgate.core.manifest import build_manifest
from fluxgate.core.models import Client, ProviderStateName
from fluxgate.core.registry import ProviderRegistry
from fluxgate.identity import ServerIdentityManager
from fluxgate.pathfinder.models import FeatureCapability, PathfinderProvider
from fluxgate.providers.amneziawg import (
    AmneziaWGParameters,
    AmneziaWGProvider,
    AmneziaWGProviderState,
    ResiliencePreset,
    ResilienceProfile,
)
from fluxgate.providers.amneziawg.rendering import render_client, render_server


def _provider(provider_context) -> AmneziaWGProvider:
    return AmneziaWGProvider(provider_context)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"jc": 0}, "greater than or equal to 1"),
        ({"jc": 129}, "less than or equal to 128"),
        ({"jmin": 100, "jmax": 100}, "Jmin must be less"),
        ({"s1": 1133}, "less than or equal to 1132"),
        ({"s2": 1189}, "less than or equal to 1188"),
        ({"h1": 4}, "greater than or equal to 5"),
        ({"h4": 1001}, "must be unique"),
    ],
)
def test_parameter_validation_rejects_unsafe_values(change: dict[str, int], message: str) -> None:
    values = {
        "jc": 4,
        "jmin": 40,
        "jmax": 80,
        "s1": 64,
        "s2": 96,
        "h1": 1001,
        "h2": 1002,
        "h3": 1003,
        "h4": 1004,
    }
    values.update(change)
    with pytest.raises(ValidationError, match=message):
        AmneziaWGParameters.model_validate(values)


def test_parameter_model_rejects_deferred_awg_knobs() -> None:
    values = ResilienceProfile.from_preset(
        "test", ResiliencePreset.STANDARD
    ).parameters.model_dump()
    values["header_protection_key"] = "not-accepted"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AmneziaWGParameters.model_validate(values)


def test_presets_resolve_to_stable_concrete_values() -> None:
    first = ResilienceProfile.from_preset("first", ResiliencePreset.BALANCED)
    second = ResilienceProfile.from_preset("second", ResiliencePreset.BALANCED)
    assert first.id != second.id
    assert first.parameters == second.parameters
    assert first.generation == "awg-3.1"


def test_rendering_is_deterministic_and_coordinates_wire_parameters(
    provider_context,
) -> None:
    profile = ResilienceProfile.from_preset("profile", ResiliencePreset.ENHANCED)
    client = Client(name="alice")
    client.provider_credentials["amneziawg"] = {
        "public_key": "client-public",
        "address": "10.79.0.2/32",
        "profile_id": str(profile.id),
    }
    server = render_server(
        provider_context.config.cores.amneziawg,
        "server-private",
        [client],
        profile,
    )
    exported = render_client(
        provider_context.config.cores.amneziawg,
        provider_context.config.server.domain,
        "server-public",
        client,
        "client-private",
        profile,
    )
    assert server == render_server(
        provider_context.config.cores.amneziawg,
        "server-private",
        [client],
        profile,
    )
    for field in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"):
        server_line = next(line for line in server.decode().splitlines() if line.startswith(field))
        assert server_line in exported
    assert "HeaderProtectionKey" not in exported
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in exported


def test_official_validator_uses_an_interface_safe_temporary_name(
    provider_context, monkeypatch
) -> None:
    provider = _provider(provider_context)
    seen: list[str] = []
    real_run = provider_context.runner.run

    def inspect(args, **kwargs):
        if len(args) >= 3 and args[1] == "strip":
            seen.append(Path(args[2]).stem)
        return real_run(args, **kwargs)

    monkeypatch.setattr(provider_context.runner, "run", inspect)
    provider_context.paths.awg_quick_binary.parent.mkdir(parents=True)
    provider_context.paths.awg_quick_binary.write_bytes(b"fake")
    provider_context.paths.awg_quick_binary.chmod(0o755)
    provider._validate_config(b"[Interface]\nPrivateKey = fake\n")
    assert seen and len(seen[0]) <= 15
    assert all(character.isalnum() or character in "_=+.-" for character in seen[0])


def test_enable_is_idempotent_and_profile_survives_disable_reenable(provider_context) -> None:
    provider = _provider(provider_context)
    first = provider.enable()
    state = AmneziaWGProviderState.model_validate_json(
        json.dumps(provider_context.state.load().providers["amneziawg"])
    )
    original_profile = state.profile.model_copy(deep=True)
    assert first.changed
    assert provider.status().state == ProviderStateName.RUNNING
    unit = provider.unit_path.read_text()
    assert "wait-uapi.py /run/amneziawg/fgawg0.sock 5" in unit
    assert "/bin/sh" not in unit
    assert "--foreground fgawg0" in unit
    assert "RuntimeDirectory=amneziawg" not in unit
    assert not provider.enable().changed

    assert provider.disable().changed
    disabled = AmneziaWGProviderState.model_validate_json(
        json.dumps(provider_context.state.load().providers["amneziawg"])
    )
    assert not disabled.enabled
    assert disabled.profile == original_profile
    assert provider.enable().changed
    reenabled = AmneziaWGProviderState.model_validate_json(
        json.dumps(provider_context.state.load().providers["amneziawg"])
    )
    assert reenabled.profile == original_profile


def test_enable_refuses_kernel_backend_before_mutation(provider_context) -> None:
    provider_context.config = AppConfig.model_validate(
        {
            "server": {"domain": "vpn.example.com"},
            "network": {"outbound_interface": "eth0"},
            "cores": {"amneziawg": {"backend": "kernel"}},
        }
    )
    with pytest.raises(ProviderError, match="kernel backend is deferred"):
        _provider(provider_context).enable()
    assert not provider_context.state.exists
    assert not provider_context.paths.amneziawg_dir.exists()


def test_enable_refuses_foreign_config_and_interface(provider_context) -> None:
    provider = _provider(provider_context)
    provider_context.paths.amneziawg_dir.mkdir(parents=True)
    provider.config_path.write_text("foreign\n")
    with pytest.raises(ProviderError, match="unmanaged AmneziaWG config"):
        provider.enable()

    provider.config_path.unlink()
    provider_context.paths.amneziawg_dir.rmdir()
    provider_context.network.interfaces.add("fgawg0")
    with pytest.raises(ProviderError, match="not owned"):
        provider.enable()


def test_enable_rolls_back_files_leases_service_and_state(provider_context, monkeypatch) -> None:
    provider = _provider(provider_context)

    def fail_listener(timeout: float = 5.0) -> bool:
        return False

    monkeypatch.setattr(provider, "_wait_healthy", fail_listener)
    with pytest.raises(FluxGateError, match="postcondition"):
        provider.enable()
    assert not provider_context.state.exists
    assert not provider_context.forwarding.configured("amneziawg")
    assert not provider_context.firewall.managed("amneziawg")
    assert not provider_context.services.is_active(provider.unit)
    assert not provider.config_path.exists()
    assert not provider.unit_path.exists()


def test_dry_run_has_no_files_state_keys_or_network_mutation(provider_context) -> None:
    provider_context.dry_run = True
    provider_context.runner.dry_run = True
    provider = _provider(provider_context)
    result = provider.enable()
    assert result.changed
    assert not provider_context.state.exists
    assert not provider_context.paths.amneziawg_dir.exists()
    assert not provider.private_key_path.exists()
    assert not provider_context.forwarding.configured("amneziawg")
    assert not provider_context.firewall.managed("amneziawg")
    assert provider_context.packages.installs == []


def test_client_lifecycle_is_selective_and_bootstrap_inventory_is_closed(
    provider_context, tmp_path: Path
) -> None:
    provider = _provider(provider_context)
    provider.enable()
    registry = ProviderRegistry([provider])
    clients = ClientService(provider_context.state, registry)
    client = clients.add("alice")
    state = provider_context.state.load()
    stored = ClientService._find(state.clients, str(client.id))
    stored.provider_credentials["wireguard"] = {
        "public_key": "wg-public",
        "address": "10.77.0.2/32",
    }
    provider_context.state.save(state)

    provisioned = clients.enable_provider("alice", "amneziawg")
    assert provisioned.provider_credentials["wireguard"]["public_key"] == "wg-public"
    profile = provider._profile()
    assert provisioned.provider_credentials["amneziawg"]["profile_id"] == str(profile.id)
    assert provider.export_client(provisioned)[0].name == "alice.conf"

    identity = ServerIdentityManager(provider_context.paths)
    bootstrap_registry = ProviderRegistry([provider])
    bootstrap = BootstrapService(
        provider_context.config,
        provider_context.state,
        bootstrap_registry,
        clients,
        identity,
    )
    # Bootstrap cannot resolve the intentionally synthetic WireGuard credential without a
    # provider, so verify the AWG-only signed inventory after preserving isolation above.
    state = provider_context.state.load()
    stored = ClientService._find(state.clients, "alice")
    stored.provider_credentials.pop("wireguard")
    provider_context.state.save(state)
    root = bootstrap.export("alice", tmp_path / "bundles")
    verification = verify_bootstrap(root, pinned_trust=identity.ensure().trust)
    assert verification.artifact_count == 1
    assert next(iter((root / "amneziawg").iterdir())).suffix == ".conf"

    revoked = clients.disable_provider("alice", "amneziawg")
    assert "amneziawg" not in revoked.provider_credentials
    assert not provider._client_config_path(revoked).exists()


def test_bootstrap_keeps_amneziawg_clients_isolated(provider_context, tmp_path: Path) -> None:
    provider = _provider(provider_context)
    provider.enable()
    clients = ClientService(provider_context.state, ProviderRegistry([provider]))
    clients.add("alice")
    clients.add("bob")
    alice = clients.enable_provider("alice", "amneziawg")
    bob = clients.enable_provider("bob", "amneziawg")
    alice_export = provider.export_client(alice)[0].content
    bob_export = provider.export_client(bob)[0].content
    assert alice_export != bob_export

    identity = ServerIdentityManager(provider_context.paths)
    bootstrap = BootstrapService(
        provider_context.config,
        provider_context.state,
        ProviderRegistry([provider]),
        clients,
        identity,
    )
    root = bootstrap.export("alice", tmp_path / "bundles")
    verification = verify_bootstrap(root, pinned_trust=identity.ensure().trust)
    artifacts = list((root / "amneziawg").iterdir())

    assert verification.artifact_count == 1
    assert len(artifacts) == 1
    assert artifacts[0].read_text() == alice_export
    assert artifacts[0].read_text() != bob_export


def test_manifest_advertises_profile_identity_not_parameters_or_secrets(
    provider_context,
) -> None:
    provider = _provider(provider_context)
    provider.enable()
    state = provider_context.state.load()
    profile = AmneziaWGProviderState.model_validate_json(
        json.dumps(state.providers["amneziawg"])
    ).profile
    manifest = build_manifest(provider_context.config, state)
    candidate = next(
        item for item in manifest.candidates if item.provider == PathfinderProvider.AMNEZIAWG
    )
    assert candidate.profile_id == profile.id
    assert FeatureCapability.AMNEZIAWG_3_1 in candidate.required_features
    rendered = manifest.render()
    assert b"amneziawg_3_1" in rendered
    for forbidden in (b"private", b"public_key", b"Jmin", b"HeaderProtectionKey"):
        assert forbidden not in rendered


def test_revoke_retry_converges_after_state_save_interruption(
    provider_context, monkeypatch
) -> None:
    provider = _provider(provider_context)
    provider.enable()
    clients = ClientService(provider_context.state, ProviderRegistry([provider]))
    clients.add("retry")
    provisioned = clients.enable_provider("retry", "amneziawg")
    real_save = provider_context.state.save
    failed = False

    def fail_once(state) -> None:
        nonlocal failed
        stored = ClientService._find(state.clients, "retry")
        if not failed and "amneziawg" not in stored.provider_credentials:
            failed = True
            raise OSError("injected state save interruption")
        real_save(state)

    monkeypatch.setattr(provider_context.state, "save", fail_once)
    with pytest.raises(FluxGateError, match="state update failed"):
        clients.disable_provider("retry", "amneziawg")
    assert "amneziawg" in provider_context.state.load().clients[0].provider_credentials
    assert not provider._client_config_path(provisioned).exists()

    reconciled = clients.disable_provider("retry", "amneziawg")
    assert "amneziawg" not in reconciled.provider_credentials


@pytest.mark.skipif(
    not os.environ.get("AMNEZIAWG_TEST_BINARY"),
    reason="set AMNEZIAWG_TEST_BINARY to the official awg-quick 3.1 executable",
)
def test_official_awg_quick_parser_accepts_generated_client(
    provider_context, tmp_path: Path
) -> None:
    from subprocess import run

    parser = os.environ["AMNEZIAWG_TEST_BINARY"]
    profile = ResilienceProfile.from_preset("parser", ResiliencePreset.STANDARD)
    client = Client(name="parser")
    client.provider_credentials["amneziawg"] = {
        "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "address": "10.79.0.2/32",
        "profile_id": str(profile.id),
    }
    content = render_client(
        provider_context.config.cores.amneziawg,
        "vpn.example.com",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        client,
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
        profile,
    )
    config = tmp_path / "parser.conf"
    config.write_text(content)
    completed = run(  # noqa: S603 - explicit opt-in parser path is the test boundary
        [parser, "strip", str(config)], capture_output=True, text=True, check=False
    )
    assert completed.returncode == 0, completed.stderr
    assert "Jc" in completed.stdout
