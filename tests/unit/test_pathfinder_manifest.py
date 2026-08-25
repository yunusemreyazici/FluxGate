from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from fluxgate.core.config import AppConfig
from fluxgate.core.manifest import ServerManifest, build_manifest
from fluxgate.core.models import (
    FluxGateState,
    ProfileDefinition,
    ProtocolName,
    SecurityName,
    TransportName,
)
from fluxgate.identity import ServerIdentityManager
from fluxgate.manifest import SignedManifestService, verify_signed_manifest
from fluxgate.pathfinder import (
    ClientCapabilities,
    ConnectionMode,
    IPFamily,
    PathfinderProtocol,
    PathfinderProvider,
    PathfinderSecurity,
    PathfinderTransport,
    evaluate_candidates,
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


def _state() -> FluxGateState:
    profiles = [
        ProfileDefinition(
            id=UUID("00000000-0000-0000-0000-000000000003"),
            name="hy2",
            protocol=ProtocolName.HYSTERIA2,
            transport=TransportName.QUIC,
            security=SecurityName.TLS,
            listen_port=8443,
            enabled=True,
        ),
        ProfileDefinition(
            id=UUID("00000000-0000-0000-0000-000000000001"),
            name="vless",
            protocol=ProtocolName.VLESS,
            transport=TransportName.TCP,
            security=SecurityName.TLS,
            listen_port=443,
            enabled=True,
        ),
        ProfileDefinition(
            name="disabled",
            protocol=ProtocolName.TROJAN,
            transport=TransportName.TCP,
            security=SecurityName.TLS,
            listen_port=444,
            enabled=False,
        ),
    ]
    return FluxGateState(profiles=profiles)


def test_manifest_has_all_enabled_candidate_types_and_no_secrets() -> None:
    manifest = build_manifest(
        _config(),
        _state(),
        server_id=UUID("00000000-0000-0000-0000-000000000099"),
        generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    identifiers = [candidate.candidate_id for candidate in manifest.candidates]
    assert identifiers == sorted(identifiers)
    assert identifiers == [
        "profile:00000000-0000-0000-0000-000000000001",
        "profile:00000000-0000-0000-0000-000000000003",
        "provider:openvpn",
        "provider:wireguard",
    ]
    rendered = manifest.render()
    assert rendered == ServerManifest.model_validate_json(rendered).render()
    lowered = rendered.lower()
    for forbidden in (b"private_key", b"password", b"credential", b"client_id", b"uuid"):
        assert forbidden not in lowered


def test_pathfinder_is_generic_deterministic_and_explains_missing_capabilities() -> None:
    manifest = build_manifest(_config(), _state())
    capabilities = ClientCapabilities(
        supported_providers=(PathfinderProvider.SINGBOX,),
        supported_protocols=(PathfinderProtocol.VLESS, PathfinderProtocol.HYSTERIA2),
        supported_transports=(PathfinderTransport.TCP,),
        supported_security=(PathfinderSecurity.TLS,),
        supported_connection_modes=(ConnectionMode.LOCAL_PROXY,),
        supported_ip_families=(IPFamily.IPV4,),
    )
    first = evaluate_candidates(manifest.candidates, capabilities)
    assert first == evaluate_candidates(tuple(reversed(manifest.candidates)), capabilities)
    by_id = {item.candidate_id: item for item in first.assessments}
    assert by_id["profile:00000000-0000-0000-0000-000000000001"].compatible
    hy2 = by_id["profile:00000000-0000-0000-0000-000000000003"]
    assert not hy2.compatible
    assert "client lacks transport:quic" in hy2.rejection_reasons
    assert "client lacks feature:udp" in hy2.rejection_reasons
    assert "client lacks feature:quic" in hy2.rejection_reasons
    assert not by_id["provider:wireguard"].compatible


def test_provider_candidates_follow_durable_enabled_state() -> None:
    config = AppConfig.model_validate({"server": {"domain": "vpn.example.test"}})
    state = FluxGateState(providers={"wireguard": {"enabled": True}, "openvpn": {"enabled": True}})
    identifiers = {candidate.candidate_id for candidate in build_manifest(config, state).candidates}
    assert identifiers == {"provider:wireguard", "provider:openvpn"}


def test_signed_manifest_exact_bytes_pinned_trust_and_atomic_replacement(
    provider_context, tmp_path: Path
) -> None:
    provider_context.state.save(_state())
    identity = ServerIdentityManager(provider_context.paths)
    service = SignedManifestService(_config(), provider_context.state, identity)
    destination = tmp_path / "signed"
    service.export(destination)
    trust = identity.load().trust
    assert len(verify_signed_manifest(destination, trust).candidates) == 4
    first_server_id = trust.server_id
    service.export(destination)
    assert identity.load().metadata.server_id == first_server_id

    original = (destination / "manifest.json").read_bytes()
    (destination / "manifest.json").write_bytes(original.replace(b"{", b"{ ", 1))
    with __import__("pytest").raises(Exception, match="signature"):
        verify_signed_manifest(destination, trust)
    (destination / "manifest.json").write_bytes(original)
    (destination / "manifest.json").chmod(0o644)
    assert verify_signed_manifest(destination, trust)


def test_signed_manifest_dry_run_has_no_identity_or_output(
    provider_context, tmp_path: Path
) -> None:
    manager = ServerIdentityManager(provider_context.paths)
    paths = SignedManifestService(_config(), provider_context.state, manager).export(
        tmp_path / "signed", dry_run=True
    )
    assert len(paths) == 3
    assert not manager.root.exists()
    assert not (tmp_path / "signed").exists()


def test_documented_capability_fixtures_parse() -> None:
    root = Path(__file__).parents[2] / "examples" / "capabilities"
    fixtures = {
        path.name: ClientCapabilities.model_validate_json(path.read_bytes())
        for path in root.glob("*.json")
    }
    assert set(fixtures) == {"desktop-full.json", "proxy-only.json", "tcp-only.json"}
    assert ConnectionMode.SYSTEM_TUNNEL in fixtures["desktop-full.json"].supported_connection_modes
    assert (
        ConnectionMode.SYSTEM_TUNNEL not in fixtures["proxy-only.json"].supported_connection_modes
    )
