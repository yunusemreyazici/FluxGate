import json
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from fluxgate.core.config import AppConfig, load_config
from fluxgate.core.errors import ConfigError, StateError
from fluxgate.core.models import Client, FluxGateState
from fluxgate.core.paths import PathLayout
from fluxgate.core.state import StateStore, atomic_write


def test_readme_exposes_canonical_project_navigation() -> None:
    readme = (Path(__file__).parents[2] / "README.md").read_text()
    assert "https://github.com/yunusemreyazici/FluxGate" in readme
    assert "https://github.com/yunusemreyazici/FluxGate/releases" in readme
    assert "https://github.com/yunusemreyazici/FluxGate/security/policy" in readme
    assert "[Testing](docs/testing.md)" in readme


def test_config_loads_toml_and_rejects_unknown_fields(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        '[server]\ndomain = "vpn.example.com"\n[cores.wireguard]\nlisten_port = 1234\n'
    )
    loaded = load_config(config)
    assert loaded.server.domain == "vpn.example.com"
    assert loaded.cores.wireguard.listen_port == 1234
    assert loaded.schema_version == 1
    assert AppConfig().as_toml().startswith("schema_version = 1")

    config.write_text("[server]\nmisspelled = true\n")
    with pytest.raises(ConfigError, match="misspelled"):
        load_config(config)


def test_config_validates_ports_interfaces_and_client_names() -> None:
    with pytest.raises(ValidationError):
        AppConfig.model_validate({"cores": {"wireguard": {"listen_port": 0}}})
    with pytest.raises(ValidationError):
        AppConfig.model_validate({"network": {"outbound_interface": "eth0; reboot"}})
    with pytest.raises(ValidationError):
        Client(name="../escape")
    with pytest.raises(ValidationError):
        AppConfig.model_validate({"server": {"domain": "vpn.example.com\n[Peer]"}})
    with pytest.raises(ValidationError):
        AppConfig.model_validate({"cores": {"wireguard": {"address": "10.0.0.0/24"}}})
    with pytest.raises(ValidationError):
        AppConfig.model_validate({"cores": {"wireguard": {"client_dns": ["not-an-ip"]}}})
    with pytest.raises(ValidationError):
        AppConfig.model_validate({"cores": {"wireguard": {"client_dns": ["2606:4700:4700::1111"]}}})
    with pytest.raises(ValidationError):
        AppConfig.model_validate({"network": {"ipv4": "true"}})


@pytest.mark.parametrize(
    "openvpn",
    [
        {"protocol": "tcp"},
        {"listen_port": 0},
        {"network": "203.0.113.0/24"},
        {"network": "10.78.0.0/30"},
        {"client_dns": []},
        {"client_dns": ["not-an-ip"]},
        {"unexpected": True},
    ],
)
def test_openvpn_config_rejects_unsupported_or_unsafe_values(openvpn: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        AppConfig.model_validate({"cores": {"openvpn": openvpn}})


def test_provider_network_interface_and_udp_port_collisions_are_rejected() -> None:
    with pytest.raises(ValidationError, match="networks must not overlap"):
        AppConfig.model_validate({"cores": {"openvpn": {"network": "10.77.0.0/24"}}})
    with pytest.raises(ValidationError, match="interface names must differ"):
        AppConfig.model_validate({"cores": {"openvpn": {"interface": "fg0"}}})
    with pytest.raises(ValidationError, match="listen ports must differ"):
        AppConfig.model_validate({"cores": {"openvpn": {"listen_port": 51820}}})


def test_openvpn_config_round_trips_through_toml(tmp_path: Path) -> None:
    original = AppConfig.model_validate(
        {
            "cores": {
                "openvpn": {
                    "enabled": True,
                    "interface": "ovpn-test",
                    "listen_port": 21194,
                    "network": "172.30.0.0/24",
                    "client_dns": ["9.9.9.9"],
                }
            }
        }
    )
    path = tmp_path / "config.toml"
    path.write_text(original.as_toml())
    assert load_config(path) == original


def test_paths_accept_only_absolute_traversal_free_overrides(tmp_path: Path) -> None:
    layout = PathLayout.from_environment({"FLUXGATE_CONFIG_DIR": str(tmp_path)})
    assert layout.config_file == tmp_path / "config.toml"
    with pytest.raises(ConfigError):
        PathLayout.from_environment({"FLUXGATE_DATA_DIR": "relative"})
    with pytest.raises(ConfigError):
        PathLayout.from_environment({"FLUXGATE_DATA_DIR": "/var/../etc"})


def test_state_round_trip_is_atomic_and_private(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "nested" / "state.json")
    state = FluxGateState(clients=[Client(name="alice")])
    store.save(state)
    assert store.load() == state
    assert (store.path.stat().st_mode & 0o777) == 0o600
    assert not list(store.path.parent.glob(f".{store.path.name}.*"))
    assert json.loads(store.path.read_text())["schema_version"] == 2


def test_v01_multi_provider_state_shape_loads_without_migration_or_data_loss(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.json"
    payload = {
        "schema_version": 1,
        "clients": [
            {
                "id": "12345678-1234-5678-1234-567812345678",
                "name": "legacy-client",
                "created_at": "2026-01-01T00:00:00Z",
                "enabled": True,
                "expires_at": None,
                "metadata": {},
                "provider_credentials": {
                    "wireguard": {
                        "public_key": "legacy-public",
                        "address": "10.77.0.2/32",
                    }
                },
            }
        ],
        "providers": {"wireguard": {"enabled": True}},
    }
    path.write_text(json.dumps(payload))
    store = StateStore(path)
    loaded = store.load()
    assert loaded.clients[0].provider_credentials == payload["clients"][0]["provider_credentials"]
    store.save(loaded)
    assert store.load().clients[0].provider_credentials["wireguard"]["public_key"] == (
        "legacy-public"
    )


def test_future_config_and_state_schema_versions_fail_closed(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text("schema_version = 2\n")
    with pytest.raises(ConfigError, match="schema_version"):
        load_config(config)
    state = tmp_path / "state.json"
    state.write_text('{"schema_version": 3, "clients": [], "providers": {}}')
    with pytest.raises(StateError, match="schema_version"):
        StateStore(state).load()
    state.write_text(
        '{"schema_version": 1, "clients": [{"name": "alice", "enabled": "false"}], "providers": {}}'
    )
    with pytest.raises(StateError, match="enabled"):
        StateStore(state).load()


def test_invalid_state_lock_file_has_a_structured_error(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.json")
    store.path.with_suffix(".json.lock").mkdir()
    with pytest.raises(StateError, match="cannot acquire state lock"), store.lock():
        pytest.fail("invalid lock path must not be entered")


def test_state_metadata_permission_error_is_structured(tmp_path: Path, monkeypatch) -> None:
    store = StateStore(tmp_path / "state.json")
    original = Path.is_symlink

    def deny_state_metadata(path: Path) -> bool:
        if path == store.path:
            raise PermissionError("injected permission denial")
        return original(path)

    monkeypatch.setattr(Path, "is_symlink", deny_state_metadata)
    with pytest.raises(StateError, match="cannot read state"):
        store.load()


def test_atomic_write_refuses_symlink_destination(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("unchanged")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(StateError, match="symlink"):
        atomic_write(link, b"replacement")
    assert target.read_text() == "unchanged"


def test_atomic_write_replaces_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "value"
    path.write_bytes(b"old")
    original_inode = os.stat(path).st_ino
    atomic_write(path, b"new", 0o640)
    assert path.read_bytes() == b"new"
    assert os.stat(path).st_ino != original_inode
    assert path.stat().st_mode & 0o777 == 0o640
