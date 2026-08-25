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


def test_config_loads_toml_and_rejects_unknown_fields(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        '[server]\ndomain = "vpn.example.com"\n[cores.wireguard]\nlisten_port = 1234\n'
    )
    loaded = load_config(config)
    assert loaded.server.domain == "vpn.example.com"
    assert loaded.cores.wireguard.listen_port == 1234

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
    assert json.loads(store.path.read_text())["schema_version"] == 1


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
