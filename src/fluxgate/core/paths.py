"""Central filesystem layout and environment handling."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from fluxgate.core.errors import ConfigError

DEFAULT_CONFIG_DIR = Path("/etc/fluxgate")
DEFAULT_DATA_DIR = Path("/var/lib/fluxgate")
DEFAULT_LOG_DIR = Path("/var/log/fluxgate")
DEFAULT_WIREGUARD_DIR = Path("/etc/wireguard")
DEFAULT_OPENVPN_DIR = Path("/etc/openvpn/server")
DEFAULT_SYSCTL_DIR = Path("/etc/sysctl.d")
DEFAULT_NFTABLES_DIR = Path("/etc/fluxgate/nftables")
DEFAULT_SYSTEMD_DIR = Path("/etc/systemd/system")
DEFAULT_LOCAL_LIB_DIR = Path("/usr/local/lib/fluxgate")


@dataclass(frozen=True, slots=True)
class PathLayout:
    config_dir: Path = DEFAULT_CONFIG_DIR
    data_dir: Path = DEFAULT_DATA_DIR
    log_dir: Path = DEFAULT_LOG_DIR
    wireguard_dir: Path = DEFAULT_WIREGUARD_DIR
    openvpn_dir: Path = DEFAULT_OPENVPN_DIR
    sysctl_dir: Path = DEFAULT_SYSCTL_DIR
    nftables_dir: Path = DEFAULT_NFTABLES_DIR
    systemd_dir: Path = DEFAULT_SYSTEMD_DIR
    local_lib_dir: Path = DEFAULT_LOCAL_LIB_DIR

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> PathLayout:
        env = os.environ if environment is None else environment

        def env_path(name: str, default: Path) -> Path:
            raw = env.get(name)
            if raw is None:
                return default
            path = Path(raw)
            if (
                not path.is_absolute()
                or ".." in path.parts
                or any(character.isspace() or ord(character) < 32 for character in raw)
            ):
                raise ConfigError(f"{name} must be an absolute, traversal-free path")
            return path

        return cls(
            config_dir=env_path("FLUXGATE_CONFIG_DIR", DEFAULT_CONFIG_DIR),
            data_dir=env_path("FLUXGATE_DATA_DIR", DEFAULT_DATA_DIR),
            log_dir=env_path("FLUXGATE_LOG_DIR", DEFAULT_LOG_DIR),
            wireguard_dir=env_path("FLUXGATE_WIREGUARD_DIR", DEFAULT_WIREGUARD_DIR),
            openvpn_dir=env_path("FLUXGATE_OPENVPN_DIR", DEFAULT_OPENVPN_DIR),
            sysctl_dir=env_path("FLUXGATE_SYSCTL_DIR", DEFAULT_SYSCTL_DIR),
            nftables_dir=env_path("FLUXGATE_NFTABLES_DIR", DEFAULT_NFTABLES_DIR),
            systemd_dir=env_path("FLUXGATE_SYSTEMD_DIR", DEFAULT_SYSTEMD_DIR),
            local_lib_dir=env_path("FLUXGATE_LOCAL_LIB_DIR", DEFAULT_LOCAL_LIB_DIR),
        )

    @property
    def config_file(self) -> Path:
        return self.config_dir / "config.toml"

    @property
    def state_file(self) -> Path:
        return self.data_dir / "state.json"

    @property
    def secrets_dir(self) -> Path:
        return self.config_dir / "secrets"

    @property
    def openvpn_pki_dir(self) -> Path:
        return self.secrets_dir / "openvpn-pki"

    @property
    def openvpn_config_file(self) -> Path:
        return self.openvpn_dir / "fluxgate.conf"

    @property
    def openvpn_ccd_dir(self) -> Path:
        return self.openvpn_dir / "fluxgate-clients"

    @property
    def openvpn_crl_file(self) -> Path:
        return self.openvpn_dir / "fluxgate-crl.pem"

    @property
    def clients_dir(self) -> Path:
        return self.config_dir / "clients"

    @property
    def singbox_dir(self) -> Path:
        return self.config_dir / "sing-box"

    @property
    def singbox_config_file(self) -> Path:
        return self.singbox_dir / "config.json"

    @property
    def singbox_tls_dir(self) -> Path:
        return self.secrets_dir / "sing-box-tls"

    @property
    def server_identity_dir(self) -> Path:
        return self.secrets_dir / "server-identity"

    @property
    def server_identity_lock_file(self) -> Path:
        return self.data_dir / "server-identity.lock"

    @property
    def singbox_unit_file(self) -> Path:
        return self.systemd_dir / "fluxgate-singbox.service"

    @property
    def singbox_binary(self) -> Path:
        return self.local_lib_dir / "sing-box-1.13.19" / "sing-box"

    @property
    def backups_dir(self) -> Path:
        return self.data_dir / "backups"

    @property
    def forwarding_file(self) -> Path:
        return self.sysctl_dir / "90-fluxgate.conf"

    @property
    def firewall_file(self) -> Path:
        return self.nftables_dir / "fluxgate.nft"

    @property
    def firewall_unit_file(self) -> Path:
        return self.systemd_dir / "fluxgate-firewall.service"
