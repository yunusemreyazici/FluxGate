"""Strict TOML configuration loading."""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path
from typing import Literal

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[import-not-found, unused-ignore]

from pydantic import Field, ValidationError, field_validator, model_validator

from fluxgate.core.errors import ConfigError
from fluxgate.core.models import StrictModel


class ServerConfig(StrictModel):
    domain: str = ""

    @field_validator("domain")
    @classmethod
    def endpoint_host(cls, value: str) -> str:
        if not value:
            return value
        if len(value) > 253 or any(
            not (character.isalnum() or character in {"-", "."}) for character in value
        ):
            raise ValueError("server domain must be a hostname or IPv4 address")
        labels = value.rstrip(".").split(".")
        if any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            for label in labels
        ):
            raise ValueError("invalid server domain")
        return value


class NetworkConfig(StrictModel):
    ipv4: bool = True
    ipv6: bool = True
    outbound_interface: str | None = None

    @field_validator("outbound_interface")
    @classmethod
    def interface_name(cls, value: str | None) -> str | None:
        if value is not None and (
            not value or len(value) > 15 or any(not (c.isalnum() or c in "_.-") for c in value)
        ):
            raise ValueError("invalid outbound interface name")
        return value


class WireGuardConfig(StrictModel):
    enabled: bool = False
    interface: str = "fg0"
    listen_port: int = Field(default=51820, ge=1, le=65535)
    address: str = "10.77.0.1/24"
    client_dns: list[str] = Field(default_factory=lambda: ["1.1.1.1", "1.0.0.1"])

    @field_validator("interface")
    @classmethod
    def interface_name(cls, value: str) -> str:
        if not value or len(value) > 15 or any(not (c.isalnum() or c in "_.-") for c in value):
            raise ValueError("invalid WireGuard interface name")
        return value

    @field_validator("address")
    @classmethod
    def tunnel_address(cls, value: str) -> str:
        try:
            interface = ipaddress.ip_interface(value)
        except ValueError as error:
            raise ValueError("invalid WireGuard tunnel address") from error
        if interface.version != 4 or interface.ip in {
            interface.network.network_address,
            interface.network.broadcast_address,
        }:
            raise ValueError("WireGuard address must be a usable IPv4 interface address")
        return value

    @field_validator("client_dns")
    @classmethod
    def dns_addresses(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("at least one client DNS address is required")
        try:
            for address in value:
                if ipaddress.ip_address(address).version != 4:
                    raise ValueError("IPv6 DNS is not supported by the IPv4-only WireGuard pool")
        except ValueError as error:
            raise ValueError("client DNS entries must be IPv4 addresses") from error
        return value


class OpenVPNConfig(StrictModel):
    enabled: bool = False
    interface: str = "fgovpn0"
    listen_port: int = Field(default=1194, ge=1, le=65535)
    protocol: Literal["udp"] = "udp"
    network: str = "10.78.0.0/24"
    client_dns: list[str] = Field(default_factory=lambda: ["1.1.1.1", "1.0.0.1"])

    @field_validator("interface")
    @classmethod
    def interface_name(cls, value: str) -> str:
        if not value or len(value) > 15 or any(not (c.isalnum() or c in "_.-") for c in value):
            raise ValueError("invalid OpenVPN interface name")
        return value

    @field_validator("network")
    @classmethod
    def tunnel_network(cls, value: str) -> str:
        try:
            network = ipaddress.ip_network(value)
        except ValueError as error:
            raise ValueError("invalid OpenVPN tunnel network") from error
        private_ranges = tuple(
            ipaddress.IPv4Network(item)
            for item in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        )
        if (
            network.version != 4
            or not 16 <= network.prefixlen <= 29
            or not any(network.subnet_of(private) for private in private_ranges)
        ):
            raise ValueError("OpenVPN network must be an RFC1918 IPv4 /16 through /29")
        return str(network)

    @field_validator("client_dns")
    @classmethod
    def dns_addresses(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("at least one OpenVPN client DNS address is required")
        try:
            for address in value:
                if ipaddress.ip_address(address).version != 4:
                    raise ValueError("IPv6 DNS is not supported by the IPv4-only OpenVPN pool")
        except ValueError as error:
            raise ValueError("OpenVPN client DNS entries must be IPv4 addresses") from error
        return value


class ToggleConfig(StrictModel):
    enabled: bool = False


class SingBoxConfig(StrictModel):
    enabled: bool = False
    binary_source: Literal["managed", "system"] = "managed"


class CoresConfig(StrictModel):
    wireguard: WireGuardConfig = Field(default_factory=WireGuardConfig)
    openvpn: OpenVPNConfig = Field(default_factory=OpenVPNConfig)
    singbox: SingBoxConfig = Field(default_factory=SingBoxConfig)
    xray: ToggleConfig = Field(default_factory=ToggleConfig)


class AppConfig(StrictModel):
    schema_version: Literal[1] = 1
    server: ServerConfig = Field(default_factory=ServerConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    cores: CoresConfig = Field(default_factory=CoresConfig)

    @model_validator(mode="after")
    def distinct_provider_networks(self) -> AppConfig:
        wireguard = ipaddress.ip_interface(self.cores.wireguard.address).network
        openvpn = ipaddress.ip_network(self.cores.openvpn.network)
        if wireguard.overlaps(openvpn):
            raise ValueError("WireGuard and OpenVPN tunnel networks must not overlap")
        if self.cores.wireguard.interface == self.cores.openvpn.interface:
            raise ValueError("WireGuard and OpenVPN interface names must differ")
        if self.cores.wireguard.listen_port == self.cores.openvpn.listen_port:
            raise ValueError("WireGuard and OpenVPN UDP listen ports must differ")
        return self

    def as_toml(self) -> str:
        """Render the small public configuration surface without secret values."""
        wg = self.cores.wireguard
        openvpn = self.cores.openvpn
        outbound = (
            f'outbound_interface = "{self.network.outbound_interface}"\n'
            if self.network.outbound_interface
            else ""
        )
        dns = ", ".join(f'"{item}"' for item in wg.client_dns)
        openvpn_dns = ", ".join(f'"{item}"' for item in openvpn.client_dns)
        return (
            "schema_version = 1\n\n"
            "[server]\n"
            f'domain = "{self.server.domain}"\n\n'
            "[network]\n"
            f"ipv4 = {str(self.network.ipv4).lower()}\n"
            f"ipv6 = {str(self.network.ipv6).lower()}\n"
            f"{outbound}\n"
            "[cores.wireguard]\n"
            f"enabled = {str(wg.enabled).lower()}\n"
            f'interface = "{wg.interface}"\n'
            f"listen_port = {wg.listen_port}\n"
            f'address = "{wg.address}"\n'
            f"client_dns = [{dns}]\n\n"
            "[cores.openvpn]\n"
            f"enabled = {str(openvpn.enabled).lower()}\n"
            f'interface = "{openvpn.interface}"\n'
            f"listen_port = {openvpn.listen_port}\n"
            f'protocol = "{openvpn.protocol}"\n'
            f'network = "{openvpn.network}"\n'
            f"client_dns = [{openvpn_dns}]\n\n"
            "[cores.singbox]\n"
            f"enabled = {str(self.cores.singbox.enabled).lower()}\n"
            f'binary_source = "{self.cores.singbox.binary_source}"\n\n'
            "[cores.xray]\n"
            f"enabled = {str(self.cores.xray.enabled).lower()}\n"
        )


def load_config(path: Path) -> AppConfig:
    if path.is_symlink() and not path.exists():
        raise ConfigError(f"refusing broken configuration symlink: {path}")
    if not path.exists():
        return AppConfig()
    try:
        with path.open("rb") as file:
            raw = tomllib.load(file)
        return AppConfig.model_validate(raw)
    except (OSError, tomllib.TOMLDecodeError, ValidationError) as error:
        raise ConfigError(f"invalid configuration at {path}: {error}") from error
