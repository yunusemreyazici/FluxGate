"""Pure OpenVPN addressing and configuration rendering."""

from __future__ import annotations

import ipaddress
from pathlib import Path

from fluxgate.core.config import OpenVPNConfig
from fluxgate.core.errors import ProviderError
from fluxgate.core.models import Client


def tunnel_network(settings: OpenVPNConfig) -> ipaddress.IPv4Network:
    network = ipaddress.ip_network(settings.network)
    if not isinstance(network, ipaddress.IPv4Network):
        raise ProviderError("OpenVPN currently requires an IPv4 tunnel network")
    return network


def server_address(settings: OpenVPNConfig) -> ipaddress.IPv4Address:
    return next(tunnel_network(settings).hosts())


def credential(client: Client, network: ipaddress.IPv4Network) -> dict[str, object]:
    value = client.provider_credentials["openvpn"]
    if set(value) != {"common_name", "serial", "address"}:
        raise ProviderError(f"invalid OpenVPN credentials for client {client.name}")
    common_name = value["common_name"]
    serial = value["serial"]
    address = value["address"]
    if (
        not isinstance(common_name, str)
        or not common_name.startswith("fluxgate-client-")
        or len(common_name) > 64
        or any(not (character.isalnum() or character == "-") for character in common_name)
        or not isinstance(serial, str)
        or not serial
        or len(serial) > 64
        or any(character not in "0123456789ABCDEFabcdef" for character in serial)
        or not isinstance(address, str)
    ):
        raise ProviderError(f"invalid OpenVPN credentials for client {client.name}")
    try:
        client_address = ipaddress.ip_address(address)
    except ValueError as error:
        raise ProviderError(f"invalid OpenVPN address for client {client.name}") from error
    if (
        not isinstance(client_address, ipaddress.IPv4Address)
        or client_address not in network
        or client_address == server_address_from_network(network)
        or client_address in {network.network_address, network.broadcast_address}
    ):
        raise ProviderError(f"invalid OpenVPN address for client {client.name}")
    return value


def server_address_from_network(network: ipaddress.IPv4Network) -> ipaddress.IPv4Address:
    return next(network.hosts())


def allocate_address(settings: OpenVPNConfig, clients: list[Client]) -> str:
    network = tunnel_network(settings)
    server = server_address_from_network(network)
    allocated = {
        ipaddress.ip_address(str(credential(client, network)["address"])) for client in clients
    }
    for address in network.hosts():
        if address != server and address not in allocated:
            return str(address)
    raise ProviderError(f"no available OpenVPN client addresses in {network}")


def common_name(client: Client) -> str:
    return f"fluxgate-client-{client.id.hex}"


def render_server(
    settings: OpenVPNConfig,
    *,
    pki_dir: Path,
    ccd_dir: Path,
    crl_path: Path,
) -> bytes:
    network = tunnel_network(settings)
    lines = [
        "# Managed by FluxGate; local edits may be replaced.",
        f"port {settings.listen_port}",
        f"proto {settings.protocol}",
        f"dev {settings.interface}",
        "dev-type tun",
        "topology subnet",
        f"server {network.network_address} {network.netmask}",
        f"client-config-dir {ccd_dir}",
        "ccd-exclusive",
        f"ca {pki_dir / 'ca.crt'}",
        f"cert {pki_dir / 'server.crt'}",
        f"key {pki_dir / 'server.key'}",
        f"crl-verify {crl_path}",
        "dh none",
        "ecdh-curve prime256v1",
        f"tls-crypt {pki_dir / 'tls-crypt.key'}",
        "tls-version-min 1.2",
        "data-ciphers AES-256-GCM:AES-128-GCM",
        "auth SHA256",
        "verify-client-cert require",
        "keepalive 10 120",
        "persist-key",
        "persist-tun",
        "user nobody",
        "group nogroup",
        'push "redirect-gateway def1 bypass-dhcp"',
    ]
    lines.extend(f'push "dhcp-option DNS {address}"' for address in settings.client_dns)
    lines.extend(
        [
            "explicit-exit-notify 1",
            "status /run/openvpn-server/fluxgate-status.log",
            "verb 3",
        ]
    )
    return ("\n".join(lines) + "\n").encode()


def render_ccd(settings: OpenVPNConfig, client: Client) -> bytes:
    value = credential(client, tunnel_network(settings))
    return (
        "# Managed by FluxGate; local edits may be replaced.\n"
        f"ifconfig-push {value['address']} {tunnel_network(settings).netmask}\n"
    ).encode()


def _pem(label: str, content: str, *, allow_comment_preamble: bool = False) -> str:
    stripped = content.strip()
    if allow_comment_preamble:
        lines = stripped.splitlines()
        while lines and lines[0].startswith("#"):
            lines.pop(0)
        stripped = "\n".join(lines).strip()
    if not stripped.startswith("-----BEGIN ") or "-----END " not in stripped:
        raise ProviderError(f"invalid OpenVPN {label} PEM material")
    return stripped


def render_client(
    settings: OpenVPNConfig,
    domain: str,
    *,
    ca_certificate: str,
    client_certificate: str,
    client_key: str,
    tls_crypt_key: str,
) -> str:
    if not domain:
        raise ProviderError("server.domain is required to export an OpenVPN client")
    ca = _pem("CA certificate", ca_certificate)
    certificate = _pem("client certificate", client_certificate)
    key = _pem("client private key", client_key)
    tls_crypt = _pem("tls-crypt key", tls_crypt_key, allow_comment_preamble=True)
    return (
        "# Generated by FluxGate\n"
        "client\n"
        "dev tun\n"
        f"proto {settings.protocol}\n"
        f"remote {domain} {settings.listen_port}\n"
        "nobind\n"
        "persist-key\n"
        "persist-tun\n"
        "remote-cert-tls server\n"
        "verify-x509-name fluxgate-server name\n"
        "tls-version-min 1.2\n"
        "data-ciphers AES-256-GCM:AES-128-GCM\n"
        "cipher AES-256-GCM\n"
        "auth SHA256\n"
        "auth-nocache\n"
        "verb 3\n"
        f"<ca>\n{ca}\n</ca>\n"
        f"<cert>\n{certificate}\n</cert>\n"
        f"<key>\n{key}\n</key>\n"
        f"<tls-crypt>\n{tls_crypt}\n</tls-crypt>\n"
    )
