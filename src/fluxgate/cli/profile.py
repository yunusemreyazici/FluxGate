"""Protocol-profile metadata commands."""

from typing import Annotated

import typer

from fluxgate.cli.common import fail
from fluxgate.core.errors import FluxGateError

profile_app = typer.Typer(help="Inspect available protocol profiles.", no_args_is_help=True)

PROFILES = {
    "wireguard": ("wireguard", "available"),
    "openvpn-udp": ("openvpn", "available"),
    "openvpn-tcp": ("openvpn", "not available; UDP only"),
    "vless": ("sing-box/xray", "planned"),
    "vless-reality": ("sing-box/xray", "planned"),
    "hysteria2": ("sing-box", "planned"),
    "tuic": ("sing-box", "planned"),
    "trojan": ("sing-box/xray", "planned"),
    "anytls": ("sing-box", "planned"),
}


@profile_app.command("list")
def profile_list() -> None:
    """List profiles without claiming planned profiles work."""
    for name, (core, state) in PROFILES.items():
        typer.echo(f"{name:<18} {core:<15} {state}")


@profile_app.command("show")
def profile_show(name: Annotated[str, typer.Argument(help="Profile name.")]) -> None:
    """Describe a profile's implementing core and availability."""
    if name not in PROFILES:
        fail(FluxGateError(f"unknown profile: {name}"))
    core, state = PROFILES[name]
    typer.echo(f"Profile: {name}\nCore: {core}\nStatus: {state}")
