"""Application dependency assembly."""

from __future__ import annotations

from dataclasses import dataclass

from fluxgate.clients import ClientService
from fluxgate.core.commands import CommandRunner
from fluxgate.core.config import AppConfig, load_config
from fluxgate.core.paths import PathLayout
from fluxgate.core.registry import ProviderRegistry
from fluxgate.core.state import StateStore
from fluxgate.profiles import ProfileService
from fluxgate.providers.base import OperationContext
from fluxgate.providers.openvpn import OpenVPNProvider
from fluxgate.providers.singbox import SingBoxProvider
from fluxgate.providers.wireguard import WireGuardProvider
from fluxgate.providers.xray import XrayProvider
from fluxgate.system.firewall import NftablesFirewallManager
from fluxgate.system.forwarding import ForwardingManager
from fluxgate.system.networking import LinuxNetworkInspector
from fluxgate.system.packages import AptPackageManager
from fluxgate.system.services import SystemdServiceManager


@dataclass(slots=True)
class Application:
    config: AppConfig
    paths: PathLayout
    state: StateStore
    providers: ProviderRegistry
    clients: ClientService
    profiles: ProfileService
    context: OperationContext


def build_application(*, dry_run: bool = False) -> Application:
    paths = PathLayout.from_environment()
    config = load_config(paths.config_file)
    state = StateStore(paths.state_file)
    runner = CommandRunner(dry_run=dry_run)
    context = OperationContext(
        config=config,
        paths=paths,
        state=state,
        runner=runner,
        packages=AptPackageManager(runner),
        services=SystemdServiceManager(runner),
        firewall=NftablesFirewallManager(runner, paths.firewall_file, paths.firewall_unit_file),
        forwarding=ForwardingManager(paths.forwarding_file, runner),
        network=LinuxNetworkInspector(runner),
        dry_run=dry_run,
    )
    providers = ProviderRegistry(
        [
            WireGuardProvider(context),
            OpenVPNProvider(context),
            SingBoxProvider(context),
            XrayProvider(context),
        ]
    )
    return Application(
        config,
        paths,
        state,
        providers,
        ClientService(state, providers),
        ProfileService(state, providers),
        context,
    )
