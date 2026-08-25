"""Independent AmneziaWG server and client key generation."""

from fluxgate.providers.base import OperationContext
from fluxgate.providers.wireguard.family import WireGuardFamilyKeys


class AmneziaWGKeys(WireGuardFamilyKeys):
    def __init__(self, context: OperationContext) -> None:
        super().__init__(
            context,
            tool=str(context.paths.awg_binary),
            private_path=context.paths.secrets_dir / "amneziawg-server.key",
            public_path=context.paths.secrets_dir / "amneziawg-server.pub",
            label="AmneziaWG",
        )
