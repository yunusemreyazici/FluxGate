"""WireGuard key generation and safe on-disk access."""

import stat
from pathlib import Path

from fluxgate.core.errors import ProviderError
from fluxgate.core.state import atomic_write
from fluxgate.providers.base import OperationContext


class WireGuardKeys:
    def __init__(self, context: OperationContext) -> None:
        self.context = context

    @property
    def private_path(self) -> Path:
        return self.context.paths.secrets_dir / "wireguard-server.key"

    @property
    def public_path(self) -> Path:
        return self.context.paths.secrets_dir / "wireguard-server.pub"

    def keypair(self) -> tuple[str, str]:
        private = self.context.runner.run(["wg", "genkey"]).stdout.strip()
        if not private:
            raise ProviderError("wg returned an empty private key")
        public = self.context.runner.run(["wg", "pubkey"], input_text=f"{private}\n").stdout.strip()
        if not public:
            raise ProviderError("wg returned an empty public key")
        return private, public

    def ensure_server(self) -> bool:
        for path in (self.private_path, self.public_path):
            if path.is_symlink():
                raise ProviderError(f"refusing to read WireGuard key through symlink: {path}")
        if self.private_path.exists():
            if self.public_path.exists():
                return False
            private = self.read_private()
            public = self.context.runner.run(
                ["wg", "pubkey"], input_text=f"{private}\n"
            ).stdout.strip()
            if not public:
                raise ProviderError("wg returned an empty public key")
            atomic_write(self.public_path, f"{public}\n".encode(), 0o644)
            return True
        if self.public_path.exists():
            raise ProviderError("WireGuard public key exists but the private key is missing")
        private, public = self.keypair()
        atomic_write(self.private_path, f"{private}\n".encode(), 0o600)
        try:
            atomic_write(self.public_path, f"{public}\n".encode(), 0o644)
        except BaseException:
            self.private_path.unlink(missing_ok=True)
            raise
        return True

    def _read(self, path: Path, label: str) -> str:
        if not path.exists():
            raise ProviderError(f"WireGuard server {label} key is missing")
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            raise ProviderError(f"WireGuard server {label} key is not a safe regular file")
        if label == "private" and stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise ProviderError(
                f"WireGuard server private key has unsafe permissions: {path}; expected 0600"
            )
        value = path.read_text().strip()
        if not value or len(value) > 128 or any(character.isspace() for character in value):
            raise ProviderError(f"WireGuard server {label} key has invalid content")
        return value

    def read_private(self) -> str:
        return self._read(self.private_path, "private")

    def read_public(self) -> str:
        return self._read(self.public_path, "public")
