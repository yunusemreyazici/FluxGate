"""Shared WireGuard-family key and IPv4 allocation primitives."""

from __future__ import annotations

import ipaddress
import os
import stat
from pathlib import Path

from fluxgate.core.errors import ProviderError
from fluxgate.core.models import Client
from fluxgate.core.state import atomic_write
from fluxgate.providers.base import OperationContext


class WireGuardFamilyKeys:
    def __init__(
        self,
        context: OperationContext,
        *,
        tool: str,
        private_path: Path,
        public_path: Path,
        label: str,
    ) -> None:
        self.context = context
        self.tool = tool
        self.private_path = private_path
        self.public_path = public_path
        self.label = label

    def _assert_safe_ancestors(self, path: Path) -> None:
        for candidate in (path.parent, *path.parent.parents):
            if candidate.is_symlink():
                raise ProviderError(f"refusing symlinked {self.label} key path: {candidate}")
            if not candidate.exists():
                continue
            if not candidate.is_dir():
                raise ProviderError(f"{self.label} key ancestor is not a directory: {candidate}")
            metadata = candidate.stat()
            mode = stat.S_IMODE(metadata.st_mode)
            if mode & 0o022 and not mode & stat.S_ISVTX:
                raise ProviderError(f"{self.label} key path is group/world-writable: {candidate}")
            if os.geteuid() == 0 and metadata.st_uid != 0:
                raise ProviderError(f"{self.label} key path is not root-owned: {candidate}")

    def _read(self, path: Path, *, private: bool) -> str:
        self._assert_safe_ancestors(path)
        label = "private" if private else "public"
        if not path.exists():
            raise ProviderError(f"{self.label} server {label} key is missing")
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            raise ProviderError(f"{self.label} server {label} key is not a safe regular file")
        metadata = path.stat()
        expected_mode = 0o600 if private else 0o644
        if metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise ProviderError(f"{self.label} server {label} key has unsafe links or permissions")
        value = path.read_text().strip()
        if not value or len(value) > 128 or any(character.isspace() for character in value):
            raise ProviderError(f"{self.label} server {label} key has invalid content")
        return value

    def keypair(self) -> tuple[str, str]:
        private = self.context.runner.run([self.tool, "genkey"]).stdout.strip()
        if not private:
            raise ProviderError(f"{self.tool} returned an empty private key")
        public = self.context.runner.run(
            [self.tool, "pubkey"], input_text=f"{private}\n"
        ).stdout.strip()
        if not public:
            raise ProviderError(f"{self.tool} returned an empty public key")
        return private, public

    def ensure_server(self) -> bool:
        for path in (self.private_path, self.public_path):
            self._assert_safe_ancestors(path)
            if path.is_symlink():
                raise ProviderError(f"refusing to read {self.label} key through symlink: {path}")
        if self.private_path.exists():
            private = self.read_private()
            derived = self.context.runner.run(
                [self.tool, "pubkey"], input_text=f"{private}\n"
            ).stdout.strip()
            if not derived:
                raise ProviderError(f"{self.tool} returned an empty public key")
            if self.public_path.exists():
                if self.read_public() != derived:
                    raise ProviderError(f"{self.label} server public/private keys do not match")
                return False
            atomic_write(self.public_path, f"{derived}\n".encode(), 0o644)
            return True
        if self.public_path.exists():
            raise ProviderError(f"{self.label} public key exists but the private key is missing")
        private, public = self.keypair()
        atomic_write(self.private_path, f"{private}\n".encode(), 0o600)
        try:
            atomic_write(self.public_path, f"{public}\n".encode(), 0o644)
        except BaseException:
            self.private_path.unlink(missing_ok=True)
            raise
        return True

    def read_private(self) -> str:
        return self._read(self.private_path, private=True)

    def read_public(self) -> str:
        return self._read(self.public_path, private=False)


def validate_credential(
    client: Client,
    network: ipaddress.IPv4Network,
    *,
    provider: str,
    expected_profile_id: str | None = None,
) -> dict[str, object]:
    value = client.provider_credentials[provider]
    expected = {"public_key", "address"}
    if expected_profile_id is not None:
        expected.add("profile_id")
    if set(value) != expected:
        raise ProviderError(f"invalid {provider} credentials for client {client.name}")
    public_key = value["public_key"]
    address = value["address"]
    if (
        not isinstance(public_key, str)
        or not public_key
        or len(public_key) > 128
        or any(character.isspace() for character in public_key)
        or not isinstance(address, str)
    ):
        raise ProviderError(f"invalid {provider} credentials for client {client.name}")
    if expected_profile_id is not None and value.get("profile_id") != expected_profile_id:
        raise ProviderError(f"{provider} client profile does not match the active profile")
    try:
        interface = ipaddress.ip_interface(address)
    except ValueError as error:
        raise ProviderError(f"invalid {provider} address for client {client.name}") from error
    if interface.version != 4 or interface.network.prefixlen != 32 or interface.ip not in network:
        raise ProviderError(f"invalid {provider} address for client {client.name}")
    return value


def allocate_ipv4_address(
    network: ipaddress.IPv4Network,
    server: ipaddress.IPv4Address,
    clients: list[Client],
    *,
    provider: str,
    expected_profile_id: str | None = None,
) -> str:
    allocated = {
        ipaddress.ip_interface(
            str(
                validate_credential(
                    client,
                    network,
                    provider=provider,
                    expected_profile_id=expected_profile_id,
                )["address"]
            )
        ).ip
        for client in clients
    }
    for address in network.hosts():
        if address != server and address not in allocated:
            return f"{address}/32"
    raise ProviderError(f"no available {provider} client addresses in {network}")
