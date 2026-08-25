from pathlib import Path

import pytest

from fluxgate.core.errors import ProviderError
from fluxgate.providers.wireguard.keys import WireGuardKeys


def test_partial_server_key_write_removes_new_private_key(provider_context, monkeypatch) -> None:
    from fluxgate.core.state import atomic_write as real_atomic_write
    from fluxgate.providers.wireguard import keys as key_module

    key_store = WireGuardKeys(provider_context)

    def fail_public(path: Path, content: bytes, mode: int) -> None:
        if path == key_store.public_path:
            raise OSError("injected public-key write failure")
        real_atomic_write(path, content, mode)

    monkeypatch.setattr(key_module, "atomic_write", fail_public)
    with pytest.raises(OSError, match="injected"):
        key_store.ensure_server()
    assert not key_store.private_path.exists()
    assert not key_store.public_path.exists()


def test_world_readable_server_private_key_is_rejected(provider_context) -> None:
    key_store = WireGuardKeys(provider_context)
    key_store.private_path.parent.mkdir(parents=True)
    key_store.private_path.write_text("existing-private\n")
    key_store.private_path.chmod(0o644)
    with pytest.raises(ProviderError, match="unsafe permissions"):
        key_store.read_private()
