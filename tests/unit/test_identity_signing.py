from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from pydantic import ValidationError

from fluxgate.core.errors import IdentityError, VerificationError
from fluxgate.identity import ServerIdentityManager
from fluxgate.identity.models import TrustDescriptor


def test_identity_is_stable_protected_and_signs_exact_bytes(provider_context) -> None:
    manager = ServerIdentityManager(provider_context.paths)
    first = manager.ensure()
    second = manager.ensure()

    assert first.metadata.server_id == second.metadata.server_id
    assert first.metadata.key_id == second.metadata.key_id
    assert manager.root.stat().st_mode & 0o777 == 0o700
    assert manager.private_path.stat().st_mode & 0o777 == 0o600
    assert manager.public_path.stat().st_mode & 0o777 == 0o644
    assert first.trust.public_key
    assert "private" not in first.trust.model_dump()

    payload = b'{"value":1}\n'
    signature = manager.sign(payload, first)
    assert signature == manager.sign(payload, first)
    manager.verify(payload, signature, first.trust)
    with pytest.raises(VerificationError, match="invalid"):
        manager.verify(b'{"value": 1}\n', signature, first.trust)


def test_signature_schema_base64_key_and_public_key_fail_closed(provider_context) -> None:
    first_manager = ServerIdentityManager(provider_context.paths)
    first = first_manager.ensure()
    payload = b"signed exact bytes"
    signature = first_manager.sign(payload, first)

    second_paths = provider_context.paths.__class__(
        config_dir=provider_context.paths.config_dir.parent / "other-config",
        data_dir=provider_context.paths.data_dir.parent / "other-data",
        log_dir=provider_context.paths.log_dir,
        wireguard_dir=provider_context.paths.wireguard_dir,
        openvpn_dir=provider_context.paths.openvpn_dir,
        sysctl_dir=provider_context.paths.sysctl_dir,
        nftables_dir=provider_context.paths.nftables_dir,
        systemd_dir=provider_context.paths.systemd_dir,
        local_lib_dir=provider_context.paths.local_lib_dir,
    )
    second = ServerIdentityManager(second_paths).ensure()
    with pytest.raises(VerificationError, match="key ID"):
        first_manager.verify(payload, signature, second.trust)

    envelope = json.loads(signature)
    for field, value in (
        ("signature", "not-base64%%%"),
        ("signature", "AA=="),
        ("algorithm", "none"),
        ("schema_version", 2),
        ("key_id", "ed25519:wrong"),
    ):
        modified = dict(envelope)
        modified[field] = value
        with pytest.raises((VerificationError, ValidationError)):
            first_manager.verify(payload, json.dumps(modified).encode(), first.trust)


def test_identity_corruption_foreign_paths_and_links_never_rotate(provider_context) -> None:
    manager = ServerIdentityManager(provider_context.paths)
    original = manager.ensure()
    manager.private_path.write_bytes(b"x" * 32)
    with pytest.raises(IdentityError):
        manager.ensure()
    assert manager.metadata_path.exists()
    assert manager.metadata_path.read_text().find(str(original.metadata.server_id)) >= 0

    manager.private_path.unlink()
    manager.private_path.write_bytes(original.private_key)
    manager.private_path.chmod(0o600)
    hardlink = manager.root / "linked.key"
    os.link(manager.private_path, hardlink)
    with pytest.raises(IdentityError, match="unexpected"):
        manager.load()
    hardlink.unlink()

    manager.root.rename(manager.root.with_name("saved-identity"))
    manager.root.symlink_to(manager.root.with_name("missing-target"))
    with pytest.raises(IdentityError, match="symlinked"):
        manager.load_optional()
    with pytest.raises(IdentityError, match="symlinked"):
        manager.ensure()


def test_concurrent_first_use_creates_one_identity(provider_context) -> None:
    manager = ServerIdentityManager(provider_context.paths)
    with ThreadPoolExecutor(max_workers=8) as pool:
        identities = list(pool.map(lambda _: manager.ensure(), range(16)))
    assert len({item.metadata.server_id for item in identities}) == 1
    assert len({item.metadata.key_id for item in identities}) == 1


def test_trust_descriptor_rejects_forged_fingerprint(provider_context) -> None:
    trust = ServerIdentityManager(provider_context.paths).ensure().trust.model_dump(mode="json")
    trust["fingerprint"] = "sha256:" + "0" * 64
    with pytest.raises(ValidationError, match="fingerprint"):
        TrustDescriptor.model_validate_json(json.dumps(trust))


def test_identity_generation_write_failure_leaves_no_partial_identity(
    provider_context, monkeypatch
) -> None:
    import fluxgate.identity.service as identity_module

    manager = ServerIdentityManager(provider_context.paths)
    real_write = identity_module.atomic_write
    calls = 0

    def failing_write(path, content, mode):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise OSError("injected public-key write failure")
        return real_write(path, content, mode)

    monkeypatch.setattr(identity_module, "atomic_write", failing_write)
    with pytest.raises(OSError, match="public-key"):
        manager.ensure()
    assert not manager.root.exists()
    assert not list(manager.root.parent.glob(".server-identity.*"))
    monkeypatch.setattr(identity_module, "atomic_write", real_write)
    assert manager.ensure().metadata.server_id


def test_identity_publication_failure_is_retryable_without_foreign_deletion(
    provider_context, monkeypatch
) -> None:
    import fluxgate.identity.service as identity_module

    manager = ServerIdentityManager(provider_context.paths)
    real_rename = identity_module.os.rename

    def failing_rename(source, destination):
        if Path(destination) == manager.root:
            raise OSError("injected identity publication failure")
        return real_rename(source, destination)

    monkeypatch.setattr(identity_module.os, "rename", failing_rename)
    with pytest.raises(OSError, match="publication"):
        manager.ensure()
    assert not manager.root.exists()
    assert not list(manager.root.parent.glob(".server-identity.*"))


def test_identity_unsafe_private_mode_fails_closed(provider_context) -> None:
    manager = ServerIdentityManager(provider_context.paths)
    identity = manager.ensure()
    manager.private_path.chmod(0o644)
    with pytest.raises(IdentityError, match="private key is unsafe"):
        manager.ensure()
    assert manager.metadata_path.read_text().find(str(identity.metadata.server_id)) >= 0
