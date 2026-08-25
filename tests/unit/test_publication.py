from __future__ import annotations

from pathlib import Path

import pytest

import fluxgate.core.publication as publication
from fluxgate.core.errors import FluxGateError, VerificationError
from fluxgate.core.publication import publish_tree


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def _verify(*expected: dict[str, bytes]):
    def verify(root: Path) -> None:
        if _snapshot(root) not in expected:
            raise VerificationError("tree does not match expected generation")

    return verify


def _publish_initial(destination: Path) -> dict[str, bytes]:
    old = {"a.txt": b"old-a", "nested/b.txt": b"old-b"}
    publish_tree(destination, {name: (value, 0o600) for name, value in old.items()}, _verify(old))
    return old


def test_parent_fsync_failure_before_commit_restores_exact_old_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "bundle"
    old = _publish_initial(destination)
    new = {"a.txt": b"new-a", "nested/b.txt": b"new-b"}
    monkeypatch.setattr(
        publication,
        "_fsync_directory",
        lambda _path: (_ for _ in ()).throw(OSError("injected parent fsync failure")),
    )
    with pytest.raises(OSError, match="parent fsync"):
        publish_tree(
            destination,
            {name: (value, 0o600) for name, value in new.items()},
            _verify(old, new),
        )
    assert _snapshot(destination) == old


def test_first_backup_cleanup_failure_retains_committed_new_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "bundle"
    old = _publish_initial(destination)
    new = {"a.txt": b"new-a", "nested/b.txt": b"new-b"}

    def fail_cleanup(_root: Path) -> None:
        raise OSError("injected first cleanup failure")

    monkeypatch.setattr(publication, "_remove_owned_tree", fail_cleanup)
    with pytest.raises(FluxGateError, match="committed successfully"):
        publish_tree(
            destination,
            {name: (value, 0o600) for name, value in new.items()},
            _verify(old, new),
        )
    assert _snapshot(destination) == new
    assert len(list(tmp_path.glob(".bundle.backup.*"))) == 1


def test_partial_backup_cleanup_failure_retains_new_tree_and_retry_is_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "bundle"
    old = _publish_initial(destination)
    new = {"a.txt": b"new-a", "nested/b.txt": b"new-b"}
    final = {"a.txt": b"final-a", "nested/b.txt": b"final-b"}
    real_remove = publication._remove_owned_tree

    def partially_remove_backup(root: Path) -> None:
        (root / "a.txt").unlink()
        raise OSError("injected partial cleanup failure")

    monkeypatch.setattr(publication, "_remove_owned_tree", partially_remove_backup)
    with pytest.raises(FluxGateError, match="stale backup remains"):
        publish_tree(
            destination,
            {name: (value, 0o600) for name, value in new.items()},
            _verify(old, new),
        )
    assert _snapshot(destination) == new
    stale = list(tmp_path.glob(".bundle.backup.*"))
    assert len(stale) == 1
    assert _snapshot(stale[0]) == {"nested/b.txt": b"old-b"}

    monkeypatch.setattr(publication, "_remove_owned_tree", real_remove)
    publish_tree(
        destination,
        {name: (value, 0o600) for name, value in final.items()},
        _verify(new, final),
    )
    assert _snapshot(destination) == final
    assert stale[0].exists()


def test_existing_destination_does_not_hide_unsafe_writable_parent(tmp_path: Path) -> None:
    parent = tmp_path / "output"
    parent.mkdir(mode=0o700)
    destination = parent / "bundle"
    old = _publish_initial(destination)
    parent.chmod(0o777)
    with pytest.raises(FluxGateError, match="group/world-writable"):
        publish_tree(destination, {"a.txt": (b"new", 0o600)}, _verify(old, {"a.txt": b"new"}))
    assert _snapshot(destination) == old
