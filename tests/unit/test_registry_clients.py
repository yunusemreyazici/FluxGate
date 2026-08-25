from multiprocessing import get_context
from pathlib import Path

import pytest

from fluxgate.clients import ClientService
from fluxgate.core.errors import FluxGateError, ProviderError, UnsupportedProviderError
from fluxgate.core.models import (
    OperationResult,
    ProviderDetection,
    ProviderStateName,
    ProviderStatus,
)
from fluxgate.core.registry import ProviderRegistry
from fluxgate.core.state import StateStore
from fluxgate.providers.base import CoreProvider
from fluxgate.providers.openvpn import OpenVPNProvider
from fluxgate.providers.xray import XrayProvider


class MinimalProvider(CoreProvider):
    name = "minimal"
    display_name = "Minimal"

    def detect(self) -> ProviderDetection:
        return ProviderDetection(available=True)

    def status(self) -> ProviderStatus:
        return ProviderStatus(name=self.name, state=ProviderStateName.DISABLED)

    def enable(self) -> OperationResult:
        return OperationResult(changed=False, message="ok")

    def disable(self) -> OperationResult:
        return OperationResult(changed=False, message="ok")


def add_client_in_process(state_path: str, name: str) -> None:
    service = ClientService(StateStore(Path(state_path)), ProviderRegistry())
    service.add(name)


def test_registry_lookup_duplicate_and_unknown(provider_context) -> None:
    provider = MinimalProvider(provider_context)
    registry = ProviderRegistry([provider])
    assert registry.get("minimal") is provider
    with pytest.raises(ProviderError, match="already registered"):
        registry.register(provider)
    with pytest.raises(ProviderError, match="unknown core"):
        registry.get("missing")
    provider.name = "../unsafe"
    with pytest.raises(ProviderError, match="invalid provider name"):
        ProviderRegistry([provider])


def test_openvpn_provider_registers_production_capabilities(provider_context) -> None:
    provider = OpenVPNProvider(provider_context)
    registry = ProviderRegistry([provider])
    assert registry.get("openvpn") is provider
    assert provider.capabilities


def test_planned_provider_messages_are_release_version_neutral(provider_context) -> None:
    provider = XrayProvider(provider_context)
    assert provider.status().detail == "provider is planned but not implemented"
    with pytest.raises(UnsupportedProviderError, match="planned but not implemented"):
        provider.enable()


def test_client_service_prevents_duplicate_names(tmp_path: Path) -> None:
    service = ClientService(StateStore(tmp_path / "state.json"), ProviderRegistry())
    first = service.add("alice")
    assert first.name == "alice"
    with pytest.raises(FluxGateError, match="already exists"):
        service.add("alice")
    assert service.find(str(first.id)).id == first.id
    deleted = service.delete("alice")
    assert deleted == first.id
    assert service.list() == []


def test_concurrent_client_identity_creation_is_serialized(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    context = get_context("fork")
    processes = [
        context.Process(target=add_client_in_process, args=(str(state_path), f"client-{index}"))
        for index in range(8)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=10)
        assert process.exitcode == 0
    clients = StateStore(state_path).load().clients
    assert {client.name for client in clients} == {f"client-{index}" for index in range(8)}
