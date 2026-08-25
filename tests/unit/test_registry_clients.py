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


def test_registry_lookup_duplicate_and_unknown(provider_context) -> None:
    provider = MinimalProvider(provider_context)
    registry = ProviderRegistry([provider])
    assert registry.get("minimal") is provider
    with pytest.raises(ProviderError, match="already registered"):
        registry.register(provider)
    with pytest.raises(ProviderError, match="unknown core"):
        registry.get("missing")


def test_placeholder_explicitly_refuses_enable(provider_context) -> None:
    provider = OpenVPNProvider(provider_context)
    assert provider.status().state == ProviderStateName.UNSUPPORTED
    with pytest.raises(UnsupportedProviderError, match="not implemented"):
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
