"""Honest placeholders for planned core providers."""

from fluxgate.core.errors import UnsupportedProviderError
from fluxgate.core.models import (
    OperationResult,
    ProviderDetection,
    ProviderStateName,
    ProviderStatus,
)
from fluxgate.providers.base import CoreProvider


class PlaceholderProvider(CoreProvider):
    def detect(self) -> ProviderDetection:
        return ProviderDetection(available=False, detail="provider is planned but not implemented")

    def status(self) -> ProviderStatus:
        return ProviderStatus(
            name=self.name,
            state=ProviderStateName.UNSUPPORTED,
            detail="not implemented in FluxGate 0.1",
        )

    def enable(self) -> OperationResult:
        raise UnsupportedProviderError(f"{self.display_name} is not implemented in FluxGate 0.1")

    def disable(self) -> OperationResult:
        raise UnsupportedProviderError(f"{self.display_name} is not implemented in FluxGate 0.1")
