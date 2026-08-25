"""Provider registry without provider-specific branches."""

from __future__ import annotations

from collections.abc import Iterable

from fluxgate.core.errors import ProviderError
from fluxgate.providers.base import CoreProvider


class ProviderRegistry:
    def __init__(self, providers: Iterable[CoreProvider] = ()) -> None:
        self._providers: dict[str, CoreProvider] = {}
        for provider in providers:
            self.register(provider)

    def register(self, provider: CoreProvider) -> None:
        if provider.name in self._providers:
            raise ProviderError(f"provider already registered: {provider.name}")
        self._providers[provider.name] = provider

    def get(self, name: str) -> CoreProvider:
        try:
            return self._providers[name]
        except KeyError as error:
            choices = ", ".join(self._providers)
            raise ProviderError(f"unknown core '{name}' (choose from: {choices})") from error

    def all(self) -> tuple[CoreProvider, ...]:
        return tuple(self._providers.values())
