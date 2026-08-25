"""Client orchestration through provider capabilities."""

from __future__ import annotations

from uuid import UUID

from fluxgate.core.errors import FluxGateError
from fluxgate.core.models import Client, ProviderCapability, ProviderStateName
from fluxgate.core.registry import ProviderRegistry
from fluxgate.core.state import StateStore


class ClientService:
    def __init__(self, state: StateStore, providers: ProviderRegistry) -> None:
        self.state = state
        self.providers = providers

    def list(self) -> list[Client]:
        return self.state.load().clients

    def find(self, identity: str) -> Client:
        state = self.state.load()
        for client in state.clients:
            if client.name == identity or str(client.id) == identity:
                return client
        raise FluxGateError(f"client not found: {identity}")

    def add(self, name: str) -> Client:
        with self.state.lock():
            state = self.state.load()
            if any(client.name == name for client in state.clients):
                raise FluxGateError(f"client name already exists: {name}")
            client = Client(name=name)
            configured = []
            try:
                for provider in self.providers.all():
                    if (
                        ProviderCapability.ADD_CLIENTS in provider.capabilities
                        and provider.status().state == ProviderStateName.RUNNING
                    ):
                        artifact = provider.add_client(client)
                        client.provider_credentials[provider.name] = artifact.credentials
                        configured.append(provider)
            except BaseException:
                for provider in reversed(configured):
                    provider.revoke_client(client)
                raise
            state.clients.append(client)
            self.state.save(state)
            return client

    def revoke(self, identity: str) -> Client:
        state = self.state.load()
        client = self.find(identity)
        for provider in self.providers.all():
            if provider.name in client.provider_credentials:
                provider.revoke_client(client)
        for index, stored in enumerate(state.clients):
            if stored.id == client.id:
                stored.enabled = False
                stored.provider_credentials = {}
                state.clients[index] = stored
        self.state.save(state)
        return client

    def delete(self, identity: str) -> UUID:
        client = self.find(identity)
        if client.enabled or client.provider_credentials:
            self.revoke(identity)
        state = self.state.load()
        state.clients = [stored for stored in state.clients if stored.id != client.id]
        self.state.save(state)
        return client.id
