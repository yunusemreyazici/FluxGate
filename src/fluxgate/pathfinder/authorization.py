"""Central authorization boundary for active probe targets."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from uuid import UUID

from fluxgate.core.errors import PathfinderAuthorizationError
from fluxgate.core.manifest import ServerManifest
from fluxgate.pathfinder.active_models import AuthorizationSource
from fluxgate.pathfinder.addressing import normalize_authorized_addresses
from fluxgate.pathfinder.models import (
    ConnectionCandidate,
    ConnectionMode,
    FeatureCapability,
    IPFamily,
    PathfinderProtocol,
    PathfinderProvider,
    PathfinderSecurity,
    PathfinderTransport,
)

MAX_AUTHORIZED_CANDIDATES = 64

_AUTHORIZED_CANDIDATE_SHAPES = {
    PathfinderProtocol.WIREGUARD: (
        PathfinderProvider.WIREGUARD,
        PathfinderTransport.UDP,
        PathfinderSecurity.WIREGUARD,
        ConnectionMode.SYSTEM_TUNNEL,
        frozenset({FeatureCapability.UDP}),
    ),
    PathfinderProtocol.AMNEZIAWG: (
        PathfinderProvider.AMNEZIAWG,
        PathfinderTransport.UDP,
        PathfinderSecurity.WIREGUARD,
        ConnectionMode.SYSTEM_TUNNEL,
        frozenset({FeatureCapability.UDP, FeatureCapability.AMNEZIAWG_3_1}),
    ),
    PathfinderProtocol.OPENVPN: (
        PathfinderProvider.OPENVPN,
        PathfinderTransport.UDP,
        PathfinderSecurity.TLS,
        ConnectionMode.SYSTEM_TUNNEL,
        frozenset({FeatureCapability.UDP}),
    ),
    PathfinderProtocol.VLESS: (
        PathfinderProvider.SINGBOX,
        PathfinderTransport.TCP,
        PathfinderSecurity.TLS,
        ConnectionMode.LOCAL_PROXY,
        frozenset(),
    ),
    PathfinderProtocol.TROJAN: (
        PathfinderProvider.SINGBOX,
        PathfinderTransport.TCP,
        PathfinderSecurity.TLS,
        ConnectionMode.LOCAL_PROXY,
        frozenset(),
    ),
    PathfinderProtocol.HYSTERIA2: (
        PathfinderProvider.SINGBOX,
        PathfinderTransport.QUIC,
        PathfinderSecurity.TLS,
        ConnectionMode.LOCAL_PROXY,
        frozenset({FeatureCapability.UDP, FeatureCapability.QUIC}),
    ),
}


@dataclass(frozen=True, slots=True)
class AuthorizedCandidateInventory:
    source: AuthorizationSource
    endpoint: str
    server_id: UUID | None
    authorized_addresses: tuple[str, ...]
    candidates: tuple[ConnectionCandidate, ...]


def _validate_endpoint(endpoint: str) -> None:
    if (
        not endpoint
        or endpoint != endpoint.strip()
        or len(endpoint) > 253
        or any(ord(character) < 33 or ord(character) == 127 for character in endpoint)
    ):
        raise PathfinderAuthorizationError("authorized Pathfinder endpoint is malformed")
    try:
        ipaddress.ip_address(endpoint)
        return
    except ValueError:
        pass
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-."
    if any(character not in allowed for character in endpoint):
        raise PathfinderAuthorizationError("authorized Pathfinder endpoint is malformed")
    labels = endpoint.rstrip(".").split(".")
    if any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        for label in labels
    ):
        raise PathfinderAuthorizationError("authorized Pathfinder endpoint is malformed")


def authorize_manifest(
    manifest: ServerManifest,
    *,
    source: AuthorizationSource,
    trusted_server_id: UUID | None = None,
    trusted_endpoint: str | None = None,
    trusted_addresses: tuple[str, ...] = (),
) -> AuthorizedCandidateInventory:
    """Authorize only candidates bound to a local or signature-verified server inventory."""
    endpoint = manifest.server.identity
    if source == AuthorizationSource.LOCAL_STATE and not manifest.candidates and not endpoint:
        return AuthorizedCandidateInventory(
            source=source,
            endpoint=endpoint,
            server_id=manifest.server.server_id,
            authorized_addresses=(),
            candidates=(),
        )
    _validate_endpoint(endpoint)
    try:
        authorized_addresses = normalize_authorized_addresses(trusted_addresses)
    except ValueError as error:
        raise PathfinderAuthorizationError(str(error)) from error
    if source == AuthorizationSource.SIGNED_MANIFEST and (
        trusted_server_id is None
        or manifest.server.server_id is None
        or manifest.server.server_id != trusted_server_id
    ):
        raise PathfinderAuthorizationError(
            "active probing requires a manifest bound to pinned server trust"
        )
    if source == AuthorizationSource.SIGNED_MANIFEST:
        if trusted_endpoint is None:
            raise PathfinderAuthorizationError(
                "active probing requires an independently pinned server endpoint"
            )
        _validate_endpoint(trusted_endpoint)
        if endpoint != trusted_endpoint:
            raise PathfinderAuthorizationError(
                "signed manifest endpoint does not match the independently pinned server endpoint"
            )
    try:
        literal_endpoint = ipaddress.ip_address(endpoint)
    except ValueError:
        literal_endpoint = None
    if literal_endpoint is not None:
        canonical_literal = str(literal_endpoint)
        if authorized_addresses and authorized_addresses != (canonical_literal,):
            raise PathfinderAuthorizationError(
                "literal server endpoint may authorize only its own address"
            )
        authorized_addresses = (canonical_literal,)
    elif source == AuthorizationSource.SIGNED_MANIFEST and not authorized_addresses:
        raise PathfinderAuthorizationError(
            "hostname-based signed probing requires an independently pinned server address"
        )
    if len(manifest.candidates) > MAX_AUTHORIZED_CANDIDATES:
        raise PathfinderAuthorizationError(
            f"active probing accepts at most {MAX_AUTHORIZED_CANDIDATES} authorized candidates"
        )
    identifiers: set[str] = set()
    for candidate in manifest.candidates:
        if candidate.candidate_id in identifiers:
            raise PathfinderAuthorizationError("authorized candidate IDs must be unique")
        identifiers.add(candidate.candidate_id)
        expected_shape = _AUTHORIZED_CANDIDATE_SHAPES[candidate.protocol]
        actual_shape = (
            candidate.provider,
            candidate.transport,
            candidate.security,
            candidate.connection_mode,
            frozenset(candidate.required_features),
        )
        if actual_shape != expected_shape:
            raise PathfinderAuthorizationError(
                f"candidate {candidate.candidate_id} has an unauthorized capability shape"
            )
        expected_socket = "tcp" if candidate.transport == PathfinderTransport.TCP else "udp"
        if candidate.socket_protocol != expected_socket:
            raise PathfinderAuthorizationError(
                f"candidate {candidate.candidate_id} has inconsistent transport metadata"
            )
        if not candidate.ip_families:
            raise PathfinderAuthorizationError(
                f"candidate {candidate.candidate_id} has no authorized IP family"
            )
        if not candidate.enabled:
            continue
        _validate_endpoint(candidate.endpoint)
        if candidate.endpoint != endpoint:
            raise PathfinderAuthorizationError(
                f"candidate {candidate.candidate_id} targets an unauthorized endpoint"
            )
        try:
            literal = ipaddress.ip_address(candidate.endpoint)
        except ValueError:
            continue
        required_family = IPFamily.IPV4 if literal.version == 4 else IPFamily.IPV6
        if required_family not in candidate.ip_families:
            raise PathfinderAuthorizationError(
                f"candidate {candidate.candidate_id} excludes its literal endpoint IP family"
            )
    return AuthorizedCandidateInventory(
        source=source,
        endpoint=endpoint,
        server_id=manifest.server.server_id,
        authorized_addresses=authorized_addresses,
        candidates=manifest.candidates,
    )
