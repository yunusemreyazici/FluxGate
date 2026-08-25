# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and this project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Independent protected Ed25519 server signing identity and exact-byte detached signatures for
  secret-free capability manifests.
- Transactional client bootstrap bundles with pinned public trust, signed artifact inventories,
  SHA-256 provider artifact verification, and offline verification.
- Typed provider/profile candidates, typed client capabilities, and a deterministic, network-free
  Pathfinder compatibility evaluator with explicit rejection reasons.

### Security

- Fail-closed signing identity and bundle path ownership, permission, symlink, hard-link,
  traversal, corruption, tamper, and atomic rollback protections.

### Fixed

- Clear only the target managed systemd unit's failure counter before restart so rapid legitimate
  profile reconciliation and rollback recover from `StartLimitBurst` exhaustion.

## [0.3.0] - 2026-08-25

### Added

- A production sing-box `CoreProvider` and typed engine separating core, protocol, transport,
  security, and stable connectable profile identities.
- VLESS/TCP/TLS, Trojan/TCP/TLS, and Hysteria2/QUIC/TLS profiles, with multiple profiles served by
  one managed sing-box daemon and no forwarding or NAT ownership for normal proxy profiles.
- Schema-2 profile state with lossless v0.2 schema-1 migration, profile-scoped client credentials,
  and provider/profile-selective provisioning and revocation.
- Unified WireGuard, OpenVPN, and sing-box exports, plus a secret-free capability manifest.
- Managed sing-box CA/server identities, verified pinned sing-box acquisition, doctor/status
  integration, reboot persistence, and TCP/UDP-aware IPv4/IPv6 listener collision checks.

### Changed

- WireGuard, OpenVPN, and sing-box can coexist under the same control plane while retaining
  provider-specific ownership and lifecycle boundaries.

### Security

- Hardened managed path, symlink, and ancestor ownership checks; secure export parents; TLS
  CA/server key pairing; portable DNS/IP identity verification; and fail-closed schema migration.
- Tightened service/config/status convergence, HTTPS redirect validation, and the sing-box systemd
  umask without adopting foreign host state.

## [0.2.0] - 2026-08-25

### Added

- Production OpenVPN UDP provider with FluxGate-owned PKI, certificate revocation and CRL
  enforcement, `tls-crypt`, standalone `.ovpn` exports, and doctor/status integration.
- Provider-independent client identities with explicit per-provider provisioning and revocation,
  plus unified provider-neutral exports.
- Safe simultaneous WireGuard/OpenVPN operation through shared forwarding ownership and
  independently tagged nftables NAT rules.
- Multi-provider rollback, idempotency, v0.1 state compatibility, packaging validation, and
  improved README/project metadata.

### Changed

- `client add` now creates only the identity; `client enable CLIENT PROVIDER` explicitly provisions
  credentials, and `client disable CLIENT PROVIDER` revokes only that provider.
- State schema 1 remains compatible because v0.1 already stored credentials by provider name.

### Fixed

- Added CRL signature/expiry validation and renewal, crash-safe revoke ordering,
  interruption-safe certificate serial handling, and systemd disable postconditions.
- Made unified export reconciliation transactional and protected installer release switching from
  interrupted rollback failures.

## [0.1.1] - 2026-08-25

### Fixed

- Made strict mypy checks portable on Python 3.10 when the conditional `tomli` dependency is
  installed. This patch does not change runtime behavior.

## [0.1.0] - 2026-08-25

### Added

- Modular `CoreProvider` architecture with a capability-based provider registry.
- WireGuard reference provider with idempotent enable/disable and provider-independent client
  creation, export, revocation, and deletion.
- Deterministic tunnel address allocation and private-key handling with restrictive file modes.
- Strict typed configuration and explicitly versioned configuration, state, client, and doctor
  schemas.
- Atomic, locked state persistence, non-mutating dry runs, and rollback-aware host operations.
- systemd service integration, forwarding management, and a FluxGate-owned nftables lifecycle.
- Status and structured doctor commands with safe ownership and collision detection.
- Guarded Ubuntu/Debian installation bootstrap and Python 3.10+ compatibility.
- Unit, regression, strict typing, linting, formatting, and GitHub Actions infrastructure.

### Production-readiness fixes

- Reconciled missing or drifted WireGuard interfaces and validated service postconditions instead
  of trusting systemd state alone.
- Refused to adopt foreign WireGuard interfaces, configurations, commands, or firewall state.
- Hardened partial-failure rollback so pre-existing host networking state is preserved.
- Serialized client mutations and made schema, state, key, export, unit, and nftables ownership
  failures fail closed.

### Not included

- OpenVPN, sing-box, Xray-core, AmneziaWG, Pathfinder, 3x-ui, web management, and later roadmap
  features are not part of FluxGate 0.1.0.
