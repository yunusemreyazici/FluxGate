# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and this project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Typed connectable profiles separating core, protocol, transport, TLS security, endpoint, and
  profile-scoped client credentials.
- FluxGate-owned sing-box core with verified pinned binary acquisition, deterministic validated
  configuration, hardened systemd service, managed SAN-bearing TLS, and health checks.
- VLESS/TCP/TLS, Trojan/TCP/TLS, and Hysteria2/QUIC/TLS server/client configurations.
- Profile lifecycle/provisioning CLI, unified and individual profile exports, and a secret-free
  capability manifest.

### Changed

- State schema 2 adds stable profile records and profile credentials while losslessly accepting
  v0.2 schema-1 WireGuard/OpenVPN state.

### Fixed

- Made schema-1 migration reject schema-2-only fields instead of silently discarding corrupt
  data, and made status fail closed on sing-box service, TLS, unit, or config divergence.
- Refused writable or symlinked managed ancestors before filesystem mutation, verified CA/server
  key pairing and CA constraints, enforced HTTPS across release redirects, and hardened the
  sing-box service umask.

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
