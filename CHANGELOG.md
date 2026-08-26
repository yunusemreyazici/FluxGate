# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and this project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Safe Failover Execution Foundation

- Added the first real library execution adapter for eligible VLESS/TCP/TLS and Trojan/TCP/TLS
  candidates. It runs an owned sing-box child behind a unique authenticated loopback SOCKS5
  listener without
  changing system routes, DNS, providers, profiles, firewall, or forwarding.
- Bound private runtime credentials to pinned signature-verified bootstrap artifacts and bound the
  live sing-box remote to an independently authorized IP literal while preserving the original TLS
  hostname/SNI. Arbitrary configs, Hysteria2, and tunnel-provider candidates remain unsupported.
- Added private ephemeral configs, exact bootstrap-generation and sing-box 1.13.19 binary/config
  validation, bounded port-race fallback, authenticated SOCKS5 verification, make-before-break
  replacement, idempotency, OS advisory scope locking, exact-child teardown, and a parent-death
  guardian that retains the lock through cleanup.
- Added controlled fake-binary subprocess, cross-process, crash, cancellation, privacy, bootstrap
  tampering, DNS destination-binding, symlink, port collision, and rollback regressions. No execute
  CLI or automatic failover daemon is exposed.

- Added deterministic secret-free execution plans that bind current/target connection candidates
  to authoritative inventory fingerprints and declare adapter, verification, rollback, strategy,
  preconditions, support, and unsupported reasons without performing mutation.
- Added a separate client connection adapter contract and transactional executor with immediate
  authoritative rebinding, stale/tampered decision rejection, per-runtime locking, bounded phases,
  explicit verification, idempotent convergence, cancellation, rollback, cleanup, and typed
  results. It has no dependency on server provider/profile/firewall/forwarding lifecycle APIs.
- Hardened transaction result invariants, successful-cleanup terminal state, current-candidate
  rebinding, total phase budgeting, cross-executor lock lifetime, bounded cancellation quarantine,
  recovery cancellation deferral, and operator-visible quarantine reconciliation.
- Added a deterministic stateful test adapter and failure, timeout, cancellation, concurrency,
  rollback, cleanup, stale-inventory, plan-integrity, schema-v2, and sentinel-secret regressions.
  No execute CLI is exposed; system-wide live connection switching remains deferred.

### Active Pathfinder Foundation

- Added a capability-driven active layer that preserves the pure offline compatibility engine and
  separates authorized inventory, probe planning/execution, ephemeral observations, deterministic
  scoring, stable selection, and failover policy.
- Added bounded DNS, TCP-connect, and verified TLS-handshake probes with typed failure outcomes,
  retry and candidate budgets, bounded parallelism, and conservative unverified semantics for
  UDP/QUIC candidates without a safe generic application probe.
- Restricted active targets to authoritative local inventory or exact-byte signature-verified
  manifests bound to pinned server trust plus independent expected-server and concrete-address
  pins, with centralized endpoint/capability validation, bounded inventory/address sets and
  resolution, pre-connect DNS-result intersection, and no arbitrary target-list or CIDR interface.
- Added explainable score components, preserved alternatives, distinct no-verified/no-viable
  selection states, and a pure failover decision using failure threshold, minimum improvement, and
  cooldown without modifying routes, DNS, providers, or client networking.
- Added `pathfinder probe`, `rank`, `select`, and `failover` operator commands with secret-free JSON
  output, plus localhost TCP/TLS integration coverage and network-free scoring/selection/failover
  tests. Probe observations remain ephemeral and persistent state remains schema 2.

### AmneziaWG 3.1 Foundation

- Added a first-class AmneziaWG `CoreProvider` using the pinned official userspace backend, an
  owned supervised systemd lifecycle, independent WireGuard-family keys/credentials, and
  provider-scoped client provisioning, export, and selective revoke.
- Added schema-versioned immutable resilience profiles with deterministic `standard`, `balanced`,
  and `enhanced` creation presets backed by a reviewed typed AWG 3.1 parameter subset.
- Integrated AmneziaWG with shared forwarding and nftables NAT leases, doctor/status, signed
  bootstrap artifact inventory, secret-free capability manifests, and generic offline Pathfinder
  compatibility requirements.
- Added pinned supply-chain acquisition/build controls, real-parser test hooks, ownership and
  failure rollback tests, state-interruption reconciliation, and cross-provider isolation coverage.
- Fixed official-parser validation failures caused by interface-length-unsafe temporary names,
  userspace startup races by waiting for the managed UAPI socket without a shell loop, and service
  restart interference with foreign AmneziaWG interfaces by not claiming the upstream shared
  runtime directory.
- Preserved the executable bit, while stripping broader archive permissions, when safely extracting
  the pinned Go toolchain used for the userspace build.
- Made selective revoke converge safely after an interrupted state save without retaining client
  artifacts or a live peer.

The project version remains 0.4.0 while v0.5 is in development.

## [0.4.0] - 2026-08-26

### Secure Client Bootstrap

- Added an independent Ed25519 FluxGate signing identity with a stable opaque server UUID, public
  trust descriptor, and explicit pinned-public-key verification.
- Added exact-byte signed capability manifests, detached Ed25519 signatures, and signed
  client-specific bootstrap descriptors.
- Added per-artifact SHA-256 verification and an exact bootstrap-to-manifest digest binding that
  prevents mixing otherwise valid signed generations inside one bundle.
- Added WireGuard, OpenVPN, and sing-box multi-provider client bundles with closed inventories and
  cross-client credential isolation.
- Added transactional whole-directory publication and deterministic ASCII-safe UUID-based
  physical artifact names while retaining display names as metadata.

### Pathfinder Foundation

- Added typed `ConnectionCandidate` and `ClientCapabilities` models with explicit
  `SYSTEM_TUNNEL` and `LOCAL_PROXY` modes.
- Added provider-independent capability requirements, deterministic compatibility evaluation, and
  human-readable incompatibility reasons.
- Added candidates for WireGuard, OpenVPN, VLESS/TCP/TLS, Trojan/TCP/TLS, and
  Hysteria2/QUIC/TLS.

### Hardening

- Established an explicit durable publication commit boundary; stale-backup cleanup can no longer
  destroy or roll back a committed replacement.
- Added Unicode- and case-insensitive-filesystem-safe bootstrap naming, case-folded collision
  rejection, exact generation-mixing rejection, and closed artifact inventory enforcement.
- Added enabled-candidate endpoint validation, corrupt signing-identity status aggregation, and
  writable-ancestor, symlink, hard-link, file-type, permission, and ownership checks.
- Cleared only the target managed systemd unit's failure counter before restart so rapid legitimate
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
