# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and this project uses
[Semantic Versioning](https://semver.org/).

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
