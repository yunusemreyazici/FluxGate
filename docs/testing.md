# Testing FluxGate

FluxGate validation is layered so fast, isolated checks and real privileged networking behavior
are both covered.

## Validation layers

1. **Unit and regression tests** exercise configuration, state, provider orchestration, rendering,
   rollback, ownership boundaries, CLI behavior, and host integrations through temporary paths and
   fakes. CI also enforces Ruff formatting and linting plus strict mypy checks.
2. **Privileged Linux lifecycle tests** exercise installation, enablement, idempotency, drift
   reconciliation, client lifecycle, service restart, reboot persistence, disablement, rollback,
   and ownership-safe cleanup on a disposable host.
3. **End-to-end WireGuard client tests** establish a real client tunnel and verify handshake,
   addressing, tunneled IPv4 egress, DNS, server peer counters, reconnect, and revoke enforcement.

## v0.1.0 validation

The v0.1.0 release was validated on an Ubuntu 24.04 VPS with a macOS WireGuard client. The test
covered a real handshake, full-tunnel IPv4 Internet egress, DNS resolution, server-side peer
counters, reconnect after service restart, revoke enforcement, reboot persistence, and
ownership-safe cleanup. Python/runtime compatibility was separately validated for the native
Python floors relevant to Ubuntu 22.04 and Debian 12.

## Full-tunnel revoke safety

Prepare the local WireGuard teardown before revoking an active full-tunnel peer. After confirming
revoke enforcement, immediately run `wg-quick down` (or the platform-equivalent teardown) for the
temporary profile. Otherwise, the test control channel can remain routed through a peer that the
server has correctly revoked.

Never record private keys, client exports, host credentials, or other secret test material in test
output or repository files.
