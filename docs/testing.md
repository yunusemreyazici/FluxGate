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
3. **End-to-end client tests** establish a real WireGuard or OpenVPN tunnel and verify protocol
   authentication, addressing, tunneled IPv4 egress, DNS, server counters/status, reconnect, and
   revoke enforcement.

## v0.1.0 validation

The v0.1.0 release was validated on an Ubuntu 24.04 VPS with a macOS WireGuard client. The test
covered a real handshake, full-tunnel IPv4 Internet egress, DNS resolution, server-side peer
counters, reconnect after service restart, revoke enforcement, reboot persistence, and
ownership-safe cleanup. Python/runtime compatibility was separately validated for the native
Python floors relevant to Ubuntu 22.04 and Debian 12.

## v0.2.0 validation

The OpenVPN implementation was validated on the same authorized Ubuntu 24.04 test host with the
existing WireGuard provider and Bob client preserved. Fresh/idempotent enable, native service and
PKI checks, client provisioning, provider-specific export, independent shared-resource cleanup in
both provider-disable orders, service restart, reboot persistence, ownership collisions, CRL
revocation, and final cleanup passed.

A temporary Homebrew OpenVPN 2.7 client on macOS completed TLS 1.3 authentication, received
10.78.0.2, negotiated AES-256-GCM, used the VPS public IPv4 for full-tunnel egress, applied and
restored pushed DNS, reconnected after service restart and VPS reboot, and was denied after its
certificate was revoked. The temporary profile, process, interface, routes, DNS changes, logs, and
server copies were removed after the test.

## Full-tunnel revoke safety

Prepare the local WireGuard teardown before revoking an active full-tunnel peer. After confirming
revoke enforcement, immediately run `wg-quick down` (or the platform-equivalent teardown) for the
temporary profile. Otherwise, the test control channel can remain routed through a peer that the
server has correctly revoked.

Never record private keys, client exports, host credentials, or other secret test material in test
output or repository files.

For OpenVPN, prepare the exact process/interface teardown before changing routes. Revoke with
strict short timeouts, confirm the session is no longer functional, and immediately stop the
temporary OpenVPN client before any further network-dependent command. Do not import the test
profile into a persistent GUI or modify unrelated VPN profiles.
