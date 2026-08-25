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
3. **End-to-end client tests** establish a real WireGuard/OpenVPN tunnel or an isolated sing-box
   localhost SOCKS proxy and verify protocol
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

## 0.3 development validation

Profile tests cover the explicit protocol/transport/security compatibility table, stable profile
IDs, schema-1 migration, selective provisioning/revocation, transactional exports, the secret-free
manifest, TCP-versus-UDP collision semantics, managed TLS SAN/expiry/modes, deterministic server and
client rendering, service ownership, rollback, and independence from forwarding/nftables. An
optional `SING_BOX_TEST_BINARY` test validates every generated profile with the real pinned upstream
parser.

Real macOS sing-box testing must use a temporary process whose SOCKS inbound binds only
`127.0.0.1`. Send explicit test requests through that proxy; do not install a TUN interface, alter
the default route, or change global DNS. Revoke tests verify a new connection with short timeouts,
then terminate the temporary process and delete only the temporary protected config directory.

For OpenVPN, prepare the exact process/interface teardown before changing routes. Revoke with
strict short timeouts, confirm the session is no longer functional, and immediately stop the
temporary OpenVPN client before any further network-dependent command. Do not import the test
profile into a persistent GUI or modify unrelated VPN profiles.
