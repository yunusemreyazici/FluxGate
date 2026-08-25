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

## v0.3.0 validation

Profile tests cover the explicit protocol/transport/security compatibility table, stable profile
IDs, schema-1 migration, selective provisioning/revocation, transactional exports, the secret-free
manifest, TCP-versus-UDP collision semantics, managed TLS SAN/expiry/modes, deterministic server and
client rendering, service ownership, rollback, and independence from forwarding/nftables. An
optional `SING_BOX_TEST_BINARY` test validates every generated profile with the real pinned upstream
parser.

Privileged Ubuntu 24.04 validation covered clean and idempotent sing-box enablement, managed TLS and
service ownership, multiple profiles in one daemon, doctor/status convergence, IPv4/IPv6 TCP and
UDP listener collision detection, service restart, VPS reboot persistence, and simultaneous
WireGuard/OpenVPN/sing-box operation. Focused Linux/OpenSSL testing reproduced and closed the
managed DNS identity portability issue using authoritative hostname verification.

Temporary macOS sing-box clients completed real VLESS/TCP/TLS, Trojan/TCP/TLS, and
Hysteria2/QUIC/TLS connections through a loopback-only SOCKS inbound. Validation included remote
DNS, public IPv4 egress through the VPS, selective profile revocation, new-session denial after
revocation, service restart recovery, and VPS reboot recovery. No persistent TUN interface or
global macOS route/DNS change was used.

Ubuntu 22.04 and Debian 12 are supported by the installer, native Python floor, and provider design,
and Python 3.10-3.14 is covered by CI. The complete privileged v0.3.0 lifecycle has so far been
exercised on Ubuntu 24.04, not on every supported distribution.

Real macOS sing-box testing must use a temporary process whose SOCKS inbound binds only
`127.0.0.1`. Send explicit test requests through that proxy; do not install a TUN interface, alter
the default route, or change global DNS. Revoke tests verify a new connection with short timeouts,
then terminate the temporary process and delete only the temporary protected config directory.

For OpenVPN, prepare the exact process/interface teardown before changing routes. Revoke with
strict short timeouts, confirm the session is no longer functional, and immediately stop the
temporary OpenVPN client before any further network-dependent command. Do not import the test
profile into a persistent GUI or modify unrelated VPN profiles.

## v0.4 development validation

The new unit suite uses real Ed25519 operations and covers first-use/reuse, exact-byte signatures,
malformed Base64 and schemas, wrong keys and IDs, key mismatch/corruption, unsafe modes, direct and
ancestor links, hard links, first-use races, and non-mutating dry runs. Bootstrap tests cover all
seven WireGuard/OpenVPN/sing-box provider combinations, disabled or unprovisioned credentials,
pinned trust, every signed document and provider artifact tamper, transactional
write/swap/post-verification failures, unmanaged destinations, and simultaneous replacements.
Review regression coverage additionally rejects mixed valid manifest/bootstrap generations,
case-folded paths, empty enabled endpoints, cross-client credential mixing, and unsafe writable
ancestors. Publication failure injection distinguishes exact rollback before parent-directory
fsync from committed-new-tree retention during first or partial stale-backup cleanup failures.
Pathfinder tests are pure and deterministic.

The upstream sing-box v1.13.19 parser gate remains separate: set `SING_BOX_TEST_BINARY` to the
checksum-verified binary and run the full suite. Existing v0.3 production data-path evidence remains
the evidence for real WireGuard, OpenVPN, and sing-box connectivity; v0.4 validation adds signing,
bundle generation, Linux verification, and offline macOS tamper verification without modifying the
Mac default route or DNS.

Focused Ubuntu 24.04 validation created and reused one stable protected signing identity, verified
doctor/status health, signed and pinned a manifest, rejected exact-byte tampering, and atomically
replaced a full temporary bootstrap containing exactly WireGuard, OpenVPN, VLESS, Trojan, and
Hysteria2 artifacts. Both signatures, all hashes, server/key identities, Bob isolation, and cleanup
passed. Rapid profile reconciliation exposed systemd start-limit exhaustion; the scoped
`reset-failed` recovery fix was regression-tested and then passed on the host. Bob, the empty
profile baseline, three running provider services, forwarding, and owned nftables rules were
preserved. A reboot was unnecessary because the identity is durable protected filesystem state and
no v0.4 daemon or boot-time behavior was introduced.

The protected bundle was copied to macOS and verified with its separately pinned trust descriptor.
Disposable changes to the manifest, bootstrap descriptor, a sing-box artifact, the WireGuard
artifact, and bundled trust were each rejected. This test created no tunnel, route, DNS change, or
network probe; all Mac and VPS temporary bundles were deleted afterward.
