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

## v0.4.0 validation

### v0.3 data-path evidence

FluxGate v0.4 retains the previously collected real data-path evidence: WireGuard and OpenVPN
full-tunnel connectivity plus VLESS, Trojan, and Hysteria2 proxy connectivity; authentication and
assigned addresses; IPv4 egress and DNS; service restart and reboot persistence; and selective
revocation enforcement. A duplicate full VPN end-to-end run was not required for the v0.4
control/bootstrap-only additions.

### v0.4 control/bootstrap evidence

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
Pathfinder tests are pure, deterministic, and verified to perform no network operations.

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

## v0.5 development validation

Active Pathfinder unit tests cover trusted-local and signature-pinned target authorization,
malformed endpoint and port rejection, capability-derived planning, explicit unsupported UDP
semantics, all-UDP and mixed TCP/UDP inventory behavior, deterministic scoring and tie handling,
preserved alternatives, no-verified/no-viable selection, failure threshold, improvement hysteresis,
cooldown, report normalization/invariants, configuration bounds, and sentinel-secret-free human and
structured CLI output. The executor is injectable, so orchestration, retry, scoring, selection, and
failover policy tests require no network.

Resolved-destination authorization regressions inject authorized, unauthorized, and mixed DNS
answers for IPv4, IPv6, loopback, private, link-local, and metadata-service addresses. They prove
that only independently pinned concrete addresses with the authorized family and port reach socket
creation, that resolver ordering cannot change deterministic selection, and that hostname TLS uses
the original DNS identity after connecting directly to the authorized numeric address. Signed CLI
and local-config tests cover missing, malformed, duplicate, excessive, private, IPv4, and IPv6 pins.

Isolated localhost integration fixtures cover TCP success/refusal/timeout and TLS success,
hostname mismatch, untrusted certificates, and handshake timeout using a runtime-generated test CA.
Literal-IP SAN verification and IPv6 TCP are also exercised. No test connects to a public
third-party endpoint. Concurrency fixtures verify the configured worker bound with forty candidates,
shared retry deadlines, a fast/slow mixture, and the 32-operation global resolver bound and recovery.
Active reports are ephemeral and regression coverage confirms persistent state remains schema 2.

The active foundation proves only its recorded generic observations. It does not establish
application authentication for WireGuard, OpenVPN, VLESS, Trojan, Hysteria2, or AmneziaWG; UDP and
QUIC candidates remain unverified until a safe provider/profile-specific probe exists. The
failover test layer validates decisions only and never changes routes, DNS, provider state, or
client networking.

The safe failover execution foundation is tested separately with a deterministic stateful adapter;
no production network adapter is registered. Tests cover deterministic no-op/ready/unsupported
plans, authoritative target and rollback-candidate rebinding, changed fingerprints, duplicate and
missing targets, plan tampering, mandatory verification, every lifecycle failure, rollback and
cleanup failure, bounded phase timeouts, explicit/task cancellation, already-converged idempotency,
same-scope exclusion, independent-scope progress, and secret-free result JSON/repr/error reasons.
Static import regression coverage prevents the execution layer from acquiring server provider,
profile, nftables, or forwarding lifecycle dependencies. The adapter test performs the actual
transaction calls rather than mocking the executor.

The default execution lock is intentionally process-local because there is no real adapter or CLI
execution surface. Cancellation-cooperative adapter tasks are fully drained in tests. An adapter
that violates cancellation is tracked within a bounded global capacity and its scope is
operator-visible until late work stops and explicit runtime reconciliation is acknowledged. Tests
cover cross-executor quarantine propagation, concurrent violation capacity, bounded lock lifetime,
rollback/cleanup cancellation deferral, and late completion around the timeout cancellation grace.
Real adapter acceptance will also require a host/runtime lock and child-process teardown
integration. Ephemeral rollback is not claimed to survive process or host termination, and an
adapter that blocks the event loop or ignores cancellation forever can delay process shutdown.

Local AWG tests cover typed parameter bounds and deferred-field rejection, deterministic preset
resolution, matching server/client wire parameters, independent credentials and addresses,
first/idempotent enable, disable/re-enable, owned service/config/binary paths, foreign-resource
refusal, dry-run zero side effects, rollback, state-save interruption recovery, selective revoke,
closed signed bootstrap inventory, secret-free manifest metadata, shared forwarding/NAT ownership,
and pinned supply-chain archive/build behavior.

Set `AMNEZIAWG_TEST_BINARY` to the official v3.1.20260812 `awg-quick` executable to enable the
portable real-parser test. Server UAPI parsing and runtime convergence require Linux plus an active
`amneziawg-go` userspace interface and belong in the privileged test layer. Record both the tools
tag and the daemon tag because the selected daemon tag retains an older embedded `--version`
constant; the immutable build provenance marker is authoritative for the exact source revision.

Privileged v0.5 validation passed on Ubuntu 24.04.4 x86_64 with kernel 7.0.0-1011-aws. The host used
the pinned AmneziaWG tools v3.1.20260812 and userspace source v3.1.20260814, with the exact managed
source provenance retained because that daemon tag reports an older embedded version constant.
Validation covered fresh and idempotent enable, official config parsing, `fgawg0` on
`10.79.0.1/24`, UDP 51821, independent client provisioning, a real userspace peer handshake and
RX/TX counters, tunnel addressing, gateway reachability, DNS, VPS-public-IPv4 egress, shared
forwarding/NAT, simultaneous WireGuard/OpenVPN/sing-box operation, selective revoke, service
restart recovery, reboot persistence, and ownership-safe cleanup. Bob and every pre-existing
provider remained intact.

The real client ran in an isolated Linux network namespace on the authorized disposable VPS. No
compatible official macOS AWG 3.1 client was safely automatable, so macOS end-to-end data-path
validation was not executed and no Mac interface, route, or DNS setting was changed. The complete
privileged AmneziaWG lifecycle has not yet been exercised on Ubuntu 22.04, Debian 12, or arm64;
do not claim those provider/platform combinations from the Ubuntu 24.04 x86_64 evidence.

If a compatible official macOS AWG 3.1 client cannot be automated safely, perform only protected
config import/parser validation and report that real E2E was not executed. Before any real tunnel,
record route/DNS state and create teardown first. A full-tunnel revoke test must never revoke the
active control path before its local teardown can execute.
