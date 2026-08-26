# FluxGate

FluxGate is a modular multi-transport connectivity server manager. It provides one typed control
plane and CLI for independently implemented VPN and tunnel engines.

**Project links:** [Repository](https://github.com/yunusemreyazici/FluxGate) ·
[Releases](https://github.com/yunusemreyazici/FluxGate/releases) ·
[Security](https://github.com/yunusemreyazici/FluxGate/security/policy) ·
[Testing](docs/testing.md)

FluxGate is **not** a VPN protocol, is not dependent on 3x-ui, and is not a bundle of unrelated
installation shell scripts. Protocol profiles and core implementations are deliberately separate:
for example, a future VLESS profile can be supplied by sing-box or Xray-core without becoming a
new FluxGate daemon.

## Status

FluxGate v0.4.0 is the latest stable early-stage release.

**Supported cores/providers:** WireGuard, OpenVPN UDP, and sing-box.

**v0.5 development:** a first-class AmneziaWG 3.1 provider, immutable resilience-profile
foundation, and the Active Pathfinder decision foundation are under development. The supported
AmneziaWG production design uses the official userspace backend. This work is not part of the
stable v0.4.0 release.

**Supported sing-box profiles:** VLESS/TCP/TLS, Trojan/TCP/TLS, and
Hysteria2/QUIC/TLS.

**Pathfinder compatibility candidates:** WireGuard, AmneziaWG, OpenVPN, VLESS, Trojan, and
Hysteria2.

FluxGate v0.4.0 includes Secure Client Bootstrap and the offline Pathfinder compatibility
foundation. The v0.5 development tree adds authorized bounded probing, observation-based
scoring/ranking, selection, and a non-mutating failover decision policy. Continuous monitoring,
automatic live route/DNS/VPN switching, remote enrollment and manifest retrieval,
anti-replay/freshness policy, signing-key rotation, Xray-core, TUIC, WebSocket/HTTP/2/gRPC,
Reality, and GUI/mobile applications remain deferred.

Supported server operating systems are Ubuntu 22.04, Ubuntu 24.04, and Debian 12. Python 3.10 or
newer is required, allowing FluxGate to use each supported distribution's native Python. Host
changes use apt, systemd, and nftables.

The complete privileged provider lifecycle, service restart, reboot persistence, cleanup, and a
real end-to-end WireGuard client connection were validated on an Ubuntu 24.04 VPS. Python/runtime
compatibility was validated for the native Python floors relevant to Ubuntu 22.04 and Debian 12;
this does not imply that the full privileged lifecycle was exercised on all three distributions.

The v0.2.0 implementation was also validated on Ubuntu 24.04 with simultaneous
WireGuard/OpenVPN operation and a real macOS OpenVPN client. That validation covered TLS and
certificate authentication, assigned address, full-tunnel IPv4 egress, pushed DNS, native
counters, service restart, provider-selective disable, reboot recovery, CRL revoke enforcement,
and cleanup.

The v0.3.0 implementation was privileged-tested on Ubuntu 24.04 with WireGuard, OpenVPN, and
sing-box active together. Real macOS clients validated VLESS/TCP/TLS, Trojan/TCP/TLS, and
Hysteria2/QUIC/TLS, including DNS, IPv4 egress, selective revocation, service restart, and VPS
reboot recovery. Ubuntu 22.04 and Debian 12 remain supported by design and CI/runtime compatibility;
their complete privileged lifecycle has not yet been exercised.

## Architecture

```text
FluxGate Server
├── WireGuard
├── AmneziaWG 3.1 (v0.5 development)
├── OpenVPN
├── sing-box
│   ├── VLESS / TCP / TLS
│   ├── Trojan / TCP / TLS
│   └── Hysteria2 / QUIC / TLS
└── Signed Capability Manifest
    └── Secure Client Bootstrap
        └── Pathfinder Compatibility
            └── Active Pathfinder (v0.5 development)
                ├── Authorized bounded probes
                ├── Explainable scoring + selection
                └── Non-mutating failover decisions
```

```text
CLI (presentation only)
  └── application services
       ├── typed TOML configuration + atomic JSON state
       ├── provider registry + capability declarations
       │    ├── WireGuard (implemented)
       │    ├── AmneziaWG userspace (v0.5 development)
       │    ├── OpenVPN UDP (implemented)
       │    ├── sing-box core (implemented)
       │    │    └── typed VLESS, Trojan, and Hysteria2 profiles
       │    └── Xray-core (planned)
       └── injected host boundaries
            ├── CommandRunner / apt
            ├── systemd
            ├── nftables
            └── forwarding + filesystem
```

**Core != Protocol != Profile.** Core, protocol, transport, security, and connectable profile are
separate concepts. A sing-box profile is an endpoint implemented by the sing-box core; it is not
another core provider. Client
credentials are keyed by stable profile UUID, while WireGuard/OpenVPN credentials remain keyed by
provider. Providers own provider-specific system behavior. The CLI and client service use the
registry and capabilities instead of switching on protocol names. Operation plans support dry runs and
best-effort reverse-order rollback. State and secrets use atomic replacement and restrictive file
modes. FluxGate providers hold independent forwarding leases and tagged rules inside one owned
nftables table, so WireGuard, OpenVPN, and AmneziaWG can coexist safely.

## FluxGate v0.5 development: AmneziaWG 3.1

AmneziaWG is a separate `CoreProvider`, not a WireGuard mode flag. It reuses only compatible
WireGuard-family primitives such as key format and IPv4 address allocation while retaining
independent server/client keys, interface, port, subnet, configuration, service, state, and
provider credentials.

v0.5 targets the reviewed stable AmneziaWG 3.1 generation: `amneziawg-tools`
v3.1.20260812 and `amneziawg-go` v3.1.20260814. The supervised userspace backend is the selected
production path. The kernel backend is explicitly deferred because current upstream build and
netlink compatibility issues have not been resolved across the supported host matrix.

One active resilience profile belongs to the one v0.5 AmneziaWG interface. `standard`, `balanced`,
and `enhanced` are deterministic creation presets only; authoritative schema-versioned state stores
the stable profile UUID and concrete validated parameters. Wire parameters are immutable after
creation because changing them without coordinated client reissue would strand existing exports.
The public signed manifest exposes only the profile identity and AWG 3.1 capability requirement;
concrete parameters remain in protected client configuration. These parameters modify traffic
characteristics and are not a replacement for WireGuard cryptography or a guarantee of network
reachability.

The v0.5 provider has completed privileged lifecycle and isolated real-client validation on Ubuntu
24.04.4 x86_64, including coexistence, DNS and IPv4 egress, selective revoke, service restart, and
reboot recovery. Ubuntu 22.04, Debian 12, arm64, and macOS AWG 3.1 client data paths remain
unvalidated for this provider; the stable release remains v0.4.0 while v0.5 is in development.

## FluxGate v0.4: signed bootstrap and Pathfinder foundation

FluxGate v0.4 adds three separate concepts without changing provider runtime paths:

- `ServerIdentity` is a stable, independent Ed25519 signing identity. Its random opaque server UUID
  and signing key are unrelated to WireGuard, OpenVPN PKI, or the sing-box TLS CA.
- `ClientBootstrap` is an administrator-generated, mode-0700 directory containing public
  `trust.json`, exact-byte signed `manifest.json`, exact-byte signed client-specific
  `bootstrap.json`, and only provider/profile artifacts already provisioned for that client.
- `ConnectionCandidate` and `ClientCapabilities` support deterministic offline compatibility
  evaluation. They distinguish system tunnels from local proxies and report missing capabilities.

The server signing identity is separate from the sing-box TLS identity, WireGuard identity, and
OpenVPN PKI. None of those protocol identities is reused as the FluxGate metadata-signing key.

Example full bundle (physical names use stable UUIDs rather than display names):

```text
client-10000000000000000000000000000001/
├── trust.json
├── manifest.json
├── manifest.sig
├── bootstrap.json
├── bootstrap.sig
├── wireguard/client-10000000000000000000000000000001.conf
├── openvpn/client-10000000000000000000000000000001.ovpn
└── singbox/profile-<profile-id-without-hyphens>.json
```

The public `trust.json` identifies the FluxGate signing key. `manifest.json` is secret-free server
candidate metadata and `manifest.sig` authenticates its exact bytes. The client-specific
`bootstrap.json` describes the bundle, binds the exact manifest digest, and inventories every
provider/profile artifact; `bootstrap.sig` authenticates that exact descriptor. Provider/profile
files contain the actual client credentials.

Physical bundle names use stable opaque client/profile UUIDs rather than display names. Display
names remain signed metadata. This avoids Unicode portability problems, case-insensitive
filesystem collisions, and rename-driven changes to physical artifact identity.

### Initial trust

An administrator explicitly generates and securely transfers a bootstrap bundle containing the
public FluxGate signing trust descriptor. The administrator or client explicitly accepts and pins
that identity through a trusted process.

### Subsequent trust

Later metadata must be verified against the separately stored pin. An adjacent `trust.json` is not
automatically trustworthy. The signing identity authenticates metadata from the pinned FluxGate
identity; it does not prove ownership of an arbitrary DNS hostname, and TLS hostname verification
remains independent. Signing does not encrypt bootstrap contents or make manifests replay-proof.
The signed bootstrap descriptor hashes the exact `manifest.json` bytes so two valid generations
cannot be mixed into one accepted bundle. This is snapshot consistency, not replay prevention.

```bash
sudo fluxgate client bootstrap alice --output ./bootstrap
fluxgate client bootstrap-verify ./bootstrap/client-<client-id-without-hyphens>
fluxgate client bootstrap-verify ./bootstrap/client-<client-id-without-hyphens> \
  --pinned-trust ./pinned/trust.json --json
sudo fluxgate manifest export-signed --output ./signed-manifest
fluxgate manifest verify ./signed-manifest --pinned-trust ./pinned/trust.json
fluxgate pathfinder evaluate --manifest ./signed-manifest/manifest.json \
  --signature ./signed-manifest/manifest.sig --trust ./pinned/trust.json \
  --capabilities examples/capabilities/desktop-full.json --json
```

Provider artifacts contain private keys, certificates, or bearer credentials. Signatures provide
authenticity and integrity, not confidentiality; bootstrap directories must be transferred and
stored as secrets. Revocation prevents future server use but cannot erase a previously copied
static bundle.

Pathfinder v0.4 is a pure compatibility/planning foundation. It accepts signed server candidate
metadata plus client capabilities and returns compatible/incompatible candidates with explicit
rejection reasons. It performs no reachability or DNS/socket probing, latency, packet-loss or
reconnect measurement, performance scoring, ranking, automatic selection, fallback/failover, or
censorship detection.

## Active Pathfinder foundation (v0.5 development)

Active Pathfinder builds on the unchanged pure compatibility engine. It accepts only candidates
from authoritative local FluxGate config/state or an exact-byte signature-verified manifest bound
to separately pinned server trust and independently supplied expected server hostname/IP and
address pins. Every enabled candidate endpoint must equal that authorized server identity,
candidate inventory and address pins are bounded, and transport/IP-family metadata must be
internally consistent, so the subsystem exposes no arbitrary host-list or CIDR scanning interface.

Probe plans are derived from typed candidate capabilities rather than protocol-name branches:

- TCP candidates receive DNS and bounded TCP-connect probes.
- TCP+TLS candidates additionally receive a verified TLS handshake using system trust or an
  explicitly supplied CA bundle.
- UDP/QUIC candidates receive DNS observation only. They remain `unverified`; creating or sending
  on a UDP socket is not treated as application success.
- Incompatible candidates are retained with their compatibility rejection reasons and are not
  probed.

Probe observations are ephemeral and secret-free. Deterministic scoring exposes each point or
penalty component for compatibility, proven DNS/TCP/TLS results, latency, typed failures, and
retries. Selection preserves the full stable ranking and represents the no-verified-candidate case
explicitly. Failover consumes a report plus current runtime context and returns only `stay`,
`switch`, `no_verified_candidate`, or `no_viable_candidate`; the first distinguishes compatible
but unverified UDP/QUIC candidates from failed/incompatible inventory. Failure threshold, minimum
score improvement, and cooldown provide hysteresis. It never changes routes, DNS, provider state,
or client networking.

Active `probe` performs network I/O and is deliberately not called a dry run. The `rank`, `select`,
and `failover` commands consume a saved ephemeral report and perform no network or host mutation:

```bash
fluxgate pathfinder probe --manifest ./signed-manifest/manifest.json \
  --signature ./signed-manifest/manifest.sig --trust ./pinned/trust.json \
  --expected-server vpn.example.test \
  --expected-address 192.0.2.10 \
  --capabilities examples/capabilities/desktop-full.json --json > active-report.json
fluxgate pathfinder rank --report active-report.json
fluxgate pathfinder select --report active-report.json --json
fluxgate pathfinder failover --report active-report.json --current 'profile:<profile-id>' \
  --consecutive-failures 2 --seconds-since-switch 60 --json
```

On the managed server, `sudo fluxgate pathfinder probe --local ...` uses its authoritative local
inventory and the bounded `authorized_server_addresses` list in `[pathfinder.probe]`. A hostname
with TCP/TLS candidates needs at least one independently established IPv4/IPv6 address pin; a
literal-IP server authorizes only that literal automatically. Use `--tls-ca` when a TLS candidate
is anchored by a private CA not present in system trust. A successful generic TCP or TLS probe
proves only the recorded transport/TLS property; it does not prove protocol authentication, VPN
health, censorship resistance, or end-to-end traffic.
WireGuard, AmneziaWG, OpenVPN/UDP, and Hysteria2 remain rankable diagnostics but cannot be selected
until a safe probe produces verified evidence. An inventory containing only those candidates yields
`no_verified_candidate`, not a claim that the compatible transports are broken.

### Safe failover execution foundation (v0.5 development)

A failover decision is still not a live connection switch. FluxGate now has a separate, explicit
client-execution foundation that can turn a typed decision into a deterministic, secret-free
`FailoverExecutionPlan`. The plan identifies the current and target candidates, required adapter,
preconditions, verification contract, rollback target, execution strategy, and whether execution
is supported. Candidate fingerprints bind the full secret-free connection shape to the
authoritative server identity and address authorization. The executor reloads that inventory under
a client-runtime-scoped lock immediately before preparation and rejects missing, disabled,
duplicate, changed, or tampered targets and rollback candidates.

The adapter contract is deliberately not a `CoreProvider`: it models client connection
`prepare -> activate -> verify -> commit`, with rollback and cleanup on failure. Explicit states,
bounded phase timeouts, cancellation, already-converged detection, make-before-break capability,
and prominent rollback/cleanup failures are covered by a deterministic adapter test suite. A
cancellation-unsafe adapter quarantines its execution scope instead of allowing another switch to
race its unfinished work. Active execution and quarantine capacity are process-wide and bounded;
quarantined scopes remain operator-visible until late work has stopped and the runtime has been
explicitly reconciled. Rollback and cleanup ignore later cancellation requests but remain subject
to their phase and total-transaction deadlines.

No real connection adapter is registered in this development foundation. In particular, FluxGate
does not yet launch a sing-box client, switch WireGuard/OpenVPN/AmneziaWG tunnels, alter routes or
DNS, or expose a `pathfinder execute` command. Exported client artifacts alone do not provide the
process ownership, health confirmation, locking, and teardown guarantees required for a safe live
adapter. The framework and its results remain ephemeral; rollback is guaranteed only while the
executor process is alive, not after `SIGKILL` or host failure. Its default lock registry is
process-local, so any future operator-facing real adapter must add the appropriate host/runtime
lock before it can be exposed safely.

Hostname DNS results are intersected with the independently authorized address pins and candidate
IP families before any socket is created. Resolver answers outside that set produce the typed
`destination_unauthorized` outcome and are never connected. Multiple IPv4/IPv6 pins are canonical,
duplicate-free, bounded to 16, and attempted in deterministic numeric order. Private, loopback, and
other special-use addresses remain usable when explicitly pinned; no public/private heuristic is
used. The executor passes only the chosen numeric sockaddr to `connect()`, so there is no second
hostname resolution or DNS-rebinding window. TLS continues to authenticate and send SNI for the
original authorized hostname; literal endpoints use IP SAN verification. This does not make DNS
authenticated—it makes an untrusted answer unable to redirect a TCP probe beyond the authorized
set. Platform resolution remains isolated behind a 32-operation global bound. A timed-out libc
resolver call cannot be force-cancelled by Python; its daemon worker may remain until the OS
resolver returns, capacity then fails closed, and such workers do not delay process exit.

```toml
[pathfinder.probe]
authorized_server_addresses = ["192.0.2.10", "2001:db8::10"]
```

Reports have no credentials and are written only when the operator redirects JSON output. Report
commands validate schema/invariants and recompute default scores from observations, but reports are
not signed and carry no freshness guarantee. Treat an operator-saved report as an untrusted,
point-in-time diagnostic input rather than durable telemetry.

## Installation

From a source checkout, the supported system installation creates an isolated versioned virtual
environment under `/opt/fluxgate`, installs the distribution's `python3-venv` package, and exposes
`/usr/local/bin/fluxgate`:

```bash
sudo ./scripts/install.sh
fluxgate version
```

The installer supports Ubuntu 22.04/24.04 and Debian 12, refuses to overwrite a command it does not
own, and preserves the previous versioned environment for rollback. It does not modify SSH or host
firewall configuration.

For an unprivileged development environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install .
fluxgate version
```

For development, use `pip install -e '.[dev]'`. Importing and testing FluxGate does not require
root. Commands that mutate the default host paths do.

## Configuration

The default configuration is `/etc/fluxgate/config.toml`:

```toml
schema_version = 1

[server]
domain = "vpn.example.com"

[network]
ipv4 = true
ipv6 = true
outbound_interface = "eth0"

[cores.wireguard]
enabled = false
interface = "fg0"
listen_port = 51820
address = "10.77.0.1/24"
client_dns = ["1.1.1.1", "1.0.0.1"]

[cores.amneziawg]
enabled = false
interface = "fgawg0"
listen_port = 51821
address = "10.79.0.1/24"
client_dns = ["1.1.1.1", "1.0.0.1"]
backend = "userspace"

[cores.amneziawg.resilience]
name = "awg-standard"
preset = "standard"

[cores.openvpn]
enabled = false
interface = "fgovpn0"
listen_port = 1194
protocol = "udp"
network = "10.78.0.0/24"
client_dns = ["1.1.1.1", "1.0.0.1"]

[cores.singbox]
enabled = false
binary_source = "managed"

[cores.xray]
enabled = false
```

Unknown fields and unsupported schema versions are rejected. `FLUXGATE_CONFIG_DIR`,
`FLUXGATE_DATA_DIR`, `FLUXGATE_LOG_DIR`,
`FLUXGATE_WIREGUARD_DIR`, `FLUXGATE_OPENVPN_DIR`, `FLUXGATE_SYSCTL_DIR`,
`FLUXGATE_NFTABLES_DIR`, and
`FLUXGATE_SYSTEMD_DIR` can override paths for isolated development and tests. FluxGate also
accepts `FLUXGATE_LOCAL_LIB_DIR` for its versioned managed sing-box binary. Values must be
absolute, traversal-free, and contain no whitespace or control characters.

## CLI examples

```bash
fluxgate version
fluxgate config validate
fluxgate status
fluxgate doctor
fluxgate doctor --json
fluxgate core list
fluxgate core enable wireguard --dry-run
fluxgate core enable openvpn --dry-run
fluxgate core enable amneziawg --dry-run
sudo fluxgate core enable wireguard
sudo fluxgate core enable openvpn
sudo fluxgate core enable singbox
sudo fluxgate core enable amneziawg
sudo fluxgate profile create primary-vless --provider singbox --protocol vless \
  --transport tcp --security tls --port 8443
sudo fluxgate profile enable primary-vless
sudo fluxgate client add alice
sudo fluxgate client enable alice wireguard
sudo fluxgate client enable alice openvpn
sudo fluxgate client enable alice amneziawg
sudo fluxgate client enable alice --profile primary-vless
sudo fluxgate client export alice --output ./exports
sudo fluxgate client export alice --profile primary-vless --output ./exports
fluxgate manifest show
sudo fluxgate client disable alice openvpn
fluxgate client show alice
sudo fluxgate client revoke alice
```

`client add` creates one provider-independent identity and does not provision every running core.
`client enable` and `client disable` explicitly manage one provider or one `--profile`. Provisioning
one sing-box profile never provisions another. An export contains one subdirectory per implementing
provider and never prints credential material to the terminal.

Dry-run lists planned mutation steps and does not write files, install packages, change services,
or alter the firewall.

## State and security model

Human-managed configuration is TOML. Machine state is stored atomically in
`/var/lib/fluxgate/state.json`; private material and generated client configurations live under
`/etc/fluxgate` with restrictive modes. Display names are never primary keys—clients and profiles
use UUIDs. State schema 2 adds profiles and profile-scoped credentials; v0.2 schema-1 state is
migrated losslessly in memory and written atomically as schema 2 on the next mutation. Managed
sing-box TLS uses a private FluxGate CA and a SAN-bearing, versioned server identity. Standalone
client JSON embeds the trust root and never uses `insecure=true`. Exported proxy JSON contains
bearer credentials and must be protected like a VPN private key.
Active Pathfinder reports remain in memory or operator-selected output files and do not change the
persistent state schema. Failover execution plans/results likewise remain ephemeral and no runtime
history or journal is added; persistent state remains schema 2.
Subprocesses use argument arrays without `shell=True`, have timeouts, and redact secret-like
options in logs. See [SECURITY.md](SECURITY.md) for reporting and operational guidance.

Before the first state-changing v0.3.0 command, an upgraded schema-1 installation can still run the
v0.2 application tree. After schema 2 is persisted, v0.2 correctly refuses the future schema; a
downgrade then requires restoring the operator's pre-upgrade state backup rather than pointing the
old application at schema-2 state.

## Development

```bash
ruff format --check .
ruff check .
mypy --strict src
pytest
```

Normal tests use temporary paths and fakes. Privileged Linux integration tests belong under the
`integration` marker and are not part of the normal unit suite. See [Testing](docs/testing.md) for
validation layers and full-tunnel test safety guidance. See [Packaging](docs/packaging.md) for the
future package-index plan; the supported system installer remains the operational installation
path.

## Roadmap

- **0.1:** architecture, CLI, configuration/state, doctor, WireGuard
- **0.2:** OpenVPN and unified client exports
- **0.3:** sing-box and protocol profiles (released)
- **0.4:** secure client bootstrap and offline Pathfinder compatibility foundation (released)
- **0.5:** AmneziaWG 3.1, resilience profiles, the Active Pathfinder decision foundation, and the
  framework-only safe failover execution boundary (development; no real connection adapters)
- **Later:** continuous Pathfinder monitoring and real explicit live-switch adapters, remote
  enrollment and manifests,
  signing-key rotation and anti-replay, Xray-core, TUIC, WebSocket/HTTP2/gRPC transports, Reality,
  CDN/fronting, censorship detection, GUI/mobile clients, optional 3x-ui integration, and
  multi-node management

No roadmap item is represented as working before it is implemented and tested.

## License

MIT. See [LICENSE](LICENSE).
