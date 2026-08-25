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

FluxGate v0.3.0 is the latest stable early-stage release.

**Supported cores/providers:** WireGuard, OpenVPN UDP, and sing-box.

**Supported sing-box profiles in v0.3.0:** VLESS/TCP/TLS, Trojan/TCP/TLS, and
Hysteria2/QUIC/TLS.

**Development:** v0.4 is building Secure Client Bootstrap and the offline Pathfinder Foundation.
It is not released. Xray-core, active network probing/scoring, automatic failover, remote
enrollment, and a web UI remain deferred.

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
CLI (presentation only)
  └── application services
       ├── typed TOML configuration + atomic JSON state
       ├── provider registry + capability declarations
       │    ├── WireGuard (implemented)
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
nftables table, so WireGuard and OpenVPN can coexist safely.

## Development v0.4: signed bootstrap and Pathfinder foundation

The v0.4 development tree adds three separate concepts without changing provider runtime paths:

- `ServerIdentity` is a stable, independent Ed25519 signing identity. Its random opaque server UUID
  and signing key are unrelated to WireGuard, OpenVPN PKI, or the sing-box TLS CA.
- `ClientBootstrap` is an administrator-generated, mode-0700 directory containing public
  `trust.json`, exact-byte signed `manifest.json`, exact-byte signed client-specific
  `bootstrap.json`, and only provider/profile artifacts already provisioned for that client.
- `PathfinderCandidate` and `ClientCapabilities` support deterministic offline compatibility
  evaluation. They distinguish system tunnels from local proxies and report missing capabilities.

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

Initial trust is explicit: an administrator securely transfers the offline bundle and the client
pins its public signing descriptor. Later metadata must be checked with that separately stored pin;
an untrusted neighboring `trust.json` is not a substitute. The signing identity authenticates
metadata from that previously trusted FluxGate identity. It does not prove arbitrary DNS ownership,
replace TLS verification, encrypt bundle contents, or make manifests replay-proof.
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

Pathfinder v0.4 performs no network I/O, probing, latency or loss measurement, scoring, connection
selection, automatic failover, censorship detection, remote manifest fetching, or enrollment.

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
`FLUXGATE_SYSTEMD_DIR` can override paths for isolated development and tests. FluxGate v0.3.0 also
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
sudo fluxgate core enable wireguard
sudo fluxgate core enable openvpn
sudo fluxgate core enable singbox
sudo fluxgate profile create primary-vless --provider singbox --protocol vless \
  --transport tcp --security tls --port 8443
sudo fluxgate profile enable primary-vless
sudo fluxgate client add alice
sudo fluxgate client enable alice wireguard
sudo fluxgate client enable alice openvpn
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
mypy src
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
- **0.4:** secure client bootstrap and offline Pathfinder compatibility foundation (development)
- **0.5:** AmneziaWG and resilience profiles
- **Later:** active Pathfinder probing/scoring/failover, remote enrollment and manifests,
  signing-key rotation and anti-replay, Xray-core, TUIC, WebSocket/HTTP2/gRPC transports, Reality,
  CDN/fronting, censorship detection, GUI/mobile clients, optional 3x-ui integration, and
  multi-node management

No roadmap item is represented as working before it is implemented and tested.

## License

MIT. See [LICENSE](LICENSE).
