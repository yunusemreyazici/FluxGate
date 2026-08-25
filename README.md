# FluxGate

FluxGate is a modular multi-transport connectivity server manager. It provides one typed control
plane and CLI for independently implemented VPN and tunnel engines.

**Project links:** [Repository](https://github.com/yunusemreyazici/FluxGate) ·
[Releases](https://github.com/yunusemreyazici/FluxGate/releases) ·
[Security](https://github.com/yunusemreyazici/FluxGate/security/policy)

FluxGate is **not** a VPN protocol, is not dependent on 3x-ui, and is not a bundle of unrelated
installation shell scripts. Protocol profiles and core implementations are deliberately separate:
for example, a future VLESS profile can be supplied by sing-box or Xray-core without becoming a
new FluxGate daemon.

## Status

FluxGate v0.1.1 is the latest stable early-stage release. The main branch is currently developing
0.2 from that baseline.

**Implemented on the 0.2 development branch:** WireGuard and OpenVPN UDP.

**Planned:** sing-box, Xray-core, AmneziaWG, and later integrations and features. The registered
sing-box and Xray-core entries remain visible placeholders that refuse enable operations.

Supported server operating systems are Ubuntu 22.04, Ubuntu 24.04, and Debian 12. Python 3.10 or
newer is required, allowing FluxGate to use each supported distribution's native Python. Host
changes use apt, systemd, and nftables.

The complete privileged provider lifecycle, service restart, reboot persistence, cleanup, and a
real end-to-end WireGuard client connection were validated on an Ubuntu 24.04 VPS. Python/runtime
compatibility was validated for the native Python floors relevant to Ubuntu 22.04 and Debian 12;
this does not imply that the full privileged lifecycle was exercised on all three distributions.

The 0.2 development implementation has also been validated on Ubuntu 24.04 with simultaneous
WireGuard/OpenVPN operation and a real macOS OpenVPN client. That validation covered TLS and
certificate authentication, assigned address, full-tunnel IPv4 egress, pushed DNS, native
counters, service restart, provider-selective disable, reboot recovery, CRL revoke enforcement,
and cleanup. It is development validation, not a 0.2 release claim.

## Architecture

```text
CLI (presentation only)
  └── application services
       ├── typed TOML configuration + atomic JSON state
       ├── provider registry + capability declarations
       │    ├── WireGuard (implemented)
       │    ├── OpenVPN UDP (implemented)
       │    ├── sing-box (planned)
       │    └── Xray-core (planned)
       └── injected host boundaries
            ├── CommandRunner / apt
            ├── systemd
            ├── nftables
            └── forwarding + filesystem
```

Providers own provider-specific system behavior. The CLI and client service use the registry and
capabilities instead of switching on provider names. Operation plans support dry runs and
best-effort reverse-order rollback. State and secrets use atomic replacement and restrictive file
modes. FluxGate providers hold independent forwarding leases and tagged rules inside one owned
nftables table, so WireGuard and OpenVPN can coexist safely.

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

[cores.xray]
enabled = false
```

Unknown fields and unsupported schema versions are rejected. `FLUXGATE_CONFIG_DIR`,
`FLUXGATE_DATA_DIR`, `FLUXGATE_LOG_DIR`,
`FLUXGATE_WIREGUARD_DIR`, `FLUXGATE_OPENVPN_DIR`, `FLUXGATE_SYSCTL_DIR`,
`FLUXGATE_NFTABLES_DIR`, and
`FLUXGATE_SYSTEMD_DIR` can override paths for isolated development and tests. Values must be
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
sudo fluxgate client add alice
sudo fluxgate client enable alice wireguard
sudo fluxgate client enable alice openvpn
sudo fluxgate client export alice --output ./exports
sudo fluxgate client disable alice openvpn
fluxgate client show alice
sudo fluxgate client revoke alice
```

`client add` creates one provider-independent identity and does not provision every running core.
`client enable` and `client disable` explicitly manage one provider. An export contains one
subdirectory per provisioned provider and never prints credential material to the terminal.

Dry-run lists planned mutation steps and does not write files, install packages, change services,
or alter the firewall.

## State and security model

Human-managed configuration is TOML. Machine state is stored atomically in
`/var/lib/fluxgate/state.json`; private material and generated client configurations live under
`/etc/fluxgate` with restrictive modes. Display names are never primary keys—clients use UUIDs.
Subprocesses use argument arrays without `shell=True`, have timeouts, and redact secret-like
options in logs. See [SECURITY.md](SECURITY.md) for reporting and operational guidance.

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
- **0.3:** sing-box and protocol profiles
- **0.4:** Xray-core and subscription exporters
- **0.5:** AmneziaWG and resilience profiles
- **Later:** optional native Hysteria2, OpenConnect, 3x-ui integration, dashboard, backup/restore,
  multi-node management, and health-based selection

No roadmap item is represented as working before it is implemented and tested.

## License

MIT. See [LICENSE](LICENSE).
