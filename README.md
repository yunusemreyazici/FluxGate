# FluxGate

FluxGate is a modular multi-transport connectivity server manager. It provides one typed control
plane and CLI for independently implemented VPN and tunnel engines.

FluxGate is **not** a VPN protocol, is not dependent on 3x-ui, and is not a bundle of unrelated
installation shell scripts. Protocol profiles and core implementations are deliberately separate:
for example, a future VLESS profile can be supplied by sing-box or Xray-core without becoming a
new FluxGate daemon.

## Status

FluxGate 0.1 is an early release. WireGuard is the reference implementation. OpenVPN, sing-box,
and Xray-core are registered, visible placeholders that refuse enable operations; they are not
claimed as supported.

Supported server operating systems are Ubuntu 22.04, Ubuntu 24.04, and Debian 12. Python 3.12 or
newer is required. Host changes use apt, systemd, and nftables.

## Architecture

```text
CLI (presentation only)
  └── application services
       ├── typed TOML configuration + atomic JSON state
       ├── provider registry + capability declarations
       │    ├── WireGuard (implemented)
       │    ├── OpenVPN (planned)
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
modes; FluxGate's nftables rules live in their own identifiable table.

## Installation

From a source checkout:

```bash
python3.12 -m venv .venv
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

[cores.singbox]
enabled = false

[cores.xray]
enabled = false
```

Unknown fields and unsupported schema versions are rejected. `FLUXGATE_CONFIG_DIR`,
`FLUXGATE_DATA_DIR`, `FLUXGATE_LOG_DIR`,
`FLUXGATE_WIREGUARD_DIR`, `FLUXGATE_SYSCTL_DIR`, `FLUXGATE_NFTABLES_DIR`, and
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
sudo fluxgate core enable wireguard
sudo fluxgate client add alice
fluxgate client show alice
sudo fluxgate client revoke alice
```

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
`integration` marker and are not part of the normal unit suite.

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
