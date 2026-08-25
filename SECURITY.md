# Security Policy

## Supported versions

FluxGate is pre-1.0. Security fixes are provided for the latest published minor release.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Contact the maintainer privately through
the security-reporting mechanism on the project hosting page. Include the affected version,
reproduction steps, impact, and any suggested mitigation. Avoid including real private keys,
tokens, passwords, server addresses, or client configurations.

## Operational expectations

FluxGate manages privileged networking state. Review a dry-run before enabling a core, keep
`/etc/fluxgate` and `/var/lib/fluxgate` root-owned, restrict backups, and do not copy generated
client exports into logs or issue reports. FluxGate owns only its named nftables table and must not
be granted permission to flush unrelated firewall state.

Commands that mutate host networking, services, packages, firewall rules, forwarding settings, or
credentials require root. FluxGate refuses to adopt foreign WireGuard or OpenVPN configurations,
OpenVPN PKI/assignment directories, interfaces, command links, or nftables state when ownership
cannot be established. It operates only its named systemd instances. Disable and rollback
operations are scoped to FluxGate-owned resources.

Private keys and generated client files are written with mode `0600`. Atomic writers reject
symlink destinations. Operators remain responsible for host updates, SSH access controls, secure
DNS, and safe distribution and revocation of client configurations.

WireGuard and OpenVPN UDP are supported in the v0.2.0 release. sing-box, Xray-core, AmneziaWG,
Pathfinder, and other roadmap integrations remain unsupported.
