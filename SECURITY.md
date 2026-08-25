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

FluxGate includes a FluxGate-owned TLS CA and versioned sing-box server
identity. Its standalone proxy exports embed the public CA but also contain bearer credentials;
store and distribute them as secrets. FluxGate does not reuse the OpenVPN PKI, enable insecure TLS,
or adopt foreign sing-box configuration, units, or TLS directories. The pinned managed binary is
downloaded over HTTPS and accepted only after its official release SHA-256 matches. Managed path
ancestors must not be symlinks or writable by other users. TLS health checks verify CA/server key
pairing, the trust chain, validity, constraints, SAN identity, and restrictive private-file modes.
DNS identities use OpenSSL hostname verification and literal IP identities use OpenSSL IP
verification. Standalone client configurations never set `insecure=true`.

WireGuard, OpenVPN UDP, and sing-box are supported in v0.4.0. Xray-core, TUIC, additional
transports, Reality, active Pathfinder probing, web management, and other roadmap integrations
remain unsupported.

## v0.4 signing and bootstrap model

FluxGate uses Ed25519 from the established `cryptography` implementation for a dedicated server
signing identity. Its server UUID and key are generated independently from cryptographic random
sources. The identity is stored in a FluxGate-owned mode-0700 directory and keeps its raw private
key in a mode-0600 regular file. It is independent of every VPN key and TLS PKI. Unsafe
ownership, modes, symlinks, hard links, corrupt key bytes, or a public/private mismatch fail closed;
FluxGate never silently regenerates a corrupt identity because that would break pinned trust.
Existing protected roots do not hide unsafe writable ancestors; sticky shared temporary-directory
boundaries remain usable while non-sticky group/world-writable ancestors are rejected.

`trust.json` contains only the public key and metadata. Its fingerprint is lowercase SHA-256 over
the canonical 32 raw Ed25519 public-key bytes, prefixed by `sha256:`. Detached envelopes use padded
RFC 4648 standard Base64. Verification authenticates the exact bytes on disk—parsing and
reserializing JSON is deliberately not part of signature verification, so whitespace changes fail.

Initial trust is established only by an administrator securely transferring an explicitly generated
offline bootstrap. Subsequent verification accepts a separately pinned trust descriptor and rejects
replacement of the bundle's adjacent trust file. This pin authenticates a FluxGate signing identity;
it does not prove DNS ownership, and TLS trust remains independent.

`bootstrap.json` signs an inventory whose entries contain SHA-256 hashes of provider artifacts and
the SHA-256 of the exact signed `manifest.json` bytes from the same generation. The latter prevents
mixing two independently valid snapshots, but does not prevent replay of a complete old snapshot.
Bootstrap physical paths are deterministic ASCII UUID-based names; display names remain metadata.
The bundle is atomically published and verified after publication. These controls provide
authenticity, integrity, and tamper detection—not confidentiality. VPN/profile artifacts remain
secrets. The client-identifying descriptor and its detached signature are both mode `0600`; public
manifest, manifest signature, and trust files are mode `0644` inside the mode-`0700` bundle.
Revoking a client cannot delete old exported copies.

Automatic key rotation, remote enrollment, remote manifest delivery, and an anti-replay protocol
are not implemented. A lost signing key requires operator recovery; a future rotation protocol
must authenticate a new key with the old trusted key. `generated_at` supports future freshness
policy but is not an anti-replay guarantee.

## v0.5 AmneziaWG security model (development)

AmneziaWG server and client keypairs are independent from WireGuard keys, the OpenVPN PKI,
sing-box TLS identities, and the FluxGate signing identity. Private keys and complete client
exports are mode-`0600` protected artifacts. Status, doctor, Pathfinder output, public manifests,
logs, command arguments, and exceptions must not expose them.

The v0.5 profile surface intentionally supports only `Jc`, `Jmin`, `Jmax`, `S1`, `S2`, and fixed
unique `H1`-`H4` values. They are coordinated wire-format configuration and are not cryptographic
secrets, but publishing the complete fingerprint is unnecessary. The signed public manifest
therefore carries only the stable profile UUID and the AWG 3.1 capability requirement; concrete
values remain in protected server/client configuration. Profile parameters are immutable after
creation. Header protection, content padding, `S3`/`S4`, custom signatures, timing controls,
random trailers, and cookie controls are deferred pending further upstream interoperability and
security review. Header-protection key material, if supported in the future, will be treated as a
secret and will never enter public metadata.

Managed AmneziaWG tools are pinned to the official v3.1.20260812 release artifact and verified
against GitHub's published SHA-256 digest. The userspace backend is built from the immutable
official v3.1.20260814 commit using a checksum-verified Go 1.25.0 toolchain, read-only Go module
metadata, the Go checksum database, bounded HTTPS downloads, path-safe archives, and isolated build
caches. Upstream does not publish an independent source-archive checksum for that userspace tag;
the immutable commit URL and HTTPS origin are the documented trust boundary. FluxGate refuses
partial or foreign managed binary trees, configurations, units, and interfaces.

The AmneziaWG kernel backend is not automatically selected and is deferred due to current upstream
kernel/toolchain and AWG 3.1 netlink compatibility issues. FluxGate does not patch upstream kernel
networking code, replace foreign modules, install DKMS automatically, or reboot the host. AmneziaWG
changes traffic characteristics and may help on some networks; FluxGate makes no claim that it is
invisible, undetectable, or guaranteed to bypass network controls.
