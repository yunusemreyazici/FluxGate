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

WireGuard, OpenVPN UDP, and sing-box are supported in v0.4.0. The v0.5 development tree includes
the bounded Active Pathfinder decision foundation described below. Xray-core, TUIC, additional
transports, Reality, automatic live failover, web management, and other roadmap integrations remain
unsupported.

## v0.5 Active Pathfinder security model (development)

Active Pathfinder is not a general scanner. Probe targets originate only from authoritative local
FluxGate config/state or an exact-byte signature-verified manifest bound to separately pinned
server trust and independently supplied expected server hostname/IP and address pins. Central
authorization requires every enabled candidate endpoint to match that server identity, validates
host/IP syntax, ports, closed capability shapes, transport/IP-family consistency, duplicate IDs, a
64-candidate inventory bound, and a 16-address pin bound, and exposes no CIDR or arbitrary
target-list input. Incompatible and disabled candidates are not probed.

For an authorized hostname, platform resolver results are filtered to the candidate's declared IP
families and intersected with a canonical independently authorized IPv4/IPv6 address set before any
socket is created. An answer outside the set returns `destination_unauthorized`; it is never passed
to `connect()`. The chosen numeric sockaddr retains the candidate-authorized port and is connected
directly, so no socket helper performs a second hostname resolution. Private and other special-use
addresses are not categorically rejected because explicitly pinned private FluxGate servers are
supported. TLS verifies the original authorized hostname and uses it for SNI even though transport
connects to a pinned numeric address. A literal endpoint authorizes only itself and retains IP SAN
verification. This boundary does not authenticate DNS; it prevents untrusted DNS from expanding
the independently authorized destination set.

Active probes perform explicit network I/O with bounded concurrency, retries, connect timeouts, and
per-candidate budgets. DNS, TCP connectivity, and verified TLS identity are distinct observations.
UDP/QUIC DNS resolution remains unverified because socket creation or a generic datagram does not
prove reachability or application authentication. A positive TCP/TLS result must not be interpreted
as successful VPN/profile authentication or end-to-end connectivity.

Python cannot cancel a platform `getaddrinfo` call after libc enters the resolver. FluxGate bounds
these calls globally to 32 daemon workers: timed-out calls may remain only until the OS resolver
returns, further resolution fails closed when capacity is exhausted, and resolver workers cannot
delay process shutdown. Socket connect and TLS handshake phases use actual socket deadlines and
explicit closure paths.

Reports contain candidate identifiers, typed outcomes, measured timings, score components, and
decision reasons—not credentials or serialized client/profile objects. Observations and failover
context are ephemeral and do not enter signed public manifests or persistent state. Failover is a
pure decision function and cannot alter routes, DNS, provider lifecycle, or client networking.
Operator-redirected report files are unsigned point-in-time diagnostics without freshness or
anti-replay guarantees; rank/select/failover validate and normalize them but do not persist them.

## v0.5 failover execution foundation security model (development)

`FailoverDecision` remains pure and non-mutating. A separate planner can produce a schema-1,
secret-free execution plan, but an unsigned Active Pathfinder report or serialized plan is never
network authority. Immediately before adapter preparation, the executor reloads an authoritative
candidate inventory and checks the target and any rollback candidate for presence, enabled state,
unique identity, unchanged endpoint/port/capability shape, server identity, authorization source,
and authorized concrete-address set. Those fields are bound by deterministic SHA-256 fingerprints;
credentials are deliberately excluded. Plan integrity is also checked before the inventory rebind.

The `ConnectionExecutionAdapter` boundary represents client runtime activity, not shared server
provider/profile lifecycle. The execution modules do not import provider, profile, firewall, or
forwarding managers. A failed prepare, activation, verification, or commit attempts bounded
rollback and cleanup. Verification is mandatory before commit, rollback failure is a distinct
prominent result, and public reasons never copy adapter exception messages. Execution is
serialized per client-runtime scope within one application process; cancellation-noncompliant adapter
work quarantines that scope and is tracked rather than permitting a racing switch. The registry
bounds active and unfinished work, exposes stable quarantined scope IDs, and permits quarantine
acknowledgement only after late adapter work has stopped; callers must reconcile runtime state
before acknowledging it. Scope entries are released after normal execution instead of accumulating.
Recovery phases defer caller cancellation and remain bounded by both phase-specific timeouts and a
conservative total transaction budget.

The library-level `SingBoxLocalProxyAdapter` is the first real adapter, but no execute command or
automatic failover surface exists. It accepts only a pinned, signature-verified bootstrap whose
exact digest is independently supplied, bound to the expected server, client, profile, manifest
generation, candidate, and artifact digest. It
derives a private ephemeral config rather than accepting arbitrary operator JSON. The remote
sing-box `server` is an independently authorized IP literal, while `tls.server_name` remains the
original authorized hostname, so live DNS cannot expand the remote destination set or weaken
certificate verification. VLESS/TCP/TLS and Trojan/TCP/TLS are supported; Hysteria2 and all tunnel
providers remain unsupported.

The adapter binds only a unique, random-credential-protected `127.0.0.1` SOCKS5 listener, never
routes or DNS, and verifies the owned process plus authenticated SOCKS5 exchange—not end-to-end
traffic. Private configs are mode 0600 inside owned mode-0700 runtime directories, process output
is discarded, and public results never contain child errors or credentials. The exact supported
sing-box 1.13.19 executable must be a safe regular single-link file below non-writable ancestors;
the executable identity and runtime-config digest are rechecked across validation and activation.
An advisory OS lock serializes the runtime scope across
processes. A parent-death guardian inherits that lock and stops the exact child before releasing
it, preventing a crashed owner from opening an overlap window. The sing-box child also inherits
the lock, so an isolated guardian crash fails closed; the owning adapter terminates the exact
dedicated process group on close or before replacement. Normal callers must use the async
adapter lifetime and close it; `SIGKILL` cannot preserve transaction rollback, but the guardian
tears down the already-started child and the next owner reconciles its private stale directory.
Plans and results remain ephemeral and do not enter `FluxGateState`, signed manifests, logs, or
telemetry.
An async adapter that blocks the event-loop thread or permanently ignores task cancellation can
still delay event-loop/process shutdown; such behavior violates the adapter contract and cannot be
made safe by in-process quarantine alone.

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
