# Packaging plan

FluxGate's supported installation path remains `scripts/install.sh`. It creates an isolated,
versioned environment under `/opt/fluxgate` because the application manages system packages,
systemd, forwarding, and nftables and therefore needs more operational context than an ordinary
user application.

Wheel and source distributions are built in CI to keep future package-index distribution
straightforward. They retain the Python import package `fluxgate` and the console command
`fluxgate`. The wheel contains only the runtime package and metadata. The source distribution
intentionally includes tests, operational scripts, CI configuration, and project documentation so
a source consumer can reproduce the project gates; the artifact check rejects caches and
secret-like files.

The `fluxgate` distribution name on PyPI belongs to another project and must not be used for a
FluxGate release. Before any future upload, the project metadata distribution name should change
to an available project-specific name such as `fluxgate-vpn`; this does not require renaming the
import package or CLI. Name availability must be checked again immediately before publishing. A
likely eventual user experience is:

```text
pipx install fluxgate-vpn
fluxgate version
```

No package-index upload, name-reservation package, credentials, or publishing workflow is part of
Phase 0.2.
