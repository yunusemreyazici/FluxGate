from __future__ import annotations

import stat
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

import fluxgate.clients.service as client_service_module
import fluxgate.providers.openvpn.pki as pki_module
import fluxgate.providers.openvpn.provider as provider_module
from fluxgate.clients import ClientService
from fluxgate.core.commands import CommandResult, CommandRunner
from fluxgate.core.errors import FluxGateError, ProviderError
from fluxgate.core.models import HealthLevel, ProviderDetection, ProviderStateName
from fluxgate.core.registry import ProviderRegistry
from fluxgate.providers.openvpn import OpenVPNProvider
from fluxgate.providers.wireguard import WireGuardProvider

PEM = "-----BEGIN {label}-----\nfluxgate-test\n-----END {label}-----\n"


class FakeOpenSSLRunner(CommandRunner):
    """Create structurally valid fake PKI files without invoking host tools."""

    def __init__(self) -> None:
        super().__init__()
        self.commands: list[tuple[str, ...]] = []
        self.wireguard_key = 0
        self.crl_expiring = False

    @staticmethod
    def _option(command: tuple[str, ...], option: str) -> Path:
        return Path(command[command.index(option) + 1])

    @staticmethod
    def _write(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def run(
        self,
        args: Sequence[str],
        *,
        input_text: str | None = None,
        timeout: float | None = None,
        check: bool = True,
        mutate: bool = False,
        environment: Mapping[str, str] | None = None,
    ) -> CommandResult:
        del timeout, check, mutate, environment
        command = tuple(args)
        self.commands.append(command)
        if command[:4] == ("ip", "link", "show", "dev"):
            return CommandResult(command, 0 if command[-1] == "eth0" else 1)
        if command == ("wg", "genkey"):
            self.wireguard_key += 1
            return CommandResult(command, 0, f"private-{self.wireguard_key}\n")
        if command == ("wg", "pubkey"):
            return CommandResult(command, 0, f"public-{self.wireguard_key}\n")
        if command[:2] == ("openssl", "genpkey"):
            self._write(self._option(command, "-out"), PEM.format(label="PRIVATE KEY"))
        elif command[:2] == ("openssl", "req"):
            label = "CERTIFICATE" if "-x509" in command else "CERTIFICATE REQUEST"
            subject = command[command.index("-subj") + 1]
            self._write(
                self._option(command, "-out"),
                PEM.format(label=label) + f"SUBJECT:{subject}\n",
            )
        elif command[:2] == ("openvpn", "--genkey"):
            self._write(
                Path(command[-1]),
                "#\n# OpenVPN static key\n#\n" + PEM.format(label="OpenVPN Static key V1"),
            )
        elif command[:2] == ("openssl", "ca") and "-extensions" in command:
            root = self._option(command, "-config").parent
            serial_path = root / "serial"
            serial = serial_path.read_text().strip()
            certificate = self._option(command, "-out")
            request = self._option(command, "-in").read_text()
            self._write(
                certificate,
                PEM.format(label="CERTIFICATE") + f"SERIAL:{serial}\n{request}",
            )
            self._write(root / "newcerts" / f"{serial}.pem", certificate.read_text())
            with (root / "index.txt").open("a") as index:
                index.write(f"V\tnever\t\t{serial}\tunknown\t/CN=fluxgate\n")
            serial_path.write_text(f"{int(serial, 16) + 1:X}\n")
        elif command[:2] == ("openssl", "ca") and "-revoke" in command:
            root = self._option(command, "-config").parent
            certificate = self._option(command, "-revoke").read_text()
            serial = certificate.split("SERIAL:", 1)[1].splitlines()[0]
            lines = (root / "index.txt").read_text().splitlines()
            rewritten = []
            for line in lines:
                fields = line.split("\t")
                if len(fields) >= 4 and fields[3] == serial:
                    fields[0] = "R"
                    line = "\t".join(fields)
                rewritten.append(line)
            (root / "index.txt").write_text("\n".join(rewritten) + "\n")
        elif command[:2] == ("openssl", "ca") and "-gencrl" in command:
            root = self._option(command, "-config").parent
            index = (root / "index.txt").read_text()
            self._write(
                self._option(command, "-out"),
                PEM.format(label="X509 CRL") + f"INDEX:{index}",
            )
            self.crl_expiring = False
        elif command[:2] == ("openssl", "x509") and "-serial" in command:
            certificate = self._option(command, "-in").read_text()
            serial = certificate.split("SERIAL:", 1)[1].splitlines()[0]
            return CommandResult(command, 0, f"serial={serial}\n")
        elif command[:2] == ("openssl", "x509") and "-checkend" in command:
            return CommandResult(command, 0)
        elif command[:2] == ("openssl", "crl"):
            next_update = (
                "Aug 26 00:00:00 2026 GMT" if self.crl_expiring else "Aug 25 00:00:00 2035 GMT"
            )
            return CommandResult(command, 0, f"nextUpdate={next_update}\n")
        return CommandResult(command, 0, input_text or "")


def available_openvpn() -> ProviderDetection:
    return ProviderDetection(
        available=True,
        binaries={"openvpn": True, "openssl": True, "nft": True},
    )


def available_wireguard() -> ProviderDetection:
    return ProviderDetection(
        available=True,
        binaries={"wg": True, "wg-quick": True, "nft": True},
    )


@pytest.fixture
def openvpn(provider_context, monkeypatch) -> OpenVPNProvider:
    provider_context.runner = FakeOpenSSLRunner()
    provider = OpenVPNProvider(provider_context)
    monkeypatch.setattr(provider, "detect", available_openvpn)
    return provider


def test_enable_is_idempotent_and_renders_secure_owned_configuration(
    openvpn: OpenVPNProvider,
) -> None:
    first = openvpn.enable()
    second = openvpn.enable()
    assert first.changed
    assert not second.changed
    assert openvpn.status().state == ProviderStateName.RUNNING
    config = openvpn.config_path.read_text()
    assert config.startswith("# Managed by FluxGate;")
    assert "proto udp" in config
    assert "dev fgovpn0\ndev-type tun" in config
    assert "server 10.78.0.0 255.255.255.0" in config
    assert "verify-client-cert require" in config
    assert "tls-version-min 1.2" in config
    assert "crl-verify " in config
    assert "redirect-gateway def1" in config
    assert stat.S_IMODE(openvpn.config_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(openvpn.pki.server_key_path.stat().st_mode) == 0o600
    assert openvpn.context.forwarding.consumers == {"openvpn"}
    assert set(openvpn.context.firewall.rules) == {"openvpn"}


def test_disable_and_reenable_preserve_pki_and_are_idempotent(
    openvpn: OpenVPNProvider,
) -> None:
    openvpn.enable()
    ca = openvpn.pki.ca_certificate_path.read_bytes()
    assert openvpn.disable().changed
    assert not openvpn.disable().changed
    assert not openvpn.context.services.is_active(openvpn.unit)
    assert not openvpn.context.firewall.managed("openvpn")
    assert not openvpn.context.forwarding.configured("openvpn")
    assert openvpn.pki.ca_certificate_path.read_bytes() == ca
    assert openvpn.enable().changed
    assert openvpn.pki.ca_certificate_path.read_bytes() == ca


def test_enable_repairs_owned_config_drift_without_rotating_ca(
    openvpn: OpenVPNProvider,
) -> None:
    openvpn.enable()
    ca = openvpn.pki.ca_certificate_path.read_bytes()
    openvpn.config_path.write_text(
        openvpn.config_path.read_text().replace("port 1194", "port 9999")
    )
    assert openvpn.enable().changed
    assert "port 1194" in openvpn.config_path.read_text()
    assert openvpn.pki.ca_certificate_path.read_bytes() == ca
    assert f"restart:{openvpn.unit}" in openvpn.context.services.events


def test_enable_refuses_unmanaged_configuration_pki_and_port_collision(
    openvpn: OpenVPNProvider,
) -> None:
    openvpn.config_path.parent.mkdir(parents=True)
    openvpn.config_path.write_text("port 443\n")
    with pytest.raises(ProviderError, match="unmanaged OpenVPN configuration"):
        openvpn.enable()
    openvpn.config_path.unlink()
    openvpn.pki.root.mkdir(parents=True)
    (openvpn.pki.root / "foreign.key").write_text("foreign")
    with pytest.raises(ProviderError, match="unmanaged OpenVPN PKI"):
        openvpn.enable()
    (openvpn.pki.root / "foreign.key").unlink()
    openvpn.pki.root.rmdir()
    openvpn.context.network.occupied_ports.add(1194)
    with pytest.raises(ProviderError, match="listen port is already in use"):
        openvpn.enable()


def test_enable_refuses_orphaned_or_missing_client_secret_state(
    openvpn: OpenVPNProvider,
) -> None:
    orphan = openvpn.context.paths.clients_dir / "orphan.openvpn.ovpn"
    orphan.parent.mkdir(parents=True)
    orphan.write_text("orphan")
    with pytest.raises(ProviderError, match="client files do not match state"):
        openvpn.enable()
    orphan.unlink()
    openvpn.enable()
    service = ClientService(openvpn.context.state, ProviderRegistry([openvpn]))
    service.add("alice")
    client = service.enable_provider("alice", "openvpn")
    openvpn._client_private_path(client).unlink()
    with pytest.raises(ProviderError, match="client files do not match state"):
        openvpn.enable()


def test_failed_live_postcondition_rolls_back_every_owned_enable_mutation(
    openvpn: OpenVPNProvider, monkeypatch
) -> None:
    monkeypatch.setattr(openvpn.context.network, "udp_listener_present", lambda port: False)
    with pytest.raises(FluxGateError, match="without its interface and UDP listener"):
        openvpn.enable()
    assert not openvpn.context.state.exists
    assert not openvpn.config_path.exists()
    assert not openvpn.pki.root.exists()
    assert not openvpn.ccd_dir.exists()
    assert not openvpn.crl_path.exists()
    assert not openvpn.context.services.is_active(openvpn.unit)
    assert not openvpn.context.firewall.managed("openvpn")
    assert not openvpn.context.forwarding.configured("openvpn")


def test_pki_commit_failure_removes_partial_initialization(
    openvpn: OpenVPNProvider, monkeypatch
) -> None:
    real_atomic_write = pki_module.atomic_write
    failed = False

    def fail_serial(path: Path, content: bytes, mode: int = 0o600) -> None:
        nonlocal failed
        if path == openvpn.pki.root / "serial" and not failed:
            failed = True
            raise OSError("injected PKI commit failure")
        real_atomic_write(path, content, mode)

    monkeypatch.setattr(pki_module, "atomic_write", fail_serial)
    with pytest.raises(OSError, match="injected PKI commit failure"):
        openvpn.pki.ensure(has_clients=False)
    assert not openvpn.pki.root.exists()


@pytest.mark.parametrize("failure_target", ["ccd", "crl"])
def test_partial_multifile_enable_step_restores_its_own_artifacts(
    openvpn: OpenVPNProvider, monkeypatch, failure_target: str
) -> None:
    real_atomic_write = provider_module.atomic_write
    failed = False

    def fail_once(path: Path, content: bytes, mode: int = 0o600) -> None:
        nonlocal failed
        target = openvpn.ccd_marker if failure_target == "ccd" else openvpn.crl_marker
        if path == target and not failed:
            failed = True
            raise OSError(f"injected {failure_target} write failure")
        real_atomic_write(path, content, mode)

    monkeypatch.setattr(provider_module, "atomic_write", fail_once)
    with pytest.raises(FluxGateError, match=f"injected {failure_target} write failure"):
        openvpn.enable()
    assert not openvpn.ccd_dir.exists()
    assert not openvpn.crl_path.exists()
    assert not openvpn.crl_marker.exists()
    assert not openvpn.pki.root.exists()


def test_client_provision_export_and_crl_enforced_revoke(openvpn: OpenVPNProvider) -> None:
    openvpn.enable()
    service = ClientService(openvpn.context.state, ProviderRegistry([openvpn]))
    identity = service.add("alice")
    client = service.enable_provider("alice", "openvpn")
    assert identity.id == client.id
    assert client.provider_credentials["openvpn"]["address"] == "10.78.0.2"
    profile = openvpn.export_client(client)[0].content
    assert "remote vpn.example.com 1194" in profile
    assert "<ca>" in profile and "<cert>" in profile and "<key>" in profile
    assert "tls-version-min 1.2" in profile
    assert "cipher AES-256-GCM" in profile
    private_path = openvpn.context.paths.secrets_dir / "clients" / f"{client.id}.openvpn.key"
    certificate_path = openvpn.context.paths.secrets_dir / "clients" / f"{client.id}.openvpn.crt"
    export_path = openvpn.context.paths.clients_dir / f"{client.id}.openvpn.ovpn"
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o600
        for path in (private_path, certificate_path, export_path)
    )
    assert stat.S_IMODE(openvpn._client_ccd_path(client).stat().st_mode) == 0o644
    assert stat.S_IMODE(openvpn.ccd_dir.stat().st_mode) == 0o755
    crl_before = openvpn.crl_path.read_bytes()
    service.disable_provider("alice", "openvpn")
    assert openvpn.crl_path.read_bytes() != crl_before
    assert not any(path.exists() for path in (private_path, certificate_path, export_path))
    assert not openvpn._client_ccd_path(client).exists()
    assert not service.find("alice").enabled
    assert f"restart:{openvpn.unit}" in openvpn.context.services.events


def test_client_state_save_failure_revokes_and_removes_generated_artifacts(
    openvpn: OpenVPNProvider, monkeypatch
) -> None:
    openvpn.enable()
    service = ClientService(openvpn.context.state, ProviderRegistry([openvpn]))
    client = service.add("alice")
    real_save = openvpn.context.state.save
    save_calls = 0

    def fail_once(state) -> None:
        nonlocal save_calls
        save_calls += 1
        if save_calls == 1:
            raise RuntimeError("injected client state save failure")
        real_save(state)

    monkeypatch.setattr(openvpn.context.state, "save", fail_once)
    with pytest.raises(RuntimeError, match="injected client state save failure"):
        service.enable_provider("alice", "openvpn")
    stored = service.find("alice")
    assert stored.provider_credentials == {}
    assert not openvpn._client_private_path(client).exists()
    assert not openvpn._client_certificate_path(client).exists()
    assert not openvpn._client_export_path(client).exists()
    assert not any(path != openvpn.ccd_marker for path in openvpn.ccd_dir.iterdir())


def test_revoke_state_save_failure_is_safely_retryable(
    openvpn: OpenVPNProvider, monkeypatch
) -> None:
    openvpn.enable()
    service = ClientService(openvpn.context.state, ProviderRegistry([openvpn]))
    service.add("alice")
    client = service.enable_provider("alice", "openvpn")
    real_save = openvpn.context.state.save

    def fail_save(state) -> None:
        raise RuntimeError("injected post-revoke state failure")

    monkeypatch.setattr(openvpn.context.state, "save", fail_save)
    with pytest.raises(FluxGateError, match="was revoked but state update failed"):
        service.disable_provider("alice", "openvpn")
    assert "openvpn" in service.find("alice").provider_credentials
    assert openvpn.pki.serial_revoked(str(client.provider_credentials["openvpn"]["serial"]))
    assert not openvpn._client_private_path(client).exists()

    monkeypatch.setattr(openvpn.context.state, "save", real_save)
    reconciled = service.disable_provider("alice", "openvpn")
    assert not reconciled.provider_credentials
    assert not service.find("alice").enabled


def test_enable_refreshes_a_crl_near_expiry(openvpn: OpenVPNProvider) -> None:
    openvpn.enable()
    runner = openvpn.context.runner
    assert isinstance(runner, FakeOpenSSLRunner)
    runner.crl_expiring = True
    before = len([command for command in runner.commands if "-gencrl" in command])
    assert openvpn.enable().changed
    after = len([command for command in runner.commands if "-gencrl" in command])
    assert after == before + 1
    assert any(
        "-verify" in command and "-nextupdate" in command
        for command in runner.commands
        if command[:2] == ("openssl", "crl")
    )
    assert any(
        command[command.index("-crldays") + 1] == "825"
        for command in runner.commands
        if "-gencrl" in command
    )


def test_revoke_pki_failure_restores_client_state_and_artifacts(
    openvpn: OpenVPNProvider, monkeypatch
) -> None:
    openvpn.enable()
    service = ClientService(openvpn.context.state, ProviderRegistry([openvpn]))
    service.add("alice")
    client = service.enable_provider("alice", "openvpn")
    index_before = openvpn.pki.root.joinpath("index.txt").read_bytes()
    real_atomic_write = pki_module.atomic_write
    failed = False

    def fail_index(path: Path, content: bytes, mode: int = 0o600) -> None:
        nonlocal failed
        if path == openvpn.pki.root / "index.txt" and not failed:
            failed = True
            raise OSError("injected revoke database failure")
        real_atomic_write(path, content, mode)

    monkeypatch.setattr(pki_module, "atomic_write", fail_index)
    with pytest.raises(FluxGateError, match="injected revoke database failure"):
        service.disable_provider("alice", "openvpn")
    assert "openvpn" in service.find("alice").provider_credentials
    assert openvpn.pki.root.joinpath("index.txt").read_bytes() == index_before
    assert openvpn._client_private_path(client).exists()
    assert openvpn._client_certificate_path(client).exists()


@pytest.mark.parametrize("first", ["wireguard", "openvpn"])
def test_provider_coexistence_and_independent_shared_cleanup(
    provider_context, monkeypatch, first: str
) -> None:
    provider_context.runner = FakeOpenSSLRunner()
    wireguard = WireGuardProvider(provider_context)
    openvpn = OpenVPNProvider(provider_context)
    monkeypatch.setattr(wireguard, "detect", available_wireguard)
    monkeypatch.setattr(openvpn, "detect", available_openvpn)
    providers = {"wireguard": wireguard, "openvpn": openvpn}
    second = "openvpn" if first == "wireguard" else "wireguard"
    providers[first].enable()
    providers[second].enable()
    assert provider_context.forwarding.consumers == {"wireguard", "openvpn"}
    assert set(provider_context.firewall.rules) == {"wireguard", "openvpn"}
    providers[first].disable()
    assert provider_context.forwarding.consumers == {second}
    assert set(provider_context.firewall.rules) == {second}
    assert providers[second].status().state == ProviderStateName.RUNNING


def test_one_identity_supports_both_providers_selective_revoke_and_unified_export(
    provider_context, monkeypatch, tmp_path: Path
) -> None:
    provider_context.runner = FakeOpenSSLRunner()
    wireguard = WireGuardProvider(provider_context)
    openvpn = OpenVPNProvider(provider_context)
    monkeypatch.setattr(wireguard, "detect", available_wireguard)
    monkeypatch.setattr(openvpn, "detect", available_openvpn)
    wireguard.enable()
    openvpn.enable()
    service = ClientService(provider_context.state, ProviderRegistry([wireguard, openvpn]))
    client = service.add("iphone")
    assert not client.enabled and client.provider_credentials == {}
    service.enable_provider("iphone", "wireguard")
    client = service.enable_provider("iphone", "openvpn")
    assert set(client.provider_credentials) == {"wireguard", "openvpn"}
    output = tmp_path / "exports"
    written = service.export("iphone", output)
    assert {path.relative_to(output).as_posix() for path in written} == {
        "iphone/openvpn/iphone.ovpn",
        "iphone/wireguard/iphone.conf",
    }
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in written)
    assert stat.S_IMODE((output / "iphone").stat().st_mode) == 0o700
    assert service.export("iphone", output) == written

    outside = tmp_path / "outside"
    outside.mkdir()
    symlinked_output = tmp_path / "symlinked-output"
    symlinked_output.symlink_to(outside, target_is_directory=True)
    with pytest.raises(FluxGateError, match="symlinked directory"):
        service.export("iphone", symlinked_output)
    assert not (outside / "iphone").exists()

    openvpn_export = output / "iphone" / "openvpn" / "iphone.ovpn"
    openvpn_export.write_text("preexisting export\n")
    openvpn_export.chmod(0o600)
    real_atomic_write = client_service_module.atomic_write
    failed = False

    def fail_wireguard_export(path: Path, content: bytes, mode: int = 0o600) -> None:
        nonlocal failed
        if path.name == "iphone.conf" and not failed:
            failed = True
            raise OSError("injected export failure")
        real_atomic_write(path, content, mode)

    monkeypatch.setattr(client_service_module, "atomic_write", fail_wireguard_export)
    with pytest.raises(OSError, match="injected export failure"):
        service.export("iphone", output)
    assert openvpn_export.read_text() == "preexisting export\n"

    service.disable_provider("iphone", "wireguard")
    remaining = service.find("iphone")
    assert remaining.enabled
    assert set(remaining.provider_credentials) == {"openvpn"}
    assert openvpn.client_artifacts_valid()
    service.export("iphone", output)
    assert not (output / "iphone" / "wireguard").exists()
    service.enable_provider("iphone", "wireguard")
    service.disable_provider("iphone", "openvpn")
    remaining = service.find("iphone")
    assert set(remaining.provider_credentials) == {"wireguard"}
    assert "# Client iphone" in wireguard.config_path.read_text()
    deleted = service.delete("iphone")
    assert deleted == client.id
    assert service.list() == []
    assert not list(provider_context.paths.clients_dir.glob(f"{client.id}.*"))
    assert not list((provider_context.paths.secrets_dir / "clients").glob(f"{client.id}.*"))


def test_doctor_contribution_detects_drift(openvpn: OpenVPNProvider) -> None:
    openvpn.enable()
    assert all(result.level != HealthLevel.FAILURE for result in openvpn.healthcheck())
    openvpn.context.firewall.rules.pop("openvpn")
    failures = {
        result.name for result in openvpn.healthcheck() if result.level == HealthLevel.FAILURE
    }
    assert "firewall" in failures


def test_doctor_has_an_explicit_crl_validity_check(openvpn: OpenVPNProvider) -> None:
    openvpn.enable()
    checks = {result.name: result for result in openvpn.healthcheck()}
    assert checks["crl"].level == HealthLevel.SUCCESS
    openvpn.crl_path.write_text("invalid CRL\n")
    checks = {result.name: result for result in openvpn.healthcheck()}
    assert checks["crl"].level == HealthLevel.FAILURE


def test_doctor_detects_tampered_client_export(openvpn: OpenVPNProvider) -> None:
    openvpn.enable()
    service = ClientService(openvpn.context.state, ProviderRegistry([openvpn]))
    service.add("alice")
    client = service.enable_provider("alice", "openvpn")
    openvpn._client_export_path(client).write_text("tampered\n")
    failures = {
        result.name for result in openvpn.healthcheck() if result.level == HealthLevel.FAILURE
    }
    assert "client-state" in failures
    assert openvpn.enable().changed
    assert openvpn.client_artifacts_valid()


def test_dry_run_lists_meaningful_steps_without_generating_secrets(
    openvpn: OpenVPNProvider, monkeypatch
) -> None:
    openvpn.context.dry_run = True
    monkeypatch.setattr(
        openvpn.context.services,
        "is_active",
        lambda unit: (_ for _ in ()).throw(AssertionError("dry-run probed systemd")),
    )
    monkeypatch.setattr(
        openvpn.context.services,
        "is_enabled",
        lambda unit: (_ for _ in ()).throw(AssertionError("dry-run probed systemd")),
    )
    result = openvpn.enable()
    assert result.changed
    assert any("OpenVPN PKI" in action for action in result.actions)
    assert any("OpenVPN nftables NAT rule" in action for action in result.actions)
    assert not openvpn.pki.root.exists()
    assert not openvpn.context.state.exists


def test_service_restart_and_boot_recovery_restore_independent_postconditions(
    openvpn: OpenVPNProvider,
) -> None:
    openvpn.enable()
    openvpn.context.services._set_active(openvpn.unit, False)
    assert openvpn.context.services.is_enabled(openvpn.unit)
    assert openvpn.status().state == ProviderStateName.STOPPED
    assert openvpn.enable().changed
    assert openvpn.status().state == ProviderStateName.RUNNING
    openvpn.context.network.listening_ports.discard(1194)
    assert openvpn.status().state == ProviderStateName.STOPPED
    assert openvpn.enable().changed
    assert openvpn.status().state == ProviderStateName.RUNNING
