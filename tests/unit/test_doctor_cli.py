from pathlib import Path

from typer.testing import CliRunner

from fluxgate.cli.app import app
from fluxgate.cli.common import safe_client
from fluxgate.core.models import Client, ProviderDetection
from fluxgate.core.registry import ProviderRegistry
from fluxgate.health import Doctor, HealthSeverity
from fluxgate.providers.wireguard import WireGuardProvider
from fluxgate.system.os import OperatingSystem


def test_doctor_aggregates_structured_provider_results(provider_context, monkeypatch) -> None:
    provider = WireGuardProvider(provider_context)
    monkeypatch.setattr(provider, "detect", lambda: ProviderDetection(available=False))
    operating_system = OperatingSystem("ubuntu", "24.04", "Ubuntu 24.04", "x86_64", True)
    report = Doctor(
        provider_context.paths,
        provider_context.state,
        ProviderRegistry([provider]),
        operating_system,
        provider_context.forwarding,
    ).run()
    assert any(check.name == "operating-system" for check in report.checks)
    assert any(check.section == "WireGuard" for check in report.checks)
    assert not any(check.severity == HealthSeverity.FAILURE for check in report.checks)


def test_cli_version_and_profiles() -> None:
    runner = CliRunner()
    version = runner.invoke(app, ["version"])
    assert version.exit_code == 0
    assert version.stdout.strip() == "0.2.0"
    profiles = runner.invoke(app, ["profile", "list"])
    assert profiles.exit_code == 0
    assert "wireguard" in profiles.stdout
    assert "planned" in profiles.stdout


def test_cli_errors_are_noninteractive_and_return_one() -> None:
    result = CliRunner().invoke(app, ["profile", "show", "does-not-exist"])
    assert result.exit_code == 1
    assert "Error: unknown profile: does-not-exist" in result.stderr


def test_explicit_client_cli_creates_identity_without_provisioning_every_provider(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("FLUXGATE_CONFIG_DIR", str(tmp_path / "etc"))
    monkeypatch.setenv("FLUXGATE_DATA_DIR", str(tmp_path / "data"))
    result = CliRunner().invoke(app, ["client", "add", "automation-client"])
    assert result.exit_code == 0
    assert '"providers": []' in result.stdout
    assert "private" not in result.stdout.lower()
    listed = CliRunner().invoke(app, ["client", "list"])
    assert listed.exit_code == 0
    assert "automation-client" in listed.stdout
    assert "unprovisioned" in listed.stdout
    failed = CliRunner().invoke(app, ["client", "enable", "automation-client", "wireguard"])
    assert failed.exit_code == 1
    assert "provider is not running: wireguard" in failed.stderr


def test_client_json_object_has_a_versioned_secret_free_shape() -> None:
    client = Client(
        name="alice",
        provider_credentials={"wireguard": {"private_key": "must-not-appear"}},
    )
    payload = safe_client(client)
    assert payload["schema_version"] == 1
    assert payload["providers"] == ["wireguard"]
    assert "private_key" not in payload


def test_cli_config_validate_with_overridden_paths(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("FLUXGATE_CONFIG_DIR", str(tmp_path / "etc"))
    monkeypatch.setenv("FLUXGATE_DATA_DIR", str(tmp_path / "data"))
    result = CliRunner().invoke(app, ["config", "validate"])
    assert result.exit_code == 0
    assert "Valid:" in result.stdout


def test_doctor_json_has_versioned_stable_envelope(tmp_path: Path, monkeypatch) -> None:
    import json

    from fluxgate.system.os import OperatingSystem

    monkeypatch.setenv("FLUXGATE_CONFIG_DIR", str(tmp_path / "etc"))
    monkeypatch.setenv("FLUXGATE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(
        "fluxgate.cli.doctor.detect_os",
        lambda: OperatingSystem("test", "1", "Unsupported Test OS", "x86_64", False),
    )
    result = CliRunner().invoke(app, ["doctor", "--json"])
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1
    assert isinstance(payload["checks"], list)
    assert result.exit_code == 1
