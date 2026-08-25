from pathlib import Path

from typer.testing import CliRunner

from fluxgate.cli.app import app
from fluxgate.core.models import ProviderDetection
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
    assert version.stdout.strip() == "0.1.0"
    profiles = runner.invoke(app, ["profile", "list"])
    assert profiles.exit_code == 0
    assert "wireguard" in profiles.stdout
    assert "planned" in profiles.stdout


def test_cli_config_validate_with_overridden_paths(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("FLUXGATE_CONFIG_DIR", str(tmp_path / "etc"))
    monkeypatch.setenv("FLUXGATE_DATA_DIR", str(tmp_path / "data"))
    result = CliRunner().invoke(app, ["config", "validate"])
    assert result.exit_code == 0
    assert "Valid:" in result.stdout
