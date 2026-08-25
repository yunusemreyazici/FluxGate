from pathlib import Path

import pytest

from fluxgate.core.commands import CommandRunner, redacted_args
from fluxgate.core.errors import CommandError, FluxGateError, StateError
from fluxgate.core.operations import OperationPlan
from fluxgate.system.firewall import NftablesFirewallManager
from fluxgate.system.os import detect_os
from fluxgate.system.packages import AptPackageManager
from fluxgate.system.services import SystemdServiceManager


def test_command_failure_is_structured_and_no_shell_is_used() -> None:
    runner = CommandRunner()
    with pytest.raises(CommandError, match=r"failed with status 7"):
        runner.run(["/bin/sh", "-c", "exit 7"])


def test_command_dry_run_only_suppresses_mutations() -> None:
    runner = CommandRunner(dry_run=True)
    planned = runner.run(["does-not-exist", "arg"], mutate=True)
    assert planned.planned
    assert runner.planned_commands == [("does-not-exist", "arg")]
    with pytest.raises(CommandError):
        runner.run(["does-not-exist"], mutate=False)


def test_secret_options_are_redacted() -> None:
    assert redacted_args(["tool", "--token", "abc", "--password=hunter2", "visible"]) == (
        "tool",
        "--token",
        "<redacted>",
        "--password=<redacted>",
        "visible",
    )


def test_operation_rolls_back_completed_steps_in_reverse() -> None:
    events: list[str] = []
    plan = OperationPlan()
    plan.add("one", lambda: events.append("apply-one"), lambda: events.append("undo-one"))
    plan.add("two", lambda: events.append("apply-two"), lambda: events.append("undo-two"))

    def fail() -> None:
        raise RuntimeError("broken")

    plan.add("three", fail)
    with pytest.raises(FluxGateError, match="step 3"):
        plan.execute()
    assert events == ["apply-one", "apply-two", "undo-two", "undo-one"]


def test_operation_dry_run_has_no_side_effects() -> None:
    called = False

    def action() -> None:
        nonlocal called
        called = True

    plan = OperationPlan()
    plan.add("Would change a thing", action)
    assert plan.execute(dry_run=True) == ["Would change a thing"]
    assert not called


class RecordingRunner:
    def __init__(self, rules_path: Path | None = None) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.rules_path = rules_path
        self.live_rules: str | None = None
        self.service_enabled = False
        self.service_active = False
        self.fail_on: tuple[str, ...] | None = None
        self.failed = False

    def run(self, args, **kwargs):
        from fluxgate.core.commands import CommandResult

        command = tuple(args)
        self.commands.append(command)
        if (
            self.fail_on is not None
            and command[: len(self.fail_on)] == self.fail_on
            and not self.failed
        ):
            self.failed = True
            raise RuntimeError("injected command failure")
        if command[:5] == ("nft", "list", "table", "inet", "fluxgate"):
            return CommandResult(
                command, 0 if self.live_rules is not None else 1, self.live_rules or ""
            )
        if command[:5] == ("nft", "delete", "table", "inet", "fluxgate"):
            self.live_rules = None
        elif command == ("nft", "-f", "-"):
            self.live_rules = kwargs.get("input_text", "")
        elif command[:3] == ("systemctl", "is-enabled", "--quiet"):
            return CommandResult(command, 0 if self.service_enabled else 1)
        elif command[:3] == ("systemctl", "is-active", "--quiet"):
            return CommandResult(command, 0 if self.service_active else 1)
        elif command[:2] == ("systemctl", "enable"):
            self.service_enabled = True
        elif command[:2] == ("systemctl", "disable"):
            self.service_enabled = False
            if "--now" in command:
                self.service_active = False
        elif command[:2] in {("systemctl", "restart"), ("systemctl", "start")}:
            self.service_active = True
            if self.rules_path is not None:
                self.live_rules = self.rules_path.read_text()
        return CommandResult(command, 0)


def test_firewall_creates_only_identifiable_fluxgate_rules(tmp_path: Path) -> None:
    rules = tmp_path / "fluxgate.nft"
    runner = RecordingRunner(rules)
    unit = tmp_path / "fluxgate-firewall.service"
    firewall = NftablesFirewallManager(runner, rules, unit)  # type: ignore[arg-type]
    assert firewall.ensure_nat("10.77.0.0/24", "eth0")
    rendered = [" ".join(command) for command in runner.commands]
    assert "table inet fluxgate" in rules.read_text()
    assert "fluxgate-managed" in rules.read_text()
    assert "nft -f" in unit.read_text()
    assert "ExecStartPre=/bin/sh -ec" in unit.read_text()
    assert "ExecStop=/bin/sh -ec" in unit.read_text()
    assert "*fluxgate-managed*chain*postrouting*fluxgate-managed*" in unit.read_text()
    assert "ExecStartPre=-/usr/sbin/nft delete" not in unit.read_text()
    assert "After=nftables.service" in unit.read_text()
    assert firewall.configured("10.77.0.0/24", "eth0")
    assert all("flush" not in command for command in rendered)


def test_firewall_refuses_to_replace_unmanaged_files(tmp_path: Path) -> None:
    runner = RecordingRunner()
    rules = tmp_path / "fluxgate.nft"
    rules.write_text("user-owned\n")
    firewall = NftablesFirewallManager(  # type: ignore[arg-type]
        runner, rules, tmp_path / "fluxgate-firewall.service"
    )
    with pytest.raises(StateError, match="unmanaged"):
        firewall.ensure_nat("10.77.0.0/24", "eth0")
    assert rules.read_text() == "user-owned\n"


def test_firewall_never_deletes_an_unmanaged_live_table(tmp_path: Path) -> None:
    runner = RecordingRunner()
    runner.live_rules = "table inet fluxgate { chain user_owned { } }\n"
    firewall = NftablesFirewallManager(  # type: ignore[arg-type]
        runner, tmp_path / "fluxgate.nft", tmp_path / "fluxgate-firewall.service"
    )
    with pytest.raises(StateError, match="unmanaged nftables table"):
        firewall.remove()
    assert runner.live_rules == "table inet fluxgate { chain user_owned { } }\n"
    assert not any(command[:2] == ("nft", "delete") for command in runner.commands)


def test_firewall_does_not_accept_a_single_rule_marker_as_table_ownership(
    tmp_path: Path,
) -> None:
    runner = RecordingRunner()
    runner.live_rules = (
        'table inet fluxgate { chain postrouting { comment "fluxgate-managed"; } }\n'
    )
    firewall = NftablesFirewallManager(  # type: ignore[arg-type]
        runner, tmp_path / "fluxgate.nft", tmp_path / "fluxgate-firewall.service"
    )
    with pytest.raises(StateError, match="unmanaged nftables table"):
        firewall.remove()
    assert runner.live_rules is not None


def test_firewall_is_idempotent_and_restores_previous_rules_on_failure(tmp_path: Path) -> None:
    rules = tmp_path / "fluxgate.nft"
    runner = RecordingRunner(rules)
    firewall = NftablesFirewallManager(  # type: ignore[arg-type]
        runner, rules, tmp_path / "fluxgate-firewall.service"
    )
    assert firewall.ensure_nat("10.77.0.0/24", "eth0")
    old_rules = rules.read_bytes()
    old_live = runner.live_rules
    assert not firewall.ensure_nat("10.77.0.0/24", "eth0")
    restart_count = runner.commands.count(("systemctl", "restart", firewall.UNIT))
    assert restart_count == 1

    runner.fail_on = ("systemctl", "restart")
    with pytest.raises(RuntimeError, match="injected"):
        firewall.ensure_nat("10.77.0.0/24", "eth1")
    assert rules.read_bytes() == old_rules
    assert runner.live_rules == old_live
    assert runner.service_enabled
    assert runner.service_active


def test_firewall_disable_removes_only_owned_artifacts(tmp_path: Path) -> None:
    rules = tmp_path / "fluxgate.nft"
    unit = tmp_path / "fluxgate-firewall.service"
    runner = RecordingRunner(rules)
    firewall = NftablesFirewallManager(runner, rules, unit)  # type: ignore[arg-type]
    firewall.ensure_nat("10.77.0.0/24", "eth0")
    assert firewall.remove()
    assert runner.live_rules is None
    assert not rules.exists()
    assert not unit.exists()
    assert not runner.service_enabled
    assert all("flush" not in command for command in runner.commands)


def test_firewall_removes_stale_service_enablement_when_unit_file_is_missing(
    tmp_path: Path,
) -> None:
    rules = tmp_path / "fluxgate.nft"
    rules.write_text("# Managed by FluxGate.\n")
    runner = RecordingRunner(rules)
    runner.service_enabled = True
    firewall = NftablesFirewallManager(  # type: ignore[arg-type]
        runner, rules, tmp_path / "missing-fluxgate-firewall.service"
    )
    assert firewall.remove()
    assert not runner.service_enabled
    assert ("systemctl", "disable", "--now", firewall.UNIT) in runner.commands


@pytest.mark.parametrize(
    ("identifier", "version"),
    [("ubuntu", "22.04"), ("ubuntu", "24.04"), ("debian", "12")],
)
def test_supported_os_detection(tmp_path: Path, identifier: str, version: str) -> None:
    release = tmp_path / "os-release"
    release.write_text(
        f'ID={identifier}\nVERSION_ID="{version}"\nPRETTY_NAME="Test Linux {version}"\n'
    )
    result = detect_os(release)
    assert result.supported
    assert result.identifier == identifier


def test_apt_refreshes_indexes_before_noninteractive_install() -> None:
    runner = RecordingRunner()
    manager = AptPackageManager(runner)  # type: ignore[arg-type]
    assert manager.install(["wireguard-tools", "nftables"])
    assert runner.commands[:2] == [
        ("apt-get", "update"),
        ("apt-get", "install", "-y", "--no-install-recommends", "wireguard-tools", "nftables"),
    ]


class PartialSystemdRunner:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    def run(self, args, **kwargs):
        from fluxgate.core.commands import CommandResult

        command = tuple(args)
        self.commands.append(command)
        if command[:2] == ("systemctl", "enable") and "--now" in command:
            raise RuntimeError("start failed after enable")
        if command[:3] in {
            ("systemctl", "is-enabled", "--quiet"),
            ("systemctl", "is-active", "--quiet"),
        }:
            return CommandResult(command, 1)
        return CommandResult(command, 0)


def test_systemd_enable_failure_restores_prior_enablement_and_activity() -> None:
    runner = PartialSystemdRunner()
    services = SystemdServiceManager(runner)  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="start failed"):
        services.enable_now("wg-quick@fg0.service")
    assert ("systemctl", "disable", "wg-quick@fg0.service") in runner.commands
    assert ("systemctl", "stop", "wg-quick@fg0.service") in runner.commands


class FailedSystemdRollbackRunner(PartialSystemdRunner):
    def run(self, args, **kwargs):
        command = tuple(args)
        if command[:2] == ("systemctl", "disable"):
            raise RuntimeError("rollback disable failed")
        return super().run(args, **kwargs)


def test_systemd_reports_failed_rollback() -> None:
    services = SystemdServiceManager(FailedSystemdRollbackRunner())  # type: ignore[arg-type]
    with pytest.raises(StateError, match="rollback failed: rollback disable failed"):
        services.enable_now("wg-quick@fg0.service")
