from pathlib import Path

import pytest

from fluxgate.core.commands import CommandRunner, redacted_args
from fluxgate.core.errors import CommandError, FluxGateError, StateError
from fluxgate.core.operations import OperationPlan
from fluxgate.system.firewall import NftablesFirewallManager
from fluxgate.system.os import detect_os


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
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    def run(self, args, **kwargs):
        from fluxgate.core.commands import CommandResult

        command = tuple(args)
        self.commands.append(command)
        exists = command[:4] == ("nft", "list", "table", "inet") and len(self.commands) > 1
        return CommandResult(command, 0 if exists else 1)


def test_firewall_creates_only_identifiable_fluxgate_rules(tmp_path: Path) -> None:
    runner = RecordingRunner()
    rules = tmp_path / "fluxgate.nft"
    unit = tmp_path / "fluxgate-firewall.service"
    firewall = NftablesFirewallManager(runner, rules, unit)  # type: ignore[arg-type]
    assert firewall.ensure_nat("10.77.0.0/24", "eth0")
    rendered = [" ".join(command) for command in runner.commands]
    assert "table inet fluxgate" in rules.read_text()
    assert "fluxgate-managed" in rules.read_text()
    assert "nft -f" in unit.read_text()
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


def test_supported_os_detection(tmp_path: Path) -> None:
    release = tmp_path / "os-release"
    release.write_text('ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04 LTS"\n')
    result = detect_os(release)
    assert result.supported
    assert result.identifier == "ubuntu"
