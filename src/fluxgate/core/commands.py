"""Safe, injectable subprocess execution."""

from __future__ import annotations

import logging
import re
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from fluxgate.core.errors import CommandError

LOGGER = logging.getLogger(__name__)
SECRET_OPTION = re.compile(r"(?i)(private|secret|password|token|key)")


@dataclass(frozen=True, slots=True)
class CommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    planned: bool = False


def redacted_args(args: Sequence[str]) -> tuple[str, ...]:
    result: list[str] = []
    redact_next = False
    for argument in args:
        if redact_next:
            result.append("<redacted>")
            redact_next = False
        elif argument.startswith("-") and SECRET_OPTION.search(argument):
            if "=" in argument:
                result.append(f"{argument.split('=', 1)[0]}=<redacted>")
            else:
                result.append(argument)
                redact_next = True
        else:
            result.append(argument)
    return tuple(result)


class CommandRunner:
    def __init__(self, *, dry_run: bool = False, default_timeout: float = 30.0) -> None:
        self.dry_run = dry_run
        self.default_timeout = default_timeout
        self.planned_commands: list[tuple[str, ...]] = []

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
        if not args or any("\x00" in item for item in args):
            raise ValueError("command arguments must be non-empty and contain no NUL bytes")
        command = tuple(args)
        LOGGER.debug("command: %s", " ".join(redacted_args(command)))
        if self.dry_run and mutate:
            self.planned_commands.append(command)
            return CommandResult(command, 0, planned=True)
        try:
            completed = subprocess.run(  # noqa: S603 - argument arrays are the safety boundary
                command,
                input=input_text,
                capture_output=True,
                text=True,
                timeout=timeout or self.default_timeout,
                check=False,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise CommandError(f"unable to execute {command[0]}: {type(error).__name__}") from error
        result = CommandResult(command, completed.returncode, completed.stdout, completed.stderr)
        if check and result.returncode != 0:
            raise CommandError(f"{command[0]} failed with status {result.returncode}")
        return result
