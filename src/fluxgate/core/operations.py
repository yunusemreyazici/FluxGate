"""Small local operation plans with best-effort rollback."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from fluxgate.core.errors import FluxGateError

Action = Callable[[], object]


@dataclass(slots=True)
class OperationStep:
    description: str
    apply: Action
    rollback: Action | None = None


@dataclass(slots=True)
class OperationPlan:
    steps: list[OperationStep] = field(default_factory=list)

    def add(self, description: str, apply: Action, rollback: Action | None = None) -> None:
        self.steps.append(OperationStep(description, apply, rollback))

    def execute(self, *, dry_run: bool = False) -> list[str]:
        descriptions = [step.description for step in self.steps]
        if dry_run:
            return descriptions
        completed: list[OperationStep] = []
        try:
            for step in self.steps:
                step.apply()
                completed.append(step)
        except BaseException as error:
            rollback_failures: list[str] = []
            for step in reversed(completed):
                if step.rollback is not None:
                    try:
                        step.rollback()
                    except BaseException as rollback_error:
                        rollback_failures.append(f"{step.description}: {rollback_error}")
            suffix = (
                f"; rollback failures: {'; '.join(rollback_failures)}" if rollback_failures else ""
            )
            raise FluxGateError(
                f"operation failed at step {len(completed) + 1}: {error}{suffix}"
            ) from error
        return [description.removeprefix("Would ") for description in descriptions]
