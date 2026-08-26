"""Secret-free models for explicit failover execution planning and results."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import Field, field_validator, model_validator

from fluxgate.core.compat import StrEnum
from fluxgate.core.models import StrictModel
from fluxgate.pathfinder.active_models import FailoverAction
from fluxgate.pathfinder.models import (
    ConnectionCandidate,
    ConnectionMode,
    PathfinderProtocol,
    PathfinderProvider,
    PathfinderSecurity,
    PathfinderTransport,
)

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ExecutionStrategy(StrEnum):
    """How an adapter changes from the existing connection to its target."""

    MAKE_BEFORE_BREAK = "make_before_break"
    BREAK_BEFORE_MAKE = "break_before_make"
    PLAN_ONLY = "plan_only"


class ExecutionPlanStatus(StrEnum):
    NO_ACTION = "no_action"
    READY = "ready"
    UNSUPPORTED = "unsupported"
    INVALID = "invalid"


class ExecutionState(StrEnum):
    PLANNED = "planned"
    PREPARING = "preparing"
    PREPARED = "prepared"
    ACTIVATING = "activating"
    VERIFYING = "verifying"
    COMMITTING = "committing"
    COMMITTED = "committed"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"
    CLEANING_UP = "cleaning_up"
    CLEANED_UP = "cleaned_up"


class ExecutionStatus(StrEnum):
    NO_ACTION = "no_action"
    ALREADY_CONVERGED = "already_converged"
    COMMITTED = "committed"
    REJECTED = "rejected"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"
    CLEANUP_FAILED = "cleanup_failed"
    CANCELLED = "cancelled"


class VerificationStatus(StrEnum):
    NOT_RUN = "not_run"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class RollbackStatus(StrEnum):
    NOT_NEEDED = "not_needed"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class CleanupStatus(StrEnum):
    NOT_NEEDED = "not_needed"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ExecutionFailureType(StrEnum):
    INVALID_DECISION = "invalid_decision"
    STALE_DECISION = "stale_decision"
    UNAUTHORIZED_TARGET = "unauthorized_target"
    UNSUPPORTED_ADAPTER = "unsupported_adapter"
    EXECUTION_CONFLICT = "execution_conflict"
    PRECONDITION_FAILURE = "precondition_failure"
    PREPARE_FAILURE = "prepare_failure"
    ACTIVATION_FAILURE = "activation_failure"
    VERIFICATION_FAILURE = "verification_failure"
    COMMIT_FAILURE = "commit_failure"
    TIMEOUT = "timeout"
    CANCELLATION = "cancellation"
    ROLLBACK_FAILURE = "rollback_failure"
    CLEANUP_FAILURE = "cleanup_failure"
    INTERNAL_ERROR = "internal_error"


class ExecutionPolicy(StrictModel):
    """Strict phase budgets and permitted switch behavior."""

    prepare_timeout_seconds: float = Field(default=5.0, gt=0.0, le=60.0)
    activation_timeout_seconds: float = Field(default=10.0, gt=0.0, le=120.0)
    verification_timeout_seconds: float = Field(default=10.0, gt=0.0, le=120.0)
    commit_timeout_seconds: float = Field(default=5.0, gt=0.0, le=60.0)
    rollback_timeout_seconds: float = Field(default=10.0, gt=0.0, le=120.0)
    cleanup_timeout_seconds: float = Field(default=5.0, gt=0.0, le=60.0)
    transaction_timeout_seconds: float = Field(default=60.0, gt=0.0, le=600.0)
    allow_break_before_make: bool = False

    @model_validator(mode="after")
    def phase_budgets_fit_transaction(self) -> ExecutionPolicy:
        conservative_budget = (
            self.verification_timeout_seconds  # already-active precondition
            + self.prepare_timeout_seconds
            + self.activation_timeout_seconds
            + self.verification_timeout_seconds
            + self.commit_timeout_seconds
            + self.rollback_timeout_seconds
            + self.cleanup_timeout_seconds
        )
        if conservative_budget > self.transaction_timeout_seconds:
            raise ValueError("execution phase budgets must fit the total transaction timeout")
        return self


class ExecutionCapability(StrictModel):
    """Secret-free declaration of candidates an adapter can execute."""

    adapter_id: str
    strategy: ExecutionStrategy
    supported_providers: tuple[PathfinderProvider, ...]
    supported_protocols: tuple[PathfinderProtocol, ...]
    supported_transports: tuple[PathfinderTransport, ...]
    supported_security: tuple[PathfinderSecurity, ...]
    supported_connection_modes: tuple[ConnectionMode, ...]
    verification: str

    @field_validator("adapter_id")
    @classmethod
    def safe_adapter_id(cls, value: str) -> str:
        if not _SAFE_IDENTIFIER.fullmatch(value):
            raise ValueError("adapter ID must be a safe printable identifier")
        return value

    @field_validator(
        "supported_providers",
        "supported_protocols",
        "supported_transports",
        "supported_security",
        "supported_connection_modes",
    )
    @classmethod
    def unique_nonempty_capabilities(cls, value: tuple[object, ...]) -> tuple[object, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("adapter capability lists must be non-empty and unique")
        return value

    @field_validator("verification")
    @classmethod
    def useful_verification(cls, value: str) -> str:
        if not value or value != value.strip() or len(value) > 256:
            raise ValueError("adapter verification description must be concise")
        return value


class CandidateExecutionBinding(StrictModel):
    """A candidate plus its binding to one authoritative inventory snapshot."""

    candidate: ConnectionCandidate
    fingerprint: str

    @field_validator("fingerprint")
    @classmethod
    def sha256_fingerprint(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("candidate fingerprint must be lowercase SHA-256")
        return value


class FailoverExecutionPlan(StrictModel):
    """Deterministic, non-mutating plan produced before any adapter activity."""

    schema_version: Literal[1] = 1
    plan_id: str
    execution_scope: str
    decision_action: FailoverAction
    status: ExecutionPlanStatus
    reason: str
    current: CandidateExecutionBinding | None
    target: CandidateExecutionBinding | None
    adapter: ExecutionCapability | None
    preconditions: tuple[str, ...]
    expected_verification: str | None
    rollback_target_candidate_id: str | None
    execution_supported: bool
    unsupported_reason: str | None = None
    policy: ExecutionPolicy

    @field_validator("plan_id")
    @classmethod
    def sha256_plan_id(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("execution plan ID must be lowercase SHA-256")
        return value

    @field_validator("execution_scope")
    @classmethod
    def safe_scope(cls, value: str) -> str:
        if not _SAFE_IDENTIFIER.fullmatch(value):
            raise ValueError("execution scope must be a safe printable identifier")
        return value

    @model_validator(mode="after")
    def internally_consistent(self) -> FailoverExecutionPlan:
        if self.status == ExecutionPlanStatus.READY:
            if (
                self.decision_action != FailoverAction.SWITCH
                or self.target is None
                or self.adapter is None
                or not self.execution_supported
                or self.unsupported_reason is not None
            ):
                raise ValueError("ready execution plan is incomplete")
            if not self.target.candidate.enabled:
                raise ValueError("ready execution target must be enabled")
            if self.current is not None and (
                not self.current.candidate.enabled
                or self.current.candidate.candidate_id == self.target.candidate.candidate_id
            ):
                raise ValueError("ready execution rollback candidate is disabled or equals target")
        elif self.execution_supported != (self.status == ExecutionPlanStatus.NO_ACTION):
            raise ValueError("only ready or no-action plans may be execution-supported")
        if self.status == ExecutionPlanStatus.NO_ACTION and self.adapter is not None:
            raise ValueError("no-action plans must not select an adapter")
        if self.adapter is None and self.expected_verification is not None:
            raise ValueError("verification requires a selected adapter")
        if self.adapter is not None and self.expected_verification != self.adapter.verification:
            raise ValueError("plan verification must match its adapter capability")
        expected_rollback = (
            self.current.candidate.candidate_id if self.current is not None else None
        )
        if self.rollback_target_candidate_id != expected_rollback:
            raise ValueError("rollback target must match the bound current candidate")
        return self


class FailoverExecutionResult(StrictModel):
    """Ephemeral, secret-free outcome of one explicit execution request."""

    schema_version: Literal[1] = 1
    execution_id: str
    decision_action: FailoverAction
    source_candidate_id: str | None
    target_candidate_id: str | None
    status: ExecutionStatus
    state_history: tuple[ExecutionState, ...]
    verification: VerificationStatus
    rollback: RollbackStatus
    cleanup: CleanupStatus
    duration_ms: float = Field(ge=0.0, allow_inf_nan=False)
    failure_type: ExecutionFailureType | None = None
    reason: str

    @field_validator("execution_id")
    @classmethod
    def sha256_execution_id(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("execution ID must be lowercase SHA-256")
        return value

    @model_validator(mode="after")
    def outcome_is_consistent(self) -> FailoverExecutionResult:
        successful = {
            ExecutionStatus.NO_ACTION,
            ExecutionStatus.ALREADY_CONVERGED,
            ExecutionStatus.COMMITTED,
        }
        if (self.status in successful) != (self.failure_type is None):
            raise ValueError("execution status and failure type disagree")
        if self.status == ExecutionStatus.COMMITTED and (
            self.verification != VerificationStatus.SUCCEEDED
            or ExecutionState.COMMITTED not in self.state_history
        ):
            raise ValueError("committed execution requires successful verification")
        if (
            self.status == ExecutionStatus.ROLLBACK_FAILED
            and self.rollback != RollbackStatus.FAILED
        ):
            raise ValueError("rollback-failed status requires failed rollback")
        if self.status == ExecutionStatus.CLEANUP_FAILED and self.cleanup != CleanupStatus.FAILED:
            raise ValueError("cleanup-failed status requires failed cleanup")
        if not self.state_history or self.state_history[0] != ExecutionState.PLANNED:
            raise ValueError("execution state history must start at planned")
        transitions = {
            ExecutionState.PLANNED: {ExecutionState.PREPARING},
            ExecutionState.PREPARING: {
                ExecutionState.PREPARED,
                ExecutionState.ROLLING_BACK,
            },
            ExecutionState.PREPARED: {ExecutionState.ACTIVATING},
            ExecutionState.ACTIVATING: {
                ExecutionState.VERIFYING,
                ExecutionState.ROLLING_BACK,
            },
            ExecutionState.VERIFYING: {
                ExecutionState.COMMITTING,
                ExecutionState.ROLLING_BACK,
            },
            ExecutionState.COMMITTING: {
                ExecutionState.COMMITTED,
                ExecutionState.ROLLING_BACK,
            },
            ExecutionState.COMMITTED: {ExecutionState.CLEANING_UP},
            ExecutionState.ROLLING_BACK: {
                ExecutionState.ROLLED_BACK,
                ExecutionState.ROLLBACK_FAILED,
            },
            ExecutionState.ROLLED_BACK: {ExecutionState.CLEANING_UP},
            ExecutionState.ROLLBACK_FAILED: set(),
            ExecutionState.CLEANING_UP: {ExecutionState.CLEANED_UP},
            ExecutionState.CLEANED_UP: set(),
        }
        for previous, current in zip(self.state_history, self.state_history[1:], strict=False):
            if current not in transitions[previous]:
                raise ValueError("execution state history contains an invalid transition")
        terminal = self.state_history[-1]
        if self.status == ExecutionStatus.NO_ACTION and (
            self.state_history != (ExecutionState.PLANNED,)
            or self.verification != VerificationStatus.NOT_RUN
            or self.rollback != RollbackStatus.NOT_NEEDED
            or self.cleanup != CleanupStatus.NOT_NEEDED
        ):
            raise ValueError("no-action result must contain no lifecycle activity")
        if self.status == ExecutionStatus.ALREADY_CONVERGED and (
            self.state_history != (ExecutionState.PLANNED,)
            or self.verification != VerificationStatus.SUCCEEDED
            or self.rollback != RollbackStatus.NOT_NEEDED
            or self.cleanup != CleanupStatus.NOT_NEEDED
        ):
            raise ValueError("already-converged result must contain only precondition verification")
        if self.status == ExecutionStatus.REJECTED and (
            self.state_history != (ExecutionState.PLANNED,)
            or self.verification != VerificationStatus.NOT_RUN
            or self.rollback != RollbackStatus.NOT_NEEDED
            or self.cleanup != CleanupStatus.NOT_NEEDED
        ):
            raise ValueError("rejected result must not contain lifecycle activity")
        if self.status == ExecutionStatus.COMMITTED and (
            terminal != ExecutionState.CLEANED_UP
            or self.rollback != RollbackStatus.NOT_NEEDED
            or self.cleanup != CleanupStatus.SUCCEEDED
        ):
            raise ValueError("committed result requires successful cleanup and no rollback")
        if self.status == ExecutionStatus.ROLLED_BACK and (
            terminal != ExecutionState.CLEANED_UP
            or self.rollback != RollbackStatus.SUCCEEDED
            or self.cleanup != CleanupStatus.SUCCEEDED
        ):
            raise ValueError("rolled-back result requires successful rollback and cleanup")
        if self.status == ExecutionStatus.ROLLBACK_FAILED and (
            terminal != ExecutionState.ROLLBACK_FAILED or self.cleanup != CleanupStatus.NOT_NEEDED
        ):
            raise ValueError("rollback-failed result must stop before cleanup")
        if self.status == ExecutionStatus.CLEANUP_FAILED:
            committed_cleanup = (
                ExecutionState.COMMITTED in self.state_history
                and self.verification == VerificationStatus.SUCCEEDED
                and self.rollback == RollbackStatus.NOT_NEEDED
            )
            rolled_back_cleanup = (
                ExecutionState.ROLLED_BACK in self.state_history
                and self.rollback == RollbackStatus.SUCCEEDED
            )
            if terminal != ExecutionState.CLEANING_UP or not (
                committed_cleanup or rolled_back_cleanup
            ):
                raise ValueError("cleanup-failed result has inconsistent prior transaction state")
        if self.status == ExecutionStatus.CANCELLED:
            cancelled_before_mutation = (
                self.state_history == (ExecutionState.PLANNED,)
                and self.rollback == RollbackStatus.NOT_NEEDED
                and self.cleanup == CleanupStatus.NOT_NEEDED
            )
            cancelled_after_rollback = (
                terminal == ExecutionState.CLEANED_UP
                and self.rollback == RollbackStatus.SUCCEEDED
                and self.cleanup == CleanupStatus.SUCCEEDED
            )
            if not (cancelled_before_mutation or cancelled_after_rollback):
                raise ValueError("cancelled result has inconsistent recovery activity")
            if self.failure_type != ExecutionFailureType.CANCELLATION:
                raise ValueError("cancelled result requires cancellation failure type")
        return self
