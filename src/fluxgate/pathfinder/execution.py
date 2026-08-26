"""Transactional client-connection execution boundary for failover decisions."""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable, Coroutine
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Protocol, TypeVar

from fluxgate.pathfinder.authorization import AuthorizedCandidateInventory
from fluxgate.pathfinder.execution_models import (
    CleanupStatus,
    ExecutionCapability,
    ExecutionFailureType,
    ExecutionPlanStatus,
    ExecutionState,
    ExecutionStatus,
    FailoverExecutionPlan,
    FailoverExecutionResult,
    RollbackStatus,
    VerificationStatus,
)
from fluxgate.pathfinder.execution_planning import (
    candidate_fingerprint,
    capability_supports,
    execution_plan_id_is_valid,
)

T = TypeVar("T")
InventoryLoader = Callable[[], AuthorizedCandidateInventory]
Clock = Callable[[], float]


class ExecutionAdapterError(Exception):
    """Expected adapter failure whose message is never copied into public results."""


class ConnectionExecutionAdapter(Protocol):
    """Client-runtime contract; deliberately separate from server CoreProvider."""

    @property
    def capability(self) -> ExecutionCapability: ...

    async def is_active_and_verified(self, plan: FailoverExecutionPlan) -> bool: ...

    async def prepare(self, plan: FailoverExecutionPlan) -> None: ...

    async def activate(self, plan: FailoverExecutionPlan) -> None: ...

    async def verify(self, plan: FailoverExecutionPlan) -> bool: ...

    async def commit(self, plan: FailoverExecutionPlan) -> None: ...

    async def rollback(self, plan: FailoverExecutionPlan) -> None: ...

    async def cleanup(self, plan: FailoverExecutionPlan) -> None: ...


class ExecutionCancellation:
    """Explicit cooperative cancellation request for one execution."""

    def __init__(self) -> None:
        self._event = asyncio.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    async def wait(self) -> None:
        await self._event.wait()


class ExecutionLockRegistry:
    """Thread-safe process-local locks and cancellation quarantine by runtime scope."""

    def __init__(self, *, max_active_executions: int = 16) -> None:
        if type(max_active_executions) is not int or not 1 <= max_active_executions <= 64:
            raise ValueError("max active executions must be an integer between 1 and 64")
        self._guard = threading.Lock()
        self._max_active_executions = max_active_executions
        self._active_scopes: set[str] = set()
        self._pending_by_scope: dict[str, set[asyncio.Task[Any]]] = {}
        self._quarantined_scopes: set[str] = set()

    def try_acquire(self, scope: str) -> bool:
        with self._guard:
            occupied_scopes = self._active_scopes | self._quarantined_scopes
            if (
                scope in self._active_scopes
                or scope in self._quarantined_scopes
                or len(occupied_scopes) >= self._max_active_executions
            ):
                return False
            self._active_scopes.add(scope)
            return True

    def release(self, scope: str) -> None:
        with self._guard:
            if scope not in self._active_scopes:
                raise RuntimeError("execution scope lock is not held")
            self._active_scopes.remove(scope)

    def quarantine(self, scope: str, task: asyncio.Task[Any]) -> None:
        with self._guard:
            if scope not in self._active_scopes:
                raise RuntimeError("only an active execution scope may be quarantined")
            self._quarantined_scopes.add(scope)
            self._pending_by_scope.setdefault(scope, set()).add(task)

    def adapter_task_completed(self, scope: str, task: asyncio.Task[Any]) -> None:
        with self._guard:
            pending = self._pending_by_scope.get(scope)
            if pending is None:
                return
            pending.discard(task)
            if not pending:
                del self._pending_by_scope[scope]

    def is_quarantined(self, scope: str) -> bool:
        with self._guard:
            return scope in self._quarantined_scopes

    @property
    def quarantined_scopes(self) -> tuple[str, ...]:
        """Return stable operator-visible scopes requiring runtime reconciliation."""
        with self._guard:
            return tuple(sorted(self._quarantined_scopes))

    def acknowledge_reconciled(self, scope: str) -> bool:
        """Clear quarantine only after late work stopped and the caller reconciled runtime state."""
        with self._guard:
            if self._pending_by_scope.get(scope):
                return False
            try:
                self._quarantined_scopes.remove(scope)
            except KeyError:
                return False
            return True

    @property
    def pending_adapter_tasks(self) -> int:
        with self._guard:
            return sum(len(tasks) for tasks in self._pending_by_scope.values())


_DEFAULT_EXECUTION_LOCKS = ExecutionLockRegistry()


@dataclass(frozen=True, slots=True)
class _PhaseFailure(Exception):
    failure_type: ExecutionFailureType
    reason: str
    verification_failed: bool = False


@dataclass(frozen=True, slots=True)
class _PhaseTimeout(Exception):
    phase: str
    adapter_stopped: bool


@dataclass(frozen=True, slots=True)
class _ExecutionCancelled(Exception):
    phase: str
    adapter_stopped: bool


def _consume_task_result(task: asyncio.Task[Any]) -> None:
    with suppress(BaseException):
        task.result()


class FailoverExecutor:
    """Execute an already-planned switch with rebinding, rollback, and cleanup."""

    _CANCELLATION_GRACE_SECONDS = 0.25

    def __init__(
        self,
        inventory_loader: InventoryLoader,
        *,
        locks: ExecutionLockRegistry | None = None,
        clock: Clock = time.monotonic,
    ) -> None:
        self._inventory_loader = inventory_loader
        self._locks = locks or _DEFAULT_EXECUTION_LOCKS
        self._clock = clock

    @property
    def pending_adapter_tasks(self) -> int:
        """Expose cancellation-contract violations for tests and safe host shutdown."""
        return self._locks.pending_adapter_tasks

    async def _stop_task(self, task: asyncio.Task[Any], scope: str) -> bool:
        task.cancel()
        done, _ = await asyncio.wait({task}, timeout=self._CANCELLATION_GRACE_SECONDS)
        if done:
            _consume_task_result(task)
            return True
        self._locks.quarantine(scope, task)

        def completed(item: asyncio.Task[Any]) -> None:
            self._locks.adapter_task_completed(scope, item)
            _consume_task_result(item)

        task.add_done_callback(completed)
        return False

    async def _run_phase(
        self,
        operation: Coroutine[Any, Any, T],
        *,
        phase: str,
        scope: str,
        timeout: float,
        transaction_deadline: float,
        cancellation: ExecutionCancellation | None,
        honor_cancellation: bool = True,
    ) -> T:
        if cancellation is not None and honor_cancellation and cancellation.cancelled:
            operation.close()
            raise _ExecutionCancelled(phase, True)
        operation_task: asyncio.Task[T] = asyncio.create_task(operation)
        cancellation_task: asyncio.Task[None] | None = None
        wait_for: set[asyncio.Task[Any]] = {operation_task}
        if cancellation is not None and honor_cancellation:
            cancellation_task = asyncio.create_task(cancellation.wait())
            wait_for.add(cancellation_task)
        deadline = min(
            asyncio.get_running_loop().time() + timeout,
            transaction_deadline,
        )
        while True:
            try:
                done, _ = await asyncio.wait(
                    wait_for,
                    timeout=max(0.0, deadline - asyncio.get_running_loop().time()),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                break
            except asyncio.CancelledError as error:
                if not honor_cancellation:
                    continue
                stopped = await self._stop_task(operation_task, scope)
                if cancellation_task is not None:
                    cancellation_task.cancel()
                    await asyncio.gather(cancellation_task, return_exceptions=True)
                raise _ExecutionCancelled(phase, stopped) from error
        if operation_task in done:
            if cancellation_task is not None:
                cancellation_task.cancel()
                await asyncio.gather(cancellation_task, return_exceptions=True)
            try:
                return operation_task.result()
            except asyncio.CancelledError as error:
                raise _ExecutionCancelled(phase, True) from error
        if cancellation_task is not None:
            cancellation_task.cancel()
            await asyncio.gather(cancellation_task, return_exceptions=True)
        stopped = await self._stop_task(operation_task, scope)
        if cancellation is not None and cancellation.cancelled:
            raise _ExecutionCancelled(phase, stopped)
        raise _PhaseTimeout(phase, stopped)

    def _result(
        self,
        plan: FailoverExecutionPlan,
        started: float,
        *,
        status: ExecutionStatus,
        states: list[ExecutionState],
        verification: VerificationStatus = VerificationStatus.NOT_RUN,
        rollback: RollbackStatus = RollbackStatus.NOT_NEEDED,
        cleanup: CleanupStatus = CleanupStatus.NOT_NEEDED,
        failure_type: ExecutionFailureType | None = None,
        reason: str,
    ) -> FailoverExecutionResult:
        return FailoverExecutionResult(
            execution_id=plan.plan_id,
            decision_action=plan.decision_action,
            source_candidate_id=(
                plan.current.candidate.candidate_id if plan.current is not None else None
            ),
            target_candidate_id=(
                plan.target.candidate.candidate_id if plan.target is not None else None
            ),
            status=status,
            state_history=tuple(states),
            verification=verification,
            rollback=rollback,
            cleanup=cleanup,
            duration_ms=max(0.0, (self._clock() - started) * 1000.0),
            failure_type=failure_type,
            reason=reason,
        )

    async def execute(
        self,
        plan: FailoverExecutionPlan,
        adapter: ConnectionExecutionAdapter | None,
        *,
        cancellation: ExecutionCancellation | None = None,
    ) -> FailoverExecutionResult:
        """Execute only a valid plan rebound to current authoritative inventory."""
        started = self._clock()
        states = [ExecutionState.PLANNED]
        if not execution_plan_id_is_valid(plan):
            return self._result(
                plan,
                started,
                status=ExecutionStatus.REJECTED,
                states=states,
                failure_type=ExecutionFailureType.INVALID_DECISION,
                reason="execution plan integrity validation failed",
            )
        if plan.status == ExecutionPlanStatus.NO_ACTION:
            return self._result(
                plan,
                started,
                status=ExecutionStatus.NO_ACTION,
                states=states,
                reason="failover decision requires no connection lifecycle activity",
            )
        if plan.status != ExecutionPlanStatus.READY or not plan.execution_supported:
            failure = (
                ExecutionFailureType.UNSUPPORTED_ADAPTER
                if plan.status == ExecutionPlanStatus.UNSUPPORTED
                else ExecutionFailureType.INVALID_DECISION
            )
            return self._result(
                plan,
                started,
                status=ExecutionStatus.REJECTED,
                states=states,
                failure_type=failure,
                reason="execution plan is not executable",
            )
        if adapter is None or plan.adapter is None or plan.target is None:
            return self._result(
                plan,
                started,
                status=ExecutionStatus.REJECTED,
                states=states,
                failure_type=ExecutionFailureType.UNSUPPORTED_ADAPTER,
                reason="the planned client connection adapter is unavailable",
            )
        scope = plan.execution_scope
        if self._locks.is_quarantined(scope):
            return self._result(
                plan,
                started,
                status=ExecutionStatus.REJECTED,
                states=states,
                failure_type=ExecutionFailureType.EXECUTION_CONFLICT,
                reason="execution scope is quarantined after an adapter cancellation violation",
            )
        if not self._locks.try_acquire(scope):
            return self._result(
                plan,
                started,
                status=ExecutionStatus.REJECTED,
                states=states,
                failure_type=ExecutionFailureType.EXECUTION_CONFLICT,
                reason=(
                    "another execution is active, quarantined, or execution capacity is exhausted"
                ),
            )
        try:
            transaction_deadline = (
                asyncio.get_running_loop().time() + plan.policy.transaction_timeout_seconds
            )
            return await self._execute_locked(
                plan,
                adapter,
                cancellation,
                started,
                states,
                transaction_deadline,
            )
        finally:
            self._locks.release(scope)

    async def _execute_locked(
        self,
        plan: FailoverExecutionPlan,
        adapter: ConnectionExecutionAdapter,
        cancellation: ExecutionCancellation | None,
        started: float,
        states: list[ExecutionState],
        transaction_deadline: float,
    ) -> FailoverExecutionResult:
        scope = plan.execution_scope
        target_binding = plan.target
        planned_capability = plan.adapter
        assert target_binding is not None
        assert planned_capability is not None
        try:
            inventory = self._inventory_loader()
        except Exception:
            return self._result(
                plan,
                started,
                status=ExecutionStatus.REJECTED,
                states=states,
                failure_type=ExecutionFailureType.INTERNAL_ERROR,
                reason="authoritative candidate inventory could not be loaded",
            )
        candidates = {candidate.candidate_id: candidate for candidate in inventory.candidates}
        if len(candidates) != len(inventory.candidates):
            return self._result(
                plan,
                started,
                status=ExecutionStatus.REJECTED,
                states=states,
                failure_type=ExecutionFailureType.UNAUTHORIZED_TARGET,
                reason="current authoritative inventory contains duplicate candidate IDs",
            )
        target = candidates.get(target_binding.candidate.candidate_id)
        if target is None or not target.enabled:
            return self._result(
                plan,
                started,
                status=ExecutionStatus.REJECTED,
                states=states,
                failure_type=ExecutionFailureType.UNAUTHORIZED_TARGET,
                reason="target is absent or disabled in the current authoritative inventory",
            )
        if candidate_fingerprint(inventory, target) != target_binding.fingerprint:
            return self._result(
                plan,
                started,
                status=ExecutionStatus.REJECTED,
                states=states,
                failure_type=ExecutionFailureType.STALE_DECISION,
                reason="target candidate authorization or connection shape changed after planning",
            )
        if plan.current is not None:
            current = candidates.get(plan.current.candidate.candidate_id)
            if current is None or not current.enabled:
                return self._result(
                    plan,
                    started,
                    status=ExecutionStatus.REJECTED,
                    states=states,
                    failure_type=ExecutionFailureType.STALE_DECISION,
                    reason="rollback candidate is absent or disabled in the current inventory",
                )
            if candidate_fingerprint(inventory, current) != plan.current.fingerprint:
                return self._result(
                    plan,
                    started,
                    status=ExecutionStatus.REJECTED,
                    states=states,
                    failure_type=ExecutionFailureType.STALE_DECISION,
                    reason="rollback candidate authorization or connection shape changed",
                )
        try:
            capability = adapter.capability
            supported = capability_supports(capability, target, plan.policy)
        except Exception:
            return self._result(
                plan,
                started,
                status=ExecutionStatus.REJECTED,
                states=states,
                failure_type=ExecutionFailureType.INTERNAL_ERROR,
                reason="client connection adapter capability inspection failed",
            )
        if capability != planned_capability or not supported:
            return self._result(
                plan,
                started,
                status=ExecutionStatus.REJECTED,
                states=states,
                failure_type=ExecutionFailureType.UNSUPPORTED_ADAPTER,
                reason="client connection adapter no longer matches the execution plan",
            )

        try:
            already_active = await self._run_phase(
                adapter.is_active_and_verified(plan),
                phase="precondition",
                scope=scope,
                timeout=plan.policy.verification_timeout_seconds,
                transaction_deadline=transaction_deadline,
                cancellation=cancellation,
            )
        except (_PhaseTimeout, _ExecutionCancelled) as error:
            failure_type = (
                ExecutionFailureType.CANCELLATION
                if isinstance(error, _ExecutionCancelled)
                else ExecutionFailureType.TIMEOUT
            )
            status = (
                ExecutionStatus.CANCELLED
                if isinstance(error, _ExecutionCancelled)
                else ExecutionStatus.REJECTED
            )
            reason = f"execution {error.phase} was cancelled or timed out"
            if not error.adapter_stopped:
                reason = "adapter did not stop after precondition cancellation; scope quarantined"
            return self._result(
                plan,
                started,
                status=status,
                states=states,
                failure_type=failure_type,
                reason=reason,
            )
        except ExecutionAdapterError:
            return self._result(
                plan,
                started,
                status=ExecutionStatus.REJECTED,
                states=states,
                failure_type=ExecutionFailureType.PRECONDITION_FAILURE,
                reason="adapter could not confirm current connection state",
            )
        except Exception:
            return self._result(
                plan,
                started,
                status=ExecutionStatus.REJECTED,
                states=states,
                failure_type=ExecutionFailureType.INTERNAL_ERROR,
                reason="unexpected adapter error during precondition validation",
            )
        if type(already_active) is not bool:
            return self._result(
                plan,
                started,
                status=ExecutionStatus.REJECTED,
                states=states,
                failure_type=ExecutionFailureType.INTERNAL_ERROR,
                reason="adapter returned an invalid current connection state",
            )
        if already_active:
            return self._result(
                plan,
                started,
                status=ExecutionStatus.ALREADY_CONVERGED,
                states=states,
                verification=VerificationStatus.SUCCEEDED,
                reason="target candidate is already active and verified",
            )

        failure: _PhaseFailure | _PhaseTimeout | _ExecutionCancelled | None = None
        verification = VerificationStatus.NOT_RUN
        mutation_started = False
        try:
            states.append(ExecutionState.PREPARING)
            mutation_started = True
            await self._run_phase(
                adapter.prepare(plan),
                phase="prepare",
                scope=scope,
                timeout=plan.policy.prepare_timeout_seconds,
                transaction_deadline=transaction_deadline,
                cancellation=cancellation,
            )
            states.append(ExecutionState.PREPARED)
            states.append(ExecutionState.ACTIVATING)
            await self._run_phase(
                adapter.activate(plan),
                phase="activation",
                scope=scope,
                timeout=plan.policy.activation_timeout_seconds,
                transaction_deadline=transaction_deadline,
                cancellation=cancellation,
            )
            states.append(ExecutionState.VERIFYING)
            verified = await self._run_phase(
                adapter.verify(plan),
                phase="verification",
                scope=scope,
                timeout=plan.policy.verification_timeout_seconds,
                transaction_deadline=transaction_deadline,
                cancellation=cancellation,
            )
            if type(verified) is not bool:
                raise _PhaseFailure(
                    ExecutionFailureType.INTERNAL_ERROR,
                    "adapter returned an invalid verification result",
                    verification_failed=True,
                )
            if not verified:
                raise _PhaseFailure(
                    ExecutionFailureType.VERIFICATION_FAILURE,
                    "target connection verification failed",
                    verification_failed=True,
                )
            verification = VerificationStatus.SUCCEEDED
            states.append(ExecutionState.COMMITTING)
            await self._run_phase(
                adapter.commit(plan),
                phase="commit",
                scope=scope,
                timeout=plan.policy.commit_timeout_seconds,
                transaction_deadline=transaction_deadline,
                cancellation=cancellation,
            )
            states.append(ExecutionState.COMMITTED)
        except ExecutionAdapterError:
            phase = states[-1]
            failure_by_state = {
                ExecutionState.PREPARING: ExecutionFailureType.PREPARE_FAILURE,
                ExecutionState.ACTIVATING: ExecutionFailureType.ACTIVATION_FAILURE,
                ExecutionState.VERIFYING: ExecutionFailureType.VERIFICATION_FAILURE,
                ExecutionState.COMMITTING: ExecutionFailureType.COMMIT_FAILURE,
            }
            failure = _PhaseFailure(
                failure_by_state[phase],
                f"client connection adapter failed during {phase.value}",
                verification_failed=phase == ExecutionState.VERIFYING,
            )
        except (_PhaseFailure, _PhaseTimeout, _ExecutionCancelled) as error:
            failure = error
        except Exception:
            failure = _PhaseFailure(
                ExecutionFailureType.INTERNAL_ERROR,
                "unexpected client connection adapter error",
                verification_failed=states[-1] == ExecutionState.VERIFYING,
            )

        if failure is None:
            return await self._finish_committed(
                plan,
                adapter,
                cancellation,
                started,
                states,
                verification,
                transaction_deadline,
            )
        if (isinstance(failure, _PhaseFailure) and failure.verification_failed) or (
            isinstance(failure, _PhaseTimeout) and failure.phase == "verification"
        ):
            verification = VerificationStatus.FAILED

        if (
            isinstance(failure, (_PhaseTimeout, _ExecutionCancelled))
            and not failure.adapter_stopped
        ):
            states.extend((ExecutionState.ROLLING_BACK, ExecutionState.ROLLBACK_FAILED))
            return self._result(
                plan,
                started,
                status=ExecutionStatus.ROLLBACK_FAILED,
                states=states,
                verification=verification,
                rollback=RollbackStatus.FAILED,
                failure_type=ExecutionFailureType.ROLLBACK_FAILURE,
                reason=(
                    "adapter did not stop after cancellation; rollback was unsafe and scope "
                    "quarantined"
                ),
            )
        if not mutation_started:
            return self._failure_without_rollback(plan, started, states, verification, failure)
        return await self._rollback(
            plan,
            adapter,
            cancellation,
            started,
            states,
            verification,
            failure,
            transaction_deadline,
        )

    def _failure_without_rollback(
        self,
        plan: FailoverExecutionPlan,
        started: float,
        states: list[ExecutionState],
        verification: VerificationStatus,
        failure: _PhaseFailure | _PhaseTimeout | _ExecutionCancelled,
    ) -> FailoverExecutionResult:
        failure_type, status, reason = self._describe_failure(failure)
        return self._result(
            plan,
            started,
            status=status,
            states=states,
            verification=verification,
            failure_type=failure_type,
            reason=reason,
        )

    @staticmethod
    def _describe_failure(
        failure: _PhaseFailure | _PhaseTimeout | _ExecutionCancelled,
    ) -> tuple[ExecutionFailureType, ExecutionStatus, str]:
        if isinstance(failure, _ExecutionCancelled):
            return (
                ExecutionFailureType.CANCELLATION,
                ExecutionStatus.CANCELLED,
                f"execution cancelled during {failure.phase}",
            )
        if isinstance(failure, _PhaseTimeout):
            return (
                ExecutionFailureType.TIMEOUT,
                ExecutionStatus.ROLLED_BACK,
                f"execution timed out during {failure.phase}",
            )
        return failure.failure_type, ExecutionStatus.ROLLED_BACK, failure.reason

    async def _rollback(
        self,
        plan: FailoverExecutionPlan,
        adapter: ConnectionExecutionAdapter,
        cancellation: ExecutionCancellation | None,
        started: float,
        states: list[ExecutionState],
        verification: VerificationStatus,
        failure: _PhaseFailure | _PhaseTimeout | _ExecutionCancelled,
        transaction_deadline: float,
    ) -> FailoverExecutionResult:
        states.append(ExecutionState.ROLLING_BACK)
        try:
            await self._run_phase(
                adapter.rollback(plan),
                phase="rollback",
                scope=plan.execution_scope,
                timeout=plan.policy.rollback_timeout_seconds,
                transaction_deadline=transaction_deadline,
                cancellation=cancellation,
                honor_cancellation=False,
            )
            states.append(ExecutionState.ROLLED_BACK)
            rollback = RollbackStatus.SUCCEEDED
        except _PhaseTimeout as error:
            states.append(ExecutionState.ROLLBACK_FAILED)
            return self._result(
                plan,
                started,
                status=ExecutionStatus.ROLLBACK_FAILED,
                states=states,
                verification=verification,
                rollback=RollbackStatus.FAILED,
                failure_type=ExecutionFailureType.TIMEOUT,
                reason=(
                    "rollback timed out after an unsuccessful connection switch"
                    + (
                        "; adapter did not stop and the scope is quarantined"
                        if not error.adapter_stopped
                        else ""
                    )
                ),
            )
        except BaseException:
            states.append(ExecutionState.ROLLBACK_FAILED)
            return self._result(
                plan,
                started,
                status=ExecutionStatus.ROLLBACK_FAILED,
                states=states,
                verification=verification,
                rollback=RollbackStatus.FAILED,
                failure_type=ExecutionFailureType.ROLLBACK_FAILURE,
                reason="rollback failed after an unsuccessful connection switch",
            )

        cleanup, cleanup_timed_out, cleanup_quarantined = await self._cleanup(
            plan, adapter, cancellation, states, transaction_deadline
        )
        if cleanup == CleanupStatus.FAILED:
            return self._result(
                plan,
                started,
                status=ExecutionStatus.CLEANUP_FAILED,
                states=states,
                verification=verification,
                rollback=rollback,
                cleanup=cleanup,
                failure_type=(
                    ExecutionFailureType.TIMEOUT
                    if cleanup_timed_out
                    else ExecutionFailureType.CLEANUP_FAILURE
                ),
                reason=(
                    (
                        "switch was rolled back but adapter cleanup timed out"
                        + (
                            "; adapter did not stop and the scope is quarantined"
                            if cleanup_quarantined
                            else ""
                        )
                    )
                    if cleanup_timed_out
                    else "switch was rolled back but adapter cleanup failed"
                ),
            )
        failure_type, status, reason = self._describe_failure(failure)
        return self._result(
            plan,
            started,
            status=status,
            states=states,
            verification=verification,
            rollback=rollback,
            cleanup=cleanup,
            failure_type=failure_type,
            reason=reason,
        )

    async def _finish_committed(
        self,
        plan: FailoverExecutionPlan,
        adapter: ConnectionExecutionAdapter,
        cancellation: ExecutionCancellation | None,
        started: float,
        states: list[ExecutionState],
        verification: VerificationStatus,
        transaction_deadline: float,
    ) -> FailoverExecutionResult:
        cleanup, cleanup_timed_out, cleanup_quarantined = await self._cleanup(
            plan, adapter, cancellation, states, transaction_deadline
        )
        if cleanup == CleanupStatus.FAILED:
            return self._result(
                plan,
                started,
                status=ExecutionStatus.CLEANUP_FAILED,
                states=states,
                verification=verification,
                cleanup=cleanup,
                failure_type=(
                    ExecutionFailureType.TIMEOUT
                    if cleanup_timed_out
                    else ExecutionFailureType.CLEANUP_FAILURE
                ),
                reason=(
                    (
                        "connection committed but adapter cleanup timed out"
                        + (
                            "; adapter did not stop and the scope is quarantined"
                            if cleanup_quarantined
                            else ""
                        )
                    )
                    if cleanup_timed_out
                    else "connection committed but adapter cleanup failed"
                ),
            )
        return self._result(
            plan,
            started,
            status=ExecutionStatus.COMMITTED,
            states=states,
            verification=verification,
            cleanup=cleanup,
            reason="target connection was activated, verified, and committed",
        )

    async def _cleanup(
        self,
        plan: FailoverExecutionPlan,
        adapter: ConnectionExecutionAdapter,
        cancellation: ExecutionCancellation | None,
        states: list[ExecutionState],
        transaction_deadline: float,
    ) -> tuple[CleanupStatus, bool, bool]:
        states.append(ExecutionState.CLEANING_UP)
        try:
            await self._run_phase(
                adapter.cleanup(plan),
                phase="cleanup",
                scope=plan.execution_scope,
                timeout=plan.policy.cleanup_timeout_seconds,
                transaction_deadline=transaction_deadline,
                cancellation=cancellation,
                honor_cancellation=False,
            )
        except _PhaseTimeout as error:
            return CleanupStatus.FAILED, True, not error.adapter_stopped
        except BaseException:
            return CleanupStatus.FAILED, False, False
        states.append(ExecutionState.CLEANED_UP)
        return CleanupStatus.SUCCEEDED, False, False
