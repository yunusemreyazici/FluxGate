"""Safe failover execution planning and transactional adapter tests."""

from __future__ import annotations

import ast
import asyncio
import inspect
import json
import threading
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

import fluxgate.pathfinder.execution as execution_module
import fluxgate.pathfinder.execution_models as execution_models_module
import fluxgate.pathfinder.execution_planning as execution_planning_module
from fluxgate.core.models import FluxGateState
from fluxgate.pathfinder.active_models import (
    AuthorizationSource,
    FailoverAction,
    FailoverDecision,
)
from fluxgate.pathfinder.authorization import AuthorizedCandidateInventory
from fluxgate.pathfinder.execution import (
    ExecutionAdapterError,
    ExecutionCancellation,
    ExecutionLockRegistry,
    FailoverExecutor,
)
from fluxgate.pathfinder.execution_models import (
    CleanupStatus,
    ExecutionCapability,
    ExecutionFailureType,
    ExecutionPlanStatus,
    ExecutionPolicy,
    ExecutionState,
    ExecutionStatus,
    ExecutionStrategy,
    RollbackStatus,
    VerificationStatus,
)
from fluxgate.pathfinder.execution_planning import plan_failover_execution
from fluxgate.pathfinder.models import (
    ConnectionCandidate,
    ConnectionMode,
    IPFamily,
    PathfinderProtocol,
    PathfinderProvider,
    PathfinderSecurity,
    PathfinderTransport,
)

SENTINEL_SECRET = "EXECUTION-SENTINEL-PRIVATE-SECRET"  # noqa: S105 - leak sentinel
SERVER_ID = UUID("00000000-0000-4000-8000-000000000001")
PROFILE_A = UUID("00000000-0000-4000-8000-00000000000a")
PROFILE_B = UUID("00000000-0000-4000-8000-00000000000b")


def candidate(
    candidate_id: str,
    *,
    protocol: PathfinderProtocol = PathfinderProtocol.VLESS,
    profile_id: UUID = PROFILE_A,
    port: int = 443,
    enabled: bool = True,
) -> ConnectionCandidate:
    return ConnectionCandidate(
        candidate_id=candidate_id,
        provider=PathfinderProvider.SINGBOX,
        profile_id=profile_id,
        protocol=protocol,
        transport=PathfinderTransport.TCP,
        security=PathfinderSecurity.TLS,
        connection_mode=ConnectionMode.LOCAL_PROXY,
        endpoint="server.example",
        port=port,
        socket_protocol="tcp",
        ip_families=(IPFamily.IPV4, IPFamily.IPV6),
        enabled=enabled,
    )


def udp_or_quic_candidate(protocol: PathfinderProtocol) -> ConnectionCandidate:
    shapes = {
        PathfinderProtocol.WIREGUARD: (
            PathfinderProvider.WIREGUARD,
            PathfinderTransport.UDP,
            PathfinderSecurity.WIREGUARD,
            ConnectionMode.SYSTEM_TUNNEL,
        ),
        PathfinderProtocol.AMNEZIAWG: (
            PathfinderProvider.AMNEZIAWG,
            PathfinderTransport.UDP,
            PathfinderSecurity.WIREGUARD,
            ConnectionMode.SYSTEM_TUNNEL,
        ),
        PathfinderProtocol.OPENVPN: (
            PathfinderProvider.OPENVPN,
            PathfinderTransport.UDP,
            PathfinderSecurity.TLS,
            ConnectionMode.SYSTEM_TUNNEL,
        ),
        PathfinderProtocol.HYSTERIA2: (
            PathfinderProvider.SINGBOX,
            PathfinderTransport.QUIC,
            PathfinderSecurity.TLS,
            ConnectionMode.LOCAL_PROXY,
        ),
    }
    provider, transport, security, connection_mode = shapes[protocol]
    return ConnectionCandidate(
        candidate_id=f"udp:{protocol.value}",
        provider=provider,
        protocol=protocol,
        transport=transport,
        security=security,
        connection_mode=connection_mode,
        endpoint="server.example",
        port=51820,
        socket_protocol="udp",
        ip_families=(IPFamily.IPV4,),
    )


def inventory(
    *candidates: ConnectionCandidate,
    endpoint: str = "server.example",
    addresses: tuple[str, ...] = ("192.0.2.10", "2001:db8::10"),
) -> AuthorizedCandidateInventory:
    return AuthorizedCandidateInventory(
        source=AuthorizationSource.LOCAL_STATE,
        endpoint=endpoint,
        server_id=SERVER_ID,
        authorized_addresses=addresses,
        candidates=tuple(candidates),
    )


def capability(
    *, strategy: ExecutionStrategy = ExecutionStrategy.MAKE_BEFORE_BREAK
) -> ExecutionCapability:
    return ExecutionCapability(
        adapter_id="test.local-proxy",
        strategy=strategy,
        supported_providers=(PathfinderProvider.SINGBOX,),
        supported_protocols=(PathfinderProtocol.VLESS, PathfinderProtocol.TROJAN),
        supported_transports=(PathfinderTransport.TCP,),
        supported_security=(PathfinderSecurity.TLS,),
        supported_connection_modes=(ConnectionMode.LOCAL_PROXY,),
        verification="test adapter confirms an independently healthy target",
    )


def policy(**updates: float | bool) -> ExecutionPolicy:
    defaults: dict[str, float | bool] = {
        "prepare_timeout_seconds": 0.2,
        "activation_timeout_seconds": 0.2,
        "verification_timeout_seconds": 0.2,
        "commit_timeout_seconds": 0.2,
        "rollback_timeout_seconds": 0.2,
        "cleanup_timeout_seconds": 0.2,
    }
    defaults.update(updates)
    return ExecutionPolicy.model_validate(defaults)


def switch_decision(
    *, current: str | None = "current", target: str | None = "target"
) -> FailoverDecision:
    return FailoverDecision(
        action=FailoverAction.SWITCH,
        current_candidate_id=current,
        target_candidate_id=target,
        reason="verified target is better",
    )


def ready_plan(
    authorized: AuthorizedCandidateInventory | None = None,
    *,
    execution_scope: str = "client-a:runtime",
    execution_policy: ExecutionPolicy | None = None,
) -> tuple[AuthorizedCandidateInventory, object]:
    current = candidate("current", protocol=PathfinderProtocol.TROJAN, profile_id=PROFILE_A)
    target = candidate("target", protocol=PathfinderProtocol.VLESS, profile_id=PROFILE_B, port=8443)
    selected_inventory = authorized or inventory(current, target)
    plan = plan_failover_execution(
        selected_inventory,
        switch_decision(),
        (capability(),),
        execution_policy or policy(),
        execution_scope=execution_scope,
    )
    return selected_inventory, plan


@dataclass
class DeterministicAdapter:
    """Stateful test adapter; transaction behavior itself is never mocked."""

    declared_capability: ExecutionCapability = field(default_factory=capability)
    active: bool = False
    failures: set[str] = field(default_factory=set)
    internal_failures: set[str] = field(default_factory=set)
    hangs: set[str] = field(default_factory=set)
    blocked: set[str] = field(default_factory=set)
    verification_result: bool = True
    calls: list[str] = field(default_factory=list)
    started: dict[str, asyncio.Event] = field(default_factory=dict)
    releases: dict[str, asyncio.Event] = field(default_factory=dict)
    active_phase_count: int = 0
    maximum_active_phases: int = 0
    private_secret: str = SENTINEL_SECRET

    @property
    def capability(self) -> ExecutionCapability:
        return self.declared_capability

    async def _phase(self, name: str) -> None:
        self.calls.append(name)
        self.active_phase_count += 1
        self.maximum_active_phases = max(self.maximum_active_phases, self.active_phase_count)
        try:
            self.started.setdefault(name, asyncio.Event()).set()
            if name in self.blocked:
                await self.releases.setdefault(name, asyncio.Event()).wait()
            if name in self.hangs:
                await asyncio.sleep(3600)
            if name in self.failures:
                raise ExecutionAdapterError(f"adapter failed with {self.private_secret}")
            if name in self.internal_failures:
                raise RuntimeError(f"bug contains {self.private_secret}")
        finally:
            self.active_phase_count -= 1

    async def is_active_and_verified(self, plan: object) -> bool:
        await self._phase("precondition")
        return self.active

    async def prepare(self, plan: object) -> None:
        await self._phase("prepare")

    async def activate(self, plan: object) -> None:
        await self._phase("activation")

    async def verify(self, plan: object) -> bool:
        await self._phase("verification")
        return self.verification_result

    async def commit(self, plan: object) -> None:
        await self._phase("commit")
        self.active = True

    async def rollback(self, plan: object) -> None:
        await self._phase("rollback")

    async def cleanup(self, plan: object) -> None:
        await self._phase("cleanup")


def execute(
    authorized: AuthorizedCandidateInventory,
    plan: object,
    adapter: DeterministicAdapter | None,
    *,
    cancellation: ExecutionCancellation | None = None,
) -> object:
    executor = FailoverExecutor(lambda: authorized)
    return asyncio.run(executor.execute(plan, adapter, cancellation=cancellation))  # type: ignore[arg-type]


def test_stay_produces_deterministic_no_action_plan() -> None:
    authorized = inventory(candidate("current"))
    decision = FailoverDecision(
        action=FailoverAction.STAY,
        current_candidate_id="current",
        target_candidate_id="current",
        reason="current remains best",
    )
    first = plan_failover_execution(
        authorized, decision, (), policy(), execution_scope="client-a:runtime"
    )
    second = plan_failover_execution(
        authorized, decision, (), policy(), execution_scope="client-a:runtime"
    )
    assert first == second
    assert first.status == ExecutionPlanStatus.NO_ACTION
    assert first.execution_supported is True
    assert first.adapter is None


def test_valid_switch_plan_is_inspectable_secret_free_and_bound() -> None:
    _, plan = ready_plan()
    payload = plan.model_dump_json(indent=2)  # type: ignore[union-attr]
    assert plan.status == ExecutionPlanStatus.READY  # type: ignore[union-attr]
    assert plan.target.candidate.candidate_id == "target"  # type: ignore[union-attr]
    assert plan.rollback_target_candidate_id == "current"  # type: ignore[union-attr]
    assert plan.adapter.strategy == ExecutionStrategy.MAKE_BEFORE_BREAK  # type: ignore[union-attr]
    assert "fingerprint" in payload
    assert SENTINEL_SECRET not in payload


@pytest.mark.parametrize("target", [None, "missing"])
def test_missing_switch_target_is_invalid(target: str | None) -> None:
    authorized = inventory(candidate("current"))
    plan = plan_failover_execution(
        authorized,
        switch_decision(target=target),
        (capability(),),
        policy(),
        execution_scope="client-a:runtime",
    )
    assert plan.status == ExecutionPlanStatus.INVALID
    assert plan.execution_supported is False


def test_disabled_target_is_not_executable() -> None:
    authorized = inventory(candidate("current"), candidate("target", enabled=False))
    plan = plan_failover_execution(
        authorized,
        switch_decision(),
        (capability(),),
        policy(),
        execution_scope="client-a:runtime",
    )
    assert plan.status == ExecutionPlanStatus.INVALID


def test_disabled_rollback_candidate_is_not_executable() -> None:
    authorized = inventory(candidate("current", enabled=False), candidate("target"))
    plan = plan_failover_execution(
        authorized,
        switch_decision(),
        (capability(),),
        policy(),
        execution_scope="client-a:runtime",
    )
    assert plan.status == ExecutionPlanStatus.INVALID


def test_missing_named_rollback_candidate_is_not_executable() -> None:
    authorized = inventory(candidate("target"))
    plan = plan_failover_execution(
        authorized,
        switch_decision(current="missing", target="target"),
        (capability(),),
        policy(),
        execution_scope="client-a:runtime",
    )
    assert plan.status == ExecutionPlanStatus.INVALID


def test_switch_to_current_candidate_is_invalid() -> None:
    authorized = inventory(candidate("current"))
    plan = plan_failover_execution(
        authorized,
        switch_decision(current="current", target="current"),
        (capability(),),
        policy(),
        execution_scope="client-a:runtime",
    )
    assert plan.status == ExecutionPlanStatus.INVALID


def test_ready_plan_model_rejects_same_bound_current_and_target() -> None:
    _, plan = ready_plan()
    assert plan.target is not None  # type: ignore[union-attr]
    payload = plan.model_dump()  # type: ignore[union-attr]
    payload["current"] = payload["target"]
    payload["rollback_target_candidate_id"] = plan.target.candidate.candidate_id  # type: ignore[union-attr]
    with pytest.raises(ValidationError):
        type(plan).model_validate(payload)


def test_unsupported_adapter_is_explicitly_plan_only() -> None:
    authorized = inventory(candidate("current"), candidate("target"))
    plan = plan_failover_execution(
        authorized,
        switch_decision(),
        (),
        policy(),
        execution_scope="client-a:runtime",
    )
    assert plan.status == ExecutionPlanStatus.UNSUPPORTED
    assert plan.target is not None
    assert plan.execution_supported is False
    assert plan.unsupported_reason is not None


def test_break_before_make_requires_explicit_policy_permission() -> None:
    authorized = inventory(candidate("current"), candidate("target"))
    denied = plan_failover_execution(
        authorized,
        switch_decision(),
        (capability(strategy=ExecutionStrategy.BREAK_BEFORE_MAKE),),
        policy(),
        execution_scope="client-a:runtime",
    )
    allowed = plan_failover_execution(
        authorized,
        switch_decision(),
        (capability(strategy=ExecutionStrategy.BREAK_BEFORE_MAKE),),
        policy(allow_break_before_make=True),
        execution_scope="client-a:runtime",
    )
    assert denied.status == ExecutionPlanStatus.UNSUPPORTED
    assert allowed.status == ExecutionPlanStatus.READY


def test_adapter_selection_is_deterministic_by_identifier() -> None:
    authorized = inventory(candidate("current"), candidate("target"))
    later = capability().model_copy(update={"adapter_id": "zzz.adapter"})
    earlier = capability().model_copy(update={"adapter_id": "aaa.adapter"})
    plan = plan_failover_execution(
        authorized,
        switch_decision(),
        (later, earlier),
        policy(),
        execution_scope="client-a:runtime",
    )
    assert plan.adapter is not None
    assert plan.adapter.adapter_id == "aaa.adapter"


def test_duplicate_adapter_identifiers_make_plan_invalid() -> None:
    authorized = inventory(candidate("current"), candidate("target"))
    duplicate = capability().model_copy(update={"verification": "different check"})
    plan = plan_failover_execution(
        authorized,
        switch_decision(),
        (capability(), duplicate),
        policy(),
        execution_scope="client-a:runtime",
    )
    assert plan.status == ExecutionPlanStatus.INVALID


def test_duplicate_adapter_ids_are_invalid_even_if_one_does_not_support_target() -> None:
    authorized = inventory(candidate("current"), candidate("target"))
    unsupported_duplicate = capability().model_copy(
        update={
            "supported_protocols": (PathfinderProtocol.HYSTERIA2,),
            "supported_transports": (PathfinderTransport.QUIC,),
        }
    )
    plan = plan_failover_execution(
        authorized,
        switch_decision(),
        (capability(), unsupported_duplicate),
        policy(),
        execution_scope="client-a:runtime",
    )
    assert plan.status == ExecutionPlanStatus.INVALID


@pytest.mark.parametrize(
    "protocol",
    [
        PathfinderProtocol.WIREGUARD,
        PathfinderProtocol.AMNEZIAWG,
        PathfinderProtocol.OPENVPN,
        PathfinderProtocol.HYSTERIA2,
    ],
)
def test_udp_and_quic_candidates_have_no_execution_adapter(
    protocol: PathfinderProtocol,
) -> None:
    target = udp_or_quic_candidate(protocol)
    authorized = inventory(candidate("current"), target)
    plan = plan_failover_execution(
        authorized,
        switch_decision(target=target.candidate_id),
        (capability(),),
        policy(),
        execution_scope="client-a:runtime",
    )
    assert plan.status == ExecutionPlanStatus.UNSUPPORTED
    assert plan.execution_supported is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("prepare_timeout_seconds", 0.0),
        ("activation_timeout_seconds", -1.0),
        ("verification_timeout_seconds", 121.0),
        ("commit_timeout_seconds", 61.0),
        ("rollback_timeout_seconds", float("inf")),
        ("cleanup_timeout_seconds", float("nan")),
        ("transaction_timeout_seconds", 601.0),
    ],
)
def test_execution_policy_rejects_unbounded_timeouts(field: str, value: float) -> None:
    with pytest.raises(ValidationError):
        ExecutionPolicy.model_validate({field: value})


def test_execution_policy_requires_all_phase_budgets_to_fit_total_timeout() -> None:
    with pytest.raises(ValidationError):
        ExecutionPolicy(
            prepare_timeout_seconds=30.0,
            activation_timeout_seconds=30.0,
            verification_timeout_seconds=30.0,
            commit_timeout_seconds=10.0,
            rollback_timeout_seconds=30.0,
            cleanup_timeout_seconds=10.0,
            transaction_timeout_seconds=100.0,
        )


def test_binding_rejects_malformed_fingerprint() -> None:
    _, plan = ready_plan()
    assert plan.target is not None  # type: ignore[union-attr]
    payload = plan.target.model_dump(mode="json")  # type: ignore[union-attr]
    payload["fingerprint"] = "not-a-sha256"
    with pytest.raises(ValidationError):
        type(plan.target).model_validate_json(json.dumps(payload))  # type: ignore[arg-type,union-attr]


def test_models_reject_unknown_strategy_and_status_values() -> None:
    capability_payload = capability().model_dump(mode="json")
    capability_payload["strategy"] = "future-strategy"
    with pytest.raises(ValidationError):
        ExecutionCapability.model_validate_json(json.dumps(capability_payload))

    authorized, plan = ready_plan()
    result = execute(authorized, plan, DeterministicAdapter())
    result_payload = result.model_dump(mode="json")  # type: ignore[union-attr]
    result_payload["status"] = "future-status"
    with pytest.raises(ValidationError):
        type(result).model_validate_json(json.dumps(result_payload))


def test_full_transaction_requires_verification_before_commit() -> None:
    authorized, plan = ready_plan()
    adapter = DeterministicAdapter()
    result = execute(authorized, plan, adapter)
    assert result.status == ExecutionStatus.COMMITTED  # type: ignore[union-attr]
    assert result.verification == VerificationStatus.SUCCEEDED  # type: ignore[union-attr]
    assert result.rollback == RollbackStatus.NOT_NEEDED  # type: ignore[union-attr]
    assert result.cleanup == CleanupStatus.SUCCEEDED  # type: ignore[union-attr]
    assert adapter.calls == [
        "precondition",
        "prepare",
        "activation",
        "verification",
        "commit",
        "cleanup",
    ]
    assert result.state_history == (  # type: ignore[union-attr]
        ExecutionState.PLANNED,
        ExecutionState.PREPARING,
        ExecutionState.PREPARED,
        ExecutionState.ACTIVATING,
        ExecutionState.VERIFYING,
        ExecutionState.COMMITTING,
        ExecutionState.COMMITTED,
        ExecutionState.CLEANING_UP,
        ExecutionState.CLEANED_UP,
    )


def test_result_model_rejects_an_impossible_state_transition() -> None:
    authorized, plan = ready_plan()
    result = execute(authorized, plan, DeterministicAdapter())
    payload = result.model_dump()  # type: ignore[union-attr]
    payload["state_history"] = (ExecutionState.PLANNED, ExecutionState.COMMITTED)
    with pytest.raises(ValidationError):
        type(result).model_validate(payload)


@pytest.mark.parametrize(
    "status",
    [
        ExecutionStatus.NO_ACTION,
        ExecutionStatus.ALREADY_CONVERGED,
        ExecutionStatus.REJECTED,
    ],
)
def test_result_model_rejects_lifecycle_history_for_non_mutating_status(
    status: ExecutionStatus,
) -> None:
    authorized, plan = ready_plan()
    result = execute(authorized, plan, DeterministicAdapter())
    payload = result.model_dump()  # type: ignore[union-attr]
    payload.update(
        status=status,
        failure_type=(
            ExecutionFailureType.INVALID_DECISION if status == ExecutionStatus.REJECTED else None
        ),
        verification=(
            VerificationStatus.SUCCEEDED
            if status == ExecutionStatus.ALREADY_CONVERGED
            else VerificationStatus.NOT_RUN
        ),
    )
    with pytest.raises(ValidationError):
        type(result).model_validate(payload)


@pytest.mark.parametrize(
    ("phase", "failure_type", "verification"),
    [
        ("prepare", ExecutionFailureType.PREPARE_FAILURE, VerificationStatus.NOT_RUN),
        ("activation", ExecutionFailureType.ACTIVATION_FAILURE, VerificationStatus.NOT_RUN),
        ("verification", ExecutionFailureType.VERIFICATION_FAILURE, VerificationStatus.FAILED),
        ("commit", ExecutionFailureType.COMMIT_FAILURE, VerificationStatus.SUCCEEDED),
    ],
)
def test_expected_phase_failure_rolls_back(
    phase: str,
    failure_type: ExecutionFailureType,
    verification: VerificationStatus,
) -> None:
    authorized, plan = ready_plan()
    adapter = DeterministicAdapter(failures={phase})
    result = execute(authorized, plan, adapter)
    assert result.status == ExecutionStatus.ROLLED_BACK  # type: ignore[union-attr]
    assert result.failure_type == failure_type  # type: ignore[union-attr]
    assert result.verification == verification  # type: ignore[union-attr]
    assert result.rollback == RollbackStatus.SUCCEEDED  # type: ignore[union-attr]
    assert adapter.calls[-2:] == ["rollback", "cleanup"]
    assert "commit" not in adapter.calls or phase == "commit"


def test_negative_verification_never_commits() -> None:
    authorized, plan = ready_plan()
    adapter = DeterministicAdapter(verification_result=False)
    result = execute(authorized, plan, adapter)
    assert result.status == ExecutionStatus.ROLLED_BACK  # type: ignore[union-attr]
    assert result.failure_type == ExecutionFailureType.VERIFICATION_FAILURE  # type: ignore[union-attr]
    assert result.verification == VerificationStatus.FAILED  # type: ignore[union-attr]
    assert "commit" not in adapter.calls


def test_unexpected_adapter_bug_is_not_mislabeled_as_network_failure() -> None:
    authorized, plan = ready_plan()
    adapter = DeterministicAdapter(internal_failures={"activation"})
    result = execute(authorized, plan, adapter)
    assert result.status == ExecutionStatus.ROLLED_BACK  # type: ignore[union-attr]
    assert result.failure_type == ExecutionFailureType.INTERNAL_ERROR  # type: ignore[union-attr]
    assert SENTINEL_SECRET not in result.model_dump_json()  # type: ignore[union-attr]


def test_rollback_failure_is_prominent() -> None:
    authorized, plan = ready_plan()
    adapter = DeterministicAdapter(failures={"verification", "rollback"})
    result = execute(authorized, plan, adapter)
    assert result.status == ExecutionStatus.ROLLBACK_FAILED  # type: ignore[union-attr]
    assert result.failure_type == ExecutionFailureType.ROLLBACK_FAILURE  # type: ignore[union-attr]
    assert result.rollback == RollbackStatus.FAILED  # type: ignore[union-attr]
    assert ExecutionState.ROLLBACK_FAILED in result.state_history  # type: ignore[union-attr]


@pytest.mark.parametrize("initial_failure", [None, "verification"])
def test_cleanup_failure_is_distinct(initial_failure: str | None) -> None:
    authorized, plan = ready_plan()
    failures = {"cleanup"}
    if initial_failure is not None:
        failures.add(initial_failure)
    adapter = DeterministicAdapter(failures=failures)
    result = execute(authorized, plan, adapter)
    assert result.status == ExecutionStatus.CLEANUP_FAILED  # type: ignore[union-attr]
    assert result.failure_type == ExecutionFailureType.CLEANUP_FAILURE  # type: ignore[union-attr]
    assert result.cleanup == CleanupStatus.FAILED  # type: ignore[union-attr]


def test_cleanup_failure_model_requires_consistent_prior_transaction() -> None:
    authorized, plan = ready_plan()
    result = execute(authorized, plan, DeterministicAdapter(failures={"cleanup"}))
    payload = result.model_dump()  # type: ignore[union-attr]
    payload["verification"] = VerificationStatus.NOT_RUN
    with pytest.raises(ValidationError):
        type(result).model_validate(payload)


@pytest.mark.parametrize("phase", ["prepare", "activation", "verification", "commit"])
def test_mutating_phase_timeout_is_bounded_and_rolls_back(phase: str) -> None:
    authorized, plan = ready_plan(
        execution_policy=policy(
            prepare_timeout_seconds=0.01,
            activation_timeout_seconds=0.01,
            verification_timeout_seconds=0.01,
            commit_timeout_seconds=0.01,
        )
    )
    adapter = DeterministicAdapter(hangs={phase})

    async def run() -> tuple[object, int]:
        executor = FailoverExecutor(lambda: authorized)
        result = await executor.execute(plan, adapter)  # type: ignore[arg-type]
        return result, executor.pending_adapter_tasks

    result, pending = asyncio.run(run())
    assert result.status == ExecutionStatus.ROLLED_BACK  # type: ignore[union-attr]
    assert result.failure_type == ExecutionFailureType.TIMEOUT  # type: ignore[union-attr]
    assert result.rollback == RollbackStatus.SUCCEEDED  # type: ignore[union-attr]
    assert pending == 0


def test_precondition_timeout_performs_no_lifecycle_activity() -> None:
    authorized, plan = ready_plan(execution_policy=policy(verification_timeout_seconds=0.01))
    adapter = DeterministicAdapter(hangs={"precondition"})
    result = execute(authorized, plan, adapter)
    assert result.status == ExecutionStatus.REJECTED  # type: ignore[union-attr]
    assert result.failure_type == ExecutionFailureType.TIMEOUT  # type: ignore[union-attr]
    assert adapter.calls == ["precondition"]


def test_adapter_completing_during_cancellation_grace_is_rolled_back() -> None:
    authorized, plan = ready_plan(execution_policy=policy(prepare_timeout_seconds=0.01))

    class GraceCompletingAdapter(DeterministicAdapter):
        completed_after_cancel: bool = False

        async def prepare(self, plan: object) -> None:
            self.calls.append("prepare")
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                self.completed_after_cancel = True

    async def run() -> tuple[object, GraceCompletingAdapter, tuple[str, ...]]:
        adapter = GraceCompletingAdapter()
        locks = ExecutionLockRegistry()
        executor = FailoverExecutor(lambda: authorized, locks=locks)
        result = await executor.execute(plan, adapter)  # type: ignore[arg-type]
        return result, adapter, locks.quarantined_scopes

    result, adapter, quarantined = asyncio.run(run())
    assert adapter.completed_after_cancel is True
    assert result.status == ExecutionStatus.ROLLED_BACK  # type: ignore[union-attr]
    assert result.failure_type == ExecutionFailureType.TIMEOUT  # type: ignore[union-attr]
    assert result.rollback == RollbackStatus.SUCCEEDED  # type: ignore[union-attr]
    assert quarantined == ()


def test_precondition_adapter_failure_is_typed_and_non_mutating() -> None:
    authorized, plan = ready_plan()
    adapter = DeterministicAdapter(failures={"precondition"})
    result = execute(authorized, plan, adapter)
    assert result.status == ExecutionStatus.REJECTED  # type: ignore[union-attr]
    assert result.failure_type == ExecutionFailureType.PRECONDITION_FAILURE  # type: ignore[union-attr]
    assert adapter.calls == ["precondition"]


@pytest.mark.parametrize("phase", ["rollback", "cleanup"])
def test_recovery_phase_timeout_is_bounded_and_prominent(phase: str) -> None:
    authorized, plan = ready_plan(
        execution_policy=policy(
            rollback_timeout_seconds=0.01,
            cleanup_timeout_seconds=0.01,
        )
    )
    failures = {"verification"} if phase == "rollback" else set()
    adapter = DeterministicAdapter(failures=failures, hangs={phase})
    result = execute(authorized, plan, adapter)
    expected = (
        ExecutionStatus.ROLLBACK_FAILED if phase == "rollback" else ExecutionStatus.CLEANUP_FAILED
    )
    assert result.status == expected  # type: ignore[union-attr]
    assert result.failure_type == ExecutionFailureType.TIMEOUT  # type: ignore[union-attr]


@pytest.mark.parametrize("phase", ["rollback", "cleanup"])
def test_cancellation_violating_recovery_phase_surfaces_quarantine(phase: str) -> None:
    authorized, plan = ready_plan(
        execution_policy=policy(
            rollback_timeout_seconds=0.01,
            cleanup_timeout_seconds=0.01,
        )
    )

    class LateRecoveryAdapter(DeterministicAdapter):
        async def rollback(self, plan: object) -> None:
            if phase != "rollback":
                await super().rollback(plan)
                return
            self.calls.append("rollback")
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                await self.releases.setdefault("rollback", asyncio.Event()).wait()

        async def cleanup(self, plan: object) -> None:
            if phase != "cleanup":
                await super().cleanup(plan)
                return
            self.calls.append("cleanup")
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                await self.releases.setdefault("cleanup", asyncio.Event()).wait()

    async def run() -> tuple[object, tuple[str, ...]]:
        failures = {"verification"} if phase == "rollback" else set()
        adapter = LateRecoveryAdapter(failures=failures)
        locks = ExecutionLockRegistry()
        executor = FailoverExecutor(lambda: authorized, locks=locks)
        result = await executor.execute(plan, adapter)  # type: ignore[arg-type]
        quarantined = locks.quarantined_scopes
        adapter.releases.setdefault(phase, asyncio.Event()).set()
        while executor.pending_adapter_tasks:
            await asyncio.sleep(0)
        return result, quarantined

    result, quarantined = asyncio.run(run())
    assert result.failure_type == ExecutionFailureType.TIMEOUT  # type: ignore[union-attr]
    assert "scope is quarantined" in result.reason  # type: ignore[union-attr]
    assert quarantined == ("client-a:runtime",)


@pytest.mark.parametrize("phase", ["prepare", "activation", "verification"])
def test_cancellation_rolls_back_without_orphan_tasks(phase: str) -> None:
    authorized, plan = ready_plan()

    async def run() -> tuple[object, DeterministicAdapter, int]:
        adapter = DeterministicAdapter(blocked={phase})
        cancellation = ExecutionCancellation()
        executor = FailoverExecutor(lambda: authorized)
        task = asyncio.create_task(executor.execute(plan, adapter, cancellation=cancellation))  # type: ignore[arg-type]
        await adapter.started.setdefault(phase, asyncio.Event()).wait()
        cancellation.cancel()
        result = await task
        return result, adapter, executor.pending_adapter_tasks

    result, adapter, pending = asyncio.run(run())
    assert result.status == ExecutionStatus.CANCELLED  # type: ignore[union-attr]
    assert result.failure_type == ExecutionFailureType.CANCELLATION  # type: ignore[union-attr]
    assert result.rollback == RollbackStatus.SUCCEEDED  # type: ignore[union-attr]
    assert "rollback" in adapter.calls
    assert pending == 0


def test_pre_cancelled_request_never_starts_adapter_lifecycle() -> None:
    authorized, plan = ready_plan()
    cancellation = ExecutionCancellation()
    cancellation.cancel()
    adapter = DeterministicAdapter()
    result = execute(authorized, plan, adapter, cancellation=cancellation)
    assert result.status == ExecutionStatus.CANCELLED  # type: ignore[union-attr]
    assert adapter.calls == []


def test_cancelled_result_model_requires_cancellation_failure_type() -> None:
    authorized, plan = ready_plan()
    cancellation = ExecutionCancellation()
    cancellation.cancel()
    result = execute(
        authorized,
        plan,
        DeterministicAdapter(),
        cancellation=cancellation,
    )
    payload = result.model_dump()  # type: ignore[union-attr]
    payload["failure_type"] = ExecutionFailureType.TIMEOUT
    with pytest.raises(ValidationError):
        type(result).model_validate(payload)


def test_caller_task_cancellation_is_typed_and_rolls_back() -> None:
    authorized, plan = ready_plan()

    async def run() -> tuple[object, DeterministicAdapter]:
        adapter = DeterministicAdapter(blocked={"activation"})
        executor = FailoverExecutor(lambda: authorized)
        task = asyncio.create_task(executor.execute(plan, adapter))  # type: ignore[arg-type]
        await adapter.started.setdefault("activation", asyncio.Event()).wait()
        task.cancel()
        return await task, adapter

    result, adapter = asyncio.run(run())
    assert result.status == ExecutionStatus.CANCELLED  # type: ignore[union-attr]
    assert result.rollback == RollbackStatus.SUCCEEDED  # type: ignore[union-attr]
    assert "rollback" in adapter.calls


def test_caller_cancellation_cannot_interrupt_bounded_rollback() -> None:
    authorized, plan = ready_plan()

    async def run() -> tuple[object, DeterministicAdapter]:
        adapter = DeterministicAdapter(failures={"verification"}, blocked={"rollback"})
        executor = FailoverExecutor(lambda: authorized)
        task = asyncio.create_task(executor.execute(plan, adapter))  # type: ignore[arg-type]
        await adapter.started.setdefault("rollback", asyncio.Event()).wait()
        task.cancel()
        adapter.releases.setdefault("rollback", asyncio.Event()).set()
        return await task, adapter

    result, adapter = asyncio.run(run())
    assert result.status == ExecutionStatus.ROLLED_BACK  # type: ignore[union-attr]
    assert result.failure_type == ExecutionFailureType.VERIFICATION_FAILURE  # type: ignore[union-attr]
    assert result.rollback == RollbackStatus.SUCCEEDED  # type: ignore[union-attr]
    assert adapter.calls[-2:] == ["rollback", "cleanup"]


def test_caller_cancellation_cannot_interrupt_bounded_cleanup() -> None:
    authorized, plan = ready_plan()

    async def run() -> tuple[object, DeterministicAdapter]:
        adapter = DeterministicAdapter(blocked={"cleanup"})
        executor = FailoverExecutor(lambda: authorized)
        task = asyncio.create_task(executor.execute(plan, adapter))  # type: ignore[arg-type]
        await adapter.started.setdefault("cleanup", asyncio.Event()).wait()
        task.cancel()
        adapter.releases.setdefault("cleanup", asyncio.Event()).set()
        return await task, adapter

    result, adapter = asyncio.run(run())
    assert result.status == ExecutionStatus.COMMITTED  # type: ignore[union-attr]
    assert result.cleanup == CleanupStatus.SUCCEEDED  # type: ignore[union-attr]
    assert adapter.calls[-1] == "cleanup"


def test_cancellation_violating_adapter_is_bounded_and_scope_is_quarantined() -> None:
    authorized, plan = ready_plan(execution_policy=policy(prepare_timeout_seconds=0.01))

    class CancellationViolatingAdapter(DeterministicAdapter):
        async def prepare(self, plan: object) -> None:
            self.calls.append("prepare")
            self.started.setdefault("prepare", asyncio.Event()).set()
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                await self.releases.setdefault("prepare", asyncio.Event()).wait()

    async def run() -> tuple[object, object, int, tuple[str, ...], bool, object]:
        adapter = CancellationViolatingAdapter()
        locks = ExecutionLockRegistry()
        executor = FailoverExecutor(lambda: authorized, locks=locks)
        first = await executor.execute(plan, adapter)  # type: ignore[arg-type]
        second_executor = FailoverExecutor(lambda: authorized, locks=locks)
        second = await second_executor.execute(plan, DeterministicAdapter())  # type: ignore[arg-type]
        adapter.releases.setdefault("prepare", asyncio.Event()).set()
        while executor.pending_adapter_tasks:
            await asyncio.sleep(0)
        quarantined = locks.quarantined_scopes
        acknowledged = locks.acknowledge_reconciled(plan.execution_scope)  # type: ignore[union-attr]
        third = await second_executor.execute(plan, DeterministicAdapter())  # type: ignore[arg-type]
        return (
            first,
            second,
            executor.pending_adapter_tasks,
            quarantined,
            acknowledged,
            third,
        )

    first, second, pending, quarantined, acknowledged, third = asyncio.run(run())
    assert first.status == ExecutionStatus.ROLLBACK_FAILED  # type: ignore[union-attr]
    assert first.failure_type == ExecutionFailureType.ROLLBACK_FAILURE  # type: ignore[union-attr]
    assert second.failure_type == ExecutionFailureType.EXECUTION_CONFLICT  # type: ignore[union-attr]
    assert pending == 0
    assert quarantined == ("client-a:runtime",)
    assert acknowledged is True
    assert third.status == ExecutionStatus.COMMITTED  # type: ignore[union-attr]


def test_quarantine_cannot_clear_while_late_adapter_task_is_running() -> None:
    async def run() -> tuple[bool, bool]:
        locks = ExecutionLockRegistry()
        release = asyncio.Event()

        async def late_work() -> None:
            await release.wait()

        task = asyncio.create_task(late_work())
        assert locks.try_acquire("client-a:runtime") is True
        locks.quarantine("client-a:runtime", task)
        locks.release("client-a:runtime")
        before = locks.acknowledge_reconciled("client-a:runtime")
        release.set()
        await task
        locks.adapter_task_completed("client-a:runtime", task)
        after = locks.acknowledge_reconciled("client-a:runtime")
        return before, after

    before, after = asyncio.run(run())
    assert before is False
    assert after is True


def test_registry_bounds_active_scopes_and_releases_scope_entries() -> None:
    locks = ExecutionLockRegistry(max_active_executions=2)
    assert locks.try_acquire("client-a:runtime") is True
    assert locks.try_acquire("client-b:runtime") is True
    assert locks.try_acquire("client-c:runtime") is False
    locks.release("client-a:runtime")
    assert locks.try_acquire("client-c:runtime") is True
    locks.release("client-b:runtime")
    locks.release("client-c:runtime")
    for index in range(1000):
        scope = f"client-{index}:runtime"
        assert locks.try_acquire(scope) is True
        locks.release(scope)


def test_completed_quarantines_still_count_toward_global_scope_capacity() -> None:
    async def run() -> tuple[bool, bool]:
        locks = ExecutionLockRegistry(max_active_executions=2)
        for scope in ("client-a:runtime", "client-b:runtime"):
            task = asyncio.create_task(asyncio.sleep(0))
            assert locks.try_acquire(scope) is True
            locks.quarantine(scope, task)
            locks.release(scope)
            await task
            locks.adapter_task_completed(scope, task)
        before = locks.try_acquire("client-c:runtime")
        assert locks.acknowledge_reconciled("client-a:runtime") is True
        after = locks.try_acquire("client-c:runtime")
        if after:
            locks.release("client-c:runtime")
        return before, after

    before, after = asyncio.run(run())
    assert before is False
    assert after is True


def test_registry_refuses_quarantine_without_active_execution_authority() -> None:
    async def run() -> None:
        locks = ExecutionLockRegistry()
        task = asyncio.create_task(asyncio.sleep(0))
        with pytest.raises(RuntimeError):
            locks.quarantine("client-a:runtime", task)
        await task

    asyncio.run(run())


def test_registry_is_thread_safe_for_simultaneous_same_scope_acquisition() -> None:
    locks = ExecutionLockRegistry()
    barrier = threading.Barrier(3)
    release = threading.Event()
    results: list[bool] = []
    results_guard = threading.Lock()

    def contend() -> None:
        barrier.wait()
        acquired = locks.try_acquire("client-a:runtime")
        with results_guard:
            results.append(acquired)
        barrier.wait()
        if acquired:
            release.wait(timeout=1.0)
            locks.release("client-a:runtime")

    workers = [threading.Thread(target=contend) for _ in range(2)]
    for worker in workers:
        worker.start()
    barrier.wait()
    barrier.wait()
    assert sorted(results) == [False, True]
    release.set()
    for worker in workers:
        worker.join(timeout=1.0)
        assert worker.is_alive() is False


@pytest.mark.parametrize("value", [True, 0, 65])
def test_registry_rejects_invalid_capacity(value: int | bool) -> None:
    with pytest.raises(ValueError):
        ExecutionLockRegistry(max_active_executions=value)


def test_registry_bounds_concurrent_cancellation_violations() -> None:
    authorized, first_plan = ready_plan(
        execution_scope="client-a:runtime",
        execution_policy=policy(prepare_timeout_seconds=0.01),
    )
    _, second_plan = ready_plan(
        authorized,
        execution_scope="client-b:runtime",
        execution_policy=policy(prepare_timeout_seconds=0.01),
    )
    _, third_plan = ready_plan(
        authorized,
        execution_scope="client-c:runtime",
        execution_policy=policy(prepare_timeout_seconds=0.01),
    )

    class LateAdapter(DeterministicAdapter):
        async def prepare(self, plan: object) -> None:
            self.calls.append("prepare")
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                await self.releases.setdefault("prepare", asyncio.Event()).wait()

    async def run() -> tuple[object, int, tuple[str, ...]]:
        locks = ExecutionLockRegistry(max_active_executions=2)
        executor = FailoverExecutor(lambda: authorized, locks=locks)
        first_adapter = LateAdapter()
        second_adapter = LateAdapter()
        first = asyncio.create_task(executor.execute(first_plan, first_adapter))  # type: ignore[arg-type]
        second = asyncio.create_task(executor.execute(second_plan, second_adapter))  # type: ignore[arg-type]
        first_result, second_result = await asyncio.gather(first, second)
        assert first_result.status == ExecutionStatus.ROLLBACK_FAILED
        assert second_result.status == ExecutionStatus.ROLLBACK_FAILED
        third_result = await executor.execute(third_plan, DeterministicAdapter())  # type: ignore[arg-type]
        pending = executor.pending_adapter_tasks
        quarantined = locks.quarantined_scopes
        first_adapter.releases.setdefault("prepare", asyncio.Event()).set()
        second_adapter.releases.setdefault("prepare", asyncio.Event()).set()
        while executor.pending_adapter_tasks:
            await asyncio.sleep(0)
        return third_result, pending, quarantined

    third_result, pending, quarantined = asyncio.run(run())
    assert third_result.failure_type == ExecutionFailureType.EXECUTION_CONFLICT  # type: ignore[union-attr]
    assert pending == 2
    assert quarantined == ("client-a:runtime", "client-b:runtime")


def test_already_converged_is_idempotent() -> None:
    authorized, plan = ready_plan()

    async def run() -> tuple[object, object, DeterministicAdapter]:
        adapter = DeterministicAdapter(active=True)
        executor = FailoverExecutor(lambda: authorized)
        first = await executor.execute(plan, adapter)  # type: ignore[arg-type]
        second = await executor.execute(plan, adapter)  # type: ignore[arg-type]
        return first, second, adapter

    first, second, adapter = asyncio.run(run())
    assert first.status == second.status == ExecutionStatus.ALREADY_CONVERGED  # type: ignore[union-attr]
    assert adapter.calls == ["precondition", "precondition"]


def test_no_action_performs_zero_adapter_activity() -> None:
    authorized = inventory(candidate("current"))
    plan = plan_failover_execution(
        authorized,
        FailoverDecision(
            action=FailoverAction.STAY,
            current_candidate_id="current",
            target_candidate_id="current",
            reason="stay",
        ),
        (),
        policy(),
        execution_scope="client-a:runtime",
    )
    adapter = DeterministicAdapter()
    result = execute(authorized, plan, adapter)
    assert result.status == ExecutionStatus.NO_ACTION  # type: ignore[union-attr]
    assert adapter.calls == []


def test_changed_candidate_fingerprint_fails_closed_before_adapter_activity() -> None:
    authorized, plan = ready_plan()
    changed = inventory(
        candidate("current", protocol=PathfinderProtocol.TROJAN, profile_id=PROFILE_A),
        candidate("target", profile_id=PROFILE_B, port=9443),
    )
    adapter = DeterministicAdapter()
    result = execute(changed, plan, adapter)
    assert result.status == ExecutionStatus.REJECTED  # type: ignore[union-attr]
    assert result.failure_type == ExecutionFailureType.STALE_DECISION  # type: ignore[union-attr]
    assert adapter.calls == []
    assert authorized != changed


def test_changed_authorization_identity_fails_as_stale() -> None:
    authorized, plan = ready_plan()
    rebound = AuthorizedCandidateInventory(
        source=AuthorizationSource.SIGNED_MANIFEST,
        endpoint=authorized.endpoint,
        server_id=authorized.server_id,
        authorized_addresses=authorized.authorized_addresses,
        candidates=authorized.candidates,
    )
    result = execute(rebound, plan, DeterministicAdapter())
    assert result.failure_type == ExecutionFailureType.STALE_DECISION  # type: ignore[union-attr]


def test_changed_rollback_candidate_fails_closed_before_adapter_activity() -> None:
    authorized, plan = ready_plan()
    changed = inventory(
        candidate("current", protocol=PathfinderProtocol.TROJAN, profile_id=PROFILE_A, port=9443),
        authorized.candidates[1],
    )
    adapter = DeterministicAdapter()
    result = execute(changed, plan, adapter)
    assert result.failure_type == ExecutionFailureType.STALE_DECISION  # type: ignore[union-attr]
    assert adapter.calls == []


def test_duplicate_authoritative_candidate_ids_fail_closed() -> None:
    authorized, plan = ready_plan()
    duplicated = inventory(*authorized.candidates, authorized.candidates[1])
    adapter = DeterministicAdapter()
    result = execute(duplicated, plan, adapter)
    assert result.failure_type == ExecutionFailureType.UNAUTHORIZED_TARGET  # type: ignore[union-attr]
    assert adapter.calls == []


def test_duplicate_candidate_ids_make_initial_plan_invalid() -> None:
    duplicate = candidate("target")
    authorized = inventory(candidate("current"), duplicate, duplicate)
    plan = plan_failover_execution(
        authorized,
        switch_decision(),
        (capability(),),
        policy(),
        execution_scope="client-a:runtime",
    )
    assert plan.status == ExecutionPlanStatus.INVALID


def test_removed_or_disabled_target_is_unauthorized_at_execution() -> None:
    authorized, plan = ready_plan()
    removed = inventory(authorized.candidates[0])
    result = execute(removed, plan, DeterministicAdapter())
    assert result.failure_type == ExecutionFailureType.UNAUTHORIZED_TARGET  # type: ignore[union-attr]


def test_tampered_plan_cannot_redirect_to_an_authorized_candidate() -> None:
    authorized, plan = ready_plan()
    attacker = candidate("attacker-choice", profile_id=PROFILE_A, port=9443)
    expanded = inventory(*authorized.candidates, attacker)
    attacker_plan = plan_failover_execution(
        expanded,
        switch_decision(target="attacker-choice"),
        (capability(),),
        policy(),
        execution_scope="client-a:runtime",
    )
    tampered = plan.model_copy(update={"target": attacker_plan.target})  # type: ignore[union-attr]
    adapter = DeterministicAdapter()
    result = execute(expanded, tampered, adapter)
    assert result.failure_type == ExecutionFailureType.INVALID_DECISION  # type: ignore[union-attr]
    assert adapter.calls == []


def test_adapter_capability_change_fails_closed() -> None:
    authorized, plan = ready_plan()
    adapter = DeterministicAdapter(
        declared_capability=capability(strategy=ExecutionStrategy.BREAK_BEFORE_MAKE)
    )
    result = execute(authorized, plan, adapter)
    assert result.failure_type == ExecutionFailureType.UNSUPPORTED_ADAPTER  # type: ignore[union-attr]
    assert adapter.calls == []


def test_same_scope_concurrent_execution_is_rejected() -> None:
    authorized, plan = ready_plan()

    async def run() -> tuple[object, object]:
        adapter = DeterministicAdapter(blocked={"prepare"})
        cancellation = ExecutionCancellation()
        executor = FailoverExecutor(lambda: authorized)
        first_task = asyncio.create_task(
            executor.execute(plan, adapter, cancellation=cancellation)  # type: ignore[arg-type]
        )
        await adapter.started.setdefault("prepare", asyncio.Event()).wait()
        second = await executor.execute(plan, DeterministicAdapter())  # type: ignore[arg-type]
        cancellation.cancel()
        first = await first_task
        return first, second

    first, second = asyncio.run(run())
    assert first.status == ExecutionStatus.CANCELLED  # type: ignore[union-attr]
    assert second.status == ExecutionStatus.REJECTED  # type: ignore[union-attr]
    assert second.failure_type == ExecutionFailureType.EXECUTION_CONFLICT  # type: ignore[union-attr]


def test_same_scope_execution_is_rejected_while_rollback_is_active() -> None:
    authorized, plan = ready_plan()

    async def run() -> tuple[object, object]:
        adapter = DeterministicAdapter(failures={"verification"}, blocked={"rollback"})
        executor = FailoverExecutor(lambda: authorized)
        first_task = asyncio.create_task(executor.execute(plan, adapter))  # type: ignore[arg-type]
        await adapter.started.setdefault("rollback", asyncio.Event()).wait()
        second = await executor.execute(plan, DeterministicAdapter())  # type: ignore[arg-type]
        adapter.releases.setdefault("rollback", asyncio.Event()).set()
        return await first_task, second

    first, second = asyncio.run(run())
    assert first.status == ExecutionStatus.ROLLED_BACK  # type: ignore[union-attr]
    assert second.failure_type == ExecutionFailureType.EXECUTION_CONFLICT  # type: ignore[union-attr]


def test_separate_executors_share_process_scope_lock() -> None:
    authorized, plan = ready_plan()

    async def run() -> tuple[object, object]:
        first_adapter = DeterministicAdapter(blocked={"prepare"})
        cancellation = ExecutionCancellation()
        first_executor = FailoverExecutor(lambda: authorized)
        second_executor = FailoverExecutor(lambda: authorized)
        first_task = asyncio.create_task(
            first_executor.execute(plan, first_adapter, cancellation=cancellation)  # type: ignore[arg-type]
        )
        await first_adapter.started.setdefault("prepare", asyncio.Event()).wait()
        second = await second_executor.execute(plan, DeterministicAdapter())  # type: ignore[arg-type]
        cancellation.cancel()
        return await first_task, second

    first, second = asyncio.run(run())
    assert first.status == ExecutionStatus.CANCELLED  # type: ignore[union-attr]
    assert second.failure_type == ExecutionFailureType.EXECUTION_CONFLICT  # type: ignore[union-attr]


def test_independent_scopes_can_progress_concurrently() -> None:
    authorized, first_plan = ready_plan(execution_scope="client-a:runtime")
    _, second_plan = ready_plan(authorized, execution_scope="client-b:runtime")

    async def run() -> DeterministicAdapter:
        adapter = DeterministicAdapter(blocked={"prepare"})
        executor = FailoverExecutor(lambda: authorized)
        first = asyncio.create_task(executor.execute(first_plan, adapter))  # type: ignore[arg-type]
        second = asyncio.create_task(executor.execute(second_plan, adapter))  # type: ignore[arg-type]
        while adapter.calls.count("prepare") < 2:
            await asyncio.sleep(0)
        adapter.releases.setdefault("prepare", asyncio.Event()).set()
        results = await asyncio.gather(first, second)
        assert all(result.status == ExecutionStatus.COMMITTED for result in results)
        return adapter

    adapter = asyncio.run(run())
    assert adapter.maximum_active_phases == 2


def test_secret_is_absent_from_result_json_and_expected_errors() -> None:
    authorized, plan = ready_plan()
    adapter = DeterministicAdapter(failures={"prepare"})
    result = execute(authorized, plan, adapter)
    combined = f"{result!r}\n{result.model_dump_json()}\n{result.reason}"  # type: ignore[union-attr]
    assert SENTINEL_SECRET not in combined


@pytest.mark.parametrize("phase", ["rollback", "cleanup"])
def test_recovery_adapter_secrets_are_absent_from_all_public_diagnostics(phase: str) -> None:
    authorized, plan = ready_plan()
    failures = {phase}
    if phase == "rollback":
        failures.add("verification")
    result = execute(authorized, plan, DeterministicAdapter(failures=failures))
    public = "\n".join(
        (
            repr(plan),  # type: ignore[arg-type]
            plan.model_dump_json(),  # type: ignore[union-attr]
            repr(result),
            result.model_dump_json(),  # type: ignore[union-attr]
            result.reason,  # type: ignore[union-attr]
        )
    )
    assert SENTINEL_SECRET not in public


def test_execution_layer_has_no_server_lifecycle_or_host_resource_imports() -> None:
    sources = (
        inspect.getsource(execution_module),
        inspect.getsource(execution_models_module),
        inspect.getsource(execution_planning_module),
    )
    imported_modules: set[str] = set()
    for source in sources:
        tree = ast.parse(source)
        imported_modules.update(
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        )
        imported_modules.update(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        )
    forbidden_prefixes = (
        "fluxgate.clients",
        "fluxgate.identity",
        "fluxgate.profiles",
        "fluxgate.providers",
        "fluxgate.system",
    )
    assert not any(
        module.startswith(prefix) for module in imported_modules for prefix in forbidden_prefixes
    )


def test_execution_results_are_ephemeral_and_state_schema_remains_v2(tmp_path: Path) -> None:
    authorized, plan = ready_plan()
    result = execute(authorized, plan, DeterministicAdapter())
    state = FluxGateState()
    assert state.schema_version == 2
    assert not hasattr(state, "executions")
    assert not hasattr(state, "failover_history")
    assert result.schema_version == 1  # type: ignore[union-attr]
    assert list(tmp_path.iterdir()) == []
