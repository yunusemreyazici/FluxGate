"""Pure construction and validation of non-mutating failover execution plans."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any

from fluxgate.pathfinder.active_models import FailoverAction, FailoverDecision
from fluxgate.pathfinder.authorization import AuthorizedCandidateInventory
from fluxgate.pathfinder.execution_models import (
    CandidateExecutionBinding,
    ExecutionCapability,
    ExecutionPlanStatus,
    ExecutionPolicy,
    ExecutionStrategy,
    FailoverExecutionPlan,
)
from fluxgate.pathfinder.models import ConnectionCandidate


def capability_supports(
    capability: ExecutionCapability, candidate: ConnectionCandidate, policy: ExecutionPolicy
) -> bool:
    return (
        candidate.enabled
        and candidate.provider in capability.supported_providers
        and candidate.protocol in capability.supported_protocols
        and candidate.transport in capability.supported_transports
        and candidate.security in capability.supported_security
        and candidate.connection_mode in capability.supported_connection_modes
        and capability.strategy != ExecutionStrategy.PLAN_ONLY
        and (
            capability.strategy != ExecutionStrategy.BREAK_BEFORE_MAKE
            or policy.allow_break_before_make
        )
    )


def candidate_fingerprint(
    inventory: AuthorizedCandidateInventory, candidate: ConnectionCandidate
) -> str:
    """Bind secret-free candidate fields to their authoritative inventory identity."""
    payload = {
        "authorization_source": inventory.source.value,
        "server_id": str(inventory.server_id) if inventory.server_id is not None else None,
        "inventory_endpoint": inventory.endpoint,
        "authorized_addresses": inventory.authorized_addresses,
        "candidate": candidate.model_dump(mode="json"),
    }
    return _digest(payload)


def make_candidate_binding(
    inventory: AuthorizedCandidateInventory, candidate: ConnectionCandidate
) -> CandidateExecutionBinding:
    return CandidateExecutionBinding(
        candidate=candidate,
        fingerprint=candidate_fingerprint(inventory, candidate),
    )


def _digest(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _plan_id(fields: dict[str, Any]) -> str:
    return _digest(fields)


def plan_failover_execution(
    inventory: AuthorizedCandidateInventory,
    decision: FailoverDecision,
    capabilities: Iterable[ExecutionCapability],
    policy: ExecutionPolicy,
    *,
    execution_scope: str,
) -> FailoverExecutionPlan:
    """Create a deterministic plan without trusting reports or performing I/O."""
    declared_capabilities = tuple(capabilities)
    candidates = {candidate.candidate_id: candidate for candidate in inventory.candidates}
    duplicate_candidate_ids = len(candidates) != len(inventory.candidates)
    duplicate_adapter_ids = len(
        {capability.adapter_id for capability in declared_capabilities}
    ) != len(declared_capabilities)
    current_candidate = (
        candidates.get(decision.current_candidate_id)
        if decision.current_candidate_id is not None
        else None
    )
    current = (
        make_candidate_binding(inventory, current_candidate)
        if current_candidate is not None
        else None
    )
    target_candidate = (
        candidates.get(decision.target_candidate_id)
        if decision.target_candidate_id is not None
        else None
    )
    target = (
        make_candidate_binding(inventory, target_candidate)
        if target_candidate is not None
        else None
    )
    adapter: ExecutionCapability | None = None
    expected_verification: str | None = None
    unsupported_reason: str | None = None
    preconditions: tuple[str, ...] = ()

    if duplicate_candidate_ids:
        status = ExecutionPlanStatus.INVALID
        execution_supported = False
        reason = "authoritative inventory contains duplicate candidate IDs"
        unsupported_reason = reason
    elif decision.action != FailoverAction.SWITCH:
        status = ExecutionPlanStatus.NO_ACTION
        execution_supported = True
        reason = decision.reason
    elif decision.target_candidate_id is None:
        status = ExecutionPlanStatus.INVALID
        execution_supported = False
        reason = "switch decision has no target candidate"
        unsupported_reason = reason
    elif target_candidate is None or not target_candidate.enabled:
        status = ExecutionPlanStatus.INVALID
        execution_supported = False
        reason = "switch target is absent or disabled in the authoritative inventory"
        unsupported_reason = reason
    elif decision.current_candidate_id is not None and current_candidate is None:
        status = ExecutionPlanStatus.INVALID
        execution_supported = False
        reason = "rollback candidate is absent from the authoritative inventory"
        unsupported_reason = reason
    elif decision.current_candidate_id == decision.target_candidate_id:
        status = ExecutionPlanStatus.INVALID
        execution_supported = False
        reason = "switch decision current and target candidates must differ"
        unsupported_reason = reason
    elif current_candidate is not None and not current_candidate.enabled:
        status = ExecutionPlanStatus.INVALID
        execution_supported = False
        reason = "rollback candidate is disabled in the authoritative inventory"
        unsupported_reason = reason
    elif duplicate_adapter_ids:
        status = ExecutionPlanStatus.INVALID
        execution_supported = False
        reason = "execution capabilities contain duplicate adapter IDs"
        unsupported_reason = reason
    else:
        matches = sorted(
            (
                capability
                for capability in declared_capabilities
                if capability_supports(capability, target_candidate, policy)
            ),
            key=lambda item: item.adapter_id,
        )
        if not matches:
            status = ExecutionPlanStatus.UNSUPPORTED
            execution_supported = False
            reason = "no authorized client connection adapter supports the target candidate"
            unsupported_reason = reason
        else:
            adapter = matches[0]
            status = ExecutionPlanStatus.READY
            execution_supported = True
            expected_verification = adapter.verification
            reason = decision.reason
            preconditions = (
                "target remains present and enabled in the authoritative inventory",
                "target secret-free fingerprint remains unchanged",
                "selected adapter capability remains unchanged",
                "target is not already active and verified",
            )

    fields: dict[str, Any] = {
        "schema_version": 1,
        "execution_scope": execution_scope,
        "decision_action": decision.action,
        "status": status,
        "reason": reason,
        "current": current,
        "target": target,
        "adapter": adapter,
        "preconditions": preconditions,
        "expected_verification": expected_verification,
        "rollback_target_candidate_id": (
            current_candidate.candidate_id if current_candidate is not None else None
        ),
        "execution_supported": execution_supported,
        "unsupported_reason": unsupported_reason,
        "policy": policy,
    }
    serializable = {
        key: value.model_dump(mode="json") if hasattr(value, "model_dump") else value
        for key, value in fields.items()
    }
    return FailoverExecutionPlan(plan_id=_plan_id(serializable), **fields)


def execution_plan_id_is_valid(plan: FailoverExecutionPlan) -> bool:
    fields = plan.model_dump(mode="json", exclude={"plan_id"})
    return plan.plan_id == _plan_id(fields)
