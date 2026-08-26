"""Pure failover decision policy; never mutates client networking."""

from __future__ import annotations

from fluxgate.core.config import PathfinderFailoverConfig
from fluxgate.pathfinder.active_models import (
    ActivePathfinderReport,
    FailoverAction,
    FailoverContext,
    FailoverDecision,
    VerificationState,
)


def decide_failover(
    report: ActivePathfinderReport,
    context: FailoverContext,
    policy: PathfinderFailoverConfig,
) -> FailoverDecision:
    eligible = [item for item in report.ranked_candidates if item.eligible]
    if not eligible:
        unverified = [
            item
            for item in report.ranked_candidates
            if item.compatible and item.observation.verification == VerificationState.UNVERIFIED
        ]
        if unverified:
            return FailoverDecision(
                action=FailoverAction.NO_VERIFIED_CANDIDATE,
                current_candidate_id=context.current_candidate_id,
                target_candidate_id=None,
                reason=(
                    "no candidate has verified active reachability; "
                    f"{len(unverified)} compatible candidate(s) remain unverified"
                ),
            )
        return FailoverDecision(
            action=FailoverAction.NO_VIABLE_CANDIDATE,
            current_candidate_id=context.current_candidate_id,
            target_candidate_id=None,
            reason="no candidate has verified active reachability",
        )
    best = eligible[0]
    if context.current_candidate_id is None:
        return FailoverDecision(
            action=FailoverAction.SWITCH,
            current_candidate_id=None,
            target_candidate_id=best.candidate_id,
            reason="no current candidate is selected",
        )
    current = next(
        (
            item
            for item in report.ranked_candidates
            if item.candidate_id == context.current_candidate_id
        ),
        None,
    )
    if current is not None and current.eligible:
        if current.candidate_id == best.candidate_id:
            return FailoverDecision(
                action=FailoverAction.STAY,
                current_candidate_id=current.candidate_id,
                target_candidate_id=current.candidate_id,
                reason="current candidate remains the highest-ranked eligible candidate",
            )
        improvement = best.score - current.score
        if improvement < policy.minimum_improvement:
            return FailoverDecision(
                action=FailoverAction.STAY,
                current_candidate_id=current.candidate_id,
                target_candidate_id=current.candidate_id,
                reason=(
                    f"score improvement {improvement} is below required margin "
                    f"{policy.minimum_improvement}"
                ),
            )
    elif context.consecutive_failures < policy.failure_threshold:
        return FailoverDecision(
            action=FailoverAction.STAY,
            current_candidate_id=context.current_candidate_id,
            target_candidate_id=context.current_candidate_id,
            reason=(
                f"failure count {context.consecutive_failures} is below threshold "
                f"{policy.failure_threshold}"
            ),
        )
    if context.seconds_since_switch < policy.cooldown_seconds:
        return FailoverDecision(
            action=FailoverAction.STAY,
            current_candidate_id=context.current_candidate_id,
            target_candidate_id=context.current_candidate_id,
            reason=(
                f"cooldown active for {policy.cooldown_seconds - context.seconds_since_switch:.1f} "
                "more seconds"
            ),
        )
    return FailoverDecision(
        action=FailoverAction.SWITCH,
        current_candidate_id=context.current_candidate_id,
        target_candidate_id=best.candidate_id,
        reason="policy thresholds permit switching to the best verified candidate",
    )
