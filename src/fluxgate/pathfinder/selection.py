"""Stable ranking and candidate selection."""

from __future__ import annotations

from fluxgate.pathfinder.active_models import (
    CandidateScore,
    SelectionDecision,
    VerificationState,
)


def rank_candidates(scores: tuple[CandidateScore, ...]) -> tuple[CandidateScore, ...]:
    return tuple(
        sorted(
            scores,
            key=lambda item: (not item.eligible, -item.score, item.candidate_id),
        )
    )


def select_candidate(ranked: tuple[CandidateScore, ...]) -> SelectionDecision:
    selected = next((item for item in ranked if item.eligible), None)
    if selected is None:
        unverified = tuple(
            item.candidate_id
            for item in ranked
            if item.compatible and item.observation.verification == VerificationState.UNVERIFIED
        )
        reason = (
            f"no candidate has verified active reachability; {len(unverified)} compatible "
            "candidate(s) remain unverified"
            if unverified
            else "no candidate has verified active reachability"
        )
        return SelectionDecision(
            selected_candidate_id=None,
            alternatives=tuple(item.candidate_id for item in ranked),
            reason=reason,
        )
    return SelectionDecision(
        selected_candidate_id=selected.candidate_id,
        alternatives=tuple(
            item.candidate_id for item in ranked if item.candidate_id != selected.candidate_id
        ),
        reason=f"selected highest-ranked eligible candidate with score {selected.score}",
    )
