"""Deterministic, explainable scoring from real probe observations."""

from __future__ import annotations

import math
from dataclasses import dataclass

from fluxgate.pathfinder.active_models import (
    CandidateScore,
    ProbeObservation,
    ProbeOutcome,
    ScoreComponent,
    VerificationState,
)
from fluxgate.pathfinder.models import CandidateAssessment


@dataclass(frozen=True, slots=True)
class ScoringPolicy:
    compatibility_points: int = 100
    dns_points: int = 15
    tcp_points: int = 50
    tls_points: int = 75
    latency_bonus_points: int = 20
    latency_bucket_ms: float = 25.0
    repeated_failure_penalty: int = 10
    unsupported_penalty: int = 10
    timeout_penalty: int = 100
    refused_penalty: int = 80
    unreachable_penalty: int = 90
    dns_failure_penalty: int = 100
    tls_verification_penalty: int = 70
    tls_handshake_penalty: int = 65
    connect_failure_penalty: int = 75
    internal_error_penalty: int = 100
    unauthorized_destination_penalty: int = 100

    def __post_init__(self) -> None:
        if not math.isfinite(self.latency_bucket_ms) or self.latency_bucket_ms <= 0:
            raise ValueError("scoring latency bucket must be finite and positive")

    def outcome_penalty(self, outcome: ProbeOutcome) -> int:
        penalties = {
            ProbeOutcome.PROBE_UNSUPPORTED: self.unsupported_penalty,
            ProbeOutcome.UNVERIFIED: self.unsupported_penalty,
            ProbeOutcome.TIMEOUT: self.timeout_penalty,
            ProbeOutcome.CONNECTION_REFUSED: self.refused_penalty,
            ProbeOutcome.NETWORK_UNREACHABLE: self.unreachable_penalty,
            ProbeOutcome.DNS_FAILURE: self.dns_failure_penalty,
            ProbeOutcome.TLS_VERIFICATION_FAILURE: self.tls_verification_penalty,
            ProbeOutcome.TLS_HANDSHAKE_FAILURE: self.tls_handshake_penalty,
            ProbeOutcome.CONNECT_FAILURE: self.connect_failure_penalty,
            ProbeOutcome.INTERNAL_ERROR: self.internal_error_penalty,
            ProbeOutcome.INVALID_CANDIDATE: self.internal_error_penalty,
            ProbeOutcome.DESTINATION_UNAUTHORIZED: self.unauthorized_destination_penalty,
        }
        return penalties.get(outcome, 0)


def score_candidate(
    assessment: CandidateAssessment,
    observation: ProbeObservation,
    policy: ScoringPolicy | None = None,
) -> CandidateScore:
    policy = policy or ScoringPolicy()
    components: list[ScoreComponent] = []
    if not assessment.compatible:
        components.append(
            ScoreComponent(
                name="compatibility",
                points=0,
                reason="candidate is incompatible with client capabilities",
            )
        )
        return CandidateScore(
            candidate_id=assessment.candidate_id,
            compatible=False,
            eligible=False,
            score=0,
            components=tuple(components),
            observation=observation,
        )

    components.append(
        ScoreComponent(
            name="compatibility",
            points=policy.compatibility_points,
            reason="candidate is compatible with client capabilities",
        )
    )
    final = observation.attempts[-1] if observation.attempts else None
    if final is not None and final.dns_succeeded:
        components.append(
            ScoreComponent(name="dns", points=policy.dns_points, reason="DNS resolution succeeded")
        )
    if final is not None and final.tcp_connected:
        components.append(
            ScoreComponent(name="tcp", points=policy.tcp_points, reason="TCP connection succeeded")
        )
    if final is not None and final.tls_verified:
        components.append(
            ScoreComponent(name="tls", points=policy.tls_points, reason="TLS identity was verified")
        )
    if (
        final is not None
        and observation.outcome == ProbeOutcome.SUCCESS
        and final.total_latency_ms is not None
    ):
        latency_points = max(
            0,
            policy.latency_bonus_points - int(final.total_latency_ms / policy.latency_bucket_ms),
        )
        components.append(
            ScoreComponent(
                name="latency",
                points=latency_points,
                reason=f"measured total latency {final.total_latency_ms:.2f} ms",
            )
        )
    penalty = policy.outcome_penalty(observation.outcome)
    if penalty:
        components.append(
            ScoreComponent(
                name="outcome",
                points=-penalty,
                reason=f"probe outcome was {observation.outcome.value}",
            )
        )
    failures = sum(attempt.outcome != ProbeOutcome.SUCCESS for attempt in observation.attempts)
    if failures > 1:
        repeated = (failures - 1) * policy.repeated_failure_penalty
        components.append(
            ScoreComponent(
                name="repeated_failures",
                points=-repeated,
                reason=f"{failures} failed probe attempts",
            )
        )
    return CandidateScore(
        candidate_id=assessment.candidate_id,
        compatible=True,
        eligible=(
            observation.outcome == ProbeOutcome.SUCCESS
            and observation.verification == VerificationState.VERIFIED
        ),
        score=sum(component.points for component in components),
        components=tuple(components),
        observation=observation,
    )
