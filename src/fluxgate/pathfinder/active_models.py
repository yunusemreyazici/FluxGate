"""Typed, secret-free active Pathfinder plans and results."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from fluxgate.core.compat import StrEnum
from fluxgate.core.models import StrictModel
from fluxgate.pathfinder.addressing import normalize_authorized_addresses
from fluxgate.pathfinder.models import CandidateAssessment, IPFamily


class AuthorizationSource(StrEnum):
    LOCAL_STATE = "local_state"
    SIGNED_MANIFEST = "signed_manifest"


class ProbeStep(StrEnum):
    DNS = "dns"
    TCP_CONNECT = "tcp_connect"
    TLS_HANDSHAKE = "tls_handshake"


class ProbeOutcome(StrEnum):
    SUCCESS = "success"
    UNVERIFIED = "unverified"
    INCOMPATIBLE = "incompatible"
    INVALID_CANDIDATE = "invalid_candidate"
    DNS_FAILURE = "dns_failure"
    TIMEOUT = "timeout"
    CONNECTION_REFUSED = "connection_refused"
    NETWORK_UNREACHABLE = "network_unreachable"
    CONNECT_FAILURE = "connect_failure"
    DESTINATION_UNAUTHORIZED = "destination_unauthorized"
    TLS_VERIFICATION_FAILURE = "tls_verification_failure"
    TLS_HANDSHAKE_FAILURE = "tls_handshake_failure"
    PROBE_UNSUPPORTED = "probe_unsupported"
    INTERNAL_ERROR = "internal_error"


class VerificationState(StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    FAILED = "failed"
    INELIGIBLE = "ineligible"


class ProbePlan(StrictModel):
    candidate_id: str
    endpoint: str
    port: int = Field(ge=1, le=65535)
    ip_families: tuple[IPFamily, ...]
    authorized_addresses: tuple[str, ...] = ()
    steps: tuple[ProbeStep, ...]
    tls_server_name: str | None = None

    @field_validator("authorized_addresses")
    @classmethod
    def canonical_authorized_addresses(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return normalize_authorized_addresses(value)

    @model_validator(mode="after")
    def valid_step_sequence(self) -> ProbePlan:
        if not self.ip_families or len(self.ip_families) != len(set(self.ip_families)):
            raise ValueError("probe plans require unique authorized IP families")
        allowed = {
            (ProbeStep.DNS,),
            (ProbeStep.DNS, ProbeStep.TCP_CONNECT),
            (ProbeStep.DNS, ProbeStep.TCP_CONNECT, ProbeStep.TLS_HANDSHAKE),
        }
        if self.steps not in allowed:
            raise ValueError("probe plan steps must follow the supported DNS/TCP/TLS sequence")
        if ProbeStep.TLS_HANDSHAKE in self.steps and not self.tls_server_name:
            raise ValueError("TLS probe plans require a server name")
        if ProbeStep.TLS_HANDSHAKE not in self.steps and self.tls_server_name is not None:
            raise ValueError("non-TLS probe plans must not carry a TLS server name")
        return self


class ProbeAttempt(StrictModel):
    attempt: int = Field(ge=1)
    outcome: ProbeOutcome
    verification: VerificationState
    dns_succeeded: bool | None = None
    tcp_connected: bool | None = None
    tls_verified: bool | None = None
    dns_latency_ms: float | None = Field(default=None, ge=0.0, allow_inf_nan=False)
    connect_latency_ms: float | None = Field(default=None, ge=0.0, allow_inf_nan=False)
    handshake_latency_ms: float | None = Field(default=None, ge=0.0, allow_inf_nan=False)
    total_latency_ms: float | None = Field(default=None, ge=0.0, allow_inf_nan=False)
    summary: str

    @model_validator(mode="after")
    def outcome_matches_verification(self) -> ProbeAttempt:
        if self.outcome == ProbeOutcome.SUCCESS and self.verification != VerificationState.VERIFIED:
            raise ValueError("successful probes must be verified")
        if self.outcome in {ProbeOutcome.PROBE_UNSUPPORTED, ProbeOutcome.UNVERIFIED} and (
            self.verification != VerificationState.UNVERIFIED
        ):
            raise ValueError("unsupported probes must remain unverified")
        if (
            self.outcome
            in {
                ProbeOutcome.DNS_FAILURE,
                ProbeOutcome.TIMEOUT,
                ProbeOutcome.CONNECTION_REFUSED,
                ProbeOutcome.NETWORK_UNREACHABLE,
                ProbeOutcome.CONNECT_FAILURE,
                ProbeOutcome.DESTINATION_UNAUTHORIZED,
                ProbeOutcome.TLS_VERIFICATION_FAILURE,
                ProbeOutcome.TLS_HANDSHAKE_FAILURE,
                ProbeOutcome.INVALID_CANDIDATE,
                ProbeOutcome.INTERNAL_ERROR,
            }
            and self.verification != VerificationState.FAILED
        ):
            raise ValueError("failed probes must use failed verification state")
        return self


class ProbeObservation(StrictModel):
    candidate_id: str
    outcome: ProbeOutcome
    verification: VerificationState
    attempts: tuple[ProbeAttempt, ...]
    summary: str

    @model_validator(mode="after")
    def final_attempt_matches_observation(self) -> ProbeObservation:
        if not self.attempts:
            if self.verification != VerificationState.INELIGIBLE:
                raise ValueError("only ineligible observations may omit probe attempts")
            return self
        final = self.attempts[-1]
        if final.outcome != self.outcome or final.verification != self.verification:
            raise ValueError("observation must describe its final probe attempt")
        return self


class ScoreComponent(StrictModel):
    name: str
    points: int
    reason: str


class CandidateScore(StrictModel):
    candidate_id: str
    compatible: bool
    eligible: bool
    score: int
    components: tuple[ScoreComponent, ...]
    observation: ProbeObservation

    @model_validator(mode="after")
    def observation_matches_candidate(self) -> CandidateScore:
        if self.observation.candidate_id != self.candidate_id:
            raise ValueError("candidate score observation ID does not match")
        if self.score != sum(component.points for component in self.components):
            raise ValueError("candidate score must equal its explainable components")
        expected_eligible = (
            self.compatible
            and self.observation.outcome == ProbeOutcome.SUCCESS
            and self.observation.verification == VerificationState.VERIFIED
        )
        if self.eligible != expected_eligible:
            raise ValueError("candidate eligibility does not match compatibility and observation")
        return self


class SelectionDecision(StrictModel):
    selected_candidate_id: str | None
    alternatives: tuple[str, ...]
    reason: str

    @model_validator(mode="after")
    def selection_is_unique(self) -> SelectionDecision:
        if len(self.alternatives) != len(set(self.alternatives)):
            raise ValueError("selection alternatives must be unique")
        if self.selected_candidate_id in self.alternatives:
            raise ValueError("selected candidate cannot also be an alternative")
        return self


class ActivePathfinderReport(StrictModel):
    schema_version: Literal[1] = 1
    assessments: tuple[CandidateAssessment, ...]
    observations: tuple[ProbeObservation, ...]
    ranked_candidates: tuple[CandidateScore, ...]
    selection: SelectionDecision

    @model_validator(mode="after")
    def candidate_inventory_is_consistent(self) -> ActivePathfinderReport:
        groups = (
            tuple(item.candidate_id for item in self.assessments),
            tuple(item.candidate_id for item in self.observations),
            tuple(item.candidate_id for item in self.ranked_candidates),
        )
        if any(len(group) != len(set(group)) for group in groups):
            raise ValueError("active Pathfinder report candidate IDs must be unique")
        if not (set(groups[0]) == set(groups[1]) == set(groups[2])):
            raise ValueError("active Pathfinder report candidate inventories differ")
        known = set(groups[0])
        selected = self.selection.selected_candidate_id
        if (selected is not None and selected not in known) or not set(
            self.selection.alternatives
        ).issubset(known):
            raise ValueError("selection references an unknown candidate")
        scores = {item.candidate_id: item for item in self.ranked_candidates}
        observations = {item.candidate_id: item for item in self.observations}
        expected_ranking = tuple(
            sorted(
                self.ranked_candidates,
                key=lambda item: (not item.eligible, -item.score, item.candidate_id),
            )
        )
        if self.ranked_candidates != expected_ranking:
            raise ValueError("active Pathfinder candidates are not deterministically ranked")
        for assessment in self.assessments:
            if scores[assessment.candidate_id].compatible != assessment.compatible:
                raise ValueError("candidate score compatibility differs from its assessment")
            incompatible = (
                observations[assessment.candidate_id].outcome == ProbeOutcome.INCOMPATIBLE
            )
            if incompatible == assessment.compatible:
                raise ValueError("candidate observation compatibility differs from its assessment")
        expected_selected = next(
            (item.candidate_id for item in self.ranked_candidates if item.eligible), None
        )
        if selected != expected_selected:
            raise ValueError("selection does not identify the first eligible ranked candidate")
        expected_alternatives = tuple(
            item.candidate_id
            for item in self.ranked_candidates
            if item.candidate_id != expected_selected
        )
        if self.selection.alternatives != expected_alternatives:
            raise ValueError("selection must preserve every ranked alternative")
        return self


class FailoverAction(StrEnum):
    STAY = "stay"
    SWITCH = "switch"
    NO_VERIFIED_CANDIDATE = "no_verified_candidate"
    NO_VIABLE_CANDIDATE = "no_viable_candidate"


class FailoverContext(StrictModel):
    current_candidate_id: str | None = None
    consecutive_failures: int = Field(default=0, ge=0)
    seconds_since_switch: float = Field(default=0.0, ge=0.0, allow_inf_nan=False)


class FailoverDecision(StrictModel):
    action: FailoverAction
    current_candidate_id: str | None
    target_candidate_id: str | None
    reason: str
