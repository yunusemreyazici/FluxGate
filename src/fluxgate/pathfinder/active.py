"""Bounded orchestration for active Pathfinder probing."""

from __future__ import annotations

import math
import ssl
import time
from concurrent.futures import Future, ThreadPoolExecutor, wait
from pathlib import Path

from fluxgate.core.config import PathfinderProbeConfig
from fluxgate.core.errors import PathfinderError
from fluxgate.pathfinder.active_models import (
    ActivePathfinderReport,
    ProbeAttempt,
    ProbeObservation,
    ProbeOutcome,
    ProbePlan,
    VerificationState,
)
from fluxgate.pathfinder.authorization import AuthorizedCandidateInventory
from fluxgate.pathfinder.models import ClientCapabilities
from fluxgate.pathfinder.probing import (
    ProbeExecutor,
    SocketProbeExecutor,
    build_probe_plan,
    create_tls_context,
)
from fluxgate.pathfinder.scoring import ScoringPolicy, score_candidate
from fluxgate.pathfinder.selection import rank_candidates, select_candidate
from fluxgate.pathfinder.service import evaluate_candidates


class ActivePathfinder:
    def __init__(
        self,
        executor: ProbeExecutor | None = None,
        scoring_policy: ScoringPolicy | None = None,
    ) -> None:
        self.executor = executor or SocketProbeExecutor()
        self.scoring_policy = scoring_policy or ScoringPolicy()

    def _execute_with_retries(
        self,
        candidate_id: str,
        *,
        plan: ProbePlan,
        config: PathfinderProbeConfig,
        tls_ca_file: Path | None,
    ) -> ProbeObservation:
        deadline = time.monotonic() + config.candidate_timeout_seconds
        attempts: list[ProbeAttempt] = []
        for attempt_number in range(1, config.retry_count + 2):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            attempt = self.executor.execute(
                plan,
                attempt=attempt_number,
                connect_timeout=min(config.connect_timeout_seconds, remaining),
                candidate_timeout=remaining,
                tls_ca_file=tls_ca_file,
            )
            if time.monotonic() > deadline:
                attempts.append(
                    ProbeAttempt(
                        attempt=attempt_number,
                        outcome=ProbeOutcome.TIMEOUT,
                        verification=VerificationState.FAILED,
                        summary="candidate timeout elapsed during probe execution",
                    )
                )
                break
            if attempt.attempt != attempt_number:
                raise PathfinderError("probe executor returned an inconsistent attempt number")
            attempts.append(attempt)
            if attempt.outcome in {
                ProbeOutcome.SUCCESS,
                ProbeOutcome.PROBE_UNSUPPORTED,
                ProbeOutcome.UNVERIFIED,
            }:
                break
        if not attempts:
            attempts.append(
                ProbeAttempt(
                    attempt=1,
                    outcome=ProbeOutcome.TIMEOUT,
                    verification=VerificationState.FAILED,
                    summary="candidate timeout elapsed before probing began",
                )
            )
        final = attempts[-1]
        return ProbeObservation(
            candidate_id=candidate_id,
            outcome=final.outcome,
            verification=final.verification,
            attempts=tuple(attempts),
            summary=final.summary,
        )

    @staticmethod
    def _incompatible_observation(candidate_id: str, reasons: tuple[str, ...]) -> ProbeObservation:
        summary = "; ".join(reasons) if reasons else "candidate is incompatible"
        return ProbeObservation(
            candidate_id=candidate_id,
            outcome=ProbeOutcome.INCOMPATIBLE,
            verification=VerificationState.INELIGIBLE,
            attempts=(),
            summary=summary,
        )

    @staticmethod
    def _timeout_observation(candidate_id: str) -> ProbeObservation:
        attempt = ProbeAttempt(
            attempt=1,
            outcome=ProbeOutcome.TIMEOUT,
            verification=VerificationState.FAILED,
            summary="candidate exceeded its bounded probe execution window",
        )
        return ProbeObservation(
            candidate_id=candidate_id,
            outcome=attempt.outcome,
            verification=attempt.verification,
            attempts=(attempt,),
            summary=attempt.summary,
        )

    @staticmethod
    def _internal_error_observation(candidate_id: str) -> ProbeObservation:
        attempt = ProbeAttempt(
            attempt=1,
            outcome=ProbeOutcome.INTERNAL_ERROR,
            verification=VerificationState.FAILED,
            summary="internal probe executor error",
        )
        return ProbeObservation(
            candidate_id=candidate_id,
            outcome=attempt.outcome,
            verification=attempt.verification,
            attempts=(attempt,),
            summary=attempt.summary,
        )

    def probe(
        self,
        inventory: AuthorizedCandidateInventory,
        capabilities: ClientCapabilities,
        config: PathfinderProbeConfig,
        *,
        tls_ca_file: Path | None = None,
    ) -> ActivePathfinderReport:
        if tls_ca_file is not None and (tls_ca_file.is_symlink() or not tls_ca_file.is_file()):
            raise PathfinderError("TLS CA file must be a safe regular file")
        if tls_ca_file is not None:
            try:
                create_tls_context(tls_ca_file)
            except (OSError, ssl.SSLError) as error:
                raise PathfinderError("TLS CA file is not a valid certificate bundle") from error
        plan = evaluate_candidates(inventory.candidates, capabilities)
        candidates = {candidate.candidate_id: candidate for candidate in inventory.candidates}
        observations: dict[str, ProbeObservation] = {}
        futures: dict[Future[ProbeObservation], str] = {}
        pool = ThreadPoolExecutor(
            max_workers=config.max_parallel_probes,
            thread_name_prefix="fluxgate-pathfinder",
        )
        try:
            for assessment in plan.assessments:
                if not assessment.compatible:
                    observations[assessment.candidate_id] = self._incompatible_observation(
                        assessment.candidate_id, assessment.rejection_reasons
                    )
                    continue
                candidate = candidates[assessment.candidate_id]
                probe_plan = build_probe_plan(
                    candidate,
                    authorized_addresses=inventory.authorized_addresses,
                )
                future = pool.submit(
                    self._execute_with_retries,
                    assessment.candidate_id,
                    plan=probe_plan,
                    config=config,
                    tls_ca_file=tls_ca_file,
                )
                futures[future] = assessment.candidate_id
            if futures:
                waves = math.ceil(len(futures) / config.max_parallel_probes)
                completed, pending = wait(
                    futures,
                    timeout=config.candidate_timeout_seconds * waves,
                )
                for future in completed:
                    candidate_id = futures[future]
                    try:
                        observations[candidate_id] = future.result()
                    except Exception:
                        observations[candidate_id] = self._internal_error_observation(candidate_id)
                for future in pending:
                    candidate_id = futures[future]
                    future.cancel()
                    observations[candidate_id] = self._timeout_observation(candidate_id)
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

        assessments = {item.candidate_id: item for item in plan.assessments}
        scores = tuple(
            score_candidate(assessments[candidate_id], observation, self.scoring_policy)
            for candidate_id, observation in sorted(observations.items())
        )
        ranked = rank_candidates(scores)
        return ActivePathfinderReport(
            assessments=plan.assessments,
            observations=tuple(observations[key] for key in sorted(observations)),
            ranked_candidates=ranked,
            selection=select_candidate(ranked),
        )
