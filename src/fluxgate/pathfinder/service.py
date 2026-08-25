"""Deterministic capability matching without network I/O or scoring."""

from __future__ import annotations

from fluxgate.pathfinder.models import (
    CandidateAssessment,
    ClientCapabilities,
    ConnectionCandidate,
    PathfinderPlan,
)


def evaluate_candidates(
    candidates: tuple[ConnectionCandidate, ...], capabilities: ClientCapabilities
) -> PathfinderPlan:
    assessments: list[CandidateAssessment] = []
    for candidate in sorted(candidates, key=lambda item: item.candidate_id):
        requirements = (
            f"provider:{candidate.provider.value}",
            f"protocol:{candidate.protocol.value}",
            f"transport:{candidate.transport.value}",
            f"security:{candidate.security.value}",
            f"connection_mode:{candidate.connection_mode.value}",
            *(f"ip_family:{item.value}" for item in candidate.ip_families),
            *(f"feature:{item.value}" for item in candidate.required_features),
        )
        checks = (
            (candidate.provider in capabilities.supported_providers, requirements[0]),
            (candidate.protocol in capabilities.supported_protocols, requirements[1]),
            (candidate.transport in capabilities.supported_transports, requirements[2]),
            (candidate.security in capabilities.supported_security, requirements[3]),
            (candidate.connection_mode in capabilities.supported_connection_modes, requirements[4]),
        )
        reasons = ["candidate is disabled"] if not candidate.enabled else []
        reasons.extend(f"client lacks {label}" for supported, label in checks if not supported)
        reasons.extend(
            f"client lacks ip_family:{family.value}"
            for family in candidate.ip_families
            if family not in capabilities.supported_ip_families
        )
        reasons.extend(
            f"client lacks feature:{feature.value}"
            for feature in candidate.required_features
            if feature not in capabilities.supported_features
        )
        assessments.append(
            CandidateAssessment(
                candidate_id=candidate.candidate_id,
                compatible=not reasons,
                rejection_reasons=tuple(reasons),
                required_capabilities=requirements,
            )
        )
    return PathfinderPlan(assessments=tuple(assessments))
