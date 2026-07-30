"""Corpus schema, scoring config, and validation.

The edge-telemetry corpus (edge_mappings/*.json) is the core IP of NoiseHound.
This module defines the shape each corpus entry must take and validates it at
load time so a malformed hand-edit fails loudly rather than skewing scores.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

VALID_SOURCES = {
    "windows_security",
    "sysmon",
    "network",
    "edr_heuristic",
    "etw",
}

VALID_RELIABILITY = {
    "low",
    "medium",
    "high",
    "high_if_auditing_enabled",
}


class CorpusError(ValueError):
    """Raised when a corpus entry fails schema validation."""


@dataclass(frozen=True)
class ScoringConfig:
    """Weights for path noise scoring (see section 2.3 of the spec).

    path_score = max(edge_scores) * max_weight + mean(edge_scores) * mean_weight

    Weighted toward the loudest single step (one bad step often burns the whole
    op) while still accounting for cumulative exposure. Exposed as config so the
    weights can be tuned empirically against real detection data.
    """

    max_weight: float = 0.6
    mean_weight: float = 0.4
    default_unknown_noise: int = 60
    candidate_paths: int = 200   # simple paths to enumerate before re-ranking
    time_budget_s: float = 20.0  # wall-clock cap on the k-shortest enumeration
    correlation: float = 0.5     # SOC correlation coefficient for P(detected)

    def validate(self) -> None:
        total = self.max_weight + self.mean_weight
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                "max_weight + mean_weight must sum to 1.0 (got %s)" % total
            )
        if not 0 <= self.default_unknown_noise <= 100:
            raise ValueError("default_unknown_noise must be in 0..100")
        if self.candidate_paths < 1:
            raise ValueError("candidate_paths must be >= 1")
        if self.time_budget_s <= 0:
            raise ValueError("time_budget_s must be > 0")
        if not 0.0 <= self.correlation <= 1.0:
            raise ValueError("correlation must be in 0.0..1.0")


def _require(entry: dict, key: str, edge_label: str) -> Any:
    if key not in entry:
        raise CorpusError("edge %r missing required field %r" % (edge_label, key))
    return entry[key]


def validate_entry(entry: dict) -> str:
    """Validate a single corpus entry dict. Returns its edge_type.

    Raises CorpusError on the first problem found.
    """
    if not isinstance(entry, dict):
        raise CorpusError("corpus entry must be a JSON object, got %s" % type(entry))

    edge_type = _require(entry, "edge_type", "<unknown>")
    if not isinstance(edge_type, str) or not edge_type:
        raise CorpusError("edge_type must be a non-empty string")

    score = _require(entry, "static_noise_score", edge_type)
    if not isinstance(score, (int, float)) or not 0 <= score <= 100:
        raise CorpusError(
            "edge %r: static_noise_score must be a number in 0..100 (got %r)"
            % (edge_type, score)
        )

    telemetry = _require(entry, "telemetry", edge_type)
    if not isinstance(telemetry, list):
        raise CorpusError("edge %r: telemetry must be a list" % edge_type)

    for i, t in enumerate(telemetry):
        if not isinstance(t, dict):
            raise CorpusError(
                "edge %r: telemetry[%d] must be an object" % (edge_type, i)
            )
        src = t.get("source")
        if src not in VALID_SOURCES:
            raise CorpusError(
                "edge %r: telemetry[%d] source %r not in %s"
                % (edge_type, i, src, sorted(VALID_SOURCES))
            )
        rel = t.get("reliability")
        if rel is not None and rel not in VALID_RELIABILITY:
            raise CorpusError(
                "edge %r: telemetry[%d] reliability %r not in %s"
                % (edge_type, i, rel, sorted(VALID_RELIABILITY))
            )

    # description is recommended but not strictly required; warn-by-absence is
    # handled at load time, not here.
    return edge_type
