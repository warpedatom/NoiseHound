"""Probabilistic detection model.

A 0-100 noise score answers "how loud", but operators and defenders think in
"what's the chance this gets caught". This module maps each edge's effective
noise score to a detection probability and combines them into a path-level
probability of a correlated alert.

The combination is not naive independence (which drives P->1 on any long path)
nor pure worst-case (which ignores cumulative exposure). It blends the two by a
correlation coefficient - the same intuition as the max/mean path score, but in
probability space:

    P(detected) = rho * max(p_i) + (1 - rho) * (1 - prod(1 - p_i))

- ``rho = 1`` : everything correlates into one incident driven by the loudest
  step (a mature SOC that triages holistically).
- ``rho = 0`` : every edge is an independent detection opportunity, so more hops
  means more chances to trip something (cumulative exposure).

The default (0.5) sits between. ``rho`` is exposed as config so it can be tuned
against real incident data.
"""
from __future__ import annotations

from .schema import ScoringConfig


def score_to_probability(score: float) -> float:
    """Map a 0-100 noise score to a per-edge detection probability (0-1).

    A first-order linear mapping: the score is already an expected detection
    cost, so score 30 -> a ~30% chance the SOC catches that single action.
    Kept simple and interpretable; calibration refines the scores upstream.
    """
    return max(0.0, min(1.0, score / 100.0))


def path_detection_probability(
    edge_scores: list,
    config: ScoringConfig | None = None,
) -> float:
    """Probability that a path trips a correlated alert (0-1)."""
    config = config or ScoringConfig()
    probs = [score_to_probability(s) for s in edge_scores]
    if not probs:
        return 0.0
    noisy_or = 1.0
    for p in probs:
        noisy_or *= (1.0 - p)
    noisy_or = 1.0 - noisy_or
    loudest = max(probs)
    rho = config.correlation
    return rho * loudest + (1.0 - rho) * noisy_or
