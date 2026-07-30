"""Annotation pass: attach effective noise scores to every edge.

For each edge, the corpus gives a static score per edge type. Where several
BloodHound rights connect the same ordered pair of nodes, an operator would
naturally take the quietest one, so we collapse to the minimum-scoring type.

Score precedence (lowest authority to highest):

    static_noise_score  ->  environment-adjusted  ->  live_noise_score

``environment`` (an EnvironmentProfile) reflects the operator-declared detection
posture of the target and only ever raises a score toward a detection floor
implied by that posture. ``live_scores`` (Phase 2) is measured ground truth and
wins outright when present.
"""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from .corpus import Corpus
from .environment import EnvironmentProfile, adjust_score


@dataclass
class AnnotationStats:
    total_edges: int
    known_edges: int
    unknown_edges: int
    unknown_types: set

    @property
    def coverage(self) -> float:
        if self.total_edges == 0:
            return 1.0
        return self.known_edges / self.total_edges


def annotate(
    g: nx.DiGraph,
    corpus: Corpus,
    live_scores: dict | None = None,
    environment: EnvironmentProfile | None = None,
) -> AnnotationStats:
    """Annotate every edge in-place; return coverage statistics.

    ``live_scores`` optionally maps ``(src, dst, edge_type)`` -> score to
    override everything (the Phase 2 live-validation hook). ``environment``
    optionally adjusts static scores for the declared target posture.
    """
    live_scores = live_scores or {}
    total = known = unknown = 0
    unknown_types: set = set()

    for src, dst, data in g.edges(data=True):
        candidate_types = data.get("edge_types") or [data.get("edge_type")]

        best_type = None
        best_static = None
        best_known = False
        for et in candidate_types:
            static, is_known = corpus.static_score(et)
            if best_static is None or static < best_static:
                best_static = static
                best_type = et
                best_known = is_known

        entry = corpus.get(best_type)
        env_score = adjust_score(best_static, entry, best_type, environment)

        live = live_scores.get((src, dst, best_type))
        effective = float(live) if live is not None else float(env_score)

        data["edge_type"] = best_type
        data["static_noise_score"] = best_static
        data["env_noise_score"] = env_score
        data["live_noise_score"] = live
        data["effective_noise_score"] = effective
        data["corpus_known"] = best_known
        # networkx path helpers optimise an additive 'weight'; expose the
        # effective score under that key so Dijkstra/Yen enumerate quiet-first.
        data["weight"] = effective

        total += 1
        if best_known:
            known += 1
        else:
            unknown += 1
            unknown_types.add(best_type)

    return AnnotationStats(
        total_edges=total,
        known_edges=known,
        unknown_edges=unknown,
        unknown_types=unknown_types,
    )
