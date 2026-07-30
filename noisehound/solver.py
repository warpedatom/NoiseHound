"""Noise-weighted path solver.

The scoring function (section 2.3 of the spec) is deliberately NOT additive:

    path_score = max(edge_scores) * max_weight + mean(edge_scores) * mean_weight

so it cannot be optimised directly by Dijkstra/Yen, which minimise a sum of
edge weights. Finding the exact minimum of a bottleneck-plus-mean objective over
simple paths is hard in general, so NoiseHound generates a strong candidate pool
and re-ranks it by the true score:

1. **Threshold sweep (correctness backstop).** For each distinct edge-noise
   value ``t`` present in the graph, restrict to the subgraph of edges with
   score <= t and take the min-weight and min-hop path within it. This is cheap
   (one Dijkstra per distinct value, and there are few distinct values) and
   provably surfaces, for every achievable "loudest edge" level, the quietest
   route that stays under it. This is what a naive k-shortest-by-sum pass alone
   misses: a longer path made of uniformly quiet edges can beat a shorter path
   containing one loud edge, even though it has a higher edge-weight *sum*.

2. **k-shortest by weight (breadth).** Enumerate simple paths quiet-first with
   Yen's algorithm, bounded by ``candidate_paths``, to widen the pool.

3. Re-rank the union by the real ``path_score`` and return the top k.

The result is a robust heuristic - not a proven global optimum, but it no longer
misses the obvious quiet-but-long route the way a pure summed-weight search does
(see tests/test_noisehound.py::test_solver_prefers_uniformly_quiet_long_path).

Objectives that are groups are handled by treating the objective node itself as
the sink: reaching it (typically via a final MemberOf/control edge) is the win,
matching BloodHound semantics.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import networkx as nx

from .probability import path_detection_probability
from .schema import ScoringConfig


@dataclass
class ScoredPath:
    rank: int
    path_score: float
    hop_count: int
    edges: list  # list of dicts: from, to, edge_type, noise, corpus_known
    detection_probability: float = 0.0  # 0-1 chance of a correlated alert

    def to_dict(self) -> dict:
        return {
            "rank": self.rank,
            "path_score": round(self.path_score, 1),
            "detection_probability": round(self.detection_probability, 3),
            "hop_count": self.hop_count,
            "edges": self.edges,
        }


def score_path(edge_scores: list, config: ScoringConfig) -> float:
    """Apply the weighted max/mean scoring to a list of edge noise scores."""
    if not edge_scores:
        return 0.0
    loudest = max(edge_scores)
    average = sum(edge_scores) / len(edge_scores)
    return loudest * config.max_weight + average * config.mean_weight


def _path_to_edges(g: nx.DiGraph, nodes: list) -> tuple[list, list]:
    edges = []
    scores = []
    for u, v in zip(nodes, nodes[1:]):
        data = g.get_edge_data(u, v)
        noise = data["effective_noise_score"]
        scores.append(noise)
        edges.append(
            {
                "from": g.nodes[u].get("name", u),
                "to": g.nodes[v].get("name", v),
                "edge_type": data["edge_type"],
                "noise": round(noise, 1),
                "corpus_known": data.get("corpus_known", False),
            }
        )
    return edges, scores


def _threshold_candidates(g: nx.DiGraph, source: str, objective: str) -> list:
    """For each distinct edge-noise level, the quietest route staying under it."""
    thresholds = sorted({d["effective_noise_score"] for _, _, d in g.edges(data=True)})
    seen: set = set()
    out: list = []
    for t in thresholds:
        # Subgraph view of edges whose effective noise is <= t. A view avoids
        # copying the graph on every threshold.
        sub = nx.subgraph_view(
            g, filter_edge=lambda u, v, t=t: g[u][v]["effective_noise_score"] <= t
        )
        if source not in sub or objective not in sub:
            continue
        for weighted in (True, False):
            try:
                if weighted:
                    nodes = nx.shortest_path(sub, source, objective, weight="weight")
                else:
                    nodes = nx.shortest_path(sub, source, objective)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            key = tuple(nodes)
            if key not in seen:
                seen.add(key)
                out.append(nodes)
    return out


def _scored_candidates(g, source, objective, config) -> list:
    """Generate and score the candidate path pool (shared by solve/solve_pareto)."""
    if source not in g:
        raise nx.NodeNotFound("source node not in graph: %s" % source)
    if objective not in g:
        raise nx.NodeNotFound("objective node not in graph: %s" % objective)
    if source == objective:
        return []

    candidates: dict = {}  # tuple(nodes) -> nodes

    # (1) Threshold sweep - the correctness backstop.
    for nodes in _threshold_candidates(g, source, objective):
        candidates[tuple(nodes)] = nodes

    # (2) k-shortest simple paths by additive weight - breadth, bounded by a
    # path count and a wall-clock budget so a large graph cannot run away.
    try:
        gen = nx.shortest_simple_paths(g, source, objective, weight="weight")
        deadline = time.monotonic() + config.time_budget_s
        found = 0
        for nodes in gen:
            candidates[tuple(nodes)] = nodes
            found += 1
            if found >= config.candidate_paths or time.monotonic() > deadline:
                break
    except nx.NetworkXNoPath:
        pass

    scored = []
    for nodes in candidates.values():
        edges, scores = _path_to_edges(g, nodes)
        scored.append({
            "path_score": score_path(scores, config),
            "prob": path_detection_probability(scores, config),
            "hops": len(nodes) - 1,
            "sum_noise": sum(e["noise"] for e in edges),
            "nodes": nodes,
            "edges": edges,
        })
    return scored


def _to_scored_path(rank: int, item: dict) -> ScoredPath:
    return ScoredPath(
        rank=rank,
        path_score=item["path_score"],
        hop_count=item["hops"],
        edges=item["edges"],
        detection_probability=item["prob"],
    )


def solve(
    g: nx.DiGraph,
    source: str,
    objective: str,
    k: int = 5,
    config: ScoringConfig | None = None,
    rank_by: str = "noise",
) -> list:
    """Return up to k quietest paths from source to objective, re-ranked.

    ``source`` and ``objective`` are node ids (resolve friendly names with
    ingest.find_node before calling). Raises nx.NodeNotFound if either is
    absent. Returns [] if no path exists.

    ``rank_by`` selects the ranking metric: "noise" (the max/mean path score,
    default) or "probability" (path detection probability, which penalises long
    paths more via cumulative exposure).
    """
    config = config or ScoringConfig()
    config.validate()
    scored = _scored_candidates(g, source, objective, config)
    if not scored:
        return []

    if rank_by == "probability":
        scored.sort(key=lambda it: (it["prob"], it["path_score"], it["hops"], it["sum_noise"]))
    else:
        scored.sort(key=lambda it: (it["path_score"], it["hops"], it["sum_noise"]))

    return [_to_scored_path(i, it) for i, it in enumerate(scored[:k], start=1)]


def _dominates(b: dict, a: dict) -> bool:
    """True if path b dominates path a on all of (noise, hops, detection prob)."""
    ge = (b["path_score"] <= a["path_score"] and b["hops"] <= a["hops"]
          and b["prob"] <= a["prob"])
    strict = (b["path_score"] < a["path_score"] or b["hops"] < a["hops"]
              or b["prob"] < a["prob"])
    return ge and strict


def solve_pareto(
    g: nx.DiGraph,
    source: str,
    objective: str,
    config: ScoringConfig | None = None,
    k: int | None = None,
) -> list:
    """Return the Pareto-optimal paths over (noise, hops, detection probability).

    A path is on the frontier if no other candidate beats it on all three
    objectives at once - so the operator sees the genuine trade-offs (a louder
    but shorter path, a longer but quieter one) instead of a single winner.
    """
    config = config or ScoringConfig()
    config.validate()
    scored = _scored_candidates(g, source, objective, config)
    if not scored:
        return []

    front = [a for a in scored if not any(_dominates(b, a) for b in scored if b is not a)]
    # Deduplicate identical-objective paths, then order by noise for display.
    seen = set()
    unique = []
    for it in sorted(front, key=lambda x: (x["path_score"], x["hops"], x["prob"])):
        key = (round(it["path_score"], 3), it["hops"], round(it["prob"], 3))
        if key not in seen:
            seen.add(key)
            unique.append(it)
    if k:
        unique = unique[:k]
    return [_to_scored_path(i, it) for i, it in enumerate(unique, start=1)]
