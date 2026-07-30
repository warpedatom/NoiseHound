"""Two-tier solve engine: dispatch to the DeadAir Rust binary when available,
falling back to the built-in Python solver.

NoiseHound owns ingestion, corpus annotation, environment/Sigma scoring, and
constraints; it hands the fully-prepared graph to whichever engine solves it.
DeadAir consumes a scored-graph JSON (nodes + edges carrying effective noise)
and returns the same ranked-paths schema the Python solver produces, so it is a
transparent drop-in that is 10-100x faster on large graphs.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

from .schema import ScoringConfig
from .solver import ScoredPath

# Graphs at or above this many nodes use DeadAir in "auto" mode (below it the
# subprocess overhead outweighs the speedup and Python is instant).
AUTO_NODE_THRESHOLD = 5000


class EngineError(RuntimeError):
    """Raised when the requested engine cannot run."""


def emit_scored_graph(graph) -> dict:
    """Serialise an annotated graph into DeadAir's scored-graph input."""
    return {
        "nodes": [
            {"id": n, "name": d.get("name", n), "type": d.get("type", "Base")}
            for n, d in graph.nodes(data=True)
        ],
        "edges": [
            {
                "source": u,
                "target": v,
                "edge_type": d["edge_type"],
                "noise": d["effective_noise_score"],
                "corpus_known": d.get("corpus_known", False),
            }
            for u, v, d in graph.edges(data=True)
        ],
    }


def find_deadair() -> str | None:
    """Locate the DeadAir binary: env var, PATH, then the sibling build dirs."""
    env = os.environ.get("NOISEHOUND_DEADAIR")
    if env and os.path.isfile(env):
        return env
    for name in ("deadair", "deadair.exe"):
        found = shutil.which(name)
        if found:
            return found
    tools_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for rel in (
        "deadair/target/release/deadair.exe",
        "deadair/target/release/deadair",
        "deadair/target/debug/deadair.exe",
        "deadair/target/debug/deadair",
    ):
        cand = os.path.join(tools_dir, rel)
        if os.path.isfile(cand):
            return cand
    return None


def choose_engine(requested: str, graph, deadair: str | None) -> str:
    """Resolve requested engine ('auto'|'python'|'rust') to 'python' or 'deadair'."""
    if requested == "python":
        return "python"
    if requested == "rust":
        if not deadair:
            raise EngineError(
                "--engine rust requested but the deadair binary was not found "
                "(set NOISEHOUND_DEADAIR, put it on PATH, or build ../deadair)"
            )
        return "deadair"
    # auto
    if deadair and graph.number_of_nodes() >= AUTO_NODE_THRESHOLD:
        return "deadair"
    return "python"


def solve_with_deadair(
    binary: str,
    graph,
    source: str,
    objective: str,
    k: int,
    config: ScoringConfig,
    mode: str = "noise",
) -> list:
    """Solve via the DeadAir binary; returns ScoredPath objects matching the
    Python solver. The graph must already be annotated and constrained."""
    payload = json.dumps(emit_scored_graph(graph))
    cmd = [
        binary, "-i", "-", "-s", source, "-o", objective, "-k", str(k),
        "--mode", mode,
        "--max-weight", repr(config.max_weight),
        "--mean-weight", repr(config.mean_weight),
        "--correlation", repr(config.correlation),
        "--candidates", str(config.candidate_paths),
        "--time-budget", repr(config.time_budget_s),
    ]
    try:
        res = subprocess.run(
            cmd, input=payload, capture_output=True, text=True,
            timeout=max(60.0, config.time_budget_s * 3),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EngineError("deadair invocation failed: %s" % exc)
    if res.returncode != 0:
        raise EngineError("deadair exited %d: %s" % (res.returncode, res.stderr.strip()))
    try:
        doc = json.loads(res.stdout)
    except json.JSONDecodeError as exc:
        raise EngineError("deadair output was not valid JSON: %s" % exc)

    return [
        ScoredPath(
            rank=p["rank"],
            path_score=p["path_score"],
            hop_count=p["hop_count"],
            edges=p["edges"],
            detection_probability=p.get("detection_probability", 0.0),
        )
        for p in doc.get("paths", [])
    ]
