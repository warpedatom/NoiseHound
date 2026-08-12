"""NoiseHound command-line interface."""
from __future__ import annotations

import argparse
import json
import sys

import networkx as nx

from . import __version__
from .annotate import annotate
from .constraints import apply_constraints
from .corpus import load_corpus
from .defend import analyse as analyse_gaps, render_text as render_gaps
from .engine import EngineError, choose_engine, find_deadair, solve_with_deadair
from .environment import EnvironmentProfile
from .ingest import edge_types_in, find_matches, find_node, load_graph
from .report import build_result, to_html, to_json
from .schema import ScoringConfig
from .solver import solve, solve_pareto


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="noisehound",
        description="Detection-aware Active Directory attack-path scoring. "
                    "Re-ranks BloodHound paths by expected detection cost.",
    )
    p.add_argument("--input", "-i", required=True,
                   help="BloodHound export (.zip), JSON file, directory, or a "
                        "bolt://host:7687 Neo4j URI (BloodHound CE database).")
    p.add_argument("--neo4j-user", default=None,
                   help="Neo4j username for Bolt input (default: $NEO4J_USER or 'neo4j').")
    p.add_argument("--neo4j-password", default=None,
                   help="Neo4j password for Bolt input (default: $NEO4J_PASSWORD). "
                        "Prefer the env var over passing it on the command line.")
    p.add_argument("--neo4j-database", default=None,
                   help="Neo4j database name for Bolt input (default: $NEO4J_DATABASE).")
    p.add_argument("--objective", "-o", required=True,
                   help="Target node (e.g. 'Domain Admins' or an object id).")
    p.add_argument("--source", "-s", required=True,
                   help="Starting principal (e.g. 'jdoe' or an object id).")
    p.add_argument("--domain", "-d", default="",
                   help="Target domain label for the report header.")
    p.add_argument("--paths", "-k", type=int, default=5,
                   help="Number of quietest paths to return (default 5).")
    p.add_argument("--corpus", default=None,
                   help="Edge-mapping corpus directory (default: bundled edge_mappings/).")
    p.add_argument("--environment", "-e", default=None,
                   help="Operator-declared target posture JSON (adjusts scores; see samples/env_profile.example.json).")
    p.add_argument("--tooling", choices=["onhost", "remote", "native"], default=None,
                   help="Operator tradecraft: 'onhost' off-the-shelf tools (loud EDR signature) vs "
                        "'remote'/'native' quiet tradecraft (no signatured binary on the host). Moves the "
                        "endpoint-signature component of tool-sensitive edges; see docs/TOOLING_AXIS.md.")
    p.add_argument("--live-scores", default=None, metavar="FILE",
                   help="JSON of measured live scores that override corpus/environment (Phase 2). Keys: "
                        "'by_edge_type' {edge: score} and/or 'overrides' [{source,target,edge_type,score}].")
    p.add_argument("--format", "-f", choices=["json", "html", "text"], default="text",
                   help="Output format (default text).")
    p.add_argument("--defensive", action="store_true",
                   help="Blue-team view: report detection gaps on the quietest paths and the "
                        "controls that would close them, ranked by impact.")
    p.add_argument("--out", default=None,
                   help="Write output to this file instead of stdout.")
    p.add_argument("--rank-by", choices=["noise", "probability"], default="noise",
                   help="Rank paths by noise score (default) or detection probability.")
    p.add_argument("--pareto", action="store_true",
                   help="Return the Pareto frontier over noise/hops/detection-probability "
                        "(the genuine trade-offs) instead of a single ranking.")
    p.add_argument("--engine", choices=["auto", "python", "rust"], default="auto",
                   help="Solve engine: auto (DeadAir on large graphs if present), "
                        "python (built-in), or rust (force DeadAir).")
    p.add_argument("--avoid", action="append", default=[], metavar="NODE",
                   help="Exclude a node from all paths (repeatable), e.g. an EDR-monitored host.")
    p.add_argument("--avoid-edge", action="append", default=[], metavar="EDGE_TYPE",
                   help="Exclude an edge type from all paths (repeatable), e.g. DCSync.")
    p.add_argument("--correlation", type=float, default=0.5,
                   help="SOC correlation coefficient for P(detected), 0..1 (default 0.5).")
    p.add_argument("--max-weight", type=float, default=0.6,
                   help="Weight on the loudest edge (default 0.6).")
    p.add_argument("--mean-weight", type=float, default=0.4,
                   help="Weight on the mean edge noise (default 0.4).")
    p.add_argument("--default-noise", type=int, default=60,
                   help="Score for edge types absent from the corpus (default 60).")
    p.add_argument("--candidates", type=int, default=200,
                   help="Simple paths to enumerate before re-ranking (default 200).")
    p.add_argument("--version", action="version", version="NoiseHound %s" % __version__)
    return p


def _render_text(result: dict) -> str:
    lines = []
    lines.append("NoiseHound %s" % result.get("version", ""))
    lines.append("Domain: %s   Source: %s -> Objective: %s"
                 % (result.get("target_domain", "?"),
                    result.get("source_principal", "?"),
                    result.get("objective", "?")))
    if result.get("environment"):
        lines.append("Environment profile applied: %s" % result["environment"])
    if result.get("constraints"):
        c = result["constraints"]
        bits = []
        if c.get("avoid_nodes"):
            bits.append("nodes: " + ", ".join(c["avoid_nodes"]))
        if c.get("avoid_edge_types"):
            bits.append("edges: " + ", ".join(c["avoid_edge_types"]))
        lines.append("Constraints (avoided) -> " + "; ".join(bits))
    if result.get("mode") == "pareto":
        lines.append("Pareto frontier: each path is a genuine trade-off "
                     "(none is beaten on noise AND hops AND P(detect) by another).")
    cov = result.get("corpus_coverage")
    if cov:
        lines.append("Corpus coverage: %d/%d edges (%.0f%%)%s"
                     % (cov["known_edges"], cov["total_edges"], cov["coverage"] * 100,
                        (" | unknown: " + ", ".join(cov["unknown_types"])) if cov["unknown_types"] else ""))
    lines.append("")
    paths = result.get("paths", [])
    if not paths:
        lines.append("No path found from source to objective.")
        return "\n".join(lines)
    for p in paths:
        prob = p.get("detection_probability")
        prob_str = ("  P(detect)=%d%%" % round(prob * 100)) if prob is not None else ""
        lines.append("#%d  score=%s  hops=%d%s"
                     % (p["rank"], p["path_score"], p["hop_count"], prob_str))
        for e in p["edges"]:
            flag = "" if e.get("corpus_known", True) else "  [unknown edge -> default]"
            lines.append("     %-22s --%s (noise %s)-->  %s%s"
                         % (e["from"], e["edge_type"], e["noise"], e["to"], flag))
        lines.append("")
    return "\n".join(lines)


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)

    config = ScoringConfig(
        max_weight=args.max_weight,
        mean_weight=args.mean_weight,
        default_unknown_noise=args.default_noise,
        candidate_paths=args.candidates,
        correlation=args.correlation,
    )
    try:
        config.validate()
    except ValueError as exc:
        print("config error: %s" % exc, file=sys.stderr)
        return 2

    try:
        corpus = load_corpus(args.corpus, default_unknown_noise=args.default_noise)
    except (FileNotFoundError, ValueError) as exc:
        print("corpus error: %s" % exc, file=sys.stderr)
        return 2

    environment = None
    if args.environment:
        try:
            environment = EnvironmentProfile.from_file(args.environment)
        except (FileNotFoundError, ValueError, KeyError) as exc:
            print("environment profile error: %s" % exc, file=sys.stderr)
            return 2

    try:
        graph = load_graph(args.input, args.neo4j_user, args.neo4j_password,
                           args.neo4j_database)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print("ingest error: %s" % exc, file=sys.stderr)
        return 2

    def _resolve(identifier, label):
        matches = find_matches(graph, identifier)
        if not matches:
            return None
        chosen = find_node(graph, identifier)
        if len(matches) > 1:
            names = ", ".join(sorted(graph.nodes[m].get("name", m) for m in matches))
            print("warning: %s %r matched %d nodes (%s); using %s. "
                  "Qualify with @DOMAIN to disambiguate."
                  % (label, identifier, len(matches), names,
                     graph.nodes[chosen].get("name", chosen)), file=sys.stderr)
        return chosen

    src = _resolve(args.source, "source")
    if src is None:
        print("source principal not found in graph: %s" % args.source, file=sys.stderr)
        return 3
    dst = _resolve(args.objective, "objective")
    if dst is None:
        print("objective not found in graph: %s" % args.objective, file=sys.stderr)
        return 3

    # Apply constraints (avoided nodes / edge types) before annotate + solve.
    if args.avoid or args.avoid_edge:
        avoid_ids = set()
        for name in args.avoid:
            avoid_ids.update(find_matches(graph, name))
        graph = apply_constraints(graph, avoid_nodes=avoid_ids,
                                  avoid_edge_types=set(args.avoid_edge),
                                  keep_nodes={src, dst})

    live_scores: dict = {}
    if args.live_scores:
        try:
            with open(args.live_scores, "r", encoding="utf-8-sig") as fh:
                spec = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            print("live-scores error: %s" % exc, file=sys.stderr)
            return 2
        for et, sc in (spec.get("by_edge_type") or {}).items():
            live_scores[et] = float(sc)
        for o in (spec.get("overrides") or []):
            live_scores[(o["source"], o["target"], o["edge_type"])] = float(o["score"])

    stats = annotate(graph, corpus, live_scores=live_scores,
                     environment=environment, tooling=args.tooling)

    # Pick the solve engine (DeadAir Rust binary vs built-in Python).
    deadair = find_deadair()
    try:
        engine = choose_engine(args.engine, graph, deadair)
    except EngineError as exc:
        print("engine error: %s" % exc, file=sys.stderr)
        return 2

    try:
        if engine == "deadair":
            mode = "pareto" if args.pareto else args.rank_by
            try:
                paths = solve_with_deadair(deadair, graph, src, dst, args.paths, config, mode)
            except EngineError as exc:
                if args.engine == "auto":
                    print("warning: DeadAir failed (%s); using the Python engine." % exc,
                          file=sys.stderr)
                    engine = "python"
                else:
                    print("engine error: %s" % exc, file=sys.stderr)
                    return 2
        if engine == "python":
            if args.pareto:
                paths = solve_pareto(graph, src, dst, config=config, k=args.paths)
            else:
                paths = solve(graph, src, dst, k=args.paths, config=config, rank_by=args.rank_by)
    except nx.NetworkXNoPath:
        paths = []
    except nx.NodeNotFound as exc:
        print("solver error: %s" % exc, file=sys.stderr)
        return 3

    result = build_result(
        paths,
        target_domain=args.domain or graph.nodes[dst].get("name", "").split("@")[-1],
        objective=args.objective,
        source_principal=args.source,
        stats=stats,
    )
    if environment is not None:
        result["environment"] = environment.name
    result["engine"] = engine
    if args.pareto:
        result["mode"] = "pareto"
    if args.avoid or args.avoid_edge:
        result["constraints"] = {"avoid_nodes": args.avoid, "avoid_edge_types": args.avoid_edge}

    if args.defensive:
        gaps = analyse_gaps(graph, corpus, paths, config=config)
        if args.format == "json":
            result["detection_gaps"] = gaps
            out = to_json(result)
        else:
            out = render_gaps(gaps)
    elif args.format == "json":
        out = to_json(result)
    elif args.format == "html":
        out = to_html(result)
    else:
        out = _render_text(result)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out)
        print("wrote %s report to %s" % (args.format, args.out), file=sys.stderr)
    else:
        print(out)

    return 0
