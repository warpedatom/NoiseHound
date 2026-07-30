"""Graph inspector.

Summarises an ingested BloodHound export without solving a path: node and edge
type histograms, corpus coverage, ADCS edges synthesised, and the loudest /
quietest edge types present. This is the fastest way to sanity-check that the
parser handled a real-world export - point it at a SharpHound/BloodHound CE zip
from a lab you have data for and confirm the shape looks right before pathing.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from . import __version__
from .annotate import annotate
from .corpus import load_corpus
from .environment import EnvironmentProfile
from .ingest import load_graph


def summarise(graph, corpus, environment=None) -> dict:
    stats = annotate(graph, corpus, environment=environment)

    node_types = Counter(d.get("type", "Base") for _, d in graph.nodes(data=True))

    edge_types: Counter = Counter()
    type_score: dict = {}
    type_known: dict = {}
    for _, _, d in graph.edges(data=True):
        et = d.get("edge_type")
        edge_types[et] += 1
        type_score[et] = d.get("effective_noise_score")
        type_known[et] = d.get("corpus_known", False)

    present = [
        {"edge_type": et, "count": edge_types[et],
         "effective_noise": type_score.get(et), "corpus_known": type_known.get(et, False)}
        for et in edge_types
    ]
    loud = sorted((p for p in present if p["effective_noise"] is not None),
                  key=lambda p: -p["effective_noise"])

    return {
        "tool": "NoiseHound",
        "version": __version__,
        "nodes": {
            "total": graph.number_of_nodes(),
            "by_type": dict(node_types.most_common()),
        },
        "edges": {
            "total": graph.number_of_edges(),
            "by_type": dict(edge_types.most_common()),
        },
        "adcs_edges_synthesized": graph.graph.get("adcs_edges_synthesized", 0),
        "corpus_coverage": {
            "known_edges": stats.known_edges,
            "total_edges": stats.total_edges,
            "coverage": round(stats.coverage, 3),
            "unknown_types": sorted(stats.unknown_types),
        },
        "loudest_edge_types": [
            {"edge_type": p["edge_type"], "effective_noise": p["effective_noise"],
             "count": p["count"]}
            for p in loud[:8]
        ],
        "quietest_edge_types": [
            {"edge_type": p["edge_type"], "effective_noise": p["effective_noise"],
             "count": p["count"]}
            for p in list(reversed(loud))[:8]
        ],
    }


def _render_text(s: dict) -> str:
    lines = ["NoiseHound inspect %s" % s["version"], ""]
    lines.append("Nodes: %d" % s["nodes"]["total"])
    for t, c in s["nodes"]["by_type"].items():
        lines.append("    %-14s %d" % (t, c))
    lines.append("")
    lines.append("Edges: %d  (ADCS ESC edges synthesised: %d)"
                 % (s["edges"]["total"], s["adcs_edges_synthesized"]))
    for t, c in s["edges"]["by_type"].items():
        cov = s["corpus_coverage"]
        flag = "" if t not in cov["unknown_types"] else "  [unknown -> default]"
        lines.append("    %-24s %d%s" % (t, c, flag))
    lines.append("")
    cov = s["corpus_coverage"]
    lines.append("Corpus coverage: %d/%d edges (%.0f%%)"
                 % (cov["known_edges"], cov["total_edges"], cov["coverage"] * 100))
    if cov["unknown_types"]:
        lines.append("    Unknown edge types (add to corpus): %s"
                     % ", ".join(cov["unknown_types"]))
    lines.append("")
    lines.append("Loudest edge types present:")
    for p in s["loudest_edge_types"]:
        lines.append("    %-24s noise %-5s  x%d"
                     % (p["edge_type"], p["effective_noise"], p["count"]))
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="noisehound-inspect",
        description="Summarise an ingested BloodHound export (no pathing).")
    p.add_argument("--input", "-i", required=True,
                   help="BloodHound export (.zip), JSON file, or directory.")
    p.add_argument("--corpus", default=None, help="Corpus directory (default: bundled).")
    p.add_argument("--environment", "-e", default=None, help="Environment profile JSON.")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    p.add_argument("--version", action="version", version="noisehound-inspect %s" % __version__)
    return p


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        corpus = load_corpus(args.corpus)
        graph = load_graph(args.input)
    except (FileNotFoundError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    environment = None
    if args.environment:
        try:
            environment = EnvironmentProfile.from_file(args.environment)
        except (FileNotFoundError, ValueError, KeyError) as exc:
            print("environment profile error: %s" % exc, file=sys.stderr)
            return 2

    summary = summarise(graph, corpus, environment)
    print(json.dumps(summary, indent=2) if args.json else _render_text(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
