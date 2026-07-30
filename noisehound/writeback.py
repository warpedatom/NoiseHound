"""Write NoiseHound edge noise scores back into the BloodHound CE Neo4j.

After NoiseHound annotates a graph, this stamps each real BloodHound
relationship with a ``noise`` property (0-100) so the scores are visible and
queryable *inside the BloodHound UI* - colour edges by loudness, or run a
noise-weighted Cypher pathfind (see docs/CYPHER.md). Synthesised edges (ADCS
ESCx, DCSync, Kerberoast) have no matching relationship in Neo4j and are simply
skipped.

Typical use: read from the same Neo4j BloodHound populates, annotate, write back.
    noisehound-writeback -i bolt://localhost:7687
"""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .annotate import annotate
from .corpus import load_corpus
from .environment import EnvironmentProfile
from .ingest import load_graph
from .neo4j_ingest import is_bolt_uri, load_from_uri  # noqa: F401 (is_bolt_uri used)

_SET_CYPHER = (
    "UNWIND $rows AS row "
    "MATCH (a)-[r]->(b) "
    "WHERE a.objectid = row.s AND b.objectid = row.t AND type(r) = row.et "
    "SET r.noise = row.n, r.noise_known = row.k "
    "RETURN count(r) AS c"
)


def _rows(graph) -> list:
    return [
        {
            "s": u,
            "t": v,
            "et": d["edge_type"],
            "n": float(d["effective_noise_score"]),
            "k": bool(d.get("corpus_known", False)),
        }
        for u, v, d in graph.edges(data=True)
    ]


def write_scores(graph, uri, user, password, database=None, batch_size=1000) -> tuple:
    """Stamp r.noise / r.noise_known onto matching Neo4j relationships.

    Returns (relationships_updated, edges_attempted).
    """
    try:
        from neo4j import GraphDatabase
    except ImportError as exc:
        raise RuntimeError(
            "the neo4j driver is required for write-back - "
            "install it with: pip install 'noisehound[neo4j]'"
        ) from exc

    rows = _rows(graph)
    updated = 0
    driver = GraphDatabase.driver(uri, auth=(user, password))
    try:
        with driver.session(database=database) as session:
            for i in range(0, len(rows), batch_size):
                rec = session.run(_SET_CYPHER, rows=rows[i:i + batch_size]).single()
                if rec is not None:
                    updated += rec["c"]
    finally:
        driver.close()
    return updated, len(rows)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="noisehound-writeback",
        description="Write NoiseHound noise scores back into the BloodHound Neo4j "
                    "as an r.noise edge property.")
    p.add_argument("--input", "-i", required=True,
                   help="Graph to score: a bolt:// URI (usual), a BloodHound zip, or JSON.")
    p.add_argument("--target", default=None,
                   help="Bolt URI to write to (default: the --input URI when it is bolt://).")
    p.add_argument("--corpus", default=None, help="Corpus directory (default: bundled).")
    p.add_argument("--environment", "-e", default=None, help="Environment profile JSON.")
    p.add_argument("--neo4j-user", default=None)
    p.add_argument("--neo4j-password", default=None)
    p.add_argument("--neo4j-database", default=None)
    p.add_argument("--version", action="version", version="noisehound-writeback %s" % __version__)
    return p


def main(argv: list | None = None) -> int:
    import os
    args = build_parser().parse_args(argv)

    target = args.target or (args.input if is_bolt_uri(args.input) else None)
    if not is_bolt_uri(target or ""):
        print("error: a bolt:// --target (or a bolt:// --input) is required to write back",
              file=sys.stderr)
        return 2

    try:
        corpus = load_corpus(args.corpus)
        graph = load_graph(args.input, args.neo4j_user, args.neo4j_password, args.neo4j_database)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    environment = None
    if args.environment:
        try:
            environment = EnvironmentProfile.from_file(args.environment)
        except (FileNotFoundError, ValueError, KeyError) as exc:
            print("environment profile error: %s" % exc, file=sys.stderr)
            return 2

    annotate(graph, corpus, environment=environment)

    user = args.neo4j_user or os.environ.get("NEO4J_USER", "neo4j")
    password = args.neo4j_password if args.neo4j_password is not None else os.environ.get("NEO4J_PASSWORD", "")
    database = args.neo4j_database or os.environ.get("NEO4J_DATABASE") or None
    try:
        updated, attempted = write_scores(graph, target, user, password, database)
    except (RuntimeError, ValueError) as exc:
        print("write-back error: %s" % exc, file=sys.stderr)
        return 2

    print("wrote r.noise to %d relationships (%d edges scored) in %s"
          % (updated, attempted, target), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
