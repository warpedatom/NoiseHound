"""Live BloodHound ingestion over the Neo4j Bolt protocol.

Reads the graph directly from the Neo4j database BloodHound CE / SharpHound
populate, instead of an offline zip. The database is already post-processed, so
computed edges (including ADCS ESCx) arrive as relationship types and are scored
like any other edge - no synthesis needed on this path.

The pure record-to-graph step is separated from the driver connection so it can
be unit-tested without a running database; the connection is validated against a
real instance (e.g. BloodHound CE via Docker).
"""
from __future__ import annotations

import os

import networkx as nx

from .ingest import _add_edge

# Most specific label wins when a node carries several (BloodHound nodes are
# usually tagged Base plus their kind).
_LABEL_PRIORITY = [
    "User", "Computer", "Group", "Domain", "OU", "GPO", "Container",
    "CertTemplate", "EnterpriseCA", "RootCA", "NTAuthStore", "AIACA",
]
_BOLT_SCHEMES = ("bolt://", "neo4j://", "bolt+s://", "neo4j+s://", "bolt+ssc://", "neo4j+ssc://")


def is_bolt_uri(path: str) -> bool:
    return isinstance(path, str) and path.startswith(_BOLT_SCHEMES)


def _primary_label(labels: list) -> str:
    labels = labels or []
    for lbl in _LABEL_PRIORITY:
        if lbl in labels:
            return lbl
    non_base = [lbl for lbl in labels if lbl != "Base"]
    return non_base[0] if non_base else (labels[0] if labels else "Base")


def build_graph_from_records(node_records: list, rel_records: list) -> nx.DiGraph:
    """Assemble a DiGraph from Neo4j node and relationship rows.

    node_records: dicts with keys oid, labels (list), name.
    rel_records:  dicts with keys source, target, rtype.
    """
    g = nx.DiGraph()
    for n in node_records:
        oid = n.get("oid")
        if not oid:
            continue
        name = n.get("name") or oid
        g.add_node(oid, name=str(name).upper(), type=_primary_label(n.get("labels")))
    for r in rel_records:
        _add_edge(g, r.get("source"), r.get("target"), r.get("rtype"))
    # The DB is already analysed; ESC edges are relationship types. Nothing to
    # synthesise here (node properties are not fetched on this fast path).
    g.graph["adcs_edges_synthesized"] = 0
    return g


def load_graph_from_neo4j(
    uri: str,
    user: str,
    password: str,
    database: str | None = None,
) -> nx.DiGraph:
    """Connect to Neo4j over Bolt and build the internal graph."""
    try:
        from neo4j import GraphDatabase
    except ImportError as exc:
        raise RuntimeError(
            "the neo4j driver is required for Bolt ingestion - "
            "install it with: pip install 'noisehound[neo4j]'"
        ) from exc

    node_query = (
        "MATCH (n) WHERE n.objectid IS NOT NULL "
        "RETURN n.objectid AS oid, labels(n) AS labels, n.name AS name"
    )
    rel_query = (
        "MATCH (a)-[r]->(b) WHERE a.objectid IS NOT NULL AND b.objectid IS NOT NULL "
        "RETURN a.objectid AS source, b.objectid AS target, type(r) AS rtype"
    )

    driver = GraphDatabase.driver(uri, auth=(user, password))
    try:
        with driver.session(database=database) as session:
            node_records = [
                {"oid": rec["oid"], "labels": rec["labels"], "name": rec["name"]}
                for rec in session.run(node_query)
            ]
            rel_records = [
                {"source": rec["source"], "target": rec["target"], "rtype": rec["rtype"]}
                for rec in session.run(rel_query)
            ]
    finally:
        driver.close()

    g = build_graph_from_records(node_records, rel_records)
    if g.number_of_nodes() == 0:
        raise ValueError("no nodes returned from Neo4j at %s (is the graph loaded?)" % uri)
    return g


def load_from_uri(
    uri: str,
    user: str | None = None,
    password: str | None = None,
    database: str | None = None,
) -> nx.DiGraph:
    """Resolve credentials (args then env) and load from a Bolt URI."""
    user = user or os.environ.get("NEO4J_USER", "neo4j")
    password = password if password is not None else os.environ.get("NEO4J_PASSWORD", "")
    database = database or os.environ.get("NEO4J_DATABASE") or None
    return load_graph_from_neo4j(uri, user, password, database)
