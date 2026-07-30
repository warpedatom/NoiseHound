"""Constrained pathing: exclude nodes or edge types before solving.

Operators often want the quietest path *subject to a constraint* - avoid an
EDR-monitored jump box, never touch a honeypot account, or refuse a specific
technique. This builds a filtered copy of the graph with the excluded nodes and
edge types removed, which the solver then treats as the whole world.

Edge-type exclusion is per-type: an edge between two nodes survives if it still
has a non-excluded relationship (an edge that is both AdminTo and CanRDP remains
usable via AdminTo when only CanRDP is excluded).
"""
from __future__ import annotations

import networkx as nx


def apply_constraints(
    g: nx.DiGraph,
    avoid_nodes: set | None = None,
    avoid_edge_types: set | None = None,
    keep_nodes: set | None = None,
) -> nx.DiGraph:
    """Return a filtered copy of g with avoided nodes and edge types removed.

    ``keep_nodes`` (typically the source and objective) are never dropped even
    if named in ``avoid_nodes``.
    """
    avoid_nodes = set(avoid_nodes or ())
    keep_nodes = set(keep_nodes or ())
    avoid_types = {t.strip().lower() for t in (avoid_edge_types or ())}
    drop_nodes = avoid_nodes - keep_nodes

    h = nx.DiGraph()
    h.graph.update(g.graph)
    for n, data in g.nodes(data=True):
        if n in drop_nodes:
            continue
        h.add_node(n, **data)

    for u, v, data in g.edges(data=True):
        if u not in h or v not in h:
            continue
        types = [
            t for t in (data.get("edge_types") or [data.get("edge_type")])
            if t and t.strip().lower() not in avoid_types
        ]
        if not types:
            continue
        new = dict(data)
        new["edge_types"] = list(types)
        new["edge_type"] = types[0]
        h.add_edge(u, v, **new)

    return h
