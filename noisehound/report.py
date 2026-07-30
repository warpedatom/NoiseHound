"""Report export: JSON (spec section 2.4) and self-contained HTML.

The HTML styling matches the OffsetInspect detection-boundary report convention
(Segoe UI, light theme, 2px-underlined h1, bordered tables, mono code) so the
DreadHost Research toolset reads as one product. Every value is HTML-encoded.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from . import __version__
from .annotate import AnnotationStats
from .solver import ScoredPath

_STYLE = (
    "<style>"
    "body{font-family:Segoe UI,Arial,sans-serif;margin:2rem;color:#1b1b1b}"
    "h1{border-bottom:2px solid #444}h2{margin-top:2rem}"
    "table{border-collapse:collapse;margin:.5rem 0}"
    "th,td{border:1px solid #ccc;padding:.25rem .5rem;font-size:.9rem;text-align:left}"
    "code{background:#f2f2f2;padding:0 .25rem}"
    ".meta{color:#555;font-size:.9rem}"
    ".loud{color:#a11;font-weight:bold}.quiet{color:#161}.mid{color:#a60}"
    ".score{font-variant-numeric:tabular-nums}"
    ".unknown{background:#fff4d6}"
    "</style>"
)


def build_result(
    paths: list,
    *,
    target_domain: str,
    objective: str,
    source_principal: str,
    stats: AnnotationStats | None = None,
) -> dict:
    """Assemble the spec section 2.4 result document."""
    doc = {
        "tool": "NoiseHound",
        "version": __version__,
        "target_domain": target_domain,
        "objective": objective,
        "source_principal": source_principal,
        "paths": [p.to_dict() for p in paths],
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if stats is not None:
        doc["corpus_coverage"] = {
            "total_edges": stats.total_edges,
            "known_edges": stats.known_edges,
            "unknown_edges": stats.unknown_edges,
            "coverage": round(stats.coverage, 3),
            "unknown_types": sorted(stats.unknown_types),
        }
    return doc


def to_json(result: dict, indent: int = 2) -> str:
    return json.dumps(result, indent=indent, ensure_ascii=False)


def _noise_class(score: float) -> str:
    if score >= 60:
        return "loud"
    if score >= 35:
        return "mid"
    return "quiet"


def _e(value) -> str:
    return html.escape(str(value))


def to_html(result: dict, title: str = "NoiseHound Attack-Path Noise Report") -> str:
    b = []
    b.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    b.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    b.append("<title>%s</title>" % _e(title))
    b.append(_STYLE)
    b.append("</head><body>")
    b.append("<h1>%s</h1>" % _e(title))

    b.append("<p class='meta'>")
    b.append(
        "Tool %s v%s &middot; domain <code>%s</code> &middot; "
        "source <code>%s</code> &rarr; objective <code>%s</code> &middot; generated %s"
        % (
            _e(result.get("tool", "NoiseHound")),
            _e(result.get("version", "")),
            _e(result.get("target_domain", "")),
            _e(result.get("source_principal", "")),
            _e(result.get("objective", "")),
            _e(result.get("generated_at", "")),
        )
    )
    b.append("</p>")

    cov = result.get("corpus_coverage")
    if cov:
        b.append(
            "<p class='meta'>Corpus coverage: %d/%d edges known (%.0f%%)."
            % (cov["known_edges"], cov["total_edges"], cov["coverage"] * 100)
        )
        if cov["unknown_types"]:
            b.append(
                " Unknown edge types defaulted to conservative score: <code>%s</code>."
                % _e(", ".join(cov["unknown_types"]))
            )
        b.append("</p>")

    paths = result.get("paths", [])
    if not paths:
        b.append("<p><strong>No path found from source to objective.</strong></p>")
        b.append("</body></html>")
        return "".join(b)

    b.append("<h2>Ranked paths (quietest first)</h2>")
    b.append("<table><thead><tr><th>Rank</th><th>Path score</th><th>P(detect)</th>"
             "<th>Hops</th><th>Route</th></tr></thead><tbody>")
    for p in paths:
        route = " &rarr; ".join(_e(e["from"]) for e in p["edges"])
        if p["edges"]:
            route += " &rarr; " + _e(p["edges"][-1]["to"])
        cls = _noise_class(p["path_score"])
        prob = p.get("detection_probability")
        prob_str = "%d%%" % round(prob * 100) if prob is not None else "-"
        b.append(
            "<tr><td>%d</td><td class='score %s'>%s</td><td class='score'>%s</td>"
            "<td>%d</td><td>%s</td></tr>"
            % (p["rank"], cls, _e(p["path_score"]), prob_str, p["hop_count"], route)
        )
    b.append("</tbody></table>")

    for p in paths:
        b.append("<h2>Path %d &mdash; score %s (%d hops)</h2>"
                 % (p["rank"], _e(p["path_score"]), p["hop_count"]))
        b.append("<table><thead><tr><th>#</th><th>From</th><th>Edge</th>"
                 "<th>To</th><th>Noise</th></tr></thead><tbody>")
        for i, e in enumerate(p["edges"], start=1):
            cls = _noise_class(e["noise"])
            row_cls = "" if e.get("corpus_known", True) else " class='unknown'"
            b.append(
                "<tr%s><td>%d</td><td><code>%s</code></td><td>%s</td>"
                "<td><code>%s</code></td><td class='score %s'>%s</td></tr>"
                % (row_cls, i, _e(e["from"]), _e(e["edge_type"]),
                   _e(e["to"]), cls, _e(e["noise"]))
            )
        b.append("</tbody></table>")

    b.append("</body></html>")
    return "".join(b)
