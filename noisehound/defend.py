"""Blue-team detection-gap analysis.

The quietest path to an objective is, by definition, where an environment's
detection is weakest. This module inverts NoiseHound's output for defenders: for
the quietest path(s) it identifies which edges are quiet *because the telemetry
that would catch them is off or absent by default*, maps each to the concrete
control that would make it loud, and ranks those controls by how much they raise
the quietest-path score. "Fixing these three things lifts your quietest path to
Domain Admins from 20 to 61."

It reuses the corpus telemetry and the environment model already in the tool:
the "fully instrumented" score of an edge (everything audited, EDR + Sysmon
present) minus its current score is the closable detection gap on that edge.
"""
from __future__ import annotations

from .environment import EnvironmentProfile, adjust_score
from .schema import ScoringConfig
from .solver import score_path

# A target with every relevant control turned on. The gap on an edge is its
# score here minus its score in the environment as it actually is.
FULLY_INSTRUMENTED = EnvironmentProfile(
    name="fully-instrumented",
    object_auditing_4662=True,
    ds_change_auditing_5136=True,
    edr="MDI",
    sysmon=True,
    powershell_logging_4104=True,
)


def controls_for_edge(entry: dict | None) -> list:
    """Human-readable controls that would raise this edge's detection."""
    if entry is None:
        return ["No corpus telemetry for this edge type - add it to the corpus."]
    controls: list = []

    def add(text):
        if text not in controls:
            controls.append(text)

    for t in entry.get("telemetry", []) or []:
        src = t.get("source")
        eid = t.get("event_id")
        rel = t.get("reliability")
        default_on = t.get("default_enabled", True)
        if src == "windows_security" and not default_on:
            if eid == 4662:
                add("Enable 'DS Access > Directory Service Access' auditing + object SACLs (Event 4662)")
            elif eid in (5136, 5137):
                add("Enable 'DS Access > Directory Service Changes' auditing (Event 5136/5137)")
            elif eid == 4104:
                add("Enable PowerShell Script Block Logging (Event 4104)")
            elif eid is not None:
                add("Enable the audit policy for Security Event %s" % eid)
        elif src == "edr_heuristic" and rel == "high":
            pc = t.get("product_class", "EDR")
            label = "Microsoft Defender for Identity (MDI)" if pc == "MDI" else "%s behavioural detection" % pc
            add("Deploy / enable %s" % label)
        elif src == "sysmon" and rel in ("high", "medium") and eid is not None:
            if eid == 10:
                add("Deploy Sysmon with ProcessAccess (Event 10) rules for LSASS")
            else:
                add("Deploy Sysmon (Event %s)" % eid)
        elif src == "wdac" and not default_on:
            add("Enforce WDAC / App Control (or audit mode) to catch off-the-shelf "
                "tooling (CodeIntegrity 3076/3077) - blind to native/remote tradecraft")
    if not controls:
        add("Already covered by default-on telemetry - no gap to close.")
    return controls


def analyse(graph, corpus, paths, config: ScoringConfig | None = None) -> dict:
    """Build a detection-gap report for a set of solved paths."""
    config = config or ScoringConfig()
    report_paths = []
    control_impact: dict = {}  # control text -> summed score delta

    for p in paths:
        edges_out = []
        current_scores = []
        audited_scores = []
        for e in p.edges:
            et = e["edge_type"]
            entry = corpus.get(et)
            base = entry["static_noise_score"] if entry else float(config.default_unknown_noise)
            audited = adjust_score(base, entry, et, FULLY_INSTRUMENTED)
            current = e["noise"]
            gap = round(audited - current, 1)
            current_scores.append(current)
            audited_scores.append(audited)
            controls = controls_for_edge(entry) if gap > 0 else []
            for c in controls:
                control_impact[c] = round(control_impact.get(c, 0.0) + gap, 1)
            edges_out.append({
                "from": e["from"], "to": e["to"], "edge_type": et,
                "current_noise": current, "instrumented_noise": round(audited, 1),
                "detection_gap": gap, "controls": controls,
            })
        report_paths.append({
            "rank": p.rank,
            "current_path_score": round(p.path_score, 1),
            "instrumented_path_score": round(score_path(audited_scores, config), 1),
            "edges": edges_out,
        })

    ranked_controls = sorted(control_impact.items(), key=lambda kv: -kv[1])
    return {
        "paths": report_paths,
        "recommended_controls": [
            {"control": c, "score_impact": impact} for c, impact in ranked_controls
        ],
    }


def render_text(report: dict) -> str:
    lines = ["DETECTION-GAP ANALYSIS (blue-team view)", ""]
    for p in report["paths"]:
        lift = p["instrumented_path_score"] - p["current_path_score"]
        lines.append("Path #%d  quietest now: %.1f  ->  fully instrumented: %.1f  (+%.1f closable)"
                     % (p["rank"], p["current_path_score"], p["instrumented_path_score"], lift))
        for e in p["edges"]:
            marker = "GAP " if e["detection_gap"] > 0 else "    "
            lines.append("  %s%-22s %-20s now %-5s -> %-5s (gap %s)"
                         % (marker, e["edge_type"], e["from"][:20],
                            e["current_noise"], e["instrumented_noise"], e["detection_gap"]))
            for c in e["controls"]:
                lines.append("        + %s" % c)
        lines.append("")
    if report["recommended_controls"]:
        lines.append("Top controls to deploy (ranked by total detection lift across these paths):")
        for i, rc in enumerate(report["recommended_controls"], 1):
            lines.append("  %d. [+%.1f] %s" % (i, rc["score_impact"], rc["control"]))
    return "\n".join(lines)
