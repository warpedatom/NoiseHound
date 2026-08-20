"""Measured Azure tier: turn a real Entra audit trail into calibration input.

The on-prem tiers are calibrated by triggering each abuse in a lab and counting
what fired (``noisehound-calibrate`` consumes a ``lab_detections.json`` of
``observations``). This module is the Azure-side *counter* that produces those
observations from Entra ID telemetry, so a lab tenant can be calibrated the same
way — "measure what actually fires," not expert estimates.

It is the cloud analogue of the on-prem PowerShell harness: instead of counting
Windows Security EventIDs on a DC, it counts **Microsoft Graph directory-audit
records** centrally. For each ``AZ*`` edge the operator exercised (declared in a
run manifest), it matches audit records by the Entra *activity signature* the
corpus now carries (``telemetry[].activity`` / ``category`` on the ``entra_audit``
source), within the run's time window, and emits ``{edge_type, runs, detections,
severity}``. That JSON drops straight into ``noisehound-calibrate`` (or is
calibrated inline with ``--profile-out``) to produce a measured Azure profile.

Inputs (all offline files the operator exports — NoiseHound never authenticates):

* ``--audit-log directoryAudits.json`` — a Graph ``/auditLogs/directoryAudits``
  export (``{"value":[...]}`` or a bare list). Each record supplies
  ``activityDisplayName``, ``category``, ``loggedByService``, ``result``,
  ``activityDateTime``.
* ``--manifest runs.json`` — what was exercised:
  ``{"environment": "lab-tenant-azure",
     "observations": [{"edge_type": "AZGlobalAdmin", "runs": 3,
                       "start": "2026-08-20T00:00:00Z", "end": "...Z"}]}``.
  ``start``/``end`` are optional; without them the whole log is the window.
* ``--risk-detections riskDetections.json`` — optional Graph
  ``/identityProtection/riskDetections`` export; a matching detection raises an
  edge's severity to the alert tier.

Only the *directory audit* signal is counted here; role/ownership-holding edges
(``AZHasRole``, ``AZOwns``) log nothing until the concrete abuse runs, and the
resource-plane edges (``AZUserAccessAdministrator``, ``AZVMContributor``,
``AZRunsAs``) surface in Azure Activity logs, not directory audits — all carry an
empty signature and are reported as not-audit-measurable rather than silently
scored.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .corpus import load_corpus


def _parse_dt(value):
    """Best-effort ISO-8601 parse; returns None if absent/unparseable.

    Entra stamps UTC as e.g. '2026-08-20T01:02:03.4567890Z'. datetime.fromisoformat
    (3.11+) handles the offset but not 7-digit fractional seconds or a bare 'Z' on
    older Pythons, so normalise both.
    """
    if not value:
        return None
    from datetime import datetime
    s = str(value).strip().replace("Z", "+00:00")
    if "." in s:  # trim fractional seconds to 6 digits (microseconds)
        head, _, tail = s.partition(".")
        digits = "".join(c for c in tail if c.isdigit())
        off = tail[len(digits):]
        s = "%s.%s%s" % (head, digits[:6], off)
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        try:
            return datetime.fromisoformat(s.split(".")[0] + "+00:00")
        except ValueError:
            return None


def edge_signatures(corpus) -> dict:
    """Map each AZ edge -> {'activity': [lowercased substrings], 'category': str|None}.

    Reads the entra_audit telemetry signatures added to the corpus. Edges with no
    entra_audit source, or an explicitly empty activity list, are not directory-
    audit measurable and are omitted.
    """
    sigs = {}
    for entry in corpus:
        et = entry["edge_type"]
        if not et.startswith("AZ"):
            continue
        for t in entry.get("telemetry", []) or []:
            if t.get("source") != "entra_audit":
                continue
            acts = [str(a).lower() for a in (t.get("activity") or []) if str(a).strip()]
            if acts:
                sigs[et] = {"activity": acts, "category": t.get("category")}
    return sigs


def _records(raw) -> list:
    if isinstance(raw, dict):
        return raw.get("value", raw.get("data", [])) or []
    return raw or []


def _matches(rec: dict, sig: dict) -> bool:
    name = str(rec.get("activityDisplayName", "")).lower()
    if not any(a in name for a in sig["activity"]):
        return False
    # If the corpus names a category, require it to agree when the record has one
    # (records always do); this rejects a like-named activity from another area.
    cat = sig.get("category")
    if cat and rec.get("category") and str(rec["category"]).lower() != str(cat).lower():
        return False
    return True


def _in_window(rec: dict, start, end) -> bool:
    if start is None and end is None:
        return True
    when = _parse_dt(rec.get("activityDateTime"))
    if when is None:
        return True  # undated record: don't exclude on a window we can't test
    if start is not None and when < start:
        return False
    if end is not None and when > end:
        return False
    return True


def build_observations(manifest: dict, audit_records: list, signatures: dict,
                       risk_detections: list | None = None) -> dict:
    """Turn a run manifest + audit records into a calibrate-ready detections dict."""
    risk_detections = risk_detections or []
    risk_activities = {str(r.get("activity", "")).lower() for r in risk_detections
                       if isinstance(r, dict)}
    observations = []
    unmeasurable = []
    for decl in manifest.get("observations", []) or []:
        et = decl.get("edge_type")
        if not et:
            continue
        runs = max(1, int(decl.get("runs", 1)))
        sig = signatures.get(et)
        if not sig:
            unmeasurable.append(et)
            continue
        start = _parse_dt(decl.get("start"))
        end = _parse_dt(decl.get("end"))
        hits = [r for r in audit_records if _matches(r, sig) and _in_window(r, start, end)]
        detections = min(runs, len(hits))
        # Alert tier: an ID-Protection risk detection referencing the same abuse.
        alerted = any(a and any(a in ra or ra in a for ra in risk_activities)
                      for a in sig["activity"])
        severity = "high" if alerted else "medium"
        obs = {"edge_type": et, "runs": runs, "detections": detections,
               "severity": severity,
               "signals": sorted({str(r.get("activityDisplayName")) for r in hits})}
        observations.append(obs)
    return {
        "environment": manifest.get("environment", "lab-tenant-azure"),
        "cloud": "entra",
        "observations": observations,
        "_unmeasurable": sorted(set(unmeasurable)),
    }


def _render_report(detections: dict, signatures: dict) -> str:
    obs = detections.get("observations", [])
    lines = ["ENTRA MEASURED  %d AZ edge(s) exercised; %d audit-measurable"
             % (len(obs) + len(detections.get("_unmeasurable", [])), len(obs)), ""]
    lines.append("edge_type                 runs  det   rate  activities matched")
    for o in sorted(obs, key=lambda x: -x["detections"] / x["runs"]):
        rate = o["detections"] / o["runs"]
        acts = ", ".join(o.get("signals") or []) or "(none in window)"
        lines.append("  %-24s %3d  %3d  %5.2f  %s"
                     % (o["edge_type"][:24], o["runs"], o["detections"], rate, acts[:44]))
    unmeas = detections.get("_unmeasurable", [])
    if unmeas:
        lines += ["", "Not directory-audit measurable (resource-plane / holding-only):",
                  "  " + ", ".join(unmeas)]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="noisehound-entra",
        description="Measure what Entra ID actually logged for triggered AZ* abuses "
                    "and emit calibrate-ready observations (a measured Azure tier).")
    p.add_argument("--audit-log", "-a", required=True,
                   help="Graph /auditLogs/directoryAudits export (JSON).")
    p.add_argument("--manifest", "-m", required=True,
                   help="Run manifest: which AZ edges were exercised, runs, and windows.")
    p.add_argument("--risk-detections", default=None,
                   help="Optional Graph /identityProtection/riskDetections export "
                        "(raises matched edges to the alert tier).")
    p.add_argument("--out", "-o", default=None,
                   help="Write the observations JSON (feeds noisehound-calibrate).")
    p.add_argument("--profile-out", default=None,
                   help="Also calibrate inline and write the measured environment profile here.")
    p.add_argument("--corpus", default=None, help="Corpus directory (default: bundled).")
    p.add_argument("--quiet", action="store_true", help="Suppress the report.")
    p.add_argument("--version", action="version", version="noisehound-entra %s" % __version__)
    return p


def _load(path):
    with open(path, "r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        corpus = load_corpus(args.corpus)
        audit = _records(_load(args.audit_log))
        manifest = _load(args.manifest)
        risk = _records(_load(args.risk_detections)) if args.risk_detections else []
    except (FileNotFoundError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    signatures = edge_signatures(corpus)
    detections = build_observations(manifest, audit, signatures, risk)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(detections, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print("wrote observations (%d edges) to %s"
              % (len(detections["observations"]), args.out), file=sys.stderr)

    if args.profile_out:
        from .calibrate import calibrate
        profile, _records_out = calibrate(detections, corpus)
        profile["_comment"] = ("MEASURED Azure tier - Entra directory-audit calibration "
                               "(noisehound-entra v%s). Pass with 'noisehound -e'." % __version__)
        with open(args.profile_out, "w", encoding="utf-8") as fh:
            json.dump(profile, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print("wrote measured Azure profile (%d edges) to %s"
              % (len(profile.get("adjustments", {})), args.profile_out), file=sys.stderr)

    if not args.out and not args.profile_out:
        print(json.dumps(detections, indent=2, ensure_ascii=False))

    if not args.quiet:
        print("\n" + _render_report(detections, signatures), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
