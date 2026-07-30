"""Score against deployed detections via Sigma rules.

Sigma is the community detection-as-code standard: a rule is YAML declaring a
log source, detection logic, and ATT&CK tags. This module parses a set of
deployed Sigma rules, works out which corpus edges each rule would fire on
(matching the edge's telemetry event IDs and MITRE technique), and emits an
environment profile whose ``adjustments`` raise the covered edges toward a
detection floor. That profile drops straight into ``--environment``, so a
NoiseHound run can be scored against the detections a defender has *actually
written* instead of static estimates.

It also reports coverage: which corpus edges your rules watch, and - the useful
part for detection engineering - which attack edges no deployed rule covers.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

from . import __version__
from .corpus import load_corpus

# Sigma rule 'level' -> detection floor when a rule covers an edge.
_LEVEL_FLOOR = {
    "informational": 40,
    "low": 55,
    "medium": 70,
    "high": 85,
    "critical": 95,
}
_DEFAULT_LEVEL = "medium"
# An event-ID match with no technique confirmation (untagged rule, or edge with
# no technique) is slightly less certain the rule is scoped to this edge.
_UNCONFIRMED_PENALTY = 10

_TECH_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)


class SigmaRule:
    __slots__ = ("title", "level", "status", "event_ids", "techniques", "source")

    def __init__(self, title, level, status, event_ids, techniques, source):
        self.title = title
        self.level = level
        self.status = status
        self.event_ids = event_ids      # set[int]
        self.techniques = techniques    # set[str] like {"T1003.006"}
        self.source = source


def _collect_event_ids(node, out: set) -> None:
    """Walk a Sigma detection block collecting any EventID values."""
    if isinstance(node, dict):
        for key, val in node.items():
            if str(key).split("|", 1)[0].strip().lower() == "eventid":
                for v in (val if isinstance(val, list) else [val]):
                    try:
                        out.add(int(v))
                    except (TypeError, ValueError):
                        pass
            else:
                _collect_event_ids(val, out)
    elif isinstance(node, list):
        for item in node:
            _collect_event_ids(item, out)


def _techniques(tags) -> set:
    out = set()
    for tag in tags or []:
        m = _TECH_RE.fullmatch(str(tag).strip())
        if m:
            out.add(m.group(1).upper())
    return out


def parse_rules(path: str) -> list:
    """Parse every Sigma .yml/.yaml rule under a file or directory."""
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError(
            "PyYAML is required for Sigma parsing - install with: "
            "pip install 'noisehound[sigma]'"
        ) from exc

    files = []
    if os.path.isdir(path):
        for root, _dirs, names in os.walk(path):
            for n in names:
                if n.endswith((".yml", ".yaml")):
                    files.append(os.path.join(root, n))
    elif os.path.isfile(path):
        files.append(path)
    else:
        raise FileNotFoundError("Sigma rules path not found: %s" % path)

    rules = []
    for fpath in sorted(files):
        with open(fpath, "r", encoding="utf-8") as fh:
            try:
                docs = list(yaml.safe_load_all(fh))
            except yaml.YAMLError:
                continue
        for doc in docs:
            if not isinstance(doc, dict) or "detection" not in doc:
                continue
            event_ids: set = set()
            _collect_event_ids(doc.get("detection", {}), event_ids)
            rules.append(SigmaRule(
                title=doc.get("title", os.path.basename(fpath)),
                level=str(doc.get("level", _DEFAULT_LEVEL)).lower(),
                status=str(doc.get("status", "")).lower(),
                event_ids=event_ids,
                techniques=_techniques(doc.get("tags")),
                source=os.path.basename(fpath),
            ))
    return rules


def _edge_event_ids(entry: dict) -> set:
    ids = set()
    for t in entry.get("telemetry", []) or []:
        if t.get("source") in ("windows_security", "sysmon") and t.get("event_id") is not None:
            ids.add(int(t["event_id"]))
    return ids


def _tech_match(rule_techs: set, edge_tech: str | None) -> bool:
    if not edge_tech:
        return False
    edge = edge_tech.upper()
    edge_base = edge.split(".", 1)[0]
    for rt in rule_techs:
        if rt == edge or rt.split(".", 1)[0] == edge_base:
            return True
    return False


def compute_coverage(corpus, rules: list) -> dict:
    """For each corpus edge, the best deployed-rule coverage (score + why).

    Conservative by design (a defensive tool must not hide gaps by over-claiming
    coverage): a rule covers an edge only if it references an event ID the edge
    generates AND, when the rule is ATT&CK-tagged, its technique agrees with the
    edge's. This rejects the common false positive where many distinct abuses
    share one event ID (e.g. everything under DS-Access 4662). A shared technique
    with no shared event ID is NOT counted - it does not mean the rule fires on
    this edge's telemetry.
    """
    coverage = {}
    for entry in corpus:
        et = entry["edge_type"]
        edge_ids = _edge_event_ids(entry)
        edge_tech = entry.get("mitre_technique")
        best = None
        for rule in rules:
            if not (edge_ids & rule.event_ids):
                continue  # rule does not fire on any event this edge generates
            # If the rule is technique-scoped and the edge has a technique, they
            # must agree - otherwise the rule targets a different abuse that
            # merely shares the event ID.
            confirmed = _tech_match(rule.techniques, edge_tech)
            if rule.techniques and edge_tech and not confirmed:
                continue
            floor = _LEVEL_FLOOR.get(rule.level, _LEVEL_FLOOR[_DEFAULT_LEVEL])
            match = "event_id"
            if confirmed:
                match = "event_id+technique"
            else:
                floor = max(0, floor - _UNCONFIRMED_PENALTY)
            if best is None or floor > best["score"]:
                best = {"score": floor, "match": match, "rule": rule.title, "level": rule.level}
        if best is not None:
            coverage[et] = best
    return coverage


def to_environment_profile(coverage: dict, name: str = "sigma-coverage") -> dict:
    return {
        "_comment": "Generated by noisehound-sigma v%s from deployed Sigma rules. "
                    "adjustments raise edges covered by a rule toward a detection floor. "
                    "Pass with --environment." % __version__,
        "name": name,
        "adjustments": {et: info["score"] for et, info in coverage.items()},
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="noisehound-sigma",
        description="Turn deployed Sigma rules into a NoiseHound environment "
                    "profile and a coverage report.")
    p.add_argument("--rules", "-r", required=True, help="Sigma rule file or directory.")
    p.add_argument("--out", "-o", default=None, help="Write the environment profile here.")
    p.add_argument("--corpus", default=None, help="Corpus directory (default: bundled).")
    p.add_argument("--name", default="sigma-coverage", help="Profile name.")
    p.add_argument("--quiet", action="store_true", help="Suppress the coverage report.")
    p.add_argument("--version", action="version", version="noisehound-sigma %s" % __version__)
    return p


def _render_report(corpus, coverage: dict) -> str:
    all_edges = {e["edge_type"] for e in corpus}
    covered = set(coverage)
    uncovered = sorted(all_edges - covered)
    lines = ["SIGMA COVERAGE  %d/%d corpus edges covered by deployed rules"
             % (len(covered), len(all_edges)), ""]
    lines.append("Covered (edge -> detection floor, match, rule):")
    for et in sorted(coverage, key=lambda e: -coverage[e]["score"]):
        c = coverage[et]
        lines.append("  %-22s %3d  [%s]  %s" % (et, c["score"], c["match"], c["rule"][:48]))
    lines.append("")
    lines.append("Detection gaps - attack edges NO deployed rule covers:")
    lines.append("  " + (", ".join(uncovered) if uncovered else "(none - full coverage)"))
    return "\n".join(lines)


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        corpus = load_corpus(args.corpus)
        rules = parse_rules(args.rules)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    coverage = compute_coverage(corpus, rules)
    profile = to_environment_profile(coverage, args.name)
    out_json = json.dumps(profile, indent=2, ensure_ascii=False)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out_json + "\n")
        print("parsed %d rules; wrote coverage profile (%d edges) to %s"
              % (len(rules), len(coverage), args.out), file=sys.stderr)
    else:
        print(out_json)

    if not args.quiet:
        print("\n" + _render_report(corpus, coverage), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
