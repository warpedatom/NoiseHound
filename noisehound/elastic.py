"""Score against a *live* Elastic Security detection inventory.

Where ``noisehound-sigma`` reads Sigma rules from disk, this tier pulls the
detection rules a defender has actually deployed and enabled in Elastic Security
(Kibana's detection engine) and computes the same coverage: which corpus edges
those rules watch, and - the useful part - which attack edges nothing covers.
"Quiet *here* because no enabled rule fires on this edge."

It reuses the Sigma tier's conservative matcher (``compute_coverage``) but opts
into technique-only matches, because Elastic detection rules are largely
behavioural KQL/EQL queries that agree on an ATT&CK technique yet never name a
Windows EventID. Each enabled rule is normalised to the same shape a Sigma rule
exposes, so the coverage -> environment-profile -> report pipeline is shared.

Two input paths:

* **Live**  ``--kibana-url https://kibana:5601 --api-key <base64 ApiKey>``
  (or ``$KIBANA_URL`` / ``$KIBANA_API_KEY``). Reads
  ``GET /api/detection_engine/rules/_find`` with pagination. Read-only.
* **Offline**  ``--rules-json rules.json`` - a saved ``_find`` response (or a
  bare list of rule objects). Lets you run it against an export with no
  credentials, and is what the test fixture exercises.

Only ``enabled: true`` rules count as deployed detections.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

from . import __version__
from .corpus import load_corpus
from .sigma import compute_coverage, to_environment_profile, _LEVEL_FLOOR, _DEFAULT_LEVEL

# Elastic rule query languages reference Windows event codes through a handful of
# ECS/Winlogbeat fields; pull every integer that follows one of them (covers
# ``event.code:4688``, ``winlog.event_id: "4624"`` and list forms like
# ``event.code:(4728 or 4729)``).
_EVENT_FIELD_RE = re.compile(
    r"(?:event\.code|winlog\.event_id|event\.id|winlog\.event_data\.EventID)"
    r"\s*[:=]\s*(\"?\(?[\d\s,\"orOR|]+\)?)",
)
_INT_RE = re.compile(r"\d+")

# Elastic severity aligns with the Sigma level floors already defined.
_SEVERITY_ALIAS = {"": _DEFAULT_LEVEL}


class _Rule:
    """Duck-types sigma.SigmaRule so compute_coverage() consumes it unchanged."""
    __slots__ = ("title", "level", "status", "event_ids", "techniques", "source")

    def __init__(self, title, level, status, event_ids, techniques, source):
        self.title = title
        self.level = level
        self.status = status
        self.event_ids = event_ids
        self.techniques = techniques
        self.source = source


def _event_ids_from_query(query: str) -> set:
    ids: set = set()
    if not query:
        return ids
    for frag in _EVENT_FIELD_RE.findall(query):
        for m in _INT_RE.findall(frag):
            ids.add(int(m))
    return ids


def _techniques_from_threat(threat) -> set:
    """Collect ATT&CK technique + subtechnique ids from a rule's threat block."""
    out: set = set()
    for block in threat or []:
        if str(block.get("framework", "MITRE ATT&CK")).upper().replace(" ", "") \
                not in ("MITREATT&CK", "MITREATTACK", ""):
            continue
        for tech in block.get("technique", []) or []:
            tid = str(tech.get("id", "")).upper()
            if re.fullmatch(r"T\d{4}", tid):
                out.add(tid)
            for sub in tech.get("subtechnique", []) or []:
                sid = str(sub.get("id", "")).upper()
                if re.fullmatch(r"T\d{4}\.\d{3}", sid):
                    out.add(sid)
    return out


def normalise_rules(raw) -> list:
    """Turn a Kibana ``_find`` payload (or a bare rule list) into _Rule objects.

    Skips disabled rules - a rule that exists but is toggled off provides no
    live coverage, and counting it would overstate the defender's posture.
    """
    if isinstance(raw, dict):
        items = raw.get("data", raw.get("rules", []))
    else:
        items = raw
    rules = []
    for r in items or []:
        if not isinstance(r, dict):
            continue
        if r.get("enabled") is False:
            continue
        # Query text can live under a few keys across rule types (query/eql/esql).
        query = " ".join(str(r.get(k, "")) for k in ("query", "esql_query", "language"))
        level = str(r.get("severity", "") or _DEFAULT_LEVEL).lower()
        if level not in _LEVEL_FLOOR:
            level = _SEVERITY_ALIAS.get(level, _DEFAULT_LEVEL)
        rules.append(_Rule(
            title=r.get("name") or r.get("rule_id") or "unnamed rule",
            level=level,
            status="enabled",
            event_ids=_event_ids_from_query(query),
            techniques=_techniques_from_threat(r.get("threat")),
            source="elastic",
        ))
    return rules


def fetch_rules(kibana_url: str, api_key: str, per_page: int = 200,
                timeout: float = 30.0) -> list:
    """Read enabled detection rules from a live Kibana detection engine.

    Read-only paginated GET against ``/api/detection_engine/rules/_find``. Auth
    is an Elastic API key (``Authorization: ApiKey <base64>``). NoiseHound never
    writes to Kibana.
    """
    base = kibana_url.rstrip("/") + "/api/detection_engine/rules/_find"
    headers = {
        "Authorization": "ApiKey %s" % api_key,
        "kbn-xsrf": "true",
        "Content-Type": "application/json",
    }
    collected: list = []
    page = 1
    while True:
        url = "%s?page=%d&per_page=%d" % (base, page, per_page)
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise RuntimeError("Kibana returned HTTP %s for %s - check the URL and "
                               "API key privileges (read on Security detections)."
                               % (exc.code, url)) from exc
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise RuntimeError("could not reach Kibana at %s: %s" % (kibana_url, exc)) from exc
        batch = payload.get("data", [])
        collected.extend(batch)
        total = payload.get("total", len(collected))
        if len(collected) >= total or not batch:
            break
        page += 1
    return collected


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="noisehound-elastic",
        description="Turn a live Elastic Security detection inventory into a "
                    "NoiseHound environment profile and a coverage report.")
    src = p.add_argument_group("detection source (one of)")
    src.add_argument("--kibana-url", default=os.environ.get("KIBANA_URL"),
                     help="Kibana base URL, e.g. https://kibana:5601 ($KIBANA_URL).")
    src.add_argument("--api-key", default=os.environ.get("KIBANA_API_KEY"),
                     help="Elastic API key for Authorization: ApiKey ($KIBANA_API_KEY). "
                          "Prefer the env var over the command line.")
    src.add_argument("--rules-json", default=None,
                     help="Offline path: a saved detection_engine/rules/_find "
                          "response (or a bare list of rule objects).")
    p.add_argument("--per-page", type=int, default=200, help="Live fetch page size.")
    p.add_argument("--out", "-o", default=None, help="Write the environment profile here.")
    p.add_argument("--corpus", default=None, help="Corpus directory (default: bundled).")
    p.add_argument("--name", default="elastic-coverage", help="Profile name.")
    p.add_argument("--quiet", action="store_true", help="Suppress the coverage report.")
    p.add_argument("--version", action="version", version="noisehound-elastic %s" % __version__)
    return p


def _is_measurable(edge) -> bool:
    """True if a detection source could ever fire on this edge.

    An edge is measurable only if its abuse leaves a signal: a MITRE technique a
    behavioural rule can agree on, or a concrete telemetry event id. Structural
    topology edges (``Contains``, ``GpLink``) carry neither - nothing *happens*
    when they exist, so no honest rule can match them. Counting them as coverage
    gaps understates the defender's posture, the same way the Azure recipe treats
    structural ``AZHasRole``/``AZOwns`` as not-measurable-by-source.
    """
    if edge.get("mitre_technique"):
        return True
    return any(t.get("event_id") for t in edge.get("telemetry") or [])


def _render_report(corpus, coverage: dict, n_rules: int) -> str:
    measurable = {e["edge_type"] for e in corpus if _is_measurable(e)}
    structural = sorted({e["edge_type"] for e in corpus} - measurable)
    covered = set(coverage) & measurable
    uncovered = sorted(measurable - covered)
    lines = ["ELASTIC COVERAGE  %d/%d measurable edges covered by %d enabled rules"
             % (len(covered), len(measurable), n_rules), ""]
    lines.append("Covered (edge -> detection floor, match, rule):")
    for et in sorted(coverage, key=lambda e: -coverage[e]["score"]):
        c = coverage[et]
        lines.append("  %-22s %3d  [%s]  %s" % (et, c["score"], c["match"], c["rule"][:48]))
    lines.append("")
    lines.append("Detection gaps - attack edges NO enabled rule covers:")
    lines.append("  " + (", ".join(uncovered) if uncovered else "(none - full coverage)"))
    if structural:
        lines.append("")
        lines.append("Not measurable by this source (structural / no abuse signal - "
                     "excluded from the denominator):")
        lines.append("  " + ", ".join(structural))
    return "\n".join(lines)


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        corpus = load_corpus(args.corpus)
        if args.rules_json:
            with open(args.rules_json, "r", encoding="utf-8-sig") as fh:
                raw = json.load(fh)
        elif args.kibana_url and args.api_key:
            raw = fetch_rules(args.kibana_url, args.api_key, per_page=args.per_page)
        else:
            print("error: provide --rules-json, or --kibana-url and --api-key "
                  "(or $KIBANA_URL / $KIBANA_API_KEY).", file=sys.stderr)
            return 2
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    rules = normalise_rules(raw)
    coverage = compute_coverage(corpus, rules, allow_technique_only=True)
    profile = to_environment_profile(
        coverage, args.name,
        source="noisehound-elastic from the live Elastic Security detection inventory")
    out_json = json.dumps(profile, indent=2, ensure_ascii=False)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out_json + "\n")
        print("read %d enabled rules; wrote coverage profile (%d edges) to %s"
              % (len(rules), len(coverage), args.out), file=sys.stderr)
    else:
        print(out_json)

    if not args.quiet:
        print("\n" + _render_report(corpus, coverage, len(rules)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
