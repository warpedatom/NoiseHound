#!/usr/bin/env python3
"""Build ``samples/sample_lab_ce.zip`` from a real SharpHound CE collection.

Item #1 on the roadmap: ship a *BHCE-ingestable* bundled sample so the operator
walkthrough is a pure "upload -> writeback -> view" flow with no Cypher seed step.
Hand-authored fixtures satisfy NoiseHound's own parser but do not always clear
BHCE's ingest validator, so the reliable source is a genuine SharpHound export.

Source: the public GOAD ``sevenkingdoms.local`` training lab (13-file CE v6
collection incl. AD CS). Because it is a well-known public lab, its structure,
names, and per-deployment SIDs are non-sensitive. This sanitiser is deliberately
conservative - it preserves every SID, name, ObjectIdentifier, ACE, and edge so
the graph ingests and post-processes identically to the original, and only:

  1. normalises the ``nh_<timestamp>_<type>.json`` filenames to canonical
     ``<type>.json`` names, and
  2. scrubs any non-boilerplate ``description`` property - GOAD hides random
     hint strings in a couple of objects (e.g. the CALIBOU OU). Standard Windows
     built-in descriptions are kept so the graph still looks like a real domain.

Run from the repo root:  python samples/build_sample_lab_ce.py <source.zip>
"""
from __future__ import annotations

import io
import json
import re
import sys
import zipfile
from pathlib import Path

# The stock Windows built-in objects all carry fixed English descriptions; any
# description that is NOT one of these boilerplate strings is a lab-injected
# value and gets cleared. Matching on a prefix keeps this list short and robust.
_BOILERPLATE_MARKERS = (
    "Built-in", "Members of this group", "Members in this group",
    "Members can", "Members are", "Designated administrators",
    "All ", "Default container", "Default location", "Builtin",
    "Servers in this group", "A backward compatibility group",
    "Supports file replication", "Backup Operators", "DNS ", "Guests have",
    "Users are prevented", "Administrators have", "Key Distribution Center",
    "The container contains", "Contains configuration",
)


def _is_boilerplate(desc: str) -> bool:
    return any(desc.startswith(m) for m in _BOILERPLATE_MARKERS)


def _canonical_name(member: str) -> str:
    # nh_20260806174234_users.json -> users.json ; leave already-clean names.
    return re.sub(r"^.*?_(?=[a-z]+\.json$)", "", member)


def sanitise(src_zip: Path, out_zip: Path) -> dict:
    scrubbed = 0
    counts: dict[str, int] = {}
    with zipfile.ZipFile(src_zip) as zin, \
            zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zout:
        for member in zin.namelist():
            doc = json.loads(zin.read(member).decode("utf-8-sig"))
            for obj in doc.get("data", []):
                props = obj.get("Properties") or {}
                desc = props.get("description")
                if isinstance(desc, str) and desc.strip() and not _is_boilerplate(desc):
                    props["description"] = ""
                    scrubbed += 1
            counts[doc.get("meta", {}).get("type", member)] = len(doc.get("data", []))
            buf = io.BytesIO()
            buf.write(json.dumps(doc, separators=(",", ":")).encode("utf-8"))
            zout.writestr(_canonical_name(member), buf.getvalue())
    return {"scrubbed": scrubbed, "counts": counts}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: build_sample_lab_ce.py <source_sharphound.zip>", file=sys.stderr)
        return 2
    src = Path(argv[1])
    out = Path(__file__).with_name("sample_lab_ce.zip")
    stats = sanitise(src, out)
    print("wrote %s" % out)
    print("scrubbed %d non-boilerplate description(s)" % stats["scrubbed"])
    for t, c in sorted(stats["counts"].items()):
        print("  %-16s %d" % (t, c))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
