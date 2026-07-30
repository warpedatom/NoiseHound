"""Corpus validator.

Runs the full schema check over every edge-mapping file plus a set of
contributor-friendly consistency checks (filename matches edge_type, scores in
range, telemetry present, recommended fields filled). Intended for CI and for
anyone adding or editing a corpus entry.

Exit code 0 when there are no errors (warnings are allowed); 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .schema import CorpusError, VALID_RELIABILITY, VALID_SOURCES, validate_entry

_DEFAULT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "edge_mappings")


def validate_corpus(directory: str) -> tuple[list, list, int]:
    """Return (errors, warnings, files_checked)."""
    errors: list = []
    warnings: list = []
    seen: dict = {}
    checked = 0

    if not os.path.isdir(directory):
        return (["corpus directory not found: %s" % directory], [], 0)

    files = sorted(n for n in os.listdir(directory) if n.endswith(".json"))
    if not files:
        return (["no .json corpus files found in %s" % directory], [], 0)

    for name in files:
        checked += 1
        full = os.path.join(directory, name)
        try:
            with open(full, "r", encoding="utf-8") as fh:
                entry = json.load(fh)
        except json.JSONDecodeError as exc:
            errors.append("%s: invalid JSON: %s" % (name, exc))
            continue

        try:
            edge_type = validate_entry(entry)
        except CorpusError as exc:
            errors.append("%s: %s" % (name, exc))
            continue

        # Filename should match the edge type (edge_mappings/DCSync.json).
        expected = edge_type + ".json"
        if name != expected:
            errors.append("%s: filename should be %r to match edge_type %r"
                          % (name, expected, edge_type))

        key = edge_type.strip().lower()
        if key in seen:
            errors.append("%s: duplicate edge_type %r (also in %s)"
                          % (name, edge_type, seen[key]))
        seen[key] = name

        # Recommended-but-not-required fields -> warnings, not errors.
        if not str(entry.get("description", "")).strip():
            warnings.append("%s: missing 'description'" % name)
        if not entry.get("telemetry"):
            warnings.append("%s: empty 'telemetry' (edge has no detection surface)" % name)
        if "mitre_technique" not in entry:
            warnings.append("%s: missing 'mitre_technique'" % name)
        for i, t in enumerate(entry.get("telemetry", []) or []):
            if "reliability" not in t:
                warnings.append("%s: telemetry[%d] missing 'reliability'" % (name, i))

    return (errors, warnings, checked)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="noisehound-validate",
        description="Validate the NoiseHound edge-mapping corpus.",
    )
    p.add_argument("--corpus", default=None,
                   help="Corpus directory to validate (default: bundled edge_mappings/).")
    p.add_argument("--strict", action="store_true",
                   help="Treat warnings as errors (fail on any warning).")
    p.add_argument("--version", action="version", version="noisehound-validate %s" % __version__)
    return p


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    directory = args.corpus or _DEFAULT_DIR

    errors, warnings, checked = validate_corpus(directory)

    for w in warnings:
        print("WARN  %s" % w, file=sys.stderr)
    for e in errors:
        print("ERROR %s" % e, file=sys.stderr)

    ok = not errors and not (args.strict and warnings)
    print("\nvalidated %d corpus file(s): %d error(s), %d warning(s) -> %s"
          % (checked, len(errors), len(warnings), "OK" if ok else "FAILED"),
          file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
