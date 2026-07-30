"""Load and index the edge-telemetry corpus."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Iterator

from . import DEFAULT_UNKNOWN_NOISE
from .schema import validate_entry

# Default corpus location: the edge_mappings/ dir shipped alongside the package.
_DEFAULT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "edge_mappings")


@dataclass
class Corpus:
    """An indexed, case-insensitive lookup of edge_type -> telemetry entry."""

    entries: dict  # normalised-edge-type -> raw entry dict
    default_unknown_noise: int = DEFAULT_UNKNOWN_NOISE

    @staticmethod
    def _norm(edge_type: str) -> str:
        return edge_type.strip().lower()

    def __contains__(self, edge_type: str) -> bool:
        return self._norm(edge_type) in self.entries

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[dict]:
        return iter(self.entries.values())

    def get(self, edge_type: str) -> dict | None:
        return self.entries.get(self._norm(edge_type))

    def static_score(self, edge_type: str) -> tuple[float, bool]:
        """Return (score, is_known) for an edge type.

        Unknown edge types return the conservative default so corpus gaps fail
        safe rather than under-reporting risk.
        """
        entry = self.get(edge_type)
        if entry is None:
            return float(self.default_unknown_noise), False
        return float(entry["static_noise_score"]), True

    def missing_edge_types(self, edge_types: set) -> set:
        """Edge types present in a graph but absent from the corpus."""
        return {et for et in edge_types if self._norm(et) not in self.entries}


def load_corpus(
    path: str | None = None,
    default_unknown_noise: int = DEFAULT_UNKNOWN_NOISE,
) -> Corpus:
    """Load every *.json edge file from a directory into a Corpus.

    Raises FileNotFoundError if the directory is missing and CorpusError (via
    validate_entry) on the first malformed file.
    """
    directory = path or _DEFAULT_DIR
    if not os.path.isdir(directory):
        raise FileNotFoundError("corpus directory not found: %s" % directory)

    entries: dict = {}
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json"):
            continue
        full = os.path.join(directory, name)
        with open(full, "r", encoding="utf-8") as fh:
            try:
                entry = json.load(fh)
            except json.JSONDecodeError as exc:
                raise ValueError("invalid JSON in %s: %s" % (full, exc)) from exc
        edge_type = validate_entry(entry)
        key = edge_type.strip().lower()
        if key in entries:
            raise ValueError(
                "duplicate edge_type %r (second file: %s)" % (edge_type, full)
            )
        entries[key] = entry

    if not entries:
        raise ValueError("no corpus entries found in %s" % directory)

    return Corpus(entries=entries, default_unknown_noise=default_unknown_noise)
