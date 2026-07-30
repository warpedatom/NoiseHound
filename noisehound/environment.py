"""Operator-declared target environment profiles.

A static corpus score cannot know whether a given target has 4662 object
auditing on, ships Sysmon, or runs an ITDR like MDI - yet those factors move an
edge's real noise enormously (DCSync is near-silent without 4662 auditing and
near-certain-detection with it). Rather than pretend the static score is
absolute, NoiseHound lets the operator *declare* the target's detection posture
in a small JSON profile, and adjusts scores transparently against the corpus's
own telemetry annotations.

This is operator-supplied, not measured - it does not replace Phase 2 live
validation - but it turns the static corpus from "one number for all
environments" into "the number for the environment you are actually in", which
is the difference between a plausible ranking and a usable one.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field


def _clamp(x: float) -> float:
    return max(0.0, min(100.0, x))


@dataclass
class EnvironmentProfile:
    """Declared detection posture of a target environment.

    All flags default to the quietest (most permissive-for-the-attacker)
    assumption, so an absent/empty profile changes nothing.
    """

    name: str = "default"
    object_auditing_4662: bool = False       # DS Access auditing (SACLs)
    ds_change_auditing_5136: bool = False     # DS Changes auditing
    edr: str = "none"                         # none | generic | EDR | MDI
    sysmon: bool = False
    powershell_logging_4104: bool = False
    # Hard per-edge overrides: edge_type -> absolute score. Highest authority
    # short of live validation; this is where an operator records calibrated
    # values from their own lab.
    adjustments: dict = field(default_factory=dict)

    _EDR_LEVELS = {"none": 0, "generic": 1, "edr": 2, "mdi": 2}

    @classmethod
    def from_dict(cls, d: dict) -> "EnvironmentProfile":
        adj = {str(k).strip().lower(): float(v) for k, v in (d.get("adjustments") or {}).items()}
        return cls(
            name=d.get("name", "default"),
            object_auditing_4662=bool(d.get("object_auditing_4662", False)),
            ds_change_auditing_5136=bool(d.get("ds_change_auditing_5136", False)),
            edr=str(d.get("edr", "none")).strip().lower(),
            sysmon=bool(d.get("sysmon", False)),
            powershell_logging_4104=bool(d.get("powershell_logging_4104", False)),
            adjustments=adj,
        )

    @classmethod
    def from_file(cls, path: str) -> "EnvironmentProfile":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    @property
    def edr_active(self) -> bool:
        return self._EDR_LEVELS.get(self.edr, 0) > 0


def _has(telemetry: list, **match) -> bool:
    """True if any telemetry entry matches all given key/value pairs."""
    for t in telemetry:
        if all(t.get(key) == val for key, val in match.items()):
            return True
    return False


def adjust_score(
    base: float,
    entry: dict | None,
    edge_type: str,
    profile: EnvironmentProfile | None,
) -> float:
    """Return the environment-adjusted score for one edge.

    Adjustments only ever *raise* a score toward a detection floor implied by
    the declared posture, using the corpus entry's own telemetry annotations as
    the evidence. Hard per-edge ``adjustments`` win outright.
    """
    if profile is None:
        return base

    key = edge_type.strip().lower()
    if key in profile.adjustments:
        return _clamp(profile.adjustments[key])

    if entry is None:
        return base  # unknown edge - no telemetry to reason about

    telemetry = entry.get("telemetry", []) or []
    score = base

    # 4662 object auditing turns "high_if_auditing_enabled" DS-access signals
    # (DCSync, LAPS reads, GenericAll on audited objects) into near-certain.
    if profile.object_auditing_4662 and _has(
        telemetry, source="windows_security", event_id=4662,
        reliability="high_if_auditing_enabled",
    ):
        score = max(score, 90.0)

    # 5136 DS-change auditing exposes attribute writes (RBCD, shadow creds,
    # DACL edits) that are otherwise silent by default.
    if profile.ds_change_auditing_5136 and (
        _has(telemetry, source="windows_security", event_id=5136, reliability="high")
        or _has(telemetry, source="windows_security", event_id=5136,
                reliability="high_if_auditing_enabled")
    ):
        score = max(score, 80.0)

    # An active EDR/ITDR realises the high-reliability heuristic detections the
    # corpus notes (e.g. non-DC DRSGetNCChanges, shadow-cred writes under MDI).
    if profile.edr_active and _has(telemetry, source="edr_heuristic", reliability="high"):
        score = max(score, 70.0)

    # Sysmon realises high-fidelity host signals (e.g. Sysmon 10 LSASS access).
    if profile.sysmon and _has(telemetry, source="sysmon", reliability="high"):
        score = max(score, 65.0)

    # Script-block logging exposes PowerShell-borne techniques.
    if profile.powershell_logging_4104 and _has(
        telemetry, source="windows_security", event_id=4104
    ):
        score = max(score, 60.0)

    return _clamp(score)
