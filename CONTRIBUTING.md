# Contributing to NoiseHound

The engine is small and stable. The part that benefits most from community
effort is the **edge-telemetry corpus** (`edge_mappings/`) - the mapping from
BloodHound edge types to their detection surface and noise scores. Better
corpus data makes every operator's ranking more trustworthy, so corpus PRs are
the most valuable contribution you can make.

## Adding or improving a corpus edge

1. Create or edit `edge_mappings/<EdgeType>.json`. The filename must match the
   `edge_type` field. See [`docs/edge_schema.json`](docs/edge_schema.json) for
   the formal schema, and any existing file (e.g. `DCSync.json`) as a template.
2. Fill in, at minimum: `edge_type`, `static_noise_score` (0-100), and a
   non-empty `telemetry` array. Strongly encouraged: `description`,
   `mitre_technique`, `prerequisite_privilege`, `abuse_primitive`, `notes`.
3. Score honestly and cite your reasoning in `notes`:
   - `static_noise_score` is the baseline expected detection cost assuming
     **default auditing** (most DS-access/DS-change auditing is OFF by default).
   - If a signal only fires with auditing enabled, mark that telemetry entry
     `"reliability": "high_if_auditing_enabled"` and `"default_enabled": false`.
     The environment-profile logic keys off exactly these fields to raise the
     score when an operator declares that auditing is on.
   - Prefer the quietest realistic abuse primitive when setting the baseline
     (an operator will pick it); note louder alternatives in `notes`.
4. Validate and test:
   ```bash
   noisehound-validate          # schema + consistency checks
   python -m pytest tests/ -q
   ```
5. Open a PR describing the technique, the telemetry, and how you arrived at the
   score (lab results, event-log observation, or published detection research).
   Measured data beats estimates - if you have lab detection numbers, say so.

### Scoring guide (rough anchors)

| Band | Meaning | Examples |
|------|---------|----------|
| 0-15  | Structural / passive; no action or token-side only | `MemberOf`, `Contains`, `HasSIDHistory` |
| 20-40 | Real action, quiet by default | `HasSession` (token), `AddKeyCredentialLink`, LAPS reads |
| 40-60 | Action with default-on or high-fidelity signal | `ForceChangePassword`, `AddMember`, ADCS ESCx |
| 60-85 | Loud or high-fidelity by default | `CanRDP`, `ADCSESC8`, `DCSync` |
| 85-100| Near-certain detection | anything with default-on high-fidelity alerting |

## Code contributions

- Keep the engine dependency-light (currently just `networkx`).
- Match the surrounding style; every module has a docstring explaining intent.
- Add or update a test in `tests/test_noisehound.py` for any behaviour change.
- Run `noisehound-validate` and `pytest` before opening a PR; CI runs both on
  Python 3.10-3.12.

## Scope and ethics

NoiseHound is for authorized security testing, detection engineering, and
research. Contributions should support defensive value or authorized offensive
assessment. Do not submit target-specific data, real engagement output, or
anything that only serves unauthorized use.
