# Changelog

All notable changes to NoiseHound are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/); this project uses semantic
versioning.

## [1.0.0] - 2026-08-10

First stable release, and the first **lab-measured calibration**. 30 of 57 corpus
edges measured on a real Hyper-V Vulnerable-AD range across four detection tiers -
including all four lateral-movement edges (CanPSRemote, AdminTo, ExecuteDCOM,
CanRDP). Calibration is honestly scoped: the remaining ~27 edges carry expert
estimates, and the roadmap (`docs/ROADMAP.md`) tracks the path to full coverage,
the MDI runtime-alert tier, and Azure/Entra.

### Added
- **Three measured environment profiles** (`profiles/`): `vulnad-hyperv-audit`
  (audit + Sysmon), `vulnad-hyperv-edr` (Defender for Endpoint severity pass), and
  `vulnad-hyperv-elastic` (open/free Elastic SIEM). Drop-in for `-e`. Notable: the
  free Elastic rules caught SQLAdmin at high (64) where MDE fired no named alert.
- **Closed-loop validation** (`docs/VALIDATION.md`) - applying a measured profile
  changes the recommended quietest path (sample graph: flips the #1 to a 1-hop ADCS
  ESC1; real graph: top-path P(detect) 62%->77%), proving calibration is functional.
- **`docs/TOOLING_AXIS.md`** and **`docs/ELASTIC_TIER.md`** - the tool-agnostic vs
  EDR-signature detection split, and the open-SIEM tier methodology.
- `windows_system` telemetry source, so System-log events (e.g. SCM 7045) are
  scored and routed to the correct log by the calibration harness.
- `lab/Measure-CanRDP.ps1` - target-side measure for interactive-logon edges.
- DeadAir (Rust engine): regression tests pinned to the measured profiles
  (audit-tier ADCS-ESC1 flip, EDR-tier DCSync loudness) - cross-engine parity
  with the Python solver. DeadAir bumped to 0.2.0.

### Fixed
- **Calibration harness `$Plan` variable collision** (critical): the `[string]$Plan`
  parameter aliased the parsed-plan variable (PowerShell is case-insensitive) and
  coerced it back to a string, so every edge was skipped and the harness calibrated
  nothing. Renamed the internal variable and added a parse guard.
- **UTF-8 BOM interop**: `noisehound-calibrate` and environment-profile loading now
  read `utf-8-sig`, and the harness writes UTF-8 without a BOM - PS 5.1 output no
  longer trips a "Unexpected UTF-8 BOM" error.
- **7045 log source**: corrected from `windows_security` to `windows_system` (SCM
  service-install lives in the System log); the harness resolves the log per source.

## [0.6.0] - 2026-07-29

First public release. Real-data hardening across three distinct labs.

### Added
- **BloodHound-native write-back** (`noisehound-writeback`, `docs/CYPHER.md`) -
  stamps `r.noise` (0-100) onto the BloodHound CE Neo4j relationships so scores
  are visible and queryable inside the BloodHound UI, including a noise-weighted
  APOC dijkstra query pack. Reads and writes the same Neo4j over Bolt.
- **Corpus completeness (45 -> 57 edges)** - coercion/relay edges
  (CoerceToTGT, CoerceAndRelayNTLMTo ADCS/LDAP/LDAPS/SMB), ADCS ESC9/10/13, and
  the PKI-flag template-control edges (WritePKIEnrollmentFlag/NameFlag), so real
  BloodHound CE exports that contain them are scored rather than defaulted.
- **Release automation** - GitHub Actions to publish the NoiseHound wheel to
  PyPI and cross-compiled DeadAir binaries (Linux/macOS/Windows) on a version tag.
- **Supply-chain hygiene** - `pip-audit` (and `cargo audit` for DeadAir) in CI,
  and a `SECURITY.md` for both repos.
- **Ingest robustness** - tolerates malformed / partial exports (null data
  arrays, nodes missing an id, ACEs missing fields) without crashing, with tests.
- **Kerberoast / AS-REP synthesis** - roastable accounts (`hasspn`,
  `dontreqpreauth`) are node properties in BloodHound and never entered a path;
  NoiseHound now synthesises `Kerberoast` / `ASREPRoast` edges from Domain Users
  to them (krbtgt excluded), with corpus entries, so the opportunity is pathable
  and scored.
- README banner and an honest project-status (beta) note.

### Fixed
- Ingest tolerates a UTF-8 BOM in export JSON (utf-8-sig) - some SharpHound /
  BloodHound CE exports carry one and previously failed to parse.
- HasSession edges are read from all three BloodHound CE session collections
  (`Sessions`, `PrivilegedSessions`, `RegistrySessions`); interactive / LoggedOn
  logons land in the latter two and were previously dropped, so real session
  edges went missing. Both caught on real third-party lab exports.

## [0.5.0] - 2026-07-28

### Added
- **Two-tier engine / DeadAir integration** (`noisehound/engine.py`, `--engine`).
  The solve can dispatch to the companion DeadAir Rust binary (10-100x faster on
  large graphs, byte-identical results) and falls back to the Python solver.
  `auto` uses DeadAir when present and the graph is large; `python`/`rust` force
  either. DeadAir is located via `$NOISEHOUND_DEADAIR`, PATH, or the sibling build.
- **Multi-objective and constrained pathing** (`noisehound/solver.py:solve_pareto`,
  `noisehound/constraints.py`) - roadmap Phase 1, item 5. `--pareto` returns the
  Pareto frontier over noise / hops / detection-probability (the genuine
  trade-offs) instead of a single ranking; `--avoid NODE` and `--avoid-edge TYPE`
  (both repeatable) exclude hosts or techniques and re-solve.
- **Probabilistic detection model** (`noisehound/probability.py`) - roadmap
  Phase 1, item 2. Every path now reports a detection probability (chance of a
  correlated alert), blending the loudest edge with the cumulative noisy-OR of
  all edges via a configurable correlation coefficient (`--correlation`). Rank
  by it with `--rank-by probability` - it penalises long paths' cumulative
  exposure, so a short loud path can beat a long quiet one. Shown in text/JSON/HTML.
- **Score against deployed detections** (`noisehound-sigma`, `noisehound/sigma.py`)
  - roadmap Phase 2, item 7 (tier 2). Parses a Sigma rule set, matches each rule
  to the corpus edges it would fire on (event ID + ATT&CK technique), and emits
  an environment profile raising the covered edges. Matching is conservative -
  event-ID plus technique agreement - so it never hides a gap by miscrediting
  rules that merely share an event ID. Reports both coverage and, more usefully,
  the attack edges no deployed rule covers. PyYAML is an optional dependency
  (`pip install 'noisehound[sigma]'`).
- **Live Neo4j / BloodHound CE ingestion** (`noisehound/neo4j_ingest.py`) -
  roadmap Phase 2, item 6. A `bolt://` / `neo4j://` URI as `--input` reads the
  graph straight from the database BloodHound CE populates (credentials via
  `--neo4j-*` flags or `NEO4J_USER`/`NEO4J_PASSWORD`), so no zip export is
  needed. The record-to-graph step is unit-tested; the driver is an optional
  dependency (`pip install 'noisehound[neo4j]'`).
- **Blue-team detection-gap mode** (`--defensive`, `noisehound/defend.py`) -
  roadmap Phase 1, item 1. Inverts the output for defenders: for the quietest
  path(s) it flags edges that are quiet only because their telemetry is off or
  absent, maps each to the concrete control that would catch it (audit-policy
  subcategory, Sysmon rule, MDI/EDR), and ranks those controls by how much they
  raise the quietest-path score. Doubles the audience from red to red+blue.
- `docs/ROADMAP.md` - the full capability roadmap (probabilistic detection
  model, BloodHound/Neo4j integration, scoring against deployed detections,
  calibrated corpus + methodology, Rust port, adversary profiles).
- README non-affiliation disclaimer (independent of SpecterOps/BloodHound).

## [0.4.0] - 2026-07-28

### Added
- **`noisehound-inspect`** - summarise an ingested export (node/edge histograms,
  corpus coverage, ADCS edges synthesised, loudest/quietest edge types) to
  validate the parser against a real-world BloodHound export before pathing.
- **Lab kit** (`lab/`): `Enable-Telemetry.ps1` (audit policy, script-block
  logging, optional DCSync SACL, Sysmon) and `Collect-Detections.ps1` (tally
  Security/Sysmon events in a window), with `lab/README.md` tying them to
  GOAD/Vulnerable-AD for domain seeding and to the calibration playbook.
- Solver honours a wall-clock `time_budget_s` for large real-world graphs.
- Multi-domain objective/source resolution: `find_matches` surfaces ambiguity and
  the CLI warns when a bare name (e.g. "Domain Admins") matches more than one
  domain, prompting an @DOMAIN qualifier. Validated against real cross-forest
  BloodHound exports (100% corpus coverage on 3 real exports).
- `samples/sample_fullspectrum_ce.zip` - a synthetic export exercising every edge
  family (membership, ACL, sessions, local admin, RDP/DCOM/PSRemote, constrained
  and RBCD delegation, DCSync, forest trust, ADCS ESC1), with a regression test
  guarding all collection handlers at once.

## [0.3.0] - 2026-07-28

### Added
- **AD CS ESC1-8 synthesis** (`noisehound/adcs.py`). Certificate-template and
  enterprise-CA facts are retained at ingest and post-processed into `ADCSESCn`
  escalation edges from the abusing principal to the domain's Domain Admins
  group, so certificate escalation is pathable and scored like any other edge.
- **Calibration harness** (`noisehound-calibrate`). Ingests lab detection
  results and emits a calibrated environment profile via a sample-size-aware
  shrinkage estimator. `--template` generates a blank per-edge checklist.
- **Corpus validator** (`noisehound-validate`) plus a formal JSON Schema
  (`docs/edge_schema.json`) and CI, making the corpus safely community-extensible.
- Corpus expanded to **43 edge types** (added ADCS ESC2-8).
- Solver wall-clock budget (`time_budget_s`) so large real-world graphs cannot
  hang the k-shortest enumeration.
- LICENSE (MIT), CONTRIBUTING, this changelog, and the calibration/lab guide
  (`docs/CALIBRATION.md`).

### Fixed
- Ingest tolerates a UTF-8 BOM in export JSON (decode as utf-8-sig) - some
  SharpHound / BloodHound CE exports carry one and previously failed to parse.
  Caught on a real third-party lab export.
- HasSession edges are now read from all three BloodHound CE session collections
  (Sessions, PrivilegedSessions, RegistrySessions), not just Sessions. Interactive
  / LoggedOn logons land in PrivilegedSessions and were previously missed - so
  real session (quiet-lateral) edges were silently dropped. Caught on a real
  `--loop` LoggedOn collection.

## [0.2.0] - 2026-07-28

### Added
- **Environment profiles** (`--environment`). Operators declare the target's
  detection posture (4662/5136 auditing, EDR/MDI, Sysmon, PowerShell logging)
  and scores adjust transparently. Hard per-edge `adjustments` are the
  calibration slot.
- Corpus expanded to 36 edge types (LAPS/gMSA, WriteSPN, RBCD control, GPO,
  trusts, SID history, extended rights).

### Fixed
- **Solver correctness**: added a threshold-sweep backstop so a long-but-quiet
  path is no longer misranked below a short-but-loud one (the bottleneck+mean
  objective is not additive).
- **DCSync synthesis**: now requires GenericAll-on-domain or both replication
  rights together, matching BloodHound, instead of over-reporting on a single
  replication right.

## [0.1.0] - 2026-07-28

### Added
- Initial MVP: BloodHound CE zip/JSON ingestion, edge-telemetry corpus (22
  edges), noise-weighted path solver, and text/JSON/HTML reporting.
