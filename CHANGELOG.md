# Changelog

All notable changes to NoiseHound are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/); this project uses semantic
versioning.

## [1.1.0] - 2026-08-21

### Added
- **First measured Azure tier from a real tenant** (`profiles/lab-tenant-azure.json`,
  validation ③). `noisehound-entra` run against a live Entra directory-audit
  calibration in the DreadHost lab tenant: seven `AZ*` directory-plane abuses
  triggered, all logged (detection rate 1.00) - AZGlobalAdmin 67, AZAddMembers 51,
  AZAddSecret 58, AZMGAddSecret/AZAppAdmin/AZCloudAppAdmin 60, AZAddOwner 55.
- **Elastic ADCS/Azure detection pack + denominator fix.** `noisehound-elastic` now
  excludes structural topology edges (`Contains`/`GpLink` - no technique/telemetry)
  from the coverage denominator, and `samples/elastic_adcs_detection_pack.ndjson`
  ships importable rules (ADCS CA-audit on 4886/4887/5136/4768, Azure VM Run Command)
  that close the stock Elastic catalog's AD CS blind spot - live-validated to
  **69/69** measurable-edge coverage. `docs/ELASTIC_TIER.md`.
- **AzureHound-native ingest** (`noisehound/azure_ingest.py` +
  `noisehound/azure_synthesis.py`). Reads `azurehound list -o` output
  directly - no BloodHound CE required for Azure/Entra data. Two phases:
  raw ingest of nodes and AzureHound's own structural edges (`AZHasRole`,
  `AZMemberOf`, `AZOwns`, resource-plane `AZ*Contributor`/`AZ*UserAccessAdmin`),
  plus a post-processing synthesis pass recovering `AZGlobalAdmin`,
  `AZPrivilegedRoleAdmin`, `AZAddMembers`, `AZAddSecret`, and
  `AZResetPassword` from directory role-holdings - the 9 of 13 corpus edges
  that only BloodHound's backend used to compute and that raw AzureHound
  output never carries. Grounded against a real `azurehound v3.1` collection
  (recon 2026-08-16/20); `samples/azurehound_native.example.json` ships a
  trimmed, sanitised real fixture. `docs/AZUREHOUND_NATIVE_INGEST.md` has
  the full schema grounding and documented gaps (`AZRunsAs` unresolved, a
  couple of unconfirmed field shapes).
- **Measured MDI runtime-alert tier** (`profiles/vulnad-hyperv-mdi.json`,
  `docs/MDI_RUNTIME_TIER.md`). Overturns the v1.0.0 "MDI runtime is dark on
  Hyper-V" finding: it was a **classic-sensor capture-path limitation**, not the
  environment. On the **new v3 (ETW/MDE-integrated) Defender for Identity sensor**
  (activated via the DC's Defender for Endpoint agent after patching the OS to the
  sensor baseline), runtime alerts fire on the same Hyper-V lab. Measured over the
  wire from Kali (Impacket/bloodyAD): Kerberoast + AS-REP at High, RBCD
  (AllowedToAct) at Medium. Honest gaps recorded: DCSync was *blocked* by Defender
  XDR Attack Disruption (prevented, not just detected); AddMember / shadow-creds /
  ADCS ESC1 did not raise MDI runtime alerts. Fourth measured detection tier
  alongside audit / EDR / Elastic.
- **`noisehound-elastic` — score against a live Elastic Security detection
  inventory.** Reads enabled detection rules from a running Kibana detection
  engine over the read-only `_find` API (or an offline `--rules-json` export),
  maps each rule's ATT&CK technique + any Windows event codes in its query, and
  emits the same `--environment` coverage profile and gap report as
  `noisehound-sigma`. Adds a conservative technique-only match tier (flagged
  `[technique]`, penalised) for behavioural KQL/EQL rules that name no event code;
  disabled rules are ignored. Stdlib-only (no new dependency).
- **`samples/sample_lab_ce.zip` — a BHCE-ingestable bundled sample.** A lightly
  sanitised real SharpHound CE collection of the public GOAD `sevenkingdoms.local`
  lab (323 objects, 25 edge families incl. full AD CS), so the operator
  walkthrough is a pure upload → writeback → view flow with no Cypher seed. Built
  reproducibly by `samples/build_sample_lab_ce.py`. Doubles as a BHCE-ingestion
  regression fixture.
- **`AZAppAdmin` corpus rename + `AZCloudAppAdmin`.** BloodHound's graph emits
  `AZAppAdmin`, not `AZApplicationAdmin` - the old key never matched a real
  collected graph, so the Application Administrator escalation edge was
  unreachable outside the synthetic fixture. Renamed, and added the sibling
  `AZCloudAppAdmin` (Cloud Application Administrator) as a new edge with the
  same telemetry footprint.
- **`defender_for_cloud` telemetry source** (modeling only - measuring needs a
  paid MDC plan + a real resource). Names Microsoft Defender for Cloud as the
  resource-plane alert layer on `AZVMContributor`/`AZUserAccessAdministrator`/
  `AZRunsAs`, the alert-tier counterpart to `azure_activity` the way
  `entra_id_protection` is to `entra_audit`.
- **Measured WDAC tier - all 6 edges** (`profiles/vulnad-hyperv-wdac.json`). WDAC
  deployed in audit mode on the Hyper-V DC; each on-host unsigned tool raised a
  CodeIntegrity 3076 would-block at image load: Rubeus (Kerberoast/ASREPRoast 44),
  Whisker (AddKeyCredentialLink 48), mimikatz (DCSync 80 / DumpSMSAPassword 40),
  Certify (ADCSESC1 50) - and WDAC saw nothing from the parallel remote
  (Impacket/bloodyAD) campaign, confirming the tooling axis. `docs/TOOLING_AXIS.md`.
- **WDAC / App Control as a tool-signature detection source.** New `wdac` telemetry
  source (CodeIntegrity 3076 audit / 3077 block) on the on-host-tool edges
  (Kerberoast, ASREPRoast, DumpSMSAPassword, DCSync, AddKeyCredentialLink, ADCSESC1),
  the detection counterpart to the tooling axis: it fires on off-the-shelf binaries
  and is blind to native/remote tradecraft. `default_enabled: false` (WDAC is opt-in),
  so `--defensive` surfaces "enforce WDAC / App Control" as a closable gap on exactly
  those edges. Lab-measurable via CodeIntegrity 3076 in audit mode (`docs/TOOLING_AXIS.md`).
- **`noisehound-entra` - measured Azure tier.** The cloud analogue of the on-prem
  calibration harness: turns a Microsoft Graph `directoryAudits` export plus a run
  manifest into calibrate-ready `observations`, matching each exercised `AZ*` edge
  by the Entra activity signature now on the corpus (`entra_audit` telemetry gained
  `activity`/`category`), and calibrates a measured `lab-tenant-azure` profile with
  `--profile-out`. Holding-only (`AZHasRole`/`AZOwns`) and resource-plane
  (`AZUserAccessAdministrator`/`AZVMContributor`/`AZRunsAs`) edges are reported as
  not-audit-measurable rather than scored from nothing. Recipe in
  `docs/AZURE_CALIBRATION.md`; fixtures `samples/entra_audit.example.json` +
  `samples/entra_runs.example.json`. Stdlib-only.
- **`noisehound-mdi`** - Microsoft Defender for Identity as a first-class detection
  source. Maps MDI's built-in runtime alerts (and, with `--include-posture`, its
  ISPM assessments) onto corpus edges, reports coverage + identity-tier gaps, and
  emits an `edr: MDI` environment profile. Tool-agnostic identity-tier counterpart
  to `noisehound-sigma`. 18/70 edges covered by MDI alerts today.
- **Selectable tooling-profile axis** (`--tooling onhost|remote|native`,
  `docs/TOOLING_AXIS.md`). Tool-sensitive edges carry an optional
  `tool_agnostic_score` (quiet floor for remote/native tradecraft) and/or
  `tool_signature_score` (loud ceiling for off-the-shelf tools on the host); the
  flag picks the base and the environment posture still applies on top, so
  tool-agnostic audit/identity detection is never lost (remote DCSync still rises
  to 90 under 4662 auditing). Seeded on DCSync/Kerberoast/ASREPRoast/DumpSMSAPassword.
- **Phase 2 `--live-scores` hook.** A JSON of measured scores (`by_edge_type`
  and/or `overrides` by source/target/edge_type) overrides the corpus/environment -
  wiring the existing `annotate()` live-score hook into the CLI.
- **Azure / Entra ID foundation.** 13 `AZ*` attack-path edges (roles/privesc, app
  & service-principal credential abuse, RBAC, account takeover, resource execution)
  with Entra-native detection telemetry, plus five Entra/Azure telemetry sources
  (`entra_audit`, `entra_signin`, `entra_id_protection`, `azure_activity`, `mdca`).
  Azure data collected via AzureHound into BloodHound CE is scored today; a
  synthetic `samples/sample_azure.json` and `docs/AZURE.md` ship with it. Corpus
  is now 70 edges (57 on-prem + 13 Azure). Azure edges are expert estimates
  pending a measured Azure calibration tier.

### Fixed
- **Ingest now reads the modern `LocalGroups` collection.** SharpHound v2.13 /
  BloodHound CE report local-group membership under a single `LocalGroups` list
  keyed by group RID (544→AdminTo, 555→CanRDP, 562→ExecuteDCOM, 580→CanPSRemote);
  the parser previously read only the deprecated per-collection `LocalAdmins` /
  `RemoteDesktopUsers` / `DcomUsers` / `PSRemoteUsers` arrays, silently dropping
  those computer-access edges on every current collection. Both formats are now
  read.
- **AZAddMembers coverage + AZResetPassword tiering.** `azure_synthesis` now includes
  DirectoryWriters + IdentityGovernanceAdministrator in the AZAddMembers non-role-
  assignable tier (both are in post.go's `AddMemberGroupNotRoleAssignableTargetRoles()`
  but were omitted), and rebuilds the `non_admin_users` exclusion from
  `_ALL_NAMED_ROLES` directly so adding a role constant can't silently misclassify a
  holder as a plain AZResetPassword target.
- **DeadAir cross-repo links made absolute.** `[DeadAir](../deadair)` markdown links
  (broken on the standalone GitHub repo) now point at the DeadAir repo URL; build-path
  references stay relative.

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
