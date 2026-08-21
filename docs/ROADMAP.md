# NoiseHound roadmap

Where NoiseHound goes from "a working detection-aware pathfinder" to a tool the
red *and* blue communities take seriously. Ordered by leverage, with each item
flagged **buildable now** or **gated** (needs lab data, a live system, or the
friend's full-collection export).

## Positioning

NoiseHound scores Active Directory attack paths by expected detection cost.
The strategic bet: the same computation serves two audiences.

- **Red / purple:** the quietest path to an objective (OPSEC planning).
- **Blue / detection engineering:** the quietest path is, by definition, where
  detection is weakest - a map of an environment's detection blind spots.

"Noise" is the shared vocabulary. Owning both framings is what separates this
from being "another BloodHound path tool."

---

## Phase 1 - Deepen the model (buildable now)

The credibility core. None of this needs external data.

1. **Blue-team / detection-gap mode.** Invert the output: for the quietest
   path(s), report which edges have little or no telemetry and emit the concrete
   mitigation for each - the audit-policy subcategory, Sigma rule, or MDI/EDR
   setting that would make that edge loud (the corpus already stores the event
   IDs). Rank fixes by how much they raise the quietest-path score
   ("enabling these 2 audit policies lifts the quietest DA path from 20 to 65").
   *This is the highest-leverage single feature - it doubles the audience.*
2. **Probabilistic detection model.** *(Shipped in v0.5.0, `probability.py`.)*
   Every path reports P(detected) - loudest edge blended with the cumulative
   noisy-OR via a correlation coefficient; `--rank-by probability` ranks on it.
3. **Tempo / dwell modeling.** The same path run over days is quieter than over
   minutes (behavioural-analytics baselines). Add an execution-tempo factor.
4. **Expose uncertainty.** Surface the calibration shrinkage as confidence
   intervals so every score ships with error bars.
5. **Multi-objective pathing.** *(Shipped in v0.5.0.)* `--pareto` returns the
   Pareto frontier over noise / hops / detection-probability; `--avoid NODE` and
   `--avoid-edge TYPE` add constrained queries ("quietest path avoiding this
   EDR host / this technique"). Remaining: a success-probability objective and a
   "stay out of tier-0 until the last hop" constraint.

## Phase 2 - Integration and reach (mostly buildable now)

Meet users where they already are.

6. **Native BloodHound CE / Neo4j integration.** *(Bolt read: shipped in v0.5.0,
   `neo4j_ingest.py` - pending live validation against a running instance.)*
   Remaining: write noise back as edge/node properties, plus a Cypher query pack,
   so "quietest path" is visible inside the BloodHound UI, and hook into
   SpecterOps OpenGraph for custom edges.
7. **Score against deployed detections.** *(Tier 2 - Sigma rule coverage -
   shipped in v0.5.0, `noisehound-sigma`.)* Remaining tiers: live SIEM/EDR API
   ingestion (Splunk/Sentinel/Elastic/MDI) to compute coverage from a running
   detection inventory. "Quiet *here* because the DCSync analytic is not
   enabled." Nobody is doing detection-aware pathing against a live inventory.

## Phase 3 - Rigor and credibility (gated: needs the lab)

What earns the tool academic/industry respect.

8. **Run the calibration loop for real** (lab kit + `docs/CALIBRATION.md` ship
   now; needs a full-collection lab - GOAD or the friend's export).
9. **Publish a lab-calibrated baseline corpus + methodology writeup.** A
   measured, documented corpus is the artifact that makes the scores defensible.
10. **A talk.** "Detection-aware attack path planning" is novel enough for SO-CON
    / Black Hat Arsenal / BSides / DEF CON. Tools become groundbreaking when
    there is a talk and a method behind them, not just code.

## Phase 4 - Scale and advanced research

11. **Rust engine** *(shipped: the DeadAir sibling crate + `--engine` dispatch,
    10-100x faster on large graphs with identical results).* Remaining: publish
    DeadAir, and add rayon parallelism for the threshold sweep if ever needed.
12. **Offload pathfinding to Neo4j GDS** (native weighted shortest path) instead
    of pulling the whole graph into Python.
13. **Adversary-profile weighting.** Bias edge selection toward a named actor's
    tradecraft ("how would APT29 reach DA quietly"), tying into the emulation
    work.
14. **Game-theoretic / adaptive modeling.** Model the defender's response (trip
    X and they start watching Y) - quietest path under an active defender.
15. **ADCS ESC9/10/13 synthesis.** *(ESC9a / ESC10b / ESC13 shipped alongside the
    ESC1-8 pass; the live Bolt path now runs the same synthesis, not just the zip
    path.)* Remaining: **ESC10a** (Kerberos weak-binding) has no template-level
    signal - it depends only on the DC `StrongCertificateBindingEnforcement`
    registry value, which BloodHound does not collect - so it is intentionally not
    synthesised (over-reporting it would fire on every auth template). Revisit if a
    future SharpHound surfaces that DC posture. ESC9b (machine-account victim) is a
    thin follow-on to ESC9a if a use case appears.

---

## Post-calibration open items (from the 2026-08 lab run)

The first real calibration is done: **30/57 on-prem edges measured** across audit, EDR
(Defender for Endpoint), and Elastic SIEM tiers, shipped in `profiles/`, with
closed-loop validation (`docs/VALIDATION.md`). What that run surfaced as next work,
by leverage:

**Coverage (highest leverage first)**
- **MDI runtime-alert tier - RESOLVED (2026-08-20).** The earlier "dark on
  Hyper-V" verdict was a **classic-sensor limitation**, not a capture-path or
  learning-period issue: on the new v3 (ETW/MDE) sensor - activated via the
  DC's onboarded MDE agent after patching the OS - runtime alerts fire on the
  same lab (Kerberoast/AS-REP High, RBCD Medium, from remote Impacket/
  bloodyAD). DCSync was *blocked* by Defender XDR Attack Disruption
  (prevented, not scored); AddMember/shadow-creds/ESC1 stayed transient/
  request-only. Measured profile `profiles/vulnad-hyperv-mdi.json` +
  `docs/MDI_RUNTIME_TIER.md` - built and merged on the main machine, pending
  cherry-pick onto this repo's `main`.
- **AzureHound-native ingest - scoped, not built** (`docs/
  AZUREHOUND_NATIVE_INGEST.md`). Real gap, not a nice-to-have: most of the
  13-edge Azure starter set is BHCE-backend post-processed, not present in
  AzureHound's raw collector output, so native ingest needs its own
  post-processing synthesis pass (mirroring `adcs.py`), not just a parser
  extension. Blocked on grounding data (a real AzureHound output + BHCE-
  imported tenant) - recon requested, not yet returned.
- **The remaining ~26 on-prem edges:** coercion/relay (needs an inbound-reachable
  attacker - flat Proxmox L2), CanRDP (4778), AllExtendedRights (4662
  confidential read). ADCS ESC2-9/11-13 now covered (ESC1-8 + ESC9a/10b/13
  synthesised; ESC10a intentionally gated - see item 15).
- **Full GOAD on a bare-metal Proxmox box.** The 30 measured are a Vulnerable-AD
  subset; a Ludus/GOAD build gives the full 57-edge on-prem surface.

**Harness quality**
- **Causal correlation + idle-baseline subtraction** (bug #3 remains): score an
  event only if it references the abuse's target object/actor, above a pre-run
  baseline. Kills the false-"detected" class on busy DCs.
- **Native cross-host measurement** (`-TargetComputer`) for lateral/relay edges that
  land events on the target, not the attacker.
- **Alert-tier automation:** query the MS Graph Security API for named alerts in the
  run window and auto-apply the severity bump (replaces the manual portal pass).
- *(Fixed this release: `$Plan` collision, UTF-8 BOM interop, and per-source log
  resolution incl. System-log 7045.)*

**Tooling-profile axis (`docs/TOOLING_AXIS.md`)** - a selectable
`{offtheshelf-onhost, remote-impacket, native-obfuscated}` dimension so a profile
reflects the tooling spread, not just the loudest case. Most-requested conceptual gap.

**Lab / DeadAir / validation**
- Consolidate the piecemeal `lab/` build scripts into one idempotent
  `Deploy-CalibrationLab.ps1`; bake 4769/4768/4886/4887 into an authoritative GPO so
  MDI's config GPO stops clobbering them.
- DeadAir: add regression fixtures using the measured profiles; add a `cargo bench`.
- Commit the real lab graph as a regression fixture with an asserted quietest-path
  (P2); ship the Elastic stack as a documented "stand up your own SIEM tier" recipe.
- **Azure/Entra** - foundation shipped (14 `AZ*` edges + Entra telemetry,
  `docs/AZURE.md`), the **measured audit tier tooling** shipped
  (`noisehound-entra` + `docs/AZURE_CALIBRATION.md`: Entra `directoryAudits` ->
  calibrated `lab-tenant-azure` profile, reusing the on-prem calibrate math,
  with an ID-Protection alert-tier hook via `--risk-detections`), and
  `defender_for_cloud` is modeled (not measured - needs a paid MDC plan) as
  the resource-plane alert layer. Next: run `noisehound-entra` against a live
  lab tenant for the first *real* measured profile (owner-only, needs tenant
  access); **AzureHound-native ingest** (scoped, see coverage section above);
  Sentinel as a second alert-tier source alongside ID Protection; the
  resource-plane (`azure_activity`) audit counter (`defender_for_cloud` only
  covers the alert half); hybrid edges (Entra Connect/PHS-PTA/seamless SSO)
  so MDI contributes across the on-prem/cloud boundary.
- **WDAC / App Control** - shipped as a tool-signature source
  (`docs/TOOLING_AXIS.md`) and measured in audit mode on the Hyper-V DC
  (`profiles/vulnad-hyperv-wdac.json`: Rubeus -> Kerberoast/ASREPRoast,
  Whisker -> AddKeyCredentialLink, CodeIntegrity 3076). DCSync/DumpSMSAPassword
  (mimikatz) and ADCSESC1 (Certify/Certipy) remain modelled-not-measured -
  those tools weren't run on-host in this session.

## Status snapshot (2026-08-20)

Shipped: BloodHound CE ingestion (real-data validated) with live-Bolt ESC/roasting
synthesis parity, 71-edge corpus (57 on-prem + 14 Azure/Entra), ADCS ESC1-9a/10b/13
synthesis (ESC10a intentionally gated), noise-weighted solver with correctness
backstop, environment profiles, **automated calibration harness + measured profiles
(on-prem audit/EDR/Elastic + WDAC tool-signature)**, blue-team detection-gap mode,
Sigma coverage, `noisehound-mdi` (identity-tier coverage), `noisehound-entra`
(measured Azure calibration tooling), tooling-profile axis (`--tooling`) +
`--live-scores`, probabilistic + Pareto pathing, live Neo4j read/write-back, DeadAir
Rust engine + `--engine` dispatch, corpus validator + schema + CI, Azure/Entra
foundation + WDAC + Defender for Cloud modeling. 66 tests, 100% corpus coverage on
real exports.

Pending merge onto this repo's `main` (built + tested on the main machine, not yet
cherry-picked here): modern `LocalGroups` ingest fix (SharpHound v2.13/BHCE emit a
single RID-keyed list; the old deprecated-array parser was silently dropping every
computer-access edge on current collections) + the BHCE-ingestable `sample_lab_ce.zip`
GOAD sample; `noisehound-elastic` (live Kibana detection-rule coverage, sibling of
`noisehound-mdi`); the measured MDI runtime tier itself (`profiles/
vulnad-hyperv-mdi.json`, logic described above).

Owner-only validation still open (live infra/auth, not buildable from either
machine): upload `sample_lab_ce.zip` into a live BHCE once and confirm Analysis
completes; run `noisehound-elastic` against the lab Elastic stack; run the
`docs/AZURE_CALIBRATION.md` recipe in a real lab tenant for the first genuine
`lab-tenant-azure` profile (everything shipped so far is fixture/synthetic-validated
for Azure, not yet real-tenant-validated).
