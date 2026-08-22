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

## Next release target

Everything below is scoped from what this Azure/tooling/ADCS batch actually
surfaced - not aspirational Phase 1-4 material. Ordered by leverage; each
item flagged **buildable now**, **gated** (needs a live system/tenant only
the owner has), or **blocked** (needs another artifact first).

**Done / resolved since this section was written**
- ~~`azure_activity` resource-plane audit counter~~ - **already shipped.**
  Wired to all 3 resource-plane edges since the original Azure foundation
  batch (verified by inspection, 2026-08-20); this item was written on a
  stale assumption, not a real gap.
- ~~`sigma.compute_coverage` reconciliation~~ - **confirmed clean, no code
  change needed.** `noisehound-mdi` and the pending `noisehound-elastic` touch
  the shared corpus/scoring layer through separate functions
  (`mdi.compute_coverage` vs `sigma.compute_coverage`'s additive
  `allow_technique_only` param) - verified by inspection and by running both
  test suites together on one tree. Not a formality; the answer happened to
  be "independent by design."

**Needs a design decision, not a mechanical build**
- **Sentinel as a distinct Azure alert-tier source.** The corpus already
  acknowledges Sentinel qualitatively (e.g. `AZGlobalAdmin.json`: *"commonly
  alerted by ID Protection / Sentinel"*), folded into `entra_id_protection`'s
  text rather than split out. Splitting it into its own `VALID_SOURCES` entry
  would mean inventing a `reliability` score with no real rule-inventory data
  behind it - unlike ID Protection (a fixed first-party product with known
  risk-detection types), Sentinel's actual detection depends entirely on
  which analytics rules a given tenant deploys. Model it honestly (needs a
  real Sentinel rule inventory) or leave it hedged as-is - don't fabricate a
  number to make this look buildable-now.

**Buildable now (no external dependency)**
1. **Tempo / dwell modeling** and **confidence intervals** (Phase 1 items 3-4,
   long-standing, still not started) - real statistical-modeling work, sizable
   enough to warrant its own design pass rather than folding into this batch.

**Done in v1.1.0 (owner live-infra runs, 2026-08-21)**
2. ~~The first real `lab-tenant-azure` profile~~ - **shipped.** Ran
   `docs/AZURE_CALIBRATION.md` against the real DreadHost tenant: seven `AZ*`
   directory-plane abuses triggered, all logged (rate 1.00) ->
   `profiles/lab-tenant-azure.json` (first measured Azure tier).
3. ~~Complete the WDAC measured tier~~ - **shipped.** mimikatz
   (DCSync/DumpSMSAPassword) and Certify (ADCSESC1) re-measured on-host under
   WDAC audit mode (CodeIntegrity 3076); `vulnad-hyperv-wdac.json` now scores
   all 6 edges.
4. ~~Live BHCE + `noisehound-elastic` validation~~ - **shipped.** BHCE
   writeback verified live (1,252 relationships stamped with `r.noise`, visible
   in the Cypher UI); `noisehound-elastic` reached 69/69 measurable-edge
   coverage against a live Kibana 8.15.3 stack.

**Done since this section was written**
- ~~AzureHound-native ingest~~ - **shipped** (`azure_ingest.py` +
  `azure_synthesis.py`, `docs/AZUREHOUND_NATIVE_INGEST.md`). The recon landed
  (2026-08-20, real DreadHost tenant collection), grounding both the raw
  schema and the `post.go` synthesis logic; built and tested same-day against
  the real trimmed fixture (`samples/azurehound_native.example.json`) plus a
  synthetic fixture for the tiering logic the real sample doesn't reach.
  Documented gaps remain (`AZRunsAs` unresolved, a couple of unconfirmed
  field shapes) - see the doc - but this is no longer the "doesn't exist yet"
  gap it was.

**Blocked (needs a prior artifact)**
5. **Hybrid edges** (Entra Connect / PHS-PTA / seamless SSO) so MDI
   contributes across the on-prem/cloud boundary - now unblocked in principle
   (native ingest gives real Azure-side principals to link against) but not
   started.

---

## v1.2+ - what would make it better (post-1.1.0)

Ordered by leverage, scoped from the v1.1.0 sanity pass and the honest gaps it
surfaced. 37 of 71 corpus edges are now lab-measured across five on-prem tiers +
a real Azure tier; the headroom is depth and breadth of measurement, not features.

1. **Deepen measured coverage toward the full 71.** The remaining ~34 edges are
   expert estimates. Highest value: the coercion/relay family, ADCS ESC2-13
   (only ESC1/9a/10b/13 are measured), and `CanRDP` on a clean bare-metal target
   (the Hyper-V DC reconnect artifact made it hard to isolate a fresh type-10).
2. **Multi-environment calibration.** Every measured profile comes from one
   Hyper-V GOAD lab. Ship profiles from a second, materially different
   environment (different audit policy, EDR vendor, forest topology) so operators
   can see how much scores move by environment - and so the shipped defaults
   generalise beyond one lab.
3. **Make detection monotonic in calibrate.** A measured detection should never
   *lower* an edge's floor below its corpus static (v1.1.0's WDAC run nudged
   DCSync 85 -> 80 because the tier's lab score sits below DCSync's baseline).
   Add a `max(calibrated, static)` guard for "detected" observations, or a
   per-tier "detection only adds noise" mode, so a new detection layer can only
   make an edge louder.
4. **Confidence intervals + sample size per edge.** Surface `runs`/`detections`
   and a calibration CI alongside each measured floor (Phase 1 item 4, elevate),
   so consumers can weight a 1-run WDAC measurement differently from a 40-run
   audit-tier one.
5. **Broader live detection-inventory ingestion.** `noisehound-elastic` +
   `noisehound-mdi` prove the normalise-then-score pattern; extend it to Splunk,
   Microsoft Sentinel (needs a real analytics-rule inventory - see the design
   note above), and Defender XDR advanced-hunting.
6. **Widen the Azure corpus.** BHCE emits many AZ edges the corpus doesn't model
   yet (`AZExecuteCommand`, `AZKeyVault*`, `AZGetSecrets/Keys/Certificates`, the
   `AZMG*` family, `AZGrant*`). Add them + their Entra/Graph telemetry signatures.
7. **SpecterOps OpenGraph integration** so NoiseHound scores ride as first-class
   edge properties and custom edge types round-trip through BHCE.
8. **`noisehound-writeback --dry-run`** (buildable now, small) - report the edges
   it *would* stamp, reassuring operators running it against production BloodHound.
9. **Ship the POC as a one-command reproducible demo** (compose lab + seed +
   writeback + the quietest-vs-shortest showcase) so the thesis is self-evident
   without a full lab build.

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
   shipped in v0.5.0, `noisehound-sigma`. Tier 3 - live Elastic Security
   inventory - shipped, `noisehound-elastic`: reads the enabled detection rules
   from a running Kibana detection engine over the read-only `_find` API (or an
   offline export), normalises each rule's ATT&CK + event-code mapping, and reuses
   the Sigma matcher with a technique-only tier for behavioural queries. Emits the
   same `--environment` coverage profile + gap report. Live-path validation
   against the lab Elastic stack is the remaining owner step.)* Remaining tiers:
   Splunk / Sentinel / MDI API ingestion on the same normalise-then-`compute_coverage`
   pattern. Nobody is doing detection-aware pathing against a live inventory.

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
  `docs/MDI_RUNTIME_TIER.md` - landed on this repo's `main`.
- ~~AzureHound-native ingest - scoped, not built~~ - **shipped** (`docs/
  AZUREHOUND_NATIVE_INGEST.md`, `azure_ingest.py` + `azure_synthesis.py`).
  Recon landed 2026-08-20 (real DreadHost tenant collection) and confirmed the
  hypothesis: only 4 of 13 corpus edges were in raw output, the other 9 needed
  the synthesis pass - built same-day against real + synthetic fixtures.
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
  the resource-plane alert layer, and `azure_activity` already backs the
  resource-plane edges' audit half. **AzureHound-native ingest shipped**
  (see coverage section above). Next: run `noisehound-entra` against a live
  lab tenant for the first *real* measured profile (owner-only, needs tenant
  access); Sentinel as a second alert-tier source alongside ID Protection
  (needs a design decision, not a mechanical build - see the next-release
  section); hybrid edges (Entra Connect/PHS-PTA/seamless SSO) so MDI
  contributes across the on-prem/cloud boundary.
- **WDAC / App Control** - shipped as a tool-signature source
  (`docs/TOOLING_AXIS.md`) and measured in audit mode on the Hyper-V DC
  (`profiles/vulnad-hyperv-wdac.json`: Rubeus -> Kerberoast/ASREPRoast,
  Whisker -> AddKeyCredentialLink, mimikatz -> DCSync/DumpSMSAPassword,
  Certify -> ADCSESC1; all via CodeIntegrity 3076). All six modelled `wdac`
  edges are now measured on-host (re-measured 2026-08-21).

## Status snapshot (2026-08-20)

Shipped: BloodHound CE ingestion (real-data validated, incl. the modern
RID-keyed `LocalGroups` format - SharpHound v2.13/BHCE dropped the old
per-collection arrays, which was silently losing every computer-access edge
until this batch) with live-Bolt ESC/roasting synthesis parity, 71-edge corpus
(57 on-prem + 14 Azure/Entra), ADCS ESC1-9a/10b/13 synthesis (ESC10a
intentionally gated), noise-weighted solver with correctness backstop,
environment profiles, **automated calibration harness + measured profiles
(on-prem audit/EDR/Elastic/MDI-runtime + WDAC tool-signature)**, blue-team
detection-gap mode, Sigma + live-Elastic coverage (`noisehound-sigma` /
`noisehound-elastic`, sharing `compute_coverage`), `noisehound-mdi`
(identity-tier coverage), `noisehound-entra` (measured Azure calibration
tooling), tooling-profile axis (`--tooling`) + `--live-scores`, the
BHCE-ingestable `samples/sample_lab_ce.zip` GOAD sample, probabilistic +
Pareto pathing, live Neo4j read/write-back, DeadAir Rust engine + `--engine`
dispatch, corpus validator + schema + CI, Azure/Entra foundation + WDAC +
Defender for Cloud modeling, and **AzureHound-native ingest**
(`azure_ingest.py` + `azure_synthesis.py` - reads `azurehound list -o` output
directly, no BHCE required, incl. the post-processing pass for the 9 of 13
corpus edges that only BHCE's backend used to compute). **75 tests**, 100%
corpus coverage on real exports. This repo's `main` and the main machine's now
hold the same on-prem/tooling/Azure feature set (modulo `docs/WALKTHROUGH.md`,
an owner-lineage doc not on this repo - separate one-file sync if wanted); the
AzureHound-native ingest work above was built directly on this repo and has
not yet round-tripped to the main machine.

Owner-only validation still open (live infra/auth, not buildable from either
machine): upload `sample_lab_ce.zip` into a live BHCE once and confirm Analysis
completes; run `noisehound-elastic` against the lab Elastic stack; run the
`docs/AZURE_CALIBRATION.md` recipe in a real lab tenant for the first genuine
`lab-tenant-azure` profile; validate AzureHound-native ingest against a full,
non-trimmed real collection (built against a 14-record trimmed sample so far).
