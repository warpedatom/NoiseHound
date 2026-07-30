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
15. **ADCS ESC9/10/13 synthesis** (ESC1-8 ship now).

---

## Status snapshot (v0.4.0)

Shipped: BloodHound CE ingestion (real-data validated), 43-edge corpus, ADCS
ESC1-8 synthesis, noise-weighted solver with correctness backstop, environment
profiles, calibration harness, corpus validator + schema + CI, inspect command,
lab detection-instrumentation kit, full docs. 29 tests, 100% corpus coverage on
real exports.

Next up when building resumes: **Phase 1, item 1 (blue-team detection-gap
mode)** - the single highest-leverage feature and fully buildable now.
