# Closed-loop validation - the calibration changes NoiseHound's decision

**Claim under test:** a measured environment profile (`-e`) does more than re-print
scores - it *changes which attack path NoiseHound recommends as quietest*. If it
doesn't, the whole calibration layer is cosmetic. This run shows it does.

## Method
One fixed graph, one fixed query, scored three ways. No Neo4j required - `--input`
accepts the BloodHound `.zip` directly.

```
# graph:  samples/sample_fullspectrum_ce.zip        (CONTOSO.LOCAL, 14/14 corpus edges)
# query:  -s S-1-5-21-PROD-1101  -o S-1-5-21-PROD-512  -f text
# tier 0: (no -e)                                    # shipped static defaults
# tier 1: -e profiles/vulnad-hyperv-audit.json       # audit-tier measured profile
# tier 2: -e profiles/vulnad-hyperv-edr.json          # alert/EDR-tier measured profile
```
(This is reproducible from a clean checkout - bundled sample graph, host venv, no lab.)

## Result - the #1 (quietest) recommendation flips

| Rank | Baseline (static) | Audit profile | EDR profile |
|------|-------------------|---------------|-------------|
| **#1** | 4-hop AdminTo->**HasSession** path - **score 19.9**, P=34% | **ADCS ESC1 (1-hop)** - **score 42.0**, P=42% | **ADCS ESC1 (1-hop)** - **42.0**, P=42% |
| #2 | CanRDP->HasSession - 39.6 | 4-hop AdminTo->HasSession - 49.3 | 4-hop AdminTo->HasSession - 49.3 |
| #3 | ADCS ESC1 (1-hop) - 45.0 | CanRDP->HasSession - 53.9 | CanRDP->HasSession - 53.9 |

Audit and EDR rank identically on this sample: the EDR-tier bumps (DCSync 85,
roasting 61, SMSA 62) aren't on any of these paths, so the two tiers only diverge
on graphs where those credential-theft edges are on-route.

**Under shipped defaults** NoiseHound tells the operator the quietest route to Domain
Admins is the 4-hop session-hijack chain (19.9), ranking direct ADCS ESC1 abuse *last* (45.0).

**After applying the lab-measured profile** the recommendation inverts: the direct
**ADCS ESC1** path is quietest (42.0) and the session-hijack chain drops to #2 (49.3).
Same graph, same goal - a different, better-informed decision.

## Why it moved (the measured deltas that did the work)
| Edge | Shipped default | Lab-measured | Effect |
|------|----------------:|-------------:|--------|
| `HasSession` | 20 | **65** | Sessions are heavily audited on a fully-instrumented DC; re-weights every lateral path hopping through a live session. |
| `AdminTo`    | 25 | **34** | Local-admin use noisier than assumed -> pushes the 4-hop chain up. |
| `ADCSESC1`   | 45 | **42** (audit) | Certificate enrollment (4886/4887) quieter than the conservative default -> the 1-hop cert abuse wins. |
| `CanRDP`     | 50 | **45** (measured) | Fresh RDP is a deterministic type-10 logon (4624); measured slightly quieter than the conservative default. Same value both tiers (a lateral edge, not EDR-alert-bumped). |
| `MemberOf`   | 2 | 2 | Structural edge, unchanged - sanity check that untouched edges stay put. |

## Second validation - on a REAL lab graph (measured-on-itself)
The sample is synthetic. Stronger test: score the **actual sevenkingdoms.local graph**
(SharpHound v2.13.0 CE, 351 objects, corpus coverage **855/855 = 100%**) with the profile
measured *on that same environment*. (That lab export is not shipped in the repo - real
collection artifacts are kept out of the tree - but the run is recorded here.)

```
# query:  -s SVC_DELEG@SEVENKINGDOMS.LOCAL  -o "Domain Admins"  -k 3
```

| | Baseline (static) | Audit profile |
|--|--|--|
| **#1 path** (5-hop: AllowedToDelegate->HasSession->...->GenericWrite) | score **37.6**, P=**62%** | score **51.1**, P=**77%** |
| **#2 path** | 3-hop AllowedToDelegate->HasSession->MemberOf (38.1) | **2-hop ADCS ESC7 shortcut** surfaces (52.6) |

- The top path's detectability rises **+13.5** (37.6->51.1), **P(detect) 62%->77%**, once the
  measured `HasSession`=65 / `AllowedToDelegate`=43 land - a defender-realistic correction on
  the operator's "quietest" route through the real environment.
- The **candidate ordering changes**: a 2-hop **ADCS ESC7** route the static model buried now
  ranks #2 under the profile - exactly the alternative-path re-prioritisation calibration exists
  to produce.

## Third profile - the Elastic (open SIEM) tier steers pathfinding too
`profiles/vulnad-hyperv-elastic.json` (10 edges, DCSync=85) was validated the same way - a full
peer to the audit/EDR profiles:
- **Sample graph:** baseline #1 = 4-hop session-hijack (19.9) -> **Elastic #1 = ADCS ESC1, 1-hop
  (45.0)** - the same inversion (driven by measured HasSession 20->65).
- **Real sevenkingdoms graph:** top-path detectability rises **62%->77%** (37.6->51.4) and a
  2-hop shortcut surfaces at #2 - same behaviour as the other tiers.

## Takeaway
- The calibration layer is **functional, not cosmetic**: measured detectability re-orders the
  ranking and changes the top recommendation - across audit, EDR, and Elastic profiles, on both
  a synthetic rich graph and a real, measured-on-itself graph.
- Audit vs EDR behave sensibly: the EDR profile diverges only on the credential-theft edges that
  raised named alerts (DCSync/roasting/SMSA); on paths without those it matches audit, as here.
  See `docs/TOOLING_AXIS.md`.
- The sample-graph flip is reproducible with the bundled graph - no lab, no Neo4j, host venv only.
