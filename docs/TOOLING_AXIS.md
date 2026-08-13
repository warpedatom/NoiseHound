# The tooling axis - why the EDR tier is not the whole story

Detection splits in two, and **only one half is tool-agnostic**. This is the single
most important caveat when reading the EDR-tier profile.

- **Technique / audit / identity signals are TOOL-AGNOSTIC.** 4662 (DCSync replication),
  4769 (Kerberoast), 5136 (ACL change), 4886/4887 (enrollment) fire on the *operation*.
  mimikatz, DSInternals, bloodyAD, Impacket `secretsdump` all trip the same events -> the
  audit + identity calibration holds for any tool.
- **EDR AV-signature detections are TOOL-SPECIFIC and execution-context-dependent.** They
  fire on the *tool's signature* and only when the binary runs *on the monitored host*.

## Measured evidence

**Kerberoast - QUIET (native) vs LOUD (Rubeus)**, same SPN, same DC:

| Tool | Technique event (4769) | EDR/AV signature alert |
|------|------------------------|------------------------|
| Native .NET `KerberosRequestorSecurityToken` | 4769 fired | none |
| `Rubeus.exe` (GhostPack) `kerberoast` | 4769 fired | "Possible use of the Rubeus kerberoasting tool" (MDE, Medium) |

Audit-tier detection (4769) is identical. The EDR tier only lights up for the signatured binary.

**DCSync - parallel confirmation:**

| Tool | Technique event (4662 DRSR replication) | EDR/AV outcome |
|------|-----------------------------------------|----------------|
| `mimikatz.exe` `lsadump::dcsync` | fired | "Mimikatz credential theft tool" (AV, High) + binary quarantined |
| DSInternals `Get-ADReplAccount` (native) | fired (same DRSR) | no signature alert; not quarantined |

## Identity-tier corroboration (Microsoft Defender for Identity, posture/ISPM)
MDI's posture engine independently read the lab directory and Completed **39/45** Defender-for-
Identity assessments covering the same edges calibrated here (ESC1/3/4/6/7/8/11/15, non-admin
DCSync rights, unsecure Kerberos delegations, gMSA/sMSA, LAPS, krbtgt, SID history). A real
product flags the same abuse surface from **directory state**, independent of the operator's tool -
the durable, tool-agnostic identity tier in action. (MDI's *runtime alert* path was dark on the
Hyper-V lab - a capture-path limitation, see the roadmap - but its posture side reinforces the point.)

## What this means for the scores
- The **EDR-tier profile (`profiles/vulnad-hyperv-edr.json`) reflects "default off-the-shelf tools,
  run on the host"** - the loudest case. A capable operator using **remote Impacket / bloodyAD /
  native tradecraft** performs the identical techniques with a **near-zero endpoint footprint**,
  caught only by the audit / network / identity tier.
- So the **audit + identity tiers are the durable, tool-agnostic half** of the calibration; the
  EDR-signature tier is the "how loud is the default toolkit" half.
## The `--tooling` flag

The tooling axis is selectable at query time:

```bash
noisehound -i export.zip -s user -o "Domain Admins" --tooling onhost   # off-the-shelf, on host (loud)
noisehound -i export.zip -s user -o "Domain Admins" --tooling remote   # Impacket from Linux (quiet endpoint)
noisehound -i export.zip -s user -o "Domain Admins" --tooling native   # native/LOLBAS (quiet AV signature)
```

How it works: the corpus static score is the tooling-neutral baseline. Tool-sensitive
edges carry an optional `tool_agnostic_score` (the quiet floor when no signatured
binary runs on the host) and/or `tool_signature_score` (the louder ceiling when
off-the-shelf tooling does). `--tooling` picks the base; today, for example:

| Edge | neutral | `--tooling remote` | `--tooling onhost` |
|------|--------:|-------------------:|-------------------:|
| DCSync (static assumes mimikatz) | 85 | **59** (Impacket) | 85 |
| Kerberoast (static = technique baseline) | 30 | 30 | **61** (Rubeus) |

**Crucially, tooling only moves the *endpoint-signature* component.** The environment
posture is applied on top of the tooling base, so tool-agnostic detection is never
lost: remote DCSync still rises to 90 under a **posture-declared**
`object_auditing_4662` profile (MDI / 4662 catch the replication regardless of the
tool). That is the whole point - remote/native tradecraft dodges the EDR AV
signature, not the AD/identity audit trail. A *measured* profile can still score
lower than the floor when it hard-codes a lab-observed value (e.g. the shipped
`profiles/vulnad-hyperv-audit.json` measures DCSync at 59) - measured always
overrides the theoretical floor, by design.

Coverage today is the well-evidenced signatured edges (DCSync, Kerberoast, ASREPRoast,
DumpSMSAPassword); more edges gain `tool_*_score` values as per-edge tooling
calibration lands.
