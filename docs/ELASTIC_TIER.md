# Elastic SIEM tier - open/free, vendor-neutral alert tier

The fourth detectability tier: **Elastic Security** prebuilt detection rules over
Windows/Sysmon telemetry. Unlike MDE (commercial EDR) and MDI (commercial identity),
Elastic is **free, self-hosted, and reproducible by anyone** - the most credible alert
tier to ship with a public tool. Profile: `profiles/vulnad-hyperv-elastic.json`.

## Stack
Elasticsearch + Kibana 8.15.3, security on, Detection Engine enabled. Both lab VMs run a
standalone Elastic Agent shipping `system.security`, `system.system`,
`windows.sysmon_operational`, `windows.powershell_operational`. ~3.5M events, ECS-normalized;
1340 prebuilt rules installed, ~281 edge-relevant enabled.

## Key constraint (and finding): an EDR quarantines the tools first
On the MDE-managed host, Defender quarantined `Rubeus.exe` / `SharpHound.exe` before they could
run - so Elastic's *tool-signature* rules can't observe them. Elastic is therefore measured on
**tool-agnostic native techniques** (its durable half). On a host where Elastic is the *sole*
endpoint tool, its signature rules would also be in play (roadmap). This is the tooling axis
again (`docs/TOOLING_AXIS.md`).

## Measured detections (native triggers vs enabled prebuilt rules)
**Detected:**
| Edge | Elastic rule | Severity | Calibrated |
|------|--------------|----------|-----------:|
| **DCSync** | Potential Credential Access via DCSync (x6) + First Time Seen Account Performing DCSync | high | 85 |
| **SQLAdmin** | Execution via MSSQL xp_cmdshell Stored Procedure | high | 64 |
| **WriteSPN** | User account exposed to Kerberoasting | high | 50 |
| **Kerberoast** | PowerShell Kerberos Ticket Request | medium | 48 |
| **AddMember** | User Added to Privileged Group | medium | 42 |

**Tested, NOT detected (honest gaps - Elastic's enabled rules don't flag these quiet dir ops):**
| Edge | Technique / event | Calibrated (toward residual) |
|------|-------------------|-----------------------------:|
| AllowedToAct (RBCD) | msDS-AllowedToActOnBehalfOfOtherIdentity write (5136) | 41 |
| ForceChangePassword | 4724 / 4738 | 38 |
| WriteDacl / GenericAll | DACL modification (5136) | 38 |
| ReadGMSAPassword | msDS-ManagedPassword read (4662) | 26 |
| ReadLAPSPassword | ms-Mcs-AdmPwd read | 26 |

**Coverage shape:** Elastic's open ruleset catches process/behavioral (xp_cmdshell),
privileged-group change (AddMember), SPN exposure (WriteSPN), and Kerberos ticket activity -
but is blind to quiet **directory reads/ACL edits** (RBCD, WriteDacl, gMSA/LAPS reads), which
only the audit tier's targeted SACLs catch. That audit-vs-SIEM split is itself a useful result.

## Cross-tier comparison (the interesting part)
| Edge | corpus default | audit | EDR (MDE) | **Elastic** |
|------|---------------:|------:|----------:|------------:|
| SQLAdmin | 50 | 44 | 44 | **64** |
| Kerberoast | 30 | 36 | 61 | 48 |
| AddMember | 35 | 38 | 38 | **42** |
| ForceChangePassword | 45 | 42 | 42 | 38 |

- **SQLAdmin: Elastic (64) > MDE (44).** The open SIEM caught SQLAdmin at *high* via a behavioral
  `sqlservr.exe`->shell rule where MDE fired no named alert on the benign `xp_cmdshell whoami`. A
  free rule beat the commercial EDR on this edge.
- **Kerberoast:** Elastic (48, native/medium) sits between audit (36) and MDE-with-Rubeus (61) -
  consistent with the tooling axis (native technique quieter than the signatured binary).
- **AddMember:** Elastic (42) edges above audit - it flagged the privileged-group addition
  MDE/audit didn't elevate.

## How DCSync got measured in all tiers (Kali network campaign)
Native on-box triggers can't do DCSync (DSInternals won't load over PS-Direct remoting; mimikatz
is EDR-quarantined). Solved by attacking from a **separate Kali host**: Impacket over **Kerberos**
(`getTGT` -> ccache -> `-k -no-pass`, since the NTLM bind was rejected), then `secretsdump` (DCSync),
`GetUserSPNs` (Kerberoast), `GetNPUsers` (AS-REP), `certipy req` (ADCS). **DCSync -> detected HIGH by
Elastic** (2 rules) + 4662 replication in audit. Elastic also fired "Sensitive Audit Policy Sub-Category
Disabled" - it caught the audit-policy tampering itself. Coercion/relay was not attempted (Kali behind
NAT isn't inbound-reachable for the DC callback - a bare-metal/Proxmox roadmap item).

## Roadmap
Starter set - extend by enabling more rule categories, native-triggering the remaining edges (ACLs,
delegation, ADCS), and on a non-EDR host adding the tool-signature rules (Rubeus/Mimikatz/BloodHound).
Same methodology, same `noisehound-calibrate` step. Packaging the stack config as a documented "stand
up your own SIEM tier" recipe is a tracked roadmap item.
