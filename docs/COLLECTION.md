# Collecting a BloodHound export that NoiseHound can fully use

NoiseHound scores every relationship BloodHound finds. To exercise the whole
model it needs an export whose graph actually *contains* the interesting edge
families - sessions, lateral movement, Kerberos delegation, DCSync, and ADCS -
not just ACLs. This note is what to hand whoever runs the collection.

## What the last export was missing (and why)

The last `-c All` run was collected correctly - the collection methods ran - but
the graph had none of the lateral/Kerberos families, because the *lab* had
nothing to collect:

- **Sessions were empty** - no user was logged into any machine when SharpHound
  ran, so there were zero `HasSession` edges.
- **One host was offline** - it returned no data at all.
- **No delegation and no replication (DCSync) rights** were configured.

So the fix is mostly about the lab's *state and content*, not the command.

## The easy path: GOAD

If you don't want to hand-configure misconfigurations, run
[GOAD (Game of Active Directory)](https://github.com/Orange-Cyberdefense/GOAD).
It ships a vulnerable multi-domain forest that already contains delegation,
ADCS, Kerberoastable accounts, trusts, and ACL abuse paths. Boot it, stage a
session (below), collect, done.

## If using your own lab: make the edges exist

1. **Stage a live session (most important).** Log a privileged account (a Domain
   Admin or a service account) *interactively or over RDP* onto a workstation or
   member server, and leave it logged in during collection. This is what creates
   `HasSession` edges - the single biggest gap last time.
2. **All target hosts online and reachable** from the collector (SMB 445, RPC
   135, remote registry). A powered-off host contributes nothing.
3. **DCSync:** grant a non-DA test principal the replication rights on the domain
   object - `Replicating Directory Changes` **and** `Replicating Directory
   Changes All`. BloodHound will compute a `DCSync` edge.
4. **Delegation (any or all):**
   - Unconstrained: set a computer/user account `TrustedForDelegation`.
   - Constrained: set `msDS-AllowedToDelegateTo` on an account.
   - RBCD: set `msDS-AllowedToActOnBehalfOfOtherIdentity` on a computer.
5. **Kerberoast / AS-REP:** an account with an SPN (`servicePrincipalName`) and a
   crackable password; and one account with "Do not require Kerberos
   preauthentication" set. (You likely already have SPN accounts.)
6. **ADCS (high value):** install AD CS and publish a deliberately vulnerable
   template - ESC1 is simplest: *supply subject in request* enabled, a
   client-authentication EKU, and manager approval **off**.
7. Keep the existing ACL misconfigurations - those already collect well.

## Collect

Use the **SharpHound that ships with BloodHound CE** (it collects AD CS; the
legacy collector does not). Run it as a domain account that has **local admin on
the target hosts** (needed for reliable logged-on/session data):

```
SharpHound.exe --collectionmethods All,LoggedOn --loop --loopduration 00:30:00
```

- `All` covers Group, ACL, Container, LocalAdmin, RDP, DCOM, PSRemote, Session,
  Trusts, ObjectProps, SPNTargets, and (in CE) CertServices.
- `LoggedOn` is **not** part of `All` and needs local admin, but it is the
  reliable way to capture who is logged in - add it.
- `--loop` for ~30 minutes catches sessions that come and go during the window.

If the collector box isn't already running as a domain user:

```
runas /netonly /user:DOMAIN\collector "SharpHound.exe --collectionmethods All,LoggedOn"
```

## Send it

SharpHound writes a single timestamped `YYYYMMDDHHMMSS_BloodHound.zip`. Send that
zip as-is - do not unzip it. That's the only artifact needed.

## How to know it worked

A good export, run through `noisehound-inspect`, shows `HasSession`, `AdminTo`,
and (if configured) `DCSync` / `AllowedToDelegate` / `ADCSESC*` in the edge
histogram - not just `GenericAll` / `GenericWrite` / `MemberOf`.
