---
title: Castle Wall macOS fresh-binary re-drill, 2026-06-16 (F1, build from main's exact tree)
date: 2026-06-16
author: Erik Newton
status: drill-evidence-PRE-DECLARED (criteria fixed before any run; results PENDING)
severity: capability-claim evidence, thesis-gate
---

# Castle Wall macOS fresh-binary re-drill, 2026-06-16

**This document was authored BEFORE the drill ran.** The criteria in the tables below
were transcribed verbatim from the prior authoritative evidence doc
([`castle-wall-macos-boot-survival-drill-2026-06-14.md`](castle-wall-macos-boot-survival-drill-2026-06-14.md))
and the per-uid allow/deny drill
([`castle-wall-macos-allow-deny-drill-2026-06-11.md`](castle-wall-macos-allow-deny-drill-2026-06-11.md)).
A criterion invented after results does not count. Result columns read `PENDING` until
the Erik-present hardware run fills them; the coordinator independently verifies the
captured evidence before any public claim moves (the operator PASS is provisional).

## Why this drill exists (the one gap it closes)

The prior boot-survival pass (06-14/15, signed build v774, git_sha `8c8efe68`) proved
A1 boot-survival 5/5 and A2 per-uid allow/deny N=3 on the **drilled** source. That source
was rebased onto main and merged as PR #450 (`7732f4d5`); the rebase was verified
behavior-preserving (clean codex, frozen-surface guard, byte-identical core boot files).
But, in the prior doc's own words:

> a fresh signed build produced from main's exact tree was not independently
> reboot-drilled. The reboot evidence is from the v774 binary built at `8c8efe68`. ...
> that is an inference from the rebase verification, not a second on-hardware drill of
> main's exact binary.

This drill removes that inference. It builds a **fresh signed binary from `origin/main`'s
exact tree**, proves the freshly-signed binary is the one actually running, and re-runs
the pre-declared criteria on it. It additionally closes the two criteria that were
unit-covered-only last run (**C6, C7**) on hardware, and populates the **boot-time audit
chain** (empty last run) plus verifies it under the recovered master.

**What landing this unlocks (and what it does NOT):** the honest public macOS claim can
become "enforces a signed operator policy with a clean per-uid allow/deny demo that
survives reboot," proven on main's exact binary. It remains **NOT** "audited per-rule
per-flow" — the producer-signed per-flow rule-attributed audit trail (C4) is an unbuilt
future build, carried forward honestly below. Nothing public changes from this document;
the coordinator drafts any claim change for Erik after verifying the captured evidence.

## Build provenance (to fill during Step 1/2)

| Item | Value |
|---|---|
| Host | Mini1 (Agents-Mac-mini), macOS Tahoe 26.5.1 |
| Source tree (origin/main exact SHA) | `053093963dbf0288e8cd5e08fb6b3dfc6037beb3` (`#590`, "freeze public surface before l1-l4 rename (PR-0)") |
| Built CFBundleVersion | PENDING (MUST be > 774; prior installed = 774) |
| Freshly-signed extension binary SHA-256 | PENDING |
| Signing identity | Developer ID Application: Erik Newton (YFQSWQ9BJN) |
| Activated extension SHA-256 post-deploy (MUST equal freshly-signed, MUST differ from prior `5fae8f4b...`) | PENDING |
| Prior installed extension (the binary this replaces) | `ai.sanctuaryprotocol.macos.castle-wall` v774, SHA-256 `5fae8f4b...` |
| Fortress / pin | drill fortress (DEFAULT fortress), global pin `c3f22755`; real `~/.sanctuary` never touched |
| Roles | MBA subthread orchestrated over SSH; Erik present at the Mini1 console for the signed build, deploy/activation, GUI arm, and reboots |

## New-binary-is-running proof (Step 2, to fill)

The stale-extension trap (a rebuilt ext does not replace the running one unless
CFBundleVersion increases AND the host app re-submits activation) must be closed and shown:

- [ ] `systemextensionsctl list` shows version > 774, `[activated enabled]`. (capture PENDING)
- [ ] sha256 of the ACTIVATED extension bundle binary == the freshly-signed sha (PENDING)
- [ ] activated sha != prior `5fae8f4b...` (PENDING)
- [ ] host-app git_sha recorded separately (NOT used as the extension-version proof). (PENDING)

---

## A1 — F1 boot-survival, fresh binary, 5/5 reboot reps (pre-declared)

Each rep is a real reboot of the armed machine. Recovery levers pre-staged BEFORE rep 1
(see "Recovery levers"). Drill-acceptance rule: N>=5 for boot-reliability.

| Rep | SSH down→up | Safe-mode daemon up before login (boot-token only) | Reachable, not bricked | Armed (activated ext sha) |
|---|---|---|---|---|
| 1 | PENDING | PENDING | PENDING | PENDING |
| 2 | PENDING | PENDING | PENDING | PENDING |
| 3 | PENDING | PENDING | PENDING | PENDING |
| 4 | PENDING | PENDING | PENDING | PENDING |
| 5 | PENDING | PENDING | PENDING | PENDING |

Pre-declared per-criterion verdicts (verbatim criteria from the prior doc; prior status in brackets):

| ID | Criterion (verbatim) | Prior status | This run |
|---|---|---|---|
| C1 | safe-mode daemon up before login, boot-token only (no fortress master key; signing via root helper; audit source `launchd-boot-safe-mode`) | PASS x5 | PENDING |
| C2 | reachable, not deny-all bricked | PASS x5 | PENDING |
| C3 | persisted manifest enforces (operator baseline manifest enforcing in the pre-daemon window) | PASS | PENDING |
| C4 | helper signing from the root safe-mode daemon (NB: this is the A1 helper-signing sub-test, NOT the per-flow audit "C4 gap" — see "What this does not prove") | IMPLICIT (not a targeted sub-test) | PENDING (targeted sub-test if feasible) |
| C5 | master key at login, no auto-supersede, not bricked | demonstrated | PENDING |
| **C6** | **wrong or absent boot token fails closed** | **PENDING (unit-covered, not hardware)** | **TARGET — close on hardware** |
| **C7** | **KeepAlive recovery after a daemon kill** | **PENDING (unit-covered, not hardware)** | **TARGET — close on hardware** |
| Item 2 | boot-daemon PATH durability (rendered plist PATH includes stable Homebrew symlink dir `/opt/homebrew/bin`) | PROVEN | PENDING (re-confirm on fresh build) |
| Item 3 | operator-reachable safe-mode socket (re-owned to operator each rep; `lstat`+`isSocket()`+`lchown` guard) | PROVEN x5 | PENDING |
| Guard | composition guard: arming implies a boot service is installed (install-boot-before-arm) | PROVEN | PENDING |

### Boot-time audit chain (TARGET — was empty last run)

| Check | Prior | This run |
|---|---|---|
| Safe-mode boot-audit segment records events (not empty) | empty | PENDING — TARGET |
| Boot-audit chain VERIFIES under the recovered master | not exercised | PENDING — TARGET |

---

## A2 — per-uid allow/deny enforcement demo, fresh binary, N>=3 (pre-declared)

Armed window enforcing the drill manifest. Same destination blocked for the agent uid,
reachable for the operator uid (per-uid differential, not a blanket block). Drill-acceptance
rule: N>=3 deterministic.

| Probe | Expected | Reps | Result |
|---|---|---|---|
| agent (uid 502) → allowlisted host (`allow-anthropic`) | connected (reachable) | 3 | PENDING |
| agent (uid 502) → non-allowlisted IP `1.1.1.1` (`deny-exfil`) | blocked (curl exit 7) | 3 | PENDING |
| operator (uid 501) → same `1.1.1.1` | reachable | >=1 | PENDING |
| operator SSH during the armed window | alive throughout | full session | PENDING |

| ID | Criterion (verbatim) | Prior status | This run |
|---|---|---|---|
| C1 | operator not cut (orchestrator SSH alive throughout) | PASS | PENDING |
| C2 | allow lane passes (agent reaches allowlisted host) | PASS x3 | PENDING |
| C3 | deny lane blocks (agent traffic to non-allowlisted IP dropped deterministically) | PASS x3 | PENDING |
| Diff | per-uid differential: same dest blocked for 502, allowed for 501, same armed window | clean demo | PENDING |
| C5 | disarm — (1) CLI `disable` dead-man lease-revoke over operator-reachable socket, operator not cut; (2) definitive filter disarm via GUI VPN & Filters toggle, blocked dest returns reachable | PASS (functional) | PENDING |

---

## What this does NOT prove (carried forward honestly — do not claim)

- **No rule-attributed per-flow audit trail (the "C4 gap").** The allow/deny differential
  is genuine external behavioral evidence, but per-flow decisions are autonomous
  extension/manifest decisions and are NOT recorded to any queryable rule-attributed
  audit log. The producer-signed per-flow audit trail that would close this is an unbuilt
  future build (C4), not a current capability. **Do not describe this work as "audited
  per-rule per-flow."**
- **One host, one OS version.** Single-machine proof on macOS Tahoe 26.5.1.
- **Not a performance claim.** No overhead numbers captured.

## Recovery levers (pre-staged BEFORE the first reboot)

- [ ] Console disarm — the proven recovery lever (Erik at the Mini1 console).
- [ ] Settings > VPN & Filters toggle-off — recovers a whole-box deny-all cut.
- [ ] Off-host recovery key captured (a sysext cannot be killed under SIP; daemon-disable
      does NOT stop the extension — only reboot or the Settings toggle does).
- [ ] Drill-fortress passphrase confirmed available (prior: `~/.sanctuary-drill-0611b-passphrase.txt`).
- [ ] Second admin path to Mini1 confirmed (physical console / mosh / `ssh -t mini1`) in
      case the filter cuts the orchestrator SSH.

## Known dead-ends (do not re-attempt)

- SE-at-boot is impossible (a root daemon cannot use the Secure Enclave before login);
  the boot key is software/FileVault/hybrid, not SE-bound.
- Headless arming on Tahoe hangs for exec'd binaries — arm via the Settings/console path.
- The manifest digest must be computed over RECEIVED BYTES, not a re-encoded struct — if
  a `ruleDigestMismatch` recurs, that is the first suspect.

## IPC-frame verification aid (Step 3.5)

`Review/Sanctuary/drill-harnesses/capture-ipc-frames.ts` (coordinator workspace) is
THROWAWAY scaffolding last exercised on the obsolete `drill/f1-lean-2026-06-14` tree
(~34 commits behind main). Per its README, treat as a starting point to re-verify/rebuild,
NOT a trusted artifact. Decision for this drill: PENDING (re-verify against main's exact
tree during the armed-window phase; not a blocker for the core A1/A2/C6/C7 criteria).

## HALT / coordinator verification

When results are filled: report the evidence doc path + one-line PASS/FAIL per criterion.
Do NOT edit `ASSURANCE_MATRIX.md`, README, or any public copy. The coordinator
independently verifies the captured evidence (operator PASS is provisional) and only then
drafts the public-claim change for Erik.
