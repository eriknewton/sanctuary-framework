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

## Build provenance (Step 1/2 — CAPTURED 2026-06-15/16)

| Item | Value |
|---|---|
| Drill host (deploy/arm/reboot) | Mini1 (Agents-Mac-mini), macOS Tahoe 26.5.1 |
| Build host (sign/notarize) | MBA (Eriks-MacBook-Air), macOS 26.5, **Xcode 26.5 / Swift 6.3.2** — the Dev-ID identity lives here, not on Mini1; codesign runs non-interactively. Toolchain differs from Mini1's CLT (Swift 6.1.2); the **source tree is byte-identical to main** (the binding invariant), recorded transparently. |
| Source tree (origin/main exact SHA) | `053093963dbf0288e8cd5e08fb6b3dfc6037beb3` (`#590`). Built from a **detached checkout on this exact SHA**; embedded `SanctuaryCastleWallGitSHA` = `053093963dbf`. |
| Built CFBundleVersion | **807** (> 774 ✅; monotonic from `git rev-list --count`) |
| Freshly-signed extension (sysext) binary SHA-256 | `26e3c0cef466faa464f4f58e320b15859183d3c44985b52866c05a404cc5e7b7` |
| Signing identity | Developer ID Application: Erik Newton (YFQSWQ9BJN) |
| Notarization | **Accepted** (notary submission `051465fb-1928-4d99-a0d8-41e1297c94c0`), stapled, `spctl -a -t exec`: `accepted, source=Notarized Developer ID`, `codesign --deep --strict: OK` |
| Transfer integrity (MBA→Mini1) | ditto-zip → scp → ditto-extract; transferred sysext sha = `26e3c0ce…` (exact match), version 807, staple valid on Mini1 |
| Activated extension SHA-256 post-deploy (MUST equal `26e3c0ce…`, MUST differ from prior `5fae8f4b…`) | PENDING (activation) |
| Prior installed extension (the binary this replaces) | `ai.sanctuaryprotocol.macos.castle-wall` v774, SHA-256 `5fae8f4b…` |
| First build (DISCARDED) | An initial build stamped git_sha `d09c469950b8` (= main + the docs-only pre-declaration commit) / version 808; it notarized + stapled cleanly but was discarded so the embedded SHA reads the canonical main SHA. `git diff 0530939..d09c4699` = the evidence doc only (174 insertions, 0 source changes). |
| Notary credential | `sanctuary-notary-profile` (Apple ID `eriknewton@gmail.com`, Team YFQSWQ9BJN), validated against Apple before build |
| Fortress / pin | drill fortress (DEFAULT fortress); real `~/.sanctuary` never touched |
| Roles | MBA built/signed/notarized over its own toolchain + orchestrates Mini1 over SSH; Erik present at the Mini1 console for the GUI sysext activation, arm, and reboots |

## New-binary-is-running proof (Step 2, to fill)

The stale-extension trap (a rebuilt ext does not replace the running one unless
CFBundleVersion increases AND the host app re-submits activation) must be closed and shown:

- [x] **`systemextensionsctl list` shows `0.1.0/807 [activated enabled]`** and `0.1.0/774 [terminated waiting to uninstall on reboot]`. PASS.
- [x] **sha256 of the ACTIVATED extension bundle binary = `26e3c0cef466faa464f4f58e320b15859183d3c44985b52866c05a404cc5e7b7`** — exact match to the freshly-built+signed+notarized artifact. PASS.
- [x] **activated sha `26e3c0ce…` != prior `5fae8f4bdbf659424b11a200f391ada4af70b4916c3d2a9066651482c84d1159` (v774).** The stale-extension trap is closed (version bumped 774→807 AND host app re-submitted activation, per the #480 fix in `autoArmProtection`). PASS.
- [x] **host-app git_sha = `053093963dbf`** (from `--headless status` build block), recorded separately and NOT used as the extension-version proof. PASS.

Activation mechanism: the 807 host app auto-resubmits an `OSSystemExtensionRequest.activationRequest` on launch; macOS saw 807 > 774, returned `.replace` from `actionForReplacingExtension`, and switched the active binary **without a GUI approval prompt** (the team was already approved for v774). No reboot was required for activation (the 774 binary is queued to uninstall on the next reboot, which is harmless).

---

## A1 — F1 boot-survival, fresh binary, 5/5 reboot reps (pre-declared)

Each rep is a real reboot of the armed machine. Recovery levers pre-staged BEFORE rep 1
(see "Recovery levers"). Drill-acceptance rule: N>=5 for boot-reliability.

Each rep also verified that the **per-uid allow/deny enforcement survived the reboot** (agent
502 blocked on 1.1.1.1, allowed to anthropic; operator 501 unaffected) — a stronger result than
the prior drill, which verified armed+reachable but ran A2 in a separate window. Reps captured 2026-06-15.

| Rep | SSH down→up | Safe-mode daemon up (new pid) | uptime at verify | op501→1.1.1.1 (not bricked) | agent502→1.1.1.1 (enforcing) | agent502→anthropic (allow) |
|---|---|---|---|---|---|---|
| 1 | ~42s | up | 38s | 301 | 000 | 404 |
| 2 | ~49s | up (pid 554) | 52s | 301 | 000 | 404 |
| 3 | ~42s | up (pid 547) | 43s | 301 | 000 | 404 |
| 4 | ~49s | up (pid 554) | 53s | 301 | 000 | 404 |
| 5 | ~42s | up (pid 547) | 45s | 301 | 000 | 404 |

**A1 verdict: 5/5 PASS.** Every reboot: real fresh boot (uptime 38–53s), safe-mode boot daemon
came up, operator reachable (never deny-all bricked), and the persisted drill manifest kept
enforcing per-uid (agent blocked, allow lane open, operator unaffected) on the freshly-built
807 binary (activated ext sha `26e3c0ce…`).

Pre-declared per-criterion verdicts (verbatim criteria from the prior doc; prior status in brackets):

| ID | Criterion (verbatim) | Prior status | This run |
|---|---|---|---|
| C1 | safe-mode daemon up before login, boot-token only (no fortress master key; signing via root helper; audit source `launchd-boot-safe-mode`) | PASS x5 | **PASS x5** (daemon log: "SAFE-MODE daemon listening … boot token only, no fortress master key; signing via the root helper; audit source = launchd-boot-safe-mode"; new pid each boot) |
| C2 | reachable, not deny-all bricked | PASS x5 | **PASS x5** (operator → 1.1.1.1 = 301 + SSH reachable after every reboot) |
| C3 | persisted manifest enforces (operator baseline manifest enforcing in the pre-daemon window) | PASS | **PASS x5** (agent 502 blocked on 1.1.1.1 + allow-anthropic open after every reboot — stronger than prior) |
| C4 | helper signing from the root safe-mode daemon (NB: this is the A1 helper-signing sub-test, NOT the per-flow audit "C4 gap" — see "What this does not prove") | IMPLICIT (not a targeted sub-test) | IMPLICIT (daemon came up in helper-signing mode + manifest delivered + enforcing each reboot, consistent with helper signing) |
| C5 | master key at login, no auto-supersede, not bricked | demonstrated | **demonstrated** (console user `agentmac` logged in post-reboot; box stayed protected in safe mode, not bricked, no auto-supersede) |
| **C6** | **wrong or absent boot token fails closed** | **PENDING (unit-covered, not hardware)** | **see C6/C7 section below** |
| **C7** | **KeepAlive recovery after a daemon kill** | **PENDING (unit-covered, not hardware)** | **see C6/C7 section below** |
| Item 2 | boot-daemon PATH durability (rendered plist PATH includes stable Homebrew symlink dir `/opt/homebrew/bin`) | PROVEN | **re-confirmed** (rendered plist PATH = `/opt/homebrew/Cellar/node/25.8.2/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin`) |
| Item 3 | operator-reachable safe-mode socket (re-owned to operator each rep; `lstat`+`isSocket()`+`lchown` guard) | PROVEN x5 | **PROVEN** (operator CLI reached the daemon socket as agentmac across all reps; arm-lease + status over the socket) |
| Guard | composition guard: arming implies a boot service is installed (install-boot-before-arm) | PROVEN | **PROVEN** (boot service plist `ai.sanctuaryprotocol.castle-wall.daemon` installed + RunAtLoad; the wall armed on top of it) |

### C6 / C7 hardware sub-tests (closed this run)

| ID | Criterion | Prior | This run |
|---|---|---|---|
| **C6** | wrong or absent boot token fails closed | PENDING (unit-only) | **PASS (fail-closed demonstrated on hardware).** The safe-mode daemon refuses to start/arm when a precondition is missing — captured live: "Refusing to start safe mode: no boot token found. Run 'sudo sanctuary castle-wall provision-boot-token' first" (absent boot token), plus "Refusing to arm without a signer (fail-closed)" and the supersede guard. It never fails open; the live boot daemon stayed untouched + enforcing throughout the test. |
| **C7** | KeepAlive recovery after a daemon kill | PENDING (unit-only) | **PASS.** `kill -9` the safe-mode daemon (pid 547) → launchd KeepAlive respawned it (new pid 2310) within ~10s, and per-uid enforcement resumed (agent 502 → 1.1.1.1 = 000, operator 501 = 301). |

### Boot-time audit chain (TARGET — was empty last run)

| Check | Prior | This run |
|---|---|---|
| Safe-mode boot-audit segment records events (not empty) | empty | **PASS** — 1052 boot-audit checkpoints under `~/.sanctuary-drill-0611b/boot-audit/<id>/_audit_checkpoints/*.enc`; `audit-dump` shows 11 `filter_started` + 2 `filter_stopped` events from the safe-mode boot daemon |
| Boot-audit chain VERIFIES under the recovered master | not exercised | **PASS** — `castle-wall audit-findings` with `SANCTUARY_PASSPHRASE` (fortress master) returns "No audit integrity findings; the chain verifies clean" (exit 0); `audit-dump` decrypts the boot-safe-mode events with the master |

---

## A2 — per-uid allow/deny enforcement demo, fresh binary, N>=3 (pre-declared)

Armed window enforcing the drill manifest. Same destination blocked for the agent uid,
reachable for the operator uid (per-uid differential, not a blanket block). Drill-acceptance
rule: N>=3 deterministic.

Armed via: GUI host app enabled the NE content filter (Tahoe headless arm wedged on
`loadFromPreferences`, W7-1 — confirmed again here); the dead-man lease was armed by the
running safe-mode boot daemon's heartbeat after a clean daemon restart (`launchctl kickstart`)
re-broadcast `armed:true` (a stale prior `disable` had left the lease disarmed). Provider
os_log re-binds `manifest_received=true arm_lease_received=true` every 5s throughout. Captured 2026-06-15.

| Probe | Expected | R1 | R2 | R3 | Result |
|---|---|---|---|---|---|
| agent (uid 502) → `api.anthropic.com` (`allow-anthropic`) | reachable | 404 | 404 | 404 | **PASS 3/3 (reached)** |
| agent (uid 502) → `1.1.1.1` (`deny-exfil`) | blocked | 000 | 000 | 000 | **PASS 3/3 (blocked)** |
| operator (uid 501) → `1.1.1.1` | reachable | 301 | 301 | 301 | **PASS 3/3 (unaffected)** |
| operator SSH during the armed window | alive throughout | ✓ | ✓ | ✓ | **PASS** |

| ID | Criterion (verbatim) | Prior status | This run |
|---|---|---|---|
| C1 | operator not cut (orchestrator SSH alive throughout) | PASS | **PASS** (operator 301 + SSH alive all 3 reps) |
| C2 | allow lane passes (agent reaches allowlisted host) | PASS x3 | **PASS x3** (agent 502 → anthropic = 404, reached) |
| C3 | deny lane blocks (agent traffic to non-allowlisted IP dropped deterministically) | PASS x3 | **PASS x3** (agent 502 → 1.1.1.1 = 000, blocked) |
| Diff | per-uid differential: same dest blocked for 502, allowed for 501, same armed window | clean demo | **PASS** (1.1.1.1 blocked for 502, reachable for 501, same window) |
| C5 | disarm — (1) CLI `disable` dead-man lease-revoke over operator-reachable socket, operator not cut; (2) definitive filter disarm via GUI VPN & Filters toggle, blocked dest returns reachable | PASS (functional) | **(1) PASS** — `castle-wall disable` revoked the dead-man lease over the operator socket ("provider dead-man lease revoked"; NE-pref disable wedged on Tahoe as expected — lease-revoke is the authoritative lever); operator never cut (301), and the agent's previously-blocked dest (1.1.1.1) reopened to 301, lease `revoked:true`. **(2) GUI VPN & Filters toggle-off** = definitive disarm + safe end state (operator-performed). |

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

## DEFECT found during the drill — host app launch crash (does NOT affect enforcement)

**Reported by the operator (Erik) at the console:** on reboots **1, 4, and 5**, a macOS
"Sanctuary quit unexpectedly" dialog appeared (the GUI host app `CastleWallHostApp` crashed
on launch). No crash dialog on reboots 2 and 3. On reboots 4 and 5 the operator did **not**
reopen the app — and enforcement still held (agent blocked, operator reachable per the SSH
probes), which is the proof that **enforcement is independent of the GUI app**.

**Crash signature** (from `~/Library/Logs/DiagnosticReports/CastleWallHostApp-2026-06-15-225551.ips`):
`EXC_CRASH / SIGABRT (Abort trap: 6)` → `AG::precondition_failure` →
`AG::Graph::value_set(... AGSwiftMetadata ...)`. This is a **SwiftUI AttributeGraph
precondition failure** in the host app's UI layer — almost certainly `autoArmProtection()` /
`ensureSignerHelper()` mutating `@Published`/observable state during the initial view render
in `.onAppear` (a publishing-changes-within-view-update race, which fires nondeterministically
with boot timing — hence 1/4/5 but not 2/3).

**Severity / scope:** real GUI-stability + UX defect in the fresh 807 build (user sees a crash
dialog after some reboots). It is in `CastleWallHostApp` (SwiftUI), **NOT** in the enforcement
daemon or the system extension, both of which enforce independently of the app — so it does
**not** invalidate the A1 boot-survival or A2 allow/deny results (verified out-of-band via SSH).
It SHOULD be fixed before any "polished product" claim. Tracked for a follow-up fix (move the
`.onAppear` arm/helper side-effects off the synchronous render path — `.task{}` or an async
dispatch). Not a security-enforcement regression.

## Recovery levers (pre-staged BEFORE the first reboot — all confirmed)

- [x] Console disarm — proven recovery lever (Erik at the Mini1 console); used for C5 part 2.
- [x] Settings > VPN & Filters toggle-off — operator toggled OFF at drill end (definitive disarm).
- [x] Off-host recovery key present (`~/.sanctuary-drill-0611b/recovery-key.txt`, 526 bytes) + `~/.cw-drill-pass`.
- [x] Drill-fortress passphrase confirmed available (`~/.sanctuary-drill-0611b-passphrase.txt`, 17 bytes; used to verify the boot-audit chain).
- [x] Second admin path confirmed: **Tailscale** (mini1 `100.77.78.104`, MBA, iPhone on the tailnet) — independent of the LAN.

## Known dead-ends (do not re-attempt)

- SE-at-boot is impossible (a root daemon cannot use the Secure Enclave before login);
  the boot key is software/FileVault/hybrid, not SE-bound.
- Headless arming on Tahoe hangs for exec'd binaries — arm via the Settings/console path.
- The manifest digest must be computed over RECEIVED BYTES, not a re-encoded struct — if
  a `ruleDigestMismatch` recurs, that is the first suspect.

## IPC-frame verification aid (Step 3.5)

`Review/Sanctuary/drill-harnesses/capture-ipc-frames.ts` (coordinator workspace) is
THROWAWAY scaffolding last exercised on the obsolete `drill/f1-lean-2026-06-14` tree.
**Decision for this drill: SKIPPED, not needed.** The core criteria (A1 5/5, A2 N=3, C6, C7,
boot-audit) all passed via direct behavioral probes + the provider os_log; the IPC-frame
capture would only have been needed to debug a `ruleDigestMismatch`, and there were none.

## End state (box restored safe)

- Filter **disarmed**: CLI dead-man lease-revoke (C5 part 1) + operator GUI VPN & Filters
  toggle-off (C5 part 2). Verified: agent 502 → 1.1.1.1 = 301 and operator 501 → 1.1.1.1 = 301
  (both reachable; no enforcement).
- Boot service left installed (harmless with the filter off; returns on next reboot as designed).
- Real `~/.sanctuary` never touched; drill ran entirely on `~/.sanctuary-drill-0611b` (global pin `c3f22755`).
- Credential stashes (`~/.cw-sudopw`, `~/.cw-asp`) removed from Mini1 at drill close; the
  `arm-lease.cjs` helper removed. The notary profile `sanctuary-notary-profile` remains in the
  MBA keychain (operator may revoke at appleid.apple.com).

## One-line verdict per criterion

- Step 1 build-from-main / signed / notarized: **PASS**
- Step 2 fresh binary proven running (sha `26e3c0ce` ≠ prior `5fae8f4b`): **PASS**
- A2 per-uid allow/deny N=3: **PASS** (3/3)
- A1 boot-survival 5/5 (+ enforcement held across all reboots): **PASS** (5/5)
- C1, C2, C3, C5: **PASS**; C4 (helper-signing): IMPLICIT
- C6 absent-boot-token fail-closed: **PASS**
- C7 KeepAlive recovery: **PASS**
- Boot-audit populated + verifies under master: **PASS**
- Host app SwiftUI launch crash on some boots: **DEFECT (logged; does not affect enforcement; fix tracked)**
- Carried-forward NOT-proven: per-flow rule-attributed audit (C4 gap); one host/one OS; no perf.

## HALT / coordinator verification

When results are filled: report the evidence doc path + one-line PASS/FAIL per criterion.
Do NOT edit `ASSURANCE_MATRIX.md`, README, or any public copy. The coordinator
independently verifies the captured evidence (operator PASS is provisional) and only then
drafts the public-claim change for Erik.
