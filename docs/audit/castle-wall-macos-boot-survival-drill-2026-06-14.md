---
title: Castle Wall macOS boot-survival drill, 2026-06-14/15 (F1, first clean reboot pass)
date: 2026-06-15
author: Erik Newton
status: drill-evidence
severity: capability-claim evidence, thesis-gate
---

# Castle Wall macOS boot-survival drill, 2026-06-14/15

**Purpose.** This document is the in-repo trace target for the F1 boot-service capability (PR #450). Sanctuary's standard for capability claims is drill evidence on the platform that matters, not a release tag. This drill is the first clean demonstration that an armed Castle Wall survives a reboot without bricking the box: the safe-mode boot daemon comes up before login on the boot token alone, the machine stays reachable while the filter is armed, and the persisted policy keeps enforcing. It is the companion to the 2026-06-11 allow/deny drill ([`castle-wall-macos-allow-deny-drill-2026-06-11.md`](castle-wall-macos-allow-deny-drill-2026-06-11.md)); this run re-confirmed the per-uid allow/deny enforcement demo on the boot-service candidate as well.

The earlier boot-service work was held because, as first shipped, the boot daemon could not even start (it crash-looped and the installer wrongly reported success), and two further gaps had to close before a clean reboot drill was meaningful. Those must-fixes landed and were codex-gated before this drill (see "Mid-drill bug caught and fixed" and the must-fix summary below).

## Claim proven

On macOS Tahoe 26.5.1, with the Castle Wall system extension armed and a persisted signed manifest in force:

- **A1 boot-survival: 5/5 reboot reps PASS.** Across five reboots the safe-mode boot daemon started before login on the boot token only, the box stayed reachable while armed, and the persisted manifest kept enforcing. The 2026-06-13 whole-box boot-cut defect would have failed this; it did not.
- **A2 per-uid allow/deny enforcement demo: PASS (N=3).** In an armed window, the wrapped agent (uid 502) was blocked on a non-allowlisted destination and allowed on its allowlisted destination, while the operator (uid 501) reached the same destination unaffected, repeated across three deterministic reps. The operator was never cut.

The drilled candidate was signed build v774 (CFBundleVersion 774), git_sha `8c8efe68`, extension binary SHA-256 `5fae8f4b...`, on Mini1 (Agents-Mac-mini), Erik present at the console, 2026-06-15.

The honest upper bound on this claim is "enforces a signed operator policy with a clean per-uid allow/deny demo and reboot-survival." It is **not** "audited per-rule per-flow" (see "What this does not prove, the C4 gap").

## Platform and builds

| Item | Value |
|---|---|
| Host | Mini1 (Agents-Mac-mini), macOS Tahoe 26.5.1 |
| System extension | `ai.sanctuaryprotocol.macos.castle-wall`, CFBundleVersion 774, activated and enabled |
| Extension binary | SHA-256 `5fae8f4b...` (verified changed from prior candidates `9f89cfff` (v771) and `badef967` (v773); the stale-extension trap was closed each rebuild) |
| Host app / CLI commit | git_sha `8c8efe68` (the drilled source; see "Rebase nuance" for how this relates to main) |
| Fortress / pin | drill fortress `.sanctuary-drill-0611b`, global pin `c3f22755`; real `~/.sanctuary` never touched |
| Roles | MBA subthread orchestrated over SSH; Erik present at the Mini1 console for the signed build, deploy, and reboots |

## A1, F1 boot-survival, 5/5 reboot reps

Criteria were pre-declared. Each rep was a real reboot of the armed machine; the table records the safe-mode daemon coming up before login and the box staying reachable.

| Rep | SSH down then up | Safe-mode daemon PID (before login) | Reachable, not bricked | Armed (ext SHA) |
|---|---|---|---|---|
| 1 | ~79s | up | yes | `5fae8f4b` |
| 2 | ~141s | up | yes | `5fae8f4b` |
| 3 | ~57s | up | yes | `5fae8f4b` |
| 4 | ~61s | up | yes | `5fae8f4b` |
| 5 | ~72s | up | yes | `5fae8f4b` |

Per-criterion verdict (one line each):

- **C1, safe-mode daemon up before login, boot-token only: PASS x5.** Each rep the daemon logged that it came up on the boot token only, with no fortress master key, signing via the root helper, audit source `launchd-boot-safe-mode`.
- **C2, reachable, not deny-all bricked: PASS x5.** The box was reachable while the extension was armed and running on every rep; the 2026-06-13 boot-cut would have failed this.
- **C3, persisted manifest enforces: PASS.** Armed and reachable on each reboot means the operator baseline manifest was enforcing in the pre-daemon window.
- **C4, helper signing from the root safe-mode daemon: IMPLICIT (not a targeted sub-test).** The daemon came up in helper-signing mode and the manifest was delivered and the box stayed reachable each reboot, which is consistent with the helper signing. A targeted peer-auth sub-test is still pending; it does not affect the not-bricked result.
- **C5, master key at login, no auto-supersede, not bricked: demonstrated.** A FileVault-passthrough login left the safe-mode daemon persisting without bricking. There is no automatic supersede of the root boot daemon by the operator full daemon (honestly de-scoped, see the must-fix summary); the box stays protected in safe mode meanwhile.
- **C6, wrong or absent boot token fails closed: PENDING targeted sub-test.** Unit-covered, not exercised on hardware in this run.
- **C7, KeepAlive recovery after a daemon kill: PENDING targeted sub-test.** Unit-covered, not exercised on hardware in this run.
- **Item 2, boot-daemon PATH durability: PROVEN.** The rendered plist PATH includes the stable Homebrew symlink dir (`/opt/homebrew/bin`), so a `brew upgrade node` will not retire the interpreter dir and re-brick the box.
- **Item 3, operator-reachable safe-mode socket: PROVEN x5.** The safe-mode socket was re-owned to the operator each rep, so the operator CLI reaches the daemon (the socket-level reachability the programmatic dead-man lever depends on; the lever's effect is covered under C5 disarm below).
- **Composition guard, arming implies a boot service is installed: PROVEN.** Code plus unit tests; the install-boot-before-arm ordering was honored.

## A2, per-uid allow/deny enforcement demo, N=3

In an armed window enforcing the drill manifest, egress was probed as the agent and as the operator. The same destination is blocked for the agent but reachable for the operator, proving the enforcement is uid-scoped agent classification, not a blanket block.

| Probe | Result | Reps |
|---|---|---|
| agent (uid 502) to allowlisted host (`allow-anthropic`) | connected (HTTP 404, reachable) | 3/3 |
| agent (uid 502) to non-allowlisted IP `1.1.1.1` (`deny-exfil`) | blocked (curl exit 7) | 3/3 |
| operator (uid 501) to the same `1.1.1.1` | reachable (HTTP 301) | 1/1 |
| operator SSH during the armed window | alive throughout | full session |

- **C1, operator not cut: PASS.** The orchestrator SSH session was alive throughout all reps.
- **C2, allow lane passes: PASS x3.** The agent reached its allowlisted host.
- **C3, deny lane blocks: PASS x3.** The agent's traffic to the non-allowlisted IP was dropped deterministically.
- **Per-uid differential: clean demo.** The same destination is blocked for the agent (502) and allowed for the operator (501) in the same armed window.
- **C5, disarm: PASS (functional).** Two distinct steps, do not conflate them. (1) The CLI `disable` dead-man lever reached the daemon over the now-operator-reachable socket and revoked the provider dead-man lease; the operator was not cut. This is the lease-revoke, not a full filter disarm. (2) Definitive filter disarm on Tahoe was via the GUI VPN and Filters toggle, after which the agent's previously blocked destination returned reachable (functional proof the filter stopped enforcing). The extension process lingered as a known Tahoe sysext artifact (loaded but not enforcing, proven by the functional test; it clears on the next reboot).

## What this does not prove, the C4 gap

- **No rule-attributed per-flow audit trail exists in this configuration. "Audited per-rule per-flow" is NOT established.** The allow/deny differential above is genuine external behavioral evidence (the extension actually allowed and blocked per-uid; it is not a daemon self-report). But the per-flow decisions are autonomous extension and manifest decisions, and they are not recorded to any queryable rule-attributed audit log: the safe-mode boot-audit segment was empty, the daemon log records lifecycle events (filter started, policy loaded) rather than per-flow verdicts, and the extension os_log is framework-level only with no rule-name attribution. A rule-attributed per-flow audit trail appears not to exist for autonomous manifest decisions, independent of safe-mode versus full daemon. This is a real observability gap. The producer-signed per-flow audit trail that would close it is an unbuilt future build (C4), not a current capability. Do not describe this work as "audited per-rule per-flow."
- **One host, one OS version.** This is a single-machine proof on macOS Tahoe 26.5.1, not a fleet or multi-version claim.
- **Not a performance claim.** No overhead numbers were captured.
- **C6 and C7 were not exercised on hardware** in this run (unit-covered only); the box-not-bricked result does not depend on them.

## Rebase nuance, drilled source versus the merged tree

The behavior proven above was captured on the drilled source at git_sha `8c8efe68` (branch `drill/f1-lean-2026-06-14`). That source was rebased onto main and merged as PR #450 (`7732f4d5`). The rebase was verified behavior-preserving: it passed the codex review and the frozen-surface guard, and the two core boot files (`server/src/castle-wall/boot/boot-token.ts` and `server/src/castle-wall/runtime/macos-daemon.ts`) are byte-identical (SHA-256 match) between the drilled commit `8c8efe68` and the merged commit `7732f4d5`.

What this drill does **not** establish: a fresh signed build produced from main's exact tree was not independently reboot-drilled. The reboot evidence is from the v774 binary built at `8c8efe68`. The byte-identity of the core boot files plus the clean codex and frozen-surface checks are the basis for treating the merged tree as behavior-equivalent; that is an inference from the rebase verification, not a second on-hardware drill of main's exact binary.

## Mid-drill bug caught and fixed

A real F1 daemon-start bug was caught on the A1 second rep of an earlier candidate (v773): a stale active-config entry plus PID reuse made the safe-mode daemon refuse to start after a reboot (the box was not bricked, the extension fail-safe held). It was fixed mid-drill in `8c8efe68`: an active-config collision now requires a live listener, not a bare PID. The fix was codex-clean and was validated live and across all five v774 reboots above.

## Must-fixes that preceded this drill

The boot-service work was held until five must-fixes closed, each code plus regression test, codex-gated (a refute-by-default codex pass caught two HIGH plus one MED that the build and diff-read both missed, all fixed before the signed rebuild):

1. Boot-daemon PATH plus stable-PID false-PASS (the original crash-loop and false install success).
2. Boot-daemon PATH durability (also prepend the stable Homebrew symlink bin dir so a `brew upgrade node` does not re-brick).
3. Safe-mode daemon socket re-owned to the operator (the programmatic dead-man lever), with a non-following `lstat` + `isSocket()` + `lchown` guard against the symlink-redirect escalation.
4. The full-daemon "supersede safe mode" behavior, which existed only in doc comments, honestly de-scoped (a root KeepAlive boot daemon cannot be stood down by the unprivileged operator daemon), with the docs corrected and an actionable stand-down handoff message added.
5. An install-boot composition guard so arming the filter refuses unless a verified boot service plist is installed (closing the path where arming with no boot daemon re-bricks the next reboot).

## Non-blocking residuals, tracked in issue #567

Two residuals were ruled non-blocking and are tracked in issue #567 (Castle Wall safe-mode hardening):

- **Socket-chown by-name TOCTOU.** The severe symlink-redirect vector is closed (`lstat` + `isSocket()` + `lchown`). The residual is intrinsic: re-owning the safe-mode socket by name in the operator-writable fortress dir is a by-name time-of-check-to-time-of-use window. Under the drill model the agent runs as a separate uid (502) that cannot write the operator's fortress dir, and the fortress dir is `0700`, so only the trusted sudo-capable operator could trip it. The clean fix (relocate the socket to a root-owned directory) is tracked in #567.
- **Real plist parse in the boot guard.** The arm-guard validates plist content (correct Label, `RunAtLoad`, `--safe-mode`); a more thorough real plist parse is the follow-on tracked in #567.

These do not block the not-bricked or the allow/deny results, and the GUI VPN and Filters toggle remains the ultimate dead-man lever throughout.

## End state, box restored safe

The filter was disarmed (functionally verified), the global pin `c3f22755` was intact, the real `~/.sanctuary` was never touched, the boot service was left installed (harmless with the filter off), and the scratch state was cleared.

## Evidence retention

Raw captures (pre-state hashes, per-rep reboot transcripts, armed-window probe transcripts, daemon and extension logs) are retained in the maintainer's drill-evidence archive under the 2026-06-14 Mini1 drill reference, alongside the full drill report. This document summarizes that evidence for in-repo traceability; the numbers above are transcribed from the captured transcripts and summaries.
