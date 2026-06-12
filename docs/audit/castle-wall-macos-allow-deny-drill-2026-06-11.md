---
title: Castle Wall macOS allow/deny drill, 2026-06-11 (first clean capture)
date: 2026-06-11
author: Erik Newton
status: drill-evidence
severity: capability-claim evidence, thesis-gate
---

# Castle Wall macOS allow/deny drill, 2026-06-11

**Purpose.** This document is the in-repo trace target for the ASSURANCE_MATRIX row "Egress enforcement: macOS". Sanctuary's standard for capability claims is drill evidence on the platform that matters, not a release tag. This drill is the first clean allow/deny demonstration under an armed Castle Wall on macOS: the wall blocked the wrapped agent, allowed the agent's allowlisted endpoint, and left the operator untouched, repeatedly.

## Claim proven

On macOS, with the Castle Wall system extension armed: **policy received + enforced + audited per rule, AND a clean allow/deny demonstration** (agent blocked on a non-allowlisted IP, agent allowed on an allowlisted hostname, operator unaffected), repeated across 3 armed cycles (N=3). Graceful disarm and dead-man fail-open each passed 3/3.

Three prior drill attempts (2026-06-10, 2026-06-11a, 2026-06-11b) cut the operator's own egress the moment the wall armed. This drill did not. The W5 manifest-digest fix (PR #479, digest over received rule bytes) and the W6 deployment-path fix (PR #480, version stamp + re-activation so a rebuilt extension actually replaces the running one) put the correct enforcement code on the box for the first time, and it behaved.

## Platform and builds

| Item | Value |
|---|---|
| Host | Mini1 (Mac mini), macOS Tahoe 26.5.1 |
| System extension | `ai.sanctuaryprotocol.macos.castle-wall`, CFBundleVersion 716, activated and enabled |
| Extension binary | SHA-256 `2380e9e0...` (verified changed from the pre-drill activated binary `d3084142...`) |
| Host app / CLI commit | `6c06c8b1` on main (CLI build SHA matched the app's `SanctuaryCastleWallGitSHA`, confirming a single-build handshake) |
| Roles | Coordinator-orchestrated; operator present at console for system-extension approval |

## Procedure

1. **Phase 0, deployment-replacement proof.** Captured the SHA-256 of the currently activated extension binary, deployed the v716 build, and verified after console approval that the newly activated binary hash matched the staged bundle and differed from the pre-drill binary. This closes the silent-stale-extension failure that invalidated the two prior drill rounds. One finding surfaced live: macOS Tahoe silently uninstalls a signed-but-unnotarized system extension at validation, so the bundle was notarized and stapled in-session before activation succeeded (hardened on main as PR #481, build fails loud if a sysext bundle is unnotarized).
2. **Armed enforcement window.** The policy in force contained a hostname allow rule (`allow-openrouter`), which causes the daemon to inject a derived DNS rule. That derived rule was the exact trigger for the prior drill's digest-mismatch reject loop. Throughout this drill the provider reported manifest and arm-lease bound every ~5 seconds with **zero `ruleDigestMismatch` events**.
3. **D1a, graceful disarm, 3 cycles.** Disarm via the CLI, confirm the provider revokes its dead-man lease and agent egress opens, then re-arm and confirm the agent is enforced again.
4. **D1b, dead-man fail-open, 3 cycles.** While armed, kill the daemon process (`SIGKILL`) and confirm the provider fails open within its heartbeat window rather than wedging the host.
5. **D2, operator/agent differential, 3 armed cycles.** Probe egress as the wrapped agent and as the operator in the same armed window.

## Results

| Leg | Probe | Result | Cycles |
|---|---|---|---|
| D2 differential | agent to 1.1.1.1 (non-allowlisted IP) | HTTP 000, blocked | 3/3 |
| D2 differential | agent to openrouter.ai (allowlisted hostname rule) | HTTP 200, allowed | 3/3 |
| D2 differential | operator to 1.1.1.1 | HTTP 301, unaffected | 3/3 |
| D1a graceful disarm | disarm, then agent egress; re-arm, then agent egress | opens on disarm (301), enforced on re-arm (000); operator 301 throughout | 3/3 |
| D1b dead-man | kill daemon while armed | fail-open within ~12 seconds; agent and operator both reach the network | 3/3 |
| Digest integrity | provider rule-digest checks across the armed session | zero `ruleDigestMismatch` | full session |

End state was safe: wall disarmed, agent and operator egress both restored, default fortress untouched.

## What this proves

- The macOS Castle Wall enforcement loop is real on hardware: the system extension receives the daemon's policy, enforces it per rule at the network-filter layer, audits it, and the enforcement is surgical (agent contained, operator unaffected).
- The allow lane works, not just the deny lane: an allowlisted hostname rule passed agent traffic while the default-deny posture blocked everything else.
- The safety levers work under repetition: graceful disarm 3/3 and dead-man fail-open 3/3.
- The deployment path is observable: a rebuilt extension demonstrably replaced the running one, with hash evidence on both sides.

## What this does not prove

- **Arm-lease TTL expiry (D1c) is inconclusive, in the safe direction.** The CLI arm path is wedged when invoked from an SSH-executed process on Tahoe, so re-arms in this drill injected a signed arm lease directly to the daemon; the live daemon re-affirms the lease on its heartbeat, so the injected TTL never counts down. The system stayed in the contained state throughout. The real TTL countdown is exercised only through the CLI enable path and needs its own leg once the headless-arm wedge (tracked as W7-1) is fixed.
- **One host, one OS version.** This is a single-machine proof on macOS Tahoe 26.5.1, not a fleet or multi-version claim.
- **Not a performance claim.** No p99 overhead numbers were captured in this drill.

## Evidence retention

Raw captures (pre-state hash capture, armed-window probe transcripts, provider log stream, daemon log) are retained in the maintainer's drill-evidence archive under reference `drill-2026-06-11c`, alongside the full drill report. This document summarizes that evidence for in-repo traceability; the summary numbers above are transcribed from the captured transcripts.
