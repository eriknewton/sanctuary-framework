---
title: Castle Wall macOS boot-survival re-drill, 2026-06-22 (F1 close, N=5 real reboots, signed v876)
date: 2026-06-22
author: Erik Newton
status: drill-evidence
severity: capability-claim evidence, thesis-gate
closes: F1 boot-survival reboot leg (deferred from the 2026-06-20 full-scope drill)
build: signed+notarized v876 (git 75a48c5794b5)
supersedes_deferral: docs/audit/castle-wall-macos-fullscope-redrill-2026-06-20.md (boot-survival reboot deferred)
---

# Castle Wall macOS boot-survival re-drill, 2026-06-22

**Purpose.** This drill closes the open F1 boot-survival reboot leg that was deferred from the
2026-06-20 full-scope re-drill. The 2026-06-20 window installed and certified the F1
LaunchDaemon boot service on signed+notarized v876 but did not perform the real-reboot cycles.
This drill runs the five consecutive real-reboot acceptance criterion on that same build.

Coordinator-orchestrated over SSH (independent verification of per-uid egress on every cycle);
Erik at the Mini1 console (FileVault unlock + reboots + GUI filter toggle).

## Result - F1 CLOSED: per-uid enforcement survives reboot, 5/5 deterministic

Build: signed+notarized v876 (git `75a48c5794b5`), sysext `[activated enabled]`, safe-mode
boot daemon installed as a LaunchDaemon (`RunAtLoad` + `KeepAlive`). Same destination
(`https://www.apple.com`) every probe. macOS Tahoe 26.5.1. System Application Firewall OFF
(confirms the agent block is the NE content filter, not ALF).

| cycle | uptime at first probe | sysext | boot daemon | operator uid 501 | agent uid 502 |
|-------|----------------------|--------|-------------|------------------|---------------|
| 1 | 59s | activated enabled | auto (pid 533) | 3/3 ALLOW (HTTP 200) | 3/3 BLOCK (curl(7) port 443, ~10ms) |
| 2 | 60s | activated enabled | auto (pid 556) | 3/3 ALLOW | 3/3 BLOCK (14-22ms) |
| 3 | 60s | activated enabled | auto (pid 559) | 3/3 ALLOW | 3/3 BLOCK (11-21ms) |
| 4 | 45s | activated enabled | auto (pid 554) | 3/3 ALLOW | 3/3 BLOCK (13-14ms) |
| 5 | 60s | activated enabled | auto (pid 530) | 3/3 ALLOW | 3/3 BLOCK (13-22ms) |

Every cycle: the box stayed reachable (SSH + operator egress up), the safe-mode boot daemon
auto-started, the sysext stayed activated/enabled, and per-uid enforcement was live within
approximately 45-60 seconds of boot. Agent block = clean TCP port-443 connection refusal
(`curl (7)`). No boot-cut on any cycle.

### Control

The first 2026-06-22 reboot was run with the NE content filter toggled OFF. That cycle showed
no enforcement (agent allowed), confirming the NE content-filter toggle is the gating control
and that filter state (on or off) persists across reboot.

## Platform and build

| Item | Value |
|------|-------|
| Host | Mini1 (Agents-Mac-mini), macOS Tahoe 26.5.1 |
| Build | signed+notarized v876 (`CFBundleVersion` 876), sysext v858 then v876 (`[activated enabled]`) |
| Git commit | `75a48c5794b5` |
| System Application Firewall | OFF (enforcement is the NE content filter, not ALF) |
| Boot daemon type | LaunchDaemon, `RunAtLoad` + `KeepAlive`, safe-mode flag |
| Global pin | `c3f22755` |
| Roles | Coordinator orchestrated over SSH; Erik at Mini1 console for FileVault unlock and reboots |

## Per-criterion verdict

- **A1, boot-survival x5 real reboots: PASS.** Every cycle the safe-mode boot daemon came up
  automatically (seen as auto-started with a fresh PID each reboot), the sysext stayed
  `activated enabled`, and per-uid enforcement was live before the first probe completed.
- **Per-uid allow/deny differential: clean.** Operator uid 501 reached the target destination
  (HTTP 200, 3/3 per cycle); agent uid 502 received a clean TCP port-443 refusal (`curl (7)`,
  3/3 per cycle). Not a blanket block - the operator was never cut.
- **Box reachable throughout: PASS.** SSH session alive and operator egress up on every cycle.
- **No boot-cut: PASS.** No cycle resulted in a deny-all or bricked state.
- **Control (filter OFF): PASS.** A reboot with the filter toggled off showed no enforcement,
  proving the NE content filter is the gating mechanism.

## What this proves

- PROVEN: with the Castle Wall NE content filter enabled, the safe-mode boot daemon's per-uid
  enforcement (operator-allow baseline + agent-deny, via the persisted signed manifest)
  survives a full reboot + FileVault login, deterministically 5 of 5. This is the production
  boot shape (RunAtLoad daemon + sticky NE filter + persisted signed manifest).

## What this does NOT cover (never-overclaim bounds)

- **GUI host-app launch verification.** This drill tested the daemon + per-uid enforcement only.
  Hardware boot-verification of the GUI host-app launch and the `#596` async-init crash fix
  (carried in v876) was not the subject of this drill.
- **Arm-lease TTL-expiry leg (W7-1).** Headless CLI arm still wedges on Tahoe
  (`loadFromPreferences`); this leg is still owed.
- **Second macOS host or OS version.** This is a single-machine proof on Tahoe 26.5.1.
- **p99 overhead.** No overhead numbers were captured.

## Relation to prior drills

| Drill | Date | Build | Boot-survival result |
|-------|------|-------|---------------------|
| 2026-06-11 allow/deny drill | 2026-06-11 | v716 | Not a boot-survival drill |
| 2026-06-14 boot-survival drill (F1 first pass) | 2026-06-15 | v774 (`8c8efe68`) | A1 5/5 PASS |
| 2026-06-16 fresh-binary re-drill | 2026-06-16 | v807 (`053093963dbf`) | A1 5/5 PASS |
| 2026-06-20 full-scope re-drill | 2026-06-20 | v876 (`75a48c5794b5`) | Boot daemon installed; reboot leg deferred |
| **2026-06-22 boot-survival re-drill (this doc)** | **2026-06-22** | **v876 (`75a48c5794b5`)** | **5/5 PASS - F1 closed** |

## Evidence retention

Raw SSH transcripts (per-cycle reboot timing, egress probe outputs, daemon log excerpts) are
retained in the maintainer's drill-evidence archive under the 2026-06-22 Mini1 drill reference.
This document summarizes that evidence for in-repo traceability.
