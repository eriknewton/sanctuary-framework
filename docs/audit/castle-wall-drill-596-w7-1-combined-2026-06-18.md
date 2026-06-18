---
title: Castle Wall macOS drill, combined #596 boot-crash + W7-1 initial-arm, 2026-06-18
date: 2026-06-18
author: Erik Newton
status: drill-evidence (hardware results captured by drill thread; coordinator verification PENDING)
severity: capability-claim evidence, host-app boot-crash regression
scope: tests PR #621 (#596 follow-up) and PR #633 (W7-1 RunLoop fix) on combined branch drill/596-w7-1-combined
supersedes_signal_in: docs/audit/castle-wall-macos-fresh-binary-redrill-2026-06-17.md (the #596 RECURS and W7-1 BLOCKER sections)
---

# Castle Wall macOS drill, combined #596 + W7-1, 2026-06-18

Operator: drill thread on the MBA signing host (Erik present for the boot legs, then away). This doc records hardware results for coordinator verification. Until the coordinator independently verifies, every verdict here is provisional and nothing is merged.

## What was tested

One binary built from `drill/596-w7-1-combined` carrying both fixes:

- **#596 follow-up (PR #621, file `ContentView.swift`):** defer the `.onChange(scenePhase)` and `.onChange(extensionState)` `@Published` writes off the synchronous SwiftUI render pass.
- **W7-1 (PR #633, file `HeadlessFilterCLI.swift`):** replace the self-deadlocking `DispatchSemaphore.wait` in `waitFor` with a bounded `RunLoop.current.run(mode:before:)` spin so a main-queue-delivered NE completion handler can fire.

Both fixes compile into the **host-app binary** (`CastleWallHostApp` / `CastleWallMain`), NOT the `CastleWallExtension` sysext. The sysext binary is byte-unaffected by either fix.

## Drilled artifact (proof of replacement)

| Item | Value |
|---|---|
| Branch / source SHA | `drill/596-w7-1-combined` at `a71cd190571f` (off session-start main `3df595ed`; both fix commits present) |
| CFBundleVersion | 856 (`git rev-list --count HEAD`); was 843 on Mini1 |
| Notarization | Accepted, submission `f828b643-27c5-4a46-b57e-99d1d29cd3c5`; stapled + validated; spctl accepted, source Notarized Developer ID |
| Host-app binary SHA-256 (built) | `22b99822f87af86fb260b2503428a55c7e699d0a1e8989f7e1311f7fef09bcde` |
| Host-app binary SHA-256 (Mini1 installed + running) | `22b99822f87af86fb260b2503428a55c7e699d0a1e8989f7e1311f7fef09bcde` (MATCH; pid confirmed running v856) |
| Sysext binary SHA-256 (built, embedded in host app) | `5606f925a9551ec30f772cbf305903ed81f2f0316dfcc456258c42c644a25ec7` |
| Sysext binary SHA-256 (Mini1 activated after deploy) | `5606f925a9551ec30f772cbf305903ed81f2f0316dfcc456258c42c644a25ec7` (MATCH; v843 `e01b3f04...` now terminated, uninstalls on reboot) |
| Drill target host | Mini1 (Agents-Mac-mini), macOS 26.5.1 (25F80), FileVault ON, operator uid 501 |

Proof of replacement PASS for both the host app and the sysext: the running binaries on Mini1 are byte-identical to the freshly built, notarized v856.

## Test A, #596 host-app boot crash, N>=3: FAIL

The fixed v856 host app STILL crashes at boot with the identical pre-#596 signature.

Evidence: two crash reports on Mini1, both build 856, both at ~38 to 39 seconds uptime:

- `~/Library/Logs/DiagnosticReports/CastleWallHostApp-2026-06-18-083637.ips` (boot 2 login)
- `~/Library/Logs/DiagnosticReports/CastleWallHostApp-2026-06-18-084054.ips` (reopen)

Both crash with `EXC_CRASH / SIGABRT`, `abort() called`, identical crashing stack:

```
abort()
AttributeGraph  AG::precondition_failure(...)
AttributeGraph  AG::Graph::value_set(...)
SwiftUI  closure #1 in AppDelegate.applicationDidChangeScreenParameters(_:)
SwiftUI  AppDelegate.applicationDidChangeScreenParameters(_:)
SwiftUI  @objc AppDelegate.applicationWillFinishLaunching(_:)
CoreFoundation  __CFNOTIFICATIONCENTER_IS_CALLING_OUT_TO_AN_OBSERVER__
```

Boot 1 (Apple-menu restart, app reopened at login) was clean, but boots 2 reproduced the crash, so the crash is not eliminated. Test A acceptance is N>=3 consecutive clean boots; this is a FAIL at N=1.

### Root cause: the fix is at the wrong layer

The abort has ZERO app-code frames. It aborts entirely inside SwiftUI's own framework `AppDelegate.applicationDidChangeScreenParameters`, fired during `applicationWillFinishLaunching` (very early launch, before the scene graph is ready), where SwiftUI sets an AttributeGraph value mid-update and trips the precondition. The app uses the pure SwiftUI `App` lifecycle (`CastleWallHostApp: App` with `WindowGroup`, no `NSApplicationDelegateAdaptor`), so SwiftUI installs this internal AppDelegate. The branch fix only deferred `ContentView`'s `.onChange` handlers, which are not even instantiated this early and never appear in the stack. `ContentView.swift` changes cannot fix a crash that lives in SwiftUI's launch-time screen-parameters handling.

Recommendation: do NOT merge PR #621 as a #596 fix. The real fix is at the SwiftUI App-lifecycle level. Design candidates are in `Review/Sanctuary/596_SwiftUI_AppLifecycle_Crash_RealFix_Design_2026-06-18.md`. Re-drill required after the real fix.

## Test B, W7-1 initial arm: PARTIAL POSITIVE SIGNAL, not the acceptance

W7-1 acceptance is: a FRESH first arm against a just-activated provider arms within seconds (no `loadFromPreferences timed out`). That full acceptance was NOT run, because a full arm needs the `~/.sanctuary-drill-0611b` fortress (absent, torn to baseline) plus its passphrase, plus Erik present for boot-cut recovery, and attempting it unattended risked stranding Mini1.

Positive signal captured: with v856 (RunLoop fix) the headless NE round-trip COMPLETED without the `loadFromPreferences` wedge. Running `--headless disable` via LaunchServices returned `{"action":"disable","ok":true,"state":"disabled","build":{"git_sha":"a71cd190571f"}}`, and the `com.apple.networkextension` log showed a clean session teardown ("configuration is now disabled, stopping" through "disconnected, last stop reason Configuration was disabled"). No 30s `loadFromPreferences timed out`.

Caveat: this exercised the DISABLE path against an ALREADY-SETTLED provider, which addresses the H2 (callback-to-parked-main-thread) hypothesis but NOT the H1 (first-arm-against-just-activated-provider registration stall) hypothesis that the W7-1 wedge was originally observed under. So this is evidence the RunLoop fix lets the headless NE completion handler fire, but it is NOT proof that the documented first-arm wedge is cleared. A first-arm drill (fresh sysext activation, Erik present, fortress provisioned) is still required to close W7-1.

## Machine final state (Mini1, left safe)

- Castle Wall content filter DISARMED: NE config `Enabled = 0`, filter session torn down. Egress open: `api.anthropic.com` HTTP 404 (reached) and `1.1.1.1` HTTP 301 (reached), so the filter is enforcing no deny. Boot-cut risk removed.
- Note: during boot the host app's `autoArmProtection()` (once the signer helper was approved via the background-item prompt) had auto-enabled the filter with no daemon present. This is the boot-cut hazard. The drill thread disarmed it via the safe `--headless disable` path before leaving the box unattended.
- Sysext v856 `[activated enabled]` (loaded, not armed); v843 `[terminated waiting to uninstall on reboot]`.
- Host app left down (it crash-loops at launch on this Tahoe build).
- `~/.cw-sudopw` deleted.

## Coordinator verification and claim movement

HALT. Do NOT merge #621, #633, or the combined branch from this thread. Do NOT edit ASSURANCE_MATRIX.md, README, or any public copy. The coordinator independently verifies this evidence (operator verdicts are provisional), then:

- #596: treat as NOT fixed by #621; route the real SwiftUI-lifecycle fix (design memo above) into a fresh build, then re-drill (boot reboots, N>=3).
- W7-1: the RunLoop fix shows a positive headless-completion signal but is not closed; schedule a first-arm drill with Erik present and the fortress provisioned. Do not widen the ASSURANCE_MATRIX W7-1 row on this partial signal.
