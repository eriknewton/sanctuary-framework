# Castle Wall macOS full-scope re-drill (signed v876) - 2026-06-20

**Status:** done. Erik-present, Mini1, coordinator-orchestrated with drill-acceptance
applied (the coordinator ran the operator side directly and independently verified the
captured evidence; Erik ran the agent side at the console, with raw `curl` connection
failures shown).

This record exists to satisfy the thesis-gate rule: the macOS Castle Wall enforcement
claim traces to drill evidence on a freshly signed binary, not to a release-tag git
commit. It is the freshest evidence behind the "Egress enforcement: macOS (Castle Wall
Phase 1)" row in [`ASSURANCE_MATRIX.md`](../../ASSURANCE_MATRIX.md). It does not widen the
proven claim; it re-grounds it on a binary built one commit behind `main`.

## The result - thesis-gate enforcement re-proven on a freshly signed build

A fresh Dev-ID-signed + notarized build **v876** (git `75a48c5794b5`, which includes the
#653 native posture-board embed and the #596 async-init crash fix) was deployed to Mini1
(system extension v858 -> v876, activated + enabled, notarized/stapled, `spctl` "Notarized
Developer ID"). The wall was armed against a fresh default fortress
(`fortress-89f3be3fba10e102`), enforced by the safe-mode boot daemon (agent-deny-by-default;
request signing via the root helper / global pin `c3f22755`).

Clean per-uid allow/deny demonstration to the same destination (`https://www.apple.com`),
deterministic across three trials each:

| uid | role | result |
|-----|------|--------|
| 501 (agentmac) | operator | **3/3 ALLOWED** (HTTP 200) |
| 502 (sanctuary-agent) | agent | **3/3 BLOCKED** (`curl (7) Couldn't connect to server`, port 443) |

This is the macOS enforcement re-prove: capability traced to drill evidence on a
freshly signed binary. The drilled tree `75a48c5794b5` is the #658 merge commit - one
commit behind `main` at the time of the drill (`2c5e3e86`, #659, which is
a process-liveness/observability change per its commit message, not itself re-drilled). This materially tightens
the earlier "the proof attaches to the drilled tree `053093963dbf`, not current
`origin/main`" bound from the 2026-06-16 re-drill.

## Also confirmed

- **#653 unarmed-badge honesty (signed build):** with the wall not enforcing, the app
  badge read amber / "unknown" and agents read "not protected" - no fake green.
- **F1 boot service installed + certified:** `install-boot` loaded the LaunchDaemon
  (`/Library/LaunchDaemons/ai.sanctuaryprotocol.castle-wall.daemon.plist`), safe-mode
  daemon up with KeepAlive. **Boot-survival itself was NOT re-closed in this window** (no
  reboot drill was run on 2026-06-20); the boot-survival evidence remains the 2026-06-16
  5-of-5 real-reboot drill.
- **#659 broker daemon liveness** (process-liveness heartbeat) converged on its
  independent multi-angle gate and merged.

## Honest bounds (must NOT be claimed beyond)

- **Armed-badge reads "unknown" under safe-mode enforcement.** While the wall is enforced
  by the safe-mode boot daemon, the dashboard badge honestly UNDER-claims ("unknown",
  never a fake green): the badge reads enforcement evidence from the master-keyed MAIN
  audit, while the safe-mode boot daemon writes verdicts to a separate boot-audit. Showing
  "armed" requires the FULL daemon (master key, main audit), which does not auto-supersede
  the root boot daemon. This is why a green/"armed" badge was not captured this window.
- This is still **NOT "audited per-rule per-flow"** and **NOT "tamper-evident per-flow
  audit"** (the unforgeable producer-signed per-flow audit remains the real C4 gap).
- **One host, one OS** (the Mini1 Tahoe host); no second machine or OS version; no p99
  overhead capture.
- **W7-1 first-arm still PARTIAL:** the headless `enable`/`disable` path remains wedged on
  Tahoe's `NEFilterManager.loadFromPreferences`; the working arm path is the GUI toggle
  (System Settings -> VPN & Filters). The TTL-expiry leg through the real CLI enable path
  remains inconclusive.
- Boot-survival, federation two-machine capture, the armed-badge full-daemon handoff, and
  the off-machine-pin leg are all deferred to a focused follow-up window (Erik-present,
  Mini1).

## Finding carried forward - systemic fortress key-loss

The real Mini1 default fortress was found ORPHANED at the start of the window (neither the
keychain/file passphrase nor the on-disk `recovery-key.txt` unlocked the master, which had
been rotated after the recovery key was minted; encrypted state unrecoverable with the
credentials on hand). It failed CLOSED correctly and was torn down (preserved aside), with
a fresh fortress provisioned and its credentials preserved off-host. This is a recurring
structural gap, not a one-off; the durable fix is tracked separately (recovery-key
preservation: confirm-captured-off-host before a fortress is usable; refuse master-rotation
unless the new credential is confirmed-captured first).
