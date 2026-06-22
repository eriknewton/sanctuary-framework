# Castle Wall macOS boot service (F1, Option C — split credential)

Status: implemented 2026-06-10 (Option C re-spec); **reboot survival drill-PROVEN
2026-06-15** (5/5 reboot reps PASS, Erik present at the Mini1 console). The
claim "the box reboots while armed and comes back in safe mode without bricking"
is now backed by on-hardware evidence, not just the unit-level logic
(boot-token custody, safe-mode bring-up wiring, plist generation, preflight
gating, install start-verification, uninstall confirmation). The in-repo
evidence is
[`docs/audit/castle-wall-macos-boot-survival-drill-2026-06-14.md`](../../docs/audit/castle-wall-macos-boot-survival-drill-2026-06-14.md):
the safe-mode boot daemon came up before login on the boot token alone, the box
stayed reachable while armed, and the persisted manifest kept enforcing, across
five reboots on macOS Tahoe 26.5.1 (signed build v774, git_sha `8c8efe68`).

Two honest bounds on that proof:

- **Rebase versus fresh binary.** The reboot evidence was captured on the v774
  binary built from the drilled source `8c8efe68`. That source was rebased onto
  main and merged as #450 (`7732f4d5`); the rebase was verified
  behavior-preserving (codex-clean, frozen-surface guard, and the core boot
  files byte-identical between `8c8efe68` and `7732f4d5`). A fresh signed build
  from main's exact tree was not independently reboot-drilled, so main's exact
  binary is treated as behavior-equivalent by inference, not by a second drill.
- **Non-blocking residual.** A socket-chown by-name TOCTOU residual and a
  real-plist-parse follow-on are tracked in issue #567. They were ruled
  non-blocking: the severe symlink-redirect vector is closed, the agent runs
  under a separate uid that cannot write the operator's `0700` fortress dir, and
  the GUI VPN and Filters toggle remains the ultimate dead-man lever.

A mid-drill daemon-start bug (a stale active-config plus PID reuse refused a
clean start) was caught on an earlier candidate and fixed in `8c8efe68`: an
active-config collision now requires a live listener, not a bare PID. The box
was left in a safe state after the drill (filter disarmed, real `~/.sanctuary`
untouched, boot service left installed and harmless with the filter off).

## The brick condition this closes

Castle Wall's macOS content filter denies by default once armed. The fortress
daemon (`sanctuary castle-wall daemon`) delivers signed policy to the system
extension and answers operator approvals. Before F1, the daemon was not a
boot service: after a reboot with the filter armed, the system re-engages the
filter but nothing restarts the daemon. The box comes up deny-by-default with
no policy delivery and no approval path. SSH is locked out. This forced
"never reboot while armed" discipline (verified on Mini1, 2026-06-09: no
LaunchDaemon plist existed).

## Two credentials, never one (the heart of Option C)

F1 needs the daemon to start **unattended, at cold boot, before any login**.
That requirement collides head-on with hardware-bound custody on macOS:

- A boot credential a daemon can use **before login** must be protected by a
  **software key on disk** (root-extractable). The Secure Enclave cannot help
  a pre-login daemon at all: SE operations require a logged-in user session
  and the data-protection keychain, neither of which exists before login.
  This is structural macOS behavior, not a missing entitlement. Full evidence:
  [`F1_SecureEnclave_Feasibility_2026-06-10.md`](../../../Review/Sanctuary/F1_SecureEnclave_Feasibility_2026-06-10.md).

The held earlier build (#450) bridged that gap by copying the **whole fortress
passphrase** into a machine-key-encrypted file the boot daemon could read.
That was a real custody downgrade (an offline / disk-snapshot attack surface
on the master secret), and the 2026-06-10 decision rejected it.

Option C splits the single secret into two, so the boot context never holds
the one that matters:

| Credential | What it is | Custody | Where it lives | What it can do |
|---|---|---|---|---|
| **Boot token** | A random 32-byte value, per machine. NOT the passphrase, NOT the master key. | Software-protected: root-only `0600`, on the FileVault-encrypted volume. Not extractable from a powered-off / snapshot disk while FileVault is on; extractable by root or an unlocked-volume snapshot. | `/Library/Application Support/Sanctuary/castle-wall-boot-token.bin` | Bring the daemon up in **safe mode**: enforce the persisted signed manifest, deny agents, keep SSH up, write a boot-token-keyed audit segment. It **cannot** decrypt fortress state, forge policy (signing stays with the pinned key it never holds), or unlock full operation. |
| **Operational secret** | The high-value fortress master key. | Login Keychain today; Secure-Enclave binding is host-app follow-on work (see "What this PR does and does not deliver"). | Login Keychain / (future) data-protection keychain | Full operation: approvals that touch fortress state, the master-key audit log, local signing. **Never present in the pre-login boot context.** |

Honest labeling rule for this feature: every doc / threat-model line must say
which credential it means. The boot token is **software-protected**; the
operational secret is the one with the strong custody story, and it is
**absent before login**.

## Safe mode: what the boot daemon does and does not do

The launchd unit runs `sanctuary castle-wall daemon --safe-mode --launchd`.
Safe mode differs from the full daemon in exactly three ways:

1. **No passphrase / master key.** It reads the boot token (fail-closed on
   absence or any custody violation — wrong length, group/other-readable mode),
   derives a safe-mode audit key from it, and records its own boot-time
   lifecycle in a dedicated `boot-audit` segment. The fortress passphrase is
   never touched.
2. **Helper signing only.** Manifest delivery routes through the root signer
   helper (A2/B2) — no private key in this process. Local signing is refused
   in safe mode because it would need the master key.
3. **Audit provenance `launchd-boot-safe-mode`**, so safe-mode bring-up is
   distinguishable from a full / interactive bring-up in the audit stream.

The wall still enforces while in safe mode: the system extension recovers and
verifies the persisted last-valid signed manifest against the pinned **public**
key (no secret), and absent a manifest classifies every flow `.agent` and
denies. Full operation (approvals that touch fortress state, the master-key
audit log) resumes at **first login**, when the operator session unlocks the
master key and starts the full daemon. There is **no automatic supersede** of
the root safe-mode boot daemon by the operator full daemon (honestly de-scoped:
an unprivileged operator daemon cannot stand down a root launchd KeepAlive
unit). The operator stands the boot daemon down explicitly (`sudo launchctl
bootout system/ai.sanctuaryprotocol.castle-wall.daemon`) when they want the full
daemon to take over the socket; the box stays protected in safe mode meanwhile.
SSH / operator reachability holds throughout, so an unattended reboot can no
longer brick the box.

### Privilege model (changed from #450, and why it is sound)

The safe-mode boot service runs in the **system (root) context** — there is no
`UserName` key in the plist. This is a deliberate change from #450's operator
daemon, and it is sound *because of* the split credential:

- The boot daemon holds only the low-value boot token, so root context never
  exposes the secret that matters.
- Root is the only context that can read a root-only `0600` token at boot
  (and the file-based System keychain, the other boot-available store).
- Full-operation signing still routes through the root signer helper; no
  private key reaches this process.
- The safe-mode socket's operator-reachability assumes the confined agent runs
  under a separate uid from the operator; the operator-owned `0o700` fortress
  dir excludes the agent from the socket dir. A same-uid agent is an unsupported
  config (it also breaks per-uid enforcement).

## Operator verbs

| Verb | Runs as | What it does |
|------|---------|--------------|
| `sudo sanctuary castle-wall provision-boot-token` | root | Mints the boot token (root-owned `0600`) in the system custody dir. Idempotent; `--rotate` replaces an existing token. Records `boot_token_provisioned` in the boot-audit segment. `install-boot` auto-provisions it, so this is only needed for explicit rotation. |
| `sudo sanctuary castle-wall install-boot` | root | Auto-provisions the boot token if absent, installs `/Library/LaunchDaemons/ai.sanctuaryprotocol.castle-wall.daemon.plist` (safe-mode, root), bootstraps it, and **verifies a live PID** before reporting success. Idempotent. Refuses (fail-closed) unless the trust anchor (global pin) and signer shim are present. |
| `sudo sanctuary castle-wall uninstall-boot --yes` | root | Boots the job out and removes the plist. **Requires `--yes`** (removing it re-arms the brick). Does NOT disarm the content filter. |

## Install path

```bash
# One command, run as root. install-boot auto-mints the boot token and
# verifies the daemon actually starts before reporting success.
sudo sanctuary castle-wall install-boot \
  --binary /opt/homebrew/bin/sanctuary \
  --signer-client "/Applications/Castle Wall.app/Contents/MacOS/castle-wall-signer-client"

# Verify:
sudo launchctl print system/ai.sanctuaryprotocol.castle-wall.daemon   # expect a live pid
```

`install-boot` resolves the operator account from `SUDO_USER` (override with
`--user`) and the fortress from the operator's home (override with
`--fortress`) so the root daemon reads the right `SANCTUARY_STORAGE_PATH` and
the logs are chowned operator-readable.

## Uninstall / disarm paths

- `sudo sanctuary castle-wall uninstall-boot --yes` removes the boot service.
  The `--yes` is mandatory: **if the filter is armed, the next reboot then
  comes up deny-by-default with no daemon again.** Disarm with
  `sanctuary castle-wall disable` before rebooting after an uninstall.
- Headless disarm is the shipped `sanctuary castle-wall disable` (PR #448), an
  unconditional dead-man lever. The boot service neither arms nor disarms the
  filter; it only brings the daemon up.
- Recovery of last resort on a bricked box stays what it was: local console
  login, then `sanctuary castle-wall disable` (or the Castle Wall app's
  Disable).

## Boot ordering: what is guaranteed and what is not

launchd cannot order a LaunchDaemon strictly before the NE content filter
engages. sysextd manages the filter's lifecycle independently; there is no
`Before=`-style dependency from a LaunchDaemon onto a system extension.
Strict happens-before (policy delivered BEFORE the filter passes its first
verdict) is therefore **not achievable with launchd alone**, and this build
does not pretend otherwise.

It does not need to be, because the provider already fails **safe = closed**
in the pre-daemon window, per the existing design (no new fail mode was
invented for F1):

1. At extension start, the provider bootstraps and the dispatcher first
   recovers the **persisted last-valid signed manifest** from disk,
   signature-verified against the pinned key, before any IPC. Last-known
   policy is enforced immediately.
2. If there is no recoverable manifest (or no pinned key), the engine has
   zero rules and no agent-origin descriptor: every flow classifies `.agent`
   and denies. Machine-wide default-deny.
3. The agent-origin descriptor is never relaxed on IPC loss; the last
   delivered descriptor is retained.

So the residual pre-daemon window (seconds) is: enforce last-known policy,
deny everything else, approvals queue unanswerable. F1's contribution is
**liveness**: the safe-mode daemon comes up at boot, re-delivers the current
manifest over IPC via the helper, and keeps the box reachable. `KeepAlive`
restarts the daemon if it crashes.

## Audit events

- Safe-mode boot-time policy delivery is audited by the daemon itself with
  source `launchd-boot-safe-mode` on `filter_started` / `filter_stopped`,
  written to the **boot-audit segment** (keyed by the boot token, since the
  master-key audit log is unreadable pre-login by design).
- `boot_token_provisioned` records the boot-token mint/rotation in the same
  boot-audit segment.
- The boot-audit segment is encrypted under the boot-token-derived key, so it
  is a **separate** stream from the master-key audit log. The operator reads it
  with the boot-token key; full-operation audit events (post-login) stay in the
  master-key log as before.

Drill-observation caveat (honest): this describes the designed and unit-covered
audit path. In the 2026-06-15 drill the safe-mode boot-audit segment was
observed **empty** on hardware, and per-flow allow/deny decisions are NOT
recorded to any rule-attributed audit log (the C4 gap). So treat the boot-audit
segment writes above as designed behavior, not as an on-hardware-proven audit
capability; see the
[drill evidence doc](../../docs/audit/castle-wall-macos-boot-survival-drill-2026-06-14.md)
for what the drill did and did not establish.

## What this PR does and does not deliver

- **Delivers:** the boot path no longer holds the master key. The boot token
  is a distinct, low-value, software-protected credential; the fortress
  passphrase / master key is never read in the pre-login boot context. That is
  the testable half of Option C and is unit-covered here.
- **Does not deliver (host-app follow-on):** true Secure-Enclave binding of the
  *operational* secret. Persisting SE keys requires the `keychain-access-groups`
  restricted entitlement = a registered App ID + Developer ID provisioning
  profile + app-style bundle wrapping (see the feasibility doc). The host app
  is already a signed bundle, so that work belongs there; this PR leaves the
  operational secret in the login Keychain and documents the trajectory rather
  than claiming SE custody it does not yet have.

## Pre-declared drill criteria and what the 2026-06-15 drill proved

Unit tests cover boot-token custody, safe-mode bring-up wiring, plist
generation, preflight fail-closed gating, install start-verification, and
uninstall confirmation; they cannot prove the on-hardware behavior. The
Erik-present drill (per the drill-acceptance rule, N>=5 boot-reliability reps)
ran on 2026-06-15. The per-criterion verdicts are below, exactly as marked: the
core boot-survival criteria (1, 2, 3) passed N=5; some criteria are IMPLICIT or
PENDING a targeted sub-test, and the per-flow audit half of criterion 7 was NOT
met (the C4 gap). Full evidence:
[`docs/audit/castle-wall-macos-boot-survival-drill-2026-06-14.md`](../../docs/audit/castle-wall-macos-boot-survival-drill-2026-06-14.md).

1. The safe-mode daemon actually starts at boot, before login, with only the
   boot token (launchd environment, root context). **PROVEN x5.**
2. The box stays reachable; the machine is not deny-all-bricked. **PROVEN x5.**
3. The persisted manifest enforces in the pre-daemon window; the safe-mode
   daemon connects and re-delivers the manifest. **PROVEN** (armed and reachable
   each reboot).
4. **Helper signing from the root safe-mode daemon peer-authenticates
   correctly.** **IMPLICIT** (the daemon came up in helper-signing mode and the
   manifest was delivered each reboot); a targeted root-peer-auth sub-test is
   still pending. Either way the box did not brick.
5. Full operation engages at first login (master key unlocks). **DEMONSTRATED**
   (a FileVault-passthrough login left the safe-mode daemon persisting without
   bricking). Note: there is no automatic supersede of the root boot daemon by
   the operator full daemon (honestly de-scoped, as documented in the safe-mode
   section above);
   the box stays protected in safe mode meanwhile.
6. KeepAlive recovery after a daemon kill while armed. **PENDING targeted
   sub-test** (unit-covered; not exercised on hardware in this run).
7. Allow/deny differential correct in the armed window, and the boot-audit
   segment carries the safe-mode lifecycle. The **per-uid allow/deny
   differential PASSED (N=3)**. The **audit half was NOT met**: in this drill
   the safe-mode boot-audit segment was empty, and there is no rule-attributed
   per-flow audit trail in this configuration (the **C4 gap**). So this work is
   "enforces a signed policy with a clean per-uid allow/deny demo," **not**
   "audited per-rule per-flow." The producer-signed per-flow audit trail that
   would close C4 is an unbuilt future build. See the drill evidence doc for
   detail.
