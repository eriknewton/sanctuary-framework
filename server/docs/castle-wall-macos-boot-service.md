# Castle Wall macOS boot service (F1, Option C — split credential)

Status: implemented 2026-06-10 (Option C re-spec). **Reboot survival is NOT
yet proven.** The unit-level logic (boot-token custody, safe-mode bring-up
wiring, plist generation, preflight gating, install start-verification,
uninstall confirmation) is tested; the claim "the box reboots while armed and
comes back in safe mode without bricking" can only be proven by an
Erik-present reboot drill on real hardware. Until that drill passes N>=5,
treat F1 as "smoke-level: the unit loads and the process starts," not "done."

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
master key and the full daemon supersedes the safe-mode one. SSH / operator
reachability holds throughout, so an unattended reboot can no longer brick the
box.

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

## What only a real reboot drill can prove (pre-declared drill criteria)

Unit tests cover boot-token custody, safe-mode bring-up wiring, plist
generation, preflight fail-closed gating, install start-verification, and
uninstall confirmation. They cannot prove the on-hardware behavior. The
Erik-present drill (per the drill-acceptance rule, N>=5 boot-reliability reps)
must prove, on the signing/boot host:

1. The safe-mode daemon actually starts at cold/network boot, before login,
   with only the boot token (launchd environment, root context, filesystem
   timing). At least one **network-cold** boot.
2. The box stays reachable: SSH session survives / can be re-established;
   the machine is not deny-all-bricked.
3. The persisted manifest enforces in the pre-daemon window; the safe-mode
   daemon connects within the backoff window and re-delivers the manifest.
4. **Helper signing from the root safe-mode daemon peer-authenticates
   correctly.** (Open verification item: the signer helper's peer-auth was
   designed against the operator-UID daemon; confirm a root peer is accepted,
   or that safe mode degrades cleanly to persisted-manifest enforcement if not.
   Either way the box must not brick.)
5. Full operation engages at first login (master key unlocks; full daemon
   supersedes safe mode; master-key audit log resumes).
6. KeepAlive recovery after a daemon kill while armed.
7. `boot_token_provisioned` + `filter_started` (source `launchd-boot-safe-mode`)
   visible in the boot-audit segment; allow/deny differential still correct
   after the reboot.
