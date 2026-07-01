# Castle Wall macOS - arm / verify / disarm WAN-containment (operator runbook)

This is the single followable runbook for turning Castle Wall WAN-containment
ON, verifying it, and turning it OFF on a macOS host. It linearizes a sequence
that otherwise lives scattered across several docs; cross-links to the deeper
references are inline.

Trust bounds for this capability are row 18 ("Egress enforcement: macOS") of
[../../ASSURANCE_MATRIX.md](../../ASSURANCE_MATRIX.md). Do not claim beyond that
row. In particular this is per-uid allow/deny enforcement that survives reboot on
a signed+notarized binary; it is NOT tamper-evident per-flow audit, and the
headless CLI arm path has a known Tahoe wedge (W7-1) noted below.

---

## Read this first: install is a signed-host ceremony, not a CLI verb

**On a machine that has never had Castle Wall installed (for example a fresh
Mini2), you cannot arm WAN-containment with a single CLI command.** The CLI arm
verbs (`enable` / `disable` / `daemon` / `status`) are the *last mile*. They
refuse to fake-arm and depend on a system extension that only a GUI, keychain-
bound, Erik-present ceremony can put in place.

The one-time install ceremony (do this at the console, signed-in, with the
Developer-ID keychain unlocked) is:

1. **Build + notarize + staple** the `Sanctuary-CastleWall.app` (Developer-ID
   signed, hardened runtime, Network Extension entitlements). See the build and
   notarize steps in
   [castle-wall-macos-deploy.md](castle-wall-macos-deploy.md).
2. **Install to `/Applications`** and launch the app once at the console.
3. **Approve the system extension** in
   System Settings > General > Login Items & Extensions > Network Extensions.
4. **On macOS Tahoe, flip the Network Extension toggle ON.** The extension ships
   disabled on Tahoe and needs this one-time console toggle. This is the same
   state the CLI reports as exit code 4 (`SYSEXT_DISABLED`) if you skip it.
5. **Grant the one-time content-filter consent.** The first arm triggers a
   GUI-only macOS consent prompt; click Allow. This is the same state the CLI
   reports as exit code 3 (`NEEDS_APPROVAL`) if you skip it. After this single
   grant, every subsequent arm/disarm works headlessly (SSH-safe).

Steps 3-5 are hard macOS GUI requirements; no CLI can perform them headlessly.
Schedule the install as an Erik-present signed-host ceremony, not as a tomorrow
one-command arm.

The boot-survival service (daemon up at boot in safe mode, so a reboot does not
come up deny-all with no daemon) is documented in
[castle-wall-macos-boot-service.md](castle-wall-macos-boot-service.md). The
arm/disarm design rationale is in
[castle-wall-headless-arm-design.md](castle-wall-headless-arm-design.md).

---

## ARM: the CLI last-mile sequence (app already installed + approved)

Once the app is installed and the sysext is approved + toggled ON and consent is
granted, arming is a short, SSH-safe CLI sequence. Every verb and flag below was
verified against `server/src/cli/castle-wall.ts`.

```bash
# 1. Provision the local pinned keypair (first install only).
sanctuary castle-wall provision-pin
#    Helper-mode / re-key path instead (migrate the trust anchor to the root
#    signer helper once the helper is installed):
# sanctuary castle-wall re-pin

# 2. Install the launchd safe-mode boot service (needs sudo; macOS).
#    Without this, arming would let the NEXT REBOOT come up deny-all with no
#    daemon - so 'enable' refuses unless this exists (or you pass --force).
sudo sanctuary castle-wall install-boot

# 3. Start the enforcement daemon (foreground until Ctrl-C), OR rely on the
#    boot service installed in step 2. 'enable' refuses if no daemon is reachable.
sanctuary castle-wall daemon

# 4. Arm the content filter. You MUST choose a dead-man TTL mode:
#      --no-ttl        durable arming (stays armed until you disarm)
#      --ttl <dur>     drill arming (auto-disarms after the TTL; e.g. --ttl 15m)
sanctuary castle-wall enable --no-ttl
#    or, for a bounded drill window:
# sanctuary castle-wall enable --ttl 15m
```

`enable` fires four honest gates before it will report armed, and refuses (never
fake-arms) if any fail:
- a reachable policy daemon (else deny-all brick risk; `--force` overrides if the
  daemon is supervised out of band),
- a persistent boot service for THIS fortress (else reboot-brick risk; `--force`
  overrides),
- a TTL mode chosen (`--ttl` or `--no-ttl`; exit code 2 if you pass neither),
- the sysext toggled ON (exit code 4 if not) and content-filter consent granted
  (exit code 3 if not).

---

## VERIFY

```bash
sanctuary castle-wall status
```

`status` re-reads the LIVE Network Extension filter state (it does not infer
"enforcing" from config presence) and prints: the pinned-key fingerprint, the
global pin + trust-anchor verdict, the sysext state, `Content filter: enabled`
when the wall is live, the app build identity, and a dead-man lease line. When
the content-filter is disabled the lease line is labeled as an advisory
broadcast, not enforcement, so it cannot be mistaken for "protected".

For a true enforcement check, confirm `Content filter: enabled` in `status`, then
(optionally) run a per-uid allow/deny probe: an agent uid is blocked on a
non-allowlisted destination and reaches an allowlisted one while the operator uid
is unaffected, in the same armed window (this is the row-18 acceptance shape).

---

## DISARM

```bash
sanctuary castle-wall disable
```

`disable` is the unconditional dead-man lever: it disarms the live filter and is
authoritative. It does NOT remove the boot service (use `sudo sanctuary
castle-wall uninstall-boot --yes` for that, and disarm first so a later reboot
does not come up deny-all).

---

## Pre-arm gotchas (read before you trip them)

These are enforced + explained at runtime, but knowing them ahead of time saves a
failed arm:

| Gotcha | Symptom | What to do |
|---|---|---|
| **TTL mode required** | `enable` exits **2** with a usage message | pass `--no-ttl` (durable) or `--ttl <dur>` (drill); never both |
| **One-time content-filter consent (GUI-only)** | `enable` exits **3** (`NEEDS_APPROVAL`) | at the console, launch `Sanctuary-CastleWall.app` once and click Allow on the content-filter prompt |
| **Tahoe sysext toggle (GUI-only)** | `enable` exits **4** (`SYSEXT_DISABLED`) | at the console, System Settings > General > Login Items & Extensions > Network Extensions, switch Castle Wall ON |
| **CWD build-SHA trap** | `enable`/`disable` fail with `deployed app <X> != CLI <Y> - rebuild + redeploy` | the CLI SHA comes from `git rev-parse HEAD` in the CURRENT WORKING DIRECTORY (or `SANCTUARY_CASTLE_BUILD_SHA`), NOT the binary. If you are inside a git worktree whose HEAD differs from the deployed app, run the arm verbs **outside any git repo**, or `export SANCTUARY_CASTLE_BUILD_SHA=<app-sha>` first. This is NOT a real rebuild need. |
| **No reachable daemon** | `enable` refuses (deny-all brick guard) | run `sanctuary castle-wall daemon` or install the boot service; `--force` only if supervised out of band |
| **No boot service for this fortress** | `enable` refuses (reboot-brick guard) | `sudo sanctuary castle-wall install-boot`; `--force` only if boot-survival is supervised out of band |

---

## Known bound: headless CLI arm wedge on Tahoe (W7-1)

Per ASSURANCE_MATRIX row 18, the TTL-expiry leg through the real CLI `enable`
path was still inconclusive on Tahoe at last drill (the headless-arm wedge,
W7-1). Arm has been proven via the GUI toggle + safe-mode boot daemon; the pure
CLI arm path on Tahoe is the leg that still owes a clean drill. Treat a
CLI-`enable` arm on Tahoe as provisional until that drill is captured; the GUI
toggle path is the proven one.
