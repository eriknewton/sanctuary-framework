# Castle Wall macOS Install And Arm Guide

This guide installs Sanctuary's macOS Castle Wall from a clean machine to a verified armed state. It targets Sanctuary `v1.7.2` and the `Sanctuary-CastleWall.app.zip` asset attached to that release.

The npm package installs the cooperative Sanctuary CLI, dashboard, keys, policy gates, and audit trail. The operating-system wall is a separate signed and notarized macOS app with a system extension, a signer helper, and a root boot service.

## Scope

- macOS 13 or newer with an interactive console session. The first System Settings approvals require a GUI login session; SSH cannot complete them.
- Node.js 22 or newer and npm 10 or newer.
- Admin credentials for `sudo`.
- One operator account that owns the fortress, usually your normal macOS account.
- One protected agent macOS account. The protected account must have a real UID at or above the default ceiling of `500`.
- The proven public bound is per-UID allow/deny plus attended reboot survival on one host and one OS version. Unattended reboot survival remains unproven. Linux has no shipped live enforcement path today; Windows is roadmapped.

## 1. Install the Sanctuary CLI and fortress

Install the pinned CLI:

```bash
npm install -g @sanctuary-framework/mcp-server@1.7.2
```

Wrap the harness you already use. For Claude Code:

```bash
sanctuary protect --claude-code
```

Substitute `--openclaw`, `--hermes`, `--cursor`, `--cline`, `--mastra`, or `--wrap <path-to-config>` for another harness.

Back up the passphrase:

```bash
sanctuary export-passphrase
```

Failure mode: this step does not install or arm the macOS wall. It prepares the fortress, cooperative gates, dashboard, audit trail, and harness config.

## 2. Download and verify the Castle Wall app

Download the `v1.7.2` release asset:

```bash
APP_ZIP="$HOME/Downloads/Sanctuary-CastleWall.app.zip"
curl -L -o "$APP_ZIP" \
  "https://github.com/eriknewton/sanctuary-framework/releases/download/v1.7.2/Sanctuary-CastleWall.app.zip"
```

Verify the SHA-256 digest:

```bash
shasum -a 256 "$APP_ZIP"
```

Expected first field:

```text
0c09842936ffb9d2d65badd6e00638675fbb91756d0efa1ac2eb6d2032ffb736
```

The GitHub release asset metadata and the release body publish this digest. The release does not publish a separate `.sha256` sidecar file for the app zip. If your digest differs, stop and discard the download.

## 3. Install and launch the app

Extract the zip and place the app where the CLI auto-discovers it:

```bash
ditto -x -k "$APP_ZIP" "$HOME/Downloads"
sudo ditto "$HOME/Downloads/Sanctuary-CastleWall.app" \
  "/Applications/Sanctuary-CastleWall.app"
open "/Applications/Sanctuary-CastleWall.app"
```

Failure mode: the CLI searches `/Applications/Sanctuary-CastleWall.app` and `~/Applications/Sanctuary-CastleWall.app` by default. If the app stays in another directory, set `SANCTUARY_CASTLE_HOSTAPP` to the app's `Contents/MacOS/CastleWallHostApp` binary and set `SANCTUARY_CASTLE_SIGNER_CLIENT` to the bundled `Contents/MacOS/castle-wall-signer-client` shim.

## 4. Approve the macOS security prompts

Run the shared-directory preflight, then use the app at the console:

```bash
sudo sanctuary castle-wall setup-shared-dir
open "/Applications/Sanctuary-CastleWall.app"
```

Approve every macOS prompt that appears:

- If the app shows "Approve Sanctuary background helper", click "Open Settings", then enable `Sanctuary-CastleWall` under System Settings > General > Login Items & Extensions > Allow in the Background.
- If macOS asks for system extension approval, open System Settings > Privacy & Security and approve the Castle Wall system extension.
- On macOS Tahoe, open System Settings > General > Login Items & Extensions > Network Extensions and switch Castle Wall on.
- If a later arm attempt says content-filter consent is missing, launch `Sanctuary-CastleWall.app` at the console, click Allow on the content-filter prompt, then retry the arm command.

Failure mode: a remote shell cannot complete the first GUI approvals. Use the Mac console, Screen Sharing, or another interactive macOS login session for this step.

## 5. Re-pin to the signer helper

Migrate the enforcement trust anchor to the approved root signer helper:

```bash
sanctuary castle-wall re-pin
```

Check helper readiness:

```bash
SANCTUARY_CASTLE_SIGNER_CLIENT="/Applications/Sanctuary-CastleWall.app/Contents/MacOS/castle-wall-signer-client" \
  sanctuary castle-wall signer-helper status
```

Expected ready output has four passing checks and this final line:

```text
Signer helper: READY (boot-started, reachable, pin-consistent).
```

Failure modes:

- `launchd_job_visible` fails: approve the Background Item in System Settings > General > Login Items & Extensions, then reboot or rerun the check.
- `xpc_reachable` fails: confirm the Background Item approval and the signer-client path.
- `pin_match` fails: rerun `sanctuary castle-wall re-pin`.
- `custody_directory` fails: rerun `sudo sanctuary castle-wall setup-shared-dir`.

## 6. Install the root boot service

The boot service keeps the Castle Wall daemon alive after boot in safe mode. It requires a persistent CLI path and the signer-client shim path:

```bash
SANCTUARY_CLI="$(command -v sanctuary)"
test -n "$SANCTUARY_CLI" && test -x "$SANCTUARY_CLI" && echo "$SANCTUARY_CLI"

sudo sanctuary castle-wall install-boot \
  --binary "$SANCTUARY_CLI" \
  --signer-client "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/castle-wall-signer-client"
```

Expected success output begins like this:

```text
Castle Wall safe-mode boot service installed and running (pid <pid>): /Library/LaunchDaemons/ai.sanctuaryprotocol.castle-wall.daemon.plist
Runs as root at boot in SAFE MODE (boot token only, never the master key); fortress <fortress-path>; KeepAlive on.
```

On first install it also prints:

```text
Boot token minted: /Library/Application Support/Sanctuary/castle-wall-boot-token.bin (root-owned 0600).
```

Failure mode: if the command cannot resolve the CLI path, reinstall with `npm install -g @sanctuary-framework/mcp-server@1.7.2` and confirm `command -v sanctuary` prints an absolute path. If bootstrap is accepted and the service does not stay running, inspect the two paths the command prints: `sudo launchctl print system/ai.sanctuaryprotocol.castle-wall.daemon` and `/var/log/castle-wall-daemon.err.log`.

## 7. Choose the protected agent UID

Pick a dedicated macOS account for the agent, then get its UID:

```bash
id -u <agent-account>
```

Use the printed integer as `<agent-uid>`. With the default ceiling, valid protected agent UIDs are `500` or higher. Root `0`, malformed values, and UIDs below the ceiling are rejected before arming.

Failure mode: the UID is never auto-derived. If you choose the wrong UID, you protect the wrong account. Re-run `id -u <agent-account>` immediately before arming.

## 8. Arm a verified deny-all quarantine

This first arm proves the wall is actually enforcing for the protected UID. It deliberately starts with zero agent egress, so the agent is confined until you promote allow rules.

```bash
sanctuary castle-wall enable \
  --agent-uid=<agent-uid> \
  --ceiling=500 \
  --no-ttl \
  --allow-no-egress
```

Expected success output includes:

```text
Agent origin configured: mode=uid agent_uid=<agent-uid> ceiling=500
Deny-all quarantine smoke passed: uid <agent-uid> could not reach example.com:443 on the direct --noproxy path.
Castle Wall armed: content filter enabled (verified via host-app status, system extension state, and enforcement availability).
```

Use `--ttl 15m` instead of `--no-ttl` for a bounded drill window. TTL values use forms like `30s`, `5m`, or `1h`.

Failure modes:

- `Refusing to arm: no agent-origin descriptor is set for this fortress.` Re-run `enable` with `--agent-uid=<agent-uid> --ceiling=500`.
- `Refusing to arm: this fortress has ZERO agent-matchable allow rules`. Use `--allow-no-egress` for the initial deny-all proof, or promote allow rules first.
- `The one-time macOS content-filter consent has not been granted on this machine.` Launch `Sanctuary-CastleWall.app` at the console, click Allow, then retry.
- `The Castle Wall system extension is installed but toggled OFF.` Open System Settings > General > Login Items & Extensions > Network Extensions and switch Castle Wall on.
- `Castle Wall arm saved by the host app, but enforcement availability is not live.` Treat the wall as unarmed, run `sanctuary castle-wall status`, fix the named availability reason, then re-run `enable`.

## 9. Confirm the wall is armed

Run:

```bash
sanctuary castle-wall status
```

Expected armed lines:

```text
Castle Wall sysext: [activated enabled]
Content filter: enabled
Enforcement availability: live (<reason>; observed=<timestamp>; active_connections=<count>)
```

The `enable` success line is the stronger proof for the arm attempt. `status` is the ongoing diagnostic. If `status` prints `Content filter: disabled`, `Castle Wall sysext: not loaded`, `Castle Wall sysext: [activated disabled]`, or `Enforcement availability: unavailable`, treat the wall as unarmed until the named condition is fixed.

## 10. Move from quarantine to useful allow rules

Turn on observe mode while the quarantine is armed:

```bash
sanctuary castle-wall observe start
```

Run the protected agent under the protected account so denied destinations are recorded. Then review candidates:

```bash
sanctuary castle-wall observe candidates
```

Promote the destinations you approve:

```bash
sanctuary castle-wall observe promote --destination <host:port>
```

Promotion is Tier-1 approved. Approved rules are re-signed and published to the rule source the enforcement daemons read. Follow the command's final instruction: either run `sanctuary castle-wall reload` for a running direct wall, or re-arm if the command says the fortress uses exclusive routing.

## Teardown

Disarm first:

```bash
sanctuary castle-wall disable
```

Expected success output:

```text
Castle Wall disarmed: content filter disabled (verified via host-app status).
```

Then remove the boot service:

```bash
sudo sanctuary castle-wall uninstall-boot --yes --fortress "$HOME/.sanctuary"
```

Expected output begins with:

```text
Castle Wall boot service removed (plist deleted; launchd job booted out or was not loaded).
```

The command also warns that removing the boot service does not disarm the content filter. Disarm with `sanctuary castle-wall disable` before rebooting, or reinstall with `install-boot`.

The shipped CLI has `disable` and `uninstall-boot`. It has no shipped `uninstall` verb that deactivates or removes the system extension. Removing `/Applications/Sanctuary-CastleWall.app` is ordinary macOS app cleanup after disarm and boot-service removal; it is not a substitute for `disable`.

## Restore and recovery

If you restore a fortress from Time Machine, backup, dotfile sync, or a cloned machine, Sanctuary can freeze trust-bearing writes until you acknowledge the restore:

```bash
sanctuary restore-attest --fortress "$HOME/.sanctuary"
```

Enter the fortress passphrase when prompted, or set `SANCTUARY_PASSPHRASE` for noninteractive recovery.

Expected success output:

```text
Attested: custody epoch re-baselined to <epoch>.
Trust-bearing writes are UNFROZEN.
A permanent audit entry (custody_restore_attested) records this restore.
```

If you did not intentionally restore anything, treat the freeze as suspicious and rotate the master before attesting.
