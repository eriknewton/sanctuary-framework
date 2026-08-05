# Deployment Guide; Running Sanctuary as a Persistent Service

This guide covers running Sanctuary as a long-lived MCP server alongside another agent's MCP server. It is written for people who run servers.

## System Requirements

- Node.js >= 22.0.0
- npm >= 10.0.0

## Installation Options

### npx (dev/testing only)

```bash
npx @sanctuary-framework/mcp-server
```

Always pulls the latest version. Network-dependent on every cold start, bad for systemd restart loops where the process might cycle and hit npm repeatedly.

Failure mode: under a supervisor with `Restart=on-failure`, a registry outage, a proxy that
blocks npm, or a rate-limit response turns every restart into another download attempt. From the
outside this looks like a Sanctuary problem, but the journal shows npm errors and no Sanctuary
output at all, because the server process never got as far as starting. The second symptom is
quieter: `npx` resolves the floating latest version on each cold start, so two restarts minutes
apart can run two different builds of Sanctuary against the same fortress.

### Global install

```bash
npm install -g @sanctuary-framework/mcp-server@0.8.0
```

Faster startup (no network on launch), but version pinning is manual. You must remember to update.

### Local project install (recommended for production)

```bash
mkdir sanctuary && cd sanctuary
npm init -y
npm install @sanctuary-framework/mcp-server@0.8.0 --save-exact
```

Pin an exact version. No network on restart. Update deliberately with `npm update`. This is the recommended approach for persistent services.

## Passphrase Management

Generate a passphrase:

```bash
openssl rand -base64 32
```

Store it in a gitignored env file:

```bash
echo 'SANCTUARY_PASSPHRASE="your-generated-passphrase"' > ~/.config/sanctuary/sanctuary.env
chmod 600 ~/.config/sanctuary/sanctuary.env
```

> **WARNING:** Your Sanctuary passphrase is the only way to decrypt your agent's state. If the passphrase is lost, all encrypted data is unrecoverable by design. Back up the passphrase to a separate secrets manager, encrypted USB, or password vault. Do not store it alongside the encrypted state.

Failure modes at boot, and what each one looks like from the outside:

| Mistake | Symptom | What to do |
|---|---|---|
| Passphrase absent (env file not loaded, variable misspelled) on a fortress that already exists | Process exits **1** within a second, printing `CustodyCredentialMissingError: existing encrypted data found ... Refusing to start`. Under `Restart=on-failure` the unit flaps on the `RestartSec` interval forever and `systemctl status` shows `activating (auto-restart)` | read the journal, not the unit state; fix the variable so the fortress's own credential reaches the process |
| Passphrase present but wrong (rotated, trailing newline, wrong fortress) | Process exits **1** with `CustodyUnlockError: the supplied credential does not unlock this fortress`. The message is deliberately generic and never says which factor failed, so it reads the same for a typo and for pointing at the wrong fortress directory | confirm `SANCTUARY_STORAGE_PATH` first, then the credential; a right passphrase against the wrong fortress produces this identical message |
| Fortress directory created by hand (`mkdir -p ~/.sanctuary`) before anything has provisioned it | The existence check passes, so the server does not report a missing fortress. It proceeds into first-run provisioning against the empty directory and then hits the recovery-key escrow gate below | let `sanctuary init` create the directory; do not pre-create it while laying down config |

The passphrase alone is not the whole custody story. On the very first boot against a brand new
fortress, Sanctuary mints a recovery key, refuses to write it inside the fortress directory, and
refuses to print it to a log or pipe. A service manager gives the process no terminal, so that
first boot fails closed with `BootRecoveryKeyEscrowRequiredError` unless a durable target exists:
either `SANCTUARY_RECOVERY_OUT` pointing at a path outside the fortress, or a passphrase, which
lets the recovery key be escrowed in the OS keyring. From the outside this looks like a service
that will not start on a machine where nothing is wrong yet. Provision the fortress interactively
with `sanctuary init` before you enable the unit and this never fires.

## Parallel MCP Server Configuration

Sanctuary runs alongside your agent's own MCP server. Both appear as separate tool providers in the same session.

### npx variant

```json
{
  "mcpServers": {
    "your-agent-server": {
      "url": "http://localhost:8766/mcp"
    },
    "sanctuary": {
      "command": "npx",
      "args": ["-y", "@sanctuary-framework/mcp-server"],
      "env": {
        "SANCTUARY_PASSPHRASE": "your-passphrase-here"
      }
    }
  }
}
```

### Local install variant (recommended)

```json
{
  "mcpServers": {
    "your-agent-server": {
      "url": "http://localhost:8766/mcp"
    },
    "sanctuary": {
      "command": "node",
      "args": ["./sanctuary/node_modules/.bin/sanctuary-mcp-server"],
      "env": {
        "SANCTUARY_PASSPHRASE": "your-passphrase-here"
      }
    }
  }
}
```

See [`docs/examples/parallel-mcp-config.json`](examples/parallel-mcp-config.json) for a reference config file.

Failure mode: these two blocks put the passphrase literally inside the harness's MCP config, while
the section above puts it in a mode-600 env file. Those are two copies of one credential, and only
the env file is protected. The harness config is usually world-readable, lives in a directory that
gets synced or backed up, and is the file people paste into issue reports.

The copies also drift. The harness spawns its own child process using the `command` and `args`
here and passes exactly this `env` block, so it never reads the env file, and a systemd unit never
reads this JSON. When the two values disagree, whichever path ran first is the one that owns the
fortress, and the other path fails with `CustodyUnlockError` while every configuration file on the
machine looks correct. If you keep both surfaces, treat one of them as the source and re-derive the
other from it, and tighten the permissions on the harness config to match the env file.

## systemd Service Unit

Create `/etc/systemd/user/sanctuary-mcp.service`:

### Using local install (recommended)

```ini
[Unit]
Description=Sanctuary MCP Server
After=network.target

[Service]
Type=simple
EnvironmentFile=%h/.config/sanctuary/sanctuary.env
ExecStart=/usr/bin/node %h/sanctuary/node_modules/.bin/sanctuary-mcp-server
Restart=on-failure
RestartSec=5s
WorkingDirectory=%h

[Install]
WantedBy=default.target
```

### Using npx

```ini
[Unit]
Description=Sanctuary MCP Server
After=network.target

[Service]
Type=simple
EnvironmentFile=%h/.config/sanctuary/sanctuary.env
ExecStart=/usr/bin/npx -y @sanctuary-framework/mcp-server
Restart=on-failure
RestartSec=5s
WorkingDirectory=%h

[Install]
WantedBy=default.target
```

Enable and start:

```bash
systemctl --user daemon-reload
systemctl --user enable sanctuary-mcp
systemctl --user start sanctuary-mcp
```

### What this unit does and does not do

Read this before you trust `systemctl status` on it.

**The MCP server speaks stdio, and only stdio.** `transport: "stdio"` is the default and the HTTP
branch is unimplemented (it prints `HTTP transport not yet implemented. Use stdio.` and exits 1).
A service manager gives the process no client on stdin. Verified behavior on a provisioned
fortress: the process boots, prints `Sanctuary MCP Server v<version> running (stdio)`, reaches
end-of-input immediately, and exits **0** in well under a second. `Restart=on-failure` treats 0 as
success, so the unit settles into `inactive (dead)` with no restart, and the last journal line is
the word "running". From the outside that reads like a healthy service that quietly stopped.

This unit is therefore a supervision and environment shell, not the process your agent talks to.
The harness in the section above spawns its own Sanctuary child and talks to that one. If your
goal is a persistent Sanctuary presence with a UI, run `sanctuary dashboard` under the service
manager instead: it is an HTTP process built to stay alive.

Failure modes in the unit itself, and what each looks like from the outside:

| Mistake | Symptom | What to do |
|---|---|---|
| `EnvironmentFile=` path missing or unreadable by the unit's user | The unit refuses to start and never executes `ExecStart`, so there is no Sanctuary output at all to explain it. The journal reports a failure to load the environment file | check the path and its owner; a file written under `sudo` is root-owned and a `--user` unit cannot read it |
| `EnvironmentFile=-` written with the leading dash | A missing file is silently ignored, the process starts with no credential, and you get the "passphrase absent" boot failure above instead of a clear message about the file | leave the dash off so the missing file is reported as itself |
| Unit installed into `/etc/systemd/system/` instead of the user path | `systemctl --user status sanctuary-mcp` reports the unit is not found while `systemctl status sanctuary-mcp` finds it. When it does run as a system unit, `%h` resolves to `/root`, so it reads `/root/.config/sanctuary/sanctuary.env` and provisions `/root/.sanctuary`. Nothing errors; the agent simply sees an empty fortress owned by another user | keep it in the user path (`/etc/systemd/user/` or `~/.config/systemd/user/`) and always pass `--user` to `systemctl` |
| Lingering not enabled for the user | It works while you are logged in and stops shortly after your last session ends, which over SSH means it dies after you disconnect and looks fine every time you log back in to check | `loginctl enable-linger $USER` |

## Bootstrap and First Run

**The fortress must exist before any of this.** The MCP server refuses to create one implicitly:
if the resolved fortress path is absent it writes a single JSON line with
`"code":"FORTRESS_NOT_FOUND"` to stderr and exits **78**. Under a supervisor with
`Restart=on-failure` that is a restart loop whose only evidence is one JSON line per attempt, and
harnesses commonly surface it as nothing more than "the MCP server failed to start". Run
`sanctuary init` first, interactively, and capture the recovery key it prints. See
[fortress-lifecycle.md](fortress-lifecycle.md).

After installation, run these tools in your first agent session:

1. **`sanctuary_bootstrap`**: Creates an Ed25519 identity, generates a Sovereignty Health Report, and optionally publishes to Verascore. Save the DID it returns.

2. **`sovereignty_audit`**: Runs a four-layer gap analysis and produces a baseline posture score (0–100). Use this to verify everything initialized correctly.

## Principal Policy for Always-On Agents

The default Principal Policy gates `sanctuary_bootstrap` as Tier 1 (requires human approval). For persistent agents with latency constraints, use the `persistent-agent` policy template which auto-allows routine operations and only gates destructive or external-facing actions.

Copy the template to your Sanctuary config:

```bash
cp node_modules/@sanctuary-framework/mcp-server/src/principal-policy/templates/persistent-agent.yaml \
   ~/.sanctuary/principal-policy.yaml
```

Or reference it in the [template directory](../src/principal-policy/templates/persistent-agent.yaml).

**This step weakens the approval gate, and the change is invisible from the outside.** With the
default policy, Tier 1 operations pause and wait for a human; with `persistent-agent`, routine
operations proceed on their own and only destructive or external-facing actions still gate. From
the operator's seat the symptom of this posture is *approval requests that never arrive*: if you
expected to be asked and weren't, check which policy file is active before assuming the gate is
broken. The policy loads once at startup, so the swap takes effect on the next server start, not
immediately, and reverting requires restoring the default template and restarting. Do not use this
template on a fortress whose approval pauses are the point (for example, one holding real
credentials or real reputation state) unless you have deliberately accepted that trade.

## Rollback

Remove from Claude Code:

```bash
claude mcp remove sanctuary
```

If the agent was wrapped:

```bash
npx @sanctuary-framework/mcp-server wrap --unwrap
```

Failure mode: `--unwrap` restores the backup that the most recent wrap took, and a wrap taken over
an already-wrapped config backs up the wrapped contents. If an earlier wrap was interrupted before
it recorded its metadata, the pristine config can no longer be identified, and unwrapping returns
you to a still-wrapped file that looks restored. Sanctuary warns loudly at wrap time when it
detects this state and points at `~/.sanctuary/backup/`, where the timestamped `config-backup-*`
files include the older pristine snapshot. Check that directory before relying on `--unwrap` if you
have wrapped the same config more than once.

Sanctuary's encrypted state remains in `~/.sanctuary/` until manually deleted.

## Audit Log Location

Audit log entries are stored as individually encrypted `.enc` files inside the Cognitive-layer
state store at `~/.sanctuary/state/_audit/`: not a plaintext log directory. You
cannot `cat` or `grep` the audit log directly; use the `audit_export_siem` MCP tool
to decrypt and export entries. The `~/.sanctuary/audit/` path referenced in some
older documentation does not exist on a running deployment.
