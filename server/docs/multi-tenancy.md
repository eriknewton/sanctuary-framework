# Running Multiple Sanctuary Agents on One Host

Sanctuary v0.10.0 ships first-class multi-tenancy: you can wrap two or more
agents on the same machine — each with its own encrypted state, its own
dashboard, and its own approval webhook — without any code changes and
without risk of cross-agent data leakage.

This document explains how.

---

## Why multi-tenancy matters

A single host often runs more than one autonomous agent: a development
assistant, a research sub-agent, a cron-driven broadcaster. Giving every
agent its own sovereignty layer means:

- **Isolated state** — one agent's credentials, memory, and audit log are
  encrypted under a per-tenant master key. A compromise of agent A cannot
  read agent B's data.
- **Isolated identity** — each agent gets its own Ed25519 keypair and DID.
  Attestations are scoped and portable.
- **Isolated approval surface** — a Tier 1 operation in agent A surfaces on
  agent A's dashboard, never on agent B's.

---

## Environment variables

Every per-tenant knob is surfaced as an environment variable. Set these
before invoking `sanctuary wrap` for each agent.

| Variable | What it controls | Default |
|---|---|---|
| `SANCTUARY_STORAGE_PATH` | Root directory for this agent's encrypted state, audit log, identities, principal policy, passphrase, and backups. | `~/.sanctuary` |
| `SANCTUARY_DASHBOARD_PORT` | Dashboard start port. Auto-falls back up to port +9 if busy. | `3501` |
| `SANCTUARY_DASHBOARD_HOST` | Dashboard bind host. | `127.0.0.1` |
| `SANCTUARY_WEBHOOK_CALLBACK_PORT` | Webhook approval callback listener port. | `3502` |
| `SANCTUARY_WEBHOOK_CALLBACK_HOST` | Webhook callback bind host. | `127.0.0.1` |
| `SANCTUARY_PASSPHRASE` | Explicit passphrase for this agent. If unset, one is generated and stored in Keychain (macOS) or an encrypted fallback file under the storage path. | *unset* |

**Rule of thumb:** the only variable you *must* set for multi-tenancy is
`SANCTUARY_STORAGE_PATH`. Everything else isolates automatically once the
storage path is distinct — dashboard port auto-fallback handles 3501→3510,
and each tenant gets its own passphrase derived from its own Keychain item
or fallback file under its own storage path.

---

## Recommended port ranges

Pick a deterministic slot per agent so you always know which port belongs
to whom. A common pattern for two agents:

| Agent | `SANCTUARY_STORAGE_PATH` | Dashboard | Webhook callback |
|---|---|---|---|
| Agent A (NSA) | `~/.sanctuary/nsa` | `3501` | `3511` |
| Agent B (Standards Tracker) | `~/.sanctuary/standards` | `3502` | `3512` |

Scaling to more agents: leave 3501–3510 for dashboards (auto-fallback
handles up to 10 concurrent wraps on one host) and use 3511–3520 for
webhook callbacks.

---

## Complete per-agent recipe

### Agent A

```bash
export SANCTUARY_STORAGE_PATH="$HOME/.sanctuary/nsa"
export SANCTUARY_DASHBOARD_PORT=3501
export SANCTUARY_WEBHOOK_CALLBACK_PORT=3511
npx @sanctuary-framework/mcp-server wrap --openclaw
```

### Agent B (in a second shell or launchd job)

```bash
export SANCTUARY_STORAGE_PATH="$HOME/.sanctuary/standards"
export SANCTUARY_DASHBOARD_PORT=3502
export SANCTUARY_WEBHOOK_CALLBACK_PORT=3512
npx @sanctuary-framework/mcp-server wrap --claude-code
```

After both wraps, each dashboard runs independently:

- Agent A — http://127.0.0.1:3501
- Agent B — http://127.0.0.1:3502

### Verifying isolation

```bash
# Each agent's state directory is owner-only (0700), files 0600.
ls -ld ~/.sanctuary/nsa ~/.sanctuary/standards

# Each agent has its own identities / audit log / backup dir.
ls ~/.sanctuary/nsa/state/_identities ~/.sanctuary/standards/state/_identities
ls ~/.sanctuary/nsa/backup ~/.sanctuary/standards/backup

# Each agent has its own passphrase (macOS Keychain item or fallback file).
# The Keychain service name for a non-default storage path is derived from a
# stable hash of the path, e.g. sanctuary-passphrase-<12-hex-chars>.
security find-generic-password -a sanctuary -s sanctuary-passphrase-<suffix> -w
```

---

## How per-tenant passphrases work

- **macOS default path** (`~/.sanctuary`) continues to use the legacy
  Keychain service name `sanctuary-passphrase`, so pre-v0.10.0 wraps keep
  reading their saved passphrase without migration.
- **Any non-default `SANCTUARY_STORAGE_PATH`** namespaces the Keychain
  service to `sanctuary-passphrase-<12-hex-chars>`, where the suffix is a
  stable SHA-256 hash of the storage path. Two agents on different paths
  get two different Keychain items.
- **Linux / Windows / Keychain-unavailable** falls back to
  `<storage_path>/passphrase.enc`, encrypted with a key derived from
  hostname + user id + home path. The file is 0600; the parent directory
  is 0700. Two agents on different storage paths get two different files.

The encryption key each agent uses for its state, audit log, identities,
and reputation is derived via Argon2id from its own passphrase, then split
per namespace via HKDF-SHA256 domain separation. Agent A cannot decrypt
Agent B's data even if an attacker gains access to B's storage path —
they would still need B's passphrase.

---

## What gets written under `SANCTUARY_STORAGE_PATH`

Every on-disk artifact lives under the agent's storage path:

```
$SANCTUARY_STORAGE_PATH/
├── cocoon-profile.json           # sovereignty profile snapshot (0600)
├── principal-policy.yaml         # runtime-frozen policy (0600)
├── passphrase.enc                # fallback passphrase file if Keychain unavailable
├── sanctuary.json                # config overrides (optional)
├── state/
│   ├── _identities/*.enc         # Ed25519 keypairs + DIDs
│   ├── _audit/*.enc              # encrypted audit log entries
│   ├── _reputation/*.enc         # signed attestations
│   ├── _context_gate_policies/   # L2 context-gating policies
│   └── <user-namespace>/*.enc    # state_write values
└── backup/
    ├── cocoon-meta.json          # unwrap pointer
    └── config-backup-*.json      # original agent config
```

Nothing lives outside this directory for a wrapped agent except the
Keychain item (macOS only), which is namespaced to the path.

---

## Common gotchas

- **Sharing `SANCTUARY_STORAGE_PATH` across two agents is unsupported.**
  Concurrent writes from two Sanctuary instances to the same storage root
  will race on audit log rotation and version metadata. Always set a
  distinct path per agent.
- **Only 10 concurrent dashboards per host.** Auto-fallback covers
  3501–3510; beyond that, set `SANCTUARY_DASHBOARD_PORT` explicitly to
  numbers outside that range.
- **Webhook callback ports do not auto-fallback.** Set
  `SANCTUARY_WEBHOOK_CALLBACK_PORT` explicitly for every agent; a port
  collision here fails the `.start()` call rather than silently moving on.
- **macOS Keychain migration.** If you previously wrapped an agent at the
  default `~/.sanctuary` and then move it to a custom path, the new path
  will derive a new Keychain service name and Sanctuary will treat it as a
  fresh install. Export the passphrase first via `sanctuary
  export-passphrase`, then pass it to the new wrap via
  `SANCTUARY_PASSPHRASE=<value> sanctuary wrap …` so your existing
  encrypted state remains readable.

---

## launchd template (macOS, two agents)

Place this at `~/Library/LaunchAgents/com.sanctuary.agent-a.plist` and
duplicate for agent B with updated values.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>com.sanctuary.agent-a</string>
    <key>ProgramArguments</key>
    <array>
      <string>/usr/local/bin/npx</string>
      <string>@sanctuary-framework/mcp-server</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
      <key>SANCTUARY_STORAGE_PATH</key>
      <string>/Users/you/.sanctuary/nsa</string>
      <key>SANCTUARY_DASHBOARD_PORT</key>
      <string>3501</string>
      <key>SANCTUARY_WEBHOOK_CALLBACK_PORT</key>
      <string>3511</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
  </dict>
</plist>
```

Load with `launchctl load ~/Library/LaunchAgents/com.sanctuary.agent-a.plist`.

---

## Verification tests

The multi-tenancy guarantees above are covered end-to-end by
`server/test/integration/multi-instance-isolation.test.ts`, which spawns
two parallel Sanctuary instances with distinct storage paths and asserts
no cross-contamination of identities, state, or audit logs. Run it with:

```bash
cd server && npm test -- --run test/integration/multi-instance-isolation.test.ts
```
