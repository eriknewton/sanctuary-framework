# BUILD REPORT: CLI Wave 1.5 Independent Verbs

Branch: `v1.x-cli-wave1_5-independent-verbs-2026-06-09`

## Behavior

### `sanctuary doctor`

Read-only local diagnostic. Checks state directory existence, permissions, and
writability; encrypted identity presence with fingerprint-only reporting when a
key is available; principal-policy presence and parse status; audit-chain
integrity via the existing export plus verifier path; package, Node.js, and npm
versions; and Castle Wall system-extension status on macOS. `--json` emits a
machine-readable report. Exit code is non-zero when any check is `FAIL`.

Secret handling: output never includes private-key fields, raw policy rules,
passphrases, recovery keys, or encrypted private-key material.

### `sanctuary completion <bash|zsh|fish>`

Pure stdout generator for shell completion. The top-level subcommand list is
stored in `server/src/cli/subcommands.ts` and imported by the completion
command, avoiding a stale hardcoded list.

### `sanctuary audit search`

Read-only local audit query. Supports repeated or comma-list `--type`,
`--since`, `--until`, `--actor`, `--limit`, and `--json`. Uses the existing
`AuditLog.query` reader and the existing key-derivation path to decrypt local
audit entries. No matches exit 0 with an empty result.

### `sanctuary generate systemd`

Pure stdout templating for a Linux systemd unit. Resolves a binary path and
supports `--user`, `--state-dir`, and `--binary`. On macOS it still emits the
Linux unit and adds a comment noting launchd is separate.

## Files Added

- `server/src/cli/audit.ts`
- `server/src/cli/completion.ts`
- `server/src/cli/doctor.ts`
- `server/src/cli/generate.ts`
- `server/src/cli/subcommands.ts`
- `server/test/cli/audit-search.test.ts`
- `server/test/cli/completion.test.ts`
- `server/test/cli/doctor.test.ts`
- `server/test/cli/generate-systemd.test.ts`
- `server/docs/cli-operator-verbs.md`
- `BUILD_REPORT_cli_wave1_5.md`

## Files Modified

- `server/src/cli.ts`
- `.test-baseline`

## Baseline Delta

- Before: `5423`
- Added tests: `20`
- After: `5443`

## Gates

- `npm run typecheck`: PASS
- `npm test -- test/cli/completion.test.ts`: PASS, 5 tests
- `npm test -- test/cli/generate-systemd.test.ts`: PASS, 5 tests
- `npm test -- test/cli/audit-search.test.ts`: PASS, 5 tests
- `npm test -- test/cli/doctor.test.ts`: PASS, 5 tests
- `npm test -- test/cli/no-em-dash-in-cli.test.ts`: PASS, 3 existing tests
- Prompt artifact scan over touched files for forbidden dash, forbidden legacy
  product name, and forbidden numbered-layer notation: PASS, no matches

## Sample Invocations

### Doctor

```bash
node dist/cli.js doctor --help
```

```text
Usage: sanctuary doctor [--json] [--fortress <path>]

Runs read-only local diagnostics for state directory, identity, principal
policy, audit-chain integrity, runtime versions, and Castle Wall status.
```

### Completion

```bash
node dist/cli.js completion fish
```

```text
# sanctuary fish completion
set -l sanctuary_commands agents anomaly audit audit-chain auto-trigger broker-server castle-wall completion compliance concierge dashboard did-web doctor erc8004 exit export-passphrase generate identity import-exit-bundle inbox init intelligence policy protect reset-passphrase secrets sentinel task template verify-exit-bundle wrap
complete -c sanctuary -f -n "__fish_use_subcommand" -a "$sanctuary_commands"
complete -c sanctuary-mcp-server -f -n "__fish_use_subcommand" -a "$sanctuary_commands"
```

### Audit Search

```bash
node dist/cli.js audit search --help
```

```text
Usage: sanctuary audit search [--type <event_type>] [--since <iso|relative>] [--until <iso|relative>] [--actor <id>] [--limit <n>] [--json]

Options:
  --type <event_type>  Filter by operation. Repeat or comma-separate.
  --since <time>       ISO time or relative duration like 5m, 2h, 7d.
  --until <time>       ISO time or relative duration like 5m, 2h, 7d.
  --actor <id>         Filter by identity_id.
  --limit <n>          Maximum records to print. Defaults to 50.
  --fortress <path>    Override fortress path.
  --passphrase <val>   Passphrase for decrypting audit entries.
  --json               Emit JSON.
```

### Generate Systemd

```bash
node dist/cli.js generate systemd --user svc --state-dir /srv/sanctuary --binary /opt/bin/sanctuary
```

```text
# Sanctuary systemd unit
# Install:
#   sudo install -m 0644 sanctuary.service /etc/systemd/system/sanctuary.service
#   sudo systemctl daemon-reload
#   sudo systemctl enable --now sanctuary.service
# Note: this host is macOS. This unit is for Linux systemd hosts; macOS launchd is out of scope.
[Unit]
Description=Sanctuary MCP Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=svc
Environment=SANCTUARY_STORAGE_PATH=/srv/sanctuary
ExecStart=/opt/bin/sanctuary dashboard --no-confirm
Restart=on-failure
RestartSec=5
WorkingDirectory=/

[Install]
WantedBy=multi-user.target
```

## Dependencies

No new production dependencies.

## Deviations

- `audit search` requires `SANCTUARY_PASSPHRASE`, `--passphrase`, or
  `SANCTUARY_RECOVERY_KEY` because the existing local audit reader decrypts
  entries under the fortress master key.
- `doctor` reports identity fingerprint only when key material is available.
  If encrypted identity records exist but no key is supplied, it reports `WARN`
  rather than attempting any prompt or write path.
- No federation HTTP endpoint is called or assumed.
