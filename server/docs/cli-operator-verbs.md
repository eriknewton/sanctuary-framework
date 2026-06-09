# Sanctuary CLI Operator Verbs

This page documents local operator commands that do not depend on a running
federation HTTP API. They either inspect local state or emit templates to
stdout.

## `sanctuary doctor`

Runs a read-only diagnostic against the local fortress.

```bash
sanctuary doctor
sanctuary doctor --json
sanctuary doctor --fortress ~/.sanctuary-work
```

Checks:

- State directory exists, has owner-only permissions, and is writable.
- Identity records exist. With `SANCTUARY_PASSPHRASE` or
  `SANCTUARY_RECOVERY_KEY`, the primary identity is loaded and reported by
  fingerprint only.
- `principal-policy.yaml` exists and parses. Raw policy rules are not printed.
- Audit log exists and chain-verifies through the same export plus verifier
  logic used by `sanctuary audit-chain`.
- Package, Node.js, and npm versions are reported.
- Castle Wall system-extension status is reported on macOS. Other platforms
  print `n/a (not macOS)`.

Exit code is non-zero if any check is `FAIL`.

## `sanctuary completion <bash|zsh|fish>`

Prints shell completion to stdout:

```bash
sanctuary completion bash
sanctuary completion zsh
sanctuary completion fish
```

The top-level command list is shared with the CLI dispatcher so completions
stay synchronized as new subcommands land.

## `sanctuary audit search`

Queries the local encrypted audit log. This is read-only and uses the existing
`AuditLog` reader.

```bash
SANCTUARY_PASSPHRASE=... sanctuary audit search --type state_read --limit 20
SANCTUARY_PASSPHRASE=... sanctuary audit search --actor agent-1 --json
SANCTUARY_PASSPHRASE=... sanctuary audit search --since 2h --until 10m
```

Options:

- `--type <event_type>` can be repeated or comma-separated.
- `--since <iso|relative>` and `--until <iso|relative>` accept ISO timestamps
  or relative durations like `5m`, `2h`, `7d`.
- `--actor <id>` filters by `identity_id`.
- `--limit <n>` defaults to 50.
- `--json` emits `{ entries, total }`.

No matches exit 0 and print an empty result.

## `sanctuary generate systemd`

Prints a Linux systemd unit to stdout:

```bash
sanctuary generate systemd
sanctuary generate systemd --user sanctuary --state-dir /var/lib/sanctuary
```

This command is pure string templating. It does not read or write Sanctuary
state. On macOS it still emits the Linux unit and includes a comment noting
that launchd is separate.
