# Sanctuary CLI Operator Verbs

This page documents local operator commands that do not depend on a running
federation HTTP API. They either inspect local state or emit templates to
stdout.

## `--fortress` goes before the subcommand

The top-level help says so, and the reason it matters is that getting it wrong is
silent. The top-level parser extracts `--fortress` only from the position ahead of the
subcommand; a subcommand that does not parse the flag itself receives it as an unknown
argument and ignores it, falling back to `~/.sanctuary`.

```bash
sanctuary --fortress ~/.sanctuary-work secrets list   # inspects ~/.sanctuary-work
sanctuary secrets list --fortress ~/.sanctuary-work   # inspects ~/.sanctuary
```

Verified: the second form reads the default fortress and prints an ordinary result for
it. Nothing warns, nothing errors, and the output of "no secrets stored" is a true
statement about the wrong fortress. Some subcommands (`doctor`, `agents`) parse the flag
in either position, which is what makes the habit easy to form and the exception easy to
miss. On a multi-fortress host, put the flag first every time, and confirm the path in
the command's own output before you trust the answer.

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

Failure mode: a run with no credential in the environment exits **0**. The identity
check downgrades to `WARN` ("encrypted identity record(s) found; no key available to
decrypt") rather than `FAIL`, because a locked fortress is a legitimate state, and only
`FAIL` moves the exit code. A CI job or health probe that reads the exit code alone
therefore reports a healthy fortress on a run where the deepest check never executed.
Read the `WARN` lines, or supply `SANCTUARY_PASSPHRASE` / `SANCTUARY_RECOVERY_KEY` so
the identity check actually runs.

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

Failure mode: the `SANCTUARY_PASSPHRASE=...` prefix shown above is convenient and it
writes your fortress passphrase into shell history verbatim, where it stays until the
history file is rotated or scrubbed. Nothing warns you. Export the variable from a
sourced mode-600 env file, or prefix the command with a space if your shell is
configured to skip those lines, rather than typing the credential inline.

## `sanctuary generate systemd`

Prints a Linux systemd unit to stdout:

```bash
sanctuary generate systemd
sanctuary generate systemd --user sanctuary --state-dir /var/lib/sanctuary
```

This command is pure string templating. It does not read or write Sanctuary
state. On macOS it still emits the Linux unit and includes a comment noting
that launchd is separate.

Read the emitted unit before you install it. Because the command templates rather than
inspects, nothing here is validated, and two defaults are wrong on a stock install:

| Line to check | What it emits by default | What to do |
|---|---|---|
| `ExecStart=` | The published package is a single bundled `dist/cli.js`, so the internal path probe for the CLI entrypoint does not match and the fallback emits the **node executable** with no script: `ExecStart=/usr/local/bin/node dashboard --no-confirm`. systemd accepts the line, and the service fails at first start because node has no `dashboard` script | pass `--binary /path/to/sanctuary` (or the absolute path to `dist/cli.js`) and confirm the rendered line names it |
| `Environment=SANCTUARY_STORAGE_PATH=` | The literal string `~/.sanctuary`. systemd performs no tilde expansion in `Environment=`, so the service receives a relative path beginning with a tilde character rather than the operator's home directory. Combined with `WorkingDirectory=/` the fortress does not resolve where anyone expects | pass `--state-dir` with an absolute path |

The unit also runs `dashboard`, the long-lived HTTP process, while its `Description=` reads
`Sanctuary MCP Server`. The dashboard is the correct thing to supervise; the description is
the part that is misleading. See [DEPLOYMENT.md](DEPLOYMENT.md) for why the stdio MCP server
is not a service-manager workload.
