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
sanctuary secrets list --fortress ~/.sanctuary-work   # refused, exit 2
```

Verified: a subcommand that does not parse the flag reads the default fortress and
prints an ordinary result for it. Nothing warns, nothing errors, and the output of
"no secrets stored" is a true statement about the wrong fortress. Some subcommands
(`doctor`, `agents`, `intelligence`) parse the flag in either position, which is what
makes the habit easy to form and the exception easy to miss. On a multi-fortress host,
put the flag first every time, and confirm the path in the command's own output before
you trust the answer.

`secrets` is the one subcommand that refuses the trailing form outright (exit 2, since
2026-08-05), because on `add`, `rotate` and `delete` the dropped flag wrote a credential
into the default fortress and reported success. That refusal is scoped to `secrets`
alone and is not a general fix.

Failure mode to watch for: every other subcommand that does not parse `--fortress`
still ignores it silently, and the result looks exactly like a correct answer for the
fortress you named. There is no way to tell from the output which fortress answered,
short of a command that prints the path. The general fix is a single shared flag parser
so that no handler can silently drop a flag; until that lands, the leading position is
the only form that is safe everywhere.

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
- On shipped installs, `WARN audit chain / no checkpoint signature was verified`
  is expected until a production checkpoint signer is wired.
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

Read the emitted unit before you install it. As of 2026-08-05 the generator refuses
rather than emitting a unit it knows will not start, but the paths it writes are still
**this host's** paths:

| Line to check | What it emits | Failure mode |
|---|---|---|
| `ExecStart=` | This host's node plus the resolved CLI entry, or the `--binary` value verbatim | A path that exists here and not on the target host gives a bare `status=203/EXEC` with no Sanctuary output at all, which reads like a Sanctuary startup failure and is not one. Generating from a source checkout run under `tsx` is refused outright, because the entry there is TypeScript and the unit's plain `node` cannot execute it; pass `--binary`, or generate from an installed package |
| `Environment=SANCTUARY_STORAGE_PATH=` | An absolute path, quoted when it contains a space or a `%` | A tilde, a relative path, or a `~user` form is refused: systemd performs no tilde expansion, so an unexpanded `~` would become a literal directory and the service would behave as though the fortress were empty. Pass `--state-dir` with an absolute path for a service user other than yourself, since this command cannot know another user's home directory |

Both of those lines were defects before 2026-08-05: `ExecStart` named the node binary with
no script on every installed package, and `Environment=` carried a literal `~/.sanctuary`.

The unit also runs `dashboard`, the long-lived HTTP process, while its `Description=` reads
`Sanctuary MCP Server`. The dashboard is the correct thing to supervise; the description is
the part that is misleading. See [DEPLOYMENT.md](DEPLOYMENT.md) for why the stdio MCP server
is not a service-manager workload.
