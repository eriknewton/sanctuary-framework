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

## `sanctuary intelligence config-reset`

Recovers a fortress whose local-intelligence config record has become unreadable. Two
shapes count as unreadable: a record that no longer decrypts or parses (`corrupt`), and
a record written by a newer Sanctuary whose version this build does not know
(`version-too-new`). Either one makes every local-intelligence config write fail closed
with a typed error that names this verb; reads keep booting on the default configuration
so the rest of the fortress is unaffected.

```bash
sanctuary intelligence config-reset
sanctuary intelligence config-reset --fortress ~/.sanctuary-work
```

What it does, in order:

1. Refuses unless stdin is an interactive terminal. There is no flag that skips the
   prompt; a piped or scripted run exits 1 before the fortress is unlocked.
2. Unlocks the fortress master with write intent (`SANCTUARY_PASSPHRASE`,
   `SANCTUARY_RECOVERY_KEY`, or the exact-fortress stored credential), holding the shared
   master-rotation barrier for the rest of the run.
3. Classifies the durable record and prints the classification. A readable record, armed
   or legacy, is refused: this verb never discards live operator state. An armed record
   that fails Q5 integrity validation is refused too; that is an integrity refusal, not an
   unreadable record, and there is no in-product disarm.
4. Prints the plan and asks you to type `reset`. Anything else aborts with nothing changed.
5. Copies the record's raw bytes to
   `<fortress>/state/_intelligence/substrate-config.quarantine.<UTC stamp>.bin`
   (owner-only, never overwritten), then removes the record, then appends an
   `intelligence_config_quarantined` audit entry.

After a successful run the next load returns the default configuration. Operator
substrate choices and any API keys that were inside the unreadable record are not
recovered; re-enter them through the dashboard or `sanctuary intelligence` as usual. A
fortress that was Q5-armed on the quarantined record is unarmed afterward and must be
re-provisioned before local load-integrity verification applies again.

Exit codes: `0` quarantined or no record existed; `1` refused (non-interactive, declined,
unlock failed, record not unreadable); `2` malformed flags.

Failure modes to know before you run it:

- **The symptom is a config write that fails, not a boot that fails.** Boot reads fall
  back to defaults and log `intelligence_config_loaded` with `was_default: true`; the
  first write (a substrate pick in the dashboard, a provisioning run) is what surfaces the
  typed error. If writes fail with a Q5 integrity reason instead (`manifest_rollback`,
  `binding_mismatch`, `manifest_signature_invalid`), the record is readable and this verb
  will refuse; that is a different condition.
- **A corrupt record also blocks `rotate-master` preflight by name** (the rotation walk
  refuses any `_intelligence` entry it cannot decrypt). Running this verb clears that
  block. The sidecar is deliberately not an encrypted entry, so rotation ignores it.
- **The sidecar is bound to the master key in effect when it was written.** A quarantined
  `version-too-new` record is still valid ciphertext under that key; after a later
  `rotate-master` it will no longer decrypt under the new master. Copy it elsewhere first
  if you intend to open it with a newer Sanctuary after rotating.
- **Two runs in the same millisecond refuse the second** rather than overwrite the first
  sidecar. Rerun; the stamp will differ.
- **A crash between the sidecar write and the record removal leaves both files.** That is
  the intended order: at no point is the record gone without a copy of its bytes. Rerun
  the verb; it quarantines again under a new stamp and completes the removal.
- **Unlock refusals are secret-free and name the source that failed** (`absent`,
  `locked`, `mismatch`). A `locked` keyring over SSH means: pass `SANCTUARY_PASSPHRASE`
  explicitly or run from a console session.
