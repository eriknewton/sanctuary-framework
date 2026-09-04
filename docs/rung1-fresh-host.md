# Rung 1: fresh-host sovereign-memory onboarding

> **Candidate status:** this document describes the software contract under
> review. Treat Rung 1 as host-ready only after you have confirmed restart
> persistence on your own host: store a memory, restart, and read it back with
> no secret typed.

Rung 1 is Sanctuary's sovereign encrypted memory substrate: your agent's memory
lives in an at-rest-encrypted vault you own, with signed provenance, and it is
portable across machines. This guide is the first-use and fresh-host
walkthrough: what to run, how a second machine opens the same fortress, and how
to recover when a passphrase is not to hand.

Rung 1 is portability, not sync: commands run only when you invoke them, they
never watch a harness directory, and they never write back into a harness's own
files. The honest claim is sovereign at rest, in portability, and in provenance;
at inference time your memory is exposed to whichever model vendor you chose.

## First use: prove it with the MCP tools

First-use is proven through the existing policy-enforcing MCP tools, not a
parallel CLI. These are the same tools your agent calls every day, so the proof
runs through the same Tier gate and the same provenance signing as real use:

1. `memory_insert` stores a record. Tier-1 (human-approved); the approval prompt
   names the memory scope and the calling agent.
2. `memory_search` finds it back by content.
3. `memory_get` reads it back byte-faithfully and proves exact content: it
   decrypts on read and re-verifies the stored `content_hash`, failing closed on
   any integrity mismatch. `memory_get` proves the bytes; it does not surface
   signer or signature fields. `memory_search` and `memory_get` are Tier 3 by
   default: hands-free reads with no approval prompt, while `memory_insert`
   stays Tier 1. Every agent connected to one fortress shares one memory scope
   today; per-agent memory isolation is not yet implemented. `memory_search`
   returns 10 results unless you pass `limit`, and at most 500.
4. Provenance: `sdw_memory_provenance` is the tool that proves verified
   provenance. For a passage id it reports the per-record signing status
   (`verified` vs a legacy unsigned row) and the fortress-recorded origin and
   admission bindings that verify for that exact passage (the `memory_provenance_*`
   verbs manage the known-signer set). A record whose provenance does not verify
   there is not trusted.

If `memory_insert`, then `memory_search`, then `memory_get` round-trips a record
byte-faithfully and `sdw_memory_provenance` reports its provenance verified,
the in-process Rung 1 data path works on this host. The separate restart drill
below is still required before calling the host ready for daily use.

## Restart persistence

Rung 1 must survive a reboot with no secret typed. The acceptance step
(`restart_and_verify_rung1`, surfaced by `sanctuary install` once the memory
surface is present) is: `memory_insert` a marker, restart the host, then
`memory_search` and `memory_get` it back, with no `SANCTUARY_PASSPHRASE` or
`SANCTUARY_RECOVERY_KEY` in the environment. The fortress unlocks from the
exact-fortress local factor: either the stored passphrase that `protect`
created or the OS-keyring custody key enrolled by interactive `init`. The daily
driver therefore never types a passphrase.

## Manual portability: emit and re-ingest

`memory_emit` (also `sanctuary memory_emit`) writes byte-faithful plaintext of
every record the secret classifier accepts to an output directory you name.
Because that crosses the encrypted-vault boundary, it is non-relaxable Tier 1:
the CLI requires a local OS human-approval dialog; an explicit command or output
path is not approval by itself. That reviewed local-human channel is implemented
on macOS today. Linux and Windows `memory_emit` fail closed until an equivalent
local-human channel ships; this does not prevent encrypted ingest/search/get.
`memory_ingest` mirrors a memory directory back into the vault. Files the
classifier refuses are skipped and named in the result, so a partial mirror is
never mistaken for a complete one; if `MEMORY.md` is refused, `memory_emit`
reports `index_present: false` and the emitted tree is not a closed re-import.

`memory_transcode` and `memory_transcode_restore` materialize a memory tree in
another harness layout (for example Claude Code to Codex). They cross the same
plaintext boundary as `memory_emit`, so both are non-relaxable Tier 1 and use
the same reviewed local-human dialog. They currently fail closed off macOS.

## Archive transfer between fortresses

`sanctuary memory_archive_export` reads a logical memory archive without
modifying its source and writes a transfer bundle; `sanctuary
memory_archive_import` rematerializes it under destination-local identifiers with authenticated
signed lineage and atomic replay/conflict guards. Every transfer is encrypted
with a fresh per-artifact key. Use this to move memory between two fortresses you
control.

## Key rotation and memory

Master-key rotation does not yet cover the memory namespaces. While memory
records are present, `rotate-master` refuses to start and changes nothing.
There is no shipped procedure yet to rotate a fortress that holds memory
records (`memory_emit` writes only harness-mirrored files, not records created
with `memory_insert`), so plan any rotation before enabling memory on a
fortress, or wait for the rotation follow-up.

## Exact-fortress unwrap on a second host

Every fortress at a non-default path is addressed with `--fortress <path>`. Its
stored passphrase and interactive-init custody key live in distinct OS-keyring
services derived from the canonical physical storage path, so symlink aliases
share one credential family while two physical fortresses never do. Compatibility
reads retain older lexical service names; new writes use the canonical identity.

When you run a memory verb on a second host, Sanctuary resolves local factors in
this order. Explicit factors always win; if a stored passphrase is stale, the
interactive-init custody key remains an authenticated fallback:

1. `--passphrase-stdin` (memory-file verbs only)
2. a legacy `--passphrase` argv value
3. `SANCTUARY_PASSPHRASE`
4. `SANCTUARY_RECOVERY_KEY`
5. the exact-fortress stored passphrase: the OS keyring or encrypted fallback
   namespaced to this fortress.
6. the exact-fortress machine-local custody key enrolled by interactive `init`.

So on a host where `protect` already stored the passphrase, memory verbs open the
fortress with no secret supplied on the command line. Sanctuary never generates a
passphrase on this path: if the keyring is locked it says so and stops; it never
overwrites a stored credential.

Custody-changing ceremonies bind every filesystem operation to the root inode
that won the kernel lock. The mutating process itself owns an exclusive Unix-
domain listener in a uid-owned 0700 runtime directory, keyed by the canonical
lock-directory device/inode; a helper process cannot release exclusion while the
mutator continues. Linux addresses filesystem capability paths through
`/proc/self/fd`; macOS uses
a short-lived child whose kernel-held working directory is that inode because
macOS cannot traverse children through `/dev/fd`. Worker requests are serialized
and bounded, and an exit or timeout stops the ceremony fail-closed.

## Second-host recovery with your recovery key

When you carry a fortress to a fresh host that has no stored credential, you open
it once with the human-held recovery key you saved at first custody, and enroll a
fresh passphrase into that host's keyring so daily use needs no secret:

```
sanctuary reset-passphrase --mode recovery-key --fortress <path>
```

This is also the first response to a lost passphrase or a copied fortress left
at an authenticated interrupted-rekey boundary. Do not nuke the fortress merely
because this host has no stored credential: the recovery key preserves the
master, identities, audit history, and memory. `--mode nuke` is a destructive
last resort only after recovery-key, configured shares, and guardian recovery
are unavailable or have been proven unusable.

Nuke binds all confirmations to the original non-symlink fortress directory,
then rechecks that directory under the custody lock. The destructive walker is
launched with that confirmed directory as its kernel-established working
directory and validates the root plus each entered `state/_meta` directory by
device/inode before deleting, so renaming the locked original and placing a new
directory at its path cannot redirect the wipe. It refuses while the OS
credential store is locked or otherwise indeterminate; a successful reset
clears every registered passphrase, custody-key, and recovery-escrow keyring
identity (canonical and compatibility forms) and explicitly removes the
encrypted fallback credential. The zero-byte custody lock inode remains as
an inert scaffold so mutual exclusion cannot be escaped by deleting a live lock
path; fresh initialization recognizes only that exact scaffold.

This mode is interactive-terminal only: it reads the recovery key from a hidden
prompt (never argv, environment, or a pipe). It unlocks the master through the
existing recovery wrap, enrolls a fresh random passphrase as a new custody wrap
and the exact-fortress stored credential, verifies both, and only then removes
the old passphrase. Your recovery key is unchanged and keeps working; the master
key, your data, and the recovery wrap are all preserved; a wrong key changes
nothing. No secret is printed.

Successful resets append an owner-only `.reset-history.log` record. The log is
written as complete newline-delimited JSON frames through an atomic, durable,
no-follow replacement. It is non-authoritative operator history only: Sanctuary
never treats it as authorization, custody proof, or a recovery decision input.

Alternatively, supply the credential for a single run with
`SANCTUARY_RECOVERY_KEY=<key>` (or `SANCTUARY_PASSPHRASE=<value>`) in the
environment. Prefer the rekey so the host works hands-free afterward.

## When a restore is detected: restore-attest

If Sanctuary sees the fortress looks older than its surviving custody evidence
(a Time Machine restore, a backup, a dotfile sync, or cloning to a new machine),
it freezes trust-bearing writes until you acknowledge the restore:

```
sanctuary restore-attest --fortress <path>
```

It re-baselines the epoch witness to what is already on disk (it cannot forge a
newer one) and records a permanent audit entry. It requires a real credential:
the passphrase by default, or your recovery key with the private
`--recovery-key-prompt` flag (a hidden interactive prompt) for the second-host
case where the passphrase is not to hand.

## Install evidence fields

`sanctuary install --profile memory --json` reports three Rung-1 daily-UX
observations. The credential/envelope portion is read-only and ignores ambient credential environment
variables (so an exported passphrase can never make a copied host look openable
when the daily driver could not open it):

- `custody_access`:
  - `usable`: a stored passphrase or interactive-init custody key opens this
    fortress with no secret typed.
  - `absent`: envelope custody exists but this host has neither local factor yet
    (the just-copied second host; run the recovery-key rekey).
  - `locked`: the OS keyring is locked or unreachable in this session (SSH, fresh
    reboot). Unlock it and re-probe.
  - `mismatch`: a stored local factor exists but does not open this fortress (a
    stale credential after a restore), or the encrypted fallback will not decrypt
    on this host.
  - `missing`: no envelope custody exists yet (virgin fortress); onboarding is
    not complete.
  - `unavailable`: the platform has no supported exact-fortress stored
    credential path; hands-free opening is not proven.
  - `unknown`: an indeterminate read; no remedy is invented.
- `custody_mutation`:
  - `available`: the reviewed process-owned, crash-recoverable custody lock is
    usable for this target fortress on this runtime. This is a local-host/runtime
    lock namespace only; known shared/network/FUSE filesystems are refused.
  - `unavailable`: authentication may still succeed, but custody changes are
    blocked because the mutation lock is unsupported or unavailable.
  - `unknown`: the mutation capability probe was indeterminate.
- `recovery_factor`: `present`, `absent`, or `unknown`, i.e. whether the fortress
  carries an authenticated, verified human-held recovery-key wrap and so whether
  a second-host recovery or recovery-key rekey is proven possible. An unverified
  recovery wrap reports `unknown`, never `present`. Enroll a recovery key while
  `recovery_factor` is `absent`.

## Secret boundaries

- No memory verb, installer response, or recovery flow ever prints a passphrase,
  recovery key, or keychain contents. Attended recovery/rekey commands default to
  hidden interactive prompts and refuse argv or piped secrets. The ordinary
  one-run memory/archive unlock compatibility path also accepts the explicitly
  documented `SANCTUARY_PASSPHRASE` or `SANCTUARY_RECOVERY_KEY` environment input;
  use it only in a private local process environment and prefer the stored-custody
  rekey for daily use.
- The installer's credential/envelope probe is read-only and never reads
  `SANCTUARY_PASSPHRASE` or `SANCTUARY_RECOVERY_KEY`. Its separate mutation-lock
  capability check creates and removes a private Unix socket and may create the
  uid-owned 0700 runtime directory under `/tmp`; it does not mutate fortress data.
- Windows is scoped to authenticated custody-envelope read only: it can open an
  existing authenticated custody envelope when an explicit or legacy encrypted
  fallback credential is available. It cannot create, migrate, rekey, reset, or
  otherwise mutate custody, and every memory verb (`memory_ingest`, `memory_emit`,
  `memory_transcode`, `memory_transcode_restore`, and memory/archive export and
  import) additionally requires the reviewed local-human approval dialog, which
  is macOS-only. Consequently no shipped memory or archive export or import verb
  runs on Windows: `custody_access` may report an authenticated read independently
  while `custody_mutation=unavailable` keeps install readiness blocked, and a
  one-shot envelope read is not evidence of writable daily custody or of any
  export capability.
- The storage layer's directory-fsync durability check tolerates only the
  platform's documented `EISDIR`/`EPERM` inability to fsync a directory
  descriptor after the file has itself been fsynced and atomically renamed; this
  is a general Windows file-write durability accommodation used by the storage
  layer, not evidence that a memory or archive export path is enabled on
  Windows. Darwin/Linux still propagate those errors as real durability
  failures; all platforms propagate real file-sync, rename, path, and I/O
  failures.
- Do not paste a passphrase, recovery key, login password, or keychain contents
  into a chat with an agent. Move a staged recovery file into a password manager
  in a private local session, then delete the staging file.
