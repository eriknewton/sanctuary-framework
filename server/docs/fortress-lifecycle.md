# Fortress lifecycle

A Sanctuary fortress is the operator-controlled state directory that holds principal policy, encrypted state, audit chain, and identity keys for one tenant. Fortresses are created by explicit operator action only. Sanctuary MCP children that boot under a host harness (Claude Code Desktop, Cursor, Cline, OpenClaw, Hermes) will refuse to silently initialize a missing fortress and will exit with code 78 (EX_CONFIG) with a structured FORTRESS_NOT_FOUND error.

## Creating a fortress

- `sanctuary init` creates a fortress at the default path (`~/.sanctuary` unless `SANCTUARY_FORTRESS_PATH` is set).
- `sanctuary wrap` creates a fortress as a side effect of wrapping a harness, if no fortress exists at the resolved path.

### Castle Wall pin provisioning at init

`sanctuary init` never reads, compares, or writes the machine-wide Castle Wall pin, the host-wide enforcement anchor at `/Library/Application Support/Sanctuary/castle-pinned-pubkey.bin`. It provisions only this fortress's own Castle key pair and records an additive `castle_wall_provision: not_yet_walled` claim: a vault this run created before the wall was turned on for it. That is the ordinary starting state for every fortress, not a fault, and it holds for a test or side-by-side isolated fortress exactly as it does for the primary one on a machine, since neither ever touches the host-wide anchor.

- `--no-pin` and `SANCTUARY_INIT_NO_PIN` are still parsed and accepted, but they are no-ops: init prints a one-line deprecation notice and provisions the fortress-local key pair the same way with or without them. There is nothing left for them to skip, because default init never touches the machine-wide anchor.
- The machine-wide anchor has exactly one writer: a confirmed `sanctuary castle-wall re-pin`, run interactively at a terminal (it refuses with no TTY and has no environment override). Re-pin publishes the anchor on a fresh host and migrates it on a host that already carries one; it is the anchor half of putting a vault on the wall.
- `castle_wall_provision` is never written as `walled`; only `not_yet_walled` is ever persisted. Whether a vault is on the wall is derived at read time, not stored: it holds only when the machine-wide anchor is consistent with the signer helper's key AND that vault's own arm evidence says armed. `doctor`, `castle-wall status`, `sanctuary status`, and the health surfaces each report what they can observe of that pair. Re-pin supplies the anchor condition; arming, a separate step run through the installer, supplies the other.

## Resolving the fortress path

In order of precedence:

1. CLI flag `--fortress <path>` (where supported).
2. Environment variable `SANCTUARY_FORTRESS_PATH`.
3. Default `~/.sanctuary`.

## Refusal behavior

MCP children booted by host harnesses do NOT create fortresses. If the resolved path does not exist, the child emits a structured FORTRESS_NOT_FOUND error to stderr and exits with code 78. The host harness should surface this error to the operator (visible in Claude Code Desktop's MCP debug log; visible in Cursor's MCP status panel; visible in Hermes's broker logs).

This behavior closes Finding UUU from the 2026-05-14 Mini1 acceptance drill.

## Recovery

If a host harness shows a FORTRESS_NOT_FOUND error and you expected a fortress to exist:

1. Check `SANCTUARY_FORTRESS_PATH` is set to the path you expect.
2. Check `~/.sanctuary` (or your custom path) actually contains `principal-policy.yaml` and `sanctuary.json`.
3. If you intentionally archived the fortress, restore it from your archive path.
4. If you want a new fortress, run `sanctuary init` explicitly.
