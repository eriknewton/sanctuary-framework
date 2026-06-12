# Fortress lifecycle

A Sanctuary fortress is the operator-controlled state directory that holds principal policy, encrypted state, audit chain, and identity keys for one tenant. Fortresses are created by explicit operator action only. Sanctuary MCP children that boot under a host harness (Claude Code Desktop, Cursor, Cline, OpenClaw, Hermes) will refuse to silently initialize a missing fortress and will exit with code 78 (EX_CONFIG) with a structured FORTRESS_NOT_FOUND error.

## Creating a fortress

- `sanctuary init` creates a fortress at the default path (`~/.sanctuary` unless `SANCTUARY_FORTRESS_PATH` is set).
- `sanctuary wrap` creates a fortress as a side effect of wrapping a harness, if no fortress exists at the resolved path.

### Castle Wall pin provisioning at init

By default `sanctuary init` also provisions the machine-wide Castle Wall pin, the host-wide enforcement anchor at `/Library/Application Support/Sanctuary/castle-pinned-pubkey.bin`. This is correct for the primary fortress on a machine, but a test or side-by-side isolated fortress should not touch that host-wide anchor.

- `sanctuary init --no-pin` provisions **no** global pin. It records an audited `castle_pin_provision_skipped` entry and prints a reminder to run `sanctuary castle-wall provision-pin` against that fortress when you are ready.
- For non-interactive harnesses, set `SANCTUARY_INIT_NO_PIN` to an explicit opt-in value (`1`, `true`, `yes`, or `on`, case-insensitive) for the same effect. Any other value (including a typo or an inherited shell value) is ignored, so the global pin is still provisioned by default.
- Default behavior (no flag, env unset) is unchanged: the global pin is provisioned exactly as before.

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
