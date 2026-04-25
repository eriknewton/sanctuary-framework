# Harness Compatibility Matrix

Last fixture run target: 2026-04-25.

This matrix covers local-fortress `sanctuary wrap` behavior for every `LocalHarnessKind` value and every README-supported wrap target. Fixture-tested means the behavior is covered by `server/test/harness/harness-compatibility.test.ts` using temp configs and injected dashboard/passphrase dependencies. The tests do not require real external harness installs.

| Harness | LocalHarnessKind mapping | Dry-run | Backup | Wrap | Dashboard URL emission | Identity creation | Audit init | Unwrap |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| OpenClaw | `openclaw` | fixture-tested | fixture-tested | fixture-tested | fixture-tested | first-unlock | first-unlock | fixture-tested |
| Hermes Agent | `hermes` | fixture-tested | fixture-tested | fixture-tested | fixture-tested | first-unlock | first-unlock | fixture-tested |
| Claude Code | `claude_code` | fixture-tested | fixture-tested | fixture-tested | fixture-tested | first-unlock | first-unlock | fixture-tested |
| Cursor | `cursor` | fixture-tested | fixture-tested | fixture-tested | fixture-tested | first-unlock | first-unlock | fixture-tested |
| Cline | `cline` | fixture-tested | fixture-tested | fixture-tested | fixture-tested | first-unlock | first-unlock | fixture-tested |
| Mastra | `mastra` via `--wrap <path>` generic MCP config | fixture-tested | fixture-tested | fixture-tested | fixture-tested | first-unlock | first-unlock | fixture-tested |
| Generic MCP | `generic_mcp` via `--wrap <path>` | fixture-tested | fixture-tested | fixture-tested | fixture-tested | first-unlock | first-unlock | fixture-tested |
| Other MCP-compatible harness | `other` via `--wrap <path>` | fixture-tested through Generic MCP | fixture-tested through Generic MCP | fixture-tested through Generic MCP | fixture-tested through Generic MCP | first-unlock | first-unlock | fixture-tested through Generic MCP |
| LangGraph | v1.1+ planned through `generic_mcp` | fixture-tested through Generic MCP | fixture-tested through Generic MCP | fixture-tested through Generic MCP | fixture-tested through Generic MCP | first-unlock | first-unlock | fixture-tested through Generic MCP |

**Cell legend:** "fixture-tested" = covered by `harness-compatibility.test.ts` against temp configs. "first-unlock" = NOT a `runWrap` effect; initialized on first cocoon-unlock when `createSanctuaryServer()` or `startStandaloneDashboard()` derive the master key from the persisted passphrase. This is the lazy-init pattern that PR #61 (`reset-passphrase`) and PR #68 (reset-history continuity) both rely on.

## Negative Coverage

| Failure mode | Coverage |
|---|---|
| Missing config file | fixture-tested for explicit `--wrap <path>` with clear "Configuration Not Found" output |
| Invalid config | fixture-tested for malformed JSON diagnostics |
| Port conflict | fixture-tested by exhausting the injected dashboard starter fallback range |
| Keychain failure simulation | fixture-tested by failing the injected passphrase resolver before config mutation |
| Backup failure simulation | fixture-tested by removing the detected config before backup and asserting wrap aborts |

## README Parity

README wrap targets are OpenClaw, Hermes Agent, Claude Code, Cursor, Cline, and `--wrap <path>` for Mastra, LangGraph, custom harnesses, and any other MCP-compatible harness. The parity test asserts those named targets map either to a first-class `LocalHarnessKind` entry or to the documented `generic_mcp` path above.

## Observed Gaps

The current `runWrap` implementation (`server/src/cocoon/cli.ts:153`) detects/bootstraps the agent config, persists/resolves the passphrase (Keychain or fallback file), creates the storage directory, writes the sovereignty profile, backs up the config, and rewrites the agent config to point at Sanctuary. It does NOT generate an Ed25519 identity keypair or write an audit genesis entry — those are deferred to first cocoon-unlock per the lazy-init pattern (server boot via `createSanctuaryServer()` or dashboard boot via `startStandaloneDashboard()` derives the master key from the persisted passphrase, then initializes identity + audit on first run).

This is correct architecture (passphrase resolution must precede key derivation; the master key cannot exist at wrap-time when the passphrase may not yet be entered). The matrix's "first-unlock" label captures the actual pattern.

**README parity follow-up:** README copy that implies identity creation + audit init are wrap-time effects should be corrected in a separate v1.0.x housekeeping pass to read "initialized on first cocoon-unlock after wrap." Filed as v1.0.2 backlog item (l).
