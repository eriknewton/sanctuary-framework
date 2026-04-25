# Harness Compatibility Matrix

Last fixture run target: 2026-04-25.

This matrix covers local-fortress `sanctuary wrap` behavior for every `LocalHarnessKind` value and every README-supported wrap target. Fixture-tested means the behavior is covered by `server/test/harness/harness-compatibility.test.ts` using temp configs and injected dashboard/passphrase dependencies. The tests do not require real external harness installs.

| Harness | LocalHarnessKind mapping | Dry-run | Backup | Wrap | Dashboard URL emission | Identity creation | Audit init | Unwrap |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| OpenClaw | `openclaw` | fixture-tested | fixture-tested | fixture-tested | fixture-tested | unsupported | unsupported | fixture-tested |
| Hermes Agent | `hermes` | fixture-tested | fixture-tested | fixture-tested | fixture-tested | unsupported | unsupported | fixture-tested |
| Claude Code | `claude_code` | fixture-tested | fixture-tested | fixture-tested | fixture-tested | unsupported | unsupported | fixture-tested |
| Cursor | `cursor` | fixture-tested | fixture-tested | fixture-tested | fixture-tested | unsupported | unsupported | fixture-tested |
| Cline | `cline` | fixture-tested | fixture-tested | fixture-tested | fixture-tested | unsupported | unsupported | fixture-tested |
| Mastra | `mastra` via `--wrap <path>` generic MCP config | fixture-tested | fixture-tested | fixture-tested | fixture-tested | unsupported | unsupported | fixture-tested |
| Generic MCP | `generic_mcp` via `--wrap <path>` | fixture-tested | fixture-tested | fixture-tested | fixture-tested | unsupported | unsupported | fixture-tested |
| Other MCP-compatible harness | `other` via `--wrap <path>` | fixture-tested through Generic MCP | fixture-tested through Generic MCP | fixture-tested through Generic MCP | fixture-tested through Generic MCP | unsupported | unsupported | fixture-tested through Generic MCP |
| LangGraph | v1.1+ planned through `generic_mcp` | fixture-tested through Generic MCP | fixture-tested through Generic MCP | fixture-tested through Generic MCP | fixture-tested through Generic MCP | unsupported | unsupported | fixture-tested through Generic MCP |

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

The current `runWrap` implementation does not create an agent identity file or initialize an audit genesis entry during wrap. The README says a portable identity is created and the audit trail is initialized as wrap effects, so those two cells are marked unsupported until the feature code lands. This workstream does not change feature code.
