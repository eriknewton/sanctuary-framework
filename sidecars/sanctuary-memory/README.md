# Sanctuary Memory Provider

This sidecar is the Microsoft Agent Framework memory provider (SDW-backed).
It exposes `SanctuaryContextProvider`, a Python provider that follows the
documented `before_run` / `after_run` `ContextProvider` lifecycle and stores
long-term memory through Sanctuary's existing SDW MCP memory tools:

- `memory_insert`
- `memory_get`
- `memory_search`
- `memory_list`
- `memory_count`
- `memory_delete`

It does not add a new TypeScript transport. The production path is MCP-stdio to
the existing Sanctuary MCP server. Tests inject a stubbed in-process
`MemoryToolClient` and never spawn a real server.

## Conformance Honesty

The provided build venv cannot import either Microsoft package:

- `agent_framework`: unavailable
- `agent_framework_core`: unavailable

Network installation is disabled for this build, so live Microsoft subclassing
is **UNVERIFIED**. The class is structured to subclass
`agent_framework.ContextProvider` when that import is present, but this change
only verifies the documented lifecycle contract and the SDW six-tool mapping
against an in-process fake.

Do not describe this as verified live Microsoft Agent Framework runtime
conformance until a coordinator runs the deferred live package check and runtime
exercise in an environment where the package is available.

## Usage

Live Sanctuary MCP-stdio usage:

```python
from sanctuary_memory import SanctuaryContextProvider

provider = SanctuaryContextProvider(
    server_command=["node", "./server/dist/cli.js", "mcp"],
    server_cwd="/path/to/Sanctuary",
    operator_id="operator-id",
    agent_id="agent-id",
)

# Intended Microsoft Agent Framework shape:
# agent = Agent(context_providers=[provider])
```

The live command above is illustrative. This build did not spawn a real
Sanctuary server because first-run boot on macOS can invoke keychain flows. The
coordinator-owned live round-trip must use a pre-seeded, keychain-free fortress.

Offline interface-shaped demo:

```bash
./.sdw-build-venv/bin/python sidecars/sanctuary-memory/examples/interface_shaped_demo.py
```

## Provider Behavior

`before_run`:

1. Resolves the Microsoft session id.
2. Builds the SDW session tag `session_id:<hash>`.
3. Calls `memory_search` with the query and session tag.
4. Calls `memory_get` for each search hit.
5. Recomputes the SDW content hash and fails closed on mismatch.
6. Injects `sanctuary_memory_context` and `sanctuary_memories` into `state` and
   mapping-like `context` objects.

`after_run`:

1. Reads explicit `sanctuary_memory_items` or `sanctuary_memory_text` from
   state or context.
2. Adds SDW tags for Microsoft memory type, session, and agent.
3. Calls `memory_insert` with a persistable taint.
4. Raises `MemoryWriteRejected` if SDW returns the fixed denial payload.
5. Verifies the returned content hash.

`request_delete`:

1. Calls `memory_delete`.
2. If Sanctuary's Tier-1 gate denies the operation, returns
   `pending_operator_approval`.
3. Never auto-approves deletion.

## Memory Type Tags

The provider emits the profile tags:

- `mem_type:procedural`
- `mem_type:user-profile`
- `mem_type:chat-summary`

It also emits:

- `ms_agent_framework`
- `sdw_context_provider`
- `session_id:<hash>`
- `agent_id:<hash>`

The current shipped MCP `memory_insert` tool does not accept metadata, so the
provider exposes profile metadata in its write result for future bindings that
can pass metadata through directly.

## Testing

Run from the repository root:

```bash
./.sdw-build-venv/bin/python -m pytest sidecars/sanctuary-memory
```

The tests use a fake six-tool MCP layer. They assert:

- store and retrieve round-trip mapping;
- session tag and owner scope derivation;
- content-hash verification;
- secret-bearing writes are rejected by the stubbed write gate;
- delete reports pending operator approval;
- no-memory `after_run` still reaches the audited MCP layer via `memory_count`.

No test invokes the macOS `security` tool. No test spawns a Sanctuary MCP or
dashboard server.

## Deferred

- Live MCP-stdio end-to-end round-trip against a pre-seeded keychain-free
  Sanctuary fortress.
- Live Microsoft Agent Framework subclass/runtime verification.
- `HistoryProvider` with lossless `Message` fidelity.
- .NET `AIContextProvider`.
- STATE-Bench effectiveness measurement.
- Operator-run TTL sweep tool with Tier-1 write gate treatment.
