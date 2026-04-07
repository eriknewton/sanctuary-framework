# Cocoon v0.7.0 — Smoke Test Results

**Date:** 2026-04-06
**Baseline:** 894 tests passing across 60 files (v0.6.1)

---

## What Works

| Component | Status | Evidence |
|-----------|--------|----------|
| `ClientManager` connection lifecycle | WORKS | Tested via unit tests; connects stdio/SSE, reconnects with backoff, shuts down cleanly |
| `ProxyRouter` enforcement chain | WORKS | 20 unit tests: injection block/escalate, context gate, governor block/cache, forward, error pass-through, timeout |
| `SovereigntyProfileStore` upstream registry | WORKS | 19 unit tests: CRUD, validation, persistence, tier overrides, env vars |
| `ProxyRouter.parseProxyToolName` | WORKS | Parses `proxy/{server}/{tool}`, handles nested slashes |
| Tool namespacing (`proxy/{server}/{tool}`) | WORKS | Unit tested — no collision with `sanctuary/*` tools |
| Tier resolution (override > default > fallback) | WORKS | Unit tested |
| Dashboard proxy status SSE events | WORKS | `proxy-server-status` events broadcast on state change |
| Dashboard `/api/proxy/servers` GET/POST | WORKS | Handlers in `dashboard.ts` merge config with live status |
| Dashboard upstream servers panel HTML/JS | WORKS | Add/remove server UI, expand tool list, status badges |
| Injection detection in proxy chain | WORKS | Block and escalate paths tested |
| CallGovernor in proxy chain | WORKS | Rate limit, volume cap, duplicate cache tested |
| Response normalization (SEC-046) | WORKS | 1MB total, 100KB per block, truncation |
| Error sanitization (SEC-050) | WORKS | Path redaction, connection string redaction |

## What Doesn't Work (End-to-End Gaps)

| Gap | Impact | Fix Required |
|-----|--------|-------------|
| **No CLI entry point for Cocoon mode** | Users must manually create `sanctuary.json` profile with upstream servers, then run `sanctuary-mcp-server` — no `npx` one-liner | Phase 2: Build `sanctuary-cocoon` CLI |
| **No Fortress View** | Dashboard shows developer-facing panels, not a human-friendly "is my agent safe?" summary | Phase 3: Build Fortress View |
| **No tool auto-classification** | All upstream tools get the server's `default_tier` unless manually overridden per-tool | Phase 4: Heuristic tier assignment |
| **No zero-config defaults for Cocoon** | Default profile has no upstream servers, no governor limits, audit ON but no protective posture | Phase 4: Opinionated defaults |
| **Dashboard doesn't show live tool call feed** | SSE events for `proxy-server-status` exist, but no feed of individual tool call decisions | Phase 3: Live feed in Fortress View |
| **No `--unwrap` rollback** | No mechanism to restore original agent config | Phase 2: Backup/restore |
| **No agent config detection** | No code to read OpenClaw/Claude Code/Cursor MCP configs | Phase 2: Config readers |

## Architecture Assessment

The proxy infrastructure is **complete and well-tested at the unit level**. The gaps are all UX:
1. No CLI to set it up (Phase 2)
2. No human-friendly dashboard view (Phase 3)
3. No smart defaults (Phase 4)
4. No integration tests proving the full chain (Phase 5)

The fix path is additive — no existing code needs to be rewritten.
