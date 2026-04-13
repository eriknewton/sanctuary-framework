# BUILD: Cocoon v0.7.0 — "One Command, My Agent Is Safe"

**Goal:** A normal person (or enterprise) can wrap any existing MCP-compatible agent in Sanctuary's enforcement chain with a single command and see what's happening through a dashboard. No MCP plumbing knowledge required.

**Thesis:** Sanctuary's architecture is excellent. The UX is the gap. This build closes it.

**Constraint:** No new sovereignty tools. No new cryptographic features. This is purely about making the existing 67 tools and the proxy infrastructure usable by someone who doesn't know what an MCP server is.

---

## What Exists (v0.6.1 — inventory before building)

Already built and tested:

- `ClientManager` — MCP client connections to upstream servers, stdio + SSE transport, exponential backoff reconnect, tool discovery (416 lines)
- `ProxyRouter` — enforcement chain: injection scan → gate → context gate → governor → forward → audit (344 lines)
- `SovereigntyProfileStore` — encrypted profile with upstream server registry, feature toggles (278 lines)
- Dashboard HTML — upstream servers panel, add/remove, SSE status events, proxy server management JS
- Integration in `index.ts` — proxy initializes on startup if upstream_servers configured
- Tests — `proxy-router.test.ts`, `upstream-registry.test.ts`
- Injection detector, outbound scanner, CallGovernor, context gate — all wired and tested
- 867 tests passing across 56 files

**Known gap (Erik, 2026-04-04):** "Cocoon mode doesn't actually work end-to-end from a human user's perspective."

---

## The Build (5 phases, ordered by dependency)

### Phase 1: End-to-End Smoke Test (prerequisite — know what's broken)

Before writing new code, verify what actually works and what doesn't.

1. Start Sanctuary MCP server with a sovereignty profile that has one upstream server (use a simple echo MCP server or the filesystem MCP server as the upstream)
2. Verify: does the ClientManager connect? Does tool discovery work? Do proxied calls route through enforcement? Does the dashboard show the upstream server status?
3. Document every failure point. This determines the rest of the build.

**Output:** `COCOON_SMOKE_RESULTS.md` — what works, what doesn't, what blocks end-to-end.

### Phase 2: `sanctuary-cocoon` CLI Wrapper

The single-command UX. A new executable (or subcommand of the existing CLI) that:

```bash
npx @sanctuary-framework/cocoon --wrap /path/to/agent-config.json
```

Or for the common case (wrapping an OpenClaw agent):

```bash
npx @sanctuary-framework/cocoon --openclaw
```

**What it does:**

1. Reads the agent's existing MCP server configuration (OpenClaw's `config.json`, Claude Code's `settings.json`, or a generic MCP config)
2. Generates a `sanctuary.json` sovereignty profile with:
   - All existing MCP servers listed as upstream servers (default Tier 2 — anomaly-gated)
   - Audit logging ON, injection detection ON, approval gate ON for Tier 1, context gating OFF (can enable later)
   - Ed25519 keypair generated (reuse quickstart identity if exists at `~/.sanctuary/quickstart-identity.json`)
3. Rewrites the agent's MCP config so the agent connects ONLY to Sanctuary, and Sanctuary proxies everything else
4. Starts the Sanctuary MCP server in Cocoon mode
5. Opens the dashboard in the default browser
6. Prints: "Your agent is now protected. Dashboard: http://localhost:3000. All tool calls are being logged and scanned."

**Rollback:** `sanctuary-cocoon --unwrap` restores the original agent config from backup.

**Key design decisions:**
- The original config is backed up to `~/.sanctuary/backup/` before any modification
- The CLI detects the agent platform (OpenClaw, Claude Code, Cursor, generic) and knows where each stores its MCP config
- If no config is provided, interactive mode asks which MCP servers to protect

### Phase 3: Dashboard "Fortress View"

The dashboard exists but is developer-facing. Make it human-facing.

**New default view: Fortress View**

A single-screen summary that answers three questions:
1. **Is my agent safe?** — Green/yellow/red overall status based on sovereignty health
2. **What is my agent doing?** — Live feed of tool calls (server, tool, decision, timestamp) — last 50, auto-scrolling
3. **What needs my attention?** — Pending Tier 1 approvals, anomaly alerts, injection detections

**Changes to existing dashboard:**
- Make Fortress View the default landing page (current detailed panels become "Advanced" tab)
- Add approval action buttons directly in the feed: "Approve" / "Deny" for pending Tier 1 calls
- Add a "Pause Agent" button — sets all upstream servers to Tier 1 (everything requires approval) as an emergency brake
- Show plain-English descriptions instead of technical tier numbers: "Requires your approval" / "Auto-monitored" / "Auto-allowed"

### Phase 4: Zero-Config Defaults That Actually Protect

The sovereignty profile defaults need to be opinionated enough to provide real protection out of the box:

- **Audit logging:** ON (non-negotiable, cannot be disabled)
- **Injection detection:** ON with default patterns
- **Outbound content scanning:** ON (catches secret leakage, internal path exposure)
- **Approval gate:** ON for Tier 1 operations (file system writes, network calls to new domains, credential access)
- **CallGovernor:** ON with default limits (200/10min volume, 20/min per-tool rate, 1000 lifetime)
- **Auto-tier assignment:** New/unknown upstream tools default to Tier 2. The CLI can pre-classify known safe tools (e.g., filesystem read → Tier 3, filesystem write → Tier 2, shell exec → Tier 1)

**Tool auto-classification heuristics:**
- Tools with "write", "delete", "exec", "run", "send", "post" in name → Tier 1 (requires approval)
- Tools with "read", "get", "list", "search", "query" in name → Tier 3 (auto-allow)
- Everything else → Tier 2 (anomaly-monitored)

### Phase 5: Integration Testing + Docs

1. **Integration test:** Full end-to-end — start Sanctuary with Cocoon wrapping a mock MCP server, send tool calls from a mock agent, verify enforcement chain fires, verify dashboard reflects state
2. **Integration test with real harness:** Test with OpenClaw filesystem MCP server as upstream
3. **README update:** New "Cocoon Mode" section in main README with the one-command flow
4. **Quickstart update:** Add Cocoon as the recommended next step after quickstart identity

---

## What This Does NOT Include (deferred)

- Per-upstream rate limiting (SEC-049 — still deferred)
- Remove tool_overrides from UpstreamServer (SEC-060 — still deferred)
- SIEM export (CEF/OCSF — separate roadmap item)
- Concordia bridge in Cocoon mode (works but not highlighted in this build)
- Mobile/responsive dashboard (desktop-first for v0.7.0)

---

## Success Criteria

The build is done when this scenario works:

1. User has an OpenClaw agent running with 3 MCP servers (filesystem, web search, database)
2. User runs `npx @sanctuary-framework/cocoon --openclaw`
3. Sanctuary starts, connects to all 3 upstream servers, dashboard opens
4. User sees live feed of their agent's tool calls with green/yellow/red status
5. Agent tries to execute a shell command → dashboard shows Tier 1 approval request → user approves or denies
6. Agent tries to read a file → auto-allowed (Tier 3) → appears in feed as green
7. Injection attempt in tool arguments → blocked → appears in feed as red with explanation
8. User runs `sanctuary-cocoon --unwrap` → original config restored, Sanctuary stops

**Test count target:** maintain 867+ baseline, add ≥20 new tests for CLI + integration.

---

## Estimated Effort

| Phase | Effort | Dependencies |
|-------|--------|-------------|
| Phase 1: Smoke test | 1 hour | None |
| Phase 2: CLI wrapper | 3-4 hours | Phase 1 results |
| Phase 3: Fortress View | 3-4 hours | Phase 1 (dashboard must work) |
| Phase 4: Zero-config defaults | 1-2 hours | Phase 2 (needs CLI to test) |
| Phase 5: Integration tests + docs | 2-3 hours | All phases |
| **Total** | **~12 hours** | |

This is a single focused sprint. No architectural changes, no new cryptographic features — just making what exists usable.
