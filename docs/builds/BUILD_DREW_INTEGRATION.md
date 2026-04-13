---
review_status: pending
created: 2026-04-13
reviewed_date:
type: build-spec
handoff_to: claude-code
---

# Sanctuary — Drew Integration Build Spec

**Scope:** Documentation + small code changes surfaced by Drew's Lobster evaluation report.
**Prerequisite:** Erik approves this spec. Then hand to a Claude Code build session.
**Repo:** `~/Desktop/Claude/Sanctuary`
**Branch:** `drew-integration-docs` (off main)
**Estimated size:** ~6 files changed/added, 0 architectural changes.

---

## Pre-flight

```bash
cd ~/Desktop/Claude/Sanctuary/server
npm run typecheck && npm test
# Record baseline: expect 1079+ passing, .test-baseline file is the gate
```

---

## Task 1: Deployment Guide for Persistent Agents

**File:** `server/docs/DEPLOYMENT.md` (NEW)

**Content:** A practical guide for running Sanctuary as a long-lived service alongside another MCP server (the Drew/Lobster use case, but generalized). Sections:

1. **System requirements** — Node.js >= 22.0.0, npm >= 10.0.0
2. **Installation options** — npx (dev/testing only), global install, local project install (recommended for production). Explain tradeoffs:
   - npx: always latest, but network-dependent on every cold start. Bad for systemd restart loops.
   - global: faster startup, but version pinning is manual (`npm install -g @sanctuary-framework/mcp-server@0.7.0`).
   - local project install: **recommended for persistent services.** Pin exact version, no network on restart, update deliberately.
3. **Passphrase management** — Generate with `openssl rand -base64 32`. Store in a gitignored env file with `chmod 600`. Reference the env file from systemd `EnvironmentFile=`. **Include a WARNING block:** if the passphrase is lost, all encrypted state is unrecoverable by design. Back up to a separate secrets manager, encrypted USB, or password vault.
4. **Parallel MCP server configuration** — Show the JSON config for running Sanctuary alongside another MCP server in a Claude Code session:
   ```json
   {
     "mcpServers": {
       "other-server": { "url": "http://localhost:8766/mcp" },
       "sanctuary": {
         "command": "npx",
         "args": ["@sanctuary-framework/mcp-server"],
         "env": { "SANCTUARY_PASSPHRASE": "your-passphrase-here" }
       }
     }
   }
   ```
   And the local-install variant:
   ```json
   {
     "mcpServers": {
       "sanctuary": {
         "command": "node",
         "args": ["./sanctuary/node_modules/.bin/sanctuary-mcp-server"],
         "env": { "SANCTUARY_PASSPHRASE": "your-passphrase-here" }
       }
     }
   }
   ```
5. **systemd service unit** — Provide a working `sanctuary-mcp.service` unit file. Use `EnvironmentFile=%h/.config/sanctuary/sanctuary.env`. `Restart=on-failure`, `RestartSec=5s`. Include both npx and local-install variants of `ExecStart`.
6. **Bootstrap and first run** — After install, run `sanctuary_bootstrap` to create identity. Run `sovereignty_audit` for baseline score.
7. **Rollback** — `claude mcp remove sanctuary`. If Cocoon was enabled, `npx @sanctuary-framework/mcp-server cocoon --unwrap`.
8. **Principal Policy for always-on agents** — Reference the new template (Task 2).

**Voice:** Direct, practical, no philosophy. This is for someone who runs servers.

---

## Task 2: Principal Policy Template for Always-On Agents

**File:** `server/src/principal-policy/templates/persistent-agent.yaml` (NEW)

**Purpose:** A Principal Policy template optimized for always-on agents like Lobster, where the dispatcher has a latency SLA (e.g., 7 seconds). Auto-allows all non-destructive operations. Only gates truly irreversible or external-facing operations.

**Content:**

```yaml
# Principal Policy: Persistent Agent
# Optimized for always-on agents with latency constraints.
# Auto-allows routine operations. Gates only destructive/external actions.
#
# Tier 1 (always require human approval):
#   - state_export, state_import (data portability — irreversible if imported over existing)
#   - identity_rotate (key rotation — old key destroyed)
#   - state_delete with secure_delete (3-pass overwrite — unrecoverable)
#   - reputation_import (external trust injection)
#   - governor_reset (resets all rate limiting)
#
# Tier 2 (approval on anomaly):
#   - reputation_record (new attestation — but only on anomaly)
#   - federation_peers with action: register (new peer trust)
#
# Tier 3 (auto-allow with audit logging):
#   - Everything else: state_read, state_write, state_list, identity_create,
#     identity_sign, identity_verify, identity_list, identity_set_primary,
#     all context_gate_* tools, all handshake_* tools, shr_generate, shr_verify,
#     sovereignty_audit, all disclosure_* tools, all proof_* tools, all zk_* tools,
#     reputation_query, reputation_query_weighted, reputation_publish,
#     bootstrap_create_escrow, bootstrap_provide_guarantee,
#     sanctuary_bootstrap, policy_status, export_identity_bundle,
#     link_to_human, sign_challenge, l2_hardening_status, l2_verify_isolation,
#     governor_status, context_gate_enforcer_status, context_gate_enforcer_configure,
#     all bridge_* tools, all shr_* tools, federation_trust_evaluate, federation_status

version: "1.0"
name: "persistent-agent"
description: "For always-on agents with latency constraints. Auto-allows routine ops."

tiers:
  tier1:
    operations:
      - state_export
      - state_import
      - identity_rotate
      - governor_reset
    rules:
      - match: "state_delete"
        condition: "params.secure_delete == true"
      - match: "reputation_import"

  tier2:
    operations:
      - reputation_record
    rules:
      - match: "federation_peers"
        condition: "params.action == 'register'"

  tier3:
    default: allow
    audit: true
```

**Also:** Register this template in the template loader so it can be applied via `--policy-template persistent-agent` CLI flag or referenced in docs. Check how existing templates are loaded (look at `server/src/principal-policy/loader.ts` and any existing template files).

---

## Task 3: Dashboard Port Documentation Fix

**Files:** `server/README.md`

**Change:** Audit all references to the dashboard port. Ensure every mention says `3501` (the actual default from `config.ts` line 129). If any reference says `3000` or `localhost:3000`, fix it.

Also check: `server/docs/`, `SANCTUARY_PROJECT_CONTEXT.md` (which says 3501 in the dashboard section — confirm).

This is a grep-and-fix task:
```bash
grep -rn "3000" server/README.md server/docs/ --include="*.md"
grep -rn "localhost:3000" . --include="*.md" --include="*.ts"
```

---

## Task 4: `sanctuary_bootstrap` Passphrase Backup Warning

**File:** `server/src/tools/meta-tools.ts` (or wherever `sanctuary_bootstrap` is implemented — find it)

**Change:** After `sanctuary_bootstrap` successfully creates an identity and prints the DID/profileUrl/tier output, append a warning message:

```
⚠️  IMPORTANT: Your Sanctuary passphrase is the only way to decrypt your agent's state.
   If lost, all encrypted data is unrecoverable by design. Back up your passphrase now
   to a password manager, encrypted USB, or other secure location separate from this machine.
```

This is a string addition to the tool's success response. No logic changes.

**Test:** Add a test asserting the bootstrap response includes the backup warning text. Something like:
```typescript
it('includes passphrase backup warning in bootstrap response', async () => {
  const result = await callTool('sanctuary_bootstrap', { ... });
  expect(result.content[0].text).toContain('passphrase');
  expect(result.content[0].text).toContain('unrecoverable');
});
```

---

## Task 5: Integration Example — Parallel MCP Config

**File:** `server/docs/examples/parallel-mcp-config.json` (NEW)

**Content:** A reference MCP config file showing Sanctuary running alongside a generic second MCP server:

```json
{
  "mcpServers": {
    "your-agent-server": {
      "command": "your-agent-command",
      "args": ["--your-flags"],
      "env": {}
    },
    "sanctuary": {
      "command": "node",
      "args": ["./node_modules/.bin/sanctuary-mcp-server"],
      "env": {
        "SANCTUARY_PASSPHRASE": "${SANCTUARY_PASSPHRASE}",
        "SANCTUARY_DASHBOARD_ENABLED": "true"
      }
    }
  }
}
```

Add a short README in `server/docs/examples/` explaining the pattern.

---

## Task 6: README — Add "Running Alongside Another MCP Server" Section

**File:** `server/README.md`

**Change:** After the existing installation/configuration section, add a short section titled "Running Alongside Another MCP Server" that:

1. Explains Sanctuary is designed to run as a parallel MCP server, not a replacement for your agent's tools
2. Links to `docs/DEPLOYMENT.md` for the full guide
3. Links to `docs/examples/parallel-mcp-config.json` for the reference config
4. Mentions the persistent-agent policy template for always-on agents

Keep it to ~10-15 lines. Don't over-explain.

---

## Breaking Changes to Consider

**None in this build.** All changes are additive (new docs, new template, new warning string). No tool signatures change. No config formats change. No existing behavior changes.

**Flag for future:** If we decide to change the default dashboard port or add mandatory passphrase backup prompts to the CLI entrypoint, those would be behavioral changes. Not in this build.

---

## Post-flight

```bash
cd ~/Desktop/Claude/Sanctuary/server
npm run typecheck && npm test
# Confirm passing count >= .test-baseline
# If new test added (Task 4), count should be baseline + 1
```

Then:
```bash
git add -A
git commit -m "docs: deployment guide, persistent-agent policy, parallel MCP examples

Adds:
- server/docs/DEPLOYMENT.md — full guide for running Sanctuary as a persistent service
- server/src/principal-policy/templates/persistent-agent.yaml — policy template for always-on agents
- server/docs/examples/ — parallel MCP config reference
- sanctuary_bootstrap passphrase backup warning
- Dashboard port documentation audit (3501, not 3000)
- README section on parallel MCP server operation

Motivated by Drew/Lobster integration evaluation (2026-04-12).

Co-Authored-By: Claude <noreply@anthropic.com>"
```

Do NOT bump version. Do NOT publish to npm. This is a docs/DX build, not a release.

---

*This spec is a handoff document. The build session executes from it. The research session (this one) does not make code changes.*
