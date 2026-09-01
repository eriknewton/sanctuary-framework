# Migrating from Sanctuary v0.3.x to v0.4.0

## Quick summary

v0.4.0 is **backwards compatible**. All v0.3.x MCP tools continue to work with the same names and parameters. This release adds decommissioning, hardening, gateway export, and context-gating tools, and introduces optional Concordia Protocol composition.

No breaking changes to:
- Tool interface (names, parameters, return types)
- SHR format (still v1.0, same schema)
- Identity system (same Ed25519 keys, same DIDs)
- Handshake protocol (same 4-step flow)
- Configuration format

## What's new

| Category | New tools | Count |
|----------|-----------|-------|
| Decommissioning | `decommission_certificate`, `decommission_verify` | 2 |
| Operational Isolation Hardening | `l2_hardening_status`, `l2_verify_isolation` | 2 |
| SHR Gateway | `shr_gateway_export` | 1 |
| Context Gating | `context_gate_set_policy`, `context_gate_filter`, `context_gate_apply_template`, `context_gate_list_policies`, `context_gate_recommend` | 5 |

The Concordia Bridge tools (`bridge_commit`, `bridge_verify`, `bridge_attest`) were added in v0.3.1 late commits and are also present.

**Total tool surface:** expanded in v0.4.0; current releases expose 80+ MCP tools.

## Upgrade steps

### 1. Update the package

```bash
npm install -g @sanctuary-framework/mcp-server@0.4.0
```

Or via pipx (if using the CLI wrapper):

```bash
pipx install --upgrade @sanctuary-framework/mcp-server
```

### 2. Restart your MCP host

**This is the critical step most operators miss.** After updating the npm package, your MCP host (OpenClaw, Claude Code, etc.) must restart its gateway to re-enumerate the tool surface.

**For OpenClaw:**

```bash
openclaw gateway stop
sleep 2
openclaw gateway start
```

**For Claude Code:**

Close and reopen Claude Code, or restart the Claude Code process:

```bash
# On macOS
killall Claude Code 2>/dev/null || true
# Then open Claude Code again
```

**For other MCP hosts:**

Refer to the host's documentation for gateway restart. The key is that the MCP client must request a fresh tool enumeration from the Sanctuary server.

### 3. Verify the tool surface

After restarting, verify that the Sanctuary tools are available:

```bash
# List all Sanctuary tools (requires MCP host running)
claude --dangerously-skip-permissions -p "List all sanctuary tools available to you"
```

You should see the v0.4.0-era core tools plus the new decommissioning, hardening, gateway export, and context-gating tools. Current releases expose 80+ MCP tools.

If you only see 4 tools (the Concordia bridge tools), the Sanctuary MCP server didn't reconnect. See "Common issues" below.

### 4. (Optional) Configure the Concordia Bridge

If you also run Concordia Protocol alongside Sanctuary, you can enable the bridge to compose Sanctuary commitment and reputation payloads from Concordia negotiations.

**Prerequisites:**
- Concordia Protocol v0.1.0+ running
- Your agent registered with Concordia (`concordia_register_agent`)

**Setup steps:**

1. Get your Concordia agent ID and auth token:
   ```bash
   concordia_agent_status
   # Note: agent_id and auth_token from output
   ```

2. Get your Sanctuary identity ID and DID:
   ```bash
   sanctuary --identity-status
   # Note: identity_id and did from output
   ```

3. Configure the bridge:
   ```bash
   claude -p "Configure the Concordia-Sanctuary bridge:
     - Concordia agent ID: [your_agent_id]
     - Concordia auth token: [your_auth_token]
     - Sanctuary identity ID: [your_identity_id]
     - Sanctuary DID: [your_did]"
   ```

4. Verify the bridge is active:
   ```bash
   claude -p "Check the Concordia-Sanctuary bridge status"
   ```

   Output should show: `enabled: true, connected: true`

**The bridge is entirely optional.** Sanctuary functions fully without it. The bridge is only needed if you want Concordia negotiations to produce Sanctuary-signed commitments and reputation portability.

## Common issues

### Issue: "I can only see 4 Sanctuary tools after upgrading"

**Root cause:** The Sanctuary MCP server didn't reconnect after the upgrade. You're seeing only the Concordia bridge tools (which are minimal connectors).

**Solution:**

1. Verify the binary was updated:
   ```bash
   which sanctuary-mcp-server
   # Should be in /usr/local/bin/ or ~/.nvm/versions/...

   npm list -g @sanctuary-framework/mcp-server
   # Should show v0.4.0
   ```

2. Check your MCP host config points to the correct path:
   - **OpenClaw:** `~/.clawhub/mcp-config.json` → `sanctuary_server.command` should point to the updated binary
   - **Claude Code:** `~/.claude/mcp-config.json` → same check

3. Fully restart the gateway (not just refresh):
   ```bash
   openclaw gateway stop
   sleep 3
   openclaw gateway start
   ```

4. Verify again:
   ```bash
   claude -p "List all available sanctuary tools"
   ```

### Issue: "SHR generation fails: 'sanctuary/shr_generate' not found"

**Root cause:** The Sanctuary MCP server isn't registered. This tool has **not been removed** - it's a gateway registration issue (same as "only 4 tools" above).

**Solution:** Follow the steps in "I can only see 4 Sanctuary tools" above. Once the gateway sees the Sanctuary tool surface, `shr_generate` will work.

### Issue: "Bridge authentication fails"

**Root cause:** The Concordia bridge requires separate authentication from Sanctuary. You need:

1. A Concordia agent registration (`concordia_register_agent`) - this gives you a Concordia auth token
2. Identity mapping - connecting your Concordia agent ID to your Sanctuary identity ID and DID

**Solution:**

1. Verify Concordia is configured:
   ```bash
   concordia_agent_status
   # Should show: registered: true, agent_id: ..., auth_token: ...
   ```

2. Get your Sanctuary identity:
   ```bash
   sanctuary --identity-status
   # Should show: identity_id: ..., did: ...
   ```

3. Reconfigure the bridge with correct credentials:
   ```bash
   claude -p "Bridge configure:
     agent_id=[output from concordia_agent_status]
     auth_token=[output from concordia_agent_status]
     sanctuary_identity_id=[output from sanctuary --identity-status]
     sanctuary_did=[output from sanctuary --identity-status]"
   ```

### Issue: "New context gating tools error on old policy format"

**Unlikely but possible:** If you have old context gate policies from v0.3.x, they may use a different format.

**Solution:** Regenerate policies using the new tools:

```bash
claude -p "Generate a context gating policy using context_gate_apply_template:
  - template: 'minimal-context'
  - target: 'remote-llm'
  - save to: 'my-gate-policy'"
```

## What did NOT change

- **All Castle Wall / Sentinels / Charter / Heralds tools:** same names, same parameters, same behavior
  - Example: `sanctuary/shr_generate`, `sanctuary/handshake_initiate`, `sanctuary/reputation_export` all work identically
- **SHR format:** Still v1.0, same schema, same signature verification
- **Identity system:** Same Ed25519 keys, same DID format, same recovery paths
- **Handshake protocol:** Same 4-step flow (initiate → respond → complete → status)
- **Federation tools:** Unchanged
- **Principal policy:** Unchanged
- **Audit logging:** Unchanged

## Rollback (if needed)

If you need to revert to v0.3.x for any reason:

```bash
npm install -g @sanctuary-framework/mcp-server@0.3.1
openclaw gateway stop
sleep 2
openclaw gateway start
```

This is safe - v0.4.0 does not modify your state store or configuration. Downgrading will simply hide the 10 new tools temporarily.

## Questions or issues?

- Check `KNOWN_ISSUES.md` for current limitations
- File a GitHub issue: https://github.com/eriknewton/sanctuary-framework/issues
- Read the `README.md` for general setup and troubleshooting
