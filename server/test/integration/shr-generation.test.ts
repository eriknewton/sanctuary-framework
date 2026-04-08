/**
 * Integration Test: SHR Generation & Verification
 *
 * Validates the end-to-end SHR flow that the v0.4.0 field report
 * identified as a regression risk during upgrades:
 *
 * 1. Create an identity
 * 2. Generate a signed SHR
 * 3. Verify the SHR contains all required fields (including implementation metadata)
 * 4. Verify the SHR signature is valid
 * 5. Export via gateway adapter
 *
 * This test should catch any future regression where SHR tools become
 * unavailable or produce invalid output after a version upgrade.
 */

import { describe, it, expect } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/l1-cognitive/state-store.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { createL1Tools } from "../../src/l1-cognitive/tools.js";
import { createSHRTools } from "../../src/shr/tools.js";
import { defaultConfig } from "../../src/config.js";

/**
 * Helper: invoke an MCP tool handler by name and return parsed JSON result.
 */
async function callTool(
  tools: Array<{
    name: string;
    handler: (args: Record<string, unknown>) => Promise<{
      content: Array<{ type: string; text: string }>;
    }>;
  }>,
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((t) => t.name === name);
  if (!tool) throw new Error(`Tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text);
}

describe("SHR Generation Integration", () => {
  it("generates a signed SHR with implementation metadata and verifies it", async () => {
    // ── Setup ─────────────────────────────────────────────────────────
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const stateStore = new StateStore(storage, masterKey);
    const auditLog = new AuditLog(storage, masterKey);
    const config = defaultConfig();

    const { tools: l1Tools, identityManager } = createL1Tools(
      stateStore, storage, masterKey, "test-recovery-key", auditLog
    );
    await identityManager.load();

    const { tools: shrTools } = createSHRTools(
      config, identityManager, masterKey, auditLog
    );

    const allTools = [...l1Tools, ...shrTools];

    // ── Step 1: Create an identity ────────────────────────────────────
    const identity = await callTool(allTools, "identity_create", {
      label: "shr-test-identity",
    });
    expect(identity.identity_id).toBeDefined();
    expect(identity.public_key).toBeDefined();

    // ── Step 2: Generate SHR ──────────────────────────────────────────
    const shr = await callTool(allTools, "shr_generate", {
      identity_id: identity.identity_id as string,
      validity_minutes: 60,
    });

    // ── Step 3: Verify structure ──────────────────────────────────────
    expect(shr.body).toBeDefined();
    expect(shr.signed_by).toBeDefined();
    expect(shr.signature).toBeDefined();

    const body = shr.body as Record<string, unknown>;
    expect(body.shr_version).toBe("1.0");
    expect(body.instance_id).toBe(identity.identity_id);
    expect(body.generated_at).toBeDefined();
    expect(body.expires_at).toBeDefined();

    // Verify implementation metadata (added post-v0.4.0 field report)
    const impl = body.implementation as Record<string, unknown>;
    expect(impl).toBeDefined();
    expect(impl.sanctuary_version).toBeDefined();
    expect(typeof impl.sanctuary_version).toBe("string");
    expect(impl.node_version).toBeDefined();
    expect(impl.generated_by).toBe("sanctuary-mcp-server");

    // Verify all four layers are present
    const layers = body.layers as Record<string, unknown>;
    expect(layers.l1).toBeDefined();
    expect(layers.l2).toBeDefined();
    expect(layers.l3).toBeDefined();
    expect(layers.l4).toBeDefined();

    // Verify capabilities
    const caps = body.capabilities as Record<string, unknown>;
    expect(caps.handshake).toBe(true);
    expect(caps.shr_exchange).toBe(true);
    expect(caps.reputation_verify).toBe(true);

    // ── Step 4: Verify signature ──────────────────────────────────────
    const verification = await callTool(allTools, "shr_verify", {
      shr: shr,
    });
    expect(verification.valid).toBe(true);
    expect(verification.errors).toEqual([]);

    // ── Step 5: Gateway export ────────────────────────────────────────
    const gatewayExport = await callTool(allTools, "shr_gateway_export", {
      identity_id: identity.identity_id as string,
      format: "generic",
    });
    expect(gatewayExport.sovereignty_score).toBeDefined();
    expect(gatewayExport.trust_level).toBeDefined();
  });

  it("shr_generate tool is registered and discoverable", async () => {
    // This test simply verifies the tool exists in the tool surface.
    // If this fails after an upgrade, the MCP server registration is broken.
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const config = defaultConfig();
    const stateStore = new StateStore(storage, masterKey);

    const { identityManager } = createL1Tools(
      stateStore, storage, masterKey, "test-recovery-key", auditLog
    );
    await identityManager.load();

    const { tools } = createSHRTools(config, identityManager, masterKey, auditLog);

    const toolNames = tools.map((t) => t.name);
    expect(toolNames).toContain("shr_generate");
    expect(toolNames).toContain("shr_verify");
    expect(toolNames).toContain("shr_gateway_export");
    expect(toolNames).toHaveLength(3);
  });
});
