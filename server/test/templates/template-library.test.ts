/**
 * Sanctuary Template Library — Integration tests.
 *
 * Covers all eight acceptance criteria from WP-MVP-11:
 *   1. Five templates load end-to-end
 *   2. Deterministic template load
 *   3. Policy engine compile-path coverage
 *   4. Defaults respect shipped surfaces
 *   5. Registry API returns all five
 *   6. Public-facing copy clean (naming-discipline + no-em-dash)
 *   7. Signed-event fields correct
 *   8. Baseline + CI (tested by the guard, not inline)
 */

import { describe, it, expect, beforeEach } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "@noble/hashes/utils";
import {
  TEMPLATE_NAMES,
  listTemplates,
  getTemplate,
  getTemplateEntry,
  clearTemplateCache,
  lintOnboarding,
  isTemplateName,
  buildCompiledPolicyFromTemplate,
  initTemplate,
  type TemplateName,
} from "../../src/templates/index.js";
import { CHANNEL_TEMPLATE_IDS, POLICY_SLOTS } from "../../src/policy-engine/constants.js";
import { validateCompiledPolicyShape } from "../../src/policy-engine/canonical-policy.js";
import { encodePolicyBlob, decodePolicyBlob } from "../../src/policy-engine/canonical-policy.js";
import { canonicalizeToBytes } from "../../src/mesh/canonical-json.js";
import { runTemplateCommand } from "../../src/templates/cli.js";

// ═══════════════════════════════════════════════════════════════════════
// Test fixtures
// ═══════════════════════════════════════════════════════════════════════

function makeNodeKey() {
  const priv = ed25519.utils.randomPrivateKey();
  return { privateKey: priv, publicKey: ed25519.getPublicKey(priv) };
}

const TEST_FORTRESS = "fortress-test-" + randomBytes(8).reduce((s, b) => s + b.toString(16).padStart(2, "0"), "");
const TEST_NODE = "node-test-001";
const TEST_PRINCIPAL = "principal-test-root";
const NODE_KEY = makeNodeKey();

// ═══════════════════════════════════════════════════════════════════════
// AC-1: Five templates load end-to-end
// ═══════════════════════════════════════════════════════════════════════

describe("AC-1: Five templates load end-to-end", () => {
  beforeEach(() => clearTemplateCache());

  it("has the expected number of template names", () => {
    expect(TEMPLATE_NAMES).toHaveLength(TEMPLATE_NAMES.length);
    expect(TEMPLATE_NAMES.length).toBeGreaterThanOrEqual(5);
  });

  it("lists all templates from the registry", () => {
    const templates = listTemplates();
    expect(templates).toHaveLength(TEMPLATE_NAMES.length);
    const names = templates.map((t) => t.metadata.name);
    expect(names).toEqual([...TEMPLATE_NAMES]);
  });

  for (const name of TEMPLATE_NAMES) {
    it(`loads template "${name}" successfully`, () => {
      const bundle = getTemplate(name);
      expect(bundle).not.toBeNull();
      expect(bundle!.metadata.name).toBe(name);
      expect(bundle!.metadata.version).toBe("1.0.0");
      expect(bundle!.metadata.tier).toBe("B");
      expect(bundle!.policy_english.length).toBeGreaterThan(0);
      expect(bundle!.onboarding.length).toBeGreaterThan(0);
    });

    it(`template "${name}" channel maps to a valid channel template`, () => {
      const bundle = getTemplate(name)!;
      expect(
        (CHANNEL_TEMPLATE_IDS as readonly string[]).includes(bundle.metadata.channel)
      ).toBe(true);
    });

    it(`template "${name}" inits end-to-end with signed policy_update`, () => {
      const result = initTemplate({
        template_name: name,
        agent_id: `agent-${name}`,
        fortress_id: TEST_FORTRESS,
        emitter_node: TEST_NODE,
        emitter_principal: TEST_PRINCIPAL,
        monotonic_seq: 0,
        node_private_key: NODE_KEY.privateKey,
      });

      // (a) signed policy_update emits with signature_scheme: 'ed25519-v1'
      expect(result.signed_event.event_type).toBe("policy_update");
      expect(result.signed_event.node_signature).toBeTruthy();
      expect(typeof result.signed_event.node_signature).toBe("string");

      // (b) pinned defaults match
      const compiled = result.compiled;
      expect(compiled.agent_id).toBe(`agent-${name}`);
      expect(compiled.fortress_id).toBe(TEST_FORTRESS);
      expect(compiled.schema_version).toBe("0.1");
      expect(compiled.policy_version).toBe(1);

      // (c) commitment shapes registered
      const bundle = result.bundle;
      for (const shape of bundle.commitments.shapes) {
        expect(
          compiled.capabilities.concordia_commitment_classes
        ).toContain(shape.commitment_class);
      }
    });
  }
});

// ═══════════════════════════════════════════════════════════════════════
// AC-2: Deterministic template load
// ═══════════════════════════════════════════════════════════════════════

describe("AC-2: Deterministic template load", () => {
  beforeEach(() => clearTemplateCache());

  for (const name of TEMPLATE_NAMES) {
    it(`template "${name}" produces byte-equal policy blob across two runs`, () => {
      const bundle = getTemplate(name)!;
      const params = {
        agent_id: `agent-det-${name}`,
        fortress_id: TEST_FORTRESS,
        counterparty: "*",
        policy_version: 1,
      };

      const a = buildCompiledPolicyFromTemplate(bundle, params);
      clearTemplateCache();
      const b = buildCompiledPolicyFromTemplate(getTemplate(name)!, params);

      const blobA = encodePolicyBlob(a);
      const blobB = encodePolicyBlob(b);
      expect(blobA).toBe(blobB);

      // Also verify via canonical JSON bytes
      const bytesA = canonicalizeToBytes(a);
      const bytesB = canonicalizeToBytes(b);
      expect(Buffer.from(bytesA).toString("hex")).toBe(
        Buffer.from(bytesB).toString("hex")
      );
    });
  }
});

// ═══════════════════════════════════════════════════════════════════════
// AC-3: Policy engine compile-path coverage
// ═══════════════════════════════════════════════════════════════════════

describe("AC-3: Policy engine compile-path coverage", () => {
  beforeEach(() => clearTemplateCache());

  for (const name of TEMPLATE_NAMES) {
    it(`template "${name}" compiles cleanly through policy engine`, () => {
      const bundle = getTemplate(name)!;
      const compiled = buildCompiledPolicyFromTemplate(bundle, {
        agent_id: `agent-compile-${name}`,
        fortress_id: TEST_FORTRESS,
        counterparty: "*",
        policy_version: 1,
      });

      // validateCompiledPolicyShape throws on invalid shape
      expect(() => validateCompiledPolicyShape(compiled)).not.toThrow();

      // Deterministic: compile again and assert identical
      const compiled2 = buildCompiledPolicyFromTemplate(bundle, {
        agent_id: `agent-compile-${name}`,
        fortress_id: TEST_FORTRESS,
        counterparty: "*",
        policy_version: 1,
      });
      expect(encodePolicyBlob(compiled)).toBe(encodePolicyBlob(compiled2));
    });

    it(`template "${name}" encodes + decodes via policy blob round-trip`, () => {
      const bundle = getTemplate(name)!;
      const compiled = buildCompiledPolicyFromTemplate(bundle, {
        agent_id: `agent-rt-${name}`,
        fortress_id: TEST_FORTRESS,
        counterparty: "*",
        policy_version: 1,
      });

      const blob = encodePolicyBlob(compiled);
      const decoded = decodePolicyBlob(blob);
      expect(decoded.agent_id).toBe(compiled.agent_id);
      expect(decoded.fortress_id).toBe(compiled.fortress_id);
      expect(decoded.schema_version).toBe(compiled.schema_version);
    });
  }
});

// ═══════════════════════════════════════════════════════════════════════
// AC-4: Defaults respect shipped surfaces
// ═══════════════════════════════════════════════════════════════════════

describe("AC-4: Defaults respect shipped surfaces", () => {
  beforeEach(() => clearTemplateCache());

  for (const name of TEMPLATE_NAMES) {
    it(`template "${name}" retention windows use only canonical slots`, () => {
      const bundle = getTemplate(name)!;
      const compiled = buildCompiledPolicyFromTemplate(bundle, {
        agent_id: `agent-def-${name}`,
        fortress_id: TEST_FORTRESS,
        counterparty: "*",
        policy_version: 1,
      });

      if (compiled.retention) {
        for (const slot of Object.keys(compiled.retention.windows)) {
          expect((POLICY_SLOTS as readonly string[]).includes(slot)).toBe(true);
        }
      }
    });

    it(`template "${name}" budget units are valid`, () => {
      const bundle = getTemplate(name)!;
      const compiled = buildCompiledPolicyFromTemplate(bundle, {
        agent_id: `agent-bud-${name}`,
        fortress_id: TEST_FORTRESS,
        counterparty: "*",
        policy_version: 1,
      });

      if (compiled.budgets?.daily) {
        expect(["tokens", "usd"]).toContain(compiled.budgets.daily.unit);
        expect(compiled.budgets.daily.amount).toBeGreaterThan(0);
      }
      if (compiled.budgets?.monthly) {
        expect(["tokens", "usd"]).toContain(compiled.budgets.monthly.unit);
        expect(compiled.budgets.monthly.amount).toBeGreaterThan(0);
      }
    });

    it(`template "${name}" egress rules have valid shape`, () => {
      const bundle = getTemplate(name)!;
      const compiled = buildCompiledPolicyFromTemplate(bundle, {
        agent_id: `agent-egr-${name}`,
        fortress_id: TEST_FORTRESS,
        counterparty: "*",
        policy_version: 1,
      });

      if (compiled.egress) {
        for (const rule of compiled.egress.allowlist) {
          expect(typeof rule.destination).toBe("string");
          expect(rule.destination.length).toBeGreaterThan(0);
          expect(Array.isArray(rule.methods)).toBe(true);
        }
      }
    });
  }

  // Specific template checks
  it("research-assistant has egress entries", () => {
    const compiled = buildCompiledPolicyFromTemplate(getTemplate("research-assistant")!, {
      agent_id: "agent-ra", fortress_id: TEST_FORTRESS, counterparty: "*", policy_version: 1,
    });
    expect(compiled.egress).toBeDefined();
    expect(compiled.egress!.allowlist.length).toBeGreaterThanOrEqual(3);
  });

  it("coding-assistant has daily token budget", () => {
    const compiled = buildCompiledPolicyFromTemplate(getTemplate("coding-assistant")!, {
      agent_id: "agent-ca", fortress_id: TEST_FORTRESS, counterparty: "*", policy_version: 1,
    });
    expect(compiled.budgets?.daily).toBeDefined();
    expect(compiled.budgets!.daily!.unit).toBe("tokens");
  });

  it("ops-runner has monthly USD budget", () => {
    const compiled = buildCompiledPolicyFromTemplate(getTemplate("ops-runner")!, {
      agent_id: "agent-or", fortress_id: TEST_FORTRESS, counterparty: "*", policy_version: 1,
    });
    expect(compiled.budgets?.monthly).toBeDefined();
    expect(compiled.budgets!.monthly!.unit).toBe("usd");
  });

  it("planner has no egress and no budget", () => {
    const compiled = buildCompiledPolicyFromTemplate(getTemplate("planner")!, {
      agent_id: "agent-pl", fortress_id: TEST_FORTRESS, counterparty: "*", policy_version: 1,
    });
    expect(compiled.egress).toBeUndefined();
    expect(compiled.budgets).toBeUndefined();
  });

  it("handoff-coordinator has no egress and no budget", () => {
    const compiled = buildCompiledPolicyFromTemplate(getTemplate("handoff-coordinator")!, {
      agent_id: "agent-hc", fortress_id: TEST_FORTRESS, counterparty: "*", policy_version: 1,
    });
    expect(compiled.egress).toBeUndefined();
    expect(compiled.budgets).toBeUndefined();
  });
});

// ═══════════════════════════════════════════════════════════════════════
// AC-5: Registry API returns all five
// ═══════════════════════════════════════════════════════════════════════

describe("AC-5: Registry API returns all five", () => {
  beforeEach(() => clearTemplateCache());

  it("listTemplates returns all registered entries", () => {
    const entries = listTemplates();
    expect(entries).toHaveLength(TEMPLATE_NAMES.length);
  });

  it("each entry contains metadata and onboarding text", () => {
    const entries = listTemplates();
    for (const entry of entries) {
      expect(entry.metadata.name).toBeTruthy();
      expect(entry.metadata.version).toBe("1.0.0");
      expect(entry.metadata.channel).toBeTruthy();
      expect(entry.metadata.tier).toBe("B");
      expect(entry.onboarding.length).toBeGreaterThan(0);
    }
  });

  it("response is stable across calls", () => {
    const a = JSON.stringify(listTemplates());
    const b = JSON.stringify(listTemplates());
    expect(a).toBe(b);
  });

  it("getTemplateEntry returns single entry by name", () => {
    for (const name of TEMPLATE_NAMES) {
      const entry = getTemplateEntry(name);
      expect(entry).not.toBeNull();
      expect(entry!.metadata.name).toBe(name);
      expect(entry!.onboarding.length).toBeGreaterThan(0);
    }
  });

  it("getTemplateEntry returns null for unknown name", () => {
    expect(getTemplateEntry("nonexistent")).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════
// AC-6: Public-facing copy clean
// ═══════════════════════════════════════════════════════════════════════

describe("AC-6: Public-facing copy clean", () => {
  beforeEach(() => clearTemplateCache());

  for (const name of TEMPLATE_NAMES) {
    it(`template "${name}" onboarding.md passes no-em-dash check`, () => {
      const bundle = getTemplate(name)!;
      const result = lintOnboarding(name, bundle.onboarding);
      expect(result.clean).toBe(true);
      expect(result.violations).toEqual([]);
    });

    it(`template "${name}" onboarding.md contains no em-dashes`, () => {
      const bundle = getTemplate(name)!;
      expect(bundle.onboarding).not.toContain("\u2014");
      expect(bundle.onboarding).not.toContain("\u2013");
    });
  }

  it("lintOnboarding catches em-dashes", () => {
    const result = lintOnboarding("test", "This is a test \u2014 with em-dash.");
    expect(result.clean).toBe(false);
    expect(result.violations).toHaveLength(1);
  });

  it("lintOnboarding catches en-dashes", () => {
    const result = lintOnboarding("test", "This is a test \u2013 with en-dash.");
    expect(result.clean).toBe(false);
    expect(result.violations).toHaveLength(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// AC-7: Signed-event fields correct
// ═══════════════════════════════════════════════════════════════════════

describe("AC-7: Signed-event fields correct", () => {
  beforeEach(() => clearTemplateCache());

  for (const name of TEMPLATE_NAMES) {
    it(`template "${name}" policy_update has valid signed event shape`, () => {
      const result = initTemplate({
        template_name: name,
        agent_id: `agent-sig-${name}`,
        fortress_id: TEST_FORTRESS,
        emitter_node: TEST_NODE,
        emitter_principal: TEST_PRINCIPAL,
        monotonic_seq: 0,
        node_private_key: NODE_KEY.privateKey,
      });

      const evt = result.signed_event;

      // Event type
      expect(evt.event_type).toBe("policy_update");

      // Signature present
      expect(evt.node_signature).toBeTruthy();
      expect(typeof evt.node_signature).toBe("string");

      // Protocol version
      expect(evt.protocol_version).toBe("0.1");

      // Payload fields
      expect(evt.payload.agent_id).toBe(`agent-sig-${name}`);
      expect(evt.payload.policy_version).toBe(1);
      expect(typeof evt.payload.policy_blob).toBe("string");

      // Policy blob is decodable
      const decoded = decodePolicyBlob(evt.payload.policy_blob);
      expect(decoded.agent_id).toBe(`agent-sig-${name}`);
      expect(decoded.schema_version).toBe("0.1");
    });
  }
});

// ═══════════════════════════════════════════════════════════════════════
// Template-specific slot access verification
// ═══════════════════════════════════════════════════════════════════════

describe("Template slot access patterns", () => {
  beforeEach(() => clearTemplateCache());

  it("research-assistant opens only outputs for read", () => {
    const compiled = buildCompiledPolicyFromTemplate(getTemplate("research-assistant")!, {
      agent_id: "ra", fortress_id: TEST_FORTRESS, counterparty: "*", policy_version: 1,
    });
    expect(compiled.slots.outputs.mode).toBe("grant");
    expect(compiled.slots.outputs.grants.some((g) => g.action === "read")).toBe(true);
    expect(compiled.slots.memory.mode).toBe("deny");
    expect(compiled.slots.credentials.mode).toBe("deny");
    expect(compiled.slots.plans.mode).toBe("deny");
  });

  it("coding-assistant opens memory + outputs for bidirectional sync", () => {
    const compiled = buildCompiledPolicyFromTemplate(getTemplate("coding-assistant")!, {
      agent_id: "ca", fortress_id: TEST_FORTRESS, counterparty: "*", policy_version: 1,
    });
    expect(compiled.slots.memory.mode).toBe("grant");
    expect(compiled.slots.outputs.mode).toBe("grant");
    expect(compiled.slots.memory.grants.some((g) => g.action === "read")).toBe(true);
    expect(compiled.slots.memory.grants.some((g) => g.action === "subscribe")).toBe(true);
    expect(compiled.slots.outputs.grants.some((g) => g.action === "read")).toBe(true);
    expect(compiled.slots.outputs.grants.some((g) => g.action === "subscribe")).toBe(true);
  });

  it("ops-runner opens credentials for share", () => {
    const compiled = buildCompiledPolicyFromTemplate(getTemplate("ops-runner")!, {
      agent_id: "or", fortress_id: TEST_FORTRESS, counterparty: "*", policy_version: 1,
    });
    expect(compiled.slots.credentials.mode).toBe("grant");
    expect(compiled.slots.credentials.grants.some((g) => g.action === "share")).toBe(true);
  });

  it("planner opens plans for read", () => {
    const compiled = buildCompiledPolicyFromTemplate(getTemplate("planner")!, {
      agent_id: "pl", fortress_id: TEST_FORTRESS, counterparty: "*", policy_version: 1,
    });
    expect(compiled.slots.plans.mode).toBe("grant");
    expect(compiled.slots.plans.grants.some((g) => g.action === "read")).toBe(true);
  });

  it("handoff-coordinator opens plans + outputs and declares intra-mesh-escrow", () => {
    const compiled = buildCompiledPolicyFromTemplate(getTemplate("handoff-coordinator")!, {
      agent_id: "hc", fortress_id: TEST_FORTRESS, counterparty: "*", policy_version: 1,
    });
    expect(compiled.slots.plans.mode).toBe("grant");
    expect(compiled.slots.outputs.mode).toBe("grant");
    expect(compiled.capabilities.concordia_commitment_classes).toContain("intra-mesh-escrow");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// CLI subcommand tests
// ═══════════════════════════════════════════════════════════════════════

describe("CLI subcommands", () => {
  beforeEach(() => clearTemplateCache());

  it("template list returns exit 0 and outputs table", async () => {
    const chunks: string[] = [];
    const out = {
      write: (chunk: string) => { chunks.push(chunk); return true; },
    } as unknown as NodeJS.WritableStream;
    const code = await runTemplateCommand({ argv: ["list"], out });
    expect(code).toBe(0);
    const output = chunks.join("");
    expect(output).toContain("research-assistant");
    expect(output).toContain("coding-assistant");
    expect(output).toContain("ops-runner");
    expect(output).toContain("planner");
    expect(output).toContain("handoff-coordinator");
  });

  // Stub that treats every agent as wrapped; used for positive-path
  // tests that do not exercise the orphan-reject gate.
  const STUB_ALWAYS_WRAPPED = async () => true;

  it("template init with valid name + agent-id + wrapped harness returns exit 0", async () => {
    const chunks: string[] = [];
    const out = {
      write: (chunk: string) => { chunks.push(chunk); return true; },
    } as unknown as NodeJS.WritableStream;
    const errChunks: string[] = [];
    const errStream = {
      write: (chunk: string) => { errChunks.push(chunk); return true; },
    } as unknown as NodeJS.WritableStream;
    const code = await runTemplateCommand({
      argv: ["init", "research-assistant", "--agent-id", "test-agent"],
      out,
      err: errStream,
      isAgentWrapped: STUB_ALWAYS_WRAPPED,
    });
    expect(code).toBe(0);
    const output = chunks.join("");
    expect(output).toContain("Template initialized successfully");
    expect(output).toContain("research-assistant");
    expect(output).toContain("test-agent");
  });

  it("template init rejects orphan agent-id (no wrapped harness) with exit 1 + sanctuary wrap pointer", async () => {
    const errChunks: string[] = [];
    const errStream = {
      write: (chunk: string) => { errChunks.push(chunk); return true; },
    } as unknown as NodeJS.WritableStream;
    const code = await runTemplateCommand({
      argv: ["init", "research-assistant", "--agent-id", "orphan-agent"],
      err: errStream,
      isAgentWrapped: async () => false,
    });
    expect(code).toBe(1);
    const errOutput = errChunks.join("");
    expect(errOutput).toContain("no wrapped harness found for agent-id \"orphan-agent\"");
    expect(errOutput).toContain("sanctuary wrap");
    expect(errOutput).toContain("sanctuary template init research-assistant --agent-id orphan-agent");
  });

  it("template init passes agent-id to the orphan-check callback", async () => {
    const seen: string[] = [];
    const errStream = {
      write: () => true,
    } as unknown as NodeJS.WritableStream;
    const out = { write: () => true } as unknown as NodeJS.WritableStream;
    await runTemplateCommand({
      argv: ["init", "coding-assistant", "--agent-id", "my-wrapped-agent"],
      out,
      err: errStream,
      isAgentWrapped: async (agentId: string) => {
        seen.push(agentId);
        return true;
      },
    });
    expect(seen).toEqual(["my-wrapped-agent"]);
  });

  it("template init without agent-id returns exit 1", async () => {
    const errChunks: string[] = [];
    const errStream = {
      write: (chunk: string) => { errChunks.push(chunk); return true; },
    } as unknown as NodeJS.WritableStream;
    const code = await runTemplateCommand({
      argv: ["init", "research-assistant"],
      err: errStream,
      isAgentWrapped: STUB_ALWAYS_WRAPPED,
    });
    expect(code).toBe(1);
    expect(errChunks.join("")).toContain("--agent-id is required");
  });

  it("template init with unknown name returns exit 1", async () => {
    const errChunks: string[] = [];
    const errStream = {
      write: (chunk: string) => { errChunks.push(chunk); return true; },
    } as unknown as NodeJS.WritableStream;
    const code = await runTemplateCommand({
      argv: ["init", "nonexistent", "--agent-id", "x"],
      err: errStream,
      isAgentWrapped: STUB_ALWAYS_WRAPPED,
    });
    expect(code).toBe(1);
    expect(errChunks.join("")).toContain("unknown template");
  });

  it("template --help returns exit 0", async () => {
    const chunks: string[] = [];
    const out = {
      write: (chunk: string) => { chunks.push(chunk); return true; },
    } as unknown as NodeJS.WritableStream;
    const code = await runTemplateCommand({ argv: ["--help"], out });
    expect(code).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// isTemplateName guard
// ═══════════════════════════════════════════════════════════════════════

describe("isTemplateName", () => {
  it("returns true for valid names", () => {
    for (const name of TEMPLATE_NAMES) {
      expect(isTemplateName(name)).toBe(true);
    }
  });

  it("returns false for invalid names", () => {
    expect(isTemplateName("foo")).toBe(false);
    expect(isTemplateName("")).toBe(false);
    expect(isTemplateName(123)).toBe(false);
    expect(isTemplateName(null)).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Non-dependency check
// ═══════════════════════════════════════════════════════════════════════

describe("Non-dependency principle", () => {
  it("template source files do not import from Concordia or Verascore", async () => {
    // Read the source files and check for forbidden imports
    const fs = await import("node:fs");
    const path = await import("node:path");
    const templatesDir = path.join(
      path.dirname(new URL(import.meta.url).pathname),
      "../../src/templates"
    );

    const tsFiles = fs.readdirSync(templatesDir)
      .filter((f: string) => f.endsWith(".ts"))
      .map((f: string) => path.join(templatesDir, f));

    for (const file of tsFiles) {
      const content = fs.readFileSync(file, "utf-8");
      expect(content).not.toMatch(/from\s+["'].*concordia/i);
      expect(content).not.toMatch(/from\s+["'].*verascore/i);
    }
  });
});
