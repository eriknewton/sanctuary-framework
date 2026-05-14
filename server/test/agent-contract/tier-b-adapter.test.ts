/**
 * Agent Contract v0.1 — Tier B adapter end-to-end tests (§5).
 *
 * Exercises the adapter contract against stubbed harnesses:
 *   - Agent Card emitted with tier="B"
 *   - HTTP_PROXY propagation
 *   - Lifecycle command translation
 *   - Envelope wrap of harness I/O
 *   - Usage event emission
 *   - Sub-agent labelling invariant (§5)
 *   - Key-material leakage prevention
 */

import { describe, it, expect } from "vitest";
import {
  bindAgentIdentity,
  InMemoryAgentKeyStore,
} from "../../src/agent-contract/identity-bind.js";
import {
  getTierBAdapter,
  listTierBAdapters,
  StubHarness,
  type TierBAdapterParams,
} from "../../src/agent-contract/adapters/tier-b-sdk.js";
import {
  ClineAdapter,
  type ClineTransport,
} from "../../src/agent-contract/adapters/cline.js";
import {
  ClaudeCodeAdapter,
  type ClaudeCodeTransport,
} from "../../src/agent-contract/adapters/claude-code.js";
import { MastraAdapter } from "../../src/agent-contract/adapters/mastra.js";
import { TierBInvariantError } from "../../src/agent-contract/errors.js";
import { buildPolicyBlobBytes, buildTestFortress } from "./fixture.js";

function makeStubClineTransport(): ClineTransport {
  const sent: string[] = [];
  let closed = false;
  return {
    async send(line) {
      sent.push(line);
    },
    async receive() {
      return null;
    },
    async close() {
      closed = true;
    },
    // Expose internal state via closure for assertions.
    ...({ __sent: sent, __closed: () => closed } as Record<string, unknown>),
  } as ClineTransport;
}

function makeStubClaudeCodeTransport(): ClaudeCodeTransport {
  const sent: string[] = [];
  const signals: string[] = [];
  let closed = false;
  return {
    async send(msg) {
      sent.push(msg);
    },
    async receive() {
      return null;
    },
    async signal(sig) {
      signals.push(sig);
    },
    async close() {
      closed = true;
    },
    ...({
      __sent: sent,
      __signals: signals,
      __closed: () => closed,
    } as Record<string, unknown>),
  } as ClaudeCodeTransport;
}

async function buildAdapterParams(overrides: Partial<TierBAdapterParams> = {}) {
  const f = buildTestFortress();
  const store = new InMemoryAgentKeyStore();
  const binding = await bindAgentIdentity({
    agent_id: "agent-a",
    fortress_id: f.master.public.fortress_id,
    fortress_master_secret: f.fortressMasterSecret,
    store,
  });
  const base: TierBAdapterParams = {
    agent_id: "agent-a",
    fortress_id: f.master.public.fortress_id,
    harness_id: "cline",
    model_provider: "anthropic",
    model_id: "claude-opus-4-7",
    capabilities: [
      { kind: "tool-call", target: "filesystem/read*" },
      { kind: "egress", target: "https://api.anthropic.com" },
    ],
    policy_version: 1,
    policy_blob_bytes: buildPolicyBlobBytes(1),
    attestation_endpoint: "http://127.0.0.1:3501/att",
    key_store: store,
    agent_identity_binding: binding,
    fortress_master_secret: f.fortressMasterSecret,
    emitter_node: f.nodeCert.node_id,
    emitter_principal: f.principalCert.principal_id,
    node_private_key: f.nodeKeypair.privateKey,
    http_proxy_url: "http://127.0.0.1:3128",
    https_proxy_url: "http://127.0.0.1:3128",
    ...overrides,
  };
  return { f, base };
}

describe("Tier B adapter SDK — registry + invariants (§5)", () => {
  it("registers all three reference adapters", () => {
    const ids = listTierBAdapters().map((r) => r.id);
    expect(ids).toContain("cline");
    expect(ids).toContain("claude-code");
    expect(ids).toContain("mastra");
  });

  it("returns registration by id", () => {
    const reg = getTierBAdapter("claude-code");
    expect(reg).toBeDefined();
    expect(reg?.label).toContain("Anthropic");
  });

  // WP-MVP-1 Follow-up — Cline wrap adapter (Layer 1) regression guard.
  // The Layer 2 SDK adapter at server/src/agent-contract/adapters/cline.ts
  // is NOT modified by the Layer 1 install-time --cline wrap flag, but any
  // future refactor that accidentally deregisters the cline SDK must fail
  // this test. See Review/Sanctuary/WP-MVP-1_Followup_Cline_Wrap_Adapter_Spawn_Prompt_2026-04-22.md A5.
  it("returns the cline Tier B SDK adapter registration (Layer 2 guard)", () => {
    const reg = getTierBAdapter("cline");
    expect(reg).toBeDefined();
    expect(reg?.id).toBe("cline");
    expect(reg?.label).toContain("Cline");
    expect(typeof reg?.factory).toBe("function");
  });

  it("buildHarnessEnv includes HTTP_PROXY + HTTPS_PROXY + Sanctuary vars", async () => {
    const { base } = await buildAdapterParams();
    const t = makeStubClineTransport();
    const adapter = new ClineAdapter({ ...base, transport: t });
    const env = adapter.buildHarnessEnv();
    expect(env.HTTP_PROXY).toBe("http://127.0.0.1:3128");
    expect(env.HTTPS_PROXY).toBe("http://127.0.0.1:3128");
    expect(env.SANCTUARY_AGENT_ID).toBe("agent-a");
    expect(env.SANCTUARY_HARNESS_TIER).toBe("B");
    expect(env.SANCTUARY_HARNESS_ID).toBe("cline");
    // Hard invariant — no key material in env.
    for (const key of Object.keys(env)) {
      expect(key).not.toMatch(/PRIVATE_KEY|MASTER_SECRET/);
    }
  });

  it("labelSubAgent produces a stable sub_of: label and refuses first-class promotion", async () => {
    const { base } = await buildAdapterParams();
    const t = makeStubClineTransport();
    const adapter = new ClineAdapter({ ...base, transport: t });
    expect(adapter.labelSubAgent("worker-1")).toBe("sub_of:agent-a:worker-1");
    expect(() => adapter.labelSubAgent("")).toThrow(TierBInvariantError);
    expect(() => adapter.labelSubAgent("has:colon")).toThrow(TierBInvariantError);
  });
});

describe("Tier B ClineAdapter end-to-end", () => {
  it("launches, emits a B-tier Agent Card + launched event, observes an action", async () => {
    const { f, base } = await buildAdapterParams();
    const transport = makeStubClineTransport();
    const adapter = new ClineAdapter({ ...base, transport });
    const { card_emission, lifecycle_emission } = await adapter.launch();
    expect(card_emission.body.tier).toBe("B");
    expect(card_emission.body.harness_id).toBe("cline");
    expect(lifecycle_emission.body.to_state).toBe("launched");
    // End-to-end observation: the harness (stubbed) reports a tool call.
    const obs = adapter.observeHarnessAction({
      capability_kind: "tool-call",
      capability_target: "filesystem/read_lines",
      input: { path: "/tmp/a" },
      output: { bytes: 12 },
    });
    expect(obs.envelope.direction).toBe("harness_out");
    expect(obs.envelope.receiver_check?.decision).toBe("allow");
    expect(obs.usage.body.capability_kind).toBe("tool-call");
    // Monotonic sequence advances with each emission.
    expect(adapter.getSeq()).toBeGreaterThanOrEqual(3);
    // Verify node + principal IDs line up with the fixture fortress.
    expect(card_emission.signed_event.emitter_node).toBe(f.nodeCert.node_id);
  });

  it("retire translates to shutdown line and emits `retired` lifecycle", async () => {
    const { base } = await buildAdapterParams();
    const transport = makeStubClineTransport() as ClineTransport & {
      __sent: string[];
    };
    const adapter = new ClineAdapter({ ...base, transport });
    await adapter.launch();
    const r = await adapter.retire("launched", "test exit");
    expect(r.body.to_state).toBe("retired");
    expect((transport as unknown as { __sent: string[] }).__sent.at(-1)).toMatch(
      /shutdown/
    );
  });

  it("refuses undeclared capability attempts via observeHarnessAction", async () => {
    const { base } = await buildAdapterParams();
    const transport = makeStubClineTransport();
    const adapter = new ClineAdapter({ ...base, transport });
    await adapter.launch();
    expect(() =>
      adapter.observeHarnessAction({
        capability_kind: "egress",
        capability_target: "https://evil.example.com",
        input: {},
        output: {},
      })
    ).toThrow(/no matching capability|not declared|per_day_max/);
  });
});

describe("Tier B ClaudeCodeAdapter", () => {
  it("pins model_provider to anthropic", async () => {
    const { base } = await buildAdapterParams();
    const transport = makeStubClaudeCodeTransport();
    expect(
      () =>
        new ClaudeCodeAdapter({
          ...base,
          model_provider: "openai",
          transport,
        })
    ).toThrow(/anthropic/);
  });

  it("launches and returns an MCP-shape deny for undeclared capability", async () => {
    const { base } = await buildAdapterParams();
    const transport = makeStubClaudeCodeTransport();
    const adapter = new ClaudeCodeAdapter({ ...base, transport });
    await adapter.launch();
    const attempt = await adapter.attemptToolCall({
      tool_name: "network/connect",
      input: { host: "evil" },
      output: null,
    });
    expect(attempt.ok).toBe(false);
    if (!attempt.ok) {
      expect(attempt.mcp_error.code).toBe(-32602);
      expect(attempt.mcp_error.message).toContain("not declared");
    }
  });

  it("sendLifecycle pause calls SIGSTOP and emits paused event", async () => {
    const { base } = await buildAdapterParams();
    const transport = makeStubClaudeCodeTransport() as ClaudeCodeTransport & {
      __signals: string[];
    };
    const adapter = new ClaudeCodeAdapter({ ...base, transport });
    await adapter.launch();
    const r = await adapter.sendLifecycle("pause", { from_state: "launched" });
    expect(r.body.to_state).toBe("paused");
    expect((transport as unknown as { __signals: string[] }).__signals).toContain(
      "SIGSTOP"
    );
  });
});

describe("Tier B MastraAdapter", () => {
  it("emits a B-tier card on launch and provides pre/post hooks", async () => {
    const { base } = await buildAdapterParams();
    const adapter = new MastraAdapter({ ...base, harness_id: "mastra" });
    const { card_emission } = await adapter.launch();
    expect(card_emission.body.tier).toBe("B");
    expect(card_emission.body.harness_id).toBe("mastra");
    const pre = adapter.buildPreActionHook();
    const post = adapter.buildPostActionHook();
    const r1 = await pre({
      tool_name: "filesystem/read_lines",
      capability_kind: "tool-call",
      input: { x: 1 },
    });
    expect(r1).toEqual({ proceed: true });
    const r2 = await post({
      tool_name: "filesystem/read_lines",
      capability_kind: "tool-call",
      input: { x: 1 },
      output: { y: 2 },
    });
    expect(r2.usage_event_id.length).toBeGreaterThan(0);
    // Undeclared capability denied by the pre-hook (does not throw).
    const r3 = await pre({
      tool_name: "network/connect",
      capability_kind: "tool-call",
      input: {},
    });
    expect(r3.proceed).toBe(false);
  });

  it("registerSubAgent rejects pipe + colon", async () => {
    const { base } = await buildAdapterParams();
    const adapter = new MastraAdapter({ ...base, harness_id: "mastra" });
    await adapter.launch();
    expect(() => adapter.registerSubAgent("has|pipe")).toThrow(
      TierBInvariantError
    );
    expect(adapter.registerSubAgent("worker")).toBe("sub_of:agent-a:worker");
  });
});

describe("Tier B SDK — stub harness helper", () => {
  it("yields invocations then returns undefined", () => {
    const stub = new StubHarness([
      {
        capability_kind: "tool-call",
        capability_target: "filesystem/read",
        input: { a: 1 },
        output: { b: 2 },
      },
    ]);
    expect(stub.next()?.capability_target).toBe("filesystem/read");
    expect(stub.next()).toBeUndefined();
    expect(stub.remaining).toBe(0);
    stub.reset();
    expect(stub.remaining).toBe(1);
  });
});
