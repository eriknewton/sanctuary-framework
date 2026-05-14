/**
 * Agent Contract v0.1 — Hermes Tier B adapter tests (§5).
 *
 * Mirrors the cline/claude-code/mastra surface test in
 * `tier-b-adapter.test.ts` but scoped to the Hermes adapter. Covers:
 *   - Agent Card emitted with tier="B" and harness_id="hermes"
 *   - HTTP_PROXY / HTTPS_PROXY propagation through buildHarnessEnv
 *   - Lifecycle command translation for all six commands
 *   - Envelope wrap of harness I/O via observeHarnessAction
 *   - Usage event emission
 *   - Sub-agent labelling invariant (colon rejection)
 *   - Key-material leakage prevention (SANCTUARY_KEY_ env vars rejected)
 *   - model_provider is NOT pinned (deliberate deviation from claude-code)
 *   - Registry registration
 */

import { describe, it, expect } from "vitest";
import {
  bindAgentIdentity,
  InMemoryAgentKeyStore,
} from "../../src/agent-contract/identity-bind.js";
import {
  getTierBAdapter,
  listTierBAdapters,
  type TierBAdapterParams,
} from "../../src/agent-contract/adapters/tier-b-sdk.js";
import {
  HermesAdapter,
  type HermesTransport,
} from "../../src/agent-contract/adapters/hermes.js";
import { TierBInvariantError } from "../../src/agent-contract/errors.js";
import { buildPolicyBlobBytes, buildTestFortress } from "./fixture.js";

function makeStubHermesTransport(): HermesTransport & {
  __sent: string[];
  __closed: () => boolean;
  __closeSignal: () => "SIGTERM" | "SIGKILL" | undefined;
} {
  const sent: string[] = [];
  let closed = false;
  let closeSignal: "SIGTERM" | "SIGKILL" | undefined;
  return {
    async send(line) {
      sent.push(line);
    },
    async receive() {
      return null;
    },
    async close(signal) {
      closed = true;
      closeSignal = signal;
    },
    __sent: sent,
    __closed: () => closed,
    __closeSignal: () => closeSignal,
  };
}

async function buildHermesAdapterParams(
  overrides: Partial<TierBAdapterParams> = {}
) {
  const f = buildTestFortress();
  const store = new InMemoryAgentKeyStore();
  const binding = await bindAgentIdentity({
    agent_id: "agent-hermes",
    fortress_id: f.master.public.fortress_id,
    fortress_master_secret: f.fortressMasterSecret,
    store,
  });
  const base: TierBAdapterParams = {
    agent_id: "agent-hermes",
    fortress_id: f.master.public.fortress_id,
    harness_id: "hermes",
    // Deliberately NOT "anthropic" — Hermes runs back-end models published
    // by NousResearch (DeepHermes / Hermes-3 / Hermes-4) or any other
    // operator-configured provider behind the harness.
    model_provider: "self-hosted",
    model_id: "hermes-4-70b",
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

describe("Tier B HermesAdapter — registry + surface", () => {
  it("registers in the Tier B adapter registry", () => {
    const ids = listTierBAdapters().map((r) => r.id);
    expect(ids).toContain("hermes");
  });

  it("exposes a label that names the harness and provider", () => {
    const reg = getTierBAdapter("hermes");
    expect(reg).toBeDefined();
    expect(reg?.label).toMatch(/Hermes/);
    expect(reg?.label).toMatch(/NousResearch/);
  });

  it("factory throws if no HermesTransport is supplied", async () => {
    const reg = getTierBAdapter("hermes");
    const { base } = await buildHermesAdapterParams();
    // Cast off the transport requirement to exercise the guard.
    expect(() => reg!.factory(base as TierBAdapterParams)).toThrow(
      /HermesTransport/
    );
  });

  it("buildHarnessEnv includes HTTP_PROXY + HTTPS_PROXY + Hermes knobs + Sanctuary vars", async () => {
    const { base } = await buildHermesAdapterParams();
    const transport = makeStubHermesTransport();
    const adapter = new HermesAdapter({ ...base, transport });
    const env = adapter.buildHarnessEnv();
    expect(env.HTTP_PROXY).toBe("http://127.0.0.1:3128");
    expect(env.HTTPS_PROXY).toBe("http://127.0.0.1:3128");
    expect(env.SANCTUARY_AGENT_ID).toBe("agent-hermes");
    expect(env.SANCTUARY_HARNESS_TIER).toBe("B");
    expect(env.SANCTUARY_HARNESS_ID).toBe("hermes");
    expect(env.HERMES_MCP_TRANSPORT).toBe("stdio");
    expect(env.HERMES_TELEMETRY_DISABLED).toBe("true");
    expect(env.HERMES_UPSTREAM_MODE).toBe("sanctuary");
    // Hard invariant — no key material in env (§5).
    for (const key of Object.keys(env)) {
      expect(key).not.toMatch(/PRIVATE_KEY|MASTER_SECRET/);
      expect(key.startsWith("SANCTUARY_KEY_")).toBe(false);
    }
  });
});

describe("Tier B HermesAdapter — model_provider not pinned (A7)", () => {
  it("accepts self-hosted model_provider (NousResearch default)", async () => {
    const { base } = await buildHermesAdapterParams({
      model_provider: "self-hosted",
    });
    const transport = makeStubHermesTransport();
    const adapter = new HermesAdapter({ ...base, transport });
    const { card_emission } = await adapter.launch();
    expect(card_emission.body.model_provider).toBe("self-hosted");
  });

  it("accepts anthropic model_provider (operator routing Hermes to Claude)", async () => {
    const { base } = await buildHermesAdapterParams({
      model_provider: "anthropic",
    });
    const transport = makeStubHermesTransport();
    const adapter = new HermesAdapter({ ...base, transport });
    const { card_emission } = await adapter.launch();
    expect(card_emission.body.model_provider).toBe("anthropic");
  });

  it("accepts openai model_provider (operator routing Hermes to GPT)", async () => {
    const { base } = await buildHermesAdapterParams({
      model_provider: "openai",
    });
    const transport = makeStubHermesTransport();
    const adapter = new HermesAdapter({ ...base, transport });
    const { card_emission } = await adapter.launch();
    expect(card_emission.body.model_provider).toBe("openai");
  });
});

describe("Tier B HermesAdapter — lifecycle translation", () => {
  it("launch emits tier-B Agent Card with harness_id=hermes and launched lifecycle", async () => {
    const { f, base } = await buildHermesAdapterParams();
    const transport = makeStubHermesTransport();
    const adapter = new HermesAdapter({ ...base, transport });
    const { card_emission, lifecycle_emission } = await adapter.launch();
    expect(card_emission.body.tier).toBe("B");
    expect(card_emission.body.harness_id).toBe("hermes");
    expect(lifecycle_emission.body.to_state).toBe("launched");
    expect(card_emission.signed_event.emitter_node).toBe(f.nodeCert.node_id);
  });

  it("translates pause to MCP notifications/cancelled and emits paused event", async () => {
    const { base } = await buildHermesAdapterParams();
    const transport = makeStubHermesTransport();
    const adapter = new HermesAdapter({ ...base, transport });
    await adapter.launch();
    const pause = await adapter.sendLifecycle("pause", {
      from_state: "launched",
    });
    expect(pause.body.to_state).toBe("paused");
    expect(transport.__sent.at(-1)).toMatch(/notifications\/cancelled/);
  });

  it("translates checkpoint to sanctuary/checkpoint and emits checkpointed event", async () => {
    const { base } = await buildHermesAdapterParams();
    const transport = makeStubHermesTransport();
    const adapter = new HermesAdapter({ ...base, transport });
    await adapter.launch();
    const checkpoint = await adapter.sendLifecycle("checkpoint", {
      from_state: "launched",
      checkpoint_hash: "ck-hermes-1",
    });
    expect(checkpoint.body.to_state).toBe("checkpointed");
    expect(transport.__sent.at(-1)).toMatch(/sanctuary\/checkpoint/);
  });

  it("translates resume to sanctuary/resume and emits resumed event (from checkpointed)", async () => {
    const { base } = await buildHermesAdapterParams();
    const transport = makeStubHermesTransport();
    const adapter = new HermesAdapter({ ...base, transport });
    await adapter.launch();
    // launched → checkpointed is a legal transition; then checkpointed → resumed.
    await adapter.sendLifecycle("checkpoint", {
      from_state: "launched",
      checkpoint_hash: "ck-hermes-1",
    });
    const resume = await adapter.sendLifecycle("resume", {
      from_state: "checkpointed",
      checkpoint_hash: "ck-hermes-1",
    });
    expect(resume.body.to_state).toBe("resumed");
    expect(transport.__sent.at(-1)).toMatch(/sanctuary\/resume/);
  });

  it("translates revoke to sanctuary/revoke and emits revoked with guardian_quorum", async () => {
    const { base } = await buildHermesAdapterParams();
    const transport = makeStubHermesTransport();
    const adapter = new HermesAdapter({ ...base, transport });
    await adapter.launch();
    const revoke = await adapter.sendLifecycle("revoke", {
      from_state: "launched",
      reason: "guardian revoke",
      guardian_quorum: [
        {
          guardian_pubkey: "pub-guardian-1",
          signature: "sig-guardian-1",
        },
      ],
    });
    expect(revoke.body.to_state).toBe("revoked");
    expect(transport.__sent.at(-1)).toMatch(/sanctuary\/revoke/);
  });

  it("retire sends shutdown, closes transport with SIGTERM, emits retired", async () => {
    const { base } = await buildHermesAdapterParams();
    const transport = makeStubHermesTransport();
    const adapter = new HermesAdapter({ ...base, transport });
    await adapter.launch();
    const retired = await adapter.retire("launched", "test exit");
    expect(retired.body.to_state).toBe("retired");
    expect(transport.__sent.at(-1)).toMatch(/shutdown/);
    expect(transport.__closed()).toBe(true);
    expect(transport.__closeSignal()).toBe("SIGTERM");
  });
});

describe("Tier B HermesAdapter — observeHarnessAction", () => {
  it("wraps a harness-origin tool call in a harness_out envelope + emits usage event", async () => {
    const { base } = await buildHermesAdapterParams();
    const transport = makeStubHermesTransport();
    const adapter = new HermesAdapter({ ...base, transport });
    await adapter.launch();
    const obs = adapter.observeHarnessAction({
      capability_kind: "tool-call",
      capability_target: "filesystem/read_lines",
      input: { path: "/tmp/a" },
      output: { bytes: 12 },
    });
    expect(obs.envelope.direction).toBe("harness_out");
    expect(obs.envelope.receiver_check?.decision).toBe("allow");
    expect(obs.usage.body.capability_kind).toBe("tool-call");
    expect(obs.usage.body.capability_target).toBe("filesystem/read_lines");
  });

  it("refuses undeclared capability attempts", async () => {
    const { base } = await buildHermesAdapterParams();
    const transport = makeStubHermesTransport();
    const adapter = new HermesAdapter({ ...base, transport });
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

  it("advances the monotonic sequence on every emission", async () => {
    const { base } = await buildHermesAdapterParams();
    const transport = makeStubHermesTransport();
    const adapter = new HermesAdapter({ ...base, transport });
    await adapter.launch();
    const before = adapter.getSeq();
    adapter.observeHarnessAction({
      capability_kind: "tool-call",
      capability_target: "filesystem/read_lines",
      input: {},
      output: {},
    });
    expect(adapter.getSeq()).toBeGreaterThan(before);
  });
});

describe("Tier B HermesAdapter — invariants (§5)", () => {
  it("labelSubAgent produces a stable sub_of: label and refuses first-class promotion", async () => {
    const { base } = await buildHermesAdapterParams();
    const transport = makeStubHermesTransport();
    const adapter = new HermesAdapter({ ...base, transport });
    expect(adapter.labelSubAgent("worker-1")).toBe(
      "sub_of:agent-hermes:worker-1"
    );
    expect(() => adapter.labelSubAgent("")).toThrow(TierBInvariantError);
    expect(() => adapter.labelSubAgent("has:colon")).toThrow(
      TierBInvariantError
    );
  });

  it("rejects env keys that leak agent key material (SANCTUARY_KEY_*)", async () => {
    class LeakyHermesAdapter extends HermesAdapter {
      protected override harnessEnv(): Record<string, string> {
        return { SANCTUARY_KEY_SEED: "would-leak-seed" };
      }
    }
    const { base } = await buildHermesAdapterParams();
    const transport = makeStubHermesTransport();
    const adapter = new LeakyHermesAdapter({ ...base, transport });
    expect(() => adapter.buildHarnessEnv()).toThrow(TierBInvariantError);
  });

  it("rejects env keys that leak the fortress master secret", async () => {
    class LeakyHermesAdapter extends HermesAdapter {
      protected override harnessEnv(): Record<string, string> {
        return { SANCTUARY_MASTER_SECRET: "would-leak-master" };
      }
    }
    const { base } = await buildHermesAdapterParams();
    const transport = makeStubHermesTransport();
    const adapter = new LeakyHermesAdapter({ ...base, transport });
    expect(() => adapter.buildHarnessEnv()).toThrow(TierBInvariantError);
  });

  it("rejects env keys that leak the agent private key", async () => {
    class LeakyHermesAdapter extends HermesAdapter {
      protected override harnessEnv(): Record<string, string> {
        return { SANCTUARY_AGENT_PRIVATE_KEY: "would-leak-agent-priv" };
      }
    }
    const { base } = await buildHermesAdapterParams();
    const transport = makeStubHermesTransport();
    const adapter = new LeakyHermesAdapter({ ...base, transport });
    expect(() => adapter.buildHarnessEnv()).toThrow(TierBInvariantError);
  });

  it("refuses double-launch for the same agent", async () => {
    const { base } = await buildHermesAdapterParams();
    const transport = makeStubHermesTransport();
    const adapter = new HermesAdapter({ ...base, transport });
    await adapter.launch();
    await expect(adapter.launch()).rejects.toThrow(/double-launched/);
  });
});
