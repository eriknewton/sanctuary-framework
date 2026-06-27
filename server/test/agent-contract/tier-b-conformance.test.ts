import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import {
  InMemoryAgentKeyStore,
  wrapAgentPrivateKey,
} from "../../src/agent-contract/identity-bind.js";
import {
  listTierBAdapters,
  StubHarness,
  type TierBAdapterId,
  type TierBAdapterParams,
} from "../../src/agent-contract/adapters/index.js";
import { TierBInvariantError } from "../../src/agent-contract/errors.js";
import { toBase64url } from "../../src/core/encoding.js";
import { buildPolicyBlobBytes, buildTestFortress } from "./fixture.js";

const SENTINEL_SEED_TEXT = "tier-b-conformance-private-key!!";

const CONFORMANCE_REFERENCE_IDS = {
  "claude-code": true,
  cline: true,
  hermes: true,
  mastra: true,
} as const satisfies Record<TierBAdapterId, true>;

interface UniversalTransport {
  sent: string[];
  signals: string[];
  closed: boolean;
  send(message: string): Promise<void>;
  receive(): Promise<string | null>;
  signal(sig: "SIGSTOP" | "SIGCONT" | "SIGTERM" | "SIGKILL"): Promise<void>;
  close(signal?: "SIGTERM" | "SIGKILL"): Promise<void>;
}

type ConformanceParams = TierBAdapterParams & {
  transport: UniversalTransport;
};

function makeUniversalTransport(): UniversalTransport {
  return {
    sent: [],
    signals: [],
    closed: false,
    async send(message) {
      this.sent.push(message);
    },
    async receive() {
      return null;
    },
    async signal(sig) {
      this.signals.push(sig);
    },
    async close() {
      this.closed = true;
    },
  };
}

function sorted(values: Iterable<string>): string[] {
  return Array.from(values).sort((a, b) => a.localeCompare(b));
}

function registeredAdapterIds(): string[] {
  return listTierBAdapters().map((r) => r.id);
}

function buildSensitiveNeedles(seed: Uint8Array): string[] {
  const raw = SENTINEL_SEED_TEXT;
  const base64 = Buffer.from(seed).toString("base64");
  const base64url = toBase64url(seed);
  const hex = Buffer.from(seed).toString("hex");
  const byteList = Array.from(seed).join(",");
  const jsonBytes = JSON.stringify(Array.from(seed));
  const needles = [raw, base64, base64url, hex, byteList, jsonBytes];
  return Array.from(
    new Set([
      ...needles,
      ...needles.map((needle) => encodeURIComponent(needle)),
    ])
  );
}

async function buildConformanceParams(
  adapterId: TierBAdapterId
): Promise<{
  params: ConformanceParams;
  sensitiveNeedles: string[];
}> {
  const f = buildTestFortress();
  const store = new InMemoryAgentKeyStore();
  const agentId = `agent-${adapterId}`;
  const seed = new TextEncoder().encode(SENTINEL_SEED_TEXT);
  expect(seed).toHaveLength(32);
  const sensitiveNeedles = buildSensitiveNeedles(seed);
  const publicKey = ed25519.getPublicKey(seed);
  const wrapped = wrapAgentPrivateKey({
    agent_private_key: seed,
    fortress_master_secret: f.fortressMasterSecret,
    agent_id: agentId,
  });
  seed.fill(0);
  await store.save(agentId, wrapped);

  return {
    sensitiveNeedles,
    params: {
      agent_id: agentId,
      fortress_id: f.master.public.fortress_id,
      harness_id: adapterId,
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
      agent_identity_binding: {
        agent_id: agentId,
        fortress_id: f.master.public.fortress_id,
        agent_pubkey: toBase64url(publicKey),
        derived_subkey_purposes: [],
        bound_at: "2026-06-22T00:00:00.000Z",
      },
      fortress_master_secret: f.fortressMasterSecret,
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      principal_private_key: f.principalKeypair.privateKey,
      http_proxy_url: "http://127.0.0.1:3128",
      https_proxy_url: "http://127.0.0.1:3128",
      transport: makeUniversalTransport(),
    },
  };
}

function assertNoKeyMaterialInEnv(
  env: Record<string, string>,
  sensitiveNeedles: string[]
): void {
  expect(Object.keys(env).length).toBeGreaterThan(0);
  for (const key of Object.keys(env)) {
    expect(key).not.toMatch(/PRIVATE_KEY|MASTER_SECRET/);
    expect(key.startsWith("SANCTUARY_KEY_")).toBe(false);
  }
  for (const value of Object.values(env)) {
    for (const needle of sensitiveNeedles) {
      expect(value).not.toContain(needle);
    }
  }
  const serializedEnv = JSON.stringify(env);
  for (const needle of sensitiveNeedles) {
    expect(serializedEnv).not.toContain(needle);
  }
}

const registrySnapshot = listTierBAdapters();
const registryRows = registrySnapshot.map((registration) => [
  registration.id,
  registration,
] as const);
const exercised = new Set<TierBAdapterId>();

describe.sequential("Tier B adapter registry conformance", () => {
  it("loads every registered adapter and has a local conformance reference", () => {
    const ids = sorted(registeredAdapterIds());
    expect(ids).toEqual(sorted(Object.keys(CONFORMANCE_REFERENCE_IDS)));
    expect(ids).toEqual(sorted(registrySnapshot.map((r) => r.id)));
    expect(ids.length).toBeGreaterThan(0);
  });

  it.each(registryRows)(
    "%s upholds the sealed Tier B invariants",
    async (_adapterId, registration) => {
      exercised.add(registration.id);
      const { params, sensitiveNeedles } = await buildConformanceParams(
        registration.id
      );
      const adapter = registration.factory(params);

      expect(adapter.harnessId).toBe(registration.id);
      assertNoKeyMaterialInEnv(adapter.buildHarnessEnv(), sensitiveNeedles);

      const { card_emission } = await adapter.launch();
      expect(card_emission.body.tier).toBe("B");
      expect(card_emission.body.harness_id).toBe(registration.id);

      const spawned = new StubHarness([
        {
          capability_kind: "tool-call",
          capability_target: "filesystem/read_lines",
          input: { requested_by: registration.id },
          output: { spawned_sub_agent: "worker-1" },
        },
      ]).next();
      const spawnedOutput = spawned?.output as { spawned_sub_agent: string };
      expect(spawnedOutput.spawned_sub_agent).toBe("worker-1");

      const cardHashBefore = adapter.getCardHash();
      expect(adapter.labelSubAgent(spawnedOutput.spawned_sub_agent)).toBe(
        `sub_of:${params.agent_id}:${spawnedOutput.spawned_sub_agent}`
      );
      expect(adapter.getCardHash()).toBe(cardHashBefore);
      expect(() => adapter.labelSubAgent("worker-1:promote")).toThrow(
        TierBInvariantError
      );
    }
  );

  it("exercises every adapter still present in the live registry", () => {
    expect(sorted(exercised)).toEqual(sorted(registeredAdapterIds()));
  });
});
