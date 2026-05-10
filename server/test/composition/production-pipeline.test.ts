/**
 * Sanctuary Composition v1.0 -- Production Pipeline Wire-up Tests.
 *
 * WP-MVP-10 Follow-up #2b acceptance suite.
 *
 * A2: commitment-boundary evaluation wired (commitment + non-commitment paths).
 * A3: composition emission gated on composition.enabled.
 * A4: audit-log fan-out is unconditional when composition emits.
 * A5: Verascore signal fan-out gated on scope (private default, public opt-in).
 * A6: default-off invariant (no composition emission code touched when disabled)
 *     plus gate-check performance bound.
 * A7: optional principal_id flows through (multi-principal v1.x invariant holdout).
 *
 * Fixtures use real fortress crypto (generateFortressMaster, real Ed25519
 * signing). No mocks for the policy engine, proposeCommitment, or the signal
 * hook. CompositionService is a real v1.0 instance with fortress context,
 * composition_enabled toggled per-test, no sidecar process spawned (emission
 * tests only exercise publishVerascoreSignal, which is in-process).
 *
 * Platform-agnostic: no Keychain, no filesystem, no sidecar spawn.
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import {
  CompositionService,
  runCompositionPipeline,
  clearPublishedSignals,
  getPublishedSignals,
  SIGNATURE_SCHEME_V1,
  type CompositionAuditEntry,
  type CompositionPipelineInput,
  type CompositionPipelineResult,
} from "../../src/composition/index.js";
import {
  evaluateCommitmentBoundary,
  type CommitmentBoundaryRequest,
  type CommitmentBoundaryCtx,
} from "../../src/policy-engine/commitment-boundary.js";
import { compileFixturePolicy } from "../../src/policy-engine/compiler-fixture.js";
import type { CompiledPolicy } from "../../src/policy-engine/types.js";
import { buildTestFortress } from "../agent-contract/fixture.js";
import type { AgentCard } from "../../src/agent-contract/types.js";

// -----------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------

const AGENT_ID = "agent-alpha";
const COUNTERPARTY = "agent-beta";
const COMMITMENT_CLASS = "task-delegate";
const FORTRESS_ID_DEFAULT = "fortress-pipeline-test";

function buildPolicy(opts?: {
  english?: string;
  policy_version?: number;
  fortress_id?: string;
}): CompiledPolicy {
  return compileFixturePolicy({
    agent_id: AGENT_ID,
    fortress_id: opts?.fortress_id ?? FORTRESS_ID_DEFAULT,
    policy_version: opts?.policy_version ?? 1,
    source_english:
      opts?.english ??
      `Agent ${AGENT_ID} may emit commitments of class ${COMMITMENT_CLASS}.`,
  });
}

function buildCard(overrides?: Partial<AgentCard>): AgentCard {
  return {
    schema_version: "0.1",
    signature_scheme: "ed25519-v1",
    agent_id: AGENT_ID,
    fortress_id: FORTRESS_ID_DEFAULT,
    tier: "B",
    harness_id: "cline",
    model_provider: "anthropic",
    model_id: "claude",
    agent_pubkey: "abc",
    policy_version_hash: "hash",
    policy_version: 1,
    attestation_endpoint: "http://localhost:1/att",
    capabilities: [{ kind: "concordia-commitment", target: COMMITMENT_CLASS }],
    issued_at: "2026-04-22T00:00:00Z",
    ...overrides,
  };
}

function commitmentRequest(overrides?: Partial<CommitmentBoundaryRequest>): CommitmentBoundaryRequest {
  return {
    agent_id: AGENT_ID,
    delegates_or_accepts: true,
    counterparty: COUNTERPARTY,
    bounded_scope: {
      deliverable: "writes a report",
      deadline_or_terminal: "2026-05-01T00:00:00Z",
      budget_ref: "budget-alpha",
    },
    commitment_class: COMMITMENT_CLASS,
    ...overrides,
  };
}

interface PipelineFixture {
  service: CompositionService | null;
  auditEntries: CompositionAuditEntry[];
  run: (
    input?: Partial<CompositionPipelineInput>
  ) => Promise<CompositionPipelineResult>;
}

function buildPipelineFixture(opts: {
  composition_enabled: boolean | "null_service";
  fortressId?: string;
  policy?: CompiledPolicy | null;
}): PipelineFixture {
  const f = buildTestFortress();
  const fortressId = opts.fortressId ?? FORTRESS_ID_DEFAULT;
  const service: CompositionService | null =
    opts.composition_enabled === "null_service"
      ? null
      : new CompositionService(
          { composition_enabled: opts.composition_enabled },
          undefined,
          {
            fortress_master_secret: f.fortressMasterSecret,
            fortress_id: fortressId,
          }
        );
  const auditEntries: CompositionAuditEntry[] = [];
  const policy =
    opts.policy === null
      ? null
      : (opts.policy ?? buildPolicy({ fortress_id: fortressId }));
  const gateCtx: CommitmentBoundaryCtx = {
    policy,
    nodeSigningKey: f.nodeKeypair.privateKey,
    nodeId: f.nodeCert.node_id,
    fortressId,
  };
  const card = buildCard({ fortress_id: fortressId });

  const run = (overrides?: Partial<CompositionPipelineInput>) =>
    runCompositionPipeline({
      request: commitmentRequest(),
      gateCtx,
      agentCard: card,
      emitterNode: f.nodeCert.node_id,
      emitterPrincipal: f.principalCert.principal_id,
      nodePrivateKey: f.nodeKeypair.privateKey,
      monotonicSeq: 0,
      compositionService: service,
      auditAppend: (entry) => {
        auditEntries.push(entry);
      },
      ...overrides,
    });

  return { service, auditEntries, run };
}

beforeEach(() => {
  clearPublishedSignals();
});

// -----------------------------------------------------------------------
// A2: commitment-boundary evaluation wired
// -----------------------------------------------------------------------

describe("A2: commitment-boundary evaluation", () => {
  it("commitment path: all four §7.1 conditions allow, pipeline proceeds to emit", async () => {
    const fx = buildPipelineFixture({ composition_enabled: true });
    const result = await fx.run();
    expect(result.gateResult.decision).toBe("allow");
    expect(result.status).toBe("commitment_emitted");
    expect(result.proposal).toBeDefined();
    expect(result.signedProposal?.event_type).toBe("agent_commitment_proposed");
  });

  it("non-commitment path: condition 1 fails, pipeline returns not_a_commitment without touching proposeCommitment", async () => {
    const fx = buildPipelineFixture({ composition_enabled: true });
    const result = await fx.run({
      request: commitmentRequest({ delegates_or_accepts: false }),
    });
    expect(result.status).toBe("not_a_commitment");
    expect(result.gateResult.decision).toBe("deny");
    expect(result.signedProposal).toBeUndefined();
    expect(result.proposal).toBeUndefined();
    expect(fx.auditEntries).toHaveLength(0);
  });
});

// -----------------------------------------------------------------------
// A3: composition emission gated on composition.enabled
// -----------------------------------------------------------------------

describe("A3: composition emission gated on composition.enabled", () => {
  it("enabled + commitment: emits proposal, signal, and both audit entries", async () => {
    const fx = buildPipelineFixture({ composition_enabled: true });
    const result = await fx.run();
    expect(result.status).toBe("commitment_emitted");
    expect(result.signal).toBeDefined();
    expect(fx.auditEntries.map((e) => e.kind).sort()).toEqual(
      ["commitment_proposed", "composition_signal"].sort()
    );
  });

  it("enabled + non-commitment: no proposal, no signal, no audit entries", async () => {
    const fx = buildPipelineFixture({ composition_enabled: true });
    const result = await fx.run({
      request: commitmentRequest({ counterparty: "" }),
    });
    expect(result.status).toBe("not_a_commitment");
    expect(result.signal).toBeUndefined();
    expect(fx.auditEntries).toHaveLength(0);
    expect(getPublishedSignals()).toHaveLength(0);
  });

  it("disabled + commitment: proposal emits, audit entry for proposal only, no signal", async () => {
    const fx = buildPipelineFixture({ composition_enabled: false });
    const result = await fx.run();
    expect(result.status).toBe("commitment_composition_off");
    expect(result.proposal).toBeDefined();
    expect(result.signedProposal).toBeDefined();
    expect(result.signal).toBeUndefined();
    expect(fx.auditEntries).toHaveLength(1);
    expect(fx.auditEntries[0]!.kind).toBe("commitment_proposed");
    expect(getPublishedSignals()).toHaveLength(0);
  });
});

// -----------------------------------------------------------------------
// A4: audit-log fan-out unconditional when composition emits
// -----------------------------------------------------------------------

describe("A4: audit-log fan-out when composition emits", () => {
  it("emits both commitment_proposed and composition_signal audit entries, carrying fortress_id on the signal entry", async () => {
    const fx = buildPipelineFixture({ composition_enabled: true });
    const result = await fx.run();
    expect(result.status).toBe("commitment_emitted");
    expect(fx.auditEntries).toHaveLength(2);

    const proposalEntry = fx.auditEntries.find(
      (e) => e.kind === "commitment_proposed"
    );
    const signalEntry = fx.auditEntries.find(
      (e) => e.kind === "composition_signal"
    );
    expect(proposalEntry).toBeDefined();
    expect(signalEntry).toBeDefined();
    if (signalEntry?.kind !== "composition_signal")
      throw new Error("type narrowing");
    expect(signalEntry.fortress_id).toBe(FORTRESS_ID_DEFAULT);
    expect(signalEntry.signal.signal_type).toBe("commitment_close");
    expect(signalEntry.signal.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
  });
});

// -----------------------------------------------------------------------
// A5: Verascore signal fan-out gated on scope
// -----------------------------------------------------------------------

describe("A5: Verascore signal fan-out gated on scope", () => {
  it("private scope (default): signal emits with scope=private and lands in the local Verascore hook store", async () => {
    const fx = buildPipelineFixture({ composition_enabled: true });
    const result = await fx.run();
    expect(result.signal?.scope).toBe("private");
    const published = getPublishedSignals();
    expect(published).toHaveLength(1);
    expect(published[0]!.scope).toBe("private");
  });

  it("public scope with explicitPublicOptIn: signal emits with scope=public and lands in the Verascore hook store", async () => {
    const fx = buildPipelineFixture({ composition_enabled: true });
    const result = await fx.run({
      verascoreScope: "public",
      explicitPublicOptIn: true,
    });
    expect(result.signal?.scope).toBe("public");
    const published = getPublishedSignals();
    expect(published).toHaveLength(1);
    expect(published[0]!.scope).toBe("public");
  });
});

// -----------------------------------------------------------------------
// A6: default-off invariant + perf bound
// -----------------------------------------------------------------------

describe("A6: default-off invariant", () => {
  it("with composition disabled, zero composition module emission functions are called on a commitment-shaped invocation", async () => {
    const fx = buildPipelineFixture({ composition_enabled: false });

    const emitSpy = vi.spyOn(fx.service!, "emitForCommitment");
    const publishSpy = vi.spyOn(fx.service!, "publishVerascoreSignal");
    const packSpy = vi.spyOn(fx.service!, "packReceipt");
    const verifySpy = vi.spyOn(fx.service!, "verifyReceipt");
    const mandateSpy = vi.spyOn(fx.service!, "verifyMandate");
    const isEnabledSpy = vi.spyOn(fx.service!, "isEnabled");

    const result = await fx.run();

    expect(result.status).toBe("commitment_composition_off");
    expect(emitSpy).not.toHaveBeenCalled();
    expect(publishSpy).not.toHaveBeenCalled();
    expect(packSpy).not.toHaveBeenCalled();
    expect(verifySpy).not.toHaveBeenCalled();
    expect(mandateSpy).not.toHaveBeenCalled();
    expect(isEnabledSpy).toHaveBeenCalledTimes(1);
    expect(getPublishedSignals()).toHaveLength(0);
  });

  it("with compositionService null, zero composition functions are called and the pipeline still emits the proposal audit entry", async () => {
    const fx = buildPipelineFixture({ composition_enabled: "null_service" });
    const result = await fx.run();
    expect(result.status).toBe("commitment_composition_off");
    expect(fx.service).toBeNull();
    expect(result.signedProposal).toBeDefined();
    expect(fx.auditEntries).toHaveLength(1);
    expect(fx.auditEntries[0]!.kind).toBe("commitment_proposed");
  });

  it("gate-check alone (evaluateCommitmentBoundary) runs with negligible per-call overhead, best-of-8-of-10 batches", () => {
    // Perf bound proves "the gate-check does not add meaningful latency to
    // a cold tool invocation." Calibration methodology and observed
    // distribution in server/docs/perf-calibration.md.
    //
    // Harness: 10 outer batches of 1000 inner iterations each, take the
    // best 8 of the 10 per-batch p50/p99 numbers (drop the 2 worst).
    // This absorbs single-batch GC or scheduler hiccups that would
    // otherwise put a stray latency spike at the p99 slot of a single
    // 1000-iteration sample.
    //
    // Bounds: p50 < 1ms (calibrated local p50 ≈ 0.23ms, stdev 0.003ms,
    // extremely stable) and p99 < 5ms (calibrated local p99 ≈ 0.5ms
    // across conditions; 5ms generous CI headroom while still trapping
    // pathological slowdowns of order 10x or worse).
    const f = buildTestFortress();
    const policy = buildPolicy();
    const ctx: CommitmentBoundaryCtx = {
      policy,
      nodeSigningKey: f.nodeKeypair.privateKey,
      nodeId: f.nodeCert.node_id,
      fortressId: FORTRESS_ID_DEFAULT,
    };
    const req = commitmentRequest({ delegates_or_accepts: false });
    const BATCHES = 10;
    const ITERATIONS_PER_BATCH = 1000;
    const KEEP_BEST = 8;
    const batchP50s: number[] = [];
    const batchP99s: number[] = [];
    for (let b = 0; b < BATCHES; b++) {
      const samples: number[] = [];
      for (let i = 0; i < ITERATIONS_PER_BATCH; i++) {
        const t0 = performance.now();
        evaluateCommitmentBoundary(ctx, req);
        samples.push(performance.now() - t0);
      }
      samples.sort((a, b) => a - b);
      batchP50s.push(samples[Math.floor(0.5 * samples.length)]!);
      batchP99s.push(samples[Math.floor(0.99 * samples.length)]!);
    }
    batchP50s.sort((a, b) => a - b);
    batchP99s.sort((a, b) => a - b);
    // Best 8 of 10 = drop the 2 worst; assert the 8th-best (index 7) passes.
    const bestOf8P50 = batchP50s[KEEP_BEST - 1]!;
    const bestOf8P99 = batchP99s[KEEP_BEST - 1]!;
    expect(bestOf8P50).toBeLessThan(1);
    expect(bestOf8P99).toBeLessThan(5);
  });
});

// -----------------------------------------------------------------------
// A7: multi-principal invariant holdout (principal_id pass-through)
// -----------------------------------------------------------------------

describe("A7: principal_id pass-through", () => {
  it("principal_id flows through to both audit entries without altering the emitted VerascoreSignal shape (v1.0 ignores on signal)", async () => {
    const fx = buildPipelineFixture({ composition_enabled: true });
    const result = await fx.run({ principal_id: "principal-omega" });
    expect(result.status).toBe("commitment_emitted");

    const proposalEntry = fx.auditEntries.find(
      (e) => e.kind === "commitment_proposed"
    );
    const signalEntry = fx.auditEntries.find(
      (e) => e.kind === "composition_signal"
    );
    if (proposalEntry?.kind !== "commitment_proposed")
      throw new Error("type narrowing");
    if (signalEntry?.kind !== "composition_signal")
      throw new Error("type narrowing");
    expect(proposalEntry.principal_id).toBe("principal-omega");
    expect(signalEntry.principal_id).toBe("principal-omega");

    // v1.0 invariant: VerascoreSignal schema does NOT carry principal_id.
    // The field is accepted at the v1.0 emitter's input for v1.x surfaces
    // to populate without a schema break, but is NOT emitted on the signal.
    expect(result.signal).not.toHaveProperty("principal_id");
    expect(JSON.stringify(result.signal)).not.toContain("principal-omega");

    // Keys of result.signal must not leak principal_id into any nested shape
    // either; the assertion above covers serialized containment.
    const serialized = JSON.stringify(result.signal);
    expect(serialized.includes("principal-omega")).toBe(false);

    // Signature is over the signal canonical form; sanity-check it verifies
    // against the HKDF-derived sidecar public key (the same invariant
    // Follow-up #2a locked for emitForCommitment).
    const signal = result.signal!;
    const signableData = { ...signal, signature: undefined };
    const canonical = JSON.stringify(
      signableData,
      Object.keys(signableData).sort()
    );
    const bytes = new TextEncoder().encode(canonical);
    const pad = "=".repeat((4 - (signal.signature.length % 4)) % 4);
    const b64 = (signal.signature + pad).replace(/-/g, "+").replace(/_/g, "/");
    const sigBytes = Uint8Array.from(Buffer.from(b64, "base64"));
    const pub = fx.service!.getSidecarSigningKey()!.publicKey;
    expect(ed25519.verify(sigBytes, bytes, pub)).toBe(true);
  });
});

// -----------------------------------------------------------------------
// Additional shape guards
// -----------------------------------------------------------------------

describe("commitment_denied classification", () => {
  it("null policy returns commitment_denied (policy refusal), not not_a_commitment (missing shape)", async () => {
    const fx = buildPipelineFixture({
      composition_enabled: true,
      policy: null,
    });
    const result = await fx.run();
    expect(result.gateResult.decision).toBe("deny");
    expect(result.status).toBe("commitment_denied");
    expect(fx.auditEntries).toHaveLength(0);
    expect(getPublishedSignals()).toHaveLength(0);
  });

  it("commitment_class not in policy capabilities returns commitment_denied", async () => {
    const fx = buildPipelineFixture({ composition_enabled: true });
    const result = await fx.run({
      request: commitmentRequest({ commitment_class: "escrow-hold" }),
    });
    expect(result.gateResult.decision).toBe("deny");
    expect(result.status).toBe("commitment_denied");
    expect(fx.auditEntries).toHaveLength(0);
  });
});
