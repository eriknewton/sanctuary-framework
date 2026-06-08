/**
 * WP-V1.3-6 Xi-2 English-Authored Policy Activation Lifecycle suite.
 *
 * Coverage:
 *   - applyRule pure function across all 5 rule kinds (tier1 add/remove,
 *     tier3 add/remove, tier2_set_field) including dedupe + invalid-rule
 *     rejection.
 *   - inverseRule symmetry for tier1/tier3 add/remove.
 *   - canonicalPolicyHash determinism + field-order independence.
 *   - PolicyActivationStore round-trip (save -> load -> list) with
 *     AAD binding per fortress.
 *   - EnglishPolicyActivator.activate(): success path, low-confidence
 *     refusal (without override + with override), already-activated
 *     idempotency, draft_not_found via revoke.
 *   - EnglishPolicyActivator.revoke(): success path, drift-warning
 *     emitted when policy mutated since activation.
 *   - HTTP routes: POST .../activate success (+ override query param),
 *     POST .../activate 409 on low-confidence refusal, GET .../status,
 *     DELETE .../{id} revoke.
 *   - Audit emission: ACTIVATED + REVOKED + ACTIVATION_REFUSED counts.
 *   - Multi-fortress isolation: PolicyActivationStore AAD prevents
 *     cross-fortress decryption.
 *   - Castle-walking: full activate + revoke round-trip emits no
 *     outbound audit ops.
 */

import { describe, it, expect } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { Writable } from "node:stream";

import {
  AuditLog,
  type AuditEntry,
} from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import type { PrincipalPolicy } from "../../src/principal-policy/types.js";
import {
  EnglishPolicyCompiler,
} from "../../src/policy-engine/english-policy-compiler.js";
import type {
  CompiledPolicy,
  CompiledPolicyRule,
} from "../../src/policy-engine/english-policy-compiler.js";
import {
  EnglishPolicyActivator,
  ENGLISH_POLICY_ACTIVATION_AUDIT_OPS,
  PolicyActivationStore,
  applyRule,
  canonicalPolicyHash,
  inverseRule,
} from "../../src/policy-engine/english-policy-activator.js";
import {
  ENGLISH_POLICY_API_PREFIX,
  EnglishPolicyDraftStore,
  handleEnglishPolicyRoute,
} from "../../src/policy-engine/english-policy-routes.js";
import { runPolicyCommand } from "../../src/cli/policy.js";

const FORTRESS_A = "fortress_a";
const FORTRESS_B = "fortress_b";
const OPERATOR = "operator_alpha";
const OPERATOR_TOKEN = "operator-token";
const OBSERVED_AT = "2026-05-09T12:00:00.000Z";

function clonePolicy(): PrincipalPolicy {
  const policy = JSON.parse(JSON.stringify(DEFAULT_POLICY)) as PrincipalPolicy;
  policy.tier1_always_approve = policy.tier1_always_approve.filter(
    (op) => op !== "state_export",
  );
  return policy;
}

function buildCompiled(
  rule: CompiledPolicyRule,
  opts?: { confidence?: CompiledPolicy["compile_confidence"] },
): CompiledPolicy {
  return {
    draft_id: `draft-${rule.kind}-${rule.operation ?? rule.tier2_update?.field ?? "x"}`,
    english_text: "fixture",
    compiled_rule: rule,
    explanation_paragraph: "fixture explanation",
    compile_confidence: opts?.confidence ?? "high",
    compile_warnings: [],
    substrate_used: "deterministic",
    compiled_at: OBSERVED_AT,
    operator_id: OPERATOR,
    fortress_id: FORTRESS_A,
  };
}

interface ActivatorRig {
  auditLog: AuditLog;
  store: PolicyActivationStore;
  activator: EnglishPolicyActivator;
  livePolicy: { current: PrincipalPolicy };
}

function makeActivatorRig(opts?: {
  fortressId?: string;
  policy?: PrincipalPolicy;
}): ActivatorRig {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const store = new PolicyActivationStore({
    storage,
    masterKey,
    fortressId: opts?.fortressId ?? FORTRESS_A,
  });
  const livePolicy = { current: opts?.policy ?? clonePolicy() };
  const activator = new EnglishPolicyActivator({
    store,
    auditLog,
    fortressId: opts?.fortressId ?? FORTRESS_A,
    readPolicy: async () => livePolicy.current,
    writePolicy: async (p) => {
      livePolicy.current = p;
    },
  });
  return { auditLog, store, activator, livePolicy };
}

async function auditOps(auditLog: AuditLog): Promise<string[]> {
  const result = await auditLog.query({ layer: "l2", limit: 200 });
  return result.entries.map((e: AuditEntry) => e.operation);
}

class CollectStream extends Writable {
  chunks: Buffer[] = [];
  override _write(chunk: Buffer, _enc: string, cb: () => void): void {
    this.chunks.push(Buffer.from(chunk));
    cb();
  }
  get text(): string {
    return Buffer.concat(this.chunks).toString("utf-8");
  }
}

describe("Xi-2 - applyRule pure function", () => {
  it("tier1_add_operation appends + dedupes", () => {
    const base = clonePolicy();
    const after = applyRule(base, {
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    expect(after.tier1_always_approve).toContain("state_export");
    // Idempotent on second apply.
    const again = applyRule(after, {
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    expect(
      again.tier1_always_approve.filter((op) => op === "state_export").length,
    ).toBe(1);
  });

  it("tier3_add_operation appends + tier3_remove_operation removes", () => {
    const added = applyRule(clonePolicy(), {
      kind: "tier3_add_operation",
      operation: "custom_op",
    });
    expect(added.tier3_always_allow).toContain("custom_op");
    const removed = applyRule(added, {
      kind: "tier3_remove_operation",
      operation: "custom_op",
    });
    expect(removed.tier3_always_allow).not.toContain("custom_op");
  });

  it("tier2_set_field updates numeric and AnomalyAction fields", () => {
    const numeric = applyRule(clonePolicy(), {
      kind: "tier2_set_field",
      tier2_update: { field: "frequency_spike_multiplier", value: 7 },
    });
    expect(numeric.tier2_anomaly.frequency_spike_multiplier).toBe(7);
    const action = applyRule(clonePolicy(), {
      kind: "tier2_set_field",
      tier2_update: { field: "first_session_policy", value: "log" },
    });
    expect(action.tier2_anomaly.first_session_policy).toBe("log");
  });

  it("invalid rule shapes throw (missing operation, missing tier2_update, bad type)", () => {
    expect(() =>
      applyRule(clonePolicy(), { kind: "tier1_add_operation" }),
    ).toThrow(/requires a non-empty operation/);
    expect(() =>
      applyRule(clonePolicy(), { kind: "tier2_set_field" }),
    ).toThrow(/requires tier2_update/);
    expect(() =>
      applyRule(clonePolicy(), {
        kind: "tier2_set_field",
        tier2_update: { field: "frequency_spike_multiplier", value: "high" },
      }),
    ).toThrow(/numeric value/);
  });
});

describe("Xi-2 - inverseRule symmetry", () => {
  it("add <-> remove inverses across tier1 and tier3", () => {
    const r: CompiledPolicyRule = {
      kind: "tier1_add_operation",
      operation: "x",
    };
    const inv = inverseRule(r, clonePolicy());
    expect(inv.kind).toBe("tier1_remove_operation");
    const back = inverseRule(inv, clonePolicy());
    expect(back.kind).toBe("tier1_add_operation");
  });
});

describe("Xi-2 - canonicalPolicyHash", () => {
  it("is order-stable: tier1 array reordering produces same hash", () => {
    const a = clonePolicy();
    const b = clonePolicy();
    a.tier1_always_approve = ["alpha", "beta"];
    b.tier1_always_approve = ["beta", "alpha"];
    expect(canonicalPolicyHash(a)).toBe(canonicalPolicyHash(b));
  });

  it("differs when content actually changes", () => {
    const a = clonePolicy();
    const b = clonePolicy();
    b.tier1_always_approve = [...b.tier1_always_approve, "novel_op"];
    expect(canonicalPolicyHash(a)).not.toBe(canonicalPolicyHash(b));
  });
});

describe("Xi-2 - PolicyActivationStore round-trip + isolation", () => {
  it("save -> load returns the same record", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new PolicyActivationStore({
      storage,
      masterKey,
      fortressId: FORTRESS_A,
    });
    const draft = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    await store.save({
      draft,
      status: "activated",
      fortress_id: FORTRESS_A,
      activated_at: OBSERVED_AT,
      activated_by: OPERATOR,
    });
    const loaded = await store.load(draft.draft_id);
    expect(loaded).not.toBeNull();
    expect(loaded!.draft.draft_id).toBe(draft.draft_id);
    expect(loaded!.status).toBe("activated");
  });

  it("list returns persisted records", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new PolicyActivationStore({
      storage,
      masterKey,
      fortressId: FORTRESS_A,
    });
    await store.save({
      draft: buildCompiled({ kind: "tier1_add_operation", operation: "x" }),
      status: "activated",
      fortress_id: FORTRESS_A,
    });
    await store.save({
      draft: buildCompiled({ kind: "tier3_add_operation", operation: "y" }),
      status: "pending",
      fortress_id: FORTRESS_A,
    });
    const all = await store.list();
    expect(all.length).toBe(2);
  });

  it("multi-fortress isolation: AAD prevents cross-fortress decrypt", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const storeA = new PolicyActivationStore({
      storage,
      masterKey,
      fortressId: FORTRESS_A,
    });
    const storeB = new PolicyActivationStore({
      storage,
      masterKey,
      fortressId: FORTRESS_B,
    });
    await storeA.save({
      draft: buildCompiled({ kind: "tier1_add_operation", operation: "x" }),
      status: "activated",
      fortress_id: FORTRESS_A,
    });
    const fromB = await storeB.load("draft-tier1_add_operation-x");
    // AAD binds the encryption key to (fortressId, draftId); decrypt
    // by storeB against the same draftId fails -> returns null.
    expect(fromB).toBeNull();
  });
});

describe("Xi-2 - EnglishPolicyActivator.activate()", () => {
  it("activates a high-confidence draft and mutates the live policy", async () => {
    const rig = makeActivatorRig();
    const draft = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    const outcome = await rig.activator.activate(draft, OPERATOR);
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.updated_policy.tier1_always_approve).toContain(
        "state_export",
      );
      expect(outcome.record.status).toBe("activated");
    }
    expect(rig.livePolicy.current.tier1_always_approve).toContain(
      "state_export",
    );
  });

  it("refuses a low-confidence draft without explicit override + emits ACTIVATION_REFUSED audit", async () => {
    const rig = makeActivatorRig();
    const draft = buildCompiled(
      { kind: "tier1_add_operation", operation: "state_export" },
      { confidence: "low" },
    );
    const outcome = await rig.activator.activate(draft, OPERATOR);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.reason).toBe("low_confidence_refused");
    const ops = await auditOps(rig.auditLog);
    expect(ops).toContain(
      ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.ACTIVATION_REFUSED,
    );
  });

  it("activates a low-confidence draft when override_low_confidence is true; record marks the override", async () => {
    const rig = makeActivatorRig();
    const draft = buildCompiled(
      { kind: "tier1_add_operation", operation: "state_export" },
      { confidence: "low" },
    );
    const outcome = await rig.activator.activate(draft, OPERATOR, {
      override_low_confidence: true,
    });
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.record.activation_override).toBe(true);
    }
  });

  it("returns already_activated on a second activate of the same draft", async () => {
    const rig = makeActivatorRig();
    const draft = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    const first = await rig.activator.activate(draft, OPERATOR);
    expect(first.ok).toBe(true);
    const second = await rig.activator.activate(draft, OPERATOR);
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.reason).toBe("already_activated");
  });
});

describe("Xi-3 - pre-activation conflict gating", () => {
  it("checkConflicts returns conflicts and emits policy_conflict_detected", async () => {
    const rig = makeActivatorRig({ policy: DEFAULT_POLICY });
    const draft = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    const conflicts = await rig.activator.checkConflicts(draft, OPERATOR);
    expect(conflicts.length).toBeGreaterThan(0);
    expect(conflicts.some((c) => c.conflict_type === "direct_override")).toBe(
      true,
    );
    const ops = await auditOps(rig.auditLog);
    expect(ops).toContain(
      ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.CONFLICT_DETECTED,
    );
  });

  it("HTTP-style activation gate refuses conflicts without acknowledgment", async () => {
    const rig = makeActivatorRig({ policy: DEFAULT_POLICY });
    const draft = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    const outcome = await rig.activator.activate(draft, OPERATOR);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.reason).toBe("policy_conflicts_unacknowledged");
      expect(outcome.conflicts?.length).toBeGreaterThan(0);
    }
  });

  it("activates low-severity direct overrides after acknowledgment", async () => {
    const rig = makeActivatorRig({ policy: DEFAULT_POLICY });
    const draft = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    const conflicts = await rig.activator.checkConflicts(draft, OPERATOR);
    const outcome = await rig.activator.activate(draft, OPERATOR, {
      conflicts_acknowledged: conflicts,
    });
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.record.conflicts_acknowledged?.length).toBe(
        conflicts.length,
      );
    }
    const ops = await auditOps(rig.auditLog);
    expect(ops).toContain(
      ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.CONFLICT_ACKNOWLEDGED,
    );
  });

  it("hard-blocks high-severity contradictions until the conflict id is forced", async () => {
    const rig = makeActivatorRig({ policy: DEFAULT_POLICY });
    const draft = buildCompiled({
      kind: "tier3_add_operation",
      operation: "state_export",
    });
    const conflicts = await rig.activator.checkConflicts(draft, OPERATOR);
    const highIds = conflicts
      .filter((c) => c.severity === "high")
      .map((c) => c.conflict_id);
    const blocked = await rig.activator.activate(draft, OPERATOR, {
      conflicts_acknowledged: conflicts,
    });
    expect(blocked.ok).toBe(false);
    if (!blocked.ok) {
      expect(blocked.reason).toBe("policy_conflict_force_required");
    }
    const forced = await rig.activator.activate(draft, OPERATOR, {
      conflicts_acknowledged: conflicts,
      force_conflict_ids: highIds,
    });
    expect(forced.ok).toBe(true);
    const ops = await auditOps(rig.auditLog);
    expect(ops).toContain(
      ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.FORCE_CONFLICT_USED,
    );
  });
});

describe("Xi-2 - EnglishPolicyActivator.revoke()", () => {
  it("revokes an activated draft and applies the inverse rule", async () => {
    const rig = makeActivatorRig();
    const draft = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    await rig.activator.activate(draft, OPERATOR);
    expect(rig.livePolicy.current.tier1_always_approve).toContain(
      "state_export",
    );
    const outcome = await rig.activator.revoke(draft.draft_id, OPERATOR);
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.record.status).toBe("revoked");
      expect(outcome.updated_policy.tier1_always_approve).not.toContain(
        "state_export",
      );
    }
  });

  it("revoke returns not_activated for a pending draft", async () => {
    const rig = makeActivatorRig();
    const outcome = await rig.activator.revoke("never-saved", OPERATOR);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.reason).toBe("draft_not_found");
  });

  it("revoke emits a drift_warning in audit when the live policy mutated since activation", async () => {
    const rig = makeActivatorRig();
    const draft = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    await rig.activator.activate(draft, OPERATOR);
    // External mutation that bypasses the activator -- simulate the
    // policy file being edited out-of-band between activate + revoke.
    rig.livePolicy.current = {
      ...rig.livePolicy.current,
      tier1_always_approve: [
        ...rig.livePolicy.current.tier1_always_approve,
        "drifted_extra_op",
      ],
    };
    const outcome = await rig.activator.revoke(draft.draft_id, OPERATOR);
    expect(outcome.ok).toBe(true);
    const auditEntries = await rig.auditLog.query({ layer: "l2", limit: 200 });
    const revokeEntry = auditEntries.entries.find(
      (e) => e.operation === ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.REVOKED,
    );
    expect(revokeEntry).toBeDefined();
    expect(revokeEntry!.details?.["drift_warning"]).toBe(
      "policy_drift_since_activation",
    );
  });
});

describe("Xi-2 - HTTP routes", () => {
  async function makeServer(deps: {
    compiler: EnglishPolicyCompiler;
    store: EnglishPolicyDraftStore;
    activator: EnglishPolicyActivator;
  }): Promise<{ base: string; close: () => Promise<void> }> {
    const server: Server = createServer(async (req, res) => {
      const handled = await handleEnglishPolicyRoute(
        {
          authConfig: { loopbackAutoAuth: true, authToken: OPERATOR_TOKEN },
          compiler: deps.compiler,
          store: deps.store,
          activator: deps.activator,
        },
        req,
        res,
      );
      if (!handled) res.writeHead(404).end();
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const addr = server.address() as AddressInfo;
    return {
      base: `http://127.0.0.1:${addr.port}`,
      close: () =>
        new Promise<void>((resolve) => server.close(() => resolve())),
    };
  }

  function operatorHeaders(extra?: HeadersInit): HeadersInit {
    return { Authorization: `Bearer ${OPERATOR_TOKEN}`, ...(extra ?? {}) };
  }

  function compilerFor(auditLog: AuditLog): EnglishPolicyCompiler {
    return new EnglishPolicyCompiler({
      auditLog,
      fortressId: FORTRESS_A,
      selector: null,
    });
  }

  it("POST /api/policy/drafts/:id/activate activates a high-confidence draft", async () => {
    const rig = makeActivatorRig();
    const compiler = compilerFor(rig.auditLog);
    const store = new EnglishPolicyDraftStore();
    const draft = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    store.put(draft);
    const { base, close } = await makeServer({
      compiler,
      store,
      activator: rig.activator,
    });
    try {
      const res = await fetch(
        `${base}${ENGLISH_POLICY_API_PREFIX}/drafts/${draft.draft_id}/activate`,
        { method: "POST", headers: operatorHeaders() },
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        data: { status: string; updated_policy?: PrincipalPolicy; record?: unknown };
      };
      expect(body.data.status).toBe("activated");
      expect(body.data.updated_policy).toBeUndefined();
      expect(body.data.record).toBeUndefined();
    } finally {
      await close();
    }
  });

  it("POST /api/policy/drafts/:id/activate refuses a non-operator caller before mutation", async () => {
    const rig = makeActivatorRig();
    const compiler = compilerFor(rig.auditLog);
    const store = new EnglishPolicyDraftStore();
    const draft = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    store.put(draft);
    const { base, close } = await makeServer({
      compiler,
      store,
      activator: rig.activator,
    });
    try {
      const res = await fetch(
        `${base}${ENGLISH_POLICY_API_PREFIX}/drafts/${draft.draft_id}/activate`,
        { method: "POST" },
      );
      expect(res.status).toBe(403);
      const body = (await res.json()) as { error: string };
      expect(body.error).toBe("operator_auth_required");
      expect(rig.livePolicy.current.tier1_always_approve).not.toContain(
        "state_export",
      );
    } finally {
      await close();
    }
  });

  it("POST .../activate without override returns 409 on a low-confidence draft", async () => {
    const rig = makeActivatorRig();
    const compiler = compilerFor(rig.auditLog);
    const store = new EnglishPolicyDraftStore();
    const draft = buildCompiled(
      { kind: "tier1_add_operation", operation: "state_export" },
      { confidence: "low" },
    );
    store.put(draft);
    const { base, close } = await makeServer({
      compiler,
      store,
      activator: rig.activator,
    });
    try {
      const res = await fetch(
        `${base}${ENGLISH_POLICY_API_PREFIX}/drafts/${draft.draft_id}/activate`,
        { method: "POST", headers: operatorHeaders() },
      );
      expect(res.status).toBe(409);
      const body = (await res.json()) as {
        error: string;
        detail?: string;
        data?: { conflicts?: unknown[] };
      };
      expect(body.error).toBe("activation_refused");
      expect(body.detail).toBeUndefined();
      expect(body.data?.conflicts).toBeUndefined();
      const okOverride = await fetch(
        `${base}${ENGLISH_POLICY_API_PREFIX}/drafts/${draft.draft_id}/activate?override=true`,
        { method: "POST", headers: operatorHeaders() },
      );
      expect(okOverride.status).toBe(200);
    } finally {
      await close();
    }
  });

  it("DELETE /api/policy/drafts/:id revokes an activated draft", async () => {
    const rig = makeActivatorRig();
    const compiler = compilerFor(rig.auditLog);
    const store = new EnglishPolicyDraftStore();
    const draft = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    store.put(draft);
    await rig.activator.activate(draft, OPERATOR);
    const { base, close } = await makeServer({
      compiler,
      store,
      activator: rig.activator,
    });
    try {
      const res = await fetch(
        `${base}${ENGLISH_POLICY_API_PREFIX}/drafts/${draft.draft_id}`,
        { method: "DELETE", headers: operatorHeaders() },
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        data: { status: string; updated_policy?: PrincipalPolicy; record?: unknown };
      };
      expect(body.data.status).toBe("revoked");
      expect(body.data.updated_policy).toBeUndefined();
      expect(body.data.record).toBeUndefined();
    } finally {
      await close();
    }
  });

  it("GET /api/policy/drafts/:id/status returns the persisted record", async () => {
    const rig = makeActivatorRig();
    const compiler = compilerFor(rig.auditLog);
    const store = new EnglishPolicyDraftStore();
    const draft = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    store.put(draft);
    await rig.activator.activate(draft, OPERATOR);
    const { base, close } = await makeServer({
      compiler,
      store,
      activator: rig.activator,
    });
    try {
      const res = await fetch(
        `${base}${ENGLISH_POLICY_API_PREFIX}/drafts/${draft.draft_id}/status`,
        { headers: operatorHeaders() },
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        data: { status: string; record?: unknown };
      };
      expect(body.data.status).toBe("activated");
      expect(body.data.record).toBeUndefined();
    } finally {
      await close();
    }
  });

  it("POST /api/policy/drafts/:id/check-conflicts returns conflicts without activating", async () => {
    const rig = makeActivatorRig({ policy: DEFAULT_POLICY });
    const compiler = compilerFor(rig.auditLog);
    const store = new EnglishPolicyDraftStore();
    const draft = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    store.put(draft);
    const { base, close } = await makeServer({
      compiler,
      store,
      activator: rig.activator,
    });
    try {
      const res = await fetch(
        `${base}${ENGLISH_POLICY_API_PREFIX}/drafts/${draft.draft_id}/check-conflicts`,
        { method: "POST", headers: operatorHeaders() },
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        data: { status: string; conflicts?: unknown[] };
      };
      expect(body.data.status).toBe("review_recorded");
      expect(body.data.conflicts).toBeUndefined();
      expect(rig.livePolicy.current.tier1_always_approve).toContain(
        "state_export",
      );
    } finally {
      await close();
    }
  });

  it("POST .../activate returns 409 without conflict acknowledgment, then proceeds with acknowledgment", async () => {
    const rig = makeActivatorRig({ policy: DEFAULT_POLICY });
    const compiler = compilerFor(rig.auditLog);
    const store = new EnglishPolicyDraftStore();
    const draft = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    store.put(draft);
    const { base, close } = await makeServer({
      compiler,
      store,
      activator: rig.activator,
    });
    try {
      const blocked = await fetch(
        `${base}${ENGLISH_POLICY_API_PREFIX}/drafts/${draft.draft_id}/activate`,
        { method: "POST", headers: operatorHeaders() },
      );
      expect(blocked.status).toBe(409);
      const blockedBody = (await blocked.json()) as {
        error: string;
        detail?: string;
        data?: { conflicts?: unknown[] };
      };
      expect(blockedBody.error).toBe("activation_refused");
      expect(blockedBody.detail).toBeUndefined();
      expect(blockedBody.data?.conflicts).toBeUndefined();
      const ok = await fetch(
        `${base}${ENGLISH_POLICY_API_PREFIX}/drafts/${draft.draft_id}/activate`,
        {
          method: "POST",
          headers: operatorHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({
            acknowledge_conflicts: true,
          }),
        },
      );
      expect(ok.status).toBe(200);
    } finally {
      await close();
    }
  });

  it("CLI drafts check-conflicts prints server-returned conflicts", async () => {
    const rig = makeActivatorRig({ policy: DEFAULT_POLICY });
    const compiler = compilerFor(rig.auditLog);
    const store = new EnglishPolicyDraftStore();
    const draft = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    store.put(draft);
    const { base, close } = await makeServer({
      compiler,
      store,
      activator: rig.activator,
    });
    try {
      const out = new CollectStream();
      const err = new CollectStream();
      const prevToken = process.env["SANCTUARY_POLICY_API_TOKEN"];
      process.env["SANCTUARY_POLICY_API_TOKEN"] = OPERATOR_TOKEN;
      const code = await runPolicyCommand({
        argv: [
          "drafts",
          "check-conflicts",
          draft.draft_id,
          "--api-base",
          base,
        ],
        out,
        err,
      });
      if (prevToken === undefined) {
        delete process.env["SANCTUARY_POLICY_API_TOKEN"];
      } else {
        process.env["SANCTUARY_POLICY_API_TOKEN"] = prevToken;
      }
      expect(code).toBe(0);
      expect(out.text).toContain("conflict review: review_recorded");
      expect(err.text).toBe("");
    } finally {
      await close();
    }
  });

  it("CLI drafts activate refuses high-severity conflicts without --force-conflict", async () => {
    const rig = makeActivatorRig({ policy: DEFAULT_POLICY });
    const compiler = compilerFor(rig.auditLog);
    const store = new EnglishPolicyDraftStore();
    const draft = buildCompiled({
      kind: "tier3_add_operation",
      operation: "state_export",
    });
    store.put(draft);
    const { base, close } = await makeServer({
      compiler,
      store,
      activator: rig.activator,
    });
    try {
      const out = new CollectStream();
      const err = new CollectStream();
      const prevToken = process.env["SANCTUARY_POLICY_API_TOKEN"];
      process.env["SANCTUARY_POLICY_API_TOKEN"] = OPERATOR_TOKEN;
      const code = await runPolicyCommand({
        argv: [
          "drafts",
          "activate",
          draft.draft_id,
          "--acknowledge-conflicts",
          "--api-base",
          base,
        ],
        out,
        err,
      });
      if (prevToken === undefined) {
        delete process.env["SANCTUARY_POLICY_API_TOKEN"];
      } else {
        process.env["SANCTUARY_POLICY_API_TOKEN"] = prevToken;
      }
      expect(code).toBe(1);
      expect(err.text).toContain("activation failed: activation_refused");
      expect(out.text).toBe("");
    } finally {
      await close();
    }
  });
});

describe("Xi-2 - audit emission + Castle-walking", () => {
  it("ACTIVATED audit op fires with the rule_kind + operation in details", async () => {
    const rig = makeActivatorRig();
    const draft = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    await rig.activator.activate(draft, OPERATOR);
    const entries = await rig.auditLog.query({ layer: "l2", limit: 200 });
    const e = entries.entries.find(
      (x) => x.operation === ENGLISH_POLICY_ACTIVATION_AUDIT_OPS.ACTIVATED,
    );
    expect(e).toBeDefined();
    expect(e!.details?.["rule_kind"]).toBe("tier1_add_operation");
    expect(e!.details?.["rule_operation"]).toBe("state_export");
  });

  it("Castle-walking: activate + revoke emit no outbound audit ops", async () => {
    const rig = makeActivatorRig();
    const draft = buildCompiled({
      kind: "tier1_add_operation",
      operation: "state_export",
    });
    await rig.activator.activate(draft, OPERATOR);
    await rig.activator.revoke(draft.draft_id, OPERATOR);
    const ops = new Set(await auditOps(rig.auditLog));
    expect([...ops].some((o) => o.startsWith("proxy_call:"))).toBe(false);
    expect(ops.has("query_anonymity_headers_stripped")).toBe(false);
    expect(ops.has("intelligence_substrate_invoked")).toBe(false);
  });
});
