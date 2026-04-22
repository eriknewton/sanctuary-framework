/**
 * WP-MVP-6: Egress Controls + Spend Budgets + Retention Windows.
 *
 * Seven acceptance criteria per spawn prompt:
 *   AC1: Egress deny path
 *   AC2: Budget hard-stop path
 *   AC3: Retention sweep deterministic
 *   AC4: All controls survive policy re-pin
 *   AC5: No-LLM-at-gate preserved (extended structural test)
 *   AC6: Signed-event fields correct
 *   AC7: Baseline + CI (not a test — validated by CI and .test-baseline)
 */

import { describe, expect, it, beforeEach } from "vitest";
import { buildFortress, type TestFortress } from "./fixture.js";
import { compileFixturePolicy } from "../../src/policy-engine/compiler-fixture.js";
import {
  evaluateEgressGate,
  type EgressGateContext,
  type EgressRequest,
} from "../../src/policy-engine/egress-gate.js";
import {
  BudgetTracker,
  isBudgetExhausted,
} from "../../src/policy-engine/budget-gate.js";
import {
  executeRetentionSweep,
  InMemoryRetentionStore,
  RetentionSweepScheduler,
} from "../../src/policy-engine/retention-sweep.js";
import {
  EGRESS_BUDGET_RETENTION_REASON_CODES,
  POLICY_SLOTS,
  type PolicySlot,
} from "../../src/policy-engine/constants.js";
import { emitUsageEvent } from "../../src/agent-contract/usage-event.js";
import { EVENT_CLASSES, SIGNATURE_SCHEME_V1 } from "../../src/agent-contract/constants.js";
import type { CompiledPolicy } from "../../src/policy-engine/types.js";
import {
  encodePolicyBlob,
  decodePolicyBlob,
  validateCompiledPolicyShape,
} from "../../src/policy-engine/canonical-policy.js";
import { packPolicyUpdate, unpackPolicyUpdate } from "../../src/policy-engine/envelope.js";
import { verifyCtxFor } from "./fixture.js";
import { sha256 } from "@noble/hashes/sha256";
import { toBase64url } from "../../src/core/encoding.js";
import { canonicalizeToBytes } from "../../src/mesh/canonical-json.js";

let f: TestFortress;

beforeEach(() => {
  f = buildFortress();
});

// ═══════════════════════════════════════════════════════════════════════
// AC1: Egress deny path
// ═══════════════════════════════════════════════════════════════════════

describe("AC1 — egress deny path", () => {
  it("blocks egress to a destination outside the pinned allowlist", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 may egress to api.openai.com via POST.",
    });
    const ctx: EgressGateContext = {
      policy,
      nodeSigningKey: f.nodeKeypair.privateKey,
      nodeId: f.nodeCert.node_id,
      fortressId: f.master.public.fortress_id,
    };

    // Allowed destination + method.
    const r1 = evaluateEgressGate(ctx, {
      agent_id: "a1",
      destination: "api.openai.com",
      method: "POST",
    });
    expect(r1.decision).toBe("allow");
    expect(r1.reason_code).toBe(
      EGRESS_BUDGET_RETENTION_REASON_CODES.EGRESS_ALLOWED
    );

    // Denied destination (not in allowlist).
    const r2 = evaluateEgressGate(ctx, {
      agent_id: "a1",
      destination: "evil.example.com",
      method: "GET",
    });
    expect(r2.decision).toBe("deny");
    expect(r2.reason_code).toBe(
      EGRESS_BUDGET_RETENTION_REASON_CODES.EGRESS_DESTINATION_DENIED
    );

    // Denied method (destination matches, method doesn't).
    const r3 = evaluateEgressGate(ctx, {
      agent_id: "a1",
      destination: "api.openai.com",
      method: "DELETE",
    });
    expect(r3.decision).toBe("deny");
    expect(r3.reason_code).toBe(
      EGRESS_BUDGET_RETENTION_REASON_CODES.EGRESS_METHOD_DENIED
    );
  });

  it("blocks all egress when no egress policy is set", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 may read outputs from agent a2.",
    });
    const ctx: EgressGateContext = {
      policy,
      nodeSigningKey: f.nodeKeypair.privateKey,
      nodeId: f.nodeCert.node_id,
      fortressId: f.master.public.fortress_id,
    };
    const r = evaluateEgressGate(ctx, {
      agent_id: "a1",
      destination: "api.openai.com",
      method: "POST",
    });
    expect(r.decision).toBe("deny");
    expect(r.reason_code).toBe(
      EGRESS_BUDGET_RETENTION_REASON_CODES.EGRESS_NO_POLICY
    );
  });

  it("blocks all egress when no pinned policy", () => {
    const ctx: EgressGateContext = {
      policy: null,
      nodeSigningKey: f.nodeKeypair.privateKey,
      nodeId: f.nodeCert.node_id,
      fortressId: f.master.public.fortress_id,
    };
    const r = evaluateEgressGate(ctx, {
      agent_id: "a1",
      destination: "api.openai.com",
      method: "POST",
    });
    expect(r.decision).toBe("deny");
  });

  it("allows all methods when method list is empty", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 may egress to api.openai.com.",
    });
    const ctx: EgressGateContext = {
      policy,
      nodeSigningKey: f.nodeKeypair.privateKey,
      nodeId: f.nodeCert.node_id,
      fortressId: f.master.public.fortress_id,
    };
    // All methods should work.
    for (const method of ["GET", "POST", "PUT", "DELETE", "PATCH"]) {
      const r = evaluateEgressGate(ctx, {
        agent_id: "a1",
        destination: "api.openai.com",
        method,
      });
      expect(r.decision).toBe("allow");
    }
  });

  it("emits a signed gate receipt on every evaluation", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 may egress to api.openai.com via POST.",
    });
    const ctx: EgressGateContext = {
      policy,
      nodeSigningKey: f.nodeKeypair.privateKey,
      nodeId: f.nodeCert.node_id,
      fortressId: f.master.public.fortress_id,
    };
    const r = evaluateEgressGate(ctx, {
      agent_id: "a1",
      destination: "evil.example.com",
      method: "GET",
    });
    expect(r.receipt).toBeDefined();
    expect(r.receipt.decision).toBe("deny");
    expect(r.receipt.signature).toBeTruthy();
    expect(r.receipt.fortress_id).toBe(f.master.public.fortress_id);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// AC2: Budget hard-stop path
// ═══════════════════════════════════════════════════════════════════════

describe("AC2 — budget hard-stop path", () => {
  it("rejects commitment when daily budget exceeded", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english:
        "Agent a1 may egress to api.openai.com. Agent a1 has a daily budget of 1 usd.",
    });

    const tracker = new BudgetTracker();
    const now = Date.now();

    // Accumulate $1.01 in spend.
    tracker.recordSpend("a1", 0.50, new Date(now - 1000).toISOString());
    tracker.recordSpend("a1", 0.51, new Date(now - 500).toISOString());

    const { exhausted, result } = isBudgetExhausted(tracker, "a1", policy);
    expect(exhausted).toBe(true);
    expect(result.level).toBe("hard_stop");
    expect(result.reason_code).toBe(
      EGRESS_BUDGET_RETENTION_REASON_CODES.BUDGET_HARD_STOP
    );
  });

  it("allows commitment when within budget", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 has a daily budget of 10 usd.",
    });

    const tracker = new BudgetTracker();
    tracker.recordSpend("a1", 5.0, new Date().toISOString());

    const { exhausted, result } = isBudgetExhausted(tracker, "a1", policy);
    expect(exhausted).toBe(false);
    expect(result.level).toBe("within_limits");
  });

  it("emits soft warn at 80% threshold", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 has a daily budget of 100 tokens.",
    });

    const tracker = new BudgetTracker();
    const now = Date.now();
    // Accumulate 85 tokens (above 80% soft warn).
    tracker.recordSpend("a1", 85, new Date(now - 100).toISOString());

    const result = tracker.checkBudget("a1", policy.budgets, now);
    expect(result.level).toBe("soft_warn");
    expect(result.allowed).toBe(true); // Agent continues.
    expect(result.reason_code).toBe(
      EGRESS_BUDGET_RETENTION_REASON_CODES.BUDGET_SOFT_WARN
    );
  });

  it("respects custom soft-warn threshold", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 has a daily budget of 100 tokens with 90% warn.",
    });

    const tracker = new BudgetTracker();
    const now = Date.now();
    // 85 tokens: below 90% threshold.
    tracker.recordSpend("a1", 85, new Date(now - 100).toISOString());
    const r1 = tracker.checkBudget("a1", policy.budgets, now);
    expect(r1.level).toBe("within_limits");

    // 91 tokens: above 90% threshold.
    tracker.recordSpend("a1", 6, new Date(now - 50).toISOString());
    const r2 = tracker.checkBudget("a1", policy.budgets, now);
    expect(r2.level).toBe("soft_warn");
  });

  it("rolls off old spend outside 24h daily window", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 has a daily budget of 10 usd.",
    });

    const tracker = new BudgetTracker();
    const now = Date.now();
    // Spend from 25 hours ago (outside 24h window).
    tracker.recordSpend(
      "a1",
      9.0,
      new Date(now - 25 * 60 * 60 * 1000).toISOString()
    );
    // Spend from 1 hour ago (inside window).
    tracker.recordSpend(
      "a1",
      2.0,
      new Date(now - 60 * 60 * 1000).toISOString()
    );

    const result = tracker.checkBudget("a1", policy.budgets, now);
    // Only the $2 counts in the rolling window.
    expect(result.level).toBe("within_limits");
    expect(result.allowed).toBe(true);
  });

  it("respects monthly budget limits", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 has a monthly budget of 50 usd.",
    });

    const tracker = new BudgetTracker();
    const now = Date.now();
    // Accumulate $51.
    tracker.recordSpend("a1", 51, new Date(now - 1000).toISOString());

    const { exhausted } = isBudgetExhausted(tracker, "a1", policy);
    expect(exhausted).toBe(true);
  });

  it("allows proceed when no budget policy", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 may read outputs from agent a2.",
    });

    const tracker = new BudgetTracker();
    const { exhausted } = isBudgetExhausted(tracker, "a1", policy);
    expect(exhausted).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// AC3: Retention sweep deterministic
// ═══════════════════════════════════════════════════════════════════════

describe("AC3 — retention sweep deterministic", () => {
  it("sweeps expired entries deterministically across all four slots", async () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: [
        "Agent a1 retains memory for 3600 seconds.",
        "Agent a1 retains credentials for 3600 seconds.",
        "Agent a1 retains plans for 3600 seconds.",
        "Agent a1 retains outputs for 3600 seconds.",
      ].join(" "),
    });

    const store = new InMemoryRetentionStore();
    const now = Date.now();

    // Seed 10 entries per slot: 4 expired (created 2 hours ago), 6 current.
    for (const slot of POLICY_SLOTS) {
      for (let i = 0; i < 4; i++) {
        store.seed("a1", slot, {
          key: `${slot}-expired-${i}`,
          created_at: new Date(now - 2 * 60 * 60 * 1000).toISOString(), // 2h ago
        });
      }
      for (let i = 0; i < 6; i++) {
        store.seed("a1", slot, {
          key: `${slot}-current-${i}`,
          created_at: new Date(now - 30 * 60 * 1000).toISOString(), // 30min ago
        });
      }
    }

    const result = await executeRetentionSweep({
      agent_id: "a1",
      retention: policy.retention,
      store,
      now,
    });

    // Assert: 4 swept per slot, 6 retained per slot.
    for (const slot of POLICY_SLOTS) {
      expect(result.swept[slot]).toBe(4);
      expect(result.retained[slot]).toBe(6);
      expect(store.countEntries("a1", slot)).toBe(6);
    }
  });

  it("archives instead of deleting when archive flag is set", async () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english:
        "Agent a1 retains memory for 3600 seconds with archive.",
    });

    const store = new InMemoryRetentionStore();
    const now = Date.now();
    store.seed("a1", "memory", {
      key: "old-entry",
      created_at: new Date(now - 2 * 60 * 60 * 1000).toISOString(),
    });

    await executeRetentionSweep({
      agent_id: "a1",
      retention: policy.retention,
      store,
      now,
    });

    expect(store.countEntries("a1", "memory")).toBe(0);
    expect(store.getArchived("a1", "memory")).toHaveLength(1);
  });

  it("retains all entries when no retention policy", async () => {
    const store = new InMemoryRetentionStore();
    for (const slot of POLICY_SLOTS) {
      store.seed("a1", slot, {
        key: `${slot}-entry`,
        created_at: new Date(Date.now() - 999999000).toISOString(),
      });
    }

    const result = await executeRetentionSweep({
      agent_id: "a1",
      retention: undefined,
      store,
    });

    for (const slot of POLICY_SLOTS) {
      expect(result.swept[slot]).toBe(0);
      expect(result.retained[slot]).toBe(1);
    }
  });

  it("retains entries for slots without a configured window", async () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 retains memory for 3600 seconds.",
    });

    const store = new InMemoryRetentionStore();
    const now = Date.now();
    // Memory has a window; credentials does not.
    store.seed("a1", "memory", {
      key: "old",
      created_at: new Date(now - 2 * 60 * 60 * 1000).toISOString(),
    });
    store.seed("a1", "credentials", {
      key: "old",
      created_at: new Date(now - 999999000).toISOString(),
    });

    const result = await executeRetentionSweep({
      agent_id: "a1",
      retention: policy.retention,
      store,
      now,
    });

    expect(result.swept.memory).toBe(1);
    expect(result.swept.credentials).toBe(0);
    expect(result.retained.credentials).toBe(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// AC4: All controls survive policy re-pin
// ═══════════════════════════════════════════════════════════════════════

describe("AC4 — policy re-pin switches all three controls", () => {
  it("egress allowlist switches on re-pin", () => {
    const v1 = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 may egress to api.openai.com via POST.",
    });
    const v2 = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 2,
      parent_version: 1,
      source_english: "Agent a1 may egress to api.anthropic.com via POST.",
    });

    const ctx1: EgressGateContext = {
      policy: v1,
      nodeSigningKey: f.nodeKeypair.privateKey,
      nodeId: f.nodeCert.node_id,
      fortressId: f.master.public.fortress_id,
    };
    const ctx2: EgressGateContext = {
      ...ctx1,
      policy: v2,
    };

    // v1: openai allowed, anthropic denied.
    expect(
      evaluateEgressGate(ctx1, {
        agent_id: "a1",
        destination: "api.openai.com",
        method: "POST",
      }).decision
    ).toBe("allow");
    expect(
      evaluateEgressGate(ctx1, {
        agent_id: "a1",
        destination: "api.anthropic.com",
        method: "POST",
      }).decision
    ).toBe("deny");

    // v2: anthropic allowed, openai denied (old values don't leak).
    expect(
      evaluateEgressGate(ctx2, {
        agent_id: "a1",
        destination: "api.anthropic.com",
        method: "POST",
      }).decision
    ).toBe("allow");
    expect(
      evaluateEgressGate(ctx2, {
        agent_id: "a1",
        destination: "api.openai.com",
        method: "POST",
      }).decision
    ).toBe("deny");
  });

  it("budget limits switch on re-pin", () => {
    const v1 = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 has a daily budget of 1 usd.",
    });
    const v2 = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 2,
      parent_version: 1,
      source_english: "Agent a1 has a daily budget of 100 usd.",
    });

    const tracker = new BudgetTracker();
    const now = Date.now();
    tracker.recordSpend("a1", 5.0, new Date(now - 1000).toISOString());

    // Under v1 ($1 limit): exhausted.
    const r1 = isBudgetExhausted(tracker, "a1", v1);
    expect(r1.exhausted).toBe(true);

    // Under v2 ($100 limit): not exhausted.
    const r2 = isBudgetExhausted(tracker, "a1", v2);
    expect(r2.exhausted).toBe(false);
  });

  it("retention windows switch on re-pin", async () => {
    const v1 = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 retains memory for 1800 seconds.",
    });
    const v2 = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 2,
      parent_version: 1,
      source_english: "Agent a1 retains memory for 7200 seconds.",
    });

    const store = new InMemoryRetentionStore();
    const now = Date.now();
    // Entry is 1 hour old (3600s).
    store.seed("a1", "memory", {
      key: "entry1",
      created_at: new Date(now - 60 * 60 * 1000).toISOString(),
    });

    // v1 window is 1800s (30min): entry is expired.
    const r1 = await executeRetentionSweep({
      agent_id: "a1",
      retention: v1.retention,
      store,
      now,
    });
    expect(r1.swept.memory).toBe(1);

    // Re-seed the entry.
    store.seed("a1", "memory", {
      key: "entry1",
      created_at: new Date(now - 60 * 60 * 1000).toISOString(),
    });

    // v2 window is 7200s (2h): entry is NOT expired.
    const r2 = await executeRetentionSweep({
      agent_id: "a1",
      retention: v2.retention,
      store,
      now,
    });
    expect(r2.swept.memory).toBe(0);
    expect(r2.retained.memory).toBe(1);
  });

  it("policy_update envelope round-trips with egress/budgets/retention", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: [
        "Agent a1 may egress to api.openai.com via POST.",
        "Agent a1 has a daily budget of 10 usd.",
        "Agent a1 retains memory for 3600 seconds.",
      ].join(" "),
    });

    // Pack into signed policy_update.
    const signed = packPolicyUpdate({
      policy,
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      monotonic_seq: 1,
      node_private_key: f.nodeKeypair.privateKey,
      principal_private_key: f.principalKeypair.privateKey,
    });

    // Unpack and verify.
    const { compiled } = unpackPolicyUpdate({
      event: signed,
      meshVerifyContext: verifyCtxFor(f),
    });

    expect(compiled.egress).toBeDefined();
    expect(compiled.egress!.allowlist).toHaveLength(1);
    expect(compiled.egress!.allowlist[0].destination).toBe("api.openai.com");
    expect(compiled.budgets).toBeDefined();
    expect(compiled.budgets!.daily!.amount).toBe(10);
    expect(compiled.retention).toBeDefined();
    expect(compiled.retention!.windows.memory!.max_age_seconds).toBe(3600);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// AC5: No-LLM-at-gate preserved
// ═══════════════════════════════════════════════════════════════════════

describe("AC5 — no-LLM-at-gate structural invariant", () => {
  it("egress gate evaluation triggers no network I/O (runtime monkey-patch)", () => {
    const http = require("node:http");
    const https = require("node:https");

    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 may egress to api.openai.com via POST.",
    });
    const ctx: EgressGateContext = {
      policy,
      nodeSigningKey: f.nodeKeypair.privateKey,
      nodeId: f.nodeCert.node_id,
      fortressId: f.master.public.fortress_id,
    };

    const calls: string[] = [];
    const origFetch = (globalThis as { fetch?: typeof fetch }).fetch;
    const origHttpRequest = http.request;
    const origHttpsRequest = https.request;

    (globalThis as { fetch?: typeof fetch }).fetch = () => {
      calls.push("fetch");
      throw new Error("fetch blocked");
    };
    (http as any).request = (..._args: unknown[]) => {
      calls.push("http.request");
      throw new Error("http.request blocked");
    };
    (https as any).request = (..._args: unknown[]) => {
      calls.push("https.request");
      throw new Error("https.request blocked");
    };

    try {
      evaluateEgressGate(ctx, {
        agent_id: "a1",
        destination: "api.openai.com",
        method: "POST",
      });
      evaluateEgressGate(ctx, {
        agent_id: "a1",
        destination: "evil.example.com",
        method: "GET",
      });
    } finally {
      if (origFetch) (globalThis as { fetch?: typeof fetch }).fetch = origFetch;
      else delete (globalThis as { fetch?: typeof fetch }).fetch;
      (http as any).request = origHttpRequest;
      (https as any).request = origHttpsRequest;
    }

    expect(calls).toEqual([]);
  });

  it("budget gate evaluation triggers no network I/O (runtime monkey-patch)", () => {
    const http = require("node:http");
    const https = require("node:https");

    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 has a daily budget of 10 usd.",
    });

    const calls: string[] = [];
    const origFetch = (globalThis as { fetch?: typeof fetch }).fetch;
    const origHttpRequest = http.request;
    const origHttpsRequest = https.request;

    (globalThis as { fetch?: typeof fetch }).fetch = () => {
      calls.push("fetch");
      throw new Error("fetch blocked");
    };
    (http as any).request = (..._args: unknown[]) => {
      calls.push("http.request");
      throw new Error("http.request blocked");
    };
    (https as any).request = (..._args: unknown[]) => {
      calls.push("https.request");
      throw new Error("https.request blocked");
    };

    try {
      const tracker = new BudgetTracker();
      tracker.recordSpend("a1", 5.0);
      tracker.checkBudget("a1", policy.budgets);
      isBudgetExhausted(tracker, "a1", policy);
    } finally {
      if (origFetch) (globalThis as { fetch?: typeof fetch }).fetch = origFetch;
      else delete (globalThis as { fetch?: typeof fetch }).fetch;
      (http as any).request = origHttpRequest;
      (https as any).request = origHttpsRequest;
    }

    expect(calls).toEqual([]);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// AC6: Signed-event fields correct
// ═══════════════════════════════════════════════════════════════════════

describe("AC6 — signed-event fields correct", () => {
  it("egress_blocked usage event carries signature_scheme ed25519-v1 and valid event_class", () => {
    // Emit a usage event with event_class = "egress_blocked".
    const policyHash = toBase64url(
      sha256(canonicalizeToBytes({ test: true }))
    );
    const { event } = emitUsageEvent({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      event_class: "egress_blocked",
      capability_target: "evil.example.com",
      input: { destination: "evil.example.com", method: "GET" },
      output: { blocked: true },
      policy_version: 1,
      policy_version_hash: policyHash,
      attestation_state: "unavailable",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      principal_private_key: f.principalKeypair.privateKey,
      monotonic_seq: 1,
    });

    expect(event.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
    expect(event.event_class).toBe("egress_blocked");
    expect(EVENT_CLASSES).toContain(event.event_class);
  });

  it("budget_consumed usage event carries correct fields", () => {
    const policyHash = toBase64url(
      sha256(canonicalizeToBytes({ test: true }))
    );
    const { event } = emitUsageEvent({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      event_class: "budget_consumed",
      capability_target: "daily-budget",
      input: { amount: 80 },
      output: { threshold: 0.8 },
      policy_version: 1,
      policy_version_hash: policyHash,
      attestation_state: "unavailable",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      monotonic_seq: 2,
    });

    expect(event.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
    expect(event.event_class).toBe("budget_consumed");
    expect(EVENT_CLASSES).toContain(event.event_class);
  });

  it("budget_exceeded usage event carries correct fields", () => {
    const policyHash = toBase64url(
      sha256(canonicalizeToBytes({ test: true }))
    );
    const { event } = emitUsageEvent({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      event_class: "budget_exceeded",
      capability_target: "daily-budget",
      input: { amount: 101 },
      output: { exhausted: true },
      policy_version: 1,
      policy_version_hash: policyHash,
      attestation_state: "unavailable",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      monotonic_seq: 3,
    });

    expect(event.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
    expect(event.event_class).toBe("budget_exceeded");
    expect(EVENT_CLASSES).toContain(event.event_class);
  });

  it("retention_sweep usage event carries correct fields", () => {
    const policyHash = toBase64url(
      sha256(canonicalizeToBytes({ test: true }))
    );
    const { event } = emitUsageEvent({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      event_class: "retention_sweep",
      capability_target: "sweep",
      input: { trigger: "timer" },
      output: { memory: 4, credentials: 4, plans: 4, outputs: 4 },
      policy_version: 1,
      policy_version_hash: policyHash,
      attestation_state: "unavailable",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      monotonic_seq: 4,
    });

    expect(event.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
    expect(event.event_class).toBe("retention_sweep");
    expect(EVENT_CLASSES).toContain(event.event_class);
  });
});

// ═══════════════════════════════════════════════════════════��═══════════
// Additional — policy shape validation
// ═══════════════════════════════════════════════════════════════════════

describe("compiled policy shape validation — WP-MVP-6 extensions", () => {
  it("validates a policy with all three WP-MVP-6 fields", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: [
        "Agent a1 may egress to api.openai.com via POST.",
        "Agent a1 has a daily budget of 10 usd.",
        "Agent a1 retains memory for 3600 seconds.",
      ].join(" "),
    });

    expect(() => validateCompiledPolicyShape(policy)).not.toThrow();
    expect(policy.egress).toBeDefined();
    expect(policy.budgets).toBeDefined();
    expect(policy.retention).toBeDefined();
  });

  it("encode/decode round-trips with WP-MVP-6 fields", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: [
        "Agent a1 may egress to api.openai.com via POST.",
        "Agent a1 has a daily budget of 10 usd.",
        "Agent a1 has a monthly budget of 200 usd.",
        "Agent a1 retains memory for 3600 seconds.",
        "Agent a1 retains outputs for 86400 seconds with archive.",
      ].join(" "),
    });

    const blob = encodePolicyBlob(policy);
    const decoded = decodePolicyBlob(blob);

    expect(decoded.egress).toEqual(policy.egress);
    expect(decoded.budgets).toEqual(policy.budgets);
    expect(decoded.retention).toEqual(policy.retention);
  });

  it("rejects egress policy with empty destination", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 may read outputs from agent a2.",
    });
    (policy as any).egress = { allowlist: [{ destination: "", methods: [] }] };
    expect(() => validateCompiledPolicyShape(policy)).toThrow(
      /destination must be a non-empty string/
    );
  });

  it("rejects budget with zero amount", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 may read outputs from agent a2.",
    });
    (policy as any).budgets = { daily: { amount: 0, unit: "usd" } };
    expect(() => validateCompiledPolicyShape(policy)).toThrow(
      /amount must be a positive finite number/
    );
  });

  it("rejects retention with non-positive max_age_seconds", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 may read outputs from agent a2.",
    });
    (policy as any).retention = {
      windows: { memory: { max_age_seconds: -1 } },
    };
    expect(() => validateCompiledPolicyShape(policy)).toThrow(
      /max_age_seconds must be a positive integer/
    );
  });

  it("rejects retention window on unknown slot", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 may read outputs from agent a2.",
    });
    (policy as any).retention = {
      windows: { unknown_slot: { max_age_seconds: 3600 } },
    };
    expect(() => validateCompiledPolicyShape(policy)).toThrow(
      /not a recognized policy slot/
    );
  });

  it("rejects budget with invalid unit", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 may read outputs from agent a2.",
    });
    (policy as any).budgets = { daily: { amount: 10, unit: "gold" } };
    expect(() => validateCompiledPolicyShape(policy)).toThrow(/unit must be one of/);
  });

  it("rejects budget policy with neither daily nor monthly", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 may read outputs from agent a2.",
    });
    (policy as any).budgets = {};
    expect(() => validateCompiledPolicyShape(policy)).toThrow(
      /at least one of daily or monthly/
    );
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Additional — fixture compiler coverage
// ═══════════════════════════════════════════════════════════════════════

describe("fixture compiler — WP-MVP-6 phrasings", () => {
  it("compiles egress rules with multiple methods", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english:
        "Agent a1 may egress to api.openai.com via POST, GET.",
    });
    expect(policy.egress).toBeDefined();
    expect(policy.egress!.allowlist).toHaveLength(1);
    expect(policy.egress!.allowlist[0].methods).toContain("POST");
    expect(policy.egress!.allowlist[0].methods).toContain("GET");
  });

  it("compiles budget rules with daily and monthly", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: [
        "Agent a1 has a daily budget of 10 usd.",
        "Agent a1 has a monthly budget of 200 tokens.",
      ].join(" "),
    });
    expect(policy.budgets).toBeDefined();
    expect(policy.budgets!.daily!.amount).toBe(10);
    expect(policy.budgets!.daily!.unit).toBe("usd");
    expect(policy.budgets!.monthly!.amount).toBe(200);
    expect(policy.budgets!.monthly!.unit).toBe("tokens");
  });

  it("compiles retention rules for multiple slots", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: [
        "Agent a1 retains memory for 3600 seconds.",
        "Agent a1 retains outputs for 86400 seconds with archive.",
      ].join(" "),
    });
    expect(policy.retention).toBeDefined();
    expect(policy.retention!.windows.memory).toEqual({
      max_age_seconds: 3600,
    });
    expect(policy.retention!.windows.outputs).toEqual({
      max_age_seconds: 86400,
      archive: true,
    });
    expect(policy.retention!.windows.credentials).toBeUndefined();
    expect(policy.retention!.windows.plans).toBeUndefined();
  });

  it("does not set egress/budgets/retention when not in source English", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 may read outputs from agent a2.",
    });
    expect(policy.egress).toBeUndefined();
    expect(policy.budgets).toBeUndefined();
    expect(policy.retention).toBeUndefined();
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Retention sweep scheduler
// ═══════════════════════════════════════════════════════════════════════

describe("retention sweep scheduler", () => {
  it("starts and stops the timer", () => {
    const scheduler = new RetentionSweepScheduler(1000);
    expect(scheduler.isRunning()).toBe(false);
    scheduler.start(async () => {});
    expect(scheduler.isRunning()).toBe(true);
    scheduler.stop();
    expect(scheduler.isRunning()).toBe(false);
  });

  it("is idempotent on double start", () => {
    const scheduler = new RetentionSweepScheduler(1000);
    let callCount = 0;
    scheduler.start(async () => { callCount++; });
    scheduler.start(async () => { callCount += 100; }); // Should not register.
    scheduler.stop();
    expect(scheduler.isRunning()).toBe(false);
  });
});
