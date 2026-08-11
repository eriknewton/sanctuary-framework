/**
 * L3 Disclosure Policy Tests
 *
 * Verifies:
 * - Policy creation and persistence
 * - Disclosure evaluation logic (disclose/withhold/proof/ask-principal)
 * - Context matching (exact, wildcard, default)
 * - Withhold takes priority over disclose
 * - Proof_required takes priority over disclose
 * - Default action applied for unmatched fields
 * - Policies stored encrypted
 */

import { describe, it, expect } from "vitest";
import {
  evaluateDisclosure,
  PolicyStore,
  validatePolicyInput,
  MAX_DISCLOSURE_POLICIES_PER_ORIGIN,
  MAX_DISCLOSURE_POLICY_RULES,
  MAX_DISCLOSURE_RULE_FIELD_ITEMS,
  MAX_DISCLOSURE_RULE_STRING_LENGTH,
  type DisclosurePolicy,
  type DisclosureRule,
} from "../../src/disclosure/policies.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

function makePolicy(
  rules: DisclosureRule[],
  defaultAction: "withhold" | "ask-principal" = "withhold"
): DisclosurePolicy {
  return {
    policy_id: "test-policy",
    policy_name: "Test Policy",
    rules,
    default_action: defaultAction,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };
}

describe("L3 Disclosure Policies", () => {
  describe("evaluateDisclosure", () => {
    it("discloses fields listed in disclose array", () => {
      const policy = makePolicy([
        {
          context: "commerce",
          disclose: ["agent_name", "capability_level"],
          withhold: [],
          proof_required: [],
        },
      ]);

      const decisions = evaluateDisclosure(policy, "commerce", [
        "agent_name",
      ]);

      expect(decisions).toHaveLength(1);
      expect(decisions[0]!.action).toBe("disclose");
    });

    it("withholds fields listed in withhold array", () => {
      const policy = makePolicy([
        {
          context: "commerce",
          disclose: ["agent_name"],
          withhold: ["spending_limit"],
          proof_required: [],
        },
      ]);

      const decisions = evaluateDisclosure(policy, "commerce", [
        "spending_limit",
      ]);

      expect(decisions[0]!.action).toBe("withhold");
    });

    it("withhold takes priority over disclose when field appears in both", () => {
      const policy = makePolicy([
        {
          context: "commerce",
          disclose: ["secret_field"],
          withhold: ["secret_field"],
          proof_required: [],
        },
      ]);

      const decisions = evaluateDisclosure(policy, "commerce", [
        "secret_field",
      ]);

      expect(decisions[0]!.action).toBe("withhold");
    });

    it("requires proof for fields in proof_required", () => {
      const policy = makePolicy([
        {
          context: "commerce",
          disclose: [],
          withhold: [],
          proof_required: ["authorization_level"],
        },
      ]);

      const decisions = evaluateDisclosure(policy, "commerce", [
        "authorization_level",
      ]);

      expect(decisions[0]!.action).toBe("proof");
    });

    it("falls back to wildcard context when no exact match", () => {
      const policy = makePolicy([
        {
          context: "*",
          disclose: ["public_name"],
          withhold: ["private_key"],
          proof_required: [],
        },
      ]);

      const decisions = evaluateDisclosure(policy, "unknown-context", [
        "public_name",
        "private_key",
      ]);

      expect(decisions[0]!.action).toBe("disclose");
      expect(decisions[1]!.action).toBe("withhold");
    });

    it("applies default action for fields not in any list", () => {
      const policy = makePolicy(
        [
          {
            context: "commerce",
            disclose: ["name"],
            withhold: [],
            proof_required: [],
          },
        ],
        "ask-principal"
      );

      const decisions = evaluateDisclosure(policy, "commerce", [
        "unknown_field",
      ]);

      expect(decisions[0]!.action).toBe("ask-principal");
    });

    it("applies default action when no rule matches context", () => {
      const policy = makePolicy(
        [
          {
            context: "commerce",
            disclose: ["name"],
            withhold: [],
            proof_required: [],
          },
        ],
        "withhold"
      );

      const decisions = evaluateDisclosure(policy, "identity", [
        "name",
      ]);

      expect(decisions[0]!.action).toBe("withhold");
    });

    it("evaluates multiple fields in one request", () => {
      const policy = makePolicy([
        {
          context: "negotiation",
          disclose: ["agent_name", "capability"],
          withhold: ["budget", "strategy"],
          proof_required: ["authorization"],
        },
      ]);

      const decisions = evaluateDisclosure(policy, "negotiation", [
        "agent_name",
        "budget",
        "authorization",
        "unknown",
      ]);

      expect(decisions).toHaveLength(4);
      expect(decisions[0]!.action).toBe("disclose");
      expect(decisions[1]!.action).toBe("withhold");
      expect(decisions[2]!.action).toBe("proof");
      expect(decisions[3]!.action).toBe("withhold"); // default
    });
  });

  describe("PolicyStore", () => {
    it("creates and retrieves a policy", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new PolicyStore(storage, masterKey);

      const result = await store.create(
        "Commerce Policy",
        [
          {
            context: "commerce",
            disclose: ["name"],
            withhold: ["secret"],
            proof_required: ["auth_level"],
          },
        ],
        "withhold"
      );

      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error("unreachable");
      const policy = result.policy;
      expect(policy.policy_id).toMatch(/^pol-/);
      expect(policy.policy_name).toBe("Commerce Policy");

      const retrieved = await store.get(policy.policy_id);
      expect(retrieved).not.toBeNull();
      expect(retrieved!.policy_name).toBe("Commerce Policy");
      expect(retrieved!.rules).toHaveLength(1);
    });

    it("lists all policies", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new PolicyStore(storage, masterKey);

      await store.create("Policy A", [], "withhold");
      await store.create("Policy B", [], "ask-principal");

      const all = await store.list();
      expect(all).toHaveLength(2);
    });

    it("stores policies encrypted — plaintext policy name not in raw storage", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new PolicyStore(storage, masterKey);

      const uniqueName = "UNIQUE_POLICY_NAME_XYZZY";
      await store.create(uniqueName, [], "withhold");

      const entries = await storage.list("_policies");
      for (const entry of entries) {
        const raw = await storage.read("_policies", entry.key);
        if (!raw) continue;
        const rawStr = new TextDecoder().decode(raw);
        expect(rawStr).not.toContain(uniqueName);
      }
    });
  });

  // LD3 — DISCLOSURE-POLICY-CACHE-UNBOUNDED: `disclosure_set_policy` used to
  // mint a fresh id and cache the caller-supplied rules on EVERY call with
  // no cap of any kind. These tests fail on the pre-fix code (unbounded
  // creation succeeds forever; any rule payload size is accepted) and pass
  // once the per-origin/global caps and rule-size bounds are enforced.
  describe("PolicyStore bounds (LD3)", () => {
    it("refuses a new policy once a single session's per-origin quota is exhausted", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new PolicyStore(storage, masterKey);
      const origin = "agent:flood-session";

      for (let i = 0; i < MAX_DISCLOSURE_POLICIES_PER_ORIGIN; i++) {
        const result = await store.create(
          `Policy ${i}`,
          [],
          "withhold",
          undefined,
          origin
        );
        expect(result.ok).toBe(true);
      }

      // The (N+1)th create from the SAME session must be refused, not
      // silently minted — this is the line that fails on unbounded code.
      const overflow = await store.create(
        "One too many",
        [],
        "withhold",
        undefined,
        origin
      );
      expect(overflow.ok).toBe(false);
      if (overflow.ok) throw new Error("unreachable");
      expect(overflow.reason).toBe("origin_quota");

      // A DIFFERENT session's own quota must be untouched by the flood.
      const otherSession = await store.create(
        "Different session's policy",
        [],
        "withhold",
        undefined,
        "agent:other-session"
      );
      expect(otherSession.ok).toBe(true);
    });

    it("rejects a policy with more rules than MAX_DISCLOSURE_POLICY_RULES", () => {
      const rules: DisclosureRule[] = Array.from(
        { length: MAX_DISCLOSURE_POLICY_RULES + 1 },
        (_, i) => ({
          context: `context-${i}`,
          disclose: [],
          withhold: [],
          proof_required: [],
        })
      );
      const result = validatePolicyInput("Too Many Rules", rules);
      expect(result.ok).toBe(false);
    });

    it("rejects a rule with more disclose entries than MAX_DISCLOSURE_RULE_FIELD_ITEMS", () => {
      const rules: DisclosureRule[] = [
        {
          context: "commerce",
          disclose: Array.from(
            { length: MAX_DISCLOSURE_RULE_FIELD_ITEMS + 1 },
            (_, i) => `field-${i}`
          ),
          withhold: [],
          proof_required: [],
        },
      ];
      const result = validatePolicyInput("Too Many Fields", rules);
      expect(result.ok).toBe(false);
    });

    it("rejects a rule field string longer than MAX_DISCLOSURE_RULE_STRING_LENGTH", () => {
      const rules: DisclosureRule[] = [
        {
          context: "commerce",
          disclose: ["x".repeat(MAX_DISCLOSURE_RULE_STRING_LENGTH + 1)],
          withhold: [],
          proof_required: [],
        },
      ];
      const result = validatePolicyInput("Oversized Field", rules);
      expect(result.ok).toBe(false);
    });

    it("accepts a policy sitting exactly at the rule/field/string caps", () => {
      const rules: DisclosureRule[] = Array.from(
        { length: MAX_DISCLOSURE_POLICY_RULES },
        (_, i) => ({
          context: `context-${i}`,
          disclose: ["x".repeat(MAX_DISCLOSURE_RULE_STRING_LENGTH)],
          withhold: [],
          proof_required: [],
        })
      );
      const result = validatePolicyInput("At The Cap", rules);
      expect(result.ok).toBe(true);
    });

    it("update-in-place replaces rules without minting a new id or consuming a new quota slot", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new PolicyStore(storage, masterKey);
      const origin = "agent:owner-session";

      const created = await store.create(
        "Original",
        [
          {
            context: "commerce",
            disclose: ["name"],
            withhold: [],
            proof_required: [],
          },
        ],
        "withhold",
        undefined,
        origin
      );
      expect(created.ok).toBe(true);
      if (!created.ok) throw new Error("unreachable");

      const updated = await store.update(
        created.policy.policy_id,
        "Updated",
        [
          {
            context: "commerce",
            disclose: [],
            withhold: ["name"],
            proof_required: [],
          },
        ],
        "withhold",
        undefined,
        origin
      );
      expect(updated.ok).toBe(true);
      if (!updated.ok) throw new Error("unreachable");
      expect(updated.policy.policy_id).toBe(created.policy.policy_id);
      expect(updated.policy.policy_name).toBe("Updated");

      const list = await store.list();
      expect(
        list.filter((p) => p.policy_id === created.policy.policy_id)
      ).toHaveLength(1);
    });

    it("refuses to update a policy owned by a different session", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new PolicyStore(storage, masterKey);

      const created = await store.create(
        "Victim's Policy",
        [],
        "withhold",
        undefined,
        "agent:victim-session"
      );
      expect(created.ok).toBe(true);
      if (!created.ok) throw new Error("unreachable");

      const attempt = await store.update(
        created.policy.policy_id,
        "Hijacked",
        [],
        "withhold",
        undefined,
        "agent:attacker-session"
      );
      expect(attempt.ok).toBe(false);
      if (attempt.ok) throw new Error("unreachable");
      expect(attempt.reason).toBe("forbidden");

      // The original policy must be untouched by the refused attempt.
      const retrieved = await store.get(created.policy.policy_id);
      expect(retrieved!.policy_name).toBe("Victim's Policy");
    });
  });

  // LD3 gate fix-round — a two-family adversarial re-review of the LD3 fix
  // above found two real defects in it. These tests fail on the
  // fix-round's pre-fix code (the commit this test file's HEAD~1 shipped)
  // and pass once both are closed.
  describe("PolicyStore bounds (LD3 gate fix-round)", () => {
    it("DEFECT 1 — strips an unknown/oversized property from a rule before it reaches storage", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new PolicyStore(storage, masterKey);
      const origin = "agent:junk-session";

      // The confirmed exploit shape: a rule object carrying all four known
      // fields PLUS an unbounded extra property.
      const junkyRule = {
        context: "commerce",
        disclose: [],
        withhold: [],
        proof_required: [],
        junk: "A".repeat(5_000_000),
      } as unknown as DisclosureRule;

      // Confirms the upstream validator alone does not catch this — it
      // bounds only the four known fields' lengths and never rejects an
      // extra own property on the rule object.
      const validation = validatePolicyInput("Junk Policy", [junkyRule]);
      expect(validation.ok).toBe(true);

      const result = await store.create(
        "Junk Policy",
        [junkyRule],
        "withhold",
        undefined,
        origin
      );
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error("unreachable");

      // The stored/returned rule must carry ONLY the four known fields —
      // on pre-fix code this assertion fails because `junk` survives.
      const storedRule = result.policy.rules[0] as unknown as Record<
        string,
        unknown
      >;
      expect(Object.keys(storedRule).sort()).toEqual(
        ["context", "disclose", "proof_required", "withhold"].sort()
      );
      expect(storedRule.junk).toBeUndefined();

      // The junk payload must never have reached durable storage either —
      // on pre-fix code the raw encrypted record would be multiple
      // megabytes; post-fix it stays small regardless of what the caller
      // tried to smuggle in.
      const entries = await storage.list("_policies");
      let checked = 0;
      for (const entry of entries) {
        const raw = await storage.read("_policies", entry.key);
        if (!raw) continue;
        checked += 1;
        expect(raw.length).toBeLessThan(10_000);
      }
      expect(checked).toBeGreaterThan(0);
    });

    it("DEFECT 1 — strips an unknown property on update() too, not only create()", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new PolicyStore(storage, masterKey);
      const origin = "agent:junk-update-session";

      const created = await store.create(
        "Original",
        [
          {
            context: "commerce",
            disclose: ["name"],
            withhold: [],
            proof_required: [],
          },
        ],
        "withhold",
        undefined,
        origin
      );
      expect(created.ok).toBe(true);
      if (!created.ok) throw new Error("unreachable");

      const junkyRule = {
        context: "commerce",
        disclose: [],
        withhold: [],
        proof_required: [],
        junk: "B".repeat(2_000_000),
      } as unknown as DisclosureRule;

      const updated = await store.update(
        created.policy.policy_id,
        "Updated",
        [junkyRule],
        "withhold",
        undefined,
        origin
      );
      expect(updated.ok).toBe(true);
      if (!updated.ok) throw new Error("unreachable");

      const storedRule = updated.policy.rules[0] as unknown as Record<
        string,
        unknown
      >;
      expect(Object.keys(storedRule).sort()).toEqual(
        ["context", "disclose", "proof_required", "withhold"].sort()
      );
      expect(storedRule.junk).toBeUndefined();
    });

    it("DEFECT 2 — rehydrates BoundedMap quota counters from persisted policies after a restart", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const origin = "agent:restart-session";

      // Pre-restart process: fill this origin's entire quota.
      const store1 = new PolicyStore(storage, masterKey);
      for (let i = 0; i < MAX_DISCLOSURE_POLICIES_PER_ORIGIN; i++) {
        const result = await store1.create(
          `Policy ${i}`,
          [],
          "withhold",
          undefined,
          origin
        );
        expect(result.ok).toBe(true);
      }

      // Simulate a process restart: a BRAND NEW PolicyStore instance
      // backed by the SAME durable storage. Its BoundedMap starts empty —
      // the policies above are on disk but this instance has never loaded
      // them into memory.
      const store2 = new PolicyStore(storage, masterKey);

      // On pre-fix code, store2's in-memory counters start at zero (never
      // rehydrated), so this create silently succeeds — a caller could
      // refill an already-exhausted quota on every restart. Post-fix,
      // create() loads persisted policies before checking the quota, so
      // this is refused exactly as it would have been pre-restart.
      const overflow = await store2.create(
        "One too many after restart",
        [],
        "withhold",
        undefined,
        origin
      );
      expect(overflow.ok).toBe(false);
      if (overflow.ok) throw new Error("unreachable");
      expect(overflow.reason).toBe("origin_quota");

      // A different origin is unaffected — the rehydrate must not turn
      // into a false global refusal.
      const otherSession = await store2.create(
        "Different session after restart",
        [],
        "withhold",
        undefined,
        "agent:other-restart-session"
      );
      expect(otherSession.ok).toBe(true);
    });
  });
});
