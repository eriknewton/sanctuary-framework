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
  type DisclosurePolicy,
  type DisclosureRule,
} from "../../src/l3-disclosure/policies.js";
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

      const policy = await store.create(
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
});
