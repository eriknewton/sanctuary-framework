/**
 * L2 Context Gating Tests
 *
 * Verifies:
 * - Policy creation and persistence (encrypted)
 * - Field evaluation logic (allow/redact/hash/summarize/deny)
 * - Provider matching (exact, wildcard, default)
 * - Redact takes absolute priority over allow
 * - Pattern matching (prefix wildcard, suffix wildcard, exact)
 * - Full context filtering with content hashes
 * - Deny action blocks entire request
 * - Default action applied for unmatched fields
 * - Policy store CRUD operations
 * - Audit trail entries created for filter operations
 */

import { describe, it, expect } from "vitest";
import {
  evaluateField,
  filterContext,
  ContextGatePolicyStore,
  MAX_CONTEXT_FIELDS,
  type ContextGatePolicy,
  type ContextGateRule,
} from "../../src/l2-operational/context-gate.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

function makePolicy(
  rules: ContextGateRule[],
  defaultAction: "redact" | "deny" = "redact"
): ContextGatePolicy {
  return {
    policy_id: "test-policy",
    policy_name: "Test Policy",
    rules,
    default_action: defaultAction,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };
}

describe("L2 Context Gating", () => {
  // ── evaluateField ──────────────────────────────────────────────────

  describe("evaluateField", () => {
    it("allows fields listed in allow array", () => {
      const policy = makePolicy([
        {
          provider: "inference",
          allow: ["task_description", "current_query"],
          redact: [],
          hash: [],
          summarize: [],
        },
      ]);

      const result = evaluateField(policy, "inference", "task_description");
      expect(result.action).toBe("allow");
    });

    it("redacts fields listed in redact array", () => {
      const policy = makePolicy([
        {
          provider: "inference",
          allow: [],
          redact: ["api_key", "secret_token"],
          hash: [],
          summarize: [],
        },
      ]);

      const result = evaluateField(policy, "inference", "api_key");
      expect(result.action).toBe("redact");
    });

    it("redact takes absolute priority over allow", () => {
      const policy = makePolicy([
        {
          provider: "inference",
          allow: ["conversation_history"],
          redact: ["conversation_history"],
          hash: [],
          summarize: [],
        },
      ]);

      const result = evaluateField(policy, "inference", "conversation_history");
      expect(result.action).toBe("redact");
    });

    it("hashes fields listed in hash array", () => {
      const policy = makePolicy([
        {
          provider: "inference",
          allow: [],
          redact: [],
          hash: ["user_id", "session_id"],
          summarize: [],
        },
      ]);

      const result = evaluateField(policy, "inference", "user_id");
      expect(result.action).toBe("hash");
    });

    it("marks fields for summarization", () => {
      const policy = makePolicy([
        {
          provider: "inference",
          allow: [],
          redact: [],
          hash: [],
          summarize: ["conversation_history"],
        },
      ]);

      const result = evaluateField(policy, "inference", "conversation_history");
      expect(result.action).toBe("summarize");
    });

    it("applies default action for unmatched fields", () => {
      const policy = makePolicy([
        {
          provider: "inference",
          allow: ["task"],
          redact: [],
          hash: [],
          summarize: [],
        },
      ], "redact");

      const result = evaluateField(policy, "inference", "unknown_field");
      expect(result.action).toBe("redact");
    });

    it("applies deny default for unmatched fields when default is deny", () => {
      const policy = makePolicy([
        {
          provider: "inference",
          allow: ["task"],
          redact: [],
          hash: [],
          summarize: [],
        },
      ], "deny");

      const result = evaluateField(policy, "inference", "unknown_field");
      expect(result.action).toBe("deny");
    });

    it("uses wildcard provider rule when no exact match", () => {
      const policy = makePolicy([
        {
          provider: "*",
          allow: ["task_description"],
          redact: ["secret_*"],
          hash: [],
          summarize: [],
        },
      ]);

      const result = evaluateField(policy, "logging", "task_description");
      expect(result.action).toBe("allow");
    });

    it("exact provider rule takes priority over wildcard", () => {
      const policy = makePolicy([
        {
          provider: "*",
          allow: ["conversation_history"],
          redact: [],
          hash: [],
          summarize: [],
        },
        {
          provider: "inference",
          allow: [],
          redact: ["conversation_history"],
          hash: [],
          summarize: [],
        },
      ]);

      // inference → redacted (exact match)
      const inferenceResult = evaluateField(policy, "inference", "conversation_history");
      expect(inferenceResult.action).toBe("redact");

      // logging → allowed (wildcard match)
      const loggingResult = evaluateField(policy, "logging", "conversation_history");
      expect(loggingResult.action).toBe("allow");
    });

    it("returns default when no rules match provider", () => {
      const policy = makePolicy([
        {
          provider: "inference",
          allow: ["task"],
          redact: [],
          hash: [],
          summarize: [],
        },
      ]);

      const result = evaluateField(policy, "analytics", "task");
      expect(result.action).toBe("redact"); // default
    });
  });

  // ── Pattern Matching ──────────────────────────────────────────────

  describe("pattern matching", () => {
    it("matches prefix wildcard (secret_*)", () => {
      // Use allow + redact to distinguish pattern match from default
      const policy = makePolicy([
        {
          provider: "*",
          allow: ["public_key"],
          redact: ["secret_*"],
          hash: [],
          summarize: [],
        },
      ]);

      expect(evaluateField(policy, "inference", "secret_key").action).toBe("redact");
      expect(evaluateField(policy, "inference", "secret_token").action).toBe("redact");
      expect(evaluateField(policy, "inference", "public_key").action).toBe("allow");
    });

    it("matches suffix wildcard (*_pii)", () => {
      const policy = makePolicy([
        {
          provider: "*",
          allow: ["task_description"],
          redact: ["*_pii"],
          hash: [],
          summarize: [],
        },
      ]);

      expect(evaluateField(policy, "inference", "name_pii").action).toBe("redact");
      expect(evaluateField(policy, "inference", "email_pii").action).toBe("redact");
      expect(evaluateField(policy, "inference", "task_description").action).toBe("allow");
    });

    it("matches full wildcard (*)", () => {
      const policy = makePolicy([
        {
          provider: "*",
          allow: [],
          redact: ["*"],
          hash: [],
          summarize: [],
        },
      ]);

      expect(evaluateField(policy, "inference", "anything").action).toBe("redact");
    });

    it("matches exact field names", () => {
      const policy = makePolicy([
        {
          provider: "*",
          allow: ["task_description"],
          redact: [],
          hash: [],
          summarize: [],
        },
      ]);

      expect(evaluateField(policy, "inference", "task_description").action).toBe("allow");
      expect(evaluateField(policy, "inference", "task_description_extra").action).not.toBe("allow");
    });

    // SEC-025 regression: case-insensitive pattern matching
    it("matches patterns case-insensitively", () => {
      const policy = makePolicy([
        {
          provider: "*",
          allow: ["task_description"],
          redact: ["api_key", "secret_*"],
          hash: [],
          summarize: [],
        },
      ]);

      // Uppercase variations must be redacted
      expect(evaluateField(policy, "inference", "API_KEY").action).toBe("redact");
      expect(evaluateField(policy, "inference", "Api_Key").action).toBe("redact");
      expect(evaluateField(policy, "inference", "SECRET_TOKEN").action).toBe("redact");
      expect(evaluateField(policy, "inference", "Secret_Data").action).toBe("redact");

      // Allow also case-insensitive
      expect(evaluateField(policy, "inference", "TASK_DESCRIPTION").action).toBe("allow");
      expect(evaluateField(policy, "inference", "Task_Description").action).toBe("allow");
    });
  });

  // ── filterContext ──────────────────────────────────────────────────

  describe("filterContext", () => {
    it("filters context and returns per-field decisions", () => {
      const policy = makePolicy([
        {
          provider: "inference",
          allow: ["task_description", "current_query"],
          redact: ["api_key", "memory"],
          hash: ["user_id"],
          summarize: ["conversation_history"],
        },
      ]);

      const context = {
        task_description: "Summarize this document",
        current_query: "What are the key points?",
        api_key: "sk-secret-12345",
        memory: "User likes concise responses",
        user_id: "user-abc-123",
        conversation_history: "Long conversation...",
      };

      const result = filterContext(policy, "inference", context);

      expect(result.fields_allowed).toBe(2);
      expect(result.fields_redacted).toBe(2);
      expect(result.fields_hashed).toBe(1);
      expect(result.fields_summarized).toBe(1);
      expect(result.fields_denied).toBe(0);

      // Verify decisions
      const decisions = new Map(result.decisions.map((d) => [d.field, d]));
      expect(decisions.get("task_description")!.action).toBe("allow");
      expect(decisions.get("api_key")!.action).toBe("redact");
      expect(decisions.get("user_id")!.action).toBe("hash");
      expect(decisions.get("user_id")!.hash_value).toBeDefined();
      expect(decisions.get("conversation_history")!.action).toBe("summarize");
    });

    it("produces content hashes for audit trail", () => {
      const policy = makePolicy([
        {
          provider: "inference",
          allow: ["task"],
          redact: ["secret"],
          hash: [],
          summarize: [],
        },
      ]);

      const context = { task: "do something", secret: "hidden" };
      const result = filterContext(policy, "inference", context);

      expect(result.original_context_hash).toBeDefined();
      expect(result.filtered_context_hash).toBeDefined();
      expect(result.original_context_hash).not.toBe(result.filtered_context_hash);
    });

    it("deny fields are counted correctly", () => {
      const policy = makePolicy([
        {
          provider: "inference",
          allow: ["task"],
          redact: [],
          hash: [],
          summarize: [],
        },
      ], "deny");

      const context = { task: "do something", forbidden_field: "should be denied" };
      const result = filterContext(policy, "inference", context);

      expect(result.fields_allowed).toBe(1);
      expect(result.fields_denied).toBe(1);
    });

    it("hash action computes SHA-256 of field value", () => {
      const policy = makePolicy([
        {
          provider: "inference",
          allow: [],
          redact: [],
          hash: ["user_id"],
          summarize: [],
        },
      ]);

      const context = { user_id: "test-user-123" };
      const result = filterContext(policy, "inference", context);

      const hashDecision = result.decisions.find((d) => d.field === "user_id");
      expect(hashDecision!.action).toBe("hash");
      expect(hashDecision!.hash_value).toBeDefined();
      expect(hashDecision!.hash_value!.length).toBeGreaterThan(0);

      // Same input should produce same hash
      const result2 = filterContext(policy, "inference", context);
      const hash2 = result2.decisions.find((d) => d.field === "user_id");
      expect(hash2!.hash_value).toBe(hashDecision!.hash_value);
    });
  });

  // ── ContextGatePolicyStore ─────────────────────────────────────────

  describe("ContextGatePolicyStore", () => {
    it("creates and retrieves a policy", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ContextGatePolicyStore(storage, masterKey);

      const policy = await store.create(
        "inference-minimal",
        [
          {
            provider: "inference",
            allow: ["task"],
            redact: ["secret_*"],
            hash: ["user_id"],
            summarize: [],
          },
        ],
        "redact"
      );

      expect(policy.policy_id).toMatch(/^cg-/);
      expect(policy.policy_name).toBe("inference-minimal");

      const retrieved = await store.get(policy.policy_id);
      expect(retrieved).toBeDefined();
      expect(retrieved!.policy_name).toBe("inference-minimal");
      expect(retrieved!.rules).toHaveLength(1);
    });

    it("lists all policies", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ContextGatePolicyStore(storage, masterKey);

      await store.create("policy-1", [], "redact");
      await store.create("policy-2", [], "deny");

      const policies = await store.list();
      expect(policies).toHaveLength(2);
    });

    it("returns null for nonexistent policy", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ContextGatePolicyStore(storage, masterKey);

      const result = await store.get("nonexistent");
      expect(result).toBeNull();
    });

    it("encrypts policies at rest", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const store = new ContextGatePolicyStore(storage, masterKey);

      const policy = await store.create("encrypted-test", [], "redact");

      // Read raw storage — should be encrypted (not plaintext policy name)
      const raw = await storage.read("_context_gate_policies", policy.policy_id);
      expect(raw).toBeDefined();
      const rawString = new TextDecoder().decode(raw!);
      // The raw storage should contain encrypted payload structure (ct = ciphertext)
      expect(rawString).toContain("ct");
      expect(rawString).toContain("iv");
      // But NOT the plaintext policy name
      expect(rawString).not.toContain("encrypted-test");
    });

    it("persists across store instances with same key", async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();

      // Create with first store instance
      const store1 = new ContextGatePolicyStore(storage, masterKey);
      const policy = await store1.create("persistent", [], "redact");

      // Retrieve with new store instance (same storage, same key)
      const store2 = new ContextGatePolicyStore(storage, masterKey);
      const retrieved = await store2.get(policy.policy_id);
      expect(retrieved).toBeDefined();
      expect(retrieved!.policy_name).toBe("persistent");
    });

    it("cannot decrypt with wrong key", async () => {
      const storage = new MemoryStorage();
      const masterKey1 = generateRandomKey();
      const masterKey2 = generateRandomKey();

      const store1 = new ContextGatePolicyStore(storage, masterKey1);
      const policy = await store1.create("secret-policy", [], "redact");

      // Try to retrieve with wrong key
      const store2 = new ContextGatePolicyStore(storage, masterKey2);
      const retrieved = await store2.get(policy.policy_id);
      expect(retrieved).toBeNull(); // Should fail to decrypt
    });
  });

  // ── SEC-027 regression: size limits ─────────────────────────────────

  describe("size limits", () => {
    it("rejects context objects exceeding MAX_CONTEXT_FIELDS", () => {
      const policy = makePolicy([
        { provider: "*", allow: ["task"], redact: [], hash: [], summarize: [] },
      ]);

      const largeContext: Record<string, unknown> = {};
      for (let i = 0; i < MAX_CONTEXT_FIELDS + 1; i++) {
        largeContext[`field_${i}`] = "value";
      }

      expect(() => filterContext(policy, "inference", largeContext)).toThrow(
        /exceeding limit/
      );
    });

    it("accepts context objects at the limit", () => {
      const policy = makePolicy([
        { provider: "*", allow: ["*"], redact: [], hash: [], summarize: [] },
      ]);

      const context: Record<string, unknown> = {};
      for (let i = 0; i < MAX_CONTEXT_FIELDS; i++) {
        context[`field_${i}`] = "value";
      }

      expect(() => filterContext(policy, "inference", context)).not.toThrow();
    });
  });

  // ── Real-world scenario tests ──────────────────────────────────────

  describe("real-world scenarios", () => {
    it("inference-minimal: only task and query reach the LLM", () => {
      const policy = makePolicy([
        {
          provider: "inference",
          allow: ["task_description", "current_query"],
          redact: ["api_key", "secret_*", "*_pii", "memory", "internal_reasoning"],
          hash: ["user_id", "session_id"],
          summarize: ["conversation_history"],
        },
      ]);

      const agentContext = {
        task_description: "Analyze quarterly revenue trends",
        current_query: "What drove the Q3 increase?",
        api_key: "sk-ant-api03-xxxxx",
        secret_token: "ghp_xxxxx",
        name_pii: "Erik Newton",
        email_pii: "erik@example.com",
        memory: "User prefers concise financial summaries",
        internal_reasoning: "I should cross-reference with last quarter...",
        user_id: "user-12345",
        session_id: "sess-67890",
        conversation_history: "Previous 50 messages...",
      };

      const result = filterContext(policy, "inference", agentContext);

      // Only task and query should pass through
      expect(result.fields_allowed).toBe(2);
      // Secrets and PII should be redacted (api_key, secret_token, name_pii, email_pii, memory, internal_reasoning)
      expect(result.fields_redacted).toBe(6);
      // IDs should be hashed
      expect(result.fields_hashed).toBe(2);
      // History should be flagged for summarization
      expect(result.fields_summarized).toBe(1);
    });

    it("different providers get different policies", () => {
      const policy = makePolicy([
        {
          provider: "inference",
          allow: ["task_description"],
          redact: ["api_key", "memory"],
          hash: [],
          summarize: [],
        },
        {
          provider: "logging",
          allow: [],
          redact: ["*"],
          hash: [],
          summarize: [],
        },
      ]);

      // Inference: task allowed, memory redacted
      const inferenceResult = evaluateField(policy, "inference", "task_description");
      expect(inferenceResult.action).toBe("allow");

      // Logging: everything redacted
      const loggingResult = evaluateField(policy, "logging", "task_description");
      expect(loggingResult.action).toBe("redact");
    });
  });
});
