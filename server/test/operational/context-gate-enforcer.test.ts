/**
 * L2 Context Gate Enforcer Tests
 *
 * Verifies:
 * - Enabled gating without a bound policy blocks before handler execution
 * - Sanctuary/ prefixed tools are bypassed
 * - log_only mode cannot bypass the no-policy fail-closed path
 * - deny action "block" returns error, "redact" continues
 * - Stats accumulate correctly
 * - Policy-based filtering works correctly
 * - on_deny configuration respected
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  ContextGateEnforcer,
  ContextGateNoPolicyError,
  type EnforcerConfig,
} from "../../src/operational/context-gate-enforcer.js";
// `ContextGatePolicyStore` and `AuditLog` are classes, so the value import below
// supplies both the value and the type; the separate `import type` lines that
// used to sit here were redundant and Vite 8's oxc transformer (stricter than
// the esbuild transformer it replaces) rejected them as redeclarations.
import { ContextGatePolicyStore } from "../../src/operational/context-gate.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import type { ToolHandler } from "../../src/router.js";
import { toolResult } from "../../src/router.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

const NO_POLICY_MESSAGE =
  "context-gating enabled but no policy bound; bind a context-gating policy or disable gating.";

describe("L2 Context Gate Enforcer", () => {
  let storage: MemoryStorage;
  let masterKey: Uint8Array;
  let policyStore: ContextGatePolicyStore;
  let auditLog: AuditLog;

  beforeEach(() => {
    storage = new MemoryStorage();
    masterKey = generateRandomKey();
    policyStore = new ContextGatePolicyStore(storage, masterKey);
    auditLog = new AuditLog(storage, masterKey);
  });

  // ── Basic Wrapping ──────────────────────────────────────────────────

  describe("Handler Wrapping", () => {
    it("blocks before handler execution when enabled with no bound policy", async () => {
      const config: EnforcerConfig = {
        enabled: true,
        bypass_prefixes: [""],
        log_only: false,
        on_deny: "block",
      };

      const enforcer = new ContextGateEnforcer(policyStore, auditLog, config);

      let handlerCalled = false;
      const originalHandler: ToolHandler = async (args) => {
        handlerCalled = true;
        return toolResult({ received_args: args });
      };

      const wrappedHandler = enforcer.wrapHandler("external/call", originalHandler);

      const result = await wrappedHandler({
        api_key: "secret123",
        task: "do something",
      });

      const content = result.content[0];
      expect(content.type).toBe("text");
      const parsed = JSON.parse(content.text);

      expect(handlerCalled).toBe(false);
      expect(parsed).toEqual({ error: "Operation not permitted" });
      expect(content.text).not.toContain("secret123");
      expect(content.text).not.toContain("do something");
      expect(content.text).not.toContain("policy");
      expect(content.text).not.toContain("bound");

      const audit = await auditLog.query({
        operation_type: "context_gate_enforcer_no_policy_block",
        limit: 10,
      });
      expect(audit.entries).toHaveLength(1);
      expect(audit.entries[0]!.result).toBe("failure");
      expect(audit.entries[0]!.details?.message).toBe(NO_POLICY_MESSAGE);
    });

    it("bypasses internal tools with wildcard sentinel", async () => {
      const config: EnforcerConfig = {
        enabled: true,
        bypass_prefixes: ["*"],
        log_only: false,
        on_deny: "block",
      };

      const enforcer = new ContextGateEnforcer(policyStore, auditLog, config);

      let handlerCalled = false;
      const originalHandler: ToolHandler = async (args) => {
        handlerCalled = true;
        return toolResult({ args });
      };

      const wrappedHandler = enforcer.wrapHandler(
        "internal_tool",
        originalHandler
      );

      await wrappedHandler({
        api_key: "secret123",
      });

      // Handler should be called with original unfiltered args
      expect(handlerCalled).toBe(true);

      const status = enforcer.getStatus();
      expect(status.stats.calls_bypassed).toBe(1);
      expect(status.stats.calls_inspected).toBe(0);
    });
  });

  // ── Enforcer Enabled/Disabled ───────────────────────────────────────

  describe("Enforcer Control", () => {
    it("passes through when disabled", async () => {
      const config: EnforcerConfig = {
        enabled: false,
        bypass_prefixes: [""],
        log_only: false,
        on_deny: "block",
      };

      const enforcer = new ContextGateEnforcer(policyStore, auditLog, config);

      const originalHandler: ToolHandler = async (args) => {
        return toolResult({ received: args });
      };

      const wrappedHandler = enforcer.wrapHandler("external/call", originalHandler);

      const result = await wrappedHandler({
        api_key: "secret123",
      });

      const content = result.content[0];
      const parsed = JSON.parse(content.text);

      // With enforcer disabled, sensitive field should NOT be redacted
      expect(parsed.received.api_key).toBe("secret123");
    });
  });

  // -- No Policy Fail Closed -------------------------------------------

  describe("No Policy Fail Closed", () => {
    it("throws before returning proxy args when enabled with no bound policy", async () => {
      const config: EnforcerConfig = {
        enabled: true,
        bypass_prefixes: [""],
        log_only: false,
        on_deny: "block",
      };
      const enforcer = new ContextGateEnforcer(policyStore, auditLog, config);
      const outboundContext = {
        token: "opaqueTopLevelToken",
        metadata: { note: "safe nested note" },
      };

      await expect(
        enforcer.filterArgs("proxy/tool", outboundContext, { respectBypass: false })
      ).rejects.toBeInstanceOf(ContextGateNoPolicyError);

      const audit = await auditLog.query({
        operation_type: "context_gate_enforcer_no_policy_block",
        limit: 10,
      });
      expect(audit.entries).toHaveLength(1);
      expect(audit.entries[0]!.details?.message).toBe(NO_POLICY_MESSAGE);
      expect(JSON.stringify(audit.entries[0]!.details)).not.toContain("opaqueTopLevelToken");
    });
  });

  // ── log_only Mode ───────────────────────────────────────────────────

  describe("log_only Mode", () => {
    it("does not pass original args when no policy is bound", async () => {
      const config: EnforcerConfig = {
        enabled: true,
        bypass_prefixes: [""],
        log_only: true,
        on_deny: "block",
      };

      const enforcer = new ContextGateEnforcer(policyStore, auditLog, config);

      let handlerCalled = false;
      const originalHandler: ToolHandler = async (args) => {
        handlerCalled = true;
        return toolResult({ received: args });
      };

      const wrappedHandler = enforcer.wrapHandler("tool/api", originalHandler);

      const result = await wrappedHandler({
        api_key: "secret123",
        task: "do something",
      });

      const content = result.content[0];
      const parsed = JSON.parse(content.text);

      expect(handlerCalled).toBe(false);
      expect(parsed).toEqual({ error: "Operation not permitted" });
      expect(content.text).not.toContain("secret123");

      const status = enforcer.getStatus();
      expect(status.log_only).toBe(true);
      expect(status.stats.calls_inspected).toBe(1);
      expect(status.stats.calls_blocked).toBe(1);
    });
  });

  // ── Stats Tracking ──────────────────────────────────────────────────

  describe("Stats Tracking", () => {
    it("accumulates stats correctly", async () => {
      const config: EnforcerConfig = {
        enabled: true,
        bypass_prefixes: ["internal"],
        log_only: false,
        on_deny: "block",
      };

      const enforcer = new ContextGateEnforcer(policyStore, auditLog, config);

      const originalHandler: ToolHandler = async (args) => {
        return toolResult({ args });
      };

      // Call 1: bypass (internal/ prefix matches)
      const wrapped1 = enforcer.wrapHandler("internal/tool", originalHandler);
      await wrapped1({ api_key: "secret" });

      // Call 2: inspect and block (external/ prefix NOT bypassed)
      const wrapped2 = enforcer.wrapHandler("external/tool", originalHandler);
      await wrapped2({ api_key: "secret", task: "work" });

      // Call 3: inspect and block regardless of field names
      const wrapped3 = enforcer.wrapHandler("external/tool2", originalHandler);
      await wrapped3({ task: "work", query: "search" });

      const status = enforcer.getStatus();
      expect(status.stats.calls_bypassed).toBe(1);
      expect(status.stats.calls_inspected).toBe(2);
      expect(status.stats.calls_blocked).toBe(2);
      expect(status.stats.fields_redacted).toBe(0);
    });

    it("can reset stats", async () => {
      const config: EnforcerConfig = {
        enabled: true,
        bypass_prefixes: [""],
        log_only: false,
        on_deny: "block",
      };

      const enforcer = new ContextGateEnforcer(policyStore, auditLog, config);

      const originalHandler: ToolHandler = async (args) => {
        return toolResult({ args });
      };

      const wrappedHandler = enforcer.wrapHandler("tool/api", originalHandler);
      await wrappedHandler({ api_key: "secret" });

      let status = enforcer.getStatus();
      expect(status.stats.calls_inspected).toBe(1);
      expect(status.stats.calls_blocked).toBe(1);

      enforcer.resetStats();

      status = enforcer.getStatus();
      expect(status.stats.calls_inspected).toBe(0);
      expect(status.stats.calls_blocked).toBe(0);
    });
  });

  // ── Policy-Based Filtering ──────────────────────────────────────────

  describe("Policy-Based Filtering", () => {
    it("uses explicit policy when set", async () => {
      // Create a policy that allows task, redacts api_key, and hashes user_id.
      const policy = await policyStore.create(
        "test-policy",
        [
          {
            provider: "tool-api",
            allow: ["task"],
            redact: ["api_key"],
            hash: ["user_id"],
            summarize: [],
          },
        ],
        "redact"
      );

      const config: EnforcerConfig = {
        enabled: true,
        default_policy_id: policy.policy_id,
        bypass_prefixes: [""],
        log_only: false,
        on_deny: "block",
      };

      const enforcer = new ContextGateEnforcer(policyStore, auditLog, config);

      const originalHandler: ToolHandler = async (args) => {
        return toolResult({ received: args });
      };

      const wrappedHandler = enforcer.wrapHandler("tool/api", originalHandler);

      const result = await wrappedHandler({
        api_key: "secret",
        task: "work",
        user_id: "user-123",
        other: "value",
      });

      const content = result.content[0];
      const parsed = JSON.parse(content.text);

      // task is allowed, api_key is redacted, user_id is hashed, other is default-redacted
      expect(parsed.received.task).toBe("work");
      expect(parsed.received.api_key).toBe("[REDACTED]");
      expect(parsed.received.user_id).toMatch(/^\[HASH:[A-Za-z0-9_-]+\]$/);
      // other field is not mentioned in policy, so default action (redact) applies
      expect(parsed.received.other).toBe("[REDACTED]");
      expect(JSON.stringify(parsed.received)).not.toContain("user-123");
    });

    it("does not copy an allowed parent object with unfiltered nested children", async () => {
      const policy = await policyStore.create(
        "nested-policy",
        [
          {
            provider: "tool-api",
            allow: ["metadata", "note"],
            redact: ["api_key"],
            hash: [],
            summarize: [],
          },
        ],
        "redact"
      );

      const config: EnforcerConfig = {
        enabled: true,
        default_policy_id: policy.policy_id,
        bypass_prefixes: [""],
        log_only: false,
        on_deny: "block",
      };
      const enforcer = new ContextGateEnforcer(policyStore, auditLog, config);

      const originalHandler: ToolHandler = async (args) => {
        return toolResult({ received: args });
      };
      const wrappedHandler = enforcer.wrapHandler("tool/api", originalHandler);

      const result = await wrappedHandler({
        metadata: {
          note: "safe nested note",
          api_key: "nested-secret-key",
        },
      });
      const parsed = JSON.parse(result.content[0].text);

      expect(parsed.received.metadata.note).toBe("safe nested note");
      expect(parsed.received.metadata.api_key).toBe("[REDACTED]");
      expect(JSON.stringify(parsed.received)).not.toContain("nested-secret-key");
    });

    it("filters proxy args with a bound policy before forwarding", async () => {
      const policy = await policyStore.create(
        "proxy-policy",
        [
          {
            provider: "tool-api",
            allow: ["task", "metadata", "note"],
            redact: ["api_key"],
            hash: ["user_id"],
            summarize: [],
          },
        ],
        "redact"
      );

      const enforcer = new ContextGateEnforcer(policyStore, auditLog, {
        enabled: true,
        default_policy_id: policy.policy_id,
        bypass_prefixes: [""],
        log_only: false,
        on_deny: "block",
      });

      const filtered = await enforcer.filterArgs(
        "proxy/server/tool",
        {
          task: "work",
          api_key: "secret",
          user_id: "user-123",
          metadata: {
            note: "safe nested note",
            api_key: "nested-secret-key",
          },
        },
        { respectBypass: false }
      );

      const metadata = filtered.metadata as Record<string, unknown>;
      expect(filtered.task).toBe("work");
      expect(filtered.api_key).toBe("[REDACTED]");
      expect(filtered.user_id).toMatch(/^\[HASH:[A-Za-z0-9_-]+\]$/);
      expect(metadata.note).toBe("safe nested note");
      expect(metadata.api_key).toBe("[REDACTED]");
      expect(JSON.stringify(filtered)).not.toContain("user-123");
      expect(JSON.stringify(filtered)).not.toContain("nested-secret-key");
    });

    it("MCP-wrapper path UNCHANGED: wrapHandler RETURNS the context_gating_blocked toolResult on a block (must not throw, must not call handler)", async () => {
      // Regression guard for the block-fail-open fix: the proxy path (filterArgs)
      // now THROWS on block, but the direct MCP-tool path (wrapHandler) must keep
      // its designed behavior — RETURN the context_gating_blocked toolResult to
      // its caller and NEVER invoke the wrapped handler.
      const policy = await policyStore.create(
        "block-policy",
        [
          {
            provider: "tool-api",
            allow: ["task"],
            redact: [],
            hash: [],
            summarize: [],
          },
        ],
        "deny"
      );

      const config: EnforcerConfig = {
        enabled: true,
        default_policy_id: policy.policy_id,
        bypass_prefixes: [""],
        log_only: false,
        on_deny: "block",
      };
      const enforcer = new ContextGateEnforcer(policyStore, auditLog, config);

      let handlerCalled = false;
      const originalHandler: ToolHandler = async (args) => {
        handlerCalled = true;
        return toolResult({ received: args });
      };

      const wrapped = enforcer.wrapHandler("tool/api", originalHandler);

      // api_key is not allowed → deny → on_deny "block".
      const result = await wrapped({ api_key: "secret", task: "work" });

      // The wrapped handler MUST NOT run (no upstream execution on a block).
      expect(handlerCalled).toBe(false);

      // The caller receives the context_gating_blocked toolResult (NOT a throw).
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toBe("context_gating_blocked");
      expect(parsed.denied_fields).toContain("api_key");
    });
  });

  // ── Control Methods ─────────────────────────────────────────────────

  describe("Control Methods", () => {
    it("can toggle enabled state", async () => {
      const config: EnforcerConfig = {
        enabled: true,
        bypass_prefixes: [""],
        log_only: false,
        on_deny: "block",
      };

      const enforcer = new ContextGateEnforcer(policyStore, auditLog, config);

      const originalHandler: ToolHandler = async (args) => {
        return toolResult({ args });
      };

      let status = enforcer.getStatus();
      expect(status.enabled).toBe(true);

      enforcer.setEnabled(false);

      status = enforcer.getStatus();
      expect(status.enabled).toBe(false);

      enforcer.setEnabled(true);

      status = enforcer.getStatus();
      expect(status.enabled).toBe(true);
    });

    it("can toggle log_only mode", async () => {
      const config: EnforcerConfig = {
        enabled: true,
        bypass_prefixes: [""],
        log_only: false,
        on_deny: "block",
      };

      const enforcer = new ContextGateEnforcer(policyStore, auditLog, config);

      let status = enforcer.getStatus();
      expect(status.log_only).toBe(false);

      enforcer.setLogOnly(true);

      status = enforcer.getStatus();
      expect(status.log_only).toBe(true);

      enforcer.setLogOnly(false);

      status = enforcer.getStatus();
      expect(status.log_only).toBe(false);
    });

    it("can set default policy", async () => {
      const policy = await policyStore.create(
        "my-policy",
        [
          {
            provider: "*",
            allow: [],
            redact: [],
            hash: [],
            summarize: [],
          },
        ],
        "redact"
      );

      const config: EnforcerConfig = {
        enabled: true,
        bypass_prefixes: [""],
        log_only: false,
        on_deny: "block",
      };

      const enforcer = new ContextGateEnforcer(policyStore, auditLog, config);

      let status = enforcer.getStatus();
      expect(status.default_policy_id).toBeNull();

      enforcer.setDefaultPolicy(policy.policy_id);

      status = enforcer.getStatus();
      expect(status.default_policy_id).toBe(policy.policy_id);
    });
  });

  // ── SEC-033: Bypass prefix namespace boundary ──────────────────────
  describe("SEC-033: Bypass prefix namespace safety", () => {
    it("bypasses all tools with wildcard sentinel", () => {
      const enforcer = new ContextGateEnforcer(policyStore, auditLog, {
        enabled: true,
        bypass_prefixes: ["*"],
        log_only: false,
        on_deny: "block",
      });

      expect(enforcer.shouldFilter("state_read")).toBe(false);
      expect(enforcer.shouldFilter("monitor_health")).toBe(false);
      expect(enforcer.shouldFilter("proxy/server/tool")).toBe(false);
    });

    it("filters proxy tools when bypass is limited to specific prefix", () => {
      const enforcer = new ContextGateEnforcer(policyStore, auditLog, {
        enabled: true,
        bypass_prefixes: ["internal"],
        log_only: false,
        on_deny: "block",
      });

      // internal/* tools are bypassed
      expect(enforcer.shouldFilter("internal/state_read")).toBe(false);
      // proxy/* and other tools are filtered
      expect(enforcer.shouldFilter("proxy/server/tool")).toBe(true);
      expect(enforcer.shouldFilter("external/steal")).toBe(true);
    });

    it("does NOT bypass tools with similar but different prefix", () => {
      const enforcer = new ContextGateEnforcer(policyStore, auditLog, {
        enabled: true,
        bypass_prefixes: ["proxy"],
        log_only: false,
        on_deny: "block",
      });

      // proxy/* tools are bypassed
      expect(enforcer.shouldFilter("proxy/server/tool")).toBe(false);
      // proxyevil/* should NOT be bypassed — namespace boundary
      expect(enforcer.shouldFilter("proxyevil/steal")).toBe(true);
      expect(enforcer.shouldFilter("proxyX/hack")).toBe(true);
    });

    it("enforces namespace boundary even without trailing slash in config", () => {
      const enforcer = new ContextGateEnforcer(policyStore, auditLog, {
        enabled: true,
        bypass_prefixes: ["proxy"],  // No trailing slash
        log_only: false,
        on_deny: "block",
      });

      // Should still be namespace-safe
      expect(enforcer.shouldFilter("proxy/server/tool")).toBe(false);
      expect(enforcer.shouldFilter("proxyevil/steal")).toBe(true);
    });
  });
});
