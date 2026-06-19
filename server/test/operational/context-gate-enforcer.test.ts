/**
 * L2 Context Gate Enforcer Tests
 *
 * Verifies:
 * - Wrapping a handler filters its arguments
 * - Sanctuary/ prefixed tools are bypassed
 * - Sensitive field patterns caught by fallback
 * - log_only mode passes original args but logs
 * - deny action "block" returns error, "redact" continues
 * - Stats accumulate correctly
 * - No policy = fallback pattern matching works
 * - Policy-based filtering works correctly
 * - on_deny configuration respected
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  ContextGateEnforcer,
  BUILTIN_SENSITIVE_PATTERNS,
  type EnforcerConfig,
} from "../../src/operational/context-gate-enforcer.js";
import type { ContextGatePolicyStore } from "../../src/operational/context-gate.js";
import { ContextGatePolicyStore } from "../../src/operational/context-gate.js";
import type { AuditLog } from "../../src/operational/audit-log.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import type { ToolHandler } from "../../src/router.js";
import { toolResult } from "../../src/router.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

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
    it("wraps a handler to filter its arguments", async () => {
      const config: EnforcerConfig = {
        enabled: true,
        bypass_prefixes: [""],
        log_only: false,
        on_deny: "block",
      };

      const enforcer = new ContextGateEnforcer(policyStore, auditLog, config);

      // Create a simple handler that echoes its args
      const originalHandler: ToolHandler = async (args) => {
        return toolResult({ received_args: args });
      };

      const wrappedHandler = enforcer.wrapHandler("external/call", originalHandler);

      // Call with sensitive fields (that should be caught by fallback)
      const result = await wrappedHandler({
        api_key: "secret123",
        task: "do something",
      });

      // In log_only mode disabled, the handler receives filtered args
      // but we're not in log_only, and we have no policy, so fallback applies
      // api_key should be redacted
      const content = result.content[0];
      expect(content.type).toBe("text");
      const parsed = JSON.parse(content.text);

      // The handler should have been called, and api_key should be redacted
      expect(parsed.received_args.api_key).toBe("[REDACTED]");
      expect(parsed.received_args.task).toBe("do something");
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

  // ── Built-in Sensitive Patterns ─────────────────────────────────────

  describe("Built-in Sensitive Field Patterns", () => {
    it("catches api_key pattern", async () => {
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

      const result = await wrappedHandler({
        api_key: "secret123",
        regular_field: "normal",
      });

      const content = result.content[0];
      const parsed = JSON.parse(content.text);
      expect(parsed.args.api_key).toBe("[REDACTED]");
      expect(parsed.args.regular_field).toBe("normal");
    });

    it("catches *_token pattern", async () => {
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

      const result = await wrappedHandler({
        access_token: "token123",
        refresh_token: "refresh456",
        session: "abc",
      });

      const content = result.content[0];
      const parsed = JSON.parse(content.text);
      expect(parsed.args.access_token).toBe("[REDACTED]");
      expect(parsed.args.refresh_token).toBe("[REDACTED]");
      expect(parsed.args.session).toBe("abc");
    });

    it("catches password pattern", async () => {
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

      const result = await wrappedHandler({
        password: "pass123",
        passwd: "pass456",
        username: "user",
      });

      const content = result.content[0];
      const parsed = JSON.parse(content.text);
      expect(parsed.args.password).toBe("[REDACTED]");
      expect(parsed.args.passwd).toBe("[REDACTED]");
      expect(parsed.args.username).toBe("user");
    });

    it("catches credential* pattern", async () => {
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

      const result = await wrappedHandler({
        credentials: "creds123",
        credentials_token: "token",
        other: "value",
      });

      const content = result.content[0];
      const parsed = JSON.parse(content.text);
      expect(parsed.args.credentials).toBe("[REDACTED]");
      expect(parsed.args.credentials_token).toBe("[REDACTED]");
      expect(parsed.args.other).toBe("value");
    });

    it("catches private_key, secret_key patterns", async () => {
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

      const result = await wrappedHandler({
        private_key: "pk123",
        secret_key: "sk456",
        master_key: "mk789",
        public_key: "pub",
      });

      const content = result.content[0];
      const parsed = JSON.parse(content.text);
      expect(parsed.args.private_key).toBe("[REDACTED]");
      expect(parsed.args.secret_key).toBe("[REDACTED]");
      expect(parsed.args.master_key).toBe("[REDACTED]");
      // public_key matches *_key pattern, so it should also be redacted
      expect(parsed.args.public_key).toBe("[REDACTED]");
    });

    it("catches credit_card and cvv patterns", async () => {
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

      const result = await wrappedHandler({
        credit_card: "4111111111111111",
        credit_card_number: "4222222222222222",
        cvv: "123",
        cvc: "456",
        amount: "100",
      });

      const content = result.content[0];
      const parsed = JSON.parse(content.text);
      expect(parsed.args.credit_card).toBe("[REDACTED]");
      expect(parsed.args.credit_card_number).toBe("[REDACTED]");
      expect(parsed.args.cvv).toBe("[REDACTED]");
      expect(parsed.args.cvc).toBe("[REDACTED]");
      expect(parsed.args.amount).toBe("100");
    });

    it("catches PII patterns (ssn, tax_id)", async () => {
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

      const result = await wrappedHandler({
        ssn: "123-45-6789",
        social_security_number: "987-65-4321",
        tax_id: "12-3456789",
        tax_id_number: "98-7654321",
        name: "John Doe",
      });

      const content = result.content[0];
      const parsed = JSON.parse(content.text);
      expect(parsed.args.ssn).toBe("[REDACTED]");
      expect(parsed.args.social_security_number).toBe("[REDACTED]");
      expect(parsed.args.tax_id).toBe("[REDACTED]");
      expect(parsed.args.tax_id_number).toBe("[REDACTED]");
      expect(parsed.args.name).toBe("John Doe");
    });

    it("redacts sensitive spans inside otherwise safe fields", async () => {
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

      const result = await wrappedHandler({
        task: "email jane@example.com about project alpha",
        nested: { note: "phone 415-555-1212" },
      });

      const content = result.content[0];
      const parsed = JSON.parse(content.text);
      expect(parsed.args.task).toBe(
        "email [EMAIL_REDACTED] about project alpha"
      );
      expect(parsed.args.nested.note).toBe("phone [PHONE_REDACTED]");
    });
  });

  // ── log_only Mode ───────────────────────────────────────────────────

  describe("log_only Mode", () => {
    it("logs filtering decision but passes original args", async () => {
      const config: EnforcerConfig = {
        enabled: true,
        bypass_prefixes: [""],
        log_only: true,
        on_deny: "block",
      };

      const enforcer = new ContextGateEnforcer(policyStore, auditLog, config);

      const originalHandler: ToolHandler = async (args) => {
        return toolResult({ received: args });
      };

      const wrappedHandler = enforcer.wrapHandler("tool/api", originalHandler);

      const result = await wrappedHandler({
        api_key: "secret123",
        task: "do something",
      });

      const content = result.content[0];
      const parsed = JSON.parse(content.text);

      // In log_only mode, original unfiltered args should be passed to handler
      expect(parsed.received.api_key).toBe("secret123");
      expect(parsed.received.task).toBe("do something");

      // But stats should reflect what would have been redacted
      const status = enforcer.getStatus();
      expect(status.log_only).toBe(true);
      expect(status.stats.fields_redacted).toBe(1); // api_key would be redacted
      expect(status.stats.calls_inspected).toBe(1);
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

      // Call 2: inspect and redact (external/ prefix NOT bypassed)
      const wrapped2 = enforcer.wrapHandler("external/tool", originalHandler);
      await wrapped2({ api_key: "secret", task: "work" });

      // Call 3: inspect but no sensitive fields
      const wrapped3 = enforcer.wrapHandler("external/tool2", originalHandler);
      await wrapped3({ task: "work", query: "search" });

      const status = enforcer.getStatus();
      expect(status.stats.calls_bypassed).toBe(1);
      expect(status.stats.calls_inspected).toBe(2);
      expect(status.stats.fields_redacted).toBe(1); // Only from call 2
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
      expect(status.stats.fields_redacted).toBe(1);

      enforcer.resetStats();

      status = enforcer.getStatus();
      expect(status.stats.calls_inspected).toBe(0);
      expect(status.stats.fields_redacted).toBe(0);
    });
  });

  // ── Policy-Based Filtering ──────────────────────────────────────────

  describe("Policy-Based Filtering", () => {
    it("uses explicit policy when set", async () => {
      // Create a policy that allows task and redacts api_key
      const policy = await policyStore.create(
        "test-policy",
        [
          {
            provider: "tool-api",
            allow: ["task"],
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
        api_key: "secret",
        task: "work",
        other: "value",
      });

      const content = result.content[0];
      const parsed = JSON.parse(content.text);

      // task is allowed, api_key is redacted, other is default-redacted
      expect(parsed.received.task).toBe("work");
      expect(parsed.received.api_key).toBe("[REDACTED]");
      // other field is not mentioned in policy, so default action (redact) applies
      expect(parsed.received.other).toBe("[REDACTED]");
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

  // ── Builtin Patterns Export ────────────────────────────────────────

  describe("Built-in Patterns", () => {
    it("exports builtin patterns for reference", () => {
      expect(BUILTIN_SENSITIVE_PATTERNS).toBeDefined();
      expect(Array.isArray(BUILTIN_SENSITIVE_PATTERNS)).toBe(true);
      expect(BUILTIN_SENSITIVE_PATTERNS.length).toBeGreaterThan(0);

      // Check some expected patterns
      expect(BUILTIN_SENSITIVE_PATTERNS).toContain("api_key");
      expect(BUILTIN_SENSITIVE_PATTERNS).toContain("*_token");
      expect(BUILTIN_SENSITIVE_PATTERNS).toContain("password");
    });
  });

  // ── No Sensitive Fields ─────────────────────────────────────────────

  describe("No Sensitive Fields", () => {
    it("passes through when no sensitive fields detected", async () => {
      const config: EnforcerConfig = {
        enabled: true,
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
        task: "work",
        query: "search",
        limit: 100,
      });

      const content = result.content[0];
      const parsed = JSON.parse(content.text);

      // All fields should pass through unchanged
      expect(parsed.received.task).toBe("work");
      expect(parsed.received.query).toBe("search");
      expect(parsed.received.limit).toBe(100);

      const status = enforcer.getStatus();
      expect(status.stats.fields_redacted).toBe(0);
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
