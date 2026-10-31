/** Context filtering preserves server routing identity and execution context on every continuing path. */
import { describe, expect, it, vi } from "vitest";
import { ContextGateEnforcer } from "../../src/operational/context-gate-enforcer.js";
import { ContextGatePolicyStore } from "../../src/operational/context-gate.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { toolResult, type ToolHandler } from "../../src/router.js";

describe("routing data survives context filtering", () => {
  it.each(["disabled", "bypass", "log_only", "redact", "pass"])("forwards identity and context unchanged on %s", async (path) => {
    const storage = new MemoryStorage();
    const key = generateRandomKey();
    const store = new ContextGatePolicyStore(storage, key);
    const policy = await store.create("routing", [{ provider: "tool-api", allow: ["task"], redact: [], hash: [], summarize: [] }], "deny");
    const gate = new ContextGateEnforcer(store, new AuditLog(storage, key), {
      enabled: path !== "disabled", bypass_prefixes: path === "bypass" ? ["*"] : [],
      default_policy_id: policy.policy_id, log_only: path === "log_only", on_deny: "redact",
    });
    const handler = vi.fn<ToolHandler>(async () => toolResult({ ok: true }));
    const context = { signal: new AbortController().signal, approvalAuditId: "approval:routing" };
    const args = path === "redact" ? { task: "save", secret: "private" } : { task: "save" };
    await gate.wrapHandler("external/call", handler)(args, "agent:hermes:fortress-0123456789abcdef", context);
    expect(handler).toHaveBeenCalledExactlyOnceWith(expect.any(Object), "agent:hermes:fortress-0123456789abcdef", context);
    expect(handler.mock.calls[0]?.[2]).toBe(context);
    if (path === "redact") expect(handler.mock.calls[0]?.[0]).not.toEqual(args);
  });
});
