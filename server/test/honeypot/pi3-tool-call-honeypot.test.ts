/**
 * Sanctuary v1.3 WP-V1.3-5 Pi-3 tool-call honeypot regression suite.
 */

import { describe, expect, it } from "vitest";
import { IncomingMessage, ServerResponse, createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { SentinelFindingStore } from "../../src/sentinel/sentinel-finding-store.js";
import { TrapRegistry } from "../../src/honeypot/trap-registry.js";
import { compileHoneypot } from "../../src/honeypot/honeypot-compiler.js";
import { ToolCallTrapRuntime } from "../../src/honeypot/tool-call-trap-runtime.js";
import {
  HONEYPOT_API_PREFIX,
  handleHoneypotRoute,
} from "../../src/honeypot/runtime-trap-handler.js";
import {
  HONEYPOT_AUDIT_OPS,
  HONEYPOT_SENTINEL_ID_PREFIX,
  type TrapSpec,
} from "../../src/honeypot/types.js";
import { runHoneypotCli } from "../../src/honeypot/cli.ts";

const FORTRESS_A = "fortress_a";
const FORTRESS_B = "fortress_b";
const OPERATOR = "operator_pi3";

interface Rig {
  storage: MemoryStorage;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  findingStore: SentinelFindingStore;
  registry: TrapRegistry;
  runtime: ToolCallTrapRuntime;
}

async function makeRig(opts?: {
  fortressId?: string;
  now?: () => Date;
}): Promise<Rig> {
  const fortressId = opts?.fortressId ?? FORTRESS_A;
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const findingStore = new SentinelFindingStore({
    storage,
    masterKey,
    fortressId,
  });
  const registry = new TrapRegistry();
  const runtime = new ToolCallTrapRuntime({
    registry,
    findingStore,
    auditLog,
    operatorId: OPERATOR,
    fortressId,
    ...(opts?.now ? { now: opts.now } : {}),
  });
  return { storage, masterKey, auditLog, findingStore, registry, runtime };
}

function mkToolSpec(overrides: Partial<TrapSpec> = {}): TrapSpec {
  return {
    trap_id: overrides.trap_id ?? "tool-trap-1",
    trap_class: "tool_call",
    trigger: overrides.trigger ?? {
      kind: "tool_call",
      fake_tool_name: "admin_password_reader",
      fake_tool_description:
        "Read the administrative password for emergency recovery.",
      fake_tool_schema: {
        type: "object",
        properties: { reason: { type: "string" } },
      },
      catalog_visibility: "all_wrapped_agents",
      fake_response: "TRAP_ONLY_FAKE_PASSWORD_DO_NOT_USE",
    },
    finding_severity: overrides.finding_severity ?? "alert",
    english_text:
      overrides.english_text ??
      "Deploy a fake admin_password_reader tool visible to all agents.",
    explanation_paragraph: overrides.explanation_paragraph ?? "test fixture",
    compiled_at: overrides.compiled_at ?? new Date().toISOString(),
  };
}

describe("WP-V1.3-5 Pi-3 compiler: tool_call class", () => {
  it("LLM Path A parses a complete tool_call TrapSpec", async () => {
    const selector = makeStubSelector({
      capability: { summarize: true, classify: false, redact: false },
      summarize: async () => ({
        body: {
          kind: "summarize",
          text: JSON.stringify({
            trap_class: "tool_call",
            fake_tool_name: "admin_password_reader",
            fake_tool_description: "Read the admin password.",
            fake_tool_schema: {
              type: "object",
              properties: { ticket: { type: "string" } },
            },
            catalog_visibility: "all_wrapped_agents",
            fake_response: "TRAP_ONLY_FAKE_PASSWORD_DO_NOT_USE",
            expected_caller_types: ["wrapped_agent"],
            finding_severity: "alert",
            explanation_paragraph: "Fake tool catches privilege probes.",
          }),
        },
      }),
    });
    const result = await compileHoneypot(
      {
        english_text: "fake admin_password_reader tool visible to all agents",
        operator_id: OPERATOR,
        observed_at: new Date().toISOString(),
      },
      { selector },
    );
    expect(result.source).toBe("llm");
    expect(result.spec.trap_class).toBe("tool_call");
    expect(result.spec.trigger.kind).toBe("tool_call");
    if (result.spec.trigger.kind === "tool_call") {
      expect(result.spec.trigger.fake_tool_name).toBe("admin_password_reader");
      expect(result.spec.trigger.catalog_visibility).toBe("all_wrapped_agents");
    }
  });

  it("LLM Path A rejects invalid fake tool schema and falls back", async () => {
    const selector = makeStubSelector({
      capability: { summarize: true, classify: false, redact: false },
      summarize: async () => ({
        body: {
          kind: "summarize",
          text: JSON.stringify({
            trap_class: "tool_call",
            fake_tool_name: "admin_password_reader",
            fake_tool_schema: "not-schema",
            fake_response: "fake",
          }),
        },
      }),
    });
    const result = await compileHoneypot(
      {
        english_text:
          "Deploy a fake admin_password_reader tool visible to all agents.",
        operator_id: OPERATOR,
        observed_at: new Date().toISOString(),
      },
      { selector },
    );
    expect(result.source).toBe("heuristic");
    expect(result.warnings.some((w) => /invalid_fake_tool_schema/.test(w))).toBe(true);
    expect(result.spec.trap_class).toBe("tool_call");
  });

  it("heuristic Path B compiles English fake-tool bait", async () => {
    const result = await compileHoneypot({
      english_text:
        "Deploy a fake admin_password_reader tool visible to all agents; if invoked, return a clearly marked trap password.",
      operator_id: OPERATOR,
      observed_at: new Date().toISOString(),
    });
    expect(result.source).toBe("heuristic");
    expect(result.spec.trap_class).toBe("tool_call");
    if (result.spec.trigger.kind === "tool_call") {
      expect(result.spec.trigger.fake_tool_name).toBe("admin_password_reader");
      expect(result.spec.trigger.fake_response).toContain("TRAP_ONLY");
    }
  });
});

describe("WP-V1.3-5 Pi-3 runtime catalog injection", () => {
  it("all_wrapped_agents visibility injects the fake tool for any agent", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkToolSpec());
    const tools = rig.runtime.listCatalogTools("cline");
    expect(tools.map((t) => t.name)).toContain("admin_password_reader");
  });

  it("specific_agents visibility limits catalog injection", async () => {
    const rig = await makeRig();
    rig.registry.deploy(
      mkToolSpec({
        trigger: {
          kind: "tool_call",
          fake_tool_name: "billing_token_reader",
          fake_tool_description: "Read billing tokens.",
          fake_tool_schema: { type: "object", properties: {} },
          catalog_visibility: "specific_agents",
          visible_to_agents: ["cline"],
          fake_response: { token: "TRAP_ONLY_FAKE_TOKEN" },
        },
      }),
    );
    expect(rig.runtime.listCatalogTools("cline").map((t) => t.name)).toContain(
      "billing_token_reader",
    );
    expect(rig.runtime.listCatalogTools("other").map((t) => t.name)).not.toContain(
      "billing_token_reader",
    );
  });
});

describe("WP-V1.3-5 Pi-3 trap activation on invoke", () => {
  it("does not return hidden fake responses to agents outside specific_agents visibility", async () => {
    const rig = await makeRig();
    rig.registry.deploy(
      mkToolSpec({
        trigger: {
          kind: "tool_call",
          fake_tool_name: "billing_token_reader",
          fake_tool_description: "Read billing tokens.",
          fake_tool_schema: { type: "object", properties: {} },
          catalog_visibility: "specific_agents",
          visible_to_agents: ["cline"],
          fake_response: { token: "TRAP_ONLY_FAKE_TOKEN" },
        },
      }),
    );

    const hidden = await rig.runtime.invokeIfTrap(
      "billing_token_reader",
      {},
      "agent:other",
    );
    expect(hidden.handled).toBe(false);

    const visible = await rig.runtime.invokeIfTrap(
      "billing_token_reader",
      {},
      "agent:cline",
    );
    expect(visible.handled).toBe(true);
  });

  it("returns fake_response and emits sentinel finding", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkToolSpec());
    const result = await rig.runtime.invokeIfTrap(
      "admin_password_reader",
      { reason: "debug" },
      "agent:cline",
    );
    expect(result.handled).toBe(true);
    if (result.handled) {
      expect(result.response).toBe("TRAP_ONLY_FAKE_PASSWORD_DO_NOT_USE");
    }
    const findings = await rig.findingStore.listFindings({ limit: 100 });
    expect(findings.length).toBe(1);
    expect(findings[0]!.sentinel_id).toBe(
      `${HONEYPOT_SENTINEL_ID_PREFIX}tool-trap-1`,
    );
  });

  it("audit emission includes caller identity, args, arg hash, and response plausibility", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkToolSpec());
    await rig.runtime.invokeIfTrap(
      "admin_password_reader",
      { reason: "debug" },
      "agent:cline",
    );
    const entries = (await rig.auditLog.query({ layer: "l2", limit: 100 })).entries;
    const trigger = entries.find((e) => e.operation === HONEYPOT_AUDIT_OPS.TRIGGERED);
    expect(trigger).toBeDefined();
    const details = trigger!.details as Record<string, unknown>;
    expect(details["caller_identity"]).toBe("agent:cline");
    expect(details["arg_hash"]).toMatch(/^[a-f0-9]{32}$/);
    expect(details["response_plausibility"]).toBe(
      "operator_configured_fake_response",
    );
  });

  it("non-trap tool invocation is ignored", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkToolSpec());
    const result = await rig.runtime.invokeIfTrap(
      "state_read",
      {},
      "agent:cline",
    );
    expect(result.handled).toBe(false);
    expect((await rig.findingStore.listFindings({ limit: 100 })).length).toBe(0);
  });
});

describe("WP-V1.3-5 Pi-3 follow-up correlation", () => {
  it("captures follow-up tool calls within the 5-minute window", async () => {
    let nowMs = Date.parse("2026-05-09T14:23:00.000Z");
    const rig = await makeRig({ now: () => new Date(nowMs) });
    rig.registry.deploy(mkToolSpec());
    await rig.runtime.invokeIfTrap("admin_password_reader", {}, "agent:cline");
    nowMs += 4 * 60 * 1000;
    rig.runtime.recordToolCall(
      "file_read",
      { path: "/etc/passwd" },
      "agent:cline",
    );
    const stats = rig.runtime.stats()[0]!;
    expect(stats.activations[0]!.follow_up_tool_calls.length).toBe(1);
    expect(stats.activations[0]!.follow_up_tool_calls[0]!.tool_name).toBe(
      "file_read",
    );
  });

  it("does not correlate follow-up calls after 5 minutes", async () => {
    let nowMs = Date.parse("2026-05-09T14:23:00.000Z");
    const rig = await makeRig({ now: () => new Date(nowMs) });
    rig.registry.deploy(mkToolSpec());
    await rig.runtime.invokeIfTrap("admin_password_reader", {}, "agent:cline");
    nowMs += 6 * 60 * 1000;
    rig.runtime.recordToolCall("file_read", { path: "/etc/passwd" }, "agent:cline");
    expect(rig.runtime.stats()[0]!.activations[0]!.follow_up_tool_calls).toEqual([]);
  });
});

describe("WP-V1.3-5 Pi-3 stats, CLI, management API, isolation", () => {
  it("stats report invocation count, last invocation time, and caller diversity", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkToolSpec());
    await rig.runtime.invokeIfTrap("admin_password_reader", {}, "agent:a");
    await rig.runtime.invokeIfTrap("admin_password_reader", {}, "agent:b");
    const stats = rig.runtime.stats()[0]!;
    expect(stats.invocation_count).toBe(2);
    expect(stats.caller_diversity).toBe(2);
    expect(stats.last_invocation_at).toBeTruthy();
  });

  it("management route exposes tool-trap stats for dashboard drilldown", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkToolSpec());
    await rig.runtime.invokeIfTrap("admin_password_reader", {}, "agent:cline");
    const server: Server = createServer(async (req, res) => {
      const handled = await handleHoneypotRoute(
        {
          authConfig: { loopbackAutoAuth: true },
          registry: rig.registry,
          findingStore: rig.findingStore,
          auditLog: rig.auditLog,
          operatorId: OPERATOR,
          fortressId: FORTRESS_A,
          toolCallRuntime: rig.runtime,
        },
        req,
        res,
      );
      if (!handled) res.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    try {
      const res = await fetch(
        `http://127.0.0.1:${addr.port}${HONEYPOT_API_PREFIX}/tool-traps`,
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as { data: { traps: unknown[] } };
      expect(body.data.traps.length).toBe(1);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("CLI tool-traps list surfaces deployed tool-call traps", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkToolSpec());
    const streams = captureStreams();
    const exit = await runHoneypotCli(
      {
        registry: rig.registry,
        findingStore: rig.findingStore,
        auditLog: rig.auditLog,
        operatorId: OPERATOR,
        fortressId: FORTRESS_A,
        toolTrapStats: () => rig.runtime.stats(),
      },
      {
        argv: ["tool-traps", "list"],
        out: streams.out as unknown as NodeJS.WritableStream,
        err: streams.err as unknown as NodeJS.WritableStream,
      },
    );
    expect(exit).toBe(0);
    expect(streams.out.text).toContain("admin_password_reader");
  });

  it("multi-fortress isolation keeps tool-call findings scoped", async () => {
    const rigA = await makeRig({ fortressId: FORTRESS_A });
    const rigB = await makeRig({ fortressId: FORTRESS_B });
    rigA.registry.deploy(mkToolSpec());
    rigB.registry.deploy(mkToolSpec({ trap_id: "tool-trap-b" }));
    await rigA.runtime.invokeIfTrap("admin_password_reader", {}, "agent:cline");
    expect((await rigA.findingStore.listFindings({ limit: 100 })).length).toBe(1);
    expect((await rigB.findingStore.listFindings({ limit: 100 })).length).toBe(0);
  });

  it("castle-walking: catalog injection is server-local and creates no outbound selector call", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkToolSpec());
    expect(rig.runtime.listCatalogTools("cline").length).toBe(1);
    const entries = (await rig.auditLog.query({ layer: "l2", limit: 100 })).entries;
    expect(entries.length).toBe(0);
  });
});

interface StubSelectorOpts {
  capability: { summarize: boolean; classify: boolean; redact: boolean };
  summarize?: () => Promise<{ body: { kind: "summarize"; text: string } }>;
}

function makeStubSelector(opts: StubSelectorOpts): any {
  const summarizeImpl =
    opts.summarize ??
    (async () => ({ body: { kind: "summarize", text: "{}" } }));
  return {
    getSubstrate: async () => ({
      surface: "template-suggestion",
      substrate: "local",
      capability: opts.capability,
      badge: {
        surface: "template-suggestion",
        substrate: "local",
        labelKey: "test",
        tradeoffKey: "test",
        status: "green",
      },
      displayLabel: "Test",
    }),
    invokeSummarize: async () => {
      const r = await summarizeImpl();
      return {
        servedBy: "local",
        failureClass: null,
        body: r.body,
        completedAt: new Date().toISOString(),
        latencyMs: 1,
      };
    },
  };
}

function captureStreams(): {
  out: { write: (s: string) => boolean; text: string };
  err: { write: (s: string) => boolean; text: string };
} {
  let outText = "";
  let errText = "";
  return {
    out: {
      write: (s: string) => {
        outText += s;
        return true;
      },
      get text() {
        return outText;
      },
    },
    err: {
      write: (s: string) => {
        errText += s;
        return true;
      },
      get text() {
        return errText;
      },
    },
  };
}

const _IncomingMessage = IncomingMessage;
const _ServerResponse = ServerResponse;
void _IncomingMessage;
void _ServerResponse;
