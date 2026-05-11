/**
 * Sanctuary v1.3 WP-V1.3-5 Pi-1 Honeypot Authoring regression suite.
 *
 * Coverage:
 *  - Compiler: LLM (Path A) success + LLM failure -> heuristic (Path B)
 *    fallback + selector-absent direct-heuristic + truly-unparseable
 *    draft yields stub trigger + warning.
 *  - Trap registry: deploy idempotency, undeploy idempotency, glob
 *    path matching (single-star, double-star, literal), method
 *    filter.
 *  - Runtime trap handler: matched request emits audit + sentinel
 *    finding + plausible 404; non-matching request returns false
 *    (handler does not intercept); /api/honeypot/* requests do not
 *    self-shadow.
 *  - Management routes: compile, deploy, list, undeploy, findings,
 *    auth gate.
 *  - CLI subcommands: compile, deploy, list, undeploy, findings.
 *  - Multi-fortress isolation: each registry holds its own traps;
 *    each finding store holds its own findings.
 *  - Castle-walking: trap responses server-local; no outbound surface
 *    from trap path itself; compile path absent-selector forces
 *    heuristic Path B.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { IncomingMessage, ServerResponse, createServer, type Server } from "node:http";
import { Socket } from "node:net";
import type { AddressInfo } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  AuditLog,
  type AuditEntry,
} from "../../src/l2-operational/audit-log.js";
import { SentinelFindingStore } from "../../src/sentinel/sentinel-finding-store.js";

import {
  TrapRegistry,
  compileGlob,
  matchesTrap,
} from "../../src/honeypot/trap-registry.js";
import {
  compileHoneypot,
  hashOfEnglishDraft,
} from "../../src/honeypot/honeypot-compiler.js";
import {
  HONEYPOT_API_PREFIX,
  handleHoneypotRoute,
  handleHoneypotTriggerIfMatch,
} from "../../src/honeypot/runtime-trap-handler.js";
import {
  HONEYPOT_AUDIT_OPS,
  HONEYPOT_SENTINEL_ID_PREFIX,
  type TrapSpec,
} from "../../src/honeypot/types.js";
import { runHoneypotCli } from "../../src/honeypot/cli.ts";

const FORTRESS_A = "fortress_a";
const FORTRESS_B = "fortress_b";
const OPERATOR = "operator_pi1";

interface Rig {
  storage: MemoryStorage;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  findingStore: SentinelFindingStore;
  registry: TrapRegistry;
}

async function makeRig(opts?: { fortressId?: string }): Promise<Rig> {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const findingStore = new SentinelFindingStore({
    storage,
    masterKey,
    fortressId: opts?.fortressId ?? FORTRESS_A,
  });
  const registry = new TrapRegistry();
  return { storage, masterKey, auditLog, findingStore, registry };
}

function mkSpec(overrides: Partial<TrapSpec> = {}): TrapSpec {
  return {
    trap_id: overrides.trap_id ?? "trap-1",
    trap_class: "http_endpoint",
    trigger: overrides.trigger ?? {
      path_pattern: "/admin/secrets",
      expected_caller_types: ["wrapped_agent"],
    },
    finding_severity: overrides.finding_severity ?? "alert",
    english_text: overrides.english_text ?? "deploy a honeypot at /admin/secrets",
    explanation_paragraph: overrides.explanation_paragraph ?? "test fixture",
    compiled_at: overrides.compiled_at ?? new Date().toISOString(),
  };
}

// ── Compiler ─────────────────────────────────────────────────────────────

describe("WP-V1.3-5 Pi-1 honeypot compiler", () => {
  it("LLM Path A: parses a valid JSON response and returns source='llm'", async () => {
    const selector = makeStubSelector({
      capability: { summarize: true, classify: false, redact: false },
      summarize: async () => ({
        body: {
          kind: "summarize",
          text: JSON.stringify({
            path_pattern: "/admin/*",
            method: "GET",
            expected_caller_types: ["wrapped_agent"],
            finding_severity: "alert",
            explanation_paragraph: "Catch unauthorized admin paths.",
          }),
        },
      }),
    });
    const result = await compileHoneypot(
      {
        english_text: "trap at /admin/* (GET)",
        operator_id: OPERATOR,
        observed_at: new Date().toISOString(),
      },
      { selector },
    );
    expect(result.source).toBe("llm");
    expect(result.spec.trigger.path_pattern).toBe("/admin/*");
    expect(result.spec.trigger.method).toBe("GET");
    expect(result.spec.finding_severity).toBe("alert");
  });

  it("Path A falls back to Path B on malformed LLM JSON; warnings populated", async () => {
    const selector = makeStubSelector({
      capability: { summarize: true, classify: false, redact: false },
      summarize: async () => ({
        body: { kind: "summarize", text: "not json at all" },
      }),
    });
    const result = await compileHoneypot(
      {
        english_text: "deploy a honeypot at /internal/debug",
        operator_id: OPERATOR,
        observed_at: new Date().toISOString(),
      },
      { selector },
    );
    expect(result.source).toBe("heuristic");
    expect(result.spec.trigger.path_pattern).toBe("/internal/debug");
    expect(result.warnings.length).toBeGreaterThanOrEqual(1);
    expect(result.warnings.some((w) => /invalid_json|falling back/.test(w))).toBe(true);
  });

  it("absent selector runs heuristic Path B directly", async () => {
    const result = await compileHoneypot({
      english_text: "honeypot at /admin/secrets",
      operator_id: OPERATOR,
      observed_at: new Date().toISOString(),
    });
    expect(result.source).toBe("heuristic");
    expect(result.spec.trigger.path_pattern).toBe("/admin/secrets");
  });

  it("unparseable English yields stub trigger + warning", async () => {
    const result = await compileHoneypot({
      english_text: "I would like a honeypot somewhere",
      operator_id: OPERATOR,
      observed_at: new Date().toISOString(),
    });
    expect(result.spec.trigger.path_pattern).toBe("/honeypot-stub");
    expect(result.warnings.some((w) => /heuristic compile/.test(w))).toBe(true);
  });
});

// ── Trap registry ────────────────────────────────────────────────────────

describe("WP-V1.3-5 Pi-1 trap registry + glob matching", () => {
  it("deploy is idempotent on trap_id; second deploy returns was_new=false", () => {
    const registry = new TrapRegistry();
    const spec = mkSpec();
    expect(registry.deploy(spec)).toBe(true);
    expect(registry.deploy(spec)).toBe(false);
    expect(registry.list().length).toBe(1);
  });

  it("undeploy is idempotent; second undeploy returns false", () => {
    const registry = new TrapRegistry();
    registry.deploy(mkSpec());
    expect(registry.undeploy("trap-1")).toBe(true);
    expect(registry.undeploy("trap-1")).toBe(false);
  });

  it("compileGlob: single-star matches one segment; double-star matches multiple", () => {
    expect(compileGlob("/admin/*").test("/admin/secrets")).toBe(true);
    expect(compileGlob("/admin/*").test("/admin/secrets/inner")).toBe(false);
    expect(compileGlob("/admin/**").test("/admin/secrets/inner")).toBe(true);
    expect(compileGlob("/exact").test("/exact")).toBe(true);
    expect(compileGlob("/exact").test("/exact/extra")).toBe(false);
  });

  it("matchesTrap respects method filter", () => {
    const spec = mkSpec({
      trigger: { path_pattern: "/admin/*", method: "POST", expected_caller_types: ["wrapped_agent"] },
    });
    expect(matchesTrap(spec, { path: "/admin/x", method: "POST" })).toBe(true);
    expect(matchesTrap(spec, { path: "/admin/x", method: "GET" })).toBe(false);
  });
});

// ── Runtime trap handler ─────────────────────────────────────────────────

describe("WP-V1.3-5 Pi-1 runtime trap handler", () => {
  it("matched request emits audit event + sentinel finding + 404", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkSpec({ trigger: { path_pattern: "/admin/*", expected_caller_types: ["wrapped_agent"] } }));

    const { req, res, capture } = makeMockReqRes("GET", "/admin/secrets");
    const handled = await handleHoneypotTriggerIfMatch(
      {
        registry: rig.registry,
        findingStore: rig.findingStore,
        auditLog: rig.auditLog,
        operatorId: OPERATOR,
        fortressId: FORTRESS_A,
      },
      req,
      res,
    );
    expect(handled).toBe(true);
    expect(capture.statusCode).toBe(404);
    const auditEntries = (await rig.auditLog.query({ layer: "l2", limit: 100 })).entries;
    const trigger = auditEntries.find(
      (e) => e.operation === HONEYPOT_AUDIT_OPS.TRIGGERED,
    );
    expect(trigger).toBeDefined();
    expect((trigger!.details as Record<string, unknown>).path_matched).toBe(
      "/admin/secrets",
    );
    const findings = await rig.findingStore.listFindings({ limit: 100 });
    expect(findings.length).toBe(1);
    expect(findings[0]!.sentinel_id).toBe(`${HONEYPOT_SENTINEL_ID_PREFIX}trap-1`);
    expect(findings[0]!.severity).toBe("alert");
  });

  it("non-matching request returns false (handler does not intercept)", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkSpec({ trigger: { path_pattern: "/admin/*", expected_caller_types: ["wrapped_agent"] } }));
    const { req, res, capture } = makeMockReqRes("GET", "/public/index.html");
    const handled = await handleHoneypotTriggerIfMatch(
      {
        registry: rig.registry,
        findingStore: rig.findingStore,
        auditLog: rig.auditLog,
        operatorId: OPERATOR,
        fortressId: FORTRESS_A,
      },
      req,
      res,
    );
    expect(handled).toBe(false);
    expect(capture.statusCode).toBeUndefined();
  });

  it("trap response body is plausible 404 JSON (no honeypot-leaking content)", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkSpec({ trigger: { path_pattern: "/admin/*", expected_caller_types: ["wrapped_agent"] } }));
    const { req, res, capture } = makeMockReqRes("GET", "/admin/secrets");
    await handleHoneypotTriggerIfMatch(
      {
        registry: rig.registry,
        findingStore: rig.findingStore,
        auditLog: rig.auditLog,
        operatorId: OPERATOR,
        fortressId: FORTRESS_A,
      },
      req,
      res,
    );
    expect(capture.body).toContain('"error":"not_found"');
    expect(capture.body).not.toContain("honeypot");
    expect(capture.body).not.toContain("trap");
  });

  it("management API path is not self-shadowed by the trap-trigger hook", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkSpec({ trigger: { path_pattern: "/**", expected_caller_types: ["wrapped_agent"] } }));
    const { req, res } = makeMockReqRes("GET", "/api/honeypot/traps");
    const handled = await handleHoneypotTriggerIfMatch(
      {
        registry: rig.registry,
        findingStore: rig.findingStore,
        auditLog: rig.auditLog,
        operatorId: OPERATOR,
        fortressId: FORTRESS_A,
      },
      req,
      res,
    );
    expect(handled).toBe(false);
  });
});

// ── Management routes ────────────────────────────────────────────────────

describe("WP-V1.3-5 Pi-1 management routes", () => {
  const tempDirs: string[] = [];
  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function makeServer(rig: Rig): Promise<{ base: string; close: () => Promise<void> }> {
    const server: Server = createServer(async (req, res) => {
      const handled = await handleHoneypotRoute(
        {
          authConfig: { loopbackAutoAuth: true },
          registry: rig.registry,
          findingStore: rig.findingStore,
          auditLog: rig.auditLog,
          operatorId: OPERATOR,
          fortressId: FORTRESS_A,
        },
        req,
        res,
      );
      if (!handled) res.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    return {
      base: `http://127.0.0.1:${addr.port}`,
      close: () => new Promise<void>((r) => server.close(() => r())),
    };
  }

  it("POST /api/honeypot/compile returns spec + emits drafted + compiled audit ops", async () => {
    const rig = await makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(`${base}${HONEYPOT_API_PREFIX}/compile`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ english_text: "honeypot at /admin/secrets" }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        ok: boolean;
        data: { spec: TrapSpec; source: string; warnings: string[] };
      };
      expect(body.ok).toBe(true);
      expect(body.data.spec.trigger.path_pattern).toBe("/admin/secrets");
      const auditEntries = (await rig.auditLog.query({ layer: "l2", limit: 100 })).entries;
      expect(auditEntries.some((e) => e.operation === HONEYPOT_AUDIT_OPS.DRAFTED)).toBe(true);
      expect(auditEntries.some((e) => e.operation === HONEYPOT_AUDIT_OPS.COMPILED)).toBe(true);
    } finally {
      await close();
    }
  });

  it("POST /api/honeypot/deploy adds spec to registry + emits deployed audit op", async () => {
    const rig = await makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const spec = mkSpec();
      const res = await fetch(`${base}${HONEYPOT_API_PREFIX}/deploy`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ spec }),
      });
      expect(res.status).toBe(200);
      expect(rig.registry.list().length).toBe(1);
      const auditEntries = (await rig.auditLog.query({ layer: "l2", limit: 100 })).entries;
      expect(auditEntries.some((e) => e.operation === HONEYPOT_AUDIT_OPS.DEPLOYED)).toBe(true);
    } finally {
      await close();
    }
  });

  it("GET /api/honeypot/traps returns the deployed list", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkSpec());
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(`${base}${HONEYPOT_API_PREFIX}/traps`);
      expect(res.status).toBe(200);
      const body = (await res.json()) as { ok: boolean; data: { traps: TrapSpec[] } };
      expect(body.data.traps.length).toBe(1);
    } finally {
      await close();
    }
  });

  it("DELETE /api/honeypot/traps/:id removes + emits undeployed audit op", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkSpec());
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(`${base}${HONEYPOT_API_PREFIX}/traps/trap-1`, {
        method: "DELETE",
      });
      expect(res.status).toBe(200);
      expect(rig.registry.list().length).toBe(0);
      const auditEntries = (await rig.auditLog.query({ layer: "l2", limit: 100 })).entries;
      expect(auditEntries.some((e) => e.operation === HONEYPOT_AUDIT_OPS.UNDEPLOYED)).toBe(true);
    } finally {
      await close();
    }
  });

  it("non-loopback request without auth token returns 401", async () => {
    const rig = await makeRig();
    const server: Server = createServer(async (req, res) => {
      const handled = await handleHoneypotRoute(
        {
          authConfig: { loopbackAutoAuth: false, authToken: "secret" },
          registry: rig.registry,
          findingStore: rig.findingStore,
          auditLog: rig.auditLog,
          operatorId: OPERATOR,
          fortressId: FORTRESS_A,
        },
        req,
        res,
      );
      if (!handled) res.writeHead(404).end();
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const addr = server.address() as AddressInfo;
    try {
      const res = await fetch(`http://127.0.0.1:${addr.port}${HONEYPOT_API_PREFIX}/traps`);
      expect(res.status).toBe(401);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
});

// ── CLI ──────────────────────────────────────────────────────────────────

describe("WP-V1.3-5 Pi-1 CLI subcommands", () => {
  function captureStreams(): { out: { write: (s: string) => boolean; text: string }; err: { write: (s: string) => boolean; text: string } } {
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

  it("compile subcommand emits drafted + compiled audit ops + prints spec", async () => {
    const rig = await makeRig();
    const streams = captureStreams();
    const exit = await runHoneypotCli(
      {
        registry: rig.registry,
        findingStore: rig.findingStore,
        auditLog: rig.auditLog,
        operatorId: OPERATOR,
        fortressId: FORTRESS_A,
      },
      {
        argv: ["compile", "honeypot at /admin/secrets"],
        out: streams.out as unknown as NodeJS.WritableStream,
        err: streams.err as unknown as NodeJS.WritableStream,
      },
    );
    expect(exit).toBe(0);
    expect(streams.out.text).toContain("pattern: /admin/secrets");
    const auditEntries = (await rig.auditLog.query({ layer: "l2", limit: 100 })).entries;
    expect(auditEntries.some((e) => e.operation === HONEYPOT_AUDIT_OPS.DRAFTED)).toBe(true);
    expect(auditEntries.some((e) => e.operation === HONEYPOT_AUDIT_OPS.COMPILED)).toBe(true);
  });

  it("deploy + list + undeploy lifecycle via CLI", async () => {
    const rig = await makeRig();
    const spec = mkSpec();
    const streams = captureStreams();
    const deps = {
      registry: rig.registry,
      findingStore: rig.findingStore,
      auditLog: rig.auditLog,
      operatorId: OPERATOR,
      fortressId: FORTRESS_A,
      resolveSpec: (id: string) => (id === "trap-1" ? spec : undefined),
    };
    const deployExit = await runHoneypotCli(deps, {
      argv: ["deploy", "trap-1"],
      out: streams.out as unknown as NodeJS.WritableStream,
      err: streams.err as unknown as NodeJS.WritableStream,
    });
    expect(deployExit).toBe(0);
    expect(rig.registry.list().length).toBe(1);

    const listExit = await runHoneypotCli(deps, {
      argv: ["list"],
      out: streams.out as unknown as NodeJS.WritableStream,
      err: streams.err as unknown as NodeJS.WritableStream,
    });
    expect(listExit).toBe(0);
    expect(streams.out.text).toContain("trap-1");

    const undeployExit = await runHoneypotCli(deps, {
      argv: ["undeploy", "trap-1"],
      out: streams.out as unknown as NodeJS.WritableStream,
      err: streams.err as unknown as NodeJS.WritableStream,
    });
    expect(undeployExit).toBe(0);
    expect(rig.registry.list().length).toBe(0);
  });

  it("findings subcommand surfaces honeypot-only findings filtered by since", async () => {
    const rig = await makeRig();
    // Seed one honeypot finding + one non-honeypot finding.
    await rig.findingStore.saveFinding({
      finding_id: "f-1",
      sentinel_id: "honeypot:trap-1",
      severity: "alert",
      summary: "test honeypot finding",
      details: {},
      observed_at: new Date().toISOString(),
      evidence_audit_ids: [],
      fortress_id: FORTRESS_A,
    });
    await rig.findingStore.saveFinding({
      finding_id: "f-2",
      sentinel_id: "egress-volume",
      severity: "warn",
      summary: "non-honeypot finding",
      details: {},
      observed_at: new Date().toISOString(),
      evidence_audit_ids: [],
      fortress_id: FORTRESS_A,
    });
    const streams = captureStreams();
    const exit = await runHoneypotCli(
      {
        registry: rig.registry,
        findingStore: rig.findingStore,
        auditLog: rig.auditLog,
        operatorId: OPERATOR,
        fortressId: FORTRESS_A,
      },
      {
        argv: ["findings", "--since=24h"],
        out: streams.out as unknown as NodeJS.WritableStream,
        err: streams.err as unknown as NodeJS.WritableStream,
      },
    );
    expect(exit).toBe(0);
    expect(streams.out.text).toContain("honeypot:trap-1");
    expect(streams.out.text).not.toContain("egress-volume");
  });
});

// ── Multi-fortress isolation ─────────────────────────────────────────────

describe("WP-V1.3-5 Pi-1 multi-fortress isolation", () => {
  it("each fortress's registry + finding store stays scoped to that fortress", async () => {
    const rigA = await makeRig({ fortressId: FORTRESS_A });
    const rigB = await makeRig({ fortressId: FORTRESS_B });
    rigA.registry.deploy(mkSpec());
    expect(rigA.registry.list().length).toBe(1);
    expect(rigB.registry.list().length).toBe(0);

    const { req, res } = makeMockReqRes("GET", "/admin/secrets");
    await handleHoneypotTriggerIfMatch(
      {
        registry: rigA.registry,
        findingStore: rigA.findingStore,
        auditLog: rigA.auditLog,
        operatorId: OPERATOR,
        fortressId: FORTRESS_A,
      },
      req,
      res,
    );
    const findingsA = await rigA.findingStore.listFindings({ limit: 100 });
    const findingsB = await rigB.findingStore.listFindings({ limit: 100 });
    expect(findingsA.length).toBe(1);
    expect(findingsB.length).toBe(0);
  });
});

// ── Helpers ──────────────────────────────────────────────────────────────

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

interface MockReqResCapture {
  statusCode?: number;
  headers?: Record<string, string>;
  body: string;
}

function makeMockReqRes(
  method: string,
  url: string,
): {
  req: IncomingMessage;
  res: ServerResponse;
  capture: MockReqResCapture;
} {
  const socket = new Socket();
  const req = new IncomingMessage(socket);
  req.method = method;
  req.url = url;
  // Push EOF so async iterators terminate.
  req.push(null);
  const capture: MockReqResCapture = { body: "" };
  const res = new ServerResponse(req);
  const originalWriteHead = res.writeHead.bind(res);
  res.writeHead = ((status: number, headers?: Record<string, string>) => {
    capture.statusCode = status;
    if (headers) capture.headers = headers;
    return originalWriteHead(status, headers as never);
  }) as typeof res.writeHead;
  const originalEnd = res.end.bind(res);
  res.end = ((data?: unknown) => {
    if (typeof data === "string") capture.body = data;
    return originalEnd(data as never);
  }) as typeof res.end;
  return { req, res, capture };
}
