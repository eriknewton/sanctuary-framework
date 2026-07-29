/**
 * WP-V1.3-6 Xi-1 English-Authored Policy Compiler regression suite.
 *
 * Coverage:
 *   - Deterministic compile path for common English shapes (4 tests
 *     across tier1 add, tier3 add, tier1 remove, tier2 set).
 *   - Ambiguous English -> low-confidence draft + warnings (2 tests).
 *   - LLM-assist fallback: schema validation success / malformed JSON
 *     / substrate failure (3 tests via mocked selector).
 *   - HTTP routes: POST /compile + GET /drafts + GET /drafts/:id +
 *     404 on unknown draft + 400 on missing english_text (5 tests).
 *   - CLI: compile subcommand prints structured output; help works (2
 *     tests).
 *   - Audit emission: DRAFTED + COMPILED + COMPILE_FAILED counts (3
 *     tests).
 *   - Multi-fortress isolation (1 test).
 *   - Castle-walking: no NEW outbound audit ops fire on a compile path
 *     (selector is the only outbound channel; not invoked in this
 *     test rig).
 *
 * Castle-walking note: the substrate selector itself is mocked in
 * these tests; the real selector wraps fetch with the Rho-1 Tier A
 * header strip, which is verified by Rho-1's own regression suite.
 * Xi-1 inherits that property by routing through the selector.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { Writable } from "node:stream";

import {
  AuditLog,
  type AuditEntry,
} from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { createTempFortress } from "../helpers/temp-fortress.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  EnglishPolicyCompiler,
  ENGLISH_POLICY_AUDIT_OPS,
  compileDeterministic,
  parseLlmOutput,
  computeDraftId,
} from "../../src/policy-engine/english-policy-compiler.js";
import {
  ENGLISH_POLICY_API_PREFIX,
  EnglishPolicyDraftStore,
  handleEnglishPolicyRoute,
} from "../../src/policy-engine/english-policy-routes.js";
import { runPolicyCommand } from "../../src/cli/policy.js";
import type { SubstrateSelector } from "../../src/intelligence/selector.js";

const FORTRESS_A = "fortress_a";
const FORTRESS_B = "fortress_b";
const OPERATOR = "operator_alpha";
const OBSERVED_AT = "2026-05-09T12:00:00.000Z";

function makeRig(opts?: {
  fortressId?: string;
  selector?: SubstrateSelector | null;
}): {
  auditLog: AuditLog;
  compiler: EnglishPolicyCompiler;
  store: EnglishPolicyDraftStore;
} {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const compiler = new EnglishPolicyCompiler({
    auditLog,
    fortressId: opts?.fortressId ?? FORTRESS_A,
    selector: opts?.selector ?? null,
  });
  const store = new EnglishPolicyDraftStore();
  return { auditLog, compiler, store };
}

async function auditOps(auditLog: AuditLog): Promise<string[]> {
  const result = await auditLog.query({ layer: "l2", limit: 200 });
  return result.entries.map((e: AuditEntry) => e.operation);
}

async function makeServer(
  compiler: EnglishPolicyCompiler,
  store: EnglishPolicyDraftStore,
): Promise<{ base: string; close: () => Promise<void> }> {
  const server: Server = createServer(async (req, res) => {
    const handled = await handleEnglishPolicyRoute(
      {
        authConfig: { loopbackAutoAuth: true },
        compiler,
        store,
      },
      req,
      res,
    );
    if (!handled) {
      res.writeHead(404).end();
    }
  });
  await new Promise<void>((resolve) =>
    server.listen(0, "127.0.0.1", resolve),
  );
  const addr = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${addr.port}`,
    close: () =>
      new Promise<void>((resolve) =>
        server.close(() => resolve()),
      ),
  };
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

// ── Deterministic compile path ──────────────────────────────────────

describe("Xi-1 — deterministic compile path", () => {
  it('compiles "always require approval for state_export" -> tier1_add_operation high', () => {
    const r = compileDeterministic("always require approval for state_export");
    expect(r).not.toBeNull();
    expect(r!.rule.kind).toBe("tier1_add_operation");
    expect(r!.rule.operation).toBe("state_export");
    expect(r!.confidence).toBe("high");
  });

  it('compiles "auto-allow state_read" -> tier3_add_operation high', () => {
    const r = compileDeterministic("auto-allow state_read");
    expect(r!.rule.kind).toBe("tier3_add_operation");
    expect(r!.rule.operation).toBe("state_read");
  });

  it('compiles "stop requiring approval for state_export" -> tier1_remove_operation high', () => {
    const r = compileDeterministic(
      "stop requiring approval for state_export",
    );
    expect(r!.rule.kind).toBe("tier1_remove_operation");
    expect(r!.rule.operation).toBe("state_export");
  });

  it('compiles "set anomaly frequency multiplier to 5" -> tier2_set_field with numeric value', () => {
    const r = compileDeterministic("set anomaly frequency multiplier to 5");
    expect(r!.rule.kind).toBe("tier2_set_field");
    expect(r!.rule.tier2_update!.field).toBe("frequency_spike_multiplier");
    expect(r!.rule.tier2_update!.value).toBe(5);
  });
});

// ── Ambiguous English -> low confidence ─────────────────────────────

describe("Xi-1 — ambiguous English -> low confidence drafts", () => {
  it("empty text returns a low-confidence draft with an empty-input warning", async () => {
    const { compiler } = makeRig();
    const draft = await compiler.compile({
      english_text: "",
      observed_at: OBSERVED_AT,
      operator_id: OPERATOR,
    });
    expect(draft.compile_confidence).toBe("low");
    expect(draft.compile_warnings).toContain("empty input");
  });

  it("oversized text (>2000 chars) returns low confidence + size warning", async () => {
    const { compiler } = makeRig();
    const text = "x".repeat(2100);
    const draft = await compiler.compile({
      english_text: text,
      observed_at: OBSERVED_AT,
      operator_id: OPERATOR,
    });
    expect(draft.compile_confidence).toBe("low");
    expect(draft.compile_warnings[0]).toContain("exceeds");
  });

  it("unrecognized phrase without LLM-assist returns low confidence + 'no deterministic match'", async () => {
    const { compiler } = makeRig({ selector: null });
    const draft = await compiler.compile({
      english_text:
        "do something interesting with credentials sometimes if vibes",
      observed_at: OBSERVED_AT,
      operator_id: OPERATOR,
    });
    expect(draft.compile_confidence).toBe("low");
    expect(draft.compile_warnings).toContain("no deterministic match");
    expect(draft.compile_warnings).toContain("LLM-assist disabled");
  });
});

// ── LLM-assist fallback path ────────────────────────────────────────

describe("Xi-1 — LLM-assist fallback", () => {
  function stubSelector(text: string, opts?: {
    failureClass?: string;
    servedBy?: string;
  }): SubstrateSelector {
    return {
      async invokeSummarize(_surface: string, _req: unknown) {
        if (opts?.failureClass) {
          return {
            servedBy: (opts.servedBy ?? "local") as never,
            failureClass: opts.failureClass as never,
            body: { kind: "failure" as const, message: "stub failure" },
            completedAt: OBSERVED_AT,
            latencyMs: 12,
          };
        }
        return {
          servedBy: (opts?.servedBy ?? "local") as never,
          failureClass: null,
          body: { kind: "summarize" as const, text },
          completedAt: OBSERVED_AT,
          latencyMs: 12,
        };
      },
    } as unknown as SubstrateSelector;
  }

  it("structured LLM JSON output produces a medium/high confidence compiled rule", async () => {
    const llmJson = JSON.stringify({
      rule: {
        kind: "tier1_add_operation",
        operation: "delete_user",
      },
      explanation:
        "Adds delete_user to Tier 1; every call requires approval.",
      confidence: "high",
      warnings: [],
    });
    const selector = stubSelector(llmJson);
    const { compiler } = makeRig({ selector });
    const draft = await compiler.compile({
      english_text:
        "i want every delete_user call to need a human signoff",
      observed_at: OBSERVED_AT,
      operator_id: OPERATOR,
    });
    expect(draft.compile_confidence).toBe("high");
    expect(draft.compiled_rule.kind).toBe("tier1_add_operation");
    expect(draft.compiled_rule.operation).toBe("delete_user");
    expect(draft.substrate_used).toBe("local");
  });

  it("malformed LLM JSON returns low confidence + schema validation warning", async () => {
    const selector = stubSelector("not json at all");
    const { compiler } = makeRig({ selector });
    const draft = await compiler.compile({
      english_text: "the substrate misbehaves",
      observed_at: OBSERVED_AT,
      operator_id: OPERATOR,
    });
    expect(draft.compile_confidence).toBe("low");
    expect(
      draft.compile_warnings.some((w) =>
        w.startsWith("schema validation failed"),
      ),
    ).toBe(true);
  });

  it("substrate failure_class returns low confidence + substrate-failure warning", async () => {
    const selector = stubSelector("", {
      failureClass: "substrate_unavailable",
    });
    const { compiler } = makeRig({ selector });
    const draft = await compiler.compile({
      english_text: "the substrate is down",
      observed_at: OBSERVED_AT,
      operator_id: OPERATOR,
    });
    expect(draft.compile_confidence).toBe("low");
    expect(
      draft.compile_warnings.some((w) => w.includes("substrate failure")),
    ).toBe(true);
  });
});

// ── parseLlmOutput pure helper coverage ─────────────────────────────

describe("Xi-1 — parseLlmOutput helper", () => {
  it("strips Markdown code-fence wrappers around JSON output", () => {
    const fenced = "```json\n{\"rule\":{\"kind\":\"tier1_add_operation\",\"operation\":\"x\"},\"explanation\":\"adds x\",\"confidence\":\"high\",\"warnings\":[]}\n```";
    const r = parseLlmOutput(fenced);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.rule.operation).toBe("x");
  });

  it("rejects missing operation on tier1_add_operation", () => {
    const json = JSON.stringify({
      rule: { kind: "tier1_add_operation" },
      explanation: "x",
    });
    const r = parseLlmOutput(json);
    expect(r.ok).toBe(false);
  });
});

// ── HTTP routes ─────────────────────────────────────────────────────

describe("Xi-1 — HTTP routes", () => {
  it("POST /api/policy/compile returns a CompiledPolicy and writes to the store", async () => {
    const { compiler, store } = makeRig();
    const { base, close } = await makeServer(compiler, store);
    try {
      const res = await fetch(`${base}${ENGLISH_POLICY_API_PREFIX}/compile`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          english_text: "always require approval for state_export",
        }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        data: {
          draft: {
            draft_id: string;
            compile_confidence: string;
            compiled_rule: { kind: string; operation: string };
          };
        };
      };
      expect(body.data.draft.compile_confidence).toBe("high");
      expect(body.data.draft.compiled_rule.operation).toBe("state_export");
      expect(store.size()).toBe(1);
    } finally {
      await close();
    }
  });

  it("GET /api/policy/drafts lists persisted drafts", async () => {
    const { compiler, store } = makeRig();
    await compiler
      .compile({
        english_text: "auto-allow state_read",
        observed_at: OBSERVED_AT,
        operator_id: OPERATOR,
      })
      .then((c) => store.put(c));
    const { base, close } = await makeServer(compiler, store);
    try {
      const res = await fetch(`${base}${ENGLISH_POLICY_API_PREFIX}/drafts`);
      const body = (await res.json()) as {
        data: { drafts: Array<{ english_text: string }> };
      };
      expect(body.data.drafts.length).toBe(1);
      expect(body.data.drafts[0]!.english_text).toBe("auto-allow state_read");
    } finally {
      await close();
    }
  });

  it("GET /api/policy/drafts/:id returns the draft; unknown id -> 404", async () => {
    const { compiler, store } = makeRig();
    const compiled = await compiler.compile({
      english_text: "auto-allow state_read",
      observed_at: OBSERVED_AT,
      operator_id: OPERATOR,
    });
    store.put(compiled);
    const { base, close } = await makeServer(compiler, store);
    try {
      const ok = await fetch(
        `${base}${ENGLISH_POLICY_API_PREFIX}/drafts/${compiled.draft_id}`,
      );
      expect(ok.status).toBe(200);
      const notFound = await fetch(
        `${base}${ENGLISH_POLICY_API_PREFIX}/drafts/no-such-id`,
      );
      expect(notFound.status).toBe(404);
    } finally {
      await close();
    }
  });

  it("POST /api/policy/compile without english_text returns 400", async () => {
    const { compiler, store } = makeRig();
    const { base, close } = await makeServer(compiler, store);
    try {
      const res = await fetch(`${base}${ENGLISH_POLICY_API_PREFIX}/compile`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(400);
    } finally {
      await close();
    }
  });
});

// ── CLI subcommands ─────────────────────────────────────────────────

describe("Xi-1 — CLI subcommands", () => {
  // Each CLI invocation gets its own fortress. `policy compile` resolves a
  // storage path to look for an intelligence substrate; without this it
  // resolved the operator's own `~/.sanctuary` and read real state.
  let fortress: Awaited<ReturnType<typeof createTempFortress>>;
  beforeEach(async () => {
    fortress = await createTempFortress("sanctuary-policy-cli");
  });
  afterEach(async () => {
    await fortress.cleanup();
  });

  it("policy compile produces a structured output containing the compiled rule", async () => {
    const out = new CollectStream();
    const err = new CollectStream();
    const code = await runPolicyCommand({
      argv: ["compile", "always require approval for state_export"],
      out,
      err,
      storagePath: fortress.storagePath,
    });
    expect(code).toBe(0);
    expect(out.text).toContain("tier1_add_operation");
    expect(out.text).toContain("state_export");
    expect(out.text).toContain("compile_confidence: high");
  });

  it("policy compile without arg surfaces the usage hint", async () => {
    const out = new CollectStream();
    const err = new CollectStream();
    const code = await runPolicyCommand({
      argv: ["compile"],
      out,
      err,
    });
    expect(code).toBe(2);
    expect(err.text).toContain("compile requires the English text");
  });

  it("no-substrate compile surfaces clearer LLM-assist message (BBBBB)", async () => {
    // Without SANCTUARY_PASSPHRASE, the CLI falls back to deterministic-only.
    // Non-deterministic English should produce a low-confidence result with
    // the improved message naming the bootstrap command.
    const savedPassphrase = process.env["SANCTUARY_PASSPHRASE"];
    delete process.env["SANCTUARY_PASSPHRASE"];
    try {
      const out = new CollectStream();
      const err = new CollectStream();
      const code = await runPolicyCommand({
        argv: ["compile", "whenever the agent seems confused, pause and ask me"],
        out,
        err,
        storagePath: fortress.storagePath,
      });
      expect(code).toBe(0);
      // Output should contain low confidence (no deterministic match, no LLM)
      expect(out.text).toContain("compile_confidence: low");
      // Stderr should contain the improved message and point to the REAL
      // config path (the dashboard picker / env vars), not the removed
      // `sanctuary intelligence configure` subcommand.
      expect(err.text).toContain("intelligence substrate");
      expect(err.text).toContain("Intelligence picker");
      expect(err.text).toContain("OLLAMA_HOST");
      expect(err.text).not.toContain("sanctuary intelligence configure");
    } finally {
      if (savedPassphrase !== undefined) {
        process.env["SANCTUARY_PASSPHRASE"] = savedPassphrase;
      }
    }
  });

  it("deterministic templates still return high confidence without substrate (BBBBB regression)", async () => {
    // Templates that match deterministically must continue to work without
    // LLM-assist. This is the regression guard: wiring LLM-assist must
    // not break the existing template path.
    const out = new CollectStream();
    const err = new CollectStream();
    const code = await runPolicyCommand({
      argv: ["compile", "always require approval for state_export"],
      out,
      err,
      storagePath: fortress.storagePath,
    });
    expect(code).toBe(0);
    expect(out.text).toContain("compile_confidence: high");
    expect(out.text).toContain("tier1_add_operation");
    expect(out.text).toContain("state_export");
    // No LLM-assist message for deterministic matches
    expect(err.text).not.toContain("intelligence substrate");
  });
});

// ── Audit emission ──────────────────────────────────────────────────

describe("Xi-1 — audit emission + multi-fortress isolation", () => {
  it("DRAFTED + COMPILED both fire on a high-confidence compile", async () => {
    const { compiler, auditLog } = makeRig();
    await compiler.compile({
      english_text: "always require approval for state_export",
      observed_at: OBSERVED_AT,
      operator_id: OPERATOR,
    });
    const ops = await auditOps(auditLog);
    expect(ops).toContain(ENGLISH_POLICY_AUDIT_OPS.DRAFTED);
    expect(ops).toContain(ENGLISH_POLICY_AUDIT_OPS.COMPILED);
    expect(ops).not.toContain(ENGLISH_POLICY_AUDIT_OPS.COMPILE_FAILED);
  });

  it("COMPILE_FAILED fires on substrate-selector failure during LLM-assist path", async () => {
    const selector: SubstrateSelector = {
      async invokeSummarize() {
        return {
          servedBy: "local" as never,
          failureClass: "substrate_unavailable" as never,
          body: { kind: "failure" as const, message: "no" },
          completedAt: OBSERVED_AT,
          latencyMs: 1,
        };
      },
    } as unknown as SubstrateSelector;
    const { compiler, auditLog } = makeRig({ selector });
    await compiler.compile({
      english_text: "this triggers the LLM fallback",
      observed_at: OBSERVED_AT,
      operator_id: OPERATOR,
    });
    const ops = await auditOps(auditLog);
    expect(ops).toContain(ENGLISH_POLICY_AUDIT_OPS.COMPILE_FAILED);
  });

  it("Castle-walking: deterministic compile path emits no outbound audit ops", async () => {
    const { compiler, auditLog } = makeRig();
    await compiler.compile({
      english_text: "auto-allow state_read",
      observed_at: OBSERVED_AT,
      operator_id: OPERATOR,
    });
    const ops = new Set(await auditOps(auditLog));
    expect([...ops].some((o) => o.startsWith("proxy_call:"))).toBe(false);
    expect(ops.has("query_anonymity_headers_stripped")).toBe(false);
    expect(ops.has("intelligence_substrate_invoked")).toBe(false);
  });

  it("multi-fortress isolation: same English compiled by two fortresses produces same draft_id but different fortress stamps", async () => {
    const draft = {
      english_text: "auto-allow state_read",
      observed_at: OBSERVED_AT,
      operator_id: OPERATOR,
    };
    const { compiler: a } = makeRig({ fortressId: FORTRESS_A });
    const { compiler: b } = makeRig({ fortressId: FORTRESS_B });
    const aOut = await a.compile(draft);
    const bOut = await b.compile(draft);
    expect(aOut.draft_id).toBe(bOut.draft_id);
    expect(aOut.draft_id).toBe(computeDraftId(draft));
    expect(aOut.fortress_id).toBe(FORTRESS_A);
    expect(bOut.fortress_id).toBe(FORTRESS_B);
  });
});
