/**
 * Tool outcome classification: every registered tool has a declared success
 * shape, the strict rule accepts only a verdict-free JSON object, custom shapes
 * still reject a verdict, and proxied tools are judged by origin.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const probe = vi.hoisted(() => ({
  registered: [] as string[][],
  dropShape: undefined as string | undefined,
}));

vi.mock("../src/router.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/router.js")>();
  return {
    ...actual,
    createServer: (tools: Parameters<typeof actual.createServer>[0], options: Parameters<typeof actual.createServer>[1]) => {
      probe.registered.push(tools.map((tool) => tool.name));
      return actual.createServer(tools, options);
    },
  };
});

vi.mock("../src/tool-outcome.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/tool-outcome.js")>();
  return {
    ...actual,
    // The real check, run against the real registry minus one entry when a test asks.
    assertToolOutcomesRegistered: (tools: readonly { readonly name: string }[]) => {
      if (probe.dropShape === undefined) return actual.assertToolOutcomesRegistered(tools);
      const shapes = { ...actual.TOOL_OUTCOME_SHAPES };
      delete shapes[probe.dropShape];
      return actual.assertToolOutcomesRegistered(tools, shapes);
    },
  };
});

import { createSanctuaryServer } from "../src/index.js";
import { MemoryStorage } from "../src/storage/memory.js";
import {
  classifyToolOutcome,
  markProxiedTool,
  recordProxiedOutcome,
  TOOL_OUTCOME_SHAPES,
} from "../src/tool-outcome.js";
import { createTempHome, TEST_PASSPHRASE } from "./helpers/temp-fortress.js";

function text(value: string) {
  return { content: [{ type: "text", text: value }] };
}
function json(value: unknown) {
  return text(JSON.stringify(value, null, 2));
}

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  probe.dropShape = undefined;
  probe.registered.length = 0;
  const errors: unknown[] = [];
  for (const cleanup of cleanups.splice(0).reverse()) {
    try { await cleanup(); } catch (error) { errors.push(error); }
  }
  if (errors.length > 0) throw errors[0];
});

async function bootRecordingTools(): Promise<string[]> {
  const home = await createTempHome("sanctuary-tool-outcome");
  cleanups.push(() => home.cleanup());
  const booted = await createSanctuaryServer({ storage: new MemoryStorage(), passphrase: TEST_PASSPHRASE });
  cleanups.push(() => booted.cleanup());
  expect(probe.registered).toHaveLength(1);
  return probe.registered[0]!;
}

describe("tool outcome registry", () => {
  it("the registry covers exactly the registered tools", async () => {
    // The default boot registers every built-in tool: no factory is
    // configuration-dependent, and proxied tools are classified by origin.
    const registered = await bootRecordingTools();
    expect(new Set(Object.keys(TOOL_OUTCOME_SHAPES))).toEqual(new Set(registered));
    expect(registered).toHaveLength(new Set(registered).size);
  }, 60_000);

  it("a server with an unregistered tool refuses to start", async () => {
    const home = await createTempHome("sanctuary-tool-outcome-refuse");
    cleanups.push(() => home.cleanup());
    probe.dropShape = "manifest";
    await expect(
      createSanctuaryServer({ storage: new MemoryStorage(), passphrase: TEST_PASSPHRASE }),
    ).rejects.toThrow(/missing an outcome shape.*\bmanifest\b/);
    expect(probe.registered).toHaveLength(0);
  }, 60_000);

  const customEntries = Object.entries(TOOL_OUTCOME_SHAPES).filter(([, shape]) => shape !== "standard");

  it("lists the custom shapes this tree declares", () => {
    expect(Object.fromEntries(customEntries)).toEqual({
      audit_export_siem: "siem_export",
      handshake_exchange: "handshake_preview",
      sanctuary_distress: "distress_signal",
      "sanctuary/sign_erc8004_identity": "erc8004_signing",
      sovereignty_audit: "sovereignty_report",
    });
  });

  it.each(customEntries)("each custom predicate rejects a result carrying a policy or ownership verdict (%s)", (name) => {
    const denial = JSON.stringify({ denied: true, message: "x" });
    const failure = JSON.stringify({ error: "not yours" });
    const partial = JSON.stringify({ status: "partial_failed" });
    for (const body of [denial, failure, partial]) {
      expect(classifyToolOutcome(name, text(body))).toBe("refusal");
      expect(classifyToolOutcome(name, { content: [{ type: "text", text: body }, { type: "text", text: body }] })).toBe("refusal");
    }
    expect(classifyToolOutcome(name, { content: [{ type: "text", text: "{}" }, { type: "text", text: "{}" }], isError: true })).toBe("refusal");
  });

  it("accepts each custom tool's own success layout", () => {
    expect(classifyToolOutcome("audit_export_siem", {
      content: [{ type: "text", text: JSON.stringify({ format: "cef", count: 0 }) }, { type: "text", text: "" }],
    })).toBe("success");
    expect(classifyToolOutcome("sovereignty_audit", {
      content: [{ type: "text", text: "Sovereignty report" }, { type: "text", text: JSON.stringify({ overall_score: 1 }) }],
    })).toBe("success");
    expect(classifyToolOutcome("handshake_exchange", json({
      attestation: {}, verification: { counterparty_valid: false, recorded: false, errors: ["bad signature"] },
    }))).toBe("success");
    expect(classifyToolOutcome("sanctuary_distress", json({ ok: true, event_id: "distress:1" }))).toBe("success");
    for (const status of ["pending_approval", "signed"]) {
      expect(classifyToolOutcome("sanctuary/sign_erc8004_identity", json({ request_id: "r", status }))).toBe("success");
    }
  });

  it("refuses each verdict a custom shape names, and only that verdict", () => {
    expect(classifyToolOutcome("handshake_exchange", json({
      attestation: {}, verification: { recorded: false, record_error: "refused" },
    }))).toBe("refusal");
    expect(classifyToolOutcome("sanctuary_distress", json({ ok: false, rate_limited: true }))).toBe("refusal");
    expect(classifyToolOutcome("sanctuary/sign_erc8004_identity", json({ request_id: "r", status: "denied", reason: "x" }))).toBe("refusal");
    // The same fields on a strict-rule tool are not verdicts it reports.
    expect(classifyToolOutcome("state_read", json({ verification: { record_error: "x" }, ok: false }))).toBe("success");
  });
});

describe("standard rule", () => {
  const cases: Array<[string, unknown, "success" | "refusal"]> = [
    ["isError: true", { ...json({ ok: true }), isError: true }, "refusal"],
    ["zero items", { content: [] }, "refusal"],
    ["two items", { content: [{ type: "text", text: "{}" }, { type: "text", text: "{}" }] }, "refusal"],
    ["a non-text item", { content: [{ type: "image", data: "", mimeType: "image/png" }] }, "refusal"],
    ["non-JSON text", text("plain words"), "refusal"],
    ["a JSON array", json([1, 2]), "refusal"],
    ["an error body", json({ error: "anything" }), "refusal"],
    ["a denial body", json({ denied: true }), "refusal"],
    ["a partial failure body", json({ status: "partial_failed" }), "refusal"],
    ["no result object", undefined, "refusal"],
    ["an ordinary success", json({ ok: true, items: [] }), "success"],
  ];
  it.each(cases)("%s", (_label, result, expected) => {
    expect(classifyToolOutcome("state_read", result)).toBe(expected);
  });

  it("a tool absent from the registry is held to the strict rule", () => {
    expect(classifyToolOutcome("fixture_only_tool", json({ ok: true }))).toBe("success");
    expect(classifyToolOutcome("fixture_only_tool", text("not json"))).toBe("refusal");
  });
});

describe("proxied origin", () => {
  it("a proxied tool is classified by origin, not by name", () => {
    const unmarked = { name: "proxy/x/y" };
    expect(classifyToolOutcome("proxy/x/y", json({ ok: true }), unmarked)).toBe("success");
    expect(classifyToolOutcome("proxy/x/y", json({ error: "e" }), unmarked)).toBe("refusal");

    const marked = markProxiedTool({ name: "any_name" });
    const upstreamBody = recordProxiedOutcome(json({ error: "upstream data" }), { upstream_failed: false, proxy_refusal: false });
    expect(classifyToolOutcome("any_name", upstreamBody, marked)).toBe("success");
    const failed = recordProxiedOutcome(json({ ok: true }), { upstream_failed: true, proxy_refusal: false });
    expect(classifyToolOutcome("any_name", failed, marked)).toBe("refusal");
    const refused = recordProxiedOutcome(json({ ok: true }), { upstream_failed: false, proxy_refusal: true });
    expect(classifyToolOutcome("any_name", refused, marked)).toBe("refusal");
  });

  it("a proxied result with no origin fact is a refusal", () => {
    const marked = markProxiedTool({ name: "proxy/s/t" });
    expect(classifyToolOutcome("proxy/s/t", json({ ok: true }), marked)).toBe("refusal");
  });
});

describe("denied-status tripwire", () => {
  const SERVER_ROOT = join(fileURLToPath(import.meta.url), "..", "..");
  // A source line that can put status: "denied" into an object or a status type.
  const DENIED_STATUS = /\bstatus\??\s*:\s*[^;=\n]*"denied"/;
  // Lanes outside the MCP router (their outcomes travel on the Hermes wire), and
  // the classifier itself, which names the verdict it refuses.
  const OUT_OF_SCOPE = new Set(["src/hermes-memory-bridge", "src/hermes-memory-client", "src/tool-outcome.ts"]);

  // Every source file that can produce a denied status, and how it reaches an
  // agent. Built from this tree's inventory: a new producer fails the first test
  // until it is placed here, and a producer reaching a registered tool's body
  // must name that tool. A tripwire over source text, not a reachability proof.
  const PRODUCERS: Record<string, { readonly tools: readonly string[] } | { readonly unreached: string }> = {
    "src/key-17/erc8004-tools.ts": { tools: ["sanctuary/sign_erc8004_identity"] },
    "src/castle-wall/observe/promote.ts": { unreached: "operator CLI promotion outcome; no MCP tool returns it" },
    "src/coordination/context-transfer.ts": { unreached: "hub and CLI context transfer; no MCP tool returns it" },
    "src/coordination/coordinator.ts": { unreached: "hub task coordinator; no MCP tool returns it" },
    "src/operational/privacy-core.ts": { unreached: "proxy privacy decision; proxied results are judged by their origin fact" },
    "src/cognitive/tools.ts": { unreached: "the status of a signed internal receipt payload, inside the signed bytes" },
  };

  function sourceFiles(dir: string): string[] {
    const files: string[] = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      const rel = relative(SERVER_ROOT, path).split("\\").join("/");
      if (OUT_OF_SCOPE.has(rel)) continue;
      if (entry.isDirectory()) files.push(...sourceFiles(path));
      else if (entry.name.endsWith(".ts")) files.push(rel);
    }
    return files;
  }

  it("lists every source file that can produce a denied status", () => {
    const producers = sourceFiles(join(SERVER_ROOT, "src"))
      .filter((rel) => DENIED_STATUS.test(readFileSync(join(SERVER_ROOT, rel), "utf8")));
    expect(new Set(producers)).toEqual(new Set(Object.keys(PRODUCERS)));
  });

  it("every registered tool whose body can carry a denied status refuses it", () => {
    const reached = Object.values(PRODUCERS).flatMap((entry) => ("tools" in entry ? entry.tools : []));
    expect(reached.length).toBeGreaterThan(0);
    for (const name of reached) {
      expect(Object.hasOwn(TOOL_OUTCOME_SHAPES, name)).toBe(true);
      expect(TOOL_OUTCOME_SHAPES[name]).not.toBe("standard");
      expect(classifyToolOutcome(name, json({ request_id: "r", status: "denied", reason: "x" }))).toBe("refusal");
    }
  });
});
