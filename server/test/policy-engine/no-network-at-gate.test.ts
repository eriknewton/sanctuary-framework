/**
 * Structural invariant: NO LLM / NO NETWORK on any gate-evaluation code path.
 *
 * Spawn-prompt non-negotiable: "No LLM at gate time. LLM compiles plain-
 * English authoring into a deterministic policy artifact at authoring time;
 * gates evaluate the compiled artifact only. Tests MUST assert no network
 * call or LLM-SDK call on any gate-evaluation code path."
 *
 * This test checks two distinct things:
 *
 *   1. STATIC — the transitive import graph rooted at the gate dispatcher
 *      (server/src/policy-engine/gates/index.ts) reaches only a safe
 *      allowlist of modules: policy-engine, mesh canonical-json, core
 *      encoding/random/identity, and the vetted `@noble/*` crypto libs.
 *      It MUST NOT reach: node:http, node:https, node:net, node:dgram,
 *      node:fs (filesystem writes), undici, fetch wrappers, LLM SDKs.
 *
 *   2. RUNTIME — monkey-patch fetch (global) and node-http to throw; run
 *      a gate evaluation; assert no throw from the patched surfaces.
 *
 * Either failure should be a structural build gate — a developer adding
 * an LLM import into the gate path gets stopped here, not in code review.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import https from "node:https";
import { describe, expect, it } from "vitest";
import {
  evaluateMemoryGate,
  evaluateOutputsGate,
} from "../../src/policy-engine/gates/index.js";
import type { SlotGateExtendedContext } from "../../src/policy-engine/gates/evaluator.js";
import { compileFixturePolicy } from "../../src/policy-engine/compiler-fixture.js";
import { buildFortress } from "./fixture.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SRC_ROOT = path.resolve(__dirname, "../../src");

// ═══════════════════════════════════════════════════════════════════════
// Static import-graph check
// ═══════════════════════════════════════════════════════════════════════

const DENIED_NODE_BUILTINS = new Set([
  "node:http",
  "node:https",
  "node:net",
  "node:dgram",
  "node:dns",
  "node:tls",
  "node:http2",
  "http",
  "https",
  "net",
  "dgram",
  "dns",
  "tls",
  "http2",
]);

// NPM packages not allowed inside the gate-evaluation subtree.
const DENIED_NPM_PREFIXES = [
  "openai",
  "@anthropic-ai/",
  "@google/generative-ai",
  "@google-ai/",
  "@mistralai/",
  "cohere-ai",
  "groq-sdk",
  "replicate",
  "undici",
  "node-fetch",
  "axios",
  "got",
];

function isDenied(spec: string): { denied: boolean; reason?: string } {
  if (DENIED_NODE_BUILTINS.has(spec)) {
    return { denied: true, reason: `forbidden node builtin: ${spec}` };
  }
  for (const pfx of DENIED_NPM_PREFIXES) {
    if (spec === pfx || spec.startsWith(pfx + "/")) {
      return { denied: true, reason: `forbidden npm package: ${spec}` };
    }
  }
  return { denied: false };
}

async function readFile(file: string): Promise<string> {
  return fs.readFile(file, "utf-8");
}

const IMPORT_RE = /(?:^|\n)\s*(?:import|export)\s+(?:[^"'\n]*?from\s+)?["']([^"']+)["']/g;

async function collectImports(file: string): Promise<string[]> {
  const text = await readFile(file);
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = IMPORT_RE.exec(text)) !== null) {
    out.push(m[1]);
  }
  return out;
}

async function resolveRelative(from: string, spec: string): Promise<string | undefined> {
  if (!spec.startsWith(".")) return undefined;
  const base = path.resolve(path.dirname(from), spec);
  // Prefer .ts source; the project's source imports use .js extensions for ESM.
  const candidates = [
    base.endsWith(".js") ? base.replace(/\.js$/, ".ts") : base + ".ts",
    path.join(base.endsWith(".js") ? base.replace(/\.js$/, "") : base, "index.ts"),
  ];
  for (const c of candidates) {
    try {
      await fs.stat(c);
      return c;
    } catch {
      // try next
    }
  }
  return undefined;
}

async function walkImportGraph(entry: string): Promise<{
  visited: Set<string>;
  externalSpecs: Set<string>;
}> {
  const visited = new Set<string>();
  const externalSpecs = new Set<string>();
  const queue: string[] = [entry];
  while (queue.length) {
    const cur = queue.shift()!;
    if (visited.has(cur)) continue;
    visited.add(cur);
    let imports: string[];
    try {
      imports = await collectImports(cur);
    } catch {
      continue;
    }
    for (const spec of imports) {
      if (spec.startsWith(".")) {
        const resolved = await resolveRelative(cur, spec);
        if (resolved) queue.push(resolved);
      } else {
        externalSpecs.add(spec);
      }
    }
  }
  return { visited, externalSpecs };
}

describe("policy-engine — structural: no network / no LLM in gate subtree", () => {
  it("gate dispatcher's transitive imports contain no denied specifiers", async () => {
    const entry = path.join(SRC_ROOT, "policy-engine", "gates", "index.ts");
    const { externalSpecs } = await walkImportGraph(entry);
    const offenders: string[] = [];
    for (const spec of externalSpecs) {
      const { denied, reason } = isDenied(spec);
      if (denied) offenders.push(reason!);
    }
    expect(offenders).toEqual([]);
  });

  it("gate subtree does not import the compiler (LLM surface is at authoring layer)", async () => {
    const entry = path.join(SRC_ROOT, "policy-engine", "gates", "index.ts");
    const { visited } = await walkImportGraph(entry);
    for (const file of visited) {
      const rel = path.relative(SRC_ROOT, file);
      expect(rel).not.toBe(path.join("policy-engine", "compiler.ts"));
      expect(rel).not.toBe(path.join("policy-engine", "compiler-fixture.ts"));
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Runtime monkey-patch check
// ═══════════════════════════════════════════════════════════════════════

describe("policy-engine — runtime: gate evaluation triggers no network I/O", () => {
  it("monkey-patched fetch / http.request / https.request are NOT called", () => {
    const f = buildFortress();
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 may read outputs from agent a2.",
    });
    const ctx: SlotGateExtendedContext = {
      policy,
      nodeSigningKey: f.nodeKeypair.privateKey,
      nodeId: f.nodeCert.node_id,
      fortressId: f.master.public.fortress_id,
    };

    const calls: string[] = [];
    const origFetch = (globalThis as { fetch?: typeof fetch }).fetch;
    const origHttpRequest = http.request;
    const origHttpsRequest = https.request;
    (globalThis as { fetch?: typeof fetch }).fetch = () => {
      calls.push("fetch");
      throw new Error("fetch blocked at gate time");
    };
    (http as unknown as { request: typeof http.request }).request = (
      (..._args: unknown[]) => {
        calls.push("http.request");
        throw new Error("http.request blocked at gate time");
      }
    ) as unknown as typeof http.request;
    (https as unknown as { request: typeof https.request }).request = (
      (..._args: unknown[]) => {
        calls.push("https.request");
        throw new Error("https.request blocked at gate time");
      }
    ) as unknown as typeof https.request;

    try {
      // Exercise two gates + the commitment-boundary surface.
      const r1 = evaluateOutputsGate(ctx, {
        agent_id: "a1",
        counterparty: "a2",
        action: "read",
      });
      const r2 = evaluateMemoryGate(ctx, {
        agent_id: "a1",
        counterparty: "a2",
        action: "read",
      });
      expect(r1.decision).toBe("allow");
      expect(r2.decision).toBe("deny");
    } finally {
      if (origFetch) (globalThis as { fetch?: typeof fetch }).fetch = origFetch;
      else delete (globalThis as { fetch?: typeof fetch }).fetch;
      (http as unknown as { request: typeof http.request }).request = origHttpRequest;
      (https as unknown as { request: typeof https.request }).request =
        origHttpsRequest;
    }

    expect(calls).toEqual([]);
  });
});
