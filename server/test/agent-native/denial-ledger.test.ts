/**
 * The denial ledger records why each tool call was refused, operator-side,
 * with bounded state and bounded I/O whatever the caller and the audit log do,
 * and never changes the refusal the agent receives.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  DENIAL_CAUSES,
  DENIAL_LEDGER_MAX_KEYS,
  DENIAL_LEDGER_MAX_PENDING_APPENDS,
  DENIAL_WINDOW_MS,
  DenialLedger,
  LEDGER_CLOSE_DEADLINE_MS,
  type DenialRecorder,
} from "../../src/agent-native/denial-ledger.js";
import { refusalResult, SessionIdentityError, SessionNotBoundError } from "../../src/agent-native/safety-base.js";
import { argumentStageCause, handlerStageCause } from "../../src/tool-outcome.js";
import { OriginUnresolvedError } from "../../src/cognitive/origin-unresolved.js";
import { AuditLog, AuditPersistenceError, type AuditEntryInput } from "../../src/operational/audit-log.js";
import { createServer, toolResult, type ToolDefinition } from "../../src/router.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

const SRC_DIR = fileURLToPath(new URL("../../src/", import.meta.url));
// Live windows: every keyed window plus the one overflow window.
const MAX_LIVE_WINDOWS = DENIAL_LEDGER_MAX_KEYS + 1;

type Behaviour = (entry: AuditEntryInput) => Promise<void>;

/** An audit log stand-in that records every critical append and settles it as told. */
class FakeAuditLog {
  readonly appends: AuditEntryInput[] = [];
  behaviour: Behaviour = async () => undefined;
  appendCritical(entry: AuditEntryInput): Promise<void> {
    this.appends.push(entry);
    return this.behaviour(entry);
  }
  ops(operation: string): AuditEntryInput[] {
    return this.appends.filter((entry) => entry.operation === operation);
  }
}

interface Deferred { promise: Promise<void>; resolve: () => void; reject: (error: unknown) => void }
function deferred(): Deferred {
  let resolve!: () => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<void>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

async function settle(): Promise<void> {
  for (let i = 0; i < 5; i++) await new Promise<void>((resolve) => setImmediate(resolve));
}

function rig() {
  const audit = new FakeAuditLog();
  let now = 1_000_000;
  const warnings: string[] = [];
  const ledger = new DenialLedger(audit as unknown as AuditLog, () => now, { warn: (line) => warnings.push(line) });
  return {
    audit,
    ledger,
    warnings,
    advance: (ms: number) => { now += ms; },
    refuse: (tool: string, cause: (typeof DENIAL_CAUSES)[number] = "gate_denied") =>
      ledger.record(cause, { tool, origin: "agent:ledger-test" }),
  };
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("denial ledger windows", () => {
  it("ten thousand refusals across three hundred tool names in one window attempt at most 257 first rows and hold at most 257 entries; after the clock passes the window, the next record closes every touched entry and attempts one summary for each with more than one refusal", async () => {
    const r = rig();
    for (let i = 0; i < 10_000; i++) r.refuse(`tool_${i % 300}`);
    expect(r.audit.ops("denial_cause")).toHaveLength(MAX_LIVE_WINDOWS);
    const held = r.ledger.snapshot();
    expect(held.open_keyed_windows + (held.overflow_open ? 1 : 0)).toBe(MAX_LIVE_WINDOWS);
    await settle();

    r.advance(DENIAL_WINDOW_MS);
    r.refuse("tool_after_window");
    // Every touched window saw more than one refusal, so each one gets a summary.
    expect(r.audit.ops("denial_cause_summary")).toHaveLength(MAX_LIVE_WINDOWS);
    const summaries = r.audit.ops("denial_cause_summary");
    expect(summaries.reduce((sum, entry) => sum + (entry.details!.attempted as number), 0)).toBe(10_000);
    expect(r.ledger.snapshot().open_keyed_windows).toBe(1);
    expect(r.ledger.snapshot().overflow_open).toBe(false);
  });

  it("a full table of open windows, then the clock passes the window, then one new key: the table holds one open entry and overflow is closed", async () => {
    const r = rig();
    for (let i = 0; i <= DENIAL_LEDGER_MAX_KEYS; i++) r.refuse(`tool_${i}`);
    expect(r.ledger.snapshot().overflow_open).toBe(true);
    await settle();
    r.advance(DENIAL_WINDOW_MS);
    r.refuse("brand_new_tool");
    const snapshot = r.ledger.snapshot();
    expect(snapshot.open_keyed_windows).toBe(1);
    expect(snapshot.overflow_open).toBe(false);
    expect(snapshot.windows.map((window) => window.key)).toEqual(["brand_new_tool"]);
  });

  it("a full table, then only the same overflowed keys keep refusing past the window: the overflow window closes, is summarized, and a new one opens", async () => {
    const r = rig();
    for (let i = 0; i < DENIAL_LEDGER_MAX_KEYS; i++) r.refuse(`tool_${i}`);
    const overflowed = ["late_a", "late_b", "late_c"];
    for (const tool of overflowed) { r.refuse(tool); r.refuse(tool); }
    const overflowGeneration = r.ledger.snapshot().windows.find((window) => window.key === "overflow window")!.generation;
    await settle();

    r.advance(DENIAL_WINDOW_MS);
    for (const tool of overflowed) r.refuse(tool);
    const overflowSummary = r.audit.ops("denial_cause_summary").find((entry) => entry.details!.tool === "overflow");
    expect(overflowSummary?.details).toMatchObject({ attempted: overflowed.length * 2, denial_ref: overflowGeneration.denial_ref });
    // The keyed table emptied with the old window, so each refusing key opens its own new window.
    const snapshot = r.ledger.snapshot();
    expect(snapshot.overflow_open).toBe(false);
    expect(snapshot.windows.map((window) => window.key).sort()).toEqual([...overflowed].sort());
    expect(snapshot.windows.every((window) => window.generation.generation_id > overflowGeneration.generation_id)).toBe(true);
  });

  it("fifty concurrent refusals for one key reserve one window and attempt one row", async () => {
    const r = rig();
    const gate = deferred();
    r.audit.behaviour = () => gate.promise;
    await Promise.all(Array.from({ length: 50 }, async () => { await Promise.resolve(); r.refuse("same_tool"); }));
    expect(r.audit.ops("denial_cause")).toHaveLength(1);
    expect(r.ledger.snapshot().windows).toEqual([expect.objectContaining({ key: "same_tool", attempted: 50 })]);
    gate.resolve();
    await settle();
  });
});

describe("denial ledger append failures", () => {
  it("a rejected first append is not retried inside its window", async () => {
    const r = rig();
    r.audit.behaviour = async () => { throw new AuditPersistenceError("fixture storage full", "storage_full"); };
    for (let i = 0; i < 5; i++) r.refuse("rejecting_tool");
    await settle();
    for (let i = 0; i < 5; i++) r.refuse("rejecting_tool");
    expect(r.audit.ops("denial_cause")).toHaveLength(1);
    expect(r.ledger.snapshot().windows[0]!.generation.first_row).toBe("failed");
    expect(r.warnings).toHaveLength(1);
  });

  it("an append that writes bytes and then throws is recorded unconfirmed and not retried", async () => {
    const r = rig();
    const written: AuditEntryInput[] = [];
    r.audit.behaviour = async (entry) => { written.push(entry); throw new Error("fixture fault after the bytes landed"); };
    r.refuse("torn_tool");
    await settle();
    r.refuse("torn_tool");
    expect(written).toHaveLength(1);
    expect(r.ledger.snapshot().windows[0]!.generation.first_row).toBe("unconfirmed");
    expect(r.warnings).toHaveLength(1);
  });

  it("a first append that settles after the response returned updates only its own generation's record", async () => {
    const r = rig();
    const late = deferred();
    r.audit.behaviour = () => late.promise;
    r.refuse("rolling_tool");
    const first = r.ledger.snapshot().windows[0]!.generation;
    r.audit.behaviour = async () => undefined;
    r.advance(DENIAL_WINDOW_MS);
    r.refuse("rolling_tool");
    const second = r.ledger.snapshot().windows[0]!.generation;
    await settle();
    expect(second.generation_id).not.toBe(first.generation_id);
    expect(second.first_row).toBe("written");
    expect(first.first_row).toBe("pending");
    expect(first.slots_held).toBe(1);

    late.reject(new Error("fixture late fault"));
    await settle();
    expect(first.first_row).toBe("unconfirmed");
    expect(first.slots_held).toBe(0);
    expect(second.first_row).toBe("written");
    expect(r.ledger.snapshot().pending_appends).toBe(0);
  });

  it("repeated reject-then-new-window waves attempt at most one first row per key per window", async () => {
    const r = rig();
    r.audit.behaviour = async () => { throw new AuditPersistenceError("fixture disk failure", "disk_failure"); };
    const keys = ["wave_a", "wave_b", "wave_c"];
    const waves = 5;
    for (let wave = 0; wave < waves; wave++) {
      for (let i = 0; i < 10; i++) for (const key of keys) r.refuse(key);
      await settle();
      r.advance(DENIAL_WINDOW_MS);
    }
    expect(r.audit.ops("denial_cause")).toHaveLength(keys.length * waves);
    expect(r.ledger.snapshot().pending_appends).toBe(0);
  });
});

describe("denial ledger pending-append budget", () => {
  // Shared across the two tests below: the second settles what the first left hanging.
  const r = rig();
  const hung: Deferred[] = [];
  r.audit.behaviour = () => { const d = deferred(); hung.push(d); return d.promise; };

  it("first rows and summaries that never settle, across three clock jumps over 257 keys, leave at most 514 pending appends, and later refusals start no I/O", async () => {
    for (let jump = 0; jump < 3; jump++) {
      for (let i = 0; i < MAX_LIVE_WINDOWS; i++) { r.refuse(`budget_${jump}_${i}`); r.refuse(`budget_${jump}_${i}`); }
      expect(r.ledger.snapshot().pending_appends).toBeLessThanOrEqual(DENIAL_LEDGER_MAX_PENDING_APPENDS);
      r.advance(DENIAL_WINDOW_MS);
    }
    expect(r.ledger.snapshot().pending_appends).toBe(DENIAL_LEDGER_MAX_PENDING_APPENDS);
    const appendsBefore = r.audit.appends.length;
    for (let i = 0; i < 100; i++) r.refuse(`after_budget_${i}`);
    expect(r.audit.appends.length).toBe(appendsBefore);
    expect(r.ledger.snapshot().ledger_budget_exhausted).toBeGreaterThan(0);
    expect(r.ledger.snapshot().windows.every((window) => window.generation.first_row === "skipped_budget")).toBe(true);
  });

  it("then every pending append settles late in reverse order: each updates only its own generation, every slot is released, and the next refusal reserves again", async () => {
    expect(hung).toHaveLength(DENIAL_LEDGER_MAX_PENDING_APPENDS);
    for (const d of [...hung].reverse()) {
      d.resolve();
      await Promise.resolve();
    }
    await settle();
    expect(r.ledger.snapshot().pending_appends).toBe(0);
    const appendsBefore = r.audit.appends.length;
    r.audit.behaviour = async () => undefined;
    r.advance(DENIAL_WINDOW_MS);
    r.refuse("after_release");
    expect(r.audit.appends.length).toBeGreaterThan(appendsBefore);
    expect(r.audit.appends.at(-1)).toMatchObject({ operation: "denial_cause", details: expect.objectContaining({ tool: "after_release" }) });
  });
});

describe("denial ledger close", () => {
  it("close with hung appends returns after the deadline and reports the unsettled count", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const r = rig();
    r.audit.behaviour = () => new Promise<void>(() => undefined);
    r.refuse("hung_a");
    r.refuse("hung_b");
    r.refuse("hung_b");
    let closed = false;
    const closing = r.ledger.close().then(() => { closed = true; });
    await vi.advanceTimersByTimeAsync(LEDGER_CLOSE_DEADLINE_MS - 1);
    expect(closed).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await closing;
    expect(closed).toBe(true);
    // Two first rows plus hung_b's summary, written at close because it saw two refusals.
    expect(r.audit.ops("denial_cause_summary")).toHaveLength(1);
    expect(r.warnings.at(-1)).toContain("3 audit appends unsettled");
  });

  it("a refusal recorded after close is counted and opens no window and no append", async () => {
    const r = rig();
    r.refuse("before_close");
    r.refuse("before_close");
    await r.ledger.close();
    const appendsAtClose = r.audit.appends.length;
    // The first row, and the summary written at close for the window that saw two refusals.
    expect(appendsAtClose).toBe(2);

    r.refuse("after_close_a");
    r.refuse("after_close_b", "handler_error");
    r.advance(DENIAL_WINDOW_MS);
    r.refuse("after_close_a");
    for (let i = 0; i < MAX_LIVE_WINDOWS; i++) r.refuse(`after_close_${i}`);

    expect(r.audit.appends.length).toBe(appendsAtClose);
    const snapshot = r.ledger.snapshot();
    expect(snapshot.windows).toEqual([]);
    expect(snapshot.open_keyed_windows).toBe(0);
    expect(snapshot.overflow_open).toBe(false);
    expect(snapshot.pending_appends).toBe(0);
    expect(snapshot.recorded_after_close).toBe(3 + MAX_LIVE_WINDOWS);
    // A second close finds nothing left to close or wait for.
    await r.ledger.close();
    expect(r.audit.appends.length).toBe(appendsAtClose);
  });
});

// ── Through the router ────────────────────────────────────────────────────

const routerCleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const cleanup of routerCleanups.splice(0).reverse()) await cleanup();
});

async function connect(tools: ToolDefinition[], denialLedger: DenialRecorder): Promise<Client> {
  const server = createServer(tools, { denialLedger });
  const client = new Client({ name: "denial-ledger-router", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  routerCleanups.push(() => client.close());
  return client;
}

function fixtureTool(name: string, body: object): ToolDefinition {
  return {
    name,
    description: name,
    tool_class: "write",
    inputSchema: { type: "object", properties: {} },
    handler: async () => toolResult(body),
  };
}

describe("denial ledger behind the router", () => {
  it("an allowed call never reaches the ledger", async () => {
    const r = rig();
    const record = vi.spyOn(r.ledger, "record");
    const client = await connect([fixtureTool("allowed_tool", { ok: true })], r.ledger);
    const result = await client.callTool({ name: "allowed_tool", arguments: {} });
    expect(result).toEqual(toolResult({ ok: true }));
    expect(record).not.toHaveBeenCalled();
    expect(r.audit.appends).toEqual([]);
  });

  it("the agent envelope is deep-equal to refusalResult() when the ledger's appends all fail, and when the budget is exhausted", async () => {
    const r = rig();
    r.audit.behaviour = async () => { throw new Error("fixture audit outage"); };
    const client = await connect([fixtureTool("refused_tool", { error: "fixture refusal" })], r.ledger);
    expect(await client.callTool({ name: "refused_tool", arguments: {} })).toEqual(refusalResult());
    await settle();
    expect(r.ledger.snapshot().windows[0]!.generation.first_row).toBe("unconfirmed");

    // Fill the budget with appends that never settle, then refuse again in a new window.
    r.audit.behaviour = () => new Promise<void>(() => undefined);
    r.advance(DENIAL_WINDOW_MS);
    // Two refusals in each live window: one hung first row each now, one hung summary each when they close.
    for (let i = 0; i < MAX_LIVE_WINDOWS; i++) { r.refuse(`filler_${i}`); r.refuse(`filler_${i}`); }
    r.advance(DENIAL_WINDOW_MS);
    expect(await client.callTool({ name: "refused_tool", arguments: {} })).toEqual(refusalResult());
    const appendsBefore = r.audit.appends.length;
    expect(await client.callTool({ name: "refused_tool", arguments: {} })).toEqual(refusalResult());
    expect(r.audit.appends.length).toBe(appendsBefore);
    expect(r.ledger.snapshot().pending_appends).toBe(DENIAL_LEDGER_MAX_PENDING_APPENDS);
    expect(r.ledger.snapshot().ledger_budget_exhausted).toBeGreaterThan(0);
  });

  it("a refusing call returns the one refusal while its ledger append to the real audit log is still pending", async () => {
    // Writes are held from the moment `holding` is set until the test releases them.
    class HeldWriteStorage extends MemoryStorage {
      holding = false;
      readonly held: Array<() => void> = [];
      override async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
        if (this.holding) await new Promise<void>((release) => { this.held.push(release); });
        return super.write(namespace, key, data);
      }
    }
    const storage = new HeldWriteStorage();
    const auditLog = new AuditLog(storage, generateRandomKey());
    // Load the chain first, so the refusing call's own stages need no write.
    await auditLog.appendCritical({ layer: "l2", operation: "fixture_warmup", identity_id: "system", result: "success" });
    const ledger = new DenialLedger(auditLog, () => 1_000_000, { warn: () => undefined });
    const server = createServer([fixtureTool("refused_tool", { error: "fixture refusal" })], { auditLog, denialLedger: ledger });
    const client = new Client({ name: "denial-ledger-held-write", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    try {
      storage.holding = true;
      expect(await client.callTool({ name: "refused_tool", arguments: {} })).toEqual(refusalResult());
      // The ledger's row reaches the held write and stays pending after the response returned.
      await vi.waitFor(() => expect(storage.held.length).toBeGreaterThan(0));
      expect(ledger.snapshot().pending_appends).toBe(1);
      expect(ledger.snapshot().windows[0]!.generation.first_row).toBe("pending");
    } finally {
      storage.holding = false;
      for (const release of storage.held.splice(0)) release();
      await auditLog.flush().catch(() => undefined);
      await client.close();
      await server.close();
    }
    expect(ledger.snapshot().windows[0]!.generation.first_row).toBe("written");
  });

  it("a ledger that throws still leaves the same refusal", async () => {
    const throwing: DenialRecorder = { record: () => { throw new Error("fixture ledger fault"); } };
    const client = await connect([fixtureTool("refused_tool", { denied: true })], throwing);
    expect(await client.callTool({ name: "refused_tool", arguments: {} })).toEqual(refusalResult());
  });
});

// ── Structure ─────────────────────────────────────────────────────────────

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return name.endsWith(".ts") ? [path] : [];
  });
}

describe("denial ledger call sites", () => {
  it("every record( call site passes a literal from the closed cause list", () => {
    const causes = new Set<string>(DENIAL_CAUSES);
    const sites: Array<{ file: string; first: string }> = [];
    const ledgerCalls: string[] = [];
    for (const file of sourceFiles(SRC_DIR)) {
      const text = readFileSync(file, "utf8");
      for (const match of text.matchAll(/(?<!function )\brecordDenial\(\s*([^,]+),/g)) {
        sites.push({ file, first: match[1]!.trim() });
      }
      for (const match of text.matchAll(/\bdenialLedger\.record\(\s*([^,]+),/g)) {
        ledgerCalls.push(`${file}: ${match[1]!.trim()}`);
      }
    }
    // The router is the only producer in this tree, and it reaches the ledger
    // through one guarded wrapper whose parameter is typed DenialCause.
    expect(ledgerCalls).toEqual([expect.stringMatching(/router\.ts: cause$/)]);
    expect(sites.length).toBeGreaterThan(0);
    // The router forwards a noted cause at exactly one site, through the closed-list filter.
    const noteSites = sites.filter((site) => !site.first.startsWith('"') &&
      !site.first.startsWith("argumentStageCause(") && !site.first.startsWith("handlerStageCause("));
    expect(noteSites.map((site) => `${site.file.endsWith("/router.ts") ? "router.ts" : site.file}: ${site.first}`))
      .toEqual(["router.ts: closedDenialCause(note.cause)"]);
    for (const site of sites) {
      if (site.first.startsWith("argumentStageCause(") || site.first.startsWith("handlerStageCause(")) continue;
      if (noteSites.includes(site)) continue;
      expect(site.first, site.file).toMatch(/^"[a-z_]+"$/);
      expect(causes.has(site.first.slice(1, -1)), `${site.file}: ${site.first}`).toBe(true);
    }
    // A cause reaches the note slot only through the one typed helper.
    const noteSlotCalls: string[] = [];
    for (const file of sourceFiles(SRC_DIR)) {
      const text = readFileSync(file, "utf8");
      for (const match of text.matchAll(/\bnoteCallScopeCause\(/g)) {
        const before = text.slice(0, match.index);
        const enclosing = [...before.matchAll(/export function (\w+)/g)].at(-1)?.[1] ?? "";
        noteSlotCalls.push(`${file.slice(SRC_DIR.length)}: ${enclosing}`);
      }
    }
    expect(noteSlotCalls.filter((call) => !call.startsWith("operational/audit-log.ts:")))
      .toEqual(["agent-native/denial-ledger.ts: noteRefusalCause"]);
    // The argument-stage and handler-stage helpers return only list literals.
    for (const name of ["argumentStageCause", "handlerStageCause"]) {
      const helper = readFileSync(join(SRC_DIR, "tool-outcome.ts"), "utf8").match(new RegExp(`export function ${name}[\\s\\S]*?\\n}\\n`))![0];
      const returned = [...helper.matchAll(/"([a-z_]+)"/g)].map((match) => match[1]!);
      expect(returned.length, name).toBeGreaterThan(0);
      for (const literal of returned) expect(causes.has(literal), literal).toBe(true);
    }
  });

  it("every cooperative deny( and every noteRefusalCause( site passes a literal from the closed cause list, except the one typed forwarding site inside deny", () => {
    const causes = new Set<string>(DENIAL_CAUSES);
    // The enclosing function of a call site, exported or nested, by the nearest preceding function declaration.
    const enclosingFunction = (text: string, index: number): string =>
      [...text.slice(0, index).matchAll(/\bfunction\s+(\w+)\s*\(/g)].at(-1)?.[1] ?? "";
    // A mention inside a comment line is prose, not a call site.
    const inComment = (text: string, index: number): boolean =>
      /^\s*(\*|\/\/)/.test(text.slice(text.lastIndexOf("\n", index) + 1, index));
    const cooperative = readFileSync(join(SRC_DIR, "agent-native", "cooperative-surface.ts"), "utf8");
    const denySites = [...cooperative.matchAll(/(?<!function )\bdeny\(\s*([^,)]*)/g)]
      .filter((match) => !inComment(cooperative, match.index!))
      .map((match) => match[1]!.trim());
    expect(denySites.length).toBeGreaterThan(0);
    for (const first of denySites) {
      expect(first).toMatch(/^"[a-z_]+"$/);
      expect(causes.has(first.slice(1, -1)), first).toBe(true);
    }
    const forwarding: string[] = [];
    let literalSites = 0;
    for (const file of sourceFiles(SRC_DIR)) {
      const text = readFileSync(file, "utf8");
      for (const match of text.matchAll(/(?<!function )\bnoteRefusalCause\(\s*([^,)]*)/g)) {
        if (inComment(text, match.index!)) continue;
        const first = match[1]!.trim();
        if (/^"[a-z_]+"$/.test(first)) {
          expect(causes.has(first.slice(1, -1)), `${file}: ${first}`).toBe(true);
          literalSites += 1;
          continue;
        }
        forwarding.push(`${file.slice(SRC_DIR.length)}: ${enclosingFunction(text, match.index!)}(${first})`);
      }
    }
    expect(literalSites).toBeGreaterThan(0);
    expect(forwarding).toEqual(["agent-native/cooperative-surface.ts: deny(cause)"]);
  });

  it("the handler stage records an unresolved origin as its own cause and every other handler error as handler_error", () => {
    expect(handlerStageCause(new OriginUnresolvedError())).toBe("origin_unresolved");
    expect(handlerStageCause(new Error("write origin could not be determined"))).toBe("handler_error");
  });

  it("the argument stage still records a session with no identity as session_not_bound", () => {
    expect(argumentStageCause(new SessionNotBoundError())).toBe("session_not_bound");
    expect(argumentStageCause(new SessionIdentityError())).toBe("pre_gate_argument_refused");
  });
});
