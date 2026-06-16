/**
 * Sanctuary v1.3 WP-V1.3-5 Pi-2 Honeypot regression suite.
 *
 * Covers Pi-2's deferred-from-Pi-1 items:
 *  (a) filesystem trap class:
 *      - compiler Path A (LLM) returns trap_class="filesystem" with
 *        ops, parser produces a FilesystemTrigger
 *      - compiler Path A rejects invalid ops -> heuristic fallback
 *      - heuristic detects filesystem class from English signals
 *      - heuristic narrows ops from operation verbs in English
 *      - heuristic defaults ops to all four when no verb hint
 *      - HTTP class still the default when no filesystem signal (Pi-1
 *        back-compat)
 *      - FilesystemTrapMonitor.observe fires finding + audit on match
 *      - ops filter excludes operations not in the trap's set
 *      - HTTP-class traps in the same registry are ignored on
 *        filesystem observe (cross-class isolation)
 *      - best-effort persistence: a finding-store failure does not
 *        throw to the caller (mirrors Pi-1's HTTP-runtime contract)
 *      - payload_hash optional; absent hash omitted from finding
 *      - multi-fortress isolation: per-fortress monitor + finding
 *        store stays scoped
 *
 *  (b) fortress-config persistence (TrapStore):
 *      - save + loadAll round-trip preserves the spec exactly
 *      - delete removes the persisted record
 *      - loadAll returns specs sorted by compiled_at ascending so the
 *        in-memory registry insertion order matches the original
 *        deploy order
 *      - multi-fortress encryption isolation: fortress A cannot decode
 *        fortress B's records
 *      - corrupted record (malformed JSON envelope) silently skipped;
 *        sibling specs still rehydrate
 *      - AAD mismatch (trap_id in payload differs from the key it was
 *        stored under) treated as corrupted and skipped
 *      - management deploy route persists to the store when wired
 *      - management undeploy route deletes from the store when wired
 *
 *  (c) boot reload scenario (end-to-end): save -> fresh registry +
 *      store -> loadAll -> deploy each -> matching observation fires
 *      finding through the new registry; this proves the boot path
 *      restores trap dispatch from cold start.
 */

import { afterEach, describe, expect, it } from "vitest";
import { IncomingMessage, ServerResponse, createServer, type Server } from "node:http";
import { Socket } from "node:net";
import type { AddressInfo } from "node:net";

import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { SentinelFindingStore } from "../../src/sentinel/sentinel-finding-store.js";
import { stringToBytes } from "../../src/core/encoding.js";

import { TrapRegistry } from "../../src/honeypot/trap-registry.js";
import { TrapStore, TRAP_STORE_NAMESPACE } from "../../src/honeypot/trap-store.js";
import { FilesystemTrapMonitor } from "../../src/honeypot/filesystem-trap-monitor.js";
import { compileHoneypot } from "../../src/honeypot/honeypot-compiler.js";
import {
  HONEYPOT_API_PREFIX,
  handleHoneypotRoute,
} from "../../src/honeypot/runtime-trap-handler.js";
import {
  HONEYPOT_AUDIT_OPS,
  HONEYPOT_SENTINEL_ID_PREFIX,
  type FilesystemOp,
  type TrapSpec,
} from "../../src/honeypot/types.js";

const FORTRESS_A = "fortress_a";
const FORTRESS_B = "fortress_b";
const OPERATOR = "operator_pi2";

interface Rig {
  storage: MemoryStorage;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  findingStore: SentinelFindingStore;
  registry: TrapRegistry;
  store: TrapStore;
  fortressId: string;
}

async function makeRig(opts?: { fortressId?: string }): Promise<Rig> {
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
  const store = new TrapStore({ storage, masterKey, fortressId });
  return {
    storage,
    masterKey,
    auditLog,
    findingStore,
    registry,
    store,
    fortressId,
  };
}

function mkFsSpec(overrides: Partial<TrapSpec> = {}): TrapSpec {
  const ops: FilesystemOp[] = (overrides.trigger?.kind === "filesystem"
    ? overrides.trigger.ops
    : undefined) ?? ["read", "write", "delete", "list"];
  return {
    trap_id: overrides.trap_id ?? "fs-trap-1",
    trap_class: "filesystem",
    trigger: overrides.trigger ?? {
      kind: "filesystem",
      path_pattern: "/etc/secrets",
      ops,
      expected_caller_types: ["wrapped_agent"],
    },
    finding_severity: overrides.finding_severity ?? "alert",
    english_text:
      overrides.english_text ?? "filesystem honeypot at /etc/secrets",
    explanation_paragraph: overrides.explanation_paragraph ?? "test fixture",
    compiled_at: overrides.compiled_at ?? new Date().toISOString(),
  };
}

function mkHttpSpec(overrides: Partial<TrapSpec> = {}): TrapSpec {
  return {
    trap_id: overrides.trap_id ?? "http-trap-1",
    trap_class: "http_endpoint",
    trigger: overrides.trigger ?? {
      kind: "http_endpoint",
      path_pattern: "/admin/secrets",
      expected_caller_types: ["wrapped_agent"],
    },
    finding_severity: overrides.finding_severity ?? "alert",
    english_text: overrides.english_text ?? "honeypot at /admin/secrets",
    explanation_paragraph: overrides.explanation_paragraph ?? "test fixture",
    compiled_at: overrides.compiled_at ?? new Date().toISOString(),
  };
}

// ── Compiler: filesystem class ───────────────────────────────────────────

describe("WP-V1.3-5 Pi-2 honeypot compiler: filesystem class", () => {
  it("LLM Path A: parses trap_class=filesystem with ops -> FilesystemTrigger", async () => {
    const selector = makeStubSelector({
      capability: { summarize: true, classify: false, redact: false },
      summarize: async () => ({
        body: {
          kind: "summarize",
          text: JSON.stringify({
            trap_class: "filesystem",
            path_pattern: "/var/run/secrets/**",
            ops: ["read", "list"],
            expected_caller_types: ["wrapped_agent"],
            finding_severity: "alert",
            explanation_paragraph:
              "Trap any read/list of mounted-secret paths.",
          }),
        },
      }),
    });
    const result = await compileHoneypot(
      {
        english_text: "trap any read or list of /var/run/secrets/**",
        operator_id: OPERATOR,
        observed_at: new Date().toISOString(),
      },
      { selector },
    );
    expect(result.source).toBe("llm");
    expect(result.spec.trap_class).toBe("filesystem");
    expect(result.spec.trigger.kind).toBe("filesystem");
    if (result.spec.trigger.kind === "filesystem") {
      expect(result.spec.trigger.ops).toEqual(["read", "list"]);
      expect(result.spec.trigger.path_pattern).toBe("/var/run/secrets/**");
    }
  });

  it("LLM Path A: invalid ops -> heuristic fallback with warning", async () => {
    const selector = makeStubSelector({
      capability: { summarize: true, classify: false, redact: false },
      summarize: async () => ({
        body: {
          kind: "summarize",
          text: JSON.stringify({
            trap_class: "filesystem",
            path_pattern: "/etc/secrets",
            ops: ["read", "chmod"],
            expected_caller_types: ["wrapped_agent"],
            finding_severity: "alert",
            explanation_paragraph: "bad ops",
          }),
        },
      }),
    });
    const result = await compileHoneypot(
      {
        english_text: "filesystem honeypot at /etc/secrets",
        operator_id: OPERATOR,
        observed_at: new Date().toISOString(),
      },
      { selector },
    );
    expect(result.source).toBe("heuristic");
    expect(
      result.warnings.some((w) => /invalid_filesystem_ops/.test(w)),
    ).toBe(true);
    // Heuristic should still pick up the filesystem signal.
    expect(result.spec.trap_class).toBe("filesystem");
  });

  it("LLM Path A: omitted ops defaults to all four operations", async () => {
    const selector = makeStubSelector({
      capability: { summarize: true, classify: false, redact: false },
      summarize: async () => ({
        body: {
          kind: "summarize",
          text: JSON.stringify({
            trap_class: "filesystem",
            path_pattern: "/etc/secrets",
            expected_caller_types: ["wrapped_agent"],
            finding_severity: "alert",
            explanation_paragraph: "watch everything",
          }),
        },
      }),
    });
    const result = await compileHoneypot(
      {
        english_text: "filesystem honeypot at /etc/secrets",
        operator_id: OPERATOR,
        observed_at: new Date().toISOString(),
      },
      { selector },
    );
    expect(result.source).toBe("llm");
    if (result.spec.trigger.kind === "filesystem") {
      expect(result.spec.trigger.ops.sort()).toEqual([
        "delete",
        "list",
        "read",
        "write",
      ]);
    }
  });

  it("heuristic Path B: detects filesystem class from English signal", async () => {
    const result = await compileHoneypot({
      english_text: "filesystem honeypot at /etc/secrets",
      operator_id: OPERATOR,
      observed_at: new Date().toISOString(),
    });
    expect(result.source).toBe("heuristic");
    expect(result.spec.trap_class).toBe("filesystem");
    expect(result.spec.trigger.kind).toBe("filesystem");
    if (result.spec.trigger.kind === "filesystem") {
      expect(result.spec.trigger.path_pattern).toBe("/etc/secrets");
    }
  });

  it("heuristic Path B: narrows ops from English verbs", async () => {
    const result = await compileHoneypot({
      english_text: "filesystem trap for file reads on /etc/secrets",
      operator_id: OPERATOR,
      observed_at: new Date().toISOString(),
    });
    if (result.spec.trigger.kind === "filesystem") {
      expect(result.spec.trigger.ops).toContain("read");
      expect(result.spec.trigger.ops).not.toContain("write");
      expect(result.spec.trigger.ops).not.toContain("delete");
    }
  });

  it("heuristic Path B: defaults ops to all four when no verb hint", async () => {
    const result = await compileHoneypot({
      english_text: "filesystem honeypot at /etc/secrets",
      operator_id: OPERATOR,
      observed_at: new Date().toISOString(),
    });
    if (result.spec.trigger.kind === "filesystem") {
      expect(result.spec.trigger.ops.sort()).toEqual([
        "delete",
        "list",
        "read",
        "write",
      ]);
    }
  });

  it("heuristic Path B: no filesystem signal -> http_endpoint default (Pi-1 back-compat)", async () => {
    const result = await compileHoneypot({
      english_text: "honeypot at /admin/secrets",
      operator_id: OPERATOR,
      observed_at: new Date().toISOString(),
    });
    expect(result.spec.trap_class).toBe("http_endpoint");
    expect(result.spec.trigger.kind).toBe("http_endpoint");
  });
});

// ── Filesystem trap monitor ──────────────────────────────────────────────

describe("WP-V1.3-5 Pi-2 filesystem trap monitor", () => {
  it("observe with matching operation fires finding + audit event", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkFsSpec());
    const monitor = new FilesystemTrapMonitor({
      registry: rig.registry,
      findingStore: rig.findingStore,
      auditLog: rig.auditLog,
      operatorId: OPERATOR,
      fortressId: rig.fortressId,
    });
    const result = await monitor.observe({
      operation: "read",
      path: "/etc/secrets",
      caller_identity: "agent:test",
      payload_hash: "deadbeef",
    });
    expect(result.triggered.length).toBe(1);
    expect(result.findings.length).toBe(1);
    expect(result.findings[0]!.severity).toBe("alert");
    expect(result.findings[0]!.sentinel_id).toBe(
      `${HONEYPOT_SENTINEL_ID_PREFIX}fs-trap-1`,
    );
    const persisted = await rig.findingStore.listFindings({ limit: 100 });
    expect(persisted.length).toBe(1);
    const auditEntries = (
      await rig.auditLog.query({ layer: "l2", limit: 100 })
    ).entries;
    const trigger = auditEntries.find(
      (e) => e.operation === HONEYPOT_AUDIT_OPS.TRIGGERED,
    );
    expect(trigger).toBeDefined();
    const details = trigger!.details as Record<string, unknown>;
    expect(details["path_matched"]).toBe("/etc/secrets");
    expect(details["operation"]).toBe("read");
    expect(details["payload_hash"]).toBe("deadbeef");
  });

  it("operation NOT in trap's ops set does not fire", async () => {
    const rig = await makeRig();
    rig.registry.deploy(
      mkFsSpec({
        trigger: {
          kind: "filesystem",
          path_pattern: "/etc/secrets",
          ops: ["write", "delete"],
          expected_caller_types: ["wrapped_agent"],
        },
      }),
    );
    const monitor = new FilesystemTrapMonitor({
      registry: rig.registry,
      findingStore: rig.findingStore,
      auditLog: rig.auditLog,
      operatorId: OPERATOR,
      fortressId: rig.fortressId,
    });
    const result = await monitor.observe({
      operation: "read",
      path: "/etc/secrets",
      caller_identity: "agent:test",
    });
    expect(result.triggered.length).toBe(0);
    expect(result.findings.length).toBe(0);
    expect(
      (await rig.findingStore.listFindings({ limit: 100 })).length,
    ).toBe(0);
  });

  it("HTTP-class traps in the same registry do NOT fire on filesystem observe", async () => {
    const rig = await makeRig();
    rig.registry.deploy(
      mkHttpSpec({ trap_id: "http-1", trigger: { kind: "http_endpoint", path_pattern: "/etc/secrets", expected_caller_types: ["wrapped_agent"] } }),
    );
    rig.registry.deploy(
      mkFsSpec({ trap_id: "fs-1", trigger: { kind: "filesystem", path_pattern: "/etc/secrets", ops: ["read"], expected_caller_types: ["wrapped_agent"] } }),
    );
    const monitor = new FilesystemTrapMonitor({
      registry: rig.registry,
      findingStore: rig.findingStore,
      auditLog: rig.auditLog,
      operatorId: OPERATOR,
      fortressId: rig.fortressId,
    });
    const result = await monitor.observe({
      operation: "read",
      path: "/etc/secrets",
      caller_identity: "agent:test",
    });
    expect(result.triggered.length).toBe(1);
    expect(result.triggered[0]!.trap_id).toBe("fs-1");
  });

  it("payload_hash optional: absent hash omitted from finding details", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkFsSpec());
    const monitor = new FilesystemTrapMonitor({
      registry: rig.registry,
      findingStore: rig.findingStore,
      auditLog: rig.auditLog,
      operatorId: OPERATOR,
      fortressId: rig.fortressId,
    });
    const result = await monitor.observe({
      operation: "read",
      path: "/etc/secrets",
      caller_identity: "agent:test",
    });
    expect(result.findings.length).toBe(1);
    const details = result.findings[0]!.details as Record<string, unknown>;
    expect("payload_hash" in details).toBe(false);
  });

  it("finding-store failure does not throw to the caller (best-effort)", async () => {
    const rig = await makeRig();
    rig.registry.deploy(mkFsSpec());
    // Sabotage the finding store so saveFinding rejects.
    const sabotaged = {
      saveFinding: () => Promise.reject(new Error("disk full")),
      listFindings: () => Promise.resolve([]),
    } as unknown as SentinelFindingStore;
    const monitor = new FilesystemTrapMonitor({
      registry: rig.registry,
      findingStore: sabotaged,
      auditLog: rig.auditLog,
      operatorId: OPERATOR,
      fortressId: rig.fortressId,
    });
    const result = await monitor.observe({
      operation: "read",
      path: "/etc/secrets",
      caller_identity: "agent:test",
    });
    // Trap still recognized + audit still emitted; finding persist
    // was best-effort.
    expect(result.triggered.length).toBe(1);
    const auditEntries = (
      await rig.auditLog.query({ layer: "l2", limit: 100 })
    ).entries;
    expect(
      auditEntries.some((e) => e.operation === HONEYPOT_AUDIT_OPS.TRIGGERED),
    ).toBe(true);
  });

  it("multi-fortress isolation: per-fortress monitor stays scoped", async () => {
    const rigA = await makeRig({ fortressId: FORTRESS_A });
    const rigB = await makeRig({ fortressId: FORTRESS_B });
    rigA.registry.deploy(mkFsSpec());
    const monitorA = new FilesystemTrapMonitor({
      registry: rigA.registry,
      findingStore: rigA.findingStore,
      auditLog: rigA.auditLog,
      operatorId: OPERATOR,
      fortressId: FORTRESS_A,
    });
    await monitorA.observe({
      operation: "read",
      path: "/etc/secrets",
      caller_identity: "agent:test",
    });
    const findingsA = await rigA.findingStore.listFindings({ limit: 100 });
    const findingsB = await rigB.findingStore.listFindings({ limit: 100 });
    expect(findingsA.length).toBe(1);
    expect(findingsB.length).toBe(0);
  });
});

// ── TrapStore: encrypted at-rest persistence ─────────────────────────────

describe("WP-V1.3-5 Pi-2 trap store persistence", () => {
  it("save + loadAll round-trip preserves the spec byte-for-byte", async () => {
    const rig = await makeRig();
    const spec = mkFsSpec({
      trap_id: "fs-roundtrip",
      trigger: {
        kind: "filesystem",
        path_pattern: "/secrets/**",
        ops: ["read", "write"],
        expected_caller_types: ["wrapped_agent", "operator"],
      },
    });
    await rig.store.save(spec);
    const loaded = await rig.store.loadAll();
    expect(loaded.length).toBe(1);
    expect(loaded[0]).toEqual(spec);
  });

  it("delete removes the persisted record (idempotent)", async () => {
    const rig = await makeRig();
    const spec = mkFsSpec({ trap_id: "fs-delete" });
    await rig.store.save(spec);
    expect(await rig.store.delete("fs-delete")).toBe(true);
    expect(await rig.store.delete("fs-delete")).toBe(false);
    expect((await rig.store.loadAll()).length).toBe(0);
  });

  it("loadAll returns specs sorted by compiled_at ascending", async () => {
    const rig = await makeRig();
    const specOld = mkFsSpec({
      trap_id: "fs-old",
      compiled_at: "2026-01-01T00:00:00.000Z",
    });
    const specNew = mkFsSpec({
      trap_id: "fs-new",
      compiled_at: "2026-03-01T00:00:00.000Z",
    });
    const specMid = mkFsSpec({
      trap_id: "fs-mid",
      compiled_at: "2026-02-01T00:00:00.000Z",
    });
    // Save in reverse-chronological order; loadAll should reorder.
    await rig.store.save(specNew);
    await rig.store.save(specOld);
    await rig.store.save(specMid);
    const loaded = await rig.store.loadAll();
    expect(loaded.map((s) => s.trap_id)).toEqual([
      "fs-old",
      "fs-mid",
      "fs-new",
    ]);
  });

  it("multi-fortress encryption isolation: fortress A cannot decode fortress B's records", async () => {
    const sharedStorage = new MemoryStorage();
    const masterKeyA = generateRandomKey();
    const masterKeyB = generateRandomKey();
    const storeA = new TrapStore({
      storage: sharedStorage,
      masterKey: masterKeyA,
      fortressId: FORTRESS_A,
    });
    const storeB = new TrapStore({
      storage: sharedStorage,
      masterKey: masterKeyB,
      fortressId: FORTRESS_B,
    });
    const specA = mkFsSpec({ trap_id: "fs-a" });
    await storeA.save(specA);
    // Fortress B sees the same storage namespace but cannot decrypt the
    // record (different HKDF subkey from its own master key); loadAll
    // silently drops the unreadable entry.
    const loadedB = await storeB.loadAll();
    expect(loadedB.length).toBe(0);
    // Sanity: store A still reads its own record.
    const loadedA = await storeA.loadAll();
    expect(loadedA.length).toBe(1);
    expect(loadedA[0]!.trap_id).toBe("fs-a");
  });

  it("corrupted record silently skipped; sibling specs still rehydrate", async () => {
    const rig = await makeRig();
    const good = mkFsSpec({ trap_id: "fs-good" });
    await rig.store.save(good);
    // Inject a corrupted entry under the same namespace.
    await rig.storage.write(
      TRAP_STORE_NAMESPACE,
      "trap.fs-bad",
      stringToBytes("not encrypted json"),
    );
    const loaded = await rig.store.loadAll();
    expect(loaded.length).toBe(1);
    expect(loaded[0]!.trap_id).toBe("fs-good");
  });

  it("AAD mismatch (trap_id in payload differs from storage key) drops the record", async () => {
    const rig = await makeRig();
    // Save a spec under one trap_id, then write a copy of the cipher
    // under a different key. The decode path checks that the recovered
    // payload's trap_id matches the storage key; mismatch -> dropped.
    const specOriginal = mkFsSpec({ trap_id: "fs-original" });
    await rig.store.save(specOriginal);
    const original = await rig.storage.read(
      TRAP_STORE_NAMESPACE,
      "trap.fs-original",
    );
    expect(original).toBeDefined();
    // Copy the same ciphertext to a different key. The HKDF subkey will
    // still decrypt (same master key + same info string + same AAD
    // bound to "fs-original"), but the recovered trap_id will not match
    // the new storage key. decode() returns null and the record is
    // silently dropped.
    //
    // Actually, the AAD is the storage-key-derived trap_id, not the
    // payload's trap_id, so decryption itself will fail (the new AAD
    // is "fs-impostor" against ciphertext bound to "fs-original").
    // Either failure mode is acceptable; both result in the record
    // being dropped from loadAll.
    await rig.storage.write(
      TRAP_STORE_NAMESPACE,
      "trap.fs-impostor",
      original!,
    );
    const loaded = await rig.store.loadAll();
    // Only the original record should appear; the impostor either
    // fails AAD verification (decrypt throws) or fails the trap_id
    // self-check; in both cases it's dropped.
    expect(loaded.map((s) => s.trap_id).sort()).toEqual(["fs-original"]);
  });
});

// ── Management routes: deploy/undeploy persistence ───────────────────────

describe("WP-V1.3-5 Pi-2 management routes: persistence", () => {
  const closers: Array<() => Promise<void>> = [];
  afterEach(async () => {
    for (const close of closers.splice(0)) await close();
  });

  async function bootServer(rig: Rig): Promise<{ base: string }> {
    const server: Server = createServer(async (req, res) => {
      const handled = await handleHoneypotRoute(
        {
          authConfig: { loopbackAutoAuth: true },
          registry: rig.registry,
          findingStore: rig.findingStore,
          auditLog: rig.auditLog,
          operatorId: OPERATOR,
          fortressId: rig.fortressId,
          store: rig.store,
        },
        req,
        res,
      );
      if (!handled) res.writeHead(404).end();
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const addr = server.address() as AddressInfo;
    closers.push(
      () => new Promise<void>((r) => server.close(() => r())),
    );
    return { base: `http://127.0.0.1:${addr.port}` };
  }

  it("POST /api/honeypot/deploy persists the spec to the store", async () => {
    const rig = await makeRig();
    const { base } = await bootServer(rig);
    const spec = mkFsSpec({ trap_id: "fs-deploy-persist" });
    const res = await fetch(`${base}${HONEYPOT_API_PREFIX}/deploy`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ spec }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { trap_id: string; was_new: boolean; persisted?: boolean };
    };
    expect(body.ok).toBe(true);
    expect(body.data.persisted).toBe(true);
    const persisted = await rig.store.loadAll();
    expect(persisted.length).toBe(1);
    expect(persisted[0]!.trap_id).toBe("fs-deploy-persist");
  });

  it("DELETE /api/honeypot/traps/:id removes the persisted record", async () => {
    const rig = await makeRig();
    const { base } = await bootServer(rig);
    const spec = mkFsSpec({ trap_id: "fs-undeploy" });
    // Pre-populate via the store directly + the registry (mimics a
    // boot-loaded trap).
    await rig.store.save(spec);
    rig.registry.deploy(spec);
    const res = await fetch(
      `${base}${HONEYPOT_API_PREFIX}/traps/fs-undeploy`,
      { method: "DELETE" },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { removed: boolean; persisted?: boolean };
    };
    expect(body.data.removed).toBe(true);
    expect(body.data.persisted).toBe(true);
    expect((await rig.store.loadAll()).length).toBe(0);
  });
});

// ── Boot reload scenario (end-to-end) ────────────────────────────────────

describe("WP-V1.3-5 Pi-2 boot reload scenario", () => {
  it("save + fresh registry/store + loadAll + deploy -> matching observation fires", async () => {
    // Phase 1: simulate a running fortress that deploys a filesystem
    // trap. Persistence is the only state that survives across the
    // boot boundary.
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const storeFirst = new TrapStore({
      storage,
      masterKey,
      fortressId: FORTRESS_A,
    });
    const specs: TrapSpec[] = [
      mkFsSpec({
        trap_id: "fs-secrets",
        trigger: {
          kind: "filesystem",
          path_pattern: "/etc/secrets",
          ops: ["read"],
          expected_caller_types: ["wrapped_agent"],
        },
      }),
      mkFsSpec({
        trap_id: "fs-keys",
        trigger: {
          kind: "filesystem",
          path_pattern: "/var/keys/**",
          ops: ["read", "write"],
          expected_caller_types: ["wrapped_agent"],
        },
        compiled_at: new Date(Date.now() + 1000).toISOString(),
      }),
    ];
    for (const spec of specs) await storeFirst.save(spec);

    // Phase 2: simulate a fortress boot. Fresh in-memory state; only
    // the encrypted at-rest namespace and the master key persist.
    const auditLog = new AuditLog(storage, masterKey);
    const findingStore = new SentinelFindingStore({
      storage,
      masterKey,
      fortressId: FORTRESS_A,
    });
    const registry = new TrapRegistry();
    const storeBoot = new TrapStore({
      storage,
      masterKey,
      fortressId: FORTRESS_A,
    });
    const loaded = await storeBoot.loadAll();
    expect(loaded.map((s) => s.trap_id)).toEqual(["fs-secrets", "fs-keys"]);
    for (const spec of loaded) registry.deploy(spec);

    // Phase 3: a matching observation against the rehydrated registry
    // fires through the monitor end-to-end.
    const monitor = new FilesystemTrapMonitor({
      registry,
      findingStore,
      auditLog,
      operatorId: OPERATOR,
      fortressId: FORTRESS_A,
    });
    const result = await monitor.observe({
      operation: "read",
      path: "/var/keys/agent.key",
      caller_identity: "agent:rebooted",
    });
    expect(result.triggered.length).toBe(1);
    expect(result.triggered[0]!.trap_id).toBe("fs-keys");
    const findings = await findingStore.listFindings({ limit: 100 });
    expect(findings.length).toBe(1);
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

// Silence unused-var warnings on imports used only in helpers.
const _ServerResponse = ServerResponse;
const _IncomingMessage = IncomingMessage;
const _Socket = Socket;
void _ServerResponse;
void _IncomingMessage;
void _Socket;
