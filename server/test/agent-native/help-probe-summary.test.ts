// fail-before-exempt: live probe-key generation imports the new classifier module; cadence and unbound assertions are witnessed with the cooperative surface restored to base and the classifier retained.
/** Help probe summaries retain bounded state and reserve audit rows synchronously. */
import { afterEach, describe, expect, it, vi } from "vitest";
import * as surface from "../../src/agent-native/cooperative-surface.js";
import { classifyIntent, HELP_NEEDLES, HELP_INTENT_MAX_CHARS, HELP_MAX_VARIANTS } from "../../src/agent-native/intent-classifier.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog, AUDIT_NAMESPACE, AUDIT_CHECKPOINT_NAMESPACE } from "../../src/operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { fingerprintIdentityId, type SessionBinding } from "../../src/agent-native/safety-base.js";

// A minute contains sixty thousand milliseconds, the audit summary interval.
const interval = surface.HELP_PROBE_ROW_INTERVAL_MS ?? 60_000;
// The next power of two above the closed set of thirty-nine probe keys.
const cap = surface.HELP_PROBE_MAX_KEYS ?? 64;
const OPERATION = "sanctuary_help_probe_summary";
afterEach(() => vi.restoreAllMocks());
function setup(storage = new MemoryStorage(), checkpointInterval?: number) {
  const key = generateRandomKey();
  const auditLog = new AuditLog(storage, key, { checkpointInterval });
  let binding: SessionBinding | undefined;
  let now = 0;
  const setOrigin = (identityId?: string) => {
    binding = identityId === undefined ? undefined : {
      identity_id: identityId, requester_identity_fingerprint: fingerprintIdentityId(identityId),
    };
  };
  setOrigin("origin-one");
  const { tools, identityManager, namespaceRegistry } = createL1Tools(new StateStore(storage, key), storage, key, "recovery-key", auditLog);
  const help = surface.createAgentNativeCooperativeTools({ identityManager, namespaceRegistry, auditLog,
    primitiveTools: tools, currentSessionBinding: () => binding, now: () => now,
  }).tools.find(tool => tool.name === "sanctuary_help")!;
  const call = async (intent: string) => JSON.parse((await help.handler({ intent })).content[0]!.text);
  // Three origins worth of rows cover eviction and both interval rounds.
  const rows = async () => (await auditLog.query({ operation_type: OPERATION, limit: cap * 3 })).entries;
  return { auditLog, call, rows, setOrigin, advance: (ms: number) => { now += ms; } };
}
const probeIntents = [...HELP_NEEDLES, "東京", "hmm", "save and hmm", "read and save", "x".repeat(HELP_INTENT_MAX_CHARS + 1),
  Array.from({ length: HELP_MAX_VARIANTS + 1 }, (_, i) => `%61${i}x`).join(" ")];
const uniqueIntents = [...new Map(probeIntents.map(intent => [classifyIntent(intent).probe_key, intent])).values()];

describe("help probe summaries", () => {
  it("bounds one thousand distinct probe intents to one row per key per minute", async () => {
    const env = setup();
    const keys = new Set<string | undefined>();
    // One thousand variations exercise retained state beyond the closed probe-key set.
    for (let i = 0; i < 1000; i += 1) {
      const intent = `${probeIntents[i % probeIntents.length]} z${i}`;
      keys.add(classifyIntent(intent).probe_key);
      await env.call(intent);
    }
    expect(keys.size).toBeLessThanOrEqual(cap);
    expect(await env.rows()).toHaveLength(keys.size);
    for (const row of await env.rows()) expect(row.details?.samples).toHaveLength(1);
    env.advance(interval);
    for (let i = 0; i < 1000; i += 1) await env.call(`${probeIntents[i % probeIntents.length]} z${i}`);
    expect(await env.rows()).toHaveLength(keys.size * 2);
    for (const row of await env.rows()) {
      expect(row.details).toBeDefined();
      const samples = row.details!.samples as string[];
      // Each key keeps the established three samples of at most one hundred twenty characters.
      expect(samples.length).toBeLessThanOrEqual(3);
      for (const sample of samples) expect(sample.length).toBeLessThanOrEqual(120);
    }
  });
  it("keeps one row per key across repeated admission cycles within an interval", async () => {
    const env = setup();
    const entries = uniqueIntents.flatMap(intent => ["origin-one", "origin-two", "origin-three"].map(origin => ({ origin, intent }))).slice(0, cap + 1);
    expect(entries).toHaveLength(cap + 1);
    const probe = async (index: number) => {
      env.setOrigin(entries[index]!.origin);
      await env.call(entries[index]!.intent);
    };
    // Two complete waves exceed the cap without advancing the interval clock.
    for (let wave = 0; wave < 2; wave += 1) {
      for (let i = 0; i < entries.length; i += 1) await probe(i);
      const rows = await env.rows();
      expect(rows).toHaveLength(cap);
      const keys = rows.map(row => `${row.identity_id}:${row.details?.probe_key}`);
      expect(new Set(keys).size).toBe(rows.length);
    }
    env.advance(interval);
    await probe(cap);
    const rows = await env.rows();
    expect(rows).toHaveLength(cap + 1);
    // One unadmitted key in each of two waves contributes to the next summary.
    expect(rows.at(-1)?.details?.overflow_count).toBe(2);
    await probe(cap);
    expect(await env.rows()).toHaveLength(cap + 1);
  });
  it("retains a pending append through full-table admission and late completion", async () => {
    const env = setup();
    const entries = uniqueIntents.flatMap(intent => ["origin-one", "origin-two", "origin-three"].map(origin => ({ origin, intent }))).slice(0, cap + 1);
    const probe = async (index: number) => {
      env.setOrigin(entries[index]!.origin);
      return env.call(entries[index]!.intent);
    };
    const append = env.auditLog.appendCritical.bind(env.auditLog);
    let release!: () => void;
    let started!: () => void;
    const held = new Promise<void>(resolve => { release = resolve; });
    const entered = new Promise<void>(resolve => { started = resolve; });
    let first = true;
    vi.spyOn(env.auditLog, "appendCritical").mockImplementation(async entry => {
      if (entry.operation === OPERATION && first) {
        first = false;
        started();
        await held;
      }
      return append(entry);
    });
    const pending = [probe(0)];
    await entered;
    try {
      for (let i = 1; i < cap; i += 1) pending.push(probe(i));
      await probe(cap);
      expect(await env.rows()).toHaveLength(0);
      env.advance(interval);
      await probe(cap);
      await probe(0);
      expect(await env.rows()).toHaveLength(0);
    } finally {
      release();
      await Promise.all(pending);
    }
    const settledRows = await env.rows();
    expect(settledRows).toHaveLength(cap);
    // The row after the held append carries both full-table admissions.
    expect(settledRows[1]?.details?.overflow_count).toBe(2);
    const keys = settledRows.map(row => `${row.identity_id}:${row.details?.probe_key}`);
    expect(new Set(keys).size).toBe(cap);
    expect(keys).toEqual(entries.slice(0, cap).map(entry => `${entry.origin}:${classifyIntent(entry.intent).probe_key}`));
    await probe(0);
    await probe(cap);
    expect(await env.rows()).toHaveLength(cap);
    env.advance(interval);
    await probe(cap);
    expect(await env.rows()).toHaveLength(cap + 1);
    expect((await env.rows()).at(-1)?.details?.overflow_count).toBe(1);
    await probe(0);
    expect(await env.rows()).toHaveLength(cap + 2);
  });
  it("reports overflow as unconfirmed when an append throws before storage", async () => {
    const env = setup();
    const entries = uniqueIntents.flatMap(intent => ["origin-one", "origin-two", "origin-three"].map(origin => ({ origin, intent }))).slice(0, cap + 1);
    const probe = async (index: number) => {
      env.setOrigin(entries[index]!.origin);
      return env.call(entries[index]!.intent);
    };
    for (let i = 0; i <= cap; i += 1) await probe(i);
    expect(await env.rows()).toHaveLength(cap);
    env.advance(interval);
    const append = env.auditLog.appendCritical.bind(env.auditLog);
    let reject = true;
    vi.spyOn(env.auditLog, "appendCritical").mockImplementation(async entry => {
      if (entry.operation === OPERATION && reject) {
        reject = false;
        throw new Error("append unavailable");
      }
      return append(entry);
    });
    expect(await probe(cap)).toHaveProperty("denied", true);
    expect(await env.rows()).toHaveLength(cap);
    await probe(1);
    expect(await env.rows()).toHaveLength(cap + 1);
    expect((await env.rows()).at(-1)?.details).toMatchObject({ overflow_count: 0, overflow_unconfirmed_count: 1 });
    await probe(2);
    expect((await env.rows()).at(-1)?.details).toMatchObject({ overflow_count: 0, overflow_unconfirmed_count: 0 });
  });
  it("reports a stored row's overflow as unconfirmed after a checkpoint write throws", async () => {
    class CheckpointStorage extends MemoryStorage {
      failCheckpoint = false;
      checkpointFailures = 0;
      override async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
        if (this.failCheckpoint && namespace === AUDIT_CHECKPOINT_NAMESPACE && key.startsWith("audit-checkpoint-")) {
          this.failCheckpoint = false;
          this.checkpointFailures += 1;
          throw new Error("checkpoint unavailable");
        }
        return super.write(namespace, key, data);
      }
    }
    const storage = new CheckpointStorage();
    // Every critical append checkpoints after its entry write.
    const env = setup(storage, 1);
    const entries = uniqueIntents.flatMap(intent => ["origin-one", "origin-two", "origin-three"].map(origin => ({ origin, intent }))).slice(0, cap + 1);
    const probe = async (index: number) => {
      env.setOrigin(entries[index]!.origin);
      return env.call(entries[index]!.intent);
    };
    for (let i = 0; i <= cap; i += 1) await probe(i);
    expect(await env.rows()).toHaveLength(cap);
    env.advance(interval);
    const storedBefore = (await storage.list("_audit")).length;
    storage.failCheckpoint = true;
    expect(await probe(cap)).toHaveProperty("denied", true);
    expect(storage.checkpointFailures).toBe(1);
    expect(await storage.list("_audit")).toHaveLength(storedBefore + 1);
    const stored = await env.rows();
    expect(stored).toHaveLength(cap + 1);
    expect(stored.at(-1)?.details?.overflow_count).toBe(1);
    await probe(1);
    const carried = (await env.rows()).slice(cap);
    expect(carried).toHaveLength(2);
    expect(carried.reduce((sum, row) => sum + Number(row.details?.overflow_count), 0)).toBe(1);
    expect(carried[0]?.details?.overflow_unconfirmed_count).toBe(0);
    expect(carried[1]?.details).toMatchObject({ overflow_count: 0, overflow_unconfirmed_count: 1 });
    await probe(2);
    expect((await env.rows()).at(-1)?.details).toMatchObject({ overflow_count: 0, overflow_unconfirmed_count: 0 });
  });
  it.each(["entry", "checkpoint"] as const)("carries unconfirmed overflow through a %s throw and an entry throw", async firstFailure => {
    class ScheduledStorage extends MemoryStorage {
      failures: Array<"entry" | "checkpoint"> = [];
      throws = 0;
      override async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
        const next = this.failures[0];
        if ((next === "entry" && namespace === AUDIT_NAMESPACE) ||
            (next === "checkpoint" && namespace === AUDIT_CHECKPOINT_NAMESPACE && key.startsWith("audit-checkpoint-"))) {
          this.failures.shift();
          this.throws += 1;
          throw new Error("scheduled storage unavailable");
        }
        return super.write(namespace, key, data);
      }
    }
    const storage = new ScheduledStorage();
    // Each real critical append writes its entry before checkpointing.
    const env = setup(storage, 1);
    const entries = uniqueIntents.flatMap(intent => ["origin-one", "origin-two", "origin-three"].map(origin => ({ origin, intent }))).slice(0, cap + 1);
    const probe = async (index: number) => {
      env.setOrigin(entries[index]!.origin);
      return env.call(entries[index]!.intent);
    };
    for (let i = 0; i <= cap; i += 1) await probe(i);
    expect(await env.rows()).toHaveLength(cap);
    const storedBefore = (await storage.list(AUDIT_NAMESPACE)).length;
    env.advance(interval);
    storage.failures = [firstFailure, "entry"];
    expect(await probe(cap)).toHaveProperty("denied", true);
    const persisted = firstFailure === "checkpoint" ? 1 : 0;
    expect(await storage.list(AUDIT_NAMESPACE)).toHaveLength(storedBefore + persisted);
    expect(await probe(1)).toHaveProperty("denied", true);
    expect(storage.throws).toBe(2);
    expect(storage.failures).toEqual([]);
    expect(await storage.list(AUDIT_NAMESPACE)).toHaveLength(storedBefore + persisted);
    expect(await env.rows()).toHaveLength(cap + persisted);
    await probe(2);
    const carried = (await env.rows()).slice(cap);
    expect(carried).toHaveLength(persisted + 1);
    expect(carried.reduce((sum, row) => sum + Number(row.details?.overflow_count), 0)).toBe(persisted);
    expect(carried.at(-1)?.details).toMatchObject({ overflow_count: 0, overflow_unconfirmed_count: 1 });
    await probe(3);
    expect((await env.rows()).at(-1)?.details).toMatchObject({ overflow_count: 0, overflow_unconfirmed_count: 0 });
  });
  it("reserves one row for fifty concurrent probes of a key", async () => {
    const env = setup();
    await Promise.all(Array.from({ length: 50 }, () => env.call("export the note")));
    expect(await env.rows()).toHaveLength(1);
  });
  it("retains a reserved row slot after an append rejects", async () => {
    const env = setup();
    const append = env.auditLog.appendCritical.bind(env.auditLog);
    let attempts = 0;
    vi.spyOn(env.auditLog, "appendCritical").mockImplementation(async entry => {
      if (entry.operation === OPERATION) { attempts += 1; throw new Error("append unavailable"); }
      return append(entry);
    });
    expect(await env.call("export the note")).toMatchObject({ denied: true, remediation_class: "wait", audit_ref: "audit:sanctuary_help" });
    for (let i = 0; i < 50; i += 1) expect(await env.call("export the note")).toHaveProperty("safety_class", "gated");
    expect(attempts).toBe(1);
    env.advance(interval);
    await env.call("export the note");
    expect(attempts).toBe(2);
  });
  it("answers gated probes without an identity and uses a distinct unbound origin", async () => {
    const env = setup();
    await env.call("export the note");
    env.setOrigin();
    const answer = await env.call("export the note");
    expect(answer).toMatchObject({ safety_class: "gated", tool: null });
    for (const field of ["error", "denied", "status", "probe_key"]) expect(answer).not.toHaveProperty(field);
    await env.call("export the note");
    expect(await env.rows()).toHaveLength(2);
    expect((await env.rows()).at(-1)).toHaveProperty("identity_id", "system");
  });
});
