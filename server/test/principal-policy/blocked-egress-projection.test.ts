import { describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import { UnifiedInboxStore, UNIFIED_INBOX_NAMESPACE } from "../../src/principal-policy/unified-inbox-store.js";
import { UnifiedInboxScheduler } from "../../src/principal-policy/unified-inbox-scheduler.js";
import { UnifiedInboxBridge } from "../../src/principal-policy/unified-inbox-bridge.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { BlockedEgressAdmissions, BLOCKED_EGRESS_ENTRY_MAX_BYTES, BLOCKED_EGRESS_RETAINED_MAX_BYTES, BLOCKED_EGRESS_RESERVATIONS_MAX,
  BLOCKED_EGRESS_ORIGIN_MAX, BLOCKED_EGRESS_LIFETIME_MS, BLOCKED_EGRESS_FUTURE_SKEW_MS, parseBlockedEgressAdmissionRecord,
  type BlockedEgressCandidate, type BlockedEgressSnapshot } from "../../src/principal-policy/blocked-egress-projection.js";
import { HUB_BLOCKED_EGRESS_FORTRESS_MAX, HUB_BLOCKED_EGRESS_EMITTED_MAX } from "../../src/hub/constants.js";
import { HubInboxStore } from "../../src/hub/inbox-store.js";
import type { HubBlockedEgressItem } from "../../src/contracts/v1.1/hub-events.js";

const NOW = Date.UTC(2026, 5, 14);
const FORTRESS = "projection-test";
const KEY = new Uint8Array(32).fill(7); // isolated AES-256 master key
const hash = (v: string) => createHash("sha256").update(v).digest("hex");
const iso = (ms: number) => new Date(ms).toISOString();
function deferred() { let resolve!: () => void; const promise = new Promise<void>(r => { resolve = r; }); return { promise, resolve }; }
function candidate(subject: string, seq: number, at = NOW, producer = subject): BlockedEgressCandidate {
  return { entry: { inbox_id: `id-${subject}-${producer}-${seq}`, source_class: "blocked_egress", source_event_id: `${subject}-${seq}`,
    fortress_id: FORTRESS, observed_at: iso(at), summary: "Blocked destination", severity: "alert", details_url: "/inbox",
    blocked_egress: { subject, destination_host: "bounded.example", attribution: { subject: "castle_wall_producer", evidence_source: "producer_signature", verifier: "castle_wall_audit_consumer", state: "verified" } } },
    signedIdentity: { producer_key_digest: hash(producer), seq, body_digest: hash(`${subject}-${seq}`) } };
}
function unsigned(seq: number, at = NOW): BlockedEgressCandidate {
  const c = candidate("unsigned", seq, at);
  delete c.signedIdentity;
  c.entry.blocked_egress = { destination_host: "bounded.example", attribution: { subject: "castle_wall_producer", evidence_source: "producer_signature", verifier: "castle_wall_audit_consumer", state: "unverified" } };
  return c;
}
function rig(retentionDays?: number) {
  const memory = new MemoryStorage();
  const calls = { read: 0, index: 0, entries: 0, list: 0, write: 0, delete: 0 };
  const storage: StorageBackend = {
    read: async (ns, key) => { calls.read++; if (key === "blocked_egress.index.v1") calls.index++; else if (key.startsWith("entry.")) calls.entries++; return memory.read(ns, key); },
    write: async (ns, key, data) => { calls.write++; await memory.write(ns, key, data); },
    delete: async (ns, key) => { calls.delete++; return memory.delete(ns, key); },
    list: async (ns, prefix) => { calls.list++; return memory.list(ns, prefix); },
    exists: (ns, key) => memory.exists(ns, key), totalSize: () => memory.totalSize(),
  };
  let now = NOW;
  const clock = () => new Date(now);
  const makeStore = () => new UnifiedInboxStore({ storage, masterKey: KEY, fortressId: FORTRESS, now: clock, retentionDays });
  const makeAdmissions = (store = makeStore()) => new BlockedEgressAdmissions({ fortressId: FORTRESS, store, now: clock, retentionDays: store.retentionDays });
  const store = makeStore();
  return { memory, calls, storage, store, admissions: makeAdmissions(store), makeStore, makeAdmissions, clock, advance: (ms: number) => { now += ms; } };
}
function card(entry: BlockedEgressSnapshot["items"][number]): HubBlockedEgressItem {
  return { version: "1.1", item_id: entry.item_id, kind: "blocked_egress", identity_id: FORTRESS, created_at: entry.observed_at,
    display_template_id: "blocked_egress.custom.other", display_template_args: [], destination_category: "custom", block_reason_class: "other", resolved: false };
}
function feed(overlay: HubInboxStore, snapshot: BlockedEgressSnapshot) {
  for (const item of snapshot.items) overlay.upsertFromSource(card(item));
  if (snapshot.presence === "complete") overlay.reconcileSourceItems("source.blocked_egress.", snapshot.presentIds, iso(NOW));
}
const overlaySize = (overlay: HubInboxStore) => (overlay as unknown as { entries: Map<string, unknown> }).entries.size;
function admit(a: BlockedEgressAdmissions, c: BlockedEgressCandidate) {
  const result = a.admit(c);
  expect(result.kind).toBe("admitted");
  if (result.kind !== "admitted") throw new Error(result.kind);
  return result;
}

describe("bounded blocked-egress projection", () => {
  it("bounds sustained per-origin admissions, durable keys, restart reads and overlay work", async () => {
    const r = rig();
    let store = r.store;
    let a = r.admissions;
    const overlay = new HubInboxStore();
    await a.restore();
    let b = 0;
    let totalAdmissions = 0;
    const evidence: unknown[] = [];
    async function check(label: string, onlyAB: boolean) {
      await a.settled();
      const before = { ...r.calls };
      const snap = a.snapshot();
      expect(r.calls).toEqual(before);
      feed(overlay, snap);
      const stats = a.stats();
      const keys = await r.memory.list(UNIFIED_INBOX_NAMESPACE, "entry.");
      const ids = await store.readBlockedEgressIndex();
      process.stdout.write(`BOUNDS_COUNTER ${JSON.stringify({ label, ...stats, durable: keys.length, index: ids.length, overlay: overlaySize(overlay), snapshotStorageCalls: 0 })}\n`);
      expect(stats.origins["subject:A"] ?? 0).toBeLessThanOrEqual(BLOCKED_EGRESS_ORIGIN_MAX);
      if (onlyAB) expect(stats.origins["subject:B"]).toBe(Math.min(BLOCKED_EGRESS_ORIGIN_MAX, b));
      expect(stats.retained).toBeLessThanOrEqual(HUB_BLOCKED_EGRESS_FORTRESS_MAX);
      expect(stats.encodedBytes).toBeLessThanOrEqual(BLOCKED_EGRESS_RETAINED_MAX_BYTES);
      expect(Math.max(peak, stats.peakReservations)).toBe(BLOCKED_EGRESS_RESERVATIONS_MAX);
      expect(stats.dedupRecords).toBe(stats.retained);
      expect(overlaySize(overlay)).toBeLessThanOrEqual(HUB_BLOCKED_EGRESS_FORTRESS_MAX);
      expect(keys.length).toBeLessThanOrEqual(HUB_BLOCKED_EGRESS_FORTRESS_MAX);
      expect(ids.length).toBeLessThanOrEqual(HUB_BLOCKED_EGRESS_FORTRESS_MAX);
      expect(keys.length).toBe(stats.retained);
      evidence.push({ label, ...stats, durable: keys.length, index: ids.length, overlay: overlaySize(overlay) });
    }
    async function restart(label: string) {
      await a.settled();
      store = r.makeStore(); a = r.makeAdmissions(store);
      const before = { ...r.calls };
      await a.restore();
      process.stdout.write(`RESTORE_COUNTER ${JSON.stringify({ label, indexReads: r.calls.index - before.index, entryReads: r.calls.entries - before.entries, lists: r.calls.list - before.list })}\n`);
      expect(r.calls.index - before.index).toBe(1);
      expect(r.calls.entries - before.entries).toBeLessThanOrEqual(HUB_BLOCKED_EGRESS_FORTRESS_MAX);
      expect(r.calls.list - before.list).toBe(0);
      evidence.push({ label, indexReads: r.calls.index - before.index, entryReads: r.calls.entries - before.entries, lists: r.calls.list - before.list });
    }
    let peak = 0;
    let reservationRefusals = 0;
    let writeGate = deferred();
    const write = r.storage.write;
    r.storage.write = async (...args) => { await writeGate.promise; await write(...args); };
    async function submit(c: BlockedEgressCandidate) {
      admit(a, c); totalAdmissions++;
      peak = Math.max(peak, a.stats().reservations);
      feed(overlay, a.snapshot());
      if (a.stats().reservations === BLOCKED_EGRESS_RESERVATIONS_MAX) {
        expect(a.admit(candidate("overflow", totalAdmissions))).toEqual({ kind: "refused", reason: "reservations_full" });
        reservationRefusals++;
        writeGate.resolve(); await a.settled(); writeGate = deferred();
      }
    }
    const WAVES = 10;
    const WAVE_SIZE = 1000;
    const INTERLEAVE = 17; // acceptance schedule: B after each seventeenth A
    for (let wave = 1; wave <= WAVES; wave++) {
      for (let offset = 1; offset <= WAVE_SIZE; offset++) {
        const seq = (wave - 1) * WAVE_SIZE + offset;
        await submit(candidate("A", seq, r.clock().getTime()));
        if (seq % INTERLEAVE === 0) await submit(candidate("B", ++b, r.clock().getTime()));
      }
      writeGate.resolve(); await a.settled();
      await check(`wave-${wave}`, true);
      if (wave === WAVES / 2 || wave === WAVES) { await restart(`restart-${wave}`); await check(`after-restart-${wave}`, true); }
      r.advance(1); // Distinct acceptance times decide age across waves.
      writeGate = deferred();
    }
    // More than one fortress worth of fresh subjects exercises the global bound independently of A's churn.
    for (let origin = 0; origin <= HUB_BLOCKED_EGRESS_FORTRESS_MAX / BLOCKED_EGRESS_ORIGIN_MAX; origin++) {
      for (let seq = 0; seq < BLOCKED_EGRESS_ORIGIN_MAX; seq++) {
        await submit(candidate(`fresh${origin}`, seq, r.clock().getTime()));
      }
      r.advance(1); // Fresh-origin waves have a strict acceptance-time order.
    }
    writeGate.resolve(); await a.settled();
    await check("global-cap", false);
    await restart("restart-global-cap"); await check("after-global-restart", false);
    expect(totalAdmissions).toBeGreaterThan(HUB_BLOCKED_EGRESS_FORTRESS_MAX);
    console.log("BOUNDS_WITNESS", JSON.stringify({ totalAdmissions, peakReservations: peak, reservationRefusals, evidence }));
  }, 90 * 1000); // Three ordinary test windows for the required 11,608 encrypted admissions and every-snapshot overlay.

  it("replaces a full origin's oldest record before another origin and uses stable id ties", async () => {
    const r = rig(); const a = r.admissions; await a.restore();
    admit(a, candidate("B", 0)); await a.settled(); r.advance(1);
    for (let i = 0; i < BLOCKED_EGRESS_ORIGIN_MAX; i++) { admit(a, candidate("A", i)); await a.settled(); }
    const replacement = admit(a, candidate("A", BLOCKED_EGRESS_ORIGIN_MAX));
    expect(replacement.evicted.map(e => e.inbox_id)).toEqual([candidate("A", 0).entry.inbox_id]);
    expect(a.stats().origins["subject:B"]).toBe(1);
    await a.settled();
  });

  it("expires from the earliest source, acceptance or policy limit and refuses invalid times", async () => {
    const r = rig(); const a = r.admissions; await a.restore();
    const age = BLOCKED_EGRESS_LIFETIME_MS / 2;
    const old = admit(a, candidate("A", 0, NOW - age));
    expect(old.entry.blocked_egress_admission?.expires_at).toBe(iso(NOW + age));
    const future = admit(a, candidate("B", 0, NOW + BLOCKED_EGRESS_FUTURE_SKEW_MS));
    expect(future.entry.blocked_egress_admission?.expires_at).toBe(iso(NOW + BLOCKED_EGRESS_LIFETIME_MS));
    expect(a.admit(candidate("C", 0, NOW + BLOCKED_EGRESS_FUTURE_SKEW_MS + 1))).toEqual({ kind: "refused", reason: "future_time" });
    const invalid = candidate("C", 0); invalid.entry.observed_at = "2026-06-14T00:00:00";
    expect(a.admit(invalid)).toEqual({ kind: "refused", reason: "invalid_time" });
    expect(a.admit(candidate("C", 0, NOW - BLOCKED_EGRESS_LIFETIME_MS))).toEqual({ kind: "refused", reason: "expired" });
    await a.settled();
    expect((await r.store.get(old.entry.inbox_id))?.retention_until).toBe(old.entry.blocked_egress_admission?.expires_at);
    const short = rig(1); await short.admissions.restore();
    const accepted = admit(short.admissions, candidate("A", 0)); await short.admissions.settled();
    expect(accepted.entry.blocked_egress_admission?.expires_at).toBe(iso(NOW + BLOCKED_EGRESS_LIFETIME_MS / 30));
    expect((await short.store.get(accepted.entry.inbox_id))?.retention_until).toBe(accepted.entry.blocked_egress_admission?.expires_at);
  });

  it("keeps identity, expiry and dismissal on retries and separates producer keys and sequence gaps", async () => {
    const r = rig(); const a = r.admissions; await a.restore();
    const first = admit(a, candidate("A", 0)).entry;
    expect(a.update({ ...first, state: "dismissed", dismissed_at: iso(NOW) })).toEqual({ kind: "applied" });
    await a.settled(); r.advance(BLOCKED_EGRESS_FUTURE_SKEW_MS);
    const duplicate = a.admit(candidate("A", 0));
    expect(duplicate.kind).toBe("duplicate");
    if (duplicate.kind === "duplicate") {
      expect(duplicate.entry.inbox_id).toBe(first.inbox_id);
      expect(duplicate.entry.state).toBe("dismissed");
      expect(duplicate.entry.blocked_egress_admission?.expires_at).toBe(first.blocked_egress_admission?.expires_at);
    }
    const conflict = candidate("A", 0); conflict.signedIdentity!.body_digest = hash("other body");
    expect(a.admit(conflict)).toEqual({ kind: "refused", reason: "identity_conflict" });
    admit(a, candidate("A", 0, NOW, "second-key"));
    admit(a, candidate("A", 100)); // sequence gaps have no projection semantics
    admit(a, unsigned(0)); expect(a.admit(unsigned(0)).kind).toBe("duplicate");
    await a.settled(); await a.restore();
    expect(a.stats().retained).toBe(4);
    expect(a.admit(candidate("A", 0)).kind).toBe("duplicate");
  });

  it("holds reservations through an aborted flush and late settlement then rebuilds on restart", async () => {
    const r = rig();
    const gate = deferred(); const started = deferred();
    const write = r.storage.write;
    r.storage.write = async (...args) => { started.resolve(); await gate.promise; await write(...args); };
    const bridge = new UnifiedInboxBridge({ auditLog: new AuditLog(new MemoryStorage(), KEY), identityId: FORTRESS, fortressId: FORTRESS, store: r.store, now: r.clock });
    await bridge.rehydratePendingFromStore();
    const input = (i: number) => ({ source_event_id: `receipt-${i}`, destination_category: "custom", block_reason_class: "other" as const, observed_at: iso(NOW) });
    for (let i = 0; i < BLOCKED_EGRESS_RESERVATIONS_MAX; i++) expect(bridge.ingestBlockedEgress(input(i))).not.toBeNull();
    await started.promise;
    const controller = new AbortController(); const pending = bridge.flushPersistence({ signal: controller.signal }); controller.abort();
    await expect(pending).rejects.toThrow("aborted");
    const whileStalled = bridge.ingestBlockedEgress(input(BLOCKED_EGRESS_RESERVATIONS_MAX));
    gate.resolve(); await bridge.flushPersistence();
    expect(whileStalled).toBeNull();
    expect(bridge.ingestBlockedEgress(input(BLOCKED_EGRESS_RESERVATIONS_MAX))).not.toBeNull(); await bridge.flushPersistence();
    const next = r.makeAdmissions(); await next.restore();
    expect(next.stats()).toMatchObject({ retained: BLOCKED_EGRESS_ORIGIN_MAX, reservations: 0 });
  });

  it("keeps the prior complete generation unknown after a mid-page read failure", async () => {
    const r = rig(); const a = r.admissions; await a.restore();
    for (let i = 0; i < 3; i++) { admit(a, candidate("A", i)); await a.settled(); }
    const before = a.snapshot();
    let reads = 0;
    const real = r.store.get.bind(r.store);
    vi.spyOn(r.store, "get").mockImplementation(async id => { if (++reads === 2) throw new Error("read unavailable"); return real(id); });
    await expect(a.restore()).rejects.toThrow("read unavailable");
    expect(a.snapshot()).toEqual({ generation: before.generation, presence: "unknown", items: before.items });
    vi.restoreAllMocks();
  });

  it("excludes parsed invalid and oversized content from a complete generation", async () => {
    const r = rig(); await r.admissions.restore();
    const entries = [];
    for (let i = 0; i < 3; i++) { entries.push(admit(r.admissions, candidate("A", i)).entry); await r.admissions.settled(); }
    await r.store.upsert({ ...entries[0]!, blocked_egress_admission: undefined });
    await r.store.upsert({ ...entries[1]!, summary: "x".repeat(BLOCKED_EGRESS_ENTRY_MAX_BYTES) });
    const a = r.makeAdmissions(); await a.restore();
    expect(a.snapshot().presence).toBe("complete"); expect(a.stats().retained).toBe(1);
    expect(await r.memory.list(UNIFIED_INBOX_NAMESPACE, "entry.")).toHaveLength(1);
  });

  it("refuses admission and workflow changes without storage calls while RESTORING and FAILED", async () => {
    const r = rig(); const a = r.admissions;
    expect(a.admit(candidate("A", 0))).toEqual({ kind: "refused", reason: "not_ready" });
    expect(a.update(candidate("A", 0).entry)).toEqual({ kind: "not_ready" });
    expect(a.remove(candidate("A", 0).entry.inbox_id)).toEqual({ kind: "not_ready" });
    expect(r.calls).toEqual({ read: 0, index: 0, entries: 0, list: 0, write: 0, delete: 0 });
    await a.restore(); const entry = admit(a, candidate("A", 0)).entry; await a.settled();
    const gate = deferred(); const started = deferred();
    const read = r.storage.read;
    r.storage.read = async (...args) => { await read(...args); started.resolve(); await gate.promise; throw new Error("read unavailable"); };
    const restoring = a.restore(); await started.promise;
    const before = { ...r.calls };
    const generation = a.snapshot().generation;
    const refuse = () => {
      expect(a.admit(candidate("B", 0))).toEqual({ kind: "refused", reason: "not_ready" });
      expect(a.update({ ...entry, state: "dismissed" })).toEqual({ kind: "not_ready" });
      expect(a.remove(entry.inbox_id)).toEqual({ kind: "not_ready" });
      expect(a.stats().retained).toBe(1);
      expect(a.stats().reservations).toBe(0);
      expect(a.snapshot().generation).toBe(generation);
      expect(r.calls).toEqual(before);
    };
    refuse(); gate.resolve(); await expect(restoring).rejects.toThrow("read unavailable");
    expect(a.stats().state).toBe("state_FAILED");
    refuse(); // The next admit schedules recovery, but none of these operations performs storage work synchronously.
    await expect(a.settled()).rejects.toThrow("read unavailable");
    expect(r.calls.write).toBe(before.write); expect(r.calls.delete).toBe(before.delete);
    r.storage.read = read; await a.restore();
    expect(a.stats()).toMatchObject({ state: "state_READY", retained: 1, reservations: 0 });
    expect(a.admit(candidate("B", 0)).kind).toBe("admitted"); await a.settled();
  });

  it("drops expired presence between reads and refuses a retry without renewal", async () => {
    const r = rig(); const a = r.admissions; await a.restore();
    admit(a, candidate("A", 0)); await a.settled(); const first = a.snapshot(); expect(first.items).toHaveLength(1);
    r.advance(BLOCKED_EGRESS_LIFETIME_MS);
    const next = a.snapshot(); expect(next.items).toHaveLength(0);
    expect(next.presence === "complete" && next.presentIds.size).toBe(0);
    expect(a.admit(candidate("A", 0))).toEqual({ kind: "refused", reason: "expired" });
    await a.settled(); expect(await r.store.readBlockedEgressIndex()).toEqual([]);
  });

  it("preserves dismissal and complete presence beyond the emitted page across refresh and restart", async () => {
    const r = rig(); let a = r.admissions; await a.restore(); const overlay = new HubInboxStore();
    admit(a, candidate("A", 0)); await a.settled();
    const first = a.snapshot().items[0]!; feed(overlay, a.snapshot());
    await overlay.resolve(first.item_id, "dismiss", iso(NOW));
    const later = NOW + 1;
    for (let i = 0; i <= HUB_BLOCKED_EGRESS_EMITTED_MAX; i++) { admit(a, candidate(`new${i}`, 0, later)); await a.settled(); }
    const beyond = a.snapshot(); expect(beyond.items.some(e => e.item_id === first.item_id)).toBe(false);
    expect(beyond.presence === "complete" && beyond.presentIds.has(first.item_id)).toBe(true);
    feed(overlay, beyond);
    expect(overlay.reconcileSourceItems("source.blocked_egress.", beyond.presence === "complete" ? beyond.presentIds : new Set(), iso(NOW))).toBe(0);
    a = r.makeAdmissions(); await a.restore(); feed(overlay, a.snapshot()); expect(overlay.get(first.item_id)?.resolved).toBe(true);
    expect(a.remove(first.inbox_id)).toEqual({ kind: "applied" }); await a.settled();
    const removed = a.snapshot(); feed(overlay, removed);
    expect(overlay.reconcileSourceItems("source.blocked_egress.", removed.presence === "complete" ? removed.presentIds : new Set(), iso(NOW))).toBe(0);
    expect(overlaySize(overlay)).toBeLessThanOrEqual(HUB_BLOCKED_EGRESS_FORTRESS_MAX);
  });

  it("refuses oversized entries before hashing or storage and parses closed admission records", async () => {
    const r = rig(); const a = r.admissions; await a.restore();
    const before = { ...r.calls }; const large = candidate("A", 0); large.entry.summary = "x".repeat(BLOCKED_EGRESS_ENTRY_MAX_BYTES);
    expect(a.admit(large)).toEqual({ kind: "refused", reason: "oversize" }); expect(r.calls).toEqual(before);
    const record = admit(a, candidate("A", 1)).entry.blocked_egress_admission!;
    expect(parseBlockedEgressAdmissionRecord(record).ok).toBe(true);
    for (const invalid of [null, {}, { ...record, version: 2 }, { ...record, extra: true }, { ...record, origin: "subject:" }, { ...record, identity: {} }, { ...record, encoded_bytes: BLOCKED_EGRESS_ENTRY_MAX_BYTES + 1 }]) expect(parseBlockedEgressAdmissionRecord(invalid).ok).toBe(false);
    await a.settled();
  });
  it("accounts for retiring encodings within the independent byte budget", async () => {
    const r = rig(); const a = r.admissions; await a.restore();
    const large = (subject: string, seq: number) => {
      const c = candidate(subject, seq);
      c.entry.summary = "x".repeat(3200); // leaves room for metadata/admission under the 4 KiB non-proof allowance
      return c;
    };
    for (let i = 0; i < HUB_BLOCKED_EGRESS_FORTRESS_MAX; i++) {
      admit(a, large(`origin${Math.floor(i / BLOCKED_EGRESS_ORIGIN_MAX)}`, i)); await a.settled();
    }
    const gate = deferred(); const write = r.storage.write;
    r.storage.write = async (...args) => { await gate.promise; await write(...args); };
    let capacityRefusals = 0;
    try {
      for (let i = 0; i < BLOCKED_EGRESS_RESERVATIONS_MAX; i++) {
        const result = a.admit(large(`replacement${i}`, i));
        if (result.kind === "refused" && result.reason === "capacity") capacityRefusals++;
        expect(a.stats().encodedBytes).toBeLessThanOrEqual(BLOCKED_EGRESS_RETAINED_MAX_BYTES);
      }
      expect(capacityRefusals).toBeGreaterThan(0);
    } finally { gate.resolve(); await a.settled(); }
    expect(a.stats().retained).toBe(HUB_BLOCKED_EGRESS_FORTRESS_MAX);
  });

  it("evicts expired records first and chooses the globally oldest at the fortress cap", async () => {
    const r = rig(); const a = r.admissions; await a.restore();
    const aged = admit(a, candidate("old", 0, NOW - BLOCKED_EGRESS_LIFETIME_MS / 2)).entry;
    await a.settled(); r.advance(BLOCKED_EGRESS_LIFETIME_MS / 2);
    const first = admit(a, candidate("live", 0, r.clock().getTime()));
    expect(first.evicted.map(e => e.inbox_id)).toEqual([aged.inbox_id]); await a.settled();
    for (let i = 1; i < HUB_BLOCKED_EGRESS_FORTRESS_MAX; i++) {
      admit(a, candidate(`fresh${i}`, 0, r.clock().getTime())); await a.settled();
    }
    const oldest = a.retained().map(e => e.inbox_id).sort()[0]!;
    const next = admit(a, candidate("last", 0, r.clock().getTime()));
    expect(next.evicted.map(e => e.inbox_id)).toEqual([oldest]); await a.settled();
  });

  it("keeps failed writes unavailable and bounds subsequent admission until a successful restore", async () => {
    const r = rig(); const a = r.admissions; await a.restore();
    const write = r.storage.write;
    r.storage.write = async () => { throw new Error("write unavailable"); };
    admit(a, candidate("A", 0));
    await expect(a.settled()).rejects.toThrow("write unavailable");
    expect(a.snapshot().presence).toBe("unknown");
    expect(a.admit(candidate("B", 0))).toEqual({ kind: "refused", reason: "not_ready" });
    expect(a.stats().reservations).toBe(0);
    r.storage.write = write;
    await a.restore(); admit(a, candidate("B", 0)); await a.settled();
    expect(a.stats().retained).toBe(1);
  });

  it("removes expired indexed records durably on restart and preserves other source classes", async () => {
    const r = rig(); const a = r.admissions; await a.restore();
    for (let i = 0; i < BLOCKED_EGRESS_ORIGIN_MAX; i++) { admit(a, candidate("A", i)); await a.settled(); }
    const approval = { ...candidate("approval", 0).entry, source_class: "approval" as const };
    delete approval.blocked_egress;
    await r.store.upsert(approval);
    const ids = await r.store.readBlockedEgressIndex();
    await r.store.writeBlockedEgressIndex([...ids, approval.inbox_id]);
    r.advance(BLOCKED_EGRESS_LIFETIME_MS);
    const next = r.makeAdmissions(); await next.restore(); await next.settled();
    expect(next.stats().retained).toBe(0);
    expect(await r.memory.list(UNIFIED_INBOX_NAMESPACE, "entry.")).toHaveLength(1);
    expect(await r.store.get(approval.inbox_id)).toMatchObject({ source_class: "approval" });
    expect(await r.store.readBlockedEgressIndex()).toEqual([]);
  });

  it("preserves the durable index through failed initial restore and repeated admissions", async () => {
    const r = rig(); await r.admissions.restore();
    const original = admit(r.admissions, candidate("A", 0)).entry; await r.admissions.settled();
    const index = await r.memory.read(UNIFIED_INBOX_NAMESPACE, "blocked_egress.index.v1");
    const a = r.makeAdmissions(r.store);
    const read = r.storage.read;
    r.storage.read = async (...args) => { if (args[1].startsWith("entry.")) throw new Error("entry unavailable"); return read(...args); };
    await expect(a.restore()).rejects.toThrow("entry unavailable");
    const before = { ...r.calls };
    for (let wave = 0; wave < 3; wave++) { // Repeated admission waves must never publish an empty durable view.
      for (let i = 0; i <= BLOCKED_EGRESS_RESERVATIONS_MAX; i++) expect(a.admit(candidate("B", i))).toEqual({ kind: "refused", reason: "not_ready" });
      await expect(a.settled()).rejects.toThrow("entry unavailable");
    }
    expect(r.calls.write).toBe(before.write); expect(r.calls.delete).toBe(before.delete);
    expect(await r.memory.read(UNIFIED_INBOX_NAMESPACE, "blocked_egress.index.v1")).toEqual(index);
    r.storage.read = read; await a.restore();
    expect(a.stats()).toMatchObject({ state: "state_READY", retained: 1, reservations: 0, dedupRecords: 1,
      encodedBytes: original.blocked_egress_admission!.encoded_bytes });
  });

  it("recovers once after a READY write failure and rebuilds exact nonnegative durable accounting", async () => {
    const r = rig(); const a = r.admissions; await a.restore();
    for (let i = 0; i < BLOCKED_EGRESS_ORIGIN_MAX; i++) { admit(a, candidate("A", i)); await a.settled(); }
    const write = r.storage.write;
    const writeGate = deferred(); const writeStarted = deferred();
    r.storage.write = async (...args) => {
      if (args[1].startsWith("entry.")) { writeStarted.resolve(); await writeGate.promise; throw new Error("entry write unavailable"); }
      return write(...args);
    };
    admit(a, candidate("A", BLOCKED_EGRESS_ORIGIN_MAX));
    admit(a, candidate("B", 0)); // This queued admission must be discarded when its predecessor fails.
    await writeStarted.promise; writeGate.resolve();
    await expect(a.settled()).rejects.toThrow("entry write unavailable");
    expect(a.stats().state).toBe("state_FAILED"); expect(a.stats().encodedBytes).toBeGreaterThanOrEqual(0);
    r.storage.write = write;
    const readGate = deferred(); const readStarted = deferred(); const read = r.storage.read;
    r.storage.read = async (...args) => { const value = await read(...args); if (args[1] === "blocked_egress.index.v1") { readStarted.resolve(); await readGate.promise; } return value; };
    const before = r.calls.index;
    for (let i = 0; i <= BLOCKED_EGRESS_RESERVATIONS_MAX; i++) expect(a.admit(candidate("B", i))).toEqual({ kind: "refused", reason: "not_ready" });
    await readStarted.promise;
    expect(a.stats().state).toBe("state_RESTORING"); expect(r.calls.index - before).toBe(1);
    expect(a.restore()).toBe(a.restore());
    readGate.resolve(); await a.settled();
    const ids = await r.store.readBlockedEgressIndex();
    const durable = await Promise.all(ids.map(id => r.store.get(id)));
    const bytes = durable.reduce((sum, e) => sum + e!.blocked_egress_admission!.encoded_bytes, 0);
    expect(a.stats()).toMatchObject({ state: "state_READY", retained: BLOCKED_EGRESS_ORIGIN_MAX - 1, encodedBytes: bytes, reservations: 0, pendingWorkflowWrites: 0 });
    expect(a.stats().encodedBytes).toBeGreaterThanOrEqual(0);
    expect(a.admit(candidate("B", 0)).kind).toBe("admitted"); await a.settled();
    expect(a.stats().encodedBytes).toBeGreaterThanOrEqual(bytes);
  });

  it("enters the restore read phase after an earlier queued write fails", async () => {
    const r = rig(); const a = r.admissions; await a.restore();
    const write = r.storage.write; const gate = deferred(); const started = deferred();
    r.storage.write = async () => { started.resolve(); await gate.promise; throw new Error("write unavailable"); };
    admit(a, candidate("A", 0)); await started.promise;
    const read = r.storage.read;
    r.storage.read = async (...args) => { expect(a.stats().state).toBe("state_RESTORING"); return read(...args); };
    const restoring = a.restore();
    expect(a.admit(candidate("B", 0))).toEqual({ kind: "refused", reason: "not_ready" });
    gate.resolve(); await restoring; await a.settled();
    expect(a.stats()).toMatchObject({ state: "state_READY", retained: 0, encodedBytes: 0, reservations: 0 });
    r.storage.write = write;
  });

  it("rehydrates other sources without throwing when the blocked index is corrupt", async () => {
    const r = rig();
    const approval = { ...candidate("approval", 0).entry, source_class: "approval" as const };
    await r.store.upsert(approval);
    await r.memory.write(UNIFIED_INBOX_NAMESPACE, "blocked_egress.index.v1", new TextEncoder().encode("invalid"));
    const bridge = new UnifiedInboxBridge({ auditLog: new AuditLog(new MemoryStorage(), KEY), identityId: FORTRESS, fortressId: FORTRESS, store: r.store, now: r.clock });
    await expect(bridge.rehydratePendingFromStore()).resolves.toBe(1);
    expect(bridge.get(approval.inbox_id)?.source_class).toBe("approval");
    expect(bridge.blockedEgressSnapshot().presence).toBe("unknown");
  });

  it("rehydrates other sources when an indexed blocked entry read throws", async () => {
    const r = rig(); await r.admissions.restore();
    const blocked = admit(r.admissions, candidate("A", 0)).entry; await r.admissions.settled();
    const approval = { ...candidate("approval", 0).entry, source_class: "approval" as const };
    await r.store.upsert(approval);
    const read = r.storage.read;
    r.storage.read = async (...args) => { if (args[1] === `entry.${blocked.inbox_id}`) throw new Error("entry unavailable"); return read(...args); };
    const bridge = new UnifiedInboxBridge({ auditLog: new AuditLog(new MemoryStorage(), KEY), identityId: FORTRESS, fortressId: FORTRESS, store: r.store, now: r.clock });
    const before = { ...r.calls };
    await expect(bridge.rehydratePendingFromStore()).resolves.toBe(1);
    expect(bridge.get(approval.inbox_id)?.source_class).toBe("approval");
    expect(bridge.blockedEgressSnapshot().presence).toBe("unknown");
    expect(r.calls.write).toBe(before.write); expect(r.calls.delete).toBe(before.delete);
    // Ordinary reads and non-indexed failures retain the existing store contract.
    await expect(r.store.list()).rejects.toThrow("entry unavailable");
    r.storage.read = async (...args) => { if (args[1] === `entry.${approval.inbox_id}`) throw new Error("approval unavailable"); return read(...args); };
    await expect(r.store.list({ exclude_source_class: "blocked_egress" })).rejects.toThrow("approval unavailable");
  });

  it("deletes nothing durable when any entry fails decryption after an expired entry was read", async () => {
    const r = rig(); const a = r.admissions; await a.restore();
    const expired = admit(a, candidate("A", 0, NOW - BLOCKED_EGRESS_LIFETIME_MS / 2)).entry; await a.settled();
    const corrupt = admit(a, candidate("B", 0)).entry; await a.settled();
    r.advance(BLOCKED_EGRESS_LIFETIME_MS / 2);
    const key = `entry.${corrupt.inbox_id}`;
    const bytes = (await r.memory.read(UNIFIED_INBOX_NAMESPACE, key))!;
    // Valid JSON with invalid authenticated ciphertext exercises decryption, not the JSON parser.
    const envelope = JSON.parse(new TextDecoder().decode(bytes));
    envelope.ct = Buffer.from("invalid ciphertext").toString("base64url");
    await r.memory.write(UNIFIED_INBOX_NAMESPACE, key, new TextEncoder().encode(JSON.stringify(envelope)));
    const before = { ...r.calls };
    const index = await r.memory.read(UNIFIED_INBOX_NAMESPACE, "blocked_egress.index.v1");
    await expect(a.restore()).rejects.toThrow();
    expect(a.stats().state).toBe("state_FAILED"); expect(a.snapshot().presence).toBe("unknown");
    expect(r.calls.delete).toBe(before.delete); expect(r.calls.write).toBe(before.write);
    expect(await r.memory.read(UNIFIED_INBOX_NAMESPACE, "blocked_egress.index.v1")).toEqual(index);
    expect(await r.memory.exists(UNIFIED_INBOX_NAMESPACE, `entry.${expired.inbox_id}`)).toBe(true);
    expect(await r.memory.exists(UNIFIED_INBOX_NAMESPACE, key)).toBe(true);
  });

  it("refuses the same receipt as expired after shortened retention", async () => {
    const r = rig(1); const a = r.admissions; await a.restore();
    const day = BLOCKED_EGRESS_LIFETIME_MS / 30; // Default lifetime is thirty days; store policy is one day.
    const old = candidate("old", 0, NOW - day / 2);
    expect(admit(a, old).entry.blocked_egress_admission!.expires_at).toBe(iso(NOW + day / 2));
    const current = candidate("A", 0); admit(a, current); await a.settled();
    r.advance(day); expect(a.snapshot().items).toHaveLength(0); await a.settled();
    expect(await r.store.readBlockedEgressIndex()).toEqual([]);
    expect(a.admit(current)).toEqual({ kind: "refused", reason: "expired" });
    const next = r.makeAdmissions(); await next.restore();
    expect(next.admit(current)).toEqual({ kind: "refused", reason: "expired" });
  });

  async function workflowRig() {
    const r = rig(); await r.admissions.restore();
    // Two full verified origins produce forty retained ids, exceeding the admission pool by eight.
    for (let i = 0; i < 2 * BLOCKED_EGRESS_ORIGIN_MAX; i++) {
      admit(r.admissions, candidate(`origin${Math.floor(i / BLOCKED_EGRESS_ORIGIN_MAX)}`, i)); await r.admissions.settled();
    }
    const auditLog = new AuditLog(new MemoryStorage(), KEY);
    const bridge = new UnifiedInboxBridge({ auditLog, identityId: FORTRESS, fortressId: FORTRESS, store: r.store, now: r.clock });
    await bridge.rehydratePendingFromStore();
    const ids = bridge.list().map(e => e.inbox_id);
    const approval = bridge.ingestApproval({ source_event_id: "approval", summary: "Approval", severity: "warn", observed_at: iso(NOW) })!;
    await bridge.flushPersistence();
    return { ...r, bridge, auditLog, ids, approval };
  }

  it("dismisses forty blocked entries and an approval without taking admission reservations", async () => {
    const r = await workflowRig();
    expect(r.ids).toHaveLength(2 * BLOCKED_EGRESS_ORIGIN_MAX);
    expect(r.bridge.dismissBatch([...r.ids, r.approval.inbox_id]).affected).toBe(r.ids.length + 1);
    expect(r.bridge.get(r.approval.inbox_id)?.state).toBe("dismissed");
    await r.bridge.flushPersistence();
    for (const id of r.ids) expect((await r.store.get(id))?.state).toBe("dismissed");
  });

  it("resurfaces forty due snoozes in one scheduler tick without throwing", async () => {
    const r = await workflowRig();
    const until = iso(NOW + 1); // One injected millisecond makes every retained snooze due together.
    for (const id of r.ids) { expect(r.bridge.snoozeBatch([id], until).affected).toBe(1); await r.bridge.flushPersistence(); }
    r.advance(1);
    const scheduler = new UnifiedInboxScheduler({ bridge: r.bridge, now: r.clock });
    expect(scheduler.tick()).toBe(r.ids.length);
    for (const id of r.ids) expect(r.bridge.get(id)?.state).toBe("active");
    await r.bridge.flushPersistence();
  });

  it("coalesces workflow writes by retained id and holds removed slots until settlement", async () => {
    const r = rig(); const a = r.admissions; await a.restore();
    const entry = admit(a, candidate("A", 0)).entry; await a.settled();
    const before = r.calls.write;
    expect(a.update({ ...entry, state: "dismissed" }).kind).toBe("applied");
    expect(a.update({ ...entry, state: "snoozed", snoozed_until: iso(NOW + 1) }).kind).toBe("applied");
    expect(a.stats()).toMatchObject({ reservations: 0, pendingWorkflowWrites: 1 });
    await a.settled(); expect(r.calls.write - before).toBe(1);
    expect((await r.store.get(entry.inbox_id))?.state).toBe("snoozed");
    expect(a.remove(entry.inbox_id).kind).toBe("applied");
    expect(a.stats()).toMatchObject({ retained: 0, pendingWorkflowWrites: 1, reservations: 0 });
    expect(a.stats().encodedBytes).toBeGreaterThan(0);
    await a.settled(); expect(a.stats().encodedBytes).toBe(0);
  });

});
