import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { AuditLog, AUDIT_ROTATION_MARGIN_FRACTION } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { countedStorage, MEASURE_CONFIG, MEASURE_MASTER_KEY, measureEntry, prepopulateAudit } from "../../scripts/measure-audit-append.js";

vi.mock("node:fs/promises", async (original) => {
  const actual = await original<typeof import("node:fs/promises")>();
  return { ...actual, stat: vi.fn(actual.stat), readdir: vi.fn(actual.readdir) };
});

let root: string;
beforeEach(async () => {
  root = await fs.mkdtemp(join(tmpdir(), "audit-listing-"));
  vi.stubEnv("HOME", root);
});
afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  await fs.rm(root, { recursive: true, force: true });
});

function auditFileStats(): number {
  return vi.mocked(fs.stat).mock.calls.filter(([path]) => String(path).includes("/_audit/") && String(path).endsWith(".enc")).length;
}
function directoryReads(path: string): number {
  return vi.mocked(fs.readdir).mock.calls.filter(([value]) => String(value) === path).length;
}

describe("append listing work", () => {
  it("uses one names-only read, no entry stats, and identical exact-key calls at 1k and 10k", async () => {
    const exactCalls: Array<Array<[string, number]>> = [];
    // One decade of growth makes an accidentally retained per-entry call visible.
    for (const population of [1_000, 10_000]) {
      const path = join(root, String(population));
      await prepopulateAudit(path, population - 1);
      const counted = countedStorage(new FilesystemStorage(path));
      const log = new AuditLog(counted.storage, MEASURE_MASTER_KEY, MEASURE_CONFIG);
      await log.appendCritical(measureEntry(population - 1));
      // The first write also sweeps stale lock temporaries once per instance;
      // this assertion measures the requested steady append at the named size.
      counted.reset(); vi.mocked(fs.stat).mockClear(); vi.mocked(fs.readdir).mockClear();
      await log.appendCritical(measureEntry(population));
      // Witness: restoring storage.list in freshen fails these call assertions.
      expect(counted.calls.get("list:_audit") ?? 0).toBe(0);
      expect(counted.calls.get("listKeys:_audit")).toBe(1);
      expect(auditFileStats()).toBe(0);
      expect(directoryReads(join(path, "_audit"))).toBe(1);
      exactCalls.push([...counted.calls].filter(([name]) => !name.startsWith("list")).sort());
    }
    expect(exactCalls[0]).toEqual(exactCalls[1]);
  }, 120_000); // Two strict cold loads plus 11,000 synthetic writes on CI disks.

  it("amortizes the sized recount over two hysteresis windows", async () => {
    const cap = 200; // Two-entry hysteresis exercises two prunes in four appends.
    const hysteresis = Math.max(1, Math.floor(cap * AUDIT_ROTATION_MARGIN_FRACTION));
    const path = join(root, "cap");
    await prepopulateAudit(path, cap);
    const counted = countedStorage(new FilesystemStorage(path));
    const log = new AuditLog(counted.storage, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, maxEntries: cap });
    await log.query({ limit: 1 }); counted.reset();
    for (let index = 0; index < 2 * hysteresis; index++) {
      await log.appendCritical(measureEntry(cap + index));
      const retained = (await fs.readdir(join(path, "_audit"))).filter((name) => name.endsWith(".enc")).length;
      expect(retained).toBeGreaterThanOrEqual(1); // A byte-bound prune may retain fewer than the count target.
      expect(retained).toBeLessThanOrEqual(cap);
    }
    expect(counted.calls.get("list:_audit")).toBe(2);
    expect(counted.calls.get("listKeys:_audit")).toBe(2 * hysteresis);
  });

  it("recounts exact bytes after a count-neutral foreign append and prune", async () => {
    const path = join(root, "foreign");
    await prepopulateAudit(path, 3);
    const raw = new FilesystemStorage(path);
    const counted = countedStorage(raw);
    const a = new AuditLog(counted.storage, MEASURE_MASTER_KEY, MEASURE_CONFIG);
    const b = new AuditLog(raw, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, maxEntries: 3 });
    await a.query({ limit: 1 });
    await b.query({ limit: 1 });
    // Make B's prune count-neutral: cap 3 prunes two entries, then refill one.
    await b.appendCritical(measureEntry(3, "larger".repeat(100)));
    await b.appendCritical(measureEntry(4, "larger".repeat(100)));
    expect(await raw.listKeys("_audit")).toHaveLength(3);
    counted.reset();
    await a.appendCritical(measureEntry(5));
    // Witness: count-only comparison misses B's changed lowest and highest keys.
    expect(counted.calls.get("list:_audit")).toBe(1);
    const exact = await raw.list("_audit");
    expect((a as any).retainedBytesEstimate).toBe(exact.reduce((sum, meta) => sum + meta.size_bytes, 0));
    expect((a as any).retainedCountExpected).toBe(exact.length);
    expect((a as any).bytesProvenance).toBe("seeded");
  });

  it("enforces the byte cap after count-neutral foreign activity stops", async () => {
    const path = join(root, "foreign-bytes");
    await prepopulateAudit(path, 3);
    const raw = new FilesystemStorage(path);
    const counted = countedStorage(raw);
    const initial = await raw.list("_audit");
    // Two small-entry sizes of headroom make A's stale estimate fit while B's
    // larger entries exceed it; a names signature must force authoritative bytes.
    const byteCap = initial.reduce((sum, meta) => sum + meta.size_bytes, 0) + 2 * initial[0]!.size_bytes;
    const a = new AuditLog(counted.storage, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, maxTotalSizeBytes: byteCap });
    const b = new AuditLog(raw, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, maxEntries: 3 });
    await a.query({ limit: 1 });
    await b.query({ limit: 1 });
    for (let index = 3; index < 5; index++) await b.appendCritical(measureEntry(index, "x".repeat(byteCap)));
    expect(await raw.list("_audit")).toHaveLength(initial.length);
    counted.reset();
    await a.appendCritical(measureEntry(5));
    expect(counted.calls.get("list:_audit")).toBe(1);
    const survivors = await raw.list("_audit");
    const total = survivors.reduce((sum, meta) => sum + meta.size_bytes, 0);
    expect(total).toBeLessThanOrEqual(byteCap);
    expect((a as any).retainedBytesEstimate).toBe(total);
  });

  it("observes a post-lock foreign handoff at most one own append late", async () => {
    const path = join(root, "handoff");
    await prepopulateAudit(path, 3);
    const raw = new FilesystemStorage(path);
    const counted = countedStorage(raw);
    const initial = await raw.list("_audit");
    const byteCap = initial.reduce((sum, meta) => sum + meta.size_bytes, 0) + 2 * initial[0]!.size_bytes;
    const a = new AuditLog(counted.storage, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, maxTotalSizeBytes: byteCap });
    const b = new AuditLog(raw, MEASURE_MASTER_KEY, MEASURE_CONFIG);
    await a.query({ limit: 1 }); await b.query({ limit: 1 }); counted.reset();
    const rotate = (a as any).maybeRotate.bind(a);
    let handoff = true;
    vi.spyOn(a as any, "maybeRotate").mockImplementation(async (...args) => {
      // maybeRotate starts only after A releases its real filesystem lock.
      if (handoff) { handoff = false; await b.appendCritical(measureEntry(4, "x".repeat(byteCap))); }
      return rotate(...args);
    });
    await a.appendCritical(measureEntry(3));
    expect(counted.calls.get("list:_audit") ?? 0).toBe(0);
    expect((await raw.list("_audit")).reduce((sum, meta) => sum + meta.size_bytes, 0)).toBeGreaterThan(byteCap);
    counted.reset(); await a.appendCritical(measureEntry(5));
    expect(counted.calls.get("list:_audit")).toBe(1);
    expect((await raw.list("_audit")).reduce((sum, meta) => sum + meta.size_bytes, 0)).toBeLessThanOrEqual(byteCap);
  });
});
