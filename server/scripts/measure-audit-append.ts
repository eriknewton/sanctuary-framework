/** Reproducible synthetic pre-population and real durable append measurement. */
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { AuditLog, type AuditLogConfig, type AuditEntryInput } from "../src/operational/audit-log.js";
import { FilesystemStorage } from "../src/storage/filesystem.js";
import type { StorageBackend, StorageEntryMeta } from "../src/storage/interface.js";

// A deterministic, non-secret fixture key, sized for AES-256.
export const MEASURE_MASTER_KEY = new Uint8Array(32).fill(7);
export const MEASURE_CONFIG: AuditLogConfig = {
  checkpointInterval: 0,
  checkpointSigner: async () => null,
  maxEntries: Number.MAX_SAFE_INTEGER,
  maxTotalSizeBytes: Number.MAX_SAFE_INTEGER,
  // Keep a small recent window while generating the large persisted chain.
  maxInMemoryEntries: 100,
};
export function measureEntry(index: number, padding = ""): AuditEntryInput {
  return { layer: "l2", operation: "append_measurement", identity_id: "fixture",
    result: "success", details: { index, padding } };
}

/**
 * Synthetic generator only: real AuditLog envelopes/anchors, tail-only discovery,
 * plain writes for unit fixtures, durable writes for the command-line benchmark.
 * A strict cold load over the unwrapped store must pass before use.
 */
export async function prepopulateAudit(
  path: string, count: number,
  Log: typeof AuditLog = AuditLog,
  Storage: typeof FilesystemStorage = FilesystemStorage,
  durableWrites = false,
): Promise<{ storage: FilesystemStorage; coldLoadMs: number }> {
  const storage = new Storage(path);
  let tail: StorageEntryMeta | undefined;
  const created = new Set<string>();
  const synthetic: StorageBackend = {
    async write(namespace, key, data) {
      // These are code-owned AuditLog fixture keys. Refuse unexpected path
      // components instead of silently changing the real storage key encoding.
      if (!/^[\w-]+$/.test(namespace) || !/^[\w-]+$/.test(key)) throw new Error("unexpected generator key");
      if (!created.has(namespace)) {
        await mkdir(join(path, namespace), { recursive: true, mode: 0o700 });
        created.add(namespace);
      }
      if (durableWrites) await storage.writeDurable(namespace, key, data);
      else await writeFile(join(path, namespace, `${key}.enc`), data, { mode: 0o600 });
      if (namespace === "_audit") tail = { namespace, key, size_bytes: data.length, modified_at: new Date().toISOString() };
    },
    read: storage.read.bind(storage), delete: storage.delete.bind(storage),
    exists: storage.exists.bind(storage), totalSize: storage.totalSize.bind(storage),
    async list(namespace, prefix) {
      if (namespace !== "_audit") return storage.list(namespace, prefix);
      return tail && (!prefix || tail.key.startsWith(prefix)) ? [tail] : [];
    },
    async listKeys(namespace, prefix) {
      return (await this.list(namespace, prefix)).map((meta) => meta.key);
    },
  };
  const generator = new Log(synthetic, MEASURE_MASTER_KEY, MEASURE_CONFIG);
  for (let index = 0; index < count; index++) await generator.appendCritical(measureEntry(index));
  const started = performance.now();
  const verifier = new Log(storage, MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, readOnly: true });
  let verifiedCount = 0;
  await verifier.streamVerifiedChain({ onEntry: () => { verifiedCount++; }, reset: () => { verifiedCount = 0; } });
  if (verifiedCount !== count) throw new Error("synthetic cold load did not verify completely");
  return { storage, coldLoadMs: performance.now() - started };
}

/** Count storage calls at the production boundary without hiding optional methods. */
export function countedStorage(storage: FilesystemStorage): {
  storage: FilesystemStorage; calls: Map<string, number>; reset(): void;
} {
  const calls = new Map<string, number>();
  return {
    calls, reset: () => calls.clear(),
    storage: new Proxy(storage, {
      get(target, name) {
        const value = Reflect.get(target, name);
        if (typeof value !== "function") return value;
        return (...args: unknown[]) => {
          const call = `${String(name)}:${String(args[0])}`;
          calls.set(call, (calls.get(call) ?? 0) + 1);
          return value.apply(target, args);
        };
      },
    }),
  };
}

// The command runner is intentionally isolated from the exported fixture helpers.
// Run with node --expose-gc --import tsx scripts/measure-audit-append.ts <label> <source-server>.
async function main(): Promise<void> {
  const fs = (await import("node:fs/promises")).default;
  const fsCallback = (await import("node:fs")).default;
  const { syncBuiltinESMExports } = await import("node:module");
  const { pathToFileURL } = await import("node:url");
  const { tmpdir } = await import("node:os");
  const { basename, resolve } = await import("node:path");
  const { PerformanceObserver } = await import("node:perf_hooks");
  const [label = "candidate", sourceServer = resolve(".")] = process.argv.slice(2);
  const sandbox = await fs.mkdtemp(join(tmpdir(), "audit-append-measure-"));
  const previousHome = process.env.HOME;
  process.env.HOME = sandbox;
  process.env.SANCTUARY_STORAGE_PATH = join(sandbox, "state");
  type Sample = {
    ms: number; readdir_ms: number; decode_ms: number; sort_ms: number;
    key_strings: number; key_array_length: number; gc_ms: number; fsync: number; filehandle_sync: number;
    sized_listings: number; names_listings: number; readdirs: number;
    stat_ms: number; prune_ms: number; deleted: number;
  };
  const empty = (): Sample => ({ key_array_length: 0, ms: 0, readdir_ms: 0, decode_ms: 0, sort_ms: 0, key_strings: 0,
    gc_ms: 0, fsync: 0, filehandle_sync: 0, sized_listings: 0, names_listings: 0,
    readdirs: 0, stat_ms: 0, prune_ms: 0, deleted: 0 });
  let sample: Sample | undefined;
  let listing = false;
  const original = { readdir: fs.readdir, stat: fs.stat, open: fs.open, fsync: fsCallback.fsync, sort: Array.prototype.sort };
  fs.readdir = (async (...args: any[]) => {
    const started = performance.now();
    const result = await (original.readdir as any)(...args);
    const active = sample;
    if (active && basename(String(args[0])) === "_audit") {
      active.readdir_ms += performance.now() - started; active.readdirs++;
      if (listing) {
        // Time the actual decode/filter loop. Base list awaits stat per item;
        // subtract those measured awaits so decode is not mislabeled stat time.
        const iterate = result[Symbol.iterator].bind(result);
        result[Symbol.iterator] = function* () {
          const began = performance.now(); const statsBefore = active.stat_ms;
          try {
            for (const name of iterate()) {
              if (typeof name === "string" && name.endsWith(".enc")) active.key_strings++;
              yield name;
            }
          } finally { active.decode_ms += Math.max(0, performance.now() - began - (active.stat_ms - statsBefore)); }
        };
      }
    }
    return result;
  }) as typeof fs.readdir;
  fs.stat = (async (...args: any[]) => {
    const started = performance.now();
    try { return await (original.stat as any)(...args); }
    finally { if (sample && String(args[0]).includes("/_audit/")) sample.stat_ms += performance.now() - started; }
  }) as typeof fs.stat;
  fs.open = (async (...args: any[]) => {
    const handle = await (original.open as any)(...args);
    const sync = handle.sync.bind(handle);
    handle.sync = async () => { if (sample) sample.filehandle_sync++; return sync(); };
    return handle;
  }) as typeof fs.open;
  fsCallback.fsync = ((...args: any[]) => { if (sample) sample.fsync++; return (original.fsync as any)(...args); }) as typeof fsCallback.fsync;
  Array.prototype.sort = function (compare?: any) {
    const first = this[0];
    const auditKeys = typeof first === "string" ? first.startsWith("entry-") : first?.key?.startsWith("entry-");
    const started = performance.now();
    try { return original.sort.call(this, compare); }
    finally { if (sample && auditKeys) sample.sort_ms += performance.now() - started; }
  };
  syncBuiltinESMExports();
  const observer = new PerformanceObserver((entries) => {
    if (sample) for (const entry of entries.getEntries()) sample.gc_ms += entry.duration;
  });
  observer.observe({ entryTypes: ["gc"] });
  try {
    const { AuditLog: Log } = await import(pathToFileURL(join(sourceServer, "src/operational/audit-log.ts")).href) as { AuditLog: typeof AuditLog };
    const { FilesystemStorage: Storage } = await import(pathToFileURL(join(sourceServer, "src/storage/filesystem.ts")).href) as { FilesystemStorage: typeof FilesystemStorage };
    for (const method of ["list", "listKeys"] as const) {
      const operation = Storage.prototype[method];
      if (typeof operation !== "function") continue;
      (Storage.prototype as any)[method] = async function (...args: any[]) {
        const active = sample;
        if (active && args[0] === "_audit") {
          if (method === "list") active.sized_listings++; else active.names_listings++;
          listing = true;
        }
        try {
          const result = await (operation as any).apply(this, args);
          if (active && args[0] === "_audit") active.key_array_length = Math.max(active.key_array_length, result.length);
          return result;
        } finally { listing = false; }
      };
    }
    const remove = Storage.prototype.delete;
    Storage.prototype.delete = async function (...args) {
      const result = await remove.apply(this, args);
      if (sample && args[0] === "_audit" && result) sample.deleted++;
      return result;
    };
    const rotate = (Log.prototype as any).maybeRotate;
    (Log.prototype as any).maybeRotate = async function (...args: any[]) {
      const start = performance.now(); const active = sample; const deletedBefore = active?.deleted ?? 0;
      try { return await rotate.apply(this, args); }
      finally { if (active && active.deleted > deletedBefore) active.prune_ms += performance.now() - start; }
    };
    const quantile = (values: number[], fraction: number) => [...values].sort((a, b) => a - b)[Math.min(values.length - 1, Math.floor(values.length * fraction))]!;
    // Three growth-phase samples and 2,100 durable cap appends cross the
    // default 1,000-entry hysteresis twice after synthetic population 100,000.
    const scenarios = [
      { population: 1_000, appends: 100, cap: false },
      { population: 10_000, appends: 100, cap: false },
      { population: 100_000, appends: 100, cap: false },
      { population: 100_000, appends: 2_100, cap: true },
    ];
    process.stdout.write(JSON.stringify({ type: "method", label, sourceServer, node: process.version,
      platform: process.platform, sandbox, synthetic: true, durability: true, synthetic_durable_writes: true,
      uv_threadpool_size: process.env.UV_THREADPOOL_SIZE ?? "default", expose_gc: typeof global.gc === "function" }) + "\n");
    for (const scenario of scenarios) {
      const path = join(sandbox, `${scenario.population}-${scenario.cap ? "cap" : "growth"}`);
      const generatedAt = performance.now();
      const generated = await prepopulateAudit(path, scenario.population, Log, Storage, true);
      const writer = new Log(generated.storage, MEASURE_MASTER_KEY, {
        ...MEASURE_CONFIG, ...(scenario.cap ? { maxEntries: scenario.population } : {}),
      });
      await writer.query({ limit: 1 });
      global.gc?.();
      await new Promise((resolve) => setImmediate(resolve));
      process.stdout.write(JSON.stringify({ type: "seed", label, ...scenario, cold_load_ms: generated.coldLoadMs,
        preparation_ms: performance.now() - generatedAt }) + "\n");
      const samples: Sample[] = [];
      for (let index = 0; index < scenario.appends; index++) {
        sample = empty(); const started = performance.now();
        await writer.appendCritical(measureEntry(scenario.population + index));
        sample.ms = performance.now() - started;
        await new Promise((resolve) => setImmediate(resolve));
        samples.push(sample);
        process.stdout.write(JSON.stringify({ type: "append", label, population: scenario.population, cap: scenario.cap, index, ...sample }) + "\n");
        sample = undefined;
      }
      const times = samples.map((value) => value.ms);
      process.stdout.write(JSON.stringify({ type: "summary", label, ...scenario, cold_load_ms: generated.coldLoadMs,
        p50_ms: quantile(times, 0.5), p99_ms: quantile(times, 0.99), max_ms: Math.max(...times),
        totals: samples.reduce((acc, value) => { for (const key of Object.keys(value) as Array<keyof Sample>) acc[key] += value[key]; return acc; }, empty()),
      }) + "\n");
      await fs.rm(path, { recursive: true, force: true });
    }
  } finally {
    sample = undefined; observer.disconnect();
    Object.assign(fs, { readdir: original.readdir, stat: original.stat, open: original.open });
    fsCallback.fsync = original.fsync; Array.prototype.sort = original.sort; syncBuiltinESMExports();
    if (previousHome === undefined) delete process.env.HOME; else process.env.HOME = previousHome;
    await fs.rm(sandbox, { recursive: true, force: true });
  }
}

const invoked = process.argv[1]?.endsWith("/measure-audit-append.ts");
if (invoked) await main();
