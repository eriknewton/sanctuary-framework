import { RESPONSE_LIMITS as L } from "./response-limits.js";
import { responseJsonBytes } from "./response-bounds.js";

interface Entry { owner: symbol; key: string; result: unknown; expires_at: number; bytes: number }
// Must share accounting across ESM/CJS copies just like processResponseController in response-runtime.ts.
const CACHE_KEY = Symbol.for("sanctuary.content-ingress.cache");
const cacheRegistry = globalThis as unknown as Record<symbol, Entry[] | undefined>;
const entries = cacheRegistry[CACHE_KEY] ??= [];
const CACHE_METADATA_BYTES = 256; // Conservative fixed allowance for owner, expiry and entry bookkeeping.

/** Process-shared LRU; governor identities consume no separate retained registry. */
export const responseCache = {
  get(owner: symbol, key: string, now: number): unknown {
    this.prune(now);
    const index = entries.findIndex(e => e.owner === owner && e.key === key);
    if (index < 0) return undefined;
    const [entry] = entries.splice(index, 1);
    entries.push(entry!);
    return entry!.result;
  },
  set(owner: symbol, key: string, result: unknown, expires_at: number): void {
    let bytes: number;
    try { bytes = responseJsonBytes(result) + Buffer.byteLength(key) + CACHE_METADATA_BYTES; }
    catch { return; } // Cache pressure cannot substitute for or disable response screening.
    this.prune(Date.now());
    const prior = entries.findIndex(e => e.owner === owner && e.key === key);
    if (prior >= 0) entries.splice(prior, 1);
    if (bytes > L.CACHE_UTF8_BYTES) return;
    // Reserve before retaining the object; accounting includes keys and metadata across instances.
    while (entries.length >= L.CACHE_ENTRIES || this.bytes() + bytes > L.CACHE_UTF8_BYTES) entries.shift();
    entries.push({ owner, key, result, expires_at, bytes });
  },
  clear(owner: symbol): void {
    for (let i = entries.length - 1; i >= 0; i--) if (entries[i]!.owner === owner) entries.splice(i, 1);
  },
  size(owner: symbol): number { return entries.filter(e => e.owner === owner).length; },
  bytes(): number { return entries.reduce((n, e) => n + e.bytes, 0); },
  prune(now: number): void {
    for (let i = entries.length - 1; i >= 0; i--) if (entries[i]!.expires_at <= now) entries.splice(i, 1);
  },
};
