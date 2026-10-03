/** Internal process-local response budgets; not a transport or fortress quota. */
export const RESPONSE_LIMITS = Object.freeze({
  CONTENT_UTF8_BYTES: 1_000_000, // One decimal MB per canonical/delivered response.
  MAX_DEPTH: 32, // Bounded JSON recursion, including metadata.
  MAX_NODES: 4096, // Bounds object/array traversal independently of text size.
  MAX_BLOCKS: 256, // Bounds normalized block metadata.
  NORMALIZE_BLOCK_UTF16: 100_000, // Existing proxy block truncation contract.
  NORMALIZE_TOTAL_UTF16: 1_000_000, // Existing proxy normalization contract.
  MAX_CANDIDATES: 64, // Must match INJECTION_MAX_DECODED_RESCANS in security/injection-detector.ts.
  MAX_SIGNALS: 64, // Bounded findings, enforced at insertion.
  SCAN_MS: 100, // Monotonic scan deadline, excluding worker startup canary.
  STARTUP_MS: 5000, // Worker bootstrap deadline; no payload is sent before readiness.
  ACTIVE_PER_SESSION: 2, // One session cannot consume the process budget.
  ACTIVE_PER_PROCESS: 8, // Includes detached work until settlement.
  RUNTIME_SLOTS: 128, // Detailed exposure records; overflow shares the unknown bucket.
  UNKNOWN_SLOTS: 1, // Fixed unknown bucket, always tainted.
  IDLE_MS: 30 * 60 * 1000, // Thirty idle minutes before inactive record eviction.
  CACHE_ENTRIES: 8, // Shared LRU across governor instances.
  CACHE_UTF8_BYTES: 8 * 1_000_000, // Eight decimal MB including keys/metadata.
  MAX_RESPONSE_COPIES: 4, // Canonical, normalized, joined and worker input.
  WORKER_HEAP_MB: 64, // V8 old-generation limit for detector scratch and object overhead.
  WORKER_YOUNG_MB: 8, // Small nursery within each admitted worker.
});
