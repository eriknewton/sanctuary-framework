/**
 * Sanctuary MCP Server — L2 Operational Isolation: Call Governor
 *
 * Runtime governance for proxied tool calls. Wraps the proxy forwarding
 * path with four enforcement mechanisms:
 *
 * 1. Volume limit — sliding-window cap on total tool calls
 * 2. Rate detection — per-tool call frequency check (loop detection)
 * 3. Duplicate detection — SHA-256 hash of tool+args, cache recent results
 * 4. Lifetime counter — hard stop after N total calls per session
 *
 * All state is in-memory. Resets on server restart.
 *
 * Security invariants:
 * - Governor cannot be bypassed — it sits in the enforcement chain
 * - Lifetime limit is a hard stop (requires reset or restart)
 * - Rate escalation triggers Tier 2 human approval
 * - Duplicate cache uses cryptographic hashing (SHA-256)
 */

import { sha256 } from "@noble/hashes/sha256";

// ── Helpers ─────────────────────────────────────────────────────────────

/** Convert a string to UTF-8 bytes */
function strToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** Convert bytes to hex string */
function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i]!.toString(16).padStart(2, "0");
  }
  return hex;
}

/** Compute SHA-256 hex digest of a string */
function sha256Hex(input: string): string {
  return bytesToHex(sha256(strToBytes(input)));
}

// ── Types ───────────────────────────────────────────────────────────────

export interface GovernorConfig {
  /** Total calls allowed in the sliding volume window (default: 200) */
  volume_limit: number;
  /** Volume window size in milliseconds (default: 600000 = 10 min) */
  volume_window_ms: number;
  /** Per-tool calls allowed in the rate window before escalation (default: 20) */
  rate_limit: number;
  /** Rate window size in milliseconds (default: 60000 = 1 min) */
  rate_window_ms: number;
  /** Duplicate cache TTL in milliseconds (default: 60000 = 1 min) */
  duplicate_ttl_ms: number;
  /** Total calls before hard stop for the session (default: 1000) */
  lifetime_limit: number;
  /** Per-server config overrides keyed by server name */
  per_server_overrides?: Record<string, Partial<GovernorConfig>>;
}

export interface GovernorCheckResult {
  /** Whether the call is allowed to proceed */
  allowed: boolean;
  /** Reason the call was blocked or flagged */
  reason?: "volume_exceeded" | "rate_exceeded" | "lifetime_exceeded" | "duplicate_cached";
  /** If duplicate, the cached response */
  cached_result?: unknown;
  /** If true, escalate to Tier 2 (human approval required) */
  escalate?: boolean;
}

export interface GovernorStatus {
  /** Current call count in the volume window */
  volume_current: number;
  /** Volume limit from config */
  volume_limit: number;
  /** Total calls this session */
  lifetime_current: number;
  /** Lifetime limit from config */
  lifetime_limit: number;
  /** Per-tool call count in the current rate window */
  rate_by_tool: Record<string, number>;
  /** Number of entries in the duplicate cache */
  duplicate_cache_size: number;
  /** Whether the governor has been hard-stopped */
  hard_stopped: boolean;
}

// ── Internal Types ──────────────────────────────────────────────────────

interface CachedResult {
  result: unknown;
  expires_at: number;
}

// ── Default Config ──────────────────────────────────────────────────────

const DEFAULT_CONFIG: GovernorConfig = {
  volume_limit: 200,
  volume_window_ms: 600_000,     // 10 minutes
  rate_limit: 20,
  rate_window_ms: 60_000,        // 1 minute
  duplicate_ttl_ms: 60_000,      // 1 minute
  lifetime_limit: 1000,
};

// ── CallGovernor ────────────────────────────────────────────────────────

export class CallGovernor {
  private config: GovernorConfig;

  /** Sliding window of all call timestamps for volume tracking */
  private volumeWindow: number[] = [];

  /** Per-tool sliding window of call timestamps for rate tracking */
  private rateWindows: Map<string, number[]> = new Map();

  /** Duplicate cache: SHA-256(server+tool+args) -> cached result + expiry */
  private duplicateCache: Map<string, CachedResult> = new Map();

  /** Total calls this session */
  private lifetimeCount = 0;

  /** Hard stop flag — set when lifetime limit is reached */
  private hardStopped = false;

  constructor(config?: Partial<GovernorConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Check if a call is allowed and apply governance.
   *
   * Evaluation order:
   * 1. Lifetime limit (hard stop — not recoverable without reset)
   * 2. Volume limit (sliding window)
   * 3. Rate limit per tool (escalates to Tier 2)
   * 4. Duplicate detection (returns cached result)
   */
  check(
    serverName: string,
    toolName: string,
    args: Record<string, unknown>
  ): GovernorCheckResult {
    const now = Date.now();
    const effectiveConfig = this.getEffectiveConfig(serverName);

    // ── 1. Lifetime limit ───────────────────────────────────────────
    if (this.hardStopped) {
      return {
        allowed: false,
        reason: "lifetime_exceeded",
      };
    }

    if (this.lifetimeCount >= effectiveConfig.lifetime_limit) {
      this.hardStopped = true;
      return {
        allowed: false,
        reason: "lifetime_exceeded",
      };
    }

    // ── 2. Volume limit (sliding window) ────────────────────────────
    this.pruneVolumeWindow(now, effectiveConfig.volume_window_ms);

    if (this.volumeWindow.length >= effectiveConfig.volume_limit) {
      return {
        allowed: false,
        reason: "volume_exceeded",
      };
    }

    // ── 3. Rate limit per tool (loop detection) ─────────────────────
    const toolKey = `${serverName}::${toolName}`;
    this.pruneRateWindow(toolKey, now, effectiveConfig.rate_window_ms);

    const rateWindow = this.rateWindows.get(toolKey);
    const currentRate = rateWindow ? rateWindow.length : 0;

    if (currentRate >= effectiveConfig.rate_limit) {
      return {
        allowed: false,
        reason: "rate_exceeded",
        escalate: true,
      };
    }

    // ── 4. Duplicate detection ──────────────────────────────────────
    const callHash = this.computeCallHash(serverName, toolName, args);
    this.pruneDuplicateCache(now);

    const cached = this.duplicateCache.get(callHash);
    if (cached && cached.expires_at > now) {
      return {
        allowed: true,
        reason: "duplicate_cached",
        cached_result: cached.result,
      };
    }

    // ── Call is allowed — record it ─────────────────────────────────
    this.volumeWindow.push(now);

    if (!this.rateWindows.has(toolKey)) {
      this.rateWindows.set(toolKey, []);
    }
    this.rateWindows.get(toolKey)!.push(now);

    this.lifetimeCount++;

    return { allowed: true };
  }

  /**
   * Record a successful call result for duplicate caching.
   */
  recordResult(
    serverName: string,
    toolName: string,
    args: Record<string, unknown>,
    result: unknown
  ): void {
    const callHash = this.computeCallHash(serverName, toolName, args);
    const effectiveConfig = this.getEffectiveConfig(serverName);

    this.duplicateCache.set(callHash, {
      result,
      expires_at: Date.now() + effectiveConfig.duplicate_ttl_ms,
    });
  }

  /**
   * Get current governor status for dashboard display.
   */
  getStatus(): GovernorStatus {
    const now = Date.now();
    this.pruneVolumeWindow(now, this.config.volume_window_ms);
    this.pruneDuplicateCache(now);

    // Build per-tool rate counts
    const rateByTool: Record<string, number> = {};
    for (const [toolKey, timestamps] of this.rateWindows.entries()) {
      const cutoff = now - this.config.rate_window_ms;
      const activeCount = timestamps.filter((t) => t >= cutoff).length;
      if (activeCount > 0) {
        rateByTool[toolKey] = activeCount;
      }
    }

    return {
      volume_current: this.volumeWindow.length,
      volume_limit: this.config.volume_limit,
      lifetime_current: this.lifetimeCount,
      lifetime_limit: this.config.lifetime_limit,
      rate_by_tool: rateByTool,
      duplicate_cache_size: this.duplicateCache.size,
      hard_stopped: this.hardStopped,
    };
  }

  /**
   * Reset all counters (Tier 1 — requires approval).
   * Clears volume window, rate windows, duplicate cache,
   * lifetime counter, and hard stop flag.
   */
  reset(): void {
    this.volumeWindow = [];
    this.rateWindows.clear();
    this.duplicateCache.clear();
    this.lifetimeCount = 0;
    this.hardStopped = false;
  }

  /**
   * Get the effective config for a given server, merging per-server overrides.
   */
  private getEffectiveConfig(serverName: string): GovernorConfig {
    const override = this.config.per_server_overrides?.[serverName];
    if (!override) return this.config;
    return { ...this.config, ...override };
  }

  /**
   * Compute a SHA-256 hash of server + tool + canonical args.
   * Used for duplicate detection.
   */
  private computeCallHash(
    serverName: string,
    toolName: string,
    args: Record<string, unknown>
  ): string {
    // Deterministic serialization of args for consistent hashing
    const stableArgs = this.stableStringify(args);
    const input = `${serverName}\0${toolName}\0${stableArgs}`;
    return sha256Hex(input);
  }

  /**
   * Deterministic JSON serialization with sorted keys.
   */
  private stableStringify(obj: unknown): string {
    if (obj === null || obj === undefined) return "null";
    if (typeof obj !== "object") return JSON.stringify(obj);
    if (Array.isArray(obj)) {
      return "[" + obj.map((item) => this.stableStringify(item)).join(",") + "]";
    }
    const sortedKeys = Object.keys(obj as Record<string, unknown>).sort();
    const pairs = sortedKeys.map(
      (key) =>
        JSON.stringify(key) +
        ":" +
        this.stableStringify((obj as Record<string, unknown>)[key])
    );
    return "{" + pairs.join(",") + "}";
  }

  /**
   * Prune volume window entries older than the window size.
   * Uses shift() from the front — timestamps are appended in order.
   */
  private pruneVolumeWindow(now: number, windowMs: number): void {
    const cutoff = now - windowMs;
    while (this.volumeWindow.length > 0 && this.volumeWindow[0]! < cutoff) {
      this.volumeWindow.shift();
    }
  }

  /**
   * Prune a per-tool rate window.
   */
  private pruneRateWindow(
    toolKey: string,
    now: number,
    windowMs: number
  ): void {
    const window = this.rateWindows.get(toolKey);
    if (!window) return;
    const cutoff = now - windowMs;
    while (window.length > 0 && window[0]! < cutoff) {
      window.shift();
    }
    // Clean up empty windows
    if (window.length === 0) {
      this.rateWindows.delete(toolKey);
    }
  }

  /**
   * Prune expired entries from the duplicate cache.
   * Amortized O(1) — only prunes when cache exceeds a size threshold.
   */
  private pruneDuplicateCache(now: number): void {
    // Only prune when cache is large enough to justify the scan
    if (this.duplicateCache.size < 100) return;

    for (const [key, entry] of this.duplicateCache) {
      if (entry.expires_at <= now) {
        this.duplicateCache.delete(key);
      }
    }
  }
}
