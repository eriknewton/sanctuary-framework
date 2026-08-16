/**
 * Sanctuary v1.3 WP-V1.3-5 Pi-3 Tool-call trap runtime.
 *
 * Server-local MCP catalog injection for fake honeypot tools. The
 * runtime reads deployed TrapSpecs from the per-fortress TrapRegistry,
 * injects visible tool_call traps into list_tools, and intercepts
 * calls to those fake tool names before regular tool dispatch.
 */

import { createHash } from "node:crypto";

import type { AuditLog } from "../operational/audit-log.js";
import type { SentinelFindingStore } from "../sentinel/sentinel-finding-store.js";
import type { SentinelFinding } from "../sentinel/types.js";
import type { ToolDefinition } from "../router.js";
import { BoundedMap } from "../core/bounded-map.js";

import { TrapRegistry } from "./trap-registry.js";
import {
  HONEYPOT_AUDIT_OPS,
  honeypotSentinelId,
  type ToolCallTrigger,
  type TrapSpec,
} from "./types.js";

export interface ToolCallTrapRuntimeDeps {
  registry: TrapRegistry;
  findingStore: SentinelFindingStore;
  auditLog: AuditLog;
  operatorId: string;
  fortressId: string;
  now?: () => Date;
}

export interface ToolCallInvocation {
  trap_id: string;
  fake_tool_name: string;
  caller_identity: string;
  // HNY-01: a byte-capped preview of the invocation args, never the raw
  // attacker object. `arg_bytes` is the true serialized size; `arg_truncated`
  // marks that the preview omits content beyond MAX_RETAINED_ARG_BYTES.
  invocation_args: Record<string, unknown>;
  arg_hash: string;
  arg_bytes: number;
  arg_truncated: boolean;
  invoked_at: string;
  finding_id: string;
  fake_response: string | Record<string, unknown>;
  response_plausibility: "operator_configured_fake_response";
  follow_up_tool_calls: ToolCallFollowUp[];
}

export interface ToolCallFollowUp {
  tool_name: string;
  caller_identity: string;
  // HNY-01: byte-capped preview, matching ToolCallInvocation.invocation_args.
  args: Record<string, unknown>;
  args_hash: string;
  args_bytes: number;
  args_truncated: boolean;
  called_at: string;
}

export interface ToolCallTrapStats {
  trap_id: string;
  fake_tool_name: string;
  catalog_visibility: ToolCallTrigger["catalog_visibility"];
  visible_to_agents?: string[];
  invocation_count: number;
  last_invocation_at: string | null;
  caller_diversity: number;
  activations: ToolCallInvocation[];
}

// 5 minutes is the product follow-up window already emitted in findings and audit.
export const FOLLOW_UP_WINDOW_MS = 5 * 60 * 1000;
// 128 retained activations allows four fully capped callers in one 5-minute window.
export const MAX_RETAINED_ACTIVATIONS_PER_TRAP = 128;
// 32 activations per caller preserves a burst of probes while bounding one caller.
export const MAX_ACTIVATIONS_PER_CALLER_PER_TRAP = 32;
// 16 follow-ups captures a realistic post-probe sequence without NxM audit growth.
export const MAX_FOLLOW_UP_TOOL_CALLS_PER_ACTIVATION = 16;

/**
 * CLASS-LEVEL durable-write coalescing (register Z-HNY-02, AGENTS.md rule 8
 * step 3): before this fix, EVERY trap invocation minted a fresh `finding_id`
 * and wrote a new durable SentinelFinding, so the honeypot's OWN in-memory
 * caps (above) bounded correlation-buffer memory but not durable-store
 * growth — a visible agent flooding one trap drove unbounded finding-store
 * rows, and the periodic anomaly-trigger sentinel then rescans the whole
 * store on every tick (sentinel/sentinels/anomaly-trigger.ts), turning
 * attacker-driven finding count into a self-inflicted decrypt-amplification
 * DoS. Coalescing keeps the FIRST finding per (trap_id, caller_identity) per
 * FOLLOW_UP_WINDOW_MS and updates it in place for subsequent invocations in
 * the same window, so durable growth is O(traps x callers) — bounded by
 * operator-provisioned trap count and observed caller diversity — instead of
 * O(invocations). The signal is preserved, not lost: "trap X hit 40,000
 * times by agent Y" is exactly what `details.repeat_count` on one row says,
 * which is MORE useful to an operator than 40,000 near-identical rows.
 */
export const MAX_DISTINCT_ARG_HASHES_PER_COALESCED_FINDING = 8;
/**
 * Bounds the (trap_id, caller_identity) coalescing tracker itself — it is
 * its own small attacker-influenceable map (caller_identity is derived from
 * the calling agent's identity, not raw request input, but is still
 * per-session data, not an operator-fixed set). Swept alongside
 * `activations` (see pruneExpiredCoalescedWindows), so under normal
 * operation this stays near (deployed trap count x live caller count); the
 * cap is a backstop against a caller-identity churn burst outrunning the
 * sweep between two invocations. 2048 mirrors the honeypot's other caps'
 * order of magnitude: generous for a real fortress, small enough to bound
 * worst-case memory.
 */
export const MAX_COALESCED_FINDING_WINDOWS = 2048;

/** State the coalescing tracker keeps per (trap_id, caller_identity). */
interface CoalescedFindingWindow {
  finding_id: string;
  /** Epoch ms when this window's finding_id was first minted. */
  window_started_at: number;
  first_observed_at: string;
  repeat_count: number;
  distinct_arg_hashes: string[];
}

function coalescedWindowKey(trapId: string, callerIdentity: string): string {
  // JSON-encode rather than string-concatenate: trap_id and caller_identity
  // are both attacker-influenceable strings, and a plain separator (e.g.
  // "::") could let two distinct (trap, caller) pairs collide on the same
  // key if either value happens to contain the separator.
  return JSON.stringify([trapId, callerIdentity]);
}

/**
 * Deterministic finding_id for a (trap, caller, time-bucket) triple
 * (register Z-HNY-02 RECHECK / rule 8 atomicity fix — see the doc above
 * `runExclusive`). The bucket is an ID-candidate domain, not the product's
 * window boundary: `invokeIfTrap` also checks the preceding bucket and the
 * stored `first_observed_at` so a rolling five-minute window survives an
 * epoch-aligned boundary and process-local cache loss. sha256 (not
 * randomUUID) precisely because concurrent callers must converge on the
 * same id candidate instead of minting a fresh value per call.
 */
function deterministicCoalescedFindingId(
  trapId: string,
  callerIdentity: string,
  windowBucket: number,
): string {
  return createHash("sha256")
    .update(JSON.stringify(["coalesced-finding-v1", trapId, callerIdentity, windowBucket]), "utf8")
    .digest("hex");
}

export class ToolCallTrapRuntime {
  private readonly registry: TrapRegistry;
  private readonly findingStore: SentinelFindingStore;
  private readonly auditLog: AuditLog;
  private readonly operatorId: string;
  private readonly fortressId: string;
  private readonly now: () => Date;
  private readonly activations = new Map<string, ToolCallInvocation[]>();
  // Per-(trap, caller) mutex chain (register Z-HNY-02 RECHECK, rule 8
  // atomicity fix). Self-cleaning: an entry exists ONLY while a call for
  // that key is in flight — `runExclusive` deletes it the moment the last
  // queued call finishes — so this is never itself an unbounded
  // attacker-writable collection; it is bounded by concurrent in-flight
  // request count, not by cumulative (trap, caller) pairs ever seen.
  private readonly windowLocks = new Map<string, Promise<void>>();
  // See MAX_COALESCED_FINDING_WINDOWS. Evict-oldest on capacity: losing a
  // tracker entry is safe because the next invocation recovers the current
  // or preceding deterministic candidate from the durable store and checks
  // its actual first-observed time. The map is a cache, never the authority,
  // so a simple oldest-first policy is sufficient.
  private readonly activeFindingWindows = new BoundedMap<
    string,
    CoalescedFindingWindow
  >({
    maxSize: MAX_COALESCED_FINDING_WINDOWS,
    selectEviction: (entries) => {
      const oldest = entries.keys().next();
      if (oldest.done) return { refuse: true };
      return { evict: oldest.value };
    },
  });

  constructor(deps: ToolCallTrapRuntimeDeps) {
    this.registry = deps.registry;
    this.findingStore = deps.findingStore;
    this.auditLog = deps.auditLog;
    this.operatorId = deps.operatorId;
    this.fortressId = deps.fortressId;
    this.now = deps.now ?? (() => new Date());
  }

  listCatalogTools(agentId?: string): ToolDefinition[] {
    const tools: ToolDefinition[] = [];
    for (const spec of this.toolCallSpecs()) {
      const trigger = spec.trigger;
      if (!isVisibleToAgent(trigger, agentId)) continue;
      tools.push({
        name: trigger.fake_tool_name,
        description: trigger.fake_tool_description,
        inputSchema: trigger.fake_tool_schema,
        handler: async () => ({ content: [] }),
      });
    }
    return tools;
  }

  async invokeIfTrap(
    toolName: string,
    args: Record<string, unknown>,
    callerIdentity: string,
  ): Promise<{ handled: false } | { handled: true; response: unknown }> {
    const now = this.now();
    this.pruneExpiredActivations(now);
    this.pruneExpiredCoalescedWindows(now);

    const spec = this.toolCallSpecs().find(
      (candidate) => candidate.trigger.fake_tool_name === toolName,
    );
    if (!spec) return { handled: false };

    const trigger = spec.trigger;
    if (!isVisibleToAgent(trigger, callerAgentId(callerIdentity))) {
      return { handled: false };
    }

    const boundedArgs = hashAndBoundArgs(args);
    const argHash = boundedArgs.hash;

    // Coalescing (register Z-HNY-02 RECHECK — atomicity fix). The ENTIRE
    // read-decide-persist-update sequence below runs inside ONE
    // `runExclusive` call, which fully serializes every `invokeIfTrap`
    // sharing this windowKey end to end — see that method's doc for why the
    // ORIGINAL code (read the tracker, decide, THEN `await saveFinding`,
    // THEN write the tracker) let two overlapping calls both observe "no
    // window" and each mint an independent finding_id for what should
    // coalesce into ONE durable row: the gap wasn't the read, it was
    // everything between the read and the final tracker write having an
    // `await` in the middle with no lock around it.
    const windowKey = coalescedWindowKey(spec.trap_id, callerIdentity);
    const nowMs = now.getTime();
    const windowBucket = Math.floor(nowMs / FOLLOW_UP_WINDOW_MS);
    // Deterministic, not random: concurrent calls compute the same current
    // candidate. The previous candidate is also checked inside the lock so
    // an existing rolling window survives crossing an aligned bucket edge.
    const currentFindingId = deterministicCoalescedFindingId(
      spec.trap_id,
      callerIdentity,
      windowBucket,
    );
    const previousFindingId = deterministicCoalescedFindingId(
      spec.trap_id,
      callerIdentity,
      windowBucket - 1,
    );

    return this.runExclusive(windowKey, async () => {
      // Ground truth is the DURABLE store, never just the in-memory
      // tracker: the tracker is a cache that can be capacity-evicted
      // (MAX_COALESCED_FINDING_WINDOWS) or lost on restart. The current and
      // preceding deterministic bucket candidates cover every possible
      // live rolling window; `first_observed_at` decides whether a candidate
      // is still live. Recover repeat_count/first_observed_at/
      // distinct_arg_hashes from the store rather than treating cache loss
      // or an aligned bucket edge as a brand-new observation.
      const existingWindow = this.activeFindingWindows.get(windowKey);
      let findingId = currentFindingId;
      let windowStartedAt = nowMs;
      let groundTruth:
        | { repeat_count: number; first_observed_at: string; distinct_arg_hashes: string[] }
        | undefined;
      const existingAge = existingWindow
        ? nowMs - existingWindow.window_started_at
        : Number.POSITIVE_INFINITY;
      if (
        existingWindow &&
        existingAge >= 0 &&
        existingAge <= FOLLOW_UP_WINDOW_MS
      ) {
        findingId = existingWindow.finding_id;
        windowStartedAt = existingWindow.window_started_at;
        groundTruth = {
          repeat_count: existingWindow.repeat_count,
          first_observed_at: existingWindow.first_observed_at,
          distinct_arg_hashes: existingWindow.distinct_arg_hashes,
        };
      } else {
        // Fail-safe (same invariant as the saveFinding try/catch below):
        // invokeIfTrap runs pre-gate and uncaught in the router, so a raw
        // store-read error must never propagate here either. Treat a read
        // failure exactly like "no existing record" — the call proceeds as
        // a fresh observation rather than throwing.
        // The current bucket is checked first: if a new rolling window was
        // already minted after the previous one expired, it is authoritative.
        // The previous bucket is the only other possible live candidate for
        // a window whose maximum age is FOLLOW_UP_WINDOW_MS.
        for (const candidateId of [currentFindingId, previousFindingId]) {
          let stored: SentinelFinding | null;
          try {
            stored = await this.findingStore.loadFinding(candidateId);
          } catch {
            stored = null;
          }
          if (!stored) continue;
          const details = stored.details as {
            first_observed_at?: string;
            repeat_count?: number;
            distinct_arg_hashes?: string[];
          };
          const firstObservedAt = details.first_observed_at ?? stored.observed_at;
          const firstObservedMs = Date.parse(firstObservedAt);
          const age = nowMs - firstObservedMs;
          if (!Number.isFinite(firstObservedMs) || age < 0 || age > FOLLOW_UP_WINDOW_MS) {
            continue;
          }
          findingId = candidateId;
          windowStartedAt = firstObservedMs;
          groundTruth = {
            repeat_count: details.repeat_count ?? 1,
            first_observed_at: firstObservedAt,
            distinct_arg_hashes: details.distinct_arg_hashes ?? [],
          };
          break;
        }
      }

      const withinWindow = groundTruth !== undefined;
      const repeatCount = withinWindow ? groundTruth!.repeat_count + 1 : 1;
      const firstObservedAt = withinWindow
        ? groundTruth!.first_observed_at
        : now.toISOString();
      const distinctArgHashes = withinWindow
        ? mergeCappedArgHash(groundTruth!.distinct_arg_hashes, argHash)
        : [argHash];

      const invocation: ToolCallInvocation = {
        trap_id: spec.trap_id,
        fake_tool_name: trigger.fake_tool_name,
        caller_identity: callerIdentity,
        invocation_args: boundedArgs.preview,
        arg_hash: argHash,
        arg_bytes: boundedArgs.bytes,
        arg_truncated: boundedArgs.truncated,
        invoked_at: now.toISOString(),
        finding_id: findingId,
        fake_response: trigger.fake_response,
        response_plausibility: "operator_configured_fake_response",
        follow_up_tool_calls: [],
      };
      const finding: SentinelFinding = {
        finding_id: findingId,
        sentinel_id: honeypotSentinelId(spec.trap_id),
        severity: spec.finding_severity,
        summary:
          `honeypot ${spec.trap_id} triggered: tool ${trigger.fake_tool_name} invoked by ${callerIdentity}` +
          (repeatCount > 1 ? ` (${repeatCount}x in window)` : ""),
        details: {
          trap_id: spec.trap_id,
          trap_class: spec.trap_class,
          fake_tool_name: trigger.fake_tool_name,
          caller_identity: callerIdentity,
          invocation_args: boundedArgs.preview,
          arg_hash: argHash,
          arg_bytes: boundedArgs.bytes,
          arg_truncated: boundedArgs.truncated,
          response_plausibility: invocation.response_plausibility,
          follow_up_window_ms: FOLLOW_UP_WINDOW_MS,
          follow_up_tool_calls: invocation.follow_up_tool_calls,
          // Coalescing fields (register Z-HNY-02): this ONE durable row
          // represents every invocation of this trap by this caller within
          // the current window, not only the invocation that triggered this
          // particular write.
          first_observed_at: firstObservedAt,
          repeat_count: repeatCount,
          distinct_arg_hashes: distinctArgHashes,
        },
        observed_at: now.toISOString(),
        evidence_audit_ids: [],
        fortress_id: this.fortressId,
      };
      // Persist the finding and trigger audit BEFORE retaining the activation
      // and updating the coalescing window, so a retained correlation-buffer
      // entry (or an updated window pointing at findingId) always has a
      // durable record behind it. invokeIfTrap runs pre-gate and uncaught in
      // the router (router.ts CallTool handler has no try/catch around this
      // call), so a raw persistence error must never propagate here: it would
      // leak an internal error to the agent (no-leak invariant) and break the
      // honeypot's stealth. On failure, skip retention (preserving "retained
      // implies persisted") and still return the fake response.
      let persisted = false;
      try {
        // `knownExisting: withinWindow` skips the finding store's per-write
        // ceiling check for a coalesced UPDATE (same finding_id, cannot grow
        // the tracked count) — see saveFinding's doc. A brand-new window
        // (withinWindow false) still pays the full ceiling check.
        await this.findingStore.saveFinding(finding, { knownExisting: withinWindow });
        await this.auditLog.append("l2", HONEYPOT_AUDIT_OPS.TRIGGERED, this.operatorId, {
          fortress_id: this.fortressId,
          trap_id: spec.trap_id,
          trap_class: spec.trap_class,
          fake_tool_name: trigger.fake_tool_name,
          caller_identity: callerIdentity,
          invocation_args: boundedArgs.preview,
          arg_hash: argHash,
          arg_bytes: boundedArgs.bytes,
          arg_truncated: boundedArgs.truncated,
          finding_id: findingId,
          severity: spec.finding_severity,
          response_plausibility: invocation.response_plausibility,
          fake_response_hash: hashJson(trigger.fake_response),
          follow_up_window_ms: FOLLOW_UP_WINDOW_MS,
          follow_up_tool_calls: [],
          repeat_count: repeatCount,
        });
        persisted = true;
      } catch {
        // Persistence failed. Do not retain an unpersisted activation; stay stealthy
        // and fail safe rather than surface the error on the pre-gate path.
      }
      if (persisted) {
        this.retainActivation(spec.trap_id, invocation);
        // BoundedMap.set() is async (core/bounded-map.ts, MUST-FIX 6): a
        // trust-bearing map awaits a critical audit before an eviction
        // delete. This map has no `onEvict` (not trust-bearing — see its
        // construction doc), so the await here resolves with no real
        // work; it is only awaited for API uniformity with `BoundedMap`.
        await this.activeFindingWindows.set(windowKey, {
          finding_id: findingId,
          window_started_at: windowStartedAt,
          first_observed_at: firstObservedAt,
          repeat_count: repeatCount,
          distinct_arg_hashes: distinctArgHashes,
        });
      }

      return { handled: true as const, response: trigger.fake_response };
    });
  }

  /**
   * Serialize every call sharing `key` — the second and later concurrent
   * callers each await the FULL completion (including any error) of every
   * call queued before them, then run in strict order. This is what turns
   * the coalescing read-decide-persist-update sequence in `invokeIfTrap`
   * into a true critical section: without it, two calls racing on the same
   * (trap, caller) window could both read "no existing record" before
   * either had written one (register Z-HNY-02 RECHECK).
   *
   * Self-cleaning (see the `windowLocks` field doc): `key`'s entry in the
   * map is a placeholder that exists only while at least one call for that
   * key is queued or running, and is removed once the queue drains back to
   * empty — the `finally` block deletes it, but ONLY if no newer call has
   * already replaced it with its own placeholder (the `=== chained` guard),
   * so a call that arrives while this one is still running is never
   * dropped from the queue by an earlier call's cleanup.
   */
  private async runExclusive<T>(
    key: string,
    fn: () => Promise<T>,
  ): Promise<T> {
    const prior = this.windowLocks.get(key) ?? Promise.resolve();
    const run = prior.then(fn, fn);
    const chained = run.then(
      () => undefined,
      () => undefined,
    );
    this.windowLocks.set(key, chained);
    try {
      return await run;
    } finally {
      if (this.windowLocks.get(key) === chained) {
        this.windowLocks.delete(key);
      }
    }
  }

  recordToolCall(
    toolName: string,
    args: Record<string, unknown>,
    callerIdentity: string,
  ): void {
    const now = this.now();
    this.pruneExpiredActivations(now);

    // Bound the args ONCE, before the loops. A caller can hold up to
    // MAX_ACTIVATIONS_PER_CALLER_PER_TRAP activations across traps, and a
    // follow-up correlates against every one still in the window; serializing
    // the args per matching activation would re-introduce the N-way
    // amplification this fix closes. The capped preview is immutable and never
    // mutated after retention, so sharing one reference across the matching
    // activations is safe and strictly cheaper than a per-activation copy.
    const boundedFollowUp = hashAndBoundArgs(args);

    for (const [trapId, invocations] of this.activations.entries()) {
      for (const activation of invocations) {
        if (activation.caller_identity !== callerIdentity) continue;
        const delta = now.getTime() - Date.parse(activation.invoked_at);
        if (delta < 0 || delta > FOLLOW_UP_WINDOW_MS) continue;
        if (
          activation.follow_up_tool_calls.length >=
          MAX_FOLLOW_UP_TOOL_CALLS_PER_ACTIVATION
        ) {
          continue;
        }
        const followUp: ToolCallFollowUp = {
          tool_name: toolName,
          caller_identity: callerIdentity,
          args: boundedFollowUp.preview,
          args_hash: boundedFollowUp.hash,
          args_bytes: boundedFollowUp.bytes,
          args_truncated: boundedFollowUp.truncated,
          called_at: now.toISOString(),
        };
        activation.follow_up_tool_calls.push(followUp);
        void this.auditLog.append(
          "l2",
          HONEYPOT_AUDIT_OPS.FOLLOW_UP_CORRELATED,
          this.operatorId,
          {
            fortress_id: this.fortressId,
            trap_id: trapId,
            fake_tool_name: activation.fake_tool_name,
            caller_identity: callerIdentity,
            follow_up_tool_name: toolName,
            args_hash: followUp.args_hash,
            activation_at: activation.invoked_at,
            called_at: followUp.called_at,
            follow_up_count: activation.follow_up_tool_calls.length,
            follow_up_cap_reached:
              activation.follow_up_tool_calls.length ===
              MAX_FOLLOW_UP_TOOL_CALLS_PER_ACTIVATION,
          },
        );
      }
    }
  }

  stats(): ToolCallTrapStats[] {
    this.pruneExpiredActivations(this.now());

    return this.toolCallSpecs().map((spec) => {
      const trigger = spec.trigger;
      const activations = [...(this.activations.get(spec.trap_id) ?? [])];
      const callers = new Set(activations.map((a) => a.caller_identity));
      const last = activations
        .map((a) => a.invoked_at)
        .sort()
        .at(-1) ?? null;
      return {
        trap_id: spec.trap_id,
        fake_tool_name: trigger.fake_tool_name,
        catalog_visibility: trigger.catalog_visibility,
        ...(trigger.visible_to_agents
          ? { visible_to_agents: [...trigger.visible_to_agents] }
          : {}),
        invocation_count: activations.length,
        last_invocation_at: last,
        caller_diversity: callers.size,
        activations,
      };
    });
  }

  private toolCallSpecs(): Array<TrapSpec & { trigger: ToolCallTrigger }> {
    return this.registry
      .list()
      .filter(
        (spec): spec is TrapSpec & { trigger: ToolCallTrigger } =>
          spec.trigger.kind === "tool_call",
      );
  }

  private retainActivation(trapId: string, invocation: ToolCallInvocation): void {
    const list = this.activations.get(trapId) ?? [];
    list.push(invocation);
    this.activations.set(trapId, this.capActivations(list));
  }

  private pruneExpiredActivations(now: Date): void {
    for (const [trapId, invocations] of this.activations.entries()) {
      const nowMs = now.getTime();
      const active = invocations.filter((activation) => {
        const invokedMs = Date.parse(activation.invoked_at);
        if (!Number.isFinite(invokedMs)) return false;
        return nowMs - invokedMs <= FOLLOW_UP_WINDOW_MS;
      });
      // The finding and trigger audit are persisted before retention, so evicting
      // an expired correlation buffer entry loses no security signal.
      const capped = this.capActivations(active);
      if (capped.length === 0) {
        this.activations.delete(trapId);
      } else {
        this.activations.set(trapId, capped);
      }
    }
  }

  private capActivations(invocations: ToolCallInvocation[]): ToolCallInvocation[] {
    const perCallerCounts = new Map<string, number>();
    const callerCapped: ToolCallInvocation[] = [];
    for (let i = invocations.length - 1; i >= 0; i -= 1) {
      const activation = invocations[i]!;
      const count = perCallerCounts.get(activation.caller_identity) ?? 0;
      if (count >= MAX_ACTIVATIONS_PER_CALLER_PER_TRAP) continue;
      perCallerCounts.set(activation.caller_identity, count + 1);
      callerCapped.push(activation);
    }
    callerCapped.reverse();
    if (callerCapped.length <= MAX_RETAINED_ACTIVATIONS_PER_TRAP) {
      return callerCapped;
    }
    return callerCapped.slice(-MAX_RETAINED_ACTIVATIONS_PER_TRAP);
  }

  /**
   * Sweep coalescing-window entries whose window has rolled past
   * FOLLOW_UP_WINDOW_MS. Mirrors pruneExpiredActivations's placement (top of
   * invokeIfTrap, the only entry point that reads or writes this map).
   */
  private pruneExpiredCoalescedWindows(now: Date): void {
    const nowMs = now.getTime();
    this.activeFindingWindows.sweep(
      (window) => nowMs - window.window_started_at > FOLLOW_UP_WINDOW_MS,
    );
  }
}

/**
 * Add `argHash` to a coalesced window's distinct-hash set, deduplicated and
 * capped at MAX_DISTINCT_ARG_HASHES_PER_COALESCED_FINDING. Once the cap is
 * reached, further distinct hashes within the same window are silently
 * dropped from the set (the window's `repeat_count` still keeps counting —
 * only the distinct-shape sample is bounded).
 */
function mergeCappedArgHash(existing: string[], argHash: string): string[] {
  if (existing.includes(argHash)) return existing;
  if (existing.length >= MAX_DISTINCT_ARG_HASHES_PER_COALESCED_FINDING) {
    return existing;
  }
  return [...existing, argHash];
}

function isVisibleToAgent(
  trigger: ToolCallTrigger,
  agentId: string | undefined,
): boolean {
  if (trigger.catalog_visibility === "all_wrapped_agents") return true;
  if (!agentId) return false;
  return (trigger.visible_to_agents ?? []).includes(agentId);
}

function callerAgentId(callerIdentity: string): string {
  return callerIdentity.startsWith("agent:")
    ? callerIdentity.slice("agent:".length)
    : callerIdentity;
}

function hashJson(value: unknown): string {
  return createHash("sha256")
    .update(JSON.stringify(value) ?? "null", "utf8")
    .digest("hex")
    .slice(0, 32);
}

// HNY-01 (register §Z RECHECK): a tool-call trap intercepts PRE-GATE
// (router.ts, before schema validation), so `args` is fully attacker-
// controlled and unvalidated on the invoke path. The correlation buffer
// retains one entry per activation plus up to 16 follow-ups each, and
// stats()/the management route serialize every retained entry. Retaining the
// raw args object graph let a visible agent drive unbounded memory growth and
// response amplification (AGENTS.md rule 8) even though the entry COUNT was
// already capped. We retain only a byte-capped preview plus the full-fidelity
// hash — identity is preserved for correlation — and the true serialized size.
// 512 bytes: enough for an operator to recognize a probe's shape; full fidelity
// is preserved by arg_hash (correlation) and arg_bytes (true size). The security
// property is that the retained/serialized size is set by PRODUCT caps, never by
// the attacker's chosen argument size.
//
// Honest per-trap ceiling (accounting for the two amplifiers a naive estimate
// misses): the retained preview is a STRING, so when stats() re-serializes it
// the JSON escaping of any backslashes/quotes inside it can roughly DOUBLE its
// on-the-wire size (~2x), and a byte-boundary truncation that splits a multibyte
// sequence appends one U+FFFD (<= +3 bytes). So a preview caps at ~512 raw bytes
// but serializes to <= ~1 KB worst case. Across the per-TRAP retention cap
// (MAX_RETAINED_ACTIVATIONS_PER_TRAP = 128, four fully-capped callers) x
// (1 invocation + 16 follow-ups): ~= 128 x 17 x ~1 KB ~= ~2.2 MB of previews,
// plus per-activation metadata (ids, hashes, timestamps) that pushes a
// fully-capped trap to ~2.9 MB total on the wire (measured). stats()/the
// management route sum this over the deployed tool-call traps, whose COUNT is
// operator-bounded (deploy needs the operator bearer). Bounded and operator-
// scaled; within a trap the attacker is bounded to 128 activations. (Lower this
// constant or the activation caps to tighten the ceiling further.)
export const MAX_RETAINED_ARG_BYTES = 512;

interface HashedBoundedArgs {
  hash: string;
  // A byte-capped stand-in for the raw args. Small args pass through verbatim;
  // oversized args become a preview marker, so nothing retained references the
  // attacker's object graph.
  preview: Record<string, unknown>;
  bytes: number;
  truncated: boolean;
}

// Serialize ONCE and derive both the hash and the bound. The invoke path
// previously called hashJson(args) (a full JSON.stringify) anyway, so this is
// no extra asymptotic cost on the single incoming object — it just stops that
// object from being RETAINED.
function hashAndBoundArgs(args: Record<string, unknown>): HashedBoundedArgs {
  const json = JSON.stringify(args) ?? "null";
  const hash = createHash("sha256").update(json, "utf8").digest("hex").slice(0, 32);
  const bytes = Buffer.byteLength(json, "utf8");
  if (bytes <= MAX_RETAINED_ARG_BYTES) {
    return { hash, preview: args, bytes, truncated: false };
  }
  // Truncate on a BYTE boundary, not a character boundary: json.slice() counts
  // UTF-16 code units, so a multibyte-heavy string could retain up to ~4x
  // MAX_RETAINED_ARG_BYTES and quietly break the ceiling above. Slicing the
  // UTF-8 buffer and decoding back caps the true retained bytes at the constant;
  // toString replaces a split trailing multibyte sequence with U+FFFD (safe, no
  // throw, and the value is only ever re-serialized, never JSON.parsed).
  const previewBytes = Buffer.from(json, "utf8").subarray(0, MAX_RETAINED_ARG_BYTES);
  return {
    hash,
    preview: {
      _sanctuary_arg_preview: previewBytes.toString("utf8"),
      _sanctuary_arg_bytes: bytes,
      _sanctuary_arg_truncated: true,
    },
    bytes,
    truncated: true,
  };
}
