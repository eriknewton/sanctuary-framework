/**
 * Castle Wall Observe / Learn Allow-List v1 -- shared types.
 *
 * Ratified design: Review/Sanctuary/ObserveLearn_AllowList_Decision_Brief_2026-07-07.md
 * (D-Q1/D-Q2/D-Q3 + v1 slice), detail in
 * Review/Sanctuary/ObserveLearn_AllowList_Scoping_2026-07-07.md, adversarial pass in
 * Review/Sanctuary/ObserveLearn_AllowList_Scoping_Review_2026-07-07.md.
 *
 * THE RED-LINE INVARIANT (D-Q1, H1 in the adversarial review): v1 ships the
 * enforce-preserving posture ONLY. The wall stays armed and default-deny while
 * observing; a denied novel destination is coalesced into this module's
 * candidate store instead of flooding a per-flow prompt. The enforcing
 * evaluator (`../egress-proxy.ts` / the Rust daemon) NEVER reads this store --
 * it is a distinct store from the live signed ruleset, reachable only through
 * this module's own read/write surface. A recorded candidate stays BLOCKED
 * until an explicit human promote (see promote.ts) re-signs the manifest.
 * Observing must never become allowing, by default or by back door.
 */

import { createHash } from "node:crypto";

/** Reserved StateStore namespace for observe-mode state + candidate rows (agent-invisible, see cognitive/tools.ts firewall). */
export const OBSERVE_NAMESPACE = "_castle_wall_observe" as const;

/** Schema version tag persisted on every candidate + state record. */
export const OBSERVE_SCHEMA_VERSION = "1.0" as const;

/** Closed registry of audit sources the observe refresh is allowed to fold. */
export const OBSERVE_AUDIT_SOURCE_IDS = ["master-audit", "boot-audit"] as const;
export type ObserveAuditSourceId = (typeof OBSERVE_AUDIT_SOURCE_IDS)[number];

export function isObserveAuditSourceId(value: unknown): value is ObserveAuditSourceId {
  return (
    typeof value === "string" &&
    (OBSERVE_AUDIT_SOURCE_IDS as readonly string[]).includes(value)
  );
}

/** How confidently the daemon derived the destination hostname. Mirrors `IpcDestination.hostname_source` (ipc/messages.ts); `null` when the producer did not report one (e.g. the Linux daemon's generic `CastleWallEventDestination` carries no hostname_source field at all). */
export type HostnameSource = "dns" | "sni" | "url" | "socket" | null;

/**
 * Which enforcement PRODUCER minted a recorded flow (adapter.ts derives it
 * from the on-disk audit-body shape + producer fingerprint). This is the
 * per-row PROVENANCE the suppression belt needs to scope the `"unknown"`
 * agent_template exemption CORRECTLY across platforms (refresh.ts):
 *
 *   - `"macos"`: a macOS NEFilterDataProvider flow (the nested
 *     `agent`/`destination` default-resolver shape from
 *     `runtime/macos-flow-events.ts`, OR a macOS producer-signed body carrying
 *     `source: "macos_extension"`). Here `agent_template: "unknown"` is the
 *     DEFAULT RESOLVER sentinel for an UNATTRIBUTED flow that no allow rule can
 *     ever truly permit (the macOS filter fail-closed-drops it regardless of
 *     allows), so such a row must NEVER be suppressed.
 *   - `"linux_daemon"`: a Rust NFQUEUE/daemon flow (the flat `dest_*` shape
 *     carrying the daemon's `decision_provenance` fingerprint). Here
 *     `agent_template: "unknown"` is a REAL, enforceable template (NFQUEUE
 *     hardcodes it, `nfqueue.rs`), so an allow rule scoped to it genuinely
 *     changes the daemon's verdict and the row IS a legitimate suppression
 *     candidate.
 *
 * OMITTED (`undefined`) on a hand-built or legacy-persisted row whose producer
 * cannot be positively identified: the suppression belt then treats it as
 * NON-daemon (the conservative direction -- the `"unknown"` exemption applies,
 * so the row stays pending; nothing is ever suppressed on a guessed origin).
 */
export type ObserveProvenance = "macos" | "linux_daemon";

/**
 * Granularity a candidate synthesizes into an AllowlistRule at (D-Q2).
 * Reuses the `LearnedGranularity` enum already declared for the prompt-time
 * "always" decision (`../ipc/messages.ts`); this feature is its first
 * production consumer.
 *
 *   - `per_template_domain` (DEFAULT): the exact observed host (or the
 *     resolved IP when no hostname was seen), scoped to the observing
 *     agent's TEMPLATE. The narrowest honest grant -- D-Q2's default.
 *   - `per_instance_domain`: the exact observed host, scoped to the single
 *     observing agent INSTANCE rather than its template.
 *   - `per_template_etld1`: the observed host's registered domain (a NAIVE
 *     last-two-labels heuristic; this repo ships no public-suffix-list
 *     dependency, so this is NOT a true eTLD+1 lookup and can mis-widen a
 *     multi-label public suffix like "co.uk" -- an honest limitation, not a
 *     silent one), scoped to template. WIDER than what was observed; per
 *     D-Q2 / adversarial review finding L2 this is offered ONLY as an
 *     explicit per-row operator choice at promote time, never the default.
 */
export type ObserveGranularity =
  | "per_template_domain"
  | "per_template_etld1"
  | "per_instance_domain";

export const DEFAULT_OBSERVE_GRANULARITY: ObserveGranularity = "per_template_domain";

/**
 * One flow the wall recorded, already normalized off the audit stream
 * (`adapter.ts`) or supplied directly by a test fixture. Destination metadata
 * ONLY -- no payload, header, path, or query capture (adversarial review M2).
 */
export interface FlowObservationEvent {
  timestamp: string;
  agent: { id: string; template: string };
  destination: {
    host: string | null;
    ip: string;
    port: number;
    protocol: "tcp" | "udp";
  };
  hostname_source: HostnameSource;
  /** What the ARMED wall did with this flow. v1 folds "denied" flows only (see fold.ts). */
  disposition: "denied" | "allowed";
  /** Which enforcement producer minted this flow (adapter.ts). Scopes the `"unknown"`-template suppression exemption per platform; see {@link ObserveProvenance}. `undefined` on a hand-built event => treated as non-daemon (conservative). */
  provenance?: ObserveProvenance;
}

/**
 * A candidate observation row (scoping doc section 2.2). Destination
 * metadata + counts + provenance ONLY -- deliberately excludes anything that
 * would let this row double as policy-inference surface beyond "a
 * destination my agent tried and was denied."
 */
export interface CandidateObservation {
  agent_id: string;
  agent_template: string;
  host: string | null;
  ip: string;
  port: number;
  protocol: "tcp" | "udp";
  hostname_source: HostnameSource;
  times_seen: number;
  first_seen: string;
  last_seen: string;
  /** Always "denied" in v1 (see fold.ts); kept as a field for fidelity with the scoping doc's CandidateObservation shape. */
  would_be_disposition: "denied" | "allowed";
  /** True when the host matches the messaging-platform exfil denylist (D-Q3). Never pre-selected for promote. */
  exfil_risk: boolean;
  /** Which enforcement producer minted the folded flow(s) behind this row; scopes the `"unknown"`-template suppression exemption per platform (see {@link ObserveProvenance} and refresh.ts `candidateCurrentlyAllowed`). Folded conservatively: `"linux_daemon"` survives ONLY when every contributing event was the Linux daemon; any macOS/undefined contribution keeps the row non-daemon. `undefined` on a legacy-persisted row => treated as non-daemon. */
  provenance?: ObserveProvenance;
}

/** Candidate-review actions that resolve a pending row without permitting it by default. */
export type ObserveCandidateReviewAction = "promote" | "discard";

/**
 * Persisted per-candidate review marker. The record lives in the observe
 * StateStore namespace, not in any audit chain, so a pruned or reset chain
 * cannot resurrect already-reviewed retained denials. A later denial after
 * `reviewed_at` may mint a fresh candidate for the same key.
 */
export interface ObserveCandidateReviewRecord {
  schema_version: typeof OBSERVE_SCHEMA_VERSION;
  candidate_key: string;
  action: ObserveCandidateReviewAction;
  reviewed_at: string;
}

/**
 * Stable dedup / lookup key: (agent template, host-or-ip, port, protocol),
 * per scoping doc section 2.1's fold rule. Built via `JSON.stringify` on a
 * tuple rather than a delimited string join, so no combination of field
 * VALUES can manufacture a false collision (JSON's per-element escaping keeps
 * a split between "a b" + "c" distinct from "a" + "b c").
 */
export function candidateKey(input: {
  agent_template: string;
  host: string | null;
  ip: string;
  port: number;
  protocol: "tcp" | "udp";
}): string {
  const dest = input.host ?? input.ip;
  return JSON.stringify([input.agent_template, dest, input.port, input.protocol]);
}

/** Short, stable, non-secret hex digest of a candidate key -- used as the on-disk StateStore key suffix so an operator-supplied host string can never itself become an unsafe storage key. */
export function candidateKeyDigest(key: string): string {
  return createHash("sha256").update(key).digest("hex").slice(0, 32);
}

/** Persisted observe-mode toggle state. */
export interface ObserveModeState {
  enabled: boolean;
  started_at: string | null;
  updated_at: string;
}

/**
 * Persisted fold watermark (its own record, DELIBERATELY not a field on
 * `ObserveModeState`, so no other state writer can ever clobber it): the
 * highest authenticated audit-chain sequence the refresh chokepoint has
 * already folded into the candidate store. Every chained event is folded
 * EXACTLY ONCE across refreshes (sweep finding R3-1: the pre-watermark
 * engine re-folded the full retained history additively on every refresh,
 * multiplying `times_seen` and resurrecting promoted/discarded candidates).
 * The sequence is the hash-chain position `AuditLog.streamVerifiedChain`
 * authenticates -- append-monotonic and prune-stable, never a skewable
 * wall-clock timestamp.
 *
 * `entry_hash` binds the watermark to the CHAIN IDENTITY, not just a bare
 * position (Codex gate HIGH-2): it is the verified `entry_hash` of the
 * chained entry at `folded_through_sequence`. A reset/rebuilt audit chain
 * that regrows past the old sequence carries a different hash there, so the
 * refresh detects the mismatch and recomputes instead of silently skipping
 * the new chain's prefix.
 */
export interface FoldWatermark {
  folded_through_sequence: number;
  entry_hash: string;
  updated_at: string;
}
