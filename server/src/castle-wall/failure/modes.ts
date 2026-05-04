/**
 * Failure-mode types for the Castle Wall.
 *
 * Each named FailureMode in this module corresponds to one of the
 * sub-failure-modes called out in scope-lock section 7. A FailureMode value
 * pairs with a FailureDisposition; subsequent PRs implement the daemon-side
 * watchdogs that detect each failure and the main-side handlers that surface
 * the disposition.
 *
 * Source: Castle Wall Phase 1 Scope Lock 2026-05-03 section 7 + Codex amendments
 * 7 (NFQUEUE flag specification + emergency `--no-wall` mode) and 8 (queue
 * saturation event type promoted to a fail-closed disposition).
 */

import type { BlockReason } from "../decision/types.js";

/** Every named failure mode the Castle Wall recognizes. */
export type FailureMode =
  | "startup_filter_install_failed"
  | "startup_policy_parse_failed"
  | "startup_ipc_bind_failed"
  | "runtime_daemon_crash"
  | "runtime_kernel_module_unloaded"
  | "runtime_ipc_drop_kernel_up"
  | "runtime_external_firewall_clobber"
  | "runtime_queue_saturated";

/** Disposition the daemon and main apply when a FailureMode fires. */
export type FailureDisposition =
  | { kind: "refuse_to_start"; operator_message_key: string }
  | { kind: "fail_closed"; emit_event: "egress_blocked"; reason: BlockReason }
  | { kind: "fail_degraded"; allowed_until: string }
  | { kind: "restore_and_audit"; restored_within_ms: number };

/**
 * Static mapping from FailureMode to its v1.0 default disposition. This is the
 * recommended default per scope-lock section 7; operators may override via
 * `sanctuary castle set-failure-mode` (PR 4 wires the override surface).
 */
export const DEFAULT_FAILURE_DISPOSITIONS: Readonly<
  Record<FailureMode, FailureDisposition>
> = Object.freeze({
  startup_filter_install_failed: {
    kind: "refuse_to_start",
    operator_message_key: "F-1",
  },
  startup_policy_parse_failed: {
    kind: "refuse_to_start",
    operator_message_key: "F-4",
  },
  startup_ipc_bind_failed: {
    kind: "refuse_to_start",
    operator_message_key: "F-3-startup",
  },
  runtime_daemon_crash: {
    kind: "fail_closed",
    emit_event: "egress_blocked",
    reason: "no_matching_rule",
  },
  runtime_kernel_module_unloaded: {
    kind: "fail_closed",
    emit_event: "egress_blocked",
    reason: "no_matching_rule",
  },
  runtime_ipc_drop_kernel_up: {
    kind: "fail_degraded",
    allowed_until: "+60s",
  },
  runtime_external_firewall_clobber: {
    kind: "restore_and_audit",
    restored_within_ms: 5_000,
  },
  runtime_queue_saturated: {
    kind: "fail_closed",
    emit_event: "egress_blocked",
    reason: "queue_saturated",
  },
});

/**
 * Emergency `--no-wall` recovery mode state. Engaging this mode disables
 * Castle Layer 1 enforcement for a bounded window. The flag is audited at
 * engage / extend / expire (per Codex amendment).
 */
export interface NoWallMode {
  engaged: boolean;
  engaged_at: string | null;
  duration_seconds: number;
  expires_at: string | null;
  re_authenticate_to_extend: true;
  audit_event_id: string | null;
}

/** The "wall is fully active" baseline state. */
export function makeNoWallModeDisengaged(): NoWallMode {
  return {
    engaged: false,
    engaged_at: null,
    duration_seconds: 0,
    expires_at: null,
    re_authenticate_to_extend: true,
    audit_event_id: null,
  };
}
