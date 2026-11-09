/** The closed reason registry and the reused-constant parity checks. */
import { describe, expect, it } from "vitest";
import {
  AGENT_WINDOW_BASE,
  AGENT_WINDOW_MAX,
  AUDIT_PERIOD,
  AVAILABILITY_WINDOW,
  CANARY_PRIMARY_CAP_PER_DAY,
  CANARY_PRIMARY_NOMINAL_PER_DAY,
  CANARY_WINDOW_BASE,
  CENSUS_PAIR_MAX,
  CENSUS_RUN,
  CENSUS_SAMPLES_MAX,
  DETECTOR_PERIOD,
  HISTORY_WINDOW,
  LAUNCHD_LEEWAY_MAX,
  POLL_BACKOFF_CAP_MAX,
  REASON_REGISTRY,
  REASON_SLOTS,
  REMOTE_AND_DELIVERY_BOUND,
  SECOND,
  STATUS_READ_DEADLINE,
  agentWindow,
  canaryWindow,
} from "../../../src/castle-wall/liveness/constants.js";
import { DEFAULT_ENFORCEMENT_AVAILABILITY_FRESHNESS_MS } from "../../../src/castle-wall/runtime/enforcement-availability.js";
import { FULL_AGENT_CRASH_WINDOW_S } from "../../../src/cli/castle-wall-full-agent-state.js";
import {
  CASTLE_WALL_DEFAULT_AUDIT_HEARTBEAT_INTERVAL_SECONDS,
  CASTLE_WALL_DEFAULT_EMISSION_LIVENESS_TICK_SECONDS,
} from "../../../src/castle-wall/runtime/macos-daemon.js";

// The binding table: [reason, wall class, wall exit, agent class, coverage effect, producer].
const D = 1;
const W = 3;
const TABLE: ReadonlyArray<[string, string, number | null, string, string, string]> = [
  ["none", "OK", 0, "OK", "none", "evaluator"],
  ["monitoring_incomplete", "n/a", null, "n/a", "LEGACY_PARTIAL", "evaluator"],
  ["agent_unmonitored", "n/a", null, "UNMONITORED", "WALL_ONLY", "evaluator"],
  ["unsupported_adapter", "DOWN", D, "UNMONITORED", "UNAVAILABLE", "evaluator"],
  ["commissioning_unproven", "DOWN", D, "UNMONITORED", "UNAVAILABLE_IF_WALL", "evaluator"],
  ["evidence_incomplete", "DOWN", D, "DOWN", "none", "evaluator"],
  ["initializing", "INITIALIZING", D, "INITIALIZING", "none", "evaluator"],
  ["recovering", "RECOVERING", D, "RECOVERING", "none", "evaluator"],
  ["ttl_expiring", "TTL_WARNING", W, "n/a", "none", "evaluator"],
  ["stale_mcp_child", "n/a", null, "DEGRADED_STALE_MCP", "none", "evaluator"],
  ["recent_restart", "DEGRADED", W, "n/a", "none", "evaluator"],
  ["write_lock_recovery", "DEGRADED", W, "n/a", "none", "evaluator"],
  ["audit_backlog", "DEGRADED", W, "n/a", "none", "evaluator"],
  ["audit_loss", "DEGRADED", W, "n/a", "none", "evaluator"],
  ["audit_rejected", "DEGRADED", W, "n/a", "none", "evaluator"],
  ["heartbeat_stale", "DEGRADED", W, "n/a", "none", "evaluator"],
  ["emission_stall", "DEGRADED", W, "n/a", "none", "evaluator"],
  ["recording_unconfirmed", "DEGRADED", W, "n/a", "none", "evaluator"],
  ["optional_reply_failed", "n/a", null, "DOWN_IF_REQUIRED", "none", "evaluator"],
  ["agent_flow_stale", "n/a", null, "DOWN", "none", "evaluator"],
  ["census_unavailable", "n/a", null, "DOWN_IF_COMMISSIONED", "none", "evaluator"],
  ["agent_process_missing", "n/a", null, "DOWN", "none", "evaluator"],
  ["process_identity_unknown", "DOWN", D, "DOWN", "none", "evaluator"],
  ["canary_failed", "DOWN", D, "n/a", "none", "evaluator"],
  ["canary_unprovisioned", "DOWN", D, "n/a", "UNAVAILABLE", "evaluator"],
  ["observer_missing", "DOWN", D, "DOWN", "UNAVAILABLE", "evaluator"],
  ["observer_stale", "DOWN", D, "DOWN", "UNAVAILABLE", "evaluator"],
  ["detector_stale", "DOWN", D, "n/a", "none", "evaluator"],
  ["daemon_telemetry_stale", "DOWN", D, "n/a", "none", "evaluator"],
  ["counter_regression", "DOWN", D, "DOWN", "none", "evaluator"],
  ["time_untrusted", "DOWN", D, "DOWN", "none", "evaluator"],
  ["observation_invalid", "DOWN", D, "DOWN", "none", "evaluator"],
  ["custody_invalid", "DOWN", D, "DOWN", "UNAVAILABLE", "evaluator"],
  ["lease_expired", "DOWN", D, "n/a", "none", "evaluator"],
  ["enforcement_not_live", "DOWN", D, "n/a", "none", "evaluator"],
  ["safe_mode_only", "SAFE_MODE", D, "n/a", "none", "evaluator"],
  ["session_logged_out", "LOGGED_OUT", D, "n/a", "none", "evaluator"],
  ["reboot_no_login", "REBOOT_NO_LOGIN", D, "n/a", "none", "evaluator"],
  ["daemon_missing", "DOWN", D, "n/a", "none", "evaluator"],
  ["daemon_unresponsive", "DOWN", D, "n/a", "none", "evaluator"],
  ["canary_destination_allowed", "DOWN", D, "n/a", "none", "evaluator"],
  ["crash_latched", "DOWN", D, "n/a", "none", "evaluator"],
  ["host_unreachable", "DOWN", D, "n/a", "none", "remote"],
  ["monitor_stopped", "REMOTE_LOCAL", null, "n/a", "none", "remote_local"],
  ["delivery_unconfirmed", "REMOTE_LOCAL", null, "n/a", "none", "remote_local"],
  ["delivery_failed", "REMOTE_LOCAL", null, "n/a", "none", "remote_local"],
];

describe("closed reason registry", () => {
  it("has exactly REASON_SLOTS unique reasons at contiguous positions", () => {
    expect(REASON_SLOTS).toBe(46);
    expect(REASON_REGISTRY.length).toBe(REASON_SLOTS);
    expect(new Set(REASON_REGISTRY.map(entry => entry.reason)).size).toBe(REASON_SLOTS);
    REASON_REGISTRY.forEach((entry, index) => expect(entry.position).toBe(index));
    expect(Object.isFrozen(REASON_REGISTRY)).toBe(true);
  });

  it("equals the binding table as a full set, in order", () => {
    const actual = REASON_REGISTRY.map(entry => [entry.reason, entry.wall, entry.wallExit, entry.agent, entry.coverage, entry.producer]);
    expect(actual).toEqual(TABLE);
    for (const entry of REASON_REGISTRY) expect(entry.alarm).toBe(entry.reason !== "none");
  });
});

describe("reused-constant parity", () => {
  it("matches the producer constants it re-types", () => {
    expect(AVAILABILITY_WINDOW).toBe(DEFAULT_ENFORCEMENT_AVAILABILITY_FRESHNESS_MS);
    expect(HISTORY_WINDOW).toBe(FULL_AGENT_CRASH_WINDOW_S * SECOND);
    expect(DETECTOR_PERIOD).toBe(CASTLE_WALL_DEFAULT_EMISSION_LIVENESS_TICK_SECONDS * SECOND);
    expect(AUDIT_PERIOD).toBe(CASTLE_WALL_DEFAULT_AUDIT_HEARTBEAT_INTERVAL_SECONDS * SECOND);
  });

  it("fits worst-case rotation recovery inside the minimum agent window", () => {
    expect((CENSUS_RUN + 1) * CENSUS_PAIR_MAX).toBeLessThanOrEqual(agentWindow(0));
    expect(agentWindow(0)).toBe(AGENT_WINDOW_BASE);
  });

  it("derives the written-out windows and caps", () => {
    expect(REMOTE_AND_DELIVERY_BOUND).toBe(372 * SECOND);
    expect(LAUNCHD_LEEWAY_MAX).toBe(242 * SECOND);
    expect(CANARY_WINDOW_BASE).toBe(268 * SECOND);
    expect(canaryWindow(LAUNCHD_LEEWAY_MAX)).toBe(510 * SECOND);
    expect(AGENT_WINDOW_BASE).toBe(93 * SECOND);
    expect(AGENT_WINDOW_MAX).toBe(510 * SECOND);
    expect(POLL_BACKOFF_CAP_MAX).toBe(417 * SECOND);
    expect(CENSUS_SAMPLES_MAX).toBe(46);
    expect(CANARY_PRIMARY_NOMINAL_PER_DAY).toBe(480);
    expect(CANARY_PRIMARY_CAP_PER_DAY).toBe(960);
    expect(STATUS_READ_DEADLINE).toBe(6 * SECOND);
  });
});
