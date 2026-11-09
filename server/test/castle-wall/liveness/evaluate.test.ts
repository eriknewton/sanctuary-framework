/** The pure liveness evaluator over raw stored evidence: state rows, refusal arms, freshness, canary and commissioning gates. */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  CANARY_WINDOW_BASE,
  HISTORY_WINDOW,
  LAUNCHD_LEEWAY_MAX,
  MINUTE,
  OBSERVER_WINDOW,
  SECOND,
  canaryWindow,
} from "../../../src/castle-wall/liveness/constants.js";
import { evaluateLiveness, type LivenessEnvelope, type LivenessInput } from "../../../src/castle-wall/liveness/evaluate.js";

type Patch = { op: "set" | "add" | "delete"; path: string; value?: unknown };
interface StateRow {
  name: string;
  table: "wall" | "agent" | "coverage";
  kind: "continuing" | "refusal";
  patches: Patch[];
  expect: Record<string, unknown>;
}
const STATES = JSON.parse(readFileSync(join(__dirname, "fixtures", "states.json"), "utf8")) as { base: LivenessInput; rows: StateRow[] };

/** Apply fixture patches to a deep copy of the base input. */
function patched(patches: readonly Patch[]): LivenessInput {
  const input = structuredClone(STATES.base) as unknown as Record<string, unknown>;
  for (const patch of patches) {
    const keys = patch.path.split(".");
    const last = keys.pop()!;
    let target = input;
    for (const key of keys) target = target[key] as Record<string, unknown>;
    if (patch.op === "delete") delete target[last];
    else if (patch.op === "add") target[last] = (target[last] as number) + (patch.value as number);
    else target[last] = structuredClone(patch.value);
  }
  return input as unknown as LivenessInput;
}
const set = (path: string, value: unknown): Patch => ({ op: "set", path, value });
const del = (path: string): Patch => ({ op: "delete", path });
const D = "daemon.value.";
const O = "observer.value.";
const C = "config.value.";
const NOW = STATES.base.nowMs;
const UP = (STATES.base.host as { uptimeMs: number }).uptimeMs;
const AGENT_UID = 502;
const evaluate = (...patches: Patch[]): LivenessEnvelope => evaluateLiveness(patched(patches));
const sorted = (values: readonly string[]) => [...values].sort();

function expectWallOk(envelope: LivenessEnvelope): void {
  expect(envelope.wall.state.startsWith("wall_OK_"), envelope.wall.reasons.join(",")).toBe(true);
  expect(envelope.exit_code).toBe(0);
}

describe("states.json rows", () => {
  it("covers every wall, agent and coverage state", () => {
    const covered = new Set(STATES.rows.flatMap(row => [row.expect.wall, row.expect.agent, row.expect.coverage]).filter(Boolean));
    for (const state of ["wall_INITIALIZING", "wall_OK_ACTIVE", "wall_OK_IDLE", "wall_OK_AGED_HISTORY", "wall_OK_TTL_COUNTDOWN", "wall_TTL_WARNING",
      "wall_DEGRADED", "wall_DOWN", "wall_RECOVERING", "wall_SAFE_MODE", "wall_REBOOT_NO_LOGIN", "wall_LOGGED_OUT",
      "agent_UNMONITORED", "agent_INITIALIZING", "agent_OK_PASSIVE", "agent_OK_OPTIONAL_REPLY", "agent_DEGRADED_STALE_MCP", "agent_DOWN", "agent_RECOVERING",
      "coverage_COMPLETE", "coverage_WALL_ONLY", "coverage_LEGACY_PARTIAL", "coverage_UNAVAILABLE"]) expect(covered.has(state), state).toBe(true);
  });

  it.each(STATES.rows.map(row => [row.name, row] as const))("%s", (_name, row) => {
    const envelope = evaluateLiveness(patched(row.patches));
    const e = row.expect;
    if (e.wall !== undefined) expect(envelope.wall.state).toBe(e.wall);
    if (e.wall_alarm !== undefined) expect(envelope.wall.alarm).toBe(e.wall_alarm);
    if (e.agent !== undefined) expect(envelope.agent.state).toBe(e.agent);
    if (e.agent_alarm !== undefined) expect(envelope.agent.alarm).toBe(e.agent_alarm);
    if (e.coverage !== undefined) expect(envelope.coverage.state).toBe(e.coverage);
    if (e.coverage_alarm !== undefined) expect(envelope.coverage.alarm).toBe(e.coverage_alarm);
    if (e.exit !== undefined) expect(envelope.exit_code).toBe(e.exit);
    if (e.wall_reasons !== undefined) expect(sorted(envelope.wall.reasons)).toEqual(sorted(e.wall_reasons as string[]));
    if (e.wall_reasons_include !== undefined) for (const reason of e.wall_reasons_include as string[]) expect(envelope.wall.reasons).toContain(reason);
    if (e.agent_reasons !== undefined) expect(sorted(envelope.agent.reasons)).toEqual(sorted(e.agent_reasons as string[]));
    if (e.agent_reasons_include !== undefined) for (const reason of e.agent_reasons_include as string[]) expect(envelope.agent.reasons).toContain(reason);
    // The top-level alarm is an alias of the wall alarm, and the wall alone sets the exit.
    expect(envelope.alarm).toBe(envelope.wall.alarm);
    expect(envelope.wall.alarm).toBe(!envelope.wall.state.startsWith("wall_OK_"));
  });
});

describe("component isolation", () => {
  it("routes an unknown reason on an agent record to agent observation_invalid and leaves the wall unchanged", () => {
    const envelope = evaluate(set(O + "evidence_failures", [{ component: "agent", reason: "reason_from_a_later_version" }]));
    expect(envelope.agent.reasons).toContain("observation_invalid");
    expect(envelope.agent.state).toBe("agent_DOWN");
    expectWallOk(envelope);
    expect(envelope.wall.reasons).toEqual(["none"]);
  });

  it("routes an unknown reason on a wall record to wall observation_invalid only", () => {
    const envelope = evaluate(set(D + "evidence_failures", [{ component: "wall", reason: "reason_from_a_later_version" }]));
    expect(envelope.wall.reasons).toEqual(["observation_invalid"]);
    expect(envelope.agent.state).toBe("agent_OK_PASSIVE");
  });

  it.each(["agent_unmonitored", "stale_mcp_child", "optional_reply_failed", "agent_flow_stale", "census_unavailable", "agent_process_missing"])(
    "agent-only reason %s leaves the wall state and exit unchanged", reason => {
      const envelope = evaluate(set(O + "evidence_failures", [{ component: "agent", reason }]));
      expect(envelope.agent.reasons).toContain(reason);
      expectWallOk(envelope);
      expect(envelope.wall.reasons).toEqual(["none"]);
    });

  it.each([
    ["census status unavailable", [set(O + "raw.census.status", "unavailable")]],
    ["gate proxied egress", [set(C + "gateway_egress", "gate_proxied")]],
    ["http version 2", [set(C + "ptb.http_version", "2")]],
    ["gateway not alive", [set(O + "raw.gateway.alive", false)]],
    ["stale mcp child", [set(O + "raw.mcp", { stale_child: true })]],
  ] as const)("agent evidence %s never reaches the wall", (_name, patches) => {
    const envelope = evaluate(...patches);
    expect(envelope.agent.state.startsWith("agent_OK_")).toBe(false);
    expectWallOk(envelope);
    expect(envelope.wall.reasons).not.toContain("census_unavailable");
  });
});

describe("canary acceptance", () => {
  it("accepts one valid live agent-subject confirmation for the exact tuple, in window, with integrity passing", () => {
    const envelope = evaluate();
    expectWallOk(envelope);
    expect(envelope.wall.evidence.canary_age_ms).toBe(60 * SECOND);
  });

  // The refusal fixtures keep a daemon instance older than CANARY_WINDOW, so absence reasons are never rewritten to initializing.
  it.each([
    ["operator subject", [set(D + "raw.canary.last_confirmation.subject_uid", 501)]],
    ["other uid", [set(D + "raw.canary.last_confirmation.subject_uid", 9999)]],
    ["other ip", [set(D + "raw.canary.last_confirmation.dest_ip", "192.0.2.253")]],
    ["other port", [set(D + "raw.canary.last_confirmation.dest_port", 10)]],
    ["other protocol", [set(D + "raw.canary.last_confirmation.dest_protocol", "udp")]],
    ["durable_wal delivery", [set(D + "raw.canary.last_confirmation.delivery", "durable_wal")]],
    ["confirmed before captured", [set(D + "raw.canary.last_confirmation.confirmed_at_ms", NOW - 61 * SECOND)]],
    ["captured older than CANARY_WINDOW", [set(D + "raw.canary.last_confirmation.captured_at_ms", NOW - canaryWindow(30 * SECOND) - 1), set(D + "raw.canary.last_confirmation.confirmed_at_ms", NOW - 100 * SECOND)]],
    ["captured beyond LOCAL_JITTER in the future", [set(D + "raw.canary.last_confirmation.captured_at_ms", NOW + 3 * SECOND), set(D + "raw.canary.last_confirmation.confirmed_at_ms", NOW + 3 * SECOND)]],
    ["no confirmation at all", [set(D + "raw.canary.last_confirmation", null)]],
  ] as const)("refuses %s with canary_failed", (_name, patches) => {
    const envelope = evaluate(...patches);
    expect(envelope.wall.reasons).toContain("canary_failed");
    expect(envelope.wall.state).toBe("wall_DOWN");
    expect(envelope.exit_code).toBe(1);
  });

  it("refuses a confirmation published under another boot: no current-boot daemon record, so canary_failed and daemon_telemetry_stale", () => {
    const envelope = evaluate(set(D + "boot_id", "boot-fixture-previous"));
    expect(envelope.wall.reasons).toContain("canary_failed");
    expect(envelope.wall.reasons).toContain("daemon_telemetry_stale");
    expect(envelope.wall.reasons).not.toContain("initializing");
    expect(UP).toBeGreaterThan(canaryWindow(30 * SECOND));
    expect(envelope.wall.state).toBe("wall_DOWN");
  });

  it("an operator-uid allow is never a canary_destination_allowed and never satisfies the gate", () => {
    // The producer ignores operator allows, so the record carries no sighting and no confirmation.
    const envelope = evaluate(set(D + "raw.canary.last_confirmation", null), set(D + "raw.canary.last_destination_allowed", null));
    expect(envelope.wall.reasons).toContain("canary_failed");
    expect(envelope.wall.reasons).not.toContain("canary_destination_allowed");
  });

  it.each(["agent", "gate"])("a %s-uid allow gives canary_destination_allowed, held for HISTORY_WINDOW", principal => {
    const held = evaluate(set(D + "raw.canary.last_destination_allowed", { captured_at_ms: NOW - HISTORY_WINDOW + SECOND, principal }));
    expect(held.wall.state).toBe("wall_DOWN");
    expect(held.wall.reasons).toContain("canary_destination_allowed");
    const aged = evaluate(set(D + "raw.canary.last_destination_allowed", { captured_at_ms: NOW - HISTORY_WINDOW - SECOND, principal }));
    expectWallOk(aged);
  });

  it("canary_destination_allowed outranks every wall reason except crash_latched", () => {
    const envelope = evaluate(
      set(D + "raw.canary.last_destination_allowed", { captured_at_ms: NOW - MINUTE, principal: "gate" }),
      set(O + "raw.session", "reboot_no_login"),
      set(O + "raw.availability.status", "not_live"),
      set(D + "raw.lease.deadline_ms", NOW - 1),
    );
    expect(envelope.wall.state).toBe("wall_DOWN");
    expect(envelope.wall.reasons[0]).toBe("canary_destination_allowed");
    const latched = evaluate(set(D + "raw.canary.last_destination_allowed", { captured_at_ms: NOW - MINUTE, principal: "gate" }), set(O + "raw.full_service.latched", true));
    expect(latched.wall.reasons.slice(0, 2)).toEqual(["crash_latched", "canary_destination_allowed"]);
  });

  it.each([
    ["missing", [set(O + "raw.canary_integrity", null)]],
    ["false", [set(O + "raw.canary_integrity.passed", false)]],
    ["older than OBSERVER_WINDOW", [set(O + "raw.canary_integrity.checked_at_ms", NOW - OBSERVER_WINDOW - SECOND)]],
  ] as const)("an integrity result that is %s is canary_unprovisioned with a fresh drop, never canary_failed", (_name, patches) => {
    const envelope = evaluate(...patches);
    expect(envelope.wall.state).toBe("wall_DOWN");
    expect(envelope.wall.reasons).toContain("canary_unprovisioned");
    expect(envelope.wall.reasons).not.toContain("canary_failed");
    expect(envelope.coverage.state).toBe("coverage_UNAVAILABLE");
  });
});

describe("commissioning", () => {
  it("an unset LAUNCHD_LEEWAY is commissioning_unproven, wall not OK and coverage UNAVAILABLE", () => {
    const envelope = evaluate(del(C + "launchd_leeway_s"));
    expect(envelope.wall.reasons).toContain("commissioning_unproven");
    expect(envelope.wall.state).toBe("wall_DOWN");
    expect(envelope.coverage.state).toBe("coverage_UNAVAILABLE");
  });

  it("a leeway of 243 s is both observation_invalid and commissioning_unproven", () => {
    const envelope = evaluate(set(C + "launchd_leeway_s", LAUNCHD_LEEWAY_MAX / SECOND + 1));
    expect(envelope.wall.reasons).toContain("observation_invalid");
    expect(envelope.wall.reasons).toContain("commissioning_unproven");
    expect(envelope.coverage.state).toBe("coverage_UNAVAILABLE");
  });

  it("a leeway of 242 s is accepted with a CANARY_WINDOW of 510 s", () => {
    const leeway = LAUNCHD_LEEWAY_MAX / SECOND;
    expect(canaryWindow(LAUNCHD_LEEWAY_MAX)).toBe(510 * SECOND);
    const inside = evaluate(set(C + "launchd_leeway_s", leeway),
      set(D + "raw.canary.last_confirmation.captured_at_ms", NOW - 509 * SECOND), set(D + "raw.canary.last_confirmation.confirmed_at_ms", NOW - 500 * SECOND));
    expectWallOk(inside);
    const outside = evaluate(set(C + "launchd_leeway_s", leeway),
      set(D + "raw.canary.last_confirmation.captured_at_ms", NOW - 511 * SECOND), set(D + "raw.canary.last_confirmation.confirmed_at_ms", NOW - 500 * SECOND));
    expect(outside.wall.reasons).toContain("canary_failed");
  });

  it("a false wall commissioned flag is wall commissioning_unproven and coverage UNAVAILABLE", () => {
    const envelope = evaluate(set(C + "commissioning.wall", false));
    expect(envelope.wall.reasons).toContain("commissioning_unproven");
    expect(envelope.wall.state).toBe("wall_DOWN");
    expect(envelope.coverage.state).toBe("coverage_UNAVAILABLE");
  });

  it("an absent config.json is wall commissioning_unproven", () => {
    const envelope = evaluate(set("config", { status: "absent" }));
    expect(envelope.wall.reasons).toContain("commissioning_unproven");
    expect(envelope.coverage.state).toBe("coverage_UNAVAILABLE");
  });

  it.each([
    ["PTB version mismatch", [set(C + "ptb.version", "22.5")]],
    ["PTB timeout mismatch", [set(C + "ptb.timeout_s", 30)]],
    ["unset POLL_BACKOFF_CAP", [del(C + "poll_backoff_cap_s")]],
    ["empty messaging set", [set(C + "messaging.ipv4", [])]],
  ] as const)("an agent-only commissioning_unproven (%s) gives coverage WALL_ONLY and leaves the wall unchanged", (_name, patches) => {
    const envelope = evaluate(...patches);
    expect(envelope.agent.reasons).toContain("commissioning_unproven");
    expect(envelope.agent.state).toBe("agent_UNMONITORED");
    expect(envelope.coverage.state).toBe("coverage_WALL_ONLY");
    expectWallOk(envelope);
  });

  it("a poll backoff cap above its maximum is agent observation_invalid and counts as unset", () => {
    const envelope = evaluate(set(C + "poll_backoff_cap_s", 418));
    expect(envelope.agent.reasons).toContain("observation_invalid");
    expect(envelope.agent.reasons).toContain("commissioning_unproven");
    expectWallOk(envelope);
  });

  it("an unrecorded alert drill keeps coverage below COMPLETE without touching the wall", () => {
    const envelope = evaluate(set(C + "commissioning.alert_drill", false));
    expect(envelope.coverage.state).not.toBe("coverage_COMPLETE");
    expectWallOk(envelope);
  });
});

describe("strict records", () => {
  it.each([
    ["daemon increased", [set(D + "raw.decisions.increased", true)], "wall"],
    ["daemon healthy", [set(D + "raw.healthy", true)], "wall"],
    ["daemon stored OK", [set(D + "state", "OK")], "wall"],
    ["daemon unknown version", [set(D + "schema_version", 2)], "wall"],
    ["observer wall part stored OK", [set(O + "raw.availability.ok", true)], "wall"],
    ["observer agent sample increased", [set(O + "raw.census.samples.3.increased", true)], "agent"],
    ["observer agent sample healthy", [set(O + "raw.census.healthy", true)], "agent"],
    ["config unknown version", [set(C + "schema_version", 2)], "wall"],
  ] as const)("%s is observation_invalid on its component and never partially read", (_name, patches, component) => {
    const envelope = evaluate(...patches);
    if (component === "wall") {
      expect(envelope.wall.reasons).toContain("observation_invalid");
      expect(envelope.wall.state).toBe("wall_DOWN");
    } else {
      expect(envelope.agent.reasons).toContain("observation_invalid");
      expect(envelope.agent.state).toBe("agent_DOWN");
      // The bad agent subtree is refused whole: no census run is credited from the remaining samples.
      expect(envelope.agent.evidence.census_run_age_ms).toBeUndefined();
      expectWallOk(envelope);
    }
  });
});

describe("freshness", () => {
  it("a stale daemon record is daemon_telemetry_stale", () => {
    const envelope = evaluate(set(D + "observed_at", new Date(NOW - 50 * SECOND).toISOString()), set(D + "observed_uptime_ms", UP - 50 * SECOND));
    expect(envelope.wall.reasons).toContain("daemon_telemetry_stale");
    expect(envelope.wall.state).toBe("wall_DOWN");
  });

  it.each([
    ["future observed_at", [set(D + "observed_at", new Date(NOW + 10 * SECOND).toISOString()), set(D + "observed_uptime_ms", UP + 10 * SECOND)]],
    ["negative uptime age", [set(D + "observed_uptime_ms", UP + 5 * SECOND), set(D + "observed_at", new Date(NOW).toISOString())]],
    ["UTC and uptime divergence beyond LOCAL_JITTER", [set(D + "observed_uptime_ms", UP - 20 * SECOND)]],
  ] as const)("%s is time_untrusted", (_name, patches) => {
    const envelope = evaluate(...patches);
    expect(envelope.wall.reasons).toContain("time_untrusted");
    expect(envelope.wall.state).toBe("wall_DOWN");
  });

  it("a failed boot provider is time_untrusted on the wall and the agent", () => {
    const envelope = evaluate(set("host", { ok: false }));
    expect(envelope.wall.reasons).toEqual(["time_untrusted"]);
    expect(envelope.agent.reasons).toEqual(["time_untrusted"]);
    expect(envelope.wall.state).toBe("wall_DOWN");
    expect(envelope.exit_code).toBe(1);
  });

  it("a counter regression without a new instance is counter_regression", () => {
    const envelope = evaluate(set(O + "raw.daemon_ref.sequence", 101));
    expect(envelope.wall.reasons).toContain("counter_regression");
    const newInstance = evaluate(set(O + "raw.daemon_ref", { daemon_instance: "daemon-fixture-0", sequence: 900 }));
    expect(newInstance.wall.reasons).not.toContain("counter_regression");
    expect(newInstance.wall.state.startsWith("wall_OK_")).toBe(false);
    expect(newInstance.wall.state).toBe("wall_RECOVERING");
    expect(newInstance.wall.reasons).toEqual(["recovering"]);
    expect(newInstance.exit_code).toBe(1);
  });

  it("an observer referencing an earlier daemon instance is never credited toward OK, even at a lower sequence", () => {
    // The restarted daemon reuses the PID and restarts its sequence, so only the instance label tells the two apart.
    const restarted = [set(D + "daemon_instance", "daemon-fixture-2"), set(D + "sequence", 5)];
    for (const sequence of [0, 4, 5, 900]) {
      const envelope = evaluate(...restarted, set(O + "raw.daemon_ref", { daemon_instance: "daemon-fixture-1", sequence }));
      expect(envelope.wall.reasons, `sequence ${sequence}`).toEqual(["recovering"]);
      expect(envelope.exit_code).toBe(1);
    }
  });

  it("recovers to OK once a fresh observer record references the current instance, with the daemon sequence ahead of the reference", () => {
    const restarted = [set(D + "daemon_instance", "daemon-fixture-2"), set(D + "sequence", 5)];
    const coherent = evaluate(...restarted, set(O + "raw.daemon_ref", { daemon_instance: "daemon-fixture-2", sequence: 4 }));
    expectWallOk(coherent);
    expect(coherent.wall.reasons).toEqual(["none"]);
    const regressed = evaluate(...restarted, set(O + "raw.daemon_ref", { daemon_instance: "daemon-fixture-2", sequence: 6 }));
    expect(regressed.wall.reasons).toContain("counter_regression");
    expect(regressed.exit_code).toBe(1);
  });

  it("other-boot records read initializing while the instance is younger than CANARY_WINDOW, never time_untrusted and never OK", () => {
    const envelope = evaluate(set("host.uptimeMs", 100 * SECOND), set(D + "boot_id", "boot-fixture-previous"), set(O + "boot_id", "boot-fixture-previous"));
    expect(envelope.wall.reasons).toEqual(["initializing"]);
    expect(envelope.wall.state).toBe("wall_INITIALIZING");
    expect(envelope.exit_code).toBe(1);
  });

  it("other-boot records read the absence reasons once the instance is older than CANARY_WINDOW", () => {
    const envelope = evaluate(set(D + "boot_id", "boot-fixture-previous"), set(O + "boot_id", "boot-fixture-previous"));
    expect(sorted(envelope.wall.reasons)).toEqual(sorted(["observer_missing", "daemon_telemetry_stale", "canary_failed"]));
    expect(envelope.wall.reasons).not.toContain("time_untrusted");
    expect(envelope.wall.state).toBe("wall_DOWN");
    expect(envelope.agent.state).toBe("agent_DOWN");
    expect(envelope.agent.reasons).toEqual(["observer_missing"]);
  });

  it.each([
    ["fortress id", [set(D + "subject.fortress_id", "fortress-fedcba9876543210")]],
    ["platform", [set(D + "subject.platform", "linux")]],
    ["operator uid", [set(D + "subject.operator_uid", 777)]],
    ["agent uid", [set(D + "subject.agent_uid", 777)]],
  ] as const)("a daemon record whose subject %s does not match is wall observation_invalid", (_name, patches) => {
    const envelope = evaluate(...patches);
    expect(envelope.wall.reasons).toContain("observation_invalid");
    expect(envelope.wall.state).toBe("wall_DOWN");
  });

  it("an observer record whose subject does not match is observation_invalid on both components it carries", () => {
    const envelope = evaluate(set(O + "subject.agent_uid", 777));
    expect(envelope.wall.reasons).toContain("observation_invalid");
    expect(envelope.agent.reasons).toContain("observation_invalid");
  });
});

describe("host sleep, boot and lock rows", () => {
  it("an uptime gap beyond every window is DOWN", () => {
    const sleep = 2 * 60 * MINUTE;
    const envelope = evaluate({ op: "add", path: "nowMs", value: sleep }, { op: "add", path: "host.uptimeMs", value: sleep });
    expect(envelope.wall.state).toBe("wall_DOWN");
    expect(envelope.wall.reasons).toContain("canary_failed");
  });

  it("recovery needs a post-fault drop plus two samples RECOVERY_GAP apart", () => {
    const fault = set(O + "recovery.wall.fault_uptime_ms", UP - 100 * SECOND);
    expectWallOk(evaluate(fault));
    const preFaultDrop = evaluate(fault, set(D + "raw.canary.last_confirmation.captured_at_ms", NOW - 150 * SECOND), set(D + "raw.canary.last_confirmation.confirmed_at_ms", NOW - 149 * SECOND));
    expect(preFaultDrop.wall.state).toBe("wall_RECOVERING");
    const closeSamples = evaluate(fault, set(O + "recovery.wall.samples.0.observed_uptime_ms", UP - 10 * SECOND));
    expect(closeSamples.wall.state).toBe("wall_RECOVERING");
    const oneSample = evaluate(set(O + "recovery.wall.samples", [{ sequence: 50, observed_uptime_ms: UP - 3 * SECOND }]));
    expect(oneSample.wall.state).toBe("wall_RECOVERING");
  });

  it("first fire after boot with old-boot records only and a young reader uptime is wall_INITIALIZING", () => {
    const envelope = evaluate(set("host.uptimeMs", CANARY_WINDOW_BASE - MINUTE), set(D + "boot_id", "boot-fixture-previous"), set(O + "boot_id", "boot-fixture-previous"));
    expect(envelope.wall.state).toBe("wall_INITIALIZING");
    expect(envelope.wall.reasons).toEqual(["initializing"]);
    expect(envelope.exit_code).toBe(1);
    expect(envelope.agent.state).toBe("agent_DOWN");
    expect(envelope.agent.reasons).toEqual(["observer_missing"]);
  });

  it("a young current-boot daemon whose lock field is not_instrumented still selects DOWN", () => {
    const young = 100 * SECOND;
    const envelope = evaluate(set(D + "instance_started_uptime_ms", UP - young), set(D + "raw.canary.last_confirmation", null), set(D + "raw.lock_recovery", { state: "not_instrumented" }));
    expect(envelope.wall.reasons).toContain("evidence_incomplete");
    expect(envelope.wall.reasons).toContain("initializing");
    expect(envelope.wall.state).toBe("wall_DOWN");
  });

  it("crash_latched in a current-boot observer record selects DOWN even during first fire", () => {
    const uptime = 100 * SECOND;
    const envelope = evaluate(set("host.uptimeMs", uptime), set(D + "boot_id", "boot-fixture-previous"),
      set(O + "observed_uptime_ms", uptime - 3 * SECOND), set(O + "recovery.wall.samples", []), set(O + "recovery.agent.samples", []),
      set(O + "raw.full_service.latched", true));
    expect(envelope.wall.reasons).toContain("crash_latched");
    expect(envelope.wall.state).toBe("wall_DOWN");
  });

  it("past CANARY_WINDOW the old-boot-only fixture is DOWN with exactly the three absence reasons", () => {
    const envelope = evaluate(set("host.uptimeMs", canaryWindow(30 * SECOND) + MINUTE), set(D + "boot_id", "boot-fixture-previous"), set(O + "boot_id", "boot-fixture-previous"));
    expect(sorted(envelope.wall.reasons)).toEqual(sorted(["observer_missing", "daemon_telemetry_stale", "canary_failed"]));
    expect(envelope.wall.state).toBe("wall_DOWN");
    expect(envelope.agent.reasons).toEqual(["observer_missing"]);
  });

  it("an otherwise wall-OK daemon record with a not_instrumented lock field is evidence_incomplete, wall DOWN, exit 1", () => {
    const envelope = evaluate(set(D + "raw.lock_recovery", { state: "not_instrumented" }));
    expect(envelope.wall.reasons).toEqual(["evidence_incomplete"]);
    expect(envelope.wall.state).toBe("wall_DOWN");
    expect(envelope.exit_code).toBe(1);
  });

  it("the instrumented lock shape with a saturated count is observation_invalid", () => {
    const envelope = evaluate(set(D + "raw.lock_recovery.count", Number.MAX_SAFE_INTEGER));
    expect(envelope.wall.reasons).toContain("observation_invalid");
  });

  it("a saturated canary failure count is observation_invalid", () => {
    const envelope = evaluate(set(D + "raw.canary.failure_count", Number.MAX_SAFE_INTEGER));
    expect(envelope.wall.reasons).toContain("observation_invalid");
  });

  it("a read deadline carries the internal exit in the envelope", () => {
    const deadline = { status: "custody_invalid", cause: "read_deadline" };
    const envelope = evaluateLiveness({ ...patched([]), daemon: deadline, observer: deadline, config: deadline, readDeadlineHit: true } as LivenessInput);
    expect(envelope.wall.reasons).toContain("custody_invalid");
    expect(envelope.wall.evidence.cause).toBe("read_deadline");
    expect(envelope.exit_code).toBe(70);
  });

  it("carries the agent uid in the envelope subject without paths", () => {
    const envelope = evaluate();
    expect(envelope.subject).toEqual({ fortress_id: STATES.base.local.fortress_id, platform: "darwin", operator_uid: 501, agent_uid: AGENT_UID });
    expect(envelope.notifications_silenced_until).toBeNull();
  });
});
