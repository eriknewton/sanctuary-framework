/**
 * Shared liveness contract constants: windows, caps, exit codes, the canary
 * tuple and the closed reason registry.
 *
 * This module is platform-neutral and imports nothing from `castle-wall/runtime/`
 * or `cli/`, because the bundled contract (`dist/liveness-contract.v1.mjs`) must
 * carry no filesystem, network or process import. Reused values from those trees
 * are re-typed here with a one-sided pin; the parity test imports both sides.
 */
import {
  DEFAULT_EMISSION_STALL_GRACE_MS,
  DEFAULT_EMISSION_STALL_MIN_DECISIONS,
} from "../audit/emission-liveness.js";

// ---------------------------------------------------------------------------
// Units. Every window below is milliseconds.
// ---------------------------------------------------------------------------
export const SECOND = 1000;
export const MINUTE = 60 * SECOND;
export const HOUR = 60 * MINUTE;
export const DAY = 24 * HOUR;

/** Version of the stored record schema; an unknown version is never partially read. */
export const LIVENESS_SCHEMA_VERSION = 1;
/** Version of the evaluator logic reported beside every derived envelope. */
export const LIVENESS_EVALUATOR_VERSION = 1;

// ---------------------------------------------------------------------------
// Reused from existing source (re-typed; parity proven by reason-registry.test.ts).
// ---------------------------------------------------------------------------
/** Re-typed because the daemon default is an inline literal (`armLeaseHeartbeatIntervalSeconds ?? 5`), not an export. */
export const LEASE_PERIOD = 5 * SECOND;
// Must match DEFAULT_ENFORCEMENT_AVAILABILITY_FRESHNESS_MS in server/src/castle-wall/runtime/enforcement-availability.ts.
export const AVAILABILITY_WINDOW = 30 * SECOND;
// Must match CASTLE_WALL_DEFAULT_EMISSION_LIVENESS_TICK_SECONDS in server/src/castle-wall/runtime/macos-daemon.ts (seconds there).
export const DETECTOR_PERIOD = 15 * SECOND;
/** The daemon publishes its record right after each detector tick, so the two periods are one. */
export const DAEMON_PERIOD = DETECTOR_PERIOD;
/** Two missed ticks are tolerated, then the third period fails. */
export const DETECTOR_WINDOW = 3 * DETECTOR_PERIOD;
export const DAEMON_WINDOW = DETECTOR_WINDOW;
/** Already milliseconds in its source module; never multiply it by SECOND again. */
export const EMISSION_GRACE = DEFAULT_EMISSION_STALL_GRACE_MS;
export const MIN_DECISIONS = DEFAULT_EMISSION_STALL_MIN_DECISIONS;
// Must match CASTLE_WALL_DEFAULT_AUDIT_HEARTBEAT_INTERVAL_SECONDS in server/src/castle-wall/runtime/macos-daemon.ts (seconds there).
export const AUDIT_PERIOD = 45 * SECOND;
/** The last successful durable heartbeat flush may be at most three audit periods old. */
export const HEARTBEAT_WINDOW = 3 * AUDIT_PERIOD;

// ---------------------------------------------------------------------------
// Observer timing.
// ---------------------------------------------------------------------------
export const OBSERVER_PERIOD = 10 * SECOND;
/** Observer scheduling and publication allocation only; not a canary launch term. */
export const LOCAL_JITTER = 2 * SECOND;
export const IPC_DEADLINE = 3 * SECOND;
export const TERM_GRACE = 1 * SECOND;
export const KILL_REAP_GRACE = 1 * SECOND;
/** Parallel bounded reads, including cancellation and reaping. */
export const COLLECT_DEADLINE = 2 * IPC_DEADLINE;
/** Worst start phase plus admitted jitter plus one complete collection. */
export const OBSERVATION_GAP = OBSERVER_PERIOD + LOCAL_JITTER + COLLECT_DEADLINE;
/** Greater than the healthy completion gap; an older observer record is stale. */
export const OBSERVER_WINDOW = 3 * OBSERVER_PERIOD;
/** Bounds every reader operation, so a stalled filesystem read cannot hold a status command. */
export const STATUS_READ_DEADLINE = COLLECT_DEADLINE;
/** The pause between the two process reads of one cycle: one full termination allocation. */
export const CENSUS_REREAD = TERM_GRACE + KILL_REAP_GRACE;
/** One bounded process read; two reads plus the pause and one termination fit COLLECT_DEADLINE. */
export const PROCESS_READ_DEADLINE = 1 * SECOND;
/** 6 - 1 - 1 = 4 s: a child read plus its termination fits one cycle deadline. */
export const CHILD_READ_DEADLINE = COLLECT_DEADLINE - TERM_GRACE - KILL_REAP_GRACE;
/** The named children one observer cycle may hold at once, one slot each. */
export const OBSERVER_CYCLE_CHILD_SET = Object.freeze([
  "full_agent_print", "canary_print", "harness_print", "ps", "id_chain", "sysctl",
] as const);
/** 6: the length of the named per-cycle child set. */
export const OBSERVER_CYCLE_CHILDREN = OBSERVER_CYCLE_CHILD_SET.length;
/** The netstat sampler runs on its own timer and owns one slot. */
export const CENSUS_CHILDREN = 1;
/** 6 + 1 = 7: every per-cycle child plus the census child. */
export const MAX_COLLECTION_CHILDREN = OBSERVER_CYCLE_CHILDREN + CENSUS_CHILDREN;
/** launchd ThrottleInterval of the observer: a restarting observer cannot republish faster than its own period. */
export const WATCH_THROTTLE_INTERVAL_S = OBSERVER_PERIOD / SECOND;

// ---------------------------------------------------------------------------
// Canary.
// ---------------------------------------------------------------------------
// Must match the canary tuple checks in server/src/castle-wall/runtime/audit-consumer.ts.
/** TEST-NET-1 documentation address; nothing else may contact it and no allow rule may cover it. */
export const CANARY_IP = "192.0.2.254";
/** The unused discard port, used only as a correlation key. */
export const CANARY_PORT = 9;
export const CANARY_PROTOCOL = "tcp";

/**
 * Monitoring-origin label for the canary tuple. The agent uid is a placeholder
 * that commissioning binds from `config.json`.
 *
 * Consumers exclude this monitoring-origin tuple.
 *
 * Must match `isMonitoringOriginDestination` in server/src/castle-wall/liveness/monitoring-origin.ts,
 * and its four consumer call sites in server/src/castle-wall/observe/adapter.ts,
 * server/src/evidence-pack/inventory.ts, server/src/principal-policy/posture.ts and
 * server/src/castle-wall/audit/per-rule-report.ts.
 */
export const CANARY_MONITORING_ORIGIN = Object.freeze({
  agent_uid: "commissioned-agent-uid",
  dest_ip: CANARY_IP,
  dest_port: CANARY_PORT,
  dest_protocol: CANARY_PROTOCOL,
} as const);

/** launchd StartInterval of the canary job. */
export const CANARY_PERIOD = 3 * MINUTE;
/** curl connect and total time cap. */
export const CANARY_CONNECT_DEADLINE = 2 * LEASE_PERIOD;
/** From the drop to primary persistence; also the slot deadline. */
export const CANARY_SETTLE = EMISSION_GRACE;
/** Latest primary confirmation, then the latest observer sample. */
export const RECORD_DELIVERY_SLACK = CANARY_SETTLE + OBSERVATION_GAP;
export const ALERT_TARGET = 15 * MINUTE;

// Remote and delivery bound, reproduced from its named terms.
export const REMOTE_PERIOD = 3 * MINUTE;
export const REMOTE_JITTER = 10 * SECOND;
export const SSH_CONNECT = 5 * SECOND;
export const SSH_DEADLINE = 4 * SSH_CONNECT;
export const SENDER_PERIOD = 10 * SECOND;
export const SENDER_JITTER = 2 * SECOND;
export const SEND_DEADLINE = 30 * SECOND;
export const SEND_BOUND = SENDER_PERIOD + SENDER_JITTER + SEND_DEADLINE;
export const PHONE_BUDGET = 2 * MINUTE;
/** 180 + 10 + 20 + 42 + 120 = 372 s from the remote poll through phone receipt. */
export const REMOTE_AND_DELIVERY_BOUND = REMOTE_PERIOD + REMOTE_JITTER + SSH_DEADLINE + SEND_BOUND + PHONE_BUDGET;

/** 900 - (180 + 10 + 78 + 18 + 372) = 242 s; a larger commissioned leeway would push the wall loss bound past the alert target. */
export const LAUNCHD_LEEWAY_MAX =
  ALERT_TARGET - (CANARY_PERIOD + CANARY_CONNECT_DEADLINE + RECORD_DELIVERY_SLACK + OBSERVATION_GAP + REMOTE_AND_DELIVERY_BOUND);
/** 180 + 10 + 78 = 268 s before the commissioned launchd leeway is added. */
export const CANARY_WINDOW_BASE = CANARY_PERIOD + CANARY_CONNECT_DEADLINE + RECORD_DELIVERY_SLACK;
/** The recording-proof horizon for a commissioned leeway in milliseconds. */
export function canaryWindow(launchdLeewayMs: number): number {
  return CANARY_WINDOW_BASE + launchdLeewayMs;
}
/** The recording window is the canary window. */
export const recordingWindow = canaryWindow;
/** Warn while less than one full recording-proof horizon of TTL remains. */
export const ttlWarningWindow = canaryWindow;
/** Every on-schedule fire re-arms; agent traffic on the same tuple forces at most two per period. */
export const CANARY_SLOT_REARM = CANARY_PERIOD / 2;
/** 86400 / 180 = 480 nominal forced primaries a day. */
export const CANARY_PRIMARY_NOMINAL_PER_DAY = DAY / CANARY_PERIOD;
/** 86400 / 90 = 960, the hard ceiling on forced primary entries a day. */
export const CANARY_PRIMARY_CAP_PER_DAY = DAY / CANARY_SLOT_REARM;
/** 180: launchd StartInterval is in seconds. */
export const CANARY_START_INTERVAL_S = CANARY_PERIOD / SECOND;
/** 10: curl takes its connect and total deadlines in seconds. */
export const CANARY_CURL_DEADLINE_S = CANARY_CONNECT_DEADLINE / SECOND;
// Declared once here and imported everywhere; must match the CANARY_LABEL row in server/reorg-surface-manifest.md.
/** launchd label of the root-owned canary LaunchDaemon, in the label family of the full agent. */
export const CANARY_LABEL = "ai.sanctuaryprotocol.castle-wall.canary";
// Declared once here and imported everywhere; must match the OBSERVER_LABEL row in server/reorg-surface-manifest.md.
/** launchd label of the operator observer LaunchAgent. */
export const OBSERVER_LABEL = "ai.sanctuaryprotocol.castle-wall.watch";

// ---------------------------------------------------------------------------
// Census and agent.
// ---------------------------------------------------------------------------
/** Consecutive strictly growing sample pairs a healthy identity needs. */
export const CENSUS_RUN = 3;
/** Sample spacing; greater than POLL_TIMEOUT, so an idle healthy long poll completes at least once per pair. */
export const CENSUS_PERIOD = 15 * SECOND;
/** python-telegram-bot 22.6, telegram.ext._updater, Updater.start_polling default `timeout` (poll_interval default 0.0). */
export const POLL_TIMEOUT = 10 * SECOND;
/** Hermes gateway telegram platform `read_timeout`, default 20.0 from HERMES_TELEGRAM_HTTP_READ_TIMEOUT. */
export const READ_TIMEOUT = 20 * SECOND;
/** 15 - 2 = 13 s, still greater than POLL_TIMEOUT so the per-pair completion derivation holds. */
export const CENSUS_PAIR_MIN = CENSUS_PERIOD - LOCAL_JITTER;
/** 15 + 2 + 6 = 23 s, a late but valid sample pair. */
export const CENSUS_PAIR_MAX = CENSUS_PERIOD + LOCAL_JITTER + COLLECT_DEADLINE;
/** 45 + 10 + 20 + 18 = 93 s before the commissioned poll backoff cap is added. */
export const AGENT_WINDOW_BASE = CENSUS_RUN * CENSUS_PERIOD + POLL_TIMEOUT + READ_TIMEOUT + OBSERVATION_GAP;
/** The agent freshness horizon for a commissioned poll backoff cap in milliseconds. */
export function agentWindow(pollBackoffCapMs: number): number {
  return AGENT_WINDOW_BASE + pollBackoffCapMs;
}
/** 900 - 18 - 372 = 510 s. */
export const AGENT_WINDOW_MAX = ALERT_TARGET - OBSERVATION_GAP - REMOTE_AND_DELIVERY_BOUND;
/** 510 - 93 = 417 s; a larger commissioned cap is invalid and counts as unset. */
export const POLL_BACKOFF_CAP_MAX = AGENT_WINDOW_MAX - AGENT_WINDOW_BASE;
/** The attended PTB transport confirmation commissioning must record exactly. */
export const COMMISSIONED_PTB = Object.freeze({
  version: "22.6",
  timeout_s: POLL_TIMEOUT / SECOND,
  poll_interval_s: 0,
  separate_get_updates_request: true,
  http_version: "1.1",
  hermes_read_timeout_s: READ_TIMEOUT / SECOND,
} as const);
/** The only messaging-service port the census credits. */
export const CENSUS_MESSAGING_PORT = 443;

// ---------------------------------------------------------------------------
// Other windows and bounds.
// ---------------------------------------------------------------------------
/** Two detector grace windows for the oldest owned unresolved evidence. */
export const PENDING_WRITE_WINDOW = 2 * EMISSION_GRACE;
// Must match FULL_AGENT_CRASH_WINDOW_S in server/src/cli/castle-wall-full-agent-state.ts (seconds there).
export const HISTORY_WINDOW = 30 * MINUTE;
/** Two independent complete samples separated by at least two observation periods. */
export const RECOVERY_GAP = 2 * OBSERVER_PERIOD;
const KIB = 1024;
export const STATUS_BYTES = 64 * KIB;
export const CONFIG_BYTES = 16 * KIB;
/** Policy capacity: qualifying messaging-set candidates stored per sample. */
export const CENSUS_PID_ROWS = 4;
/** ceil((510 + 3 * 23) / 13) + 1 = ceil(579 / 13) + 1 = 46 samples a reader can need. */
export const CENSUS_SAMPLES_MAX = Math.ceil((AGENT_WINDOW_MAX + CENSUS_RUN * CENSUS_PAIR_MAX) / CENSUS_PAIR_MIN) + 1;
export const PROCESS_BYTES = KIB * KIB;
export const PROCESS_ROWS = 4096;
export const CENSUS_INPUT_BYTES = PROCESS_BYTES;
export const CENSUS_INPUT_ROWS = PROCESS_ROWS;
export const MAX_MESSAGING_PREFIXES = 32;
/** Policy capacity: script paths one config `mcp` block may name. */
export const MAX_MCP_SCRIPT_PATHS = 8;
/** Policy capacity: MCP candidate children one cycle may classify before the check fails closed. */
export const MAX_STALE_CHILDREN = 16;
/** 4 * 1024: four times the macOS PATH_MAX of 1024 bytes, a policy capacity for one configured path. */
export const PATH_BYTES = 4 * KIB;
/** Saturation point for every stored count; a saturated count reads observation_invalid. */
export const COUNTER_MAX = Number.MAX_SAFE_INTEGER;
/**
 * Bound on any stored identifier or label: printable ASCII without quote or
 * backslash, so its JSON encoding is exactly its length. 64 covers the longest
 * label this contract stores (a 36-character boot session UUID) with room for
 * prefixed digests and fixture names, and keeps the largest record inside
 * STATUS_BYTES.
 */
export const LABEL_BYTES = 64;
/** An account name is a label in this contract. */
export const ACCOUNT_NAME_MAX = LABEL_BYTES;
/** 21 = "255.255.255.255" (15) + "." + "65535" (5): a stored census row is always an IPv4 `addr.port`. */
export const CENSUS_ADDRESS_TEXT_MAX = 21;
/** 16 hex digits: `gencnt` is a 64-bit socket generation count. */
export const GENCNT_HEX_DIGITS = 16;
/** Bound on the typed evidence failure list one record may carry: one entry per registry slot (46). */
export const EVIDENCE_FAILURES_MAX = 46;
/** A record carries at most two recovery sample references per component. */
export const RECOVERY_SAMPLES_PER_COMPONENT = 2;

// ---------------------------------------------------------------------------
// Exit codes.
// ---------------------------------------------------------------------------
// Must match the exit mapping in server/src/cli/castle-wall-liveness-status.ts, server/src/cli/castle-wall.ts and server/src/cli/castle-wall-full-agent.ts.
// The installer exits WATCH_EXIT_CANARY_PENDING (5) and WATCH_EXIT_CANARY_STILL_INSTALLED (6) in
// server/src/cli/castle-wall-watch.ts must not equal any value in this block.
/** Wall OK. */
export const LIVENESS_EXIT_OK = 0;
/** Wall INITIALIZING, DOWN, RECOVERING, SAFE_MODE, REBOOT_NO_LOGIN or LOGGED_OUT. */
export const LIVENESS_EXIT_DOWN = 1;
/** Usage error; never a liveness value. */
export const LIVENESS_EXIT_USAGE = 2;
/** Wall TTL_WARNING or DEGRADED. */
export const LIVENESS_EXIT_WARNING = 3;
/** EX_SOFTWARE: internal inability to evaluate, including a read past STATUS_READ_DEADLINE. */
export const LIVENESS_STATUS_INTERNAL_EXIT_CODE = 70;
/** EX_CONFIG: install-full refused an unstable runtime path before any credential read or write. */
export const STABLE_RUNTIME_REFUSAL_EXIT_CODE = 78;

// ---------------------------------------------------------------------------
// Closed reason registry.
// ---------------------------------------------------------------------------
export type WallState =
  | "wall_INITIALIZING"
  | "wall_OK_ACTIVE"
  | "wall_OK_IDLE"
  | "wall_OK_AGED_HISTORY"
  | "wall_OK_TTL_COUNTDOWN"
  | "wall_TTL_WARNING"
  | "wall_DEGRADED"
  | "wall_DOWN"
  | "wall_RECOVERING"
  | "wall_SAFE_MODE"
  | "wall_REBOOT_NO_LOGIN"
  | "wall_LOGGED_OUT";
export type AgentState =
  | "agent_UNMONITORED"
  | "agent_INITIALIZING"
  | "agent_OK_PASSIVE"
  | "agent_OK_OPTIONAL_REPLY"
  | "agent_DEGRADED_STALE_MCP"
  | "agent_DOWN"
  | "agent_RECOVERING";
export type CoverageState =
  | "coverage_COMPLETE"
  | "coverage_WALL_ONLY"
  | "coverage_LEGACY_PARTIAL"
  | "coverage_UNAVAILABLE";

/** The state class a reason gives the wall, or `n/a` when the wall cannot carry it. */
export type WallClass =
  | "OK"
  | "INITIALIZING"
  | "RECOVERING"
  | "TTL_WARNING"
  | "DEGRADED"
  | "DOWN"
  | "SAFE_MODE"
  | "LOGGED_OUT"
  | "REBOOT_NO_LOGIN"
  | "REMOTE_LOCAL"
  | "n/a";
/** The state class a reason gives the agent, or `n/a` when the agent cannot carry it. */
export type AgentClass =
  | "OK"
  | "UNMONITORED"
  | "INITIALIZING"
  | "RECOVERING"
  | "DEGRADED_STALE_MCP"
  | "DOWN"
  | "DOWN_IF_REQUIRED"
  | "DOWN_IF_COMMISSIONED"
  | "n/a";
export type CoverageEffect =
  | "none"
  | "LEGACY_PARTIAL"
  | "WALL_ONLY"
  | "UNAVAILABLE"
  | "UNAVAILABLE_IF_WALL";
/** Who may produce the reason; only `evaluator` reasons come from this module. */
export type ReasonProducer = "evaluator" | "remote" | "remote_local";

export interface ReasonRegistryEntry {
  readonly position: number;
  readonly reason: string;
  readonly wall: WallClass;
  /** The evaluated exit for a wall carrying this reason, or null when the wall cannot carry it. */
  readonly wallExit: number | null;
  readonly agent: AgentClass;
  readonly coverage: CoverageEffect;
  readonly alarm: boolean;
  readonly producer: ReasonProducer;
}

function entry(
  reason: string,
  wall: WallClass,
  wallExit: number | null,
  agent: AgentClass,
  coverage: CoverageEffect = "none",
  producer: ReasonProducer = "evaluator",
): Omit<ReasonRegistryEntry, "position"> {
  return { reason, wall, wallExit, agent, coverage, alarm: reason !== "none", producer };
}

const D = LIVENESS_EXIT_DOWN;
const W = LIVENESS_EXIT_WARNING;
/**
 * The closed, totally ordered reason registry. Position is the severity
 * integer; nothing else re-types this list, and an unknown reason maps to
 * `observation_invalid` on the component that carried it.
 */
export const REASON_REGISTRY: readonly ReasonRegistryEntry[] = Object.freeze(
  [
    entry("none", "OK", LIVENESS_EXIT_OK, "OK"),
    entry("monitoring_incomplete", "n/a", null, "n/a", "LEGACY_PARTIAL"),
    entry("agent_unmonitored", "n/a", null, "UNMONITORED", "WALL_ONLY"),
    entry("unsupported_adapter", "DOWN", D, "UNMONITORED", "UNAVAILABLE"),
    entry("commissioning_unproven", "DOWN", D, "UNMONITORED", "UNAVAILABLE_IF_WALL"),
    entry("evidence_incomplete", "DOWN", D, "DOWN"),
    entry("initializing", "INITIALIZING", D, "INITIALIZING"),
    entry("recovering", "RECOVERING", D, "RECOVERING"),
    entry("ttl_expiring", "TTL_WARNING", W, "n/a"),
    entry("stale_mcp_child", "n/a", null, "DEGRADED_STALE_MCP"),
    entry("recent_restart", "DEGRADED", W, "n/a"),
    // The full daemon records its audit write-lock recoveries for the history window.
    entry("write_lock_recovery", "DEGRADED", W, "n/a"),
    entry("audit_backlog", "DEGRADED", W, "n/a"),
    entry("audit_loss", "DEGRADED", W, "n/a"),
    entry("audit_rejected", "DEGRADED", W, "n/a"),
    entry("heartbeat_stale", "DEGRADED", W, "n/a"),
    entry("emission_stall", "DEGRADED", W, "n/a"),
    entry("recording_unconfirmed", "DEGRADED", W, "n/a"),
    entry("optional_reply_failed", "n/a", null, "DOWN_IF_REQUIRED"),
    entry("agent_flow_stale", "n/a", null, "DOWN"),
    entry("census_unavailable", "n/a", null, "DOWN_IF_COMMISSIONED"),
    entry("agent_process_missing", "n/a", null, "DOWN"),
    entry("process_identity_unknown", "DOWN", D, "DOWN"),
    entry("canary_failed", "DOWN", D, "n/a"),
    entry("canary_unprovisioned", "DOWN", D, "n/a", "UNAVAILABLE"),
    entry("observer_missing", "DOWN", D, "DOWN", "UNAVAILABLE"),
    entry("observer_stale", "DOWN", D, "DOWN", "UNAVAILABLE"),
    entry("detector_stale", "DOWN", D, "n/a"),
    entry("daemon_telemetry_stale", "DOWN", D, "n/a"),
    entry("counter_regression", "DOWN", D, "DOWN"),
    entry("time_untrusted", "DOWN", D, "DOWN"),
    entry("observation_invalid", "DOWN", D, "DOWN"),
    entry("custody_invalid", "DOWN", D, "DOWN", "UNAVAILABLE"),
    entry("lease_expired", "DOWN", D, "n/a"),
    entry("enforcement_not_live", "DOWN", D, "n/a"),
    entry("safe_mode_only", "SAFE_MODE", D, "n/a"),
    entry("session_logged_out", "LOGGED_OUT", D, "n/a"),
    entry("reboot_no_login", "REBOOT_NO_LOGIN", D, "n/a"),
    entry("daemon_missing", "DOWN", D, "n/a"),
    entry("daemon_unresponsive", "DOWN", D, "n/a"),
    // The highest wall severity below the crash latch.
    entry("canary_destination_allowed", "DOWN", D, "n/a"),
    entry("crash_latched", "DOWN", D, "n/a"),
    entry("host_unreachable", "DOWN", D, "n/a", "none", "remote"),
    entry("monitor_stopped", "REMOTE_LOCAL", null, "n/a", "none", "remote_local"),
    entry("delivery_unconfirmed", "REMOTE_LOCAL", null, "n/a", "none", "remote_local"),
    entry("delivery_failed", "REMOTE_LOCAL", null, "n/a", "none", "remote_local"),
  ].map((item, position) => Object.freeze({ position, ...item })),
);

/** Equals the registry length; a test asserts it. */
export const REASON_SLOTS = 46;

export type LivenessReason = string;
const REASON_POSITIONS: ReadonlyMap<string, number> = new Map(
  REASON_REGISTRY.map(item => [item.reason, item.position]),
);
/** Severity position of a registered reason, or undefined for an unknown name. */
export function reasonPosition(reason: string): number | undefined {
  return REASON_POSITIONS.get(reason);
}
/** The registry entry for a registered reason, or undefined for an unknown name. */
export function reasonEntry(reason: string): ReasonRegistryEntry | undefined {
  const position = REASON_POSITIONS.get(reason);
  return position === undefined ? undefined : REASON_REGISTRY[position];
}

/** Records under `<fortress>/liveness/`. */
export const LIVENESS_DIRECTORY = "liveness";
export const DAEMON_RECORD_FILE = "daemon.json";
export const OBSERVER_RECORD_FILE = "observer.json";
export const CONFIG_RECORD_FILE = "config.json";
