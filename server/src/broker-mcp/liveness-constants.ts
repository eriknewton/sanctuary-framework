/**
 * Secret-broker daemon liveness-heartbeat constants (Option C, Erik-ratified).
 *
 * These mirror the Castle Wall observability Slice-2 heartbeat constants
 * (`castle-wall/constants.ts`) for the long-running `sanctuary broker-server`
 * MCP daemon. They are at-rest audit operation strings + a provenance marker,
 * read by the feature-health reader (`principal-policy/feature-health.ts`) to
 * answer ONE blunt question: is the broker daemon PROCESS still alive, or did it
 * silently die in a quiet window?
 *
 * HONEST SCOPE (do NOT overclaim; the multi-angle review hammers this):
 *
 *  - A heartbeat proves ONLY that the long-running broker daemon PROCESS is
 *    alive (it detects the process dying / being killed / wedging). It does NOT
 *    prove the broker would correctly mint or deny a token (no enforcement
 *    evidence exists for that), NOT that the keychain backend is reachable, and
 *    it says NOTHING about the per-invocation `sanctuary secrets` CLI or the
 *    in-server tool path. The reader label is "broker daemon alive" / process
 *    liveness, NEVER "broker healthy" or green.
 *  - The matching feature-health row carries an EMPTY `invocationOps` set, so it
 *    is STRUCTURALLY impossible for the heartbeat ever to earn the green
 *    `active` light. A heartbeat is liveness, not request-correctness.
 *
 * TRUST BASIS (same boundary the Castle Wall channel heartbeat discloses): the
 * heartbeat is a DIRECT channel-basis `auditLog.append` (provenance marker only,
 * NO producer signature) - the broker has no per-event producer-signing infra,
 * exactly like the Castle Wall heartbeat on a non-key-bearing host. The reader
 * recognizes it on the CHANNEL/marker basis (`livenessEntryCounts`). An
 * in-process L3 writer that already holds `AuditLog.append` could mint a fake
 * fresh `broker_daemon_heartbeat` to suppress the silent-death alarm, but - like
 * the Castle Wall channel heartbeat - that can only move the verdict from
 * `fault`/red to a non-green `unknown`, NEVER manufacture green. This adds no
 * weaker trust basis than the alarm it relabels.
 *
 * These are NEW at-rest audit operation strings (documented per the
 * frozen-surface rule); none is a wire message type and none alters any existing
 * display string.
 */

/** Audit layer the broker daemon writes to. The broker is an L3 feature. */
export const BROKER_DAEMON_AUDIT_LAYER = "l3" as const;

/**
 * Audit operation name for the periodic broker daemon LIVENESS heartbeat. The
 * daemon appends an `l3` audit entry under this operation on an audit-cadence
 * interval (~45s), stamped with the broker provenance marker below, so the
 * reader can tell an alive broker daemon from one that silently died in a quiet
 * window.
 *
 * DISJOINT from the event-driven `broker_token_issued` / `broker_token_denied`
 * ops (the `secret_broker` row's invocation vocabulary): a liveness beat is NOT
 * a token decision and must never be counted as one.
 */
export const BROKER_DAEMON_HEARTBEAT_OPERATION = "broker_daemon_heartbeat" as const;

/**
 * Audit operation name for an INTENTIONAL broker daemon stand-down (clean stop).
 * The daemon appends an `l3` audit entry under this operation when it receives
 * SIGTERM / SIGINT (or the transport closes), stamped with the same broker
 * provenance marker the heartbeat carries.
 *
 * WHY IT EXISTS (the #657 false-RED lesson): a clean operator stop and a genuine
 * silent death both stop the liveness heartbeat. With NO recorded reason, a
 * heartbeat-then-silent pattern is indistinguishable from a daemon that was
 * KILLED mid-flight, so the silent-death reader would raise a false-RED
 * `dead_no_heartbeat` alarm for the whole digest window. This stand-down gives a
 * clean shutdown the recognizable "stood down on purpose" signal; only a GENUINE
 * silent death (process killed before it could announce) now leaves no
 * stand-down at all. This stand-down emission is the load-bearing parity
 * requirement with the corrected Castle Wall Slice-2 pattern.
 *
 * TRUST BASIS: a DIRECT channel-basis audit append (marker only, no producer
 * signature), EXACTLY like the heartbeat. The reader only lets it relabel
 * `fault` -> a non-green `unknown`, NEVER green, so it introduces no weaker trust
 * basis than the alarm it relabels.
 */
export const BROKER_DAEMON_STAND_DOWN_OPERATION = "broker_daemon_stopped" as const;

/**
 * Provenance marker stamped into the `details` of every heartbeat / stand-down
 * entry the broker daemon writes. It is constructed by the producer from fixed
 * fields only and stamped LAST, mirroring `CASTLE_WALL_AUDIT_PROVENANCE_KEY` /
 * `CASTLE_WALL_AUDIT_PROVENANCE_VALUE`. The reader REQUIRES it: a different L3
 * producer reusing the `broker_daemon_heartbeat` operation name (or a beat that
 * simply omits the marker) can never be mistaken for real broker daemon
 * liveness. There is NO signature scheme here - recognition rests on the
 * channel/marker basis, the same basis a genuine Castle Wall heartbeat uses on a
 * non-key-bearing host.
 */
export const BROKER_DAEMON_AUDIT_PROVENANCE_KEY = "broker_source" as const;
export const BROKER_DAEMON_AUDIT_PROVENANCE_VALUE = "broker_daemon" as const;

/**
 * Audit-cadence interval (seconds) for the periodic liveness heartbeat. ~45s,
 * matching the Castle Wall audit heartbeat cadence, so a daemon that silently
 * dies is surfaced within roughly the same window on both surfaces.
 */
export const BROKER_DAEMON_HEARTBEAT_INTERVAL_SECONDS = 45 as const;
