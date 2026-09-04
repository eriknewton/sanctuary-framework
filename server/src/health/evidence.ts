import type { StatusResponse } from "../castle-wall/ipc/messages.js";
import {
  castleWallRuntimeReadiness,
  manifestFieldsAreAuthoritative,
} from "../castle-wall/ipc/messages.js";
import type { SanctuaryConfig } from "../config.js";
import { getMcpSdkVersion, getSanctuaryVersion } from "../version.js";

export type RuntimeStatus =
  | "active"
  | "inactive"
  | "degraded"
  | "not_configured"
  | "unknown";

/**
 * State of the consumer-side signed-evidence channel.
 *
 * OWNER RULING (2026-09-02): a confirmed audit ACK is MANDATORY before
 * Sanctuary reports drain health, arms full activation, or makes a
 * complete-enforcement claim. A pre-v2 daemon may keep operating, but operating
 * is not the same as being healthy, and the difference must be explicit rather
 * than silent.
 *
 * - `confirmed`       the daemon negotiated `audit_drain_ack_response` AND the
 *                     drain loop is live, so every reclaimed WAL range was
 *                     positively acknowledged. The ONLY state that may support a
 *                     complete-enforcement claim.
 * - `unconfirmed_ack` the peer does not confirm ACKs (pre-v2). Evidence still
 *                     flows and the daemon still truncates, so operation
 *                     continues, but the consumer cannot distinguish a REFUSED
 *                     truncation from an applied one: reclamation is unproven.
 * - `faulted`         the drain link itself is not delivering signed evidence.
 *
 * ABSENT means "this runtime has no consumer-side drain channel to report on"
 * (the macOS path), NOT "the channel is fine". Only a detector that actually has
 * a drain channel populates it.
 */
export type CastleWallEvidenceChannel =
  | "confirmed"
  | "unconfirmed_ack"
  /**
   * The daemon answered a drain or ACK with a RETRYABLE condition (busy, or
   * stopping) and the loop is backing off. Evidence flow is STALLED but the link
   * is not proven broken and nothing has been torn down. Distinct from
   * `faulted`: folding the two together is what let an ordinary `systemctl stop`
   * write permanent not-armed evidence about a healthy wall. Still degrades the
   * verdict, because a stalled channel is not a working one.
   */
  | "drain_retrying"
  | "faulted"
  /**
   * The daemon was observed directly, but the CONSUMER-side drain loop is not
   * observable from this process.
   *
   * This is the honest reading for the MCP server process: the drain loop runs
   * in whichever process called the activation gate (the `wrap` / `castle-wall
   * daemon` CLI), so a health report built here can prove what the daemon says
   * about itself and cannot prove that signed evidence is reaching a consumer.
   * It is NOT `confirmed` (nothing proved the channel) and NOT `faulted`
   * (nothing proved it broken). Absence of a fault is not evidence of health.
   */
  | "unobserved";

export interface CastleWallRuntimeSnapshot {
  platform?: string;
  configured?: boolean | "unknown";
  daemonUp?: boolean | "unknown";
  nftablesApplied?: boolean | "unknown";
  cgroupAttached?: boolean | "unknown";
  /**
   * The daemon's last `status_response`. The lifecycle/runtime members are
   * OPTIONAL on `StatusResponse` because a pre-v2 daemon does not send them;
   * `evaluateCastleWall` routes their absence to `unknown` through
   * `castleWallRuntimeReadiness`, never to `degraded`.
   */
  statusResponse?: Pick<
    StatusResponse,
    | "uptime_seconds"
    | "loaded_rule_count"
    | "no_wall_engaged"
    | "loaded_manifest_signature_b64url"
    | "manifest_state"
    | "lifecycle_state"
    | "runtime_state"
    | "kernel_runtime_ready"
    | "enforcing"
    | "runtime_health"
  >;
  /**
   * State of the signed-evidence channel behind this runtime. Anything other
   * than `confirmed` DEGRADES the verdict, whatever the daemon says about its
   * own kernel runtime: a wall whose evidence cannot be proven reclaimed is not
   * a wall Sanctuary may report as active (owner ruling, 2026-09-02).
   */
  evidenceChannel?: CastleWallEvidenceChannel;
  lastEventAt?: string | null;
  detectorName?: string;
  reason?: string;
}

export interface CastleWallEvidence {
  platform: string;
  status: RuntimeStatus;
  last_event_at: string | null;
  detector_evidence: string;
}

export interface LayerEvidence {
  status: RuntimeStatus;
  evidence: string;
  [key: string]: unknown;
}

export interface HealthEvidenceReport {
  sanctuary_version: string;
  mcp_sdk_version: string;
  castle_wall: CastleWallEvidence;
  audit: {
    writes_persistent: boolean;
    chain_verified: boolean | "unknown";
  };
  state: {
    default_verify_on_read: boolean;
  };
  egress: {
    enforcement: RuntimeStatus;
    evidence: string;
  };
  layers: {
    l1: LayerEvidence;
    l2: LayerEvidence;
    l3: LayerEvidence;
    l4: LayerEvidence;
  };
  degradations: Array<{
    layer: string;
    description: string;
    severity: string;
    mitigation: string;
  }>;
}

export interface BuildHealthEvidenceInput {
  config: SanctuaryConfig;
  identityCount: number;
  storageBackendName: string;
  castleWall?: CastleWallRuntimeSnapshot;
}

export function buildHealthEvidenceReport(input: BuildHealthEvidenceInput): HealthEvidenceReport {
  const castleWall = evaluateCastleWall(input.castleWall);
  const cognitiveStatus = cognitiveStatusFromCastleWall(castleWall.status);
  const operationalStatus: RuntimeStatus =
    input.config.execution.environment === "tee" ? "active" : "degraded";
  const auditWritesPersistent = input.storageBackendName === "FilesystemStorage";
  const degradations = buildDegradations(castleWall, cognitiveStatus, operationalStatus);

  return {
    sanctuary_version: getSanctuaryVersion(),
    mcp_sdk_version: getMcpSdkVersion(),
    castle_wall: castleWall,
    audit: {
      writes_persistent: auditWritesPersistent,
      chain_verified: "unknown",
    },
    state: {
      default_verify_on_read: true,
    },
    egress: {
      enforcement: castleWall.status,
      evidence: castleWall.detector_evidence,
    },
    layers: {
      l1: {
        status: cognitiveStatus,
        evidence:
          `state encryption ${input.config.state.encryption}; ` +
          `state integrity ${input.config.state.integrity}; ` +
          `identity keys ${input.identityCount}; ` +
          `Castle Wall ${castleWall.status}`,
        encryption_algorithm: input.config.state.encryption,
        key_count: input.identityCount,
        state_integrity: input.config.state.integrity,
      },
      l2: {
        status: operationalStatus,
        evidence:
          input.config.execution.environment === "tee"
            ? "TEE execution environment configured"
            : `${input.config.execution.environment} isolation; no TEE runtime evidence`,
        isolation_type: input.config.execution.environment,
        attestation_available: input.config.execution.attestation,
      },
      l3: {
        // Honesty (audit seam #4): a configured proof system is presence, not
        // enforcement evidence. No detector observes a proof being emitted or
        // verified in this server process, so report "unknown" (configured,
        // unverified) rather than "active". "active" is reserved for an
        // observed disclosure operation, matching the Castle Wall discipline.
        status: l3StatusFromConfig(input.config.disclosure.proof_system),
        evidence:
          input.config.disclosure.proof_system === "commitment-only"
            ? "commitment-only disclosure configured (no zero-knowledge proof system); no proof emitted in this window"
            : `${input.config.disclosure.proof_system} disclosure proof system configured; no proof emitted in this window`,
        proof_system: input.config.disclosure.proof_system,
        proof_emitted_in_window: false,
      },
      l4: {
        // Honesty (audit seam #4 / #11): reputation telemetry is unavailable,
        // so reserve "active" for an observed reputation operation. Report
        // "unknown" (configured, unverified) while nothing has exercised the
        // layer. This is the self-claim ASSURANCE_MATRIX row 16 said was
        // removed, now actually removed from the evidence report.
        status: "unknown",
        evidence: `${input.config.reputation.mode} reputation mode configured; interaction telemetry unavailable (configured, unverified)`,
        mode: input.config.reputation.mode,
        interaction_count: "unknown",
        reputation_exportable: true,
      },
    },
    degradations,
  };
}

export function evaluateCastleWall(snapshot?: CastleWallRuntimeSnapshot): CastleWallEvidence {
  const platform = snapshot?.platform ?? process.platform;
  if (!snapshot) {
    return {
      platform,
      status: "unknown",
      last_event_at: null,
      detector_evidence:
        "No Castle Wall runtime detector applies on this platform (the Linux " +
        "producer-signed detector is Linux-only; macOS uses the channel basis)",
    };
  }

  if (snapshot.configured === false) {
    return {
      platform,
      status: "not_configured",
      last_event_at: snapshot.lastEventAt ?? null,
      detector_evidence: snapshot.reason ?? "Castle Wall is not configured for this runtime",
    };
  }

  if (snapshot.daemonUp === false) {
    return {
      platform,
      status: "inactive",
      last_event_at: snapshot.lastEventAt ?? null,
      detector_evidence: snapshot.reason ?? "Castle Wall daemon is not running",
    };
  }

  const daemonUp = snapshot.daemonUp === true || snapshot.statusResponse !== undefined;
  if (!daemonUp) {
    return {
      platform,
      status: "unknown",
      last_event_at: snapshot.lastEventAt ?? null,
      detector_evidence: snapshot.reason ?? "Castle Wall daemon status is unavailable",
    };
  }

  const evidence = castleWallEvidenceString(snapshot);
  // The operator's EMERGENCY BYPASS keeps top precedence. It is also `degraded`,
  // so the verdict is identical either way, but it is the more urgent fact for
  // whoever reads the evidence string: "someone turned the wall off" outranks
  // "the peer does not confirm ACKs".
  if (snapshot.statusResponse?.no_wall_engaged === true) {
    return castleWallResult(platform, "degraded", snapshot, `${evidence}; no wall engaged`);
  }
  // EVIDENCE-CHANNEL GATE, checked BEFORE the runtime readiness switch.
  //
  // Owner ruling: absence of negotiated ACK confirmation is an explicit
  // degraded/incomplete state, never a silent pass. It outranks the runtime
  // block because it is a POSITIVE fact we observed (the peer did not advertise
  // the capability / the link faulted), not an indeterminate one: reporting
  // `unknown` here would understate something we actually know.
  if (snapshot.evidenceChannel === "unconfirmed_ack") {
    return castleWallResult(
      platform,
      "degraded",
      snapshot,
      `${evidence}; signed audit evidence is reclaimed WITHOUT confirmed ACKs ` +
        `(peer does not negotiate audit_drain_ack_response), so truncation is unproven`
    );
  }
  if (snapshot.evidenceChannel === "faulted") {
    return castleWallResult(
      platform,
      "degraded",
      snapshot,
      `${evidence}; signed enforcement evidence is not reaching the consumer ` +
        `(drain link unhealthy)`
    );
  }
  // Checked AFTER `faulted` and `unconfirmed_ack`, both of which are stronger
  // statements. A stalled channel degrades the verdict like the others, but the
  // reason must say the link is not proven broken, or an operator reads a
  // transient backoff as a dead wall and acts on it.
  if (snapshot.evidenceChannel === "drain_retrying") {
    return castleWallResult(
      platform,
      "degraded",
      snapshot,
      `${evidence}; signed enforcement evidence flow is STALLED - the daemon ` +
        `reported a retryable condition and the drain loop is backing off. The ` +
        `link is not proven broken and nothing was torn down; a clean cycle ` +
        `restores health, and a persistent refusal escalates to a fault`
    );
  }
  // Checked BEFORE the runtime block, and it is a CEILING rather than a verdict:
  // whatever the daemon says about its own kernel runtime, a report that cannot
  // observe the evidence channel cannot conclude `active`. The runtime block
  // below still runs, so a PROVEN-degraded daemon is still reported as degraded;
  // it is only the positive claim that is withheld.
  const evidenceChannelUnobserved = snapshot.evidenceChannel === "unobserved";
  if (snapshot.statusResponse !== undefined) {
    const readiness = castleWallRuntimeReadiness(snapshot.statusResponse);
    const reported =
      `daemon reports lifecycle=${snapshot.statusResponse.lifecycle_state ?? "unreported"} ` +
      `runtime=${snapshot.statusResponse.runtime_state ?? "unreported"} ` +
      `health=${snapshot.statusResponse.runtime_health ?? "unreported"}`;
    switch (readiness) {
      case "unavailable":
        // INDETERMINATE, not degraded. The daemon either predates the runtime
        // status block or its health probe had no current answer; inventing a
        // failure verdict from that is the flap this replaces, and asserting
        // health from it would be the far worse direction.
        return castleWallResult(
          platform,
          "unknown",
          snapshot,
          `${evidence}; ${reported} (runtime state not currently proven)`
        );
      case "degraded":
      case "control_plane_only":
        // `control_plane_only` is honest non-enforcement (macOS, unprivileged
        // host): the daemon is up but no kernel runtime is behind it, so the
        // Castle Wall is not active.
        return castleWallResult(platform, "degraded", snapshot, `${evidence}; ${reported}`);
      case "kernel_runtime_ready":
      case "enforcing":
        // Fall through to the remaining detector checks below. NOTE the honesty
        // bound: `kernel_runtime_ready` means the kernel runtime is live with NO
        // agent wrapped, which is this slice's ceiling. Requiring `enforcing`
        // here would demand a claim the daemon documents as never produced, so
        // every healthy host would read degraded forever.
        break;
    }
  }
  if (evidenceChannelUnobserved) {
    return castleWallResult(
      platform,
      "unknown",
      snapshot,
      `${evidence}; the daemon answered, but the signed-evidence drain loop runs ` +
        `in the process that armed the wall and is NOT observable from here, so ` +
        `this report proves the daemon's own runtime state only. Absence of a ` +
        `fault is not evidence that evidence is flowing`
    );
  }
  if (snapshot.nftablesApplied === false) {
    return castleWallResult(platform, "degraded", snapshot, `${evidence}; nftables rules not applied`);
  }
  if (snapshot.cgroupAttached === false) {
    return castleWallResult(platform, "degraded", snapshot, `${evidence}; cgroup not attached`);
  }
  if (snapshot.nftablesApplied !== true || snapshot.cgroupAttached !== true) {
    return castleWallResult(platform, "degraded", snapshot, `${evidence}; enforcement detail incomplete`);
  }

  return castleWallResult(platform, "active", snapshot, evidence);
}

function castleWallResult(
  platform: string,
  status: RuntimeStatus,
  snapshot: CastleWallRuntimeSnapshot,
  detector_evidence: string
): CastleWallEvidence {
  return {
    platform,
    status,
    last_event_at: snapshot.lastEventAt ?? null,
    detector_evidence,
  };
}

function castleWallEvidenceString(snapshot: CastleWallRuntimeSnapshot): string {
  const parts = [
    `${snapshot.detectorName ?? "Castle Wall runtime"} reports daemon up`,
  ];
  if (snapshot.statusResponse) {
    parts.push(`uptime ${snapshot.statusResponse.uptime_seconds}s`);
    if (manifestFieldsAreAuthoritative(snapshot.statusResponse.manifest_state)) {
      parts.push(`loaded rules ${snapshot.statusResponse.loaded_rule_count}`);
      parts.push(
        snapshot.statusResponse.loaded_manifest_signature_b64url
          ? "manifest signature loaded"
          : "manifest signature unavailable"
      );
    } else {
      parts.push("manifest fields unavailable (store state not authoritative)");
    }
  }
  if (snapshot.nftablesApplied !== undefined) {
    parts.push(`nftables ${snapshot.nftablesApplied}`);
  }
  if (snapshot.cgroupAttached !== undefined) {
    parts.push(`cgroup ${snapshot.cgroupAttached}`);
  }
  return parts.join("; ");
}

function cognitiveStatusFromCastleWall(status: RuntimeStatus): RuntimeStatus {
  if (status === "active") return "active";
  if (status === "unknown") return "unknown";
  return "degraded";
}

/**
 * Honesty (audit seam #4): derive the L3 disclosure status from config
 * presence without claiming enforcement. A "commitment-only" proof_system has
 * no zero-knowledge proof system configured at all (not_configured); any other
 * configured proof system is present but unverified by this process (unknown).
 * Neither is "active"; that label is reserved for an observed disclosure
 * operation, which no detector reports here.
 */
function l3StatusFromConfig(
  proofSystem: SanctuaryConfig["disclosure"]["proof_system"]
): RuntimeStatus {
  return proofSystem === "commitment-only" ? "not_configured" : "unknown";
}

function buildDegradations(
  castleWall: CastleWallEvidence,
  cognitiveStatus: RuntimeStatus,
  operationalStatus: RuntimeStatus
): HealthEvidenceReport["degradations"] {
  const degradations: HealthEvidenceReport["degradations"] = [];
  if (cognitiveStatus !== "active") {
    degradations.push({
      layer: "l1",
      description: `Castle Wall status is ${castleWall.status}`,
      severity: castleWall.status === "unknown" ? "warning" : "critical",
      mitigation: "Wire the Castle Wall runtime detector or enable Castle Wall enforcement",
    });
  }
  if (operationalStatus === "degraded") {
    degradations.push({
      layer: "l2",
      description: "Process-level isolation only (no TEE)",
      severity: "warning",
      mitigation: "TEE support planned for a future release",
    });
  }
  return degradations;
}
