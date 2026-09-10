import type { StatusResponse } from "../castle-wall/ipc/messages.js";
import type { CastleWallProvisionState } from "../castle-wall/provision-state.js";
import type { SanctuaryConfig } from "../config.js";
import { getMcpSdkVersion, getSanctuaryVersion } from "../version.js";

export type RuntimeStatus =
  | "active"
  | "inactive"
  | "degraded"
  | "not_configured"
  | "unknown";

export interface CastleWallRuntimeSnapshot {
  platform?: string;
  configured?: boolean | "unknown";
  daemonUp?: boolean | "unknown";
  nftablesApplied?: boolean | "unknown";
  cgroupAttached?: boolean | "unknown";
  statusResponse?: Pick<
    StatusResponse,
    "uptime_seconds" | "loaded_rule_count" | "no_wall_engaged" | "loaded_manifest_signature_b64url"
  >;
  lastEventAt?: string | null;
  detectorName?: string;
  reason?: string;
  /**
   * THIS VAULT's own Castle Wall provisioning state (castle-wall/
   * provision-state.ts), when the fortress carries the claim `init` persists.
   * Deliberately separate from every other member here: the rest describe a
   * RUNTIME (a daemon, a kernel ruleset, an evidence channel), and none of them
   * is a claim that the vault being reported on is on the wall that is running.
   * Absent = the fortress carries no claim, which is not a claim of protection
   * either.
   */
  vaultProvision?: CastleWallProvisionState;
  /**
   * `false` when NO runtime detector applies on this platform, so this object
   * exists only to carry {@link vaultProvision}.
   *
   * WHY IT EXISTS: on macOS the Linux producer-signed detector returns
   * `undefined`, and `undefined` cannot carry a field. Before this flag the
   * vault's own wall claim was silently dropped on macOS — the platform the
   * claim is about — so `monitor_health`, `exec_attest` and the signed SHR
   * payload all omitted it there. `evaluateCastleWall` maps this flag to
   * BYTE-IDENTICAL evidence to the `undefined` case, so the runtime verdict on
   * that platform is unchanged and only the additive field is new.
   */
  runtimeDetectorApplies?: false;
}

export interface CastleWallEvidence {
  platform: string;
  status: RuntimeStatus;
  last_event_at: string | null;
  detector_evidence: string;
  /**
   * ADDITIVE: the vault-level wall claim, carried verbatim from the snapshot.
   * Present only when the fortress carries the claim, so every report about a
   * fortress that predates the state is byte-identical to before. This is the
   * ONE shape `monitor_health`, `exec_attest`, and the signed SHR publish
   * payload all read, so the three cannot disagree about the same vault.
   */
  vault_provision?: CastleWallProvisionState;
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

/**
 * Evaluate the Castle Wall runtime AND carry this vault's own wall claim.
 *
 * The claim is attached HERE rather than at each of the many verdict returns
 * below: a hand-mirrored copy at every branch is the drift shape AGENTS rule 5
 * names, and a branch that silently lost the field would look exactly like a
 * fortress that never carried one.
 */
export function evaluateCastleWall(snapshot?: CastleWallRuntimeSnapshot): CastleWallEvidence {
  const evidence = evaluateCastleWallRuntime(snapshot);
  return snapshot?.vaultProvision === undefined
    ? evidence
    : { ...evidence, vault_provision: snapshot.vaultProvision };
}

function evaluateCastleWallRuntime(snapshot?: CastleWallRuntimeSnapshot): CastleWallEvidence {
  const platform = snapshot?.platform ?? process.platform;
  // Must stay one branch with the `!snapshot` case: a carrier object exists
  // only to hold the vault claim and asserts nothing about a runtime, so its
  // runtime verdict has to be the same "no detector applies" answer, byte for
  // byte, that the absent snapshot produces.
  if (!snapshot || snapshot.runtimeDetectorApplies === false) {
    return {
      platform,
      status: "unknown",
      last_event_at: null,
      detector_evidence:
        "No Castle Wall runtime detector is wired into this server process",
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
  if (snapshot.statusResponse?.no_wall_engaged === true) {
    return castleWallResult(platform, "degraded", snapshot, `${evidence}; no wall engaged`);
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
    parts.push(`loaded rules ${snapshot.statusResponse.loaded_rule_count}`);
    parts.push(
      snapshot.statusResponse.loaded_manifest_signature_b64url
        ? "manifest signature loaded"
        : "manifest signature unavailable"
    );
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
