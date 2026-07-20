import {
  exclusiveEgressCapsAggregateGreen,
  type ExclusiveEgressStatus,
} from "./posture.js";

/**
 * Protection-copy chokepoint for the wrap success banner and legacy dashboard
 * hero. The posture-home page is a separate posture dashboard renderer whose
 * copy is derived from stable posture/feature-health basis enums.
 */
const protectionStateClaimBrand: unique symbol = Symbol("ProtectionStateClaim");

export type ProtectionClaimState =
  | "exclusive"
  | "coarse-only"
  | "unprotected"
  | "unknown";

export type ProtectionFeatureStatus =
  | "active"
  | "fault"
  | "unconfirmed"
  | "unknown"
  | "coarse_only";

export type ProtectionFeatureBasis =
  | "fresh_enforcement_evidence"
  | "fault_evidence"
  | "dead_no_heartbeat"
  | "intentionally_stopped"
  | "daemon_liveness_unconfirmed"
  | string;

export type ProtectionStateObservation =
  | {
      state: "exclusive";
      basis:
        | "castle_wall_enforcement_observed"
        | "exclusive_egress_observed";
      reasons?: readonly string[];
    }
  | {
      state: "coarse-only";
      basis:
        | "exclusive_egress_cap_observed"
        | "exclusive_egress_unarmed_coarse_active";
      reasons?: readonly string[];
    }
  | {
      state: "unprotected";
      basis:
        | "not_enforcing_observed"
        | "disarm_observed_off";
      reasons?: readonly string[];
    }
  | {
      state: "unknown";
      basis:
        | "provider_unavailable"
        | "read_failed"
        | "insufficient_evidence"
        | "provision_outcome_not_observation"
        | "daemon_liveness_missing"
        | "exclusive_egress_repark_failed"
        | "subject_unbound_evidence"
        | "legacy_macos_audit_token"
        | "subject_unresolvable";
      reasons: readonly string[];
    };

export type ProtectionStateClaim = Readonly<{
  [protectionStateClaimBrand]: true;
  state: ProtectionClaimState;
  basis: ProtectionStateObservation["basis"];
  reasons: readonly string[];
}>;

export interface ProtectionStateAdvice {
  green: boolean;
  operatorSentence: string;
  castleWallLabel: string;
  imperative: string | null;
}

export const PROTECTION_HERO_COPY = Object.freeze({
  green: "Your agent is protected.",
  nonGreen: "Protection not confirmed.",
});

export function protectionHeroCopyForLight(light: string): string {
  return light === "green"
    ? PROTECTION_HERO_COPY.green
    : PROTECTION_HERO_COPY.nonGreen;
}

export function protectionStateClaimFromObservation(
  observation: ProtectionStateObservation,
): ProtectionStateClaim {
  return Object.freeze({
    [protectionStateClaimBrand]: true as const,
    state: observation.state,
    basis: observation.basis,
    reasons: Object.freeze([...(observation.reasons ?? [])]),
  });
}

export function protectionObservationFromFeatureHealth(input: {
  castleWallEgressStatus: ProtectionFeatureStatus | undefined;
  castleWallEgressBasis?: ProtectionFeatureBasis;
  exclusiveEgress: ExclusiveEgressStatus | null;
}): ProtectionStateObservation {
  const exclusive = input.exclusiveEgress;
  if (
    exclusive?.fine_grained_declared === true &&
    exclusive.mode === null
  ) {
    return {
      state: "unknown",
      basis: "read_failed",
      reasons: exclusive.reasons,
    };
  }
  if (input.castleWallEgressStatus === "coarse_only") {
    return {
      state: "coarse-only",
      basis: "exclusive_egress_cap_observed",
      reasons: exclusive?.reasons ?? [],
    };
  }
  if (input.castleWallEgressStatus === "active") {
    if (exclusiveEgressCapsAggregateGreen(exclusive)) {
      return {
        state: "coarse-only",
        basis: "exclusive_egress_cap_observed",
        reasons: exclusive?.reasons ?? [],
      };
    }
    if (
      exclusive?.fine_grained_declared === true &&
      exclusive.exclusive_egress_live === true &&
      exclusive.mode === "exclusive"
    ) {
      return {
        state: "exclusive",
        basis: "exclusive_egress_observed",
        reasons: exclusive.reasons,
      };
    }
    return {
      state: "exclusive",
      basis: "castle_wall_enforcement_observed",
      reasons: exclusive?.reasons ?? [],
    };
  }
  if (input.castleWallEgressStatus === "fault") {
    if (input.castleWallEgressBasis === "dead_no_heartbeat") {
      return {
        state: "unknown",
        basis: "daemon_liveness_missing",
        reasons: [
          "Castle Wall daemon heartbeat is missing; traffic may be fail-closed rather than unfiltered",
        ],
      };
    }
    return {
      state: "unprotected",
      basis: "not_enforcing_observed",
      reasons: ["Castle Wall reported not-enforcing evidence"],
    };
  }
  if (
    input.castleWallEgressBasis === "intentionally_stopped" ||
    input.castleWallEgressBasis === "daemon_liveness_unconfirmed"
  ) {
    return {
      state: "unknown",
      basis: "insufficient_evidence",
      reasons: ["Castle Wall enforcement could not be observed after newer liveness evidence"],
    };
  }
  if (input.castleWallEgressBasis === "subject_unbound_evidence") {
    return {
      state: "unknown",
      basis: "subject_unbound_evidence",
      reasons: ["Castle Wall has recent evidence, but not for this confined agent subject"],
    };
  }
  if (input.castleWallEgressBasis === "legacy_macos_audit_token") {
    return {
      state: "unknown",
      basis: "legacy_macos_audit_token",
      reasons: [
        "Castle Wall has recent evidence in the legacy macOS audit-token format; re-run protection to bind it to this confined agent subject",
      ],
    };
  }
  if (input.castleWallEgressBasis === "subject_unresolvable") {
    return {
      state: "unknown",
      basis: "subject_unresolvable",
      reasons: [
        "Castle Wall has recent evidence, but the agent's confinement identity could not be read",
      ],
    };
  }
  return {
    state: "unknown",
    basis: "insufficient_evidence",
    reasons: ["Castle Wall enforcement could not be observed"],
  };
}

export function protectionStateAdvice(
  claim: ProtectionStateClaim,
): ProtectionStateAdvice {
  const inspectImperative =
    "Run 'sanctuary castle-wall status' to inspect live enforcement before relying on this wrap.";
  const repairImperative =
    "Run 'sudo sanctuary protect --repair-egress-gate' to repair fine-grained exclusive egress.";
  switch (claim.state) {
    case "exclusive":
      return {
        green: true,
        operatorSentence: PROTECTION_HERO_COPY.green,
        castleWallLabel: "Castle Wall Full",
        imperative: null,
      };
    case "coarse-only":
      return {
        green: false,
        operatorSentence:
          "Your agent is wrapped, but only coarse Castle Wall enforcement is confirmed.",
        castleWallLabel:
          "Castle Wall coarse-only (fine-grained egress not live)",
        imperative: repairImperative,
      };
    case "unprotected":
      return {
        green: false,
        operatorSentence:
          "Your agent is wrapped, but enforcement is not confirmed.",
        castleWallLabel: "Castle Wall NOT ARMED (traffic not filtered)",
        imperative: inspectImperative,
      };
    case "unknown":
      if (claim.basis === "daemon_liveness_missing") {
        return {
          green: false,
          operatorSentence:
            "Your agent is wrapped, but enforcement state is not confirmed.",
          castleWallLabel:
            "Castle Wall status unknown (daemon heartbeat missing; traffic may be blocked)",
          imperative: inspectImperative,
        };
      }
      if (claim.basis === "exclusive_egress_repark_failed") {
        return {
          green: false,
          operatorSentence:
            "Your agent is wrapped, but exclusive-egress boot re-park is not confirmed.",
          castleWallLabel:
            "Castle Wall status unknown (exclusive-egress boot re-park failed)",
          imperative: repairImperative,
        };
      }
      if (claim.basis === "subject_unbound_evidence") {
        return {
          green: false,
          operatorSentence:
            "Your agent is wrapped, but enforcement is not confirmed for this confined agent.",
          castleWallLabel:
            "Castle Wall status unknown (no subject-bound enforcement evidence)",
          imperative: inspectImperative,
        };
      }
      if (claim.basis === "legacy_macos_audit_token") {
        return {
          green: false,
          operatorSentence:
            "Your agent is wrapped, but its Castle Wall evidence uses the older macOS identity format.",
          castleWallLabel:
            "Castle Wall status unknown (legacy audit-token evidence)",
          imperative: inspectImperative,
        };
      }
      if (claim.basis === "subject_unresolvable") {
        return {
          green: false,
          operatorSentence:
            "Your agent is wrapped, but its confinement identity could not be read.",
          castleWallLabel:
            "Castle Wall status unknown (agent confinement identity unreadable)",
          imperative: inspectImperative,
        };
      }
      return {
        green: false,
        operatorSentence:
          "Your agent is wrapped, but enforcement is not confirmed.",
        castleWallLabel: "Castle Wall status unknown (not confirmed armed)",
        imperative: inspectImperative,
      };
    default:
      return {
        green: false,
        operatorSentence:
          "Your agent is wrapped, but enforcement is not confirmed.",
        castleWallLabel: "Castle Wall status unknown (not confirmed armed)",
        imperative: inspectImperative,
      };
  }
}
