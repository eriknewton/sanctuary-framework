import type { ExclusiveEgressStatus } from "./posture.js";

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

export type ProtectionStateObservation =
  | {
      state: "exclusive";
      basis: "exclusive_egress_observed";
      reasons?: readonly string[];
    }
  | {
      state: "coarse-only";
      basis:
        | "coarse_wall_observed"
        | "exclusive_egress_cap_observed";
      reasons?: readonly string[];
    }
  | {
      state: "unprotected";
      basis: "not_enforcing_observed";
      reasons?: readonly string[];
    }
  | {
      state: "unknown";
      basis:
        | "provider_unavailable"
        | "read_failed"
        | "insufficient_evidence";
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
      state: "coarse-only",
      basis: "coarse_wall_observed",
      reasons: exclusive?.reasons ?? [],
    };
  }
  if (input.castleWallEgressStatus === "fault") {
    return {
      state: "unprotected",
      basis: "not_enforcing_observed",
      reasons: ["Castle Wall reported not-enforcing evidence"],
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
  switch (claim.state) {
    case "exclusive":
      return {
        green: true,
        operatorSentence: "Your agent is protected.",
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
        imperative: null,
      };
    case "unprotected":
      return {
        green: false,
        operatorSentence:
          "Your agent is wrapped, but enforcement is not confirmed.",
        castleWallLabel: "Castle Wall NOT ARMED (traffic not filtered)",
        imperative: null,
      };
    case "unknown":
      return {
        green: false,
        operatorSentence:
          "Your agent is wrapped, but enforcement is not confirmed.",
        castleWallLabel: "Castle Wall status unknown (not confirmed armed)",
        imperative: null,
      };
  }
}
