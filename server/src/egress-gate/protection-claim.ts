import {
  exclusiveEgressCapsAggregateGreen,
  type ExclusiveEgressStatus,
} from "./posture.js";
import { GENERIC_UID_CONFINEMENT_REMEDY } from "./operator-advice.js";

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
        /**
         * F-ARMSUMMARY. The generic unknown bases above render as "Castle Wall
         * status unknown (not confirmed armed)". After a run whose OWN arm step
         * reported success, that sentence reads as a flat contradiction of the
         * success line printed moments earlier -- the 2026-07-26 Mini1 drill
         * captured all three claims in one successful run (`L1-arm-exclusive.log`
         * lines 16, 65 and 75) while independent measurement said armed.
         *
         * This basis carries the SAME verdict (unknown, never green) with the
         * qualifier that resolves the contradiction. It claims nothing new: "this
         * run's arm step reported success" is a statement about control flow and
         * is worded as one, and enforcement is still reported as unobserved.
         */
        | "armed_this_run_enforcement_unobserved"
        | "provision_outcome_not_observation"
        | "daemon_liveness_missing"
        | "exclusive_egress_repark_failed"
        | "subject_unbound_evidence"
        | "legacy_macos_audit_token"
        | "pre_canonical_linux_agent_name"
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
  if (input.castleWallEgressBasis === "pre_canonical_linux_agent_name") {
    return {
      state: "unknown",
      basis: "pre_canonical_linux_agent_name",
      reasons: [
        "Castle Wall has recent Linux evidence from a pre-canonical daemon; upgrade the daemon path so evidence is bound to this confined agent subject",
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

/**
 * The generic unknown bases: the ones whose advice is the bare "Castle Wall
 * status unknown (not confirmed armed)". Every OTHER unknown basis already
 * names what specifically could not be established and must be left alone.
 */
const GENERIC_UNKNOWN_BASES: ReadonlySet<string> = new Set([
  "provider_unavailable",
  "read_failed",
  "insufficient_evidence",
]);

/**
 * F-ARMSUMMARY, half one. THE one place the wrap banner reconciles what the
 * run DID with what the run OBSERVED.
 *
 * A wrap whose arm step succeeded and whose enforcement evidence has not
 * arrived yet used to close on "Castle Wall status unknown (not confirmed
 * armed)" -- true about the evidence, and unreadable next to the success line
 * the same run printed. The verdict is unchanged (unknown, never green, same
 * imperative); only the sentence acquires the qualifier that makes the two
 * lines consistent.
 *
 * `armStepReportedSuccess` is exactly what its name says: the run's own
 * provisioning outcome, which this codebase deliberately does NOT treat as an
 * observation of enforcement (see the `provision_outcome_not_observation`
 * basis). It is therefore only ever allowed to change WORDING, never state,
 * never green, and never to upgrade a specific unknown basis into a vaguer one.
 */
export function reconcileProtectionClaimWithArmOutcome(
  claim: ProtectionStateClaim,
  armStepReportedSuccess: boolean,
): ProtectionStateClaim {
  if (!armStepReportedSuccess) return claim;
  if (claim.state !== "unknown") return claim;
  if (!GENERIC_UNKNOWN_BASES.has(claim.basis)) return claim;
  return protectionStateClaimFromObservation({
    state: "unknown",
    basis: "armed_this_run_enforcement_unobserved",
    reasons: claim.reasons,
  });
}

/**
 * F-ARMSUMMARY, half two. The operator-facing copy for a Castle Wall daemon
 * that this run FAILED TO START.
 *
 * The old copy opened "WARNING: Castle Wall is NOT armed ... outbound traffic
 * is NOT filtered" for every start failure, derived from the exception alone.
 * Nothing at that point in the flow observes the host. In the 2026-07-26 Mini1
 * drill the reason printed directly underneath the words "Castle Wall is NOT
 * armed" was "A Castle Wall SAFE-MODE boot daemon (PID 1432) is currently
 * enforcing this fortress" -- the message contradicted itself in two adjacent
 * lines, and measurement (`Content filter: enabled`, lease `armed`, the
 * confined uid measurably confined) agreed with the reason, not the headline.
 *
 * So the headline is now a function of the failure, and the one thing this
 * code genuinely knows is stated first: THIS RUN did not start a daemon. It
 * makes no claim about whether the host is filtering, because it did not look.
 * Same shape as the observed-confinement sentence on the provisioning surface.
 *
 * Returns the headline lines; the caller adds the reason and any migration
 * guidance. Exported so the failure -> sentence mapping is asserted directly.
 */
export function castleWallDaemonStartFailureHeadline(
  failureMessage: string,
): readonly string[] {
  if (CASTLE_WALL_ALREADY_HELD_RE.test(failureMessage)) {
    return [
      "  NOTE: this run did not start a Castle Wall daemon, because another one",
      "  already holds this fortress. Enforcement is whatever THAT daemon is doing;",
      "  this run neither armed nor disarmed anything.",
    ];
  }
  return [
    "  WARNING: this run did not start the Castle Wall enforcement daemon, so it",
    "  did not arm anything. Whether this host is filtering outbound traffic right",
    "  now was NOT checked here; confirm it before relying on this wrap.",
  ];
}

/**
 * Failure messages that mean "a Castle Wall daemon is already holding this
 * fortress" -- i.e. the start failed BECAUSE something is already enforcing.
 * Saying "NOT armed" over one of these is not an under-claim, it is wrong.
 */
const CASTLE_WALL_ALREADY_HELD_RE =
  /\b(already (running|enforcing|armed|holds|holding))\b|\bis currently enforcing\b|\bboot daemon\b.*\benforcing\b/i;

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
          imperative: GENERIC_UID_CONFINEMENT_REMEDY,
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
      if (claim.basis === "pre_canonical_linux_agent_name") {
        return {
          green: false,
          operatorSentence:
            "Your agent is wrapped, but its Castle Wall evidence was produced by a pre-canonical Linux daemon.",
          castleWallLabel:
            "Castle Wall status unknown (pre-canonical Linux evidence)",
          imperative: inspectImperative,
        };
      }
      if (claim.basis === "armed_this_run_enforcement_unobserved") {
        return {
          green: false,
          operatorSentence:
            "Your agent is wrapped. This run's arm step reported success, but enforcement " +
            "has not been observed yet, so protection is not confirmed.",
          castleWallLabel:
            "Castle Wall status unknown (this run's arm step reported success; enforcement not yet observed)",
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
          imperative: GENERIC_UID_CONFINEMENT_REMEDY,
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
