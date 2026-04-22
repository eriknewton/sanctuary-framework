/**
 * Recovery Flows — ceremony-specific errors.
 *
 * Each error is operator-visible. Public-facing surfaces that render these
 * errors MUST NOT introduce em-dashes (naming-discipline rule for public copy)
 * or name competitors; this module emits the machine-readable shape only. UI
 * copy lives in WP-MVP-2.
 */

export class CeremonyError extends Error {
  readonly name: string = "CeremonyError";
  constructor(message: string) {
    super(message);
  }
}

export class CeremonyNotConfirmedError extends CeremonyError {
  readonly name = "CeremonyNotConfirmedError";
  constructor(ceremony: string) {
    super(
      `ceremony "${ceremony}" has no operator confirmation; Key 8 invariant requires an explicit operator confirm() call before any state changes are applied`
    );
  }
}

export class DMswitchGraceWindowActive extends CeremonyError {
  readonly name = "DMswitchGraceWindowActive";
  /**
   * ISO8601 timestamp after which the device-loss ceremony will proceed.
   * Operator UI surfaces this as "recovery available on <date>".
   */
  readonly available_at: string;
  readonly remaining_ms: number;
  constructor(params: { available_at: string; remaining_ms: number }) {
    super(
      `device-loss recovery is gated by the DMswitch grace window; available_at=${params.available_at} remaining_ms=${params.remaining_ms}`
    );
    this.available_at = params.available_at;
    this.remaining_ms = params.remaining_ms;
  }
}

export class BroadcastAckTimeoutError extends CeremonyError {
  readonly name = "BroadcastAckTimeoutError";
  readonly dissenting_nodes: string[];
  readonly received_acks: string[];
  constructor(params: {
    dissenting_nodes: string[];
    received_acks: string[];
    ceremony: string;
  }) {
    super(
      `${params.ceremony} broadcast ack timeout; dissenting_nodes=${JSON.stringify(params.dissenting_nodes)} received_acks=${JSON.stringify(params.received_acks)}`
    );
    this.dissenting_nodes = params.dissenting_nodes;
    this.received_acks = params.received_acks;
  }
}

export class SecretBundleError extends CeremonyError {
  readonly name = "SecretBundleError";
  constructor(message: string) {
    super(message);
  }
}
