/**
 * Sanctuary Agent Contract v0.1 — Errors.
 *
 * Typed errors for every Agent Contract enforcement boundary. Each error
 * subclass maps to a specific Contract §N enforcement point so callers can
 * fail closed deterministically.
 */

export class AgentContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AgentContractError";
  }
}

/** §3 Agent Card schema validation failed. */
export class AgentCardSchemaError extends AgentContractError {
  constructor(message: string) {
    super(message);
    this.name = "AgentCardSchemaError";
  }
}

/** §3 Agent Card signature verification failed — tampered card or wrong key. */
export class AgentCardVerificationError extends AgentContractError {
  constructor(message: string) {
    super(message);
    this.name = "AgentCardVerificationError";
  }
}

/** §6 Usage event schema validation failed. */
export class UsageEventSchemaError extends AgentContractError {
  constructor(message: string) {
    super(message);
    this.name = "UsageEventSchemaError";
  }
}

/**
 * §2.4 Capability runtime enforcement — agent attempted an action whose kind
 * is not declared on its Agent Card. Fail-closed at the broker.
 */
export class CapabilityUndeclaredError extends AgentContractError {
  constructor(
    public readonly agent_id: string,
    public readonly attempted_kind: string,
    public readonly attempted_target: string
  ) {
    super(
      `agent ${agent_id} attempted ${attempted_kind} on ${attempted_target} but no matching capability is declared on its Agent Card — fail closed per §2.4`
    );
    this.name = "CapabilityUndeclaredError";
  }
}

/** §7.1 Commitment boundary refused — caller MUST NOT emit the commitment. */
export class CommitmentBoundaryRefusedError extends AgentContractError {
  constructor(
    public readonly agent_id: string,
    public readonly reason_code: string,
    public readonly explanation: string
  ) {
    super(
      `commitment boundary refused for ${agent_id}: ${reason_code} — ${explanation}`
    );
    this.name = "CommitmentBoundaryRefusedError";
  }
}

/** §2.8 Lifecycle transition requested from an invalid starting state. */
export class LifecycleTransitionError extends AgentContractError {
  constructor(
    public readonly agent_id: string,
    public readonly from_state: string,
    public readonly to_state: string
  ) {
    super(
      `agent ${agent_id} cannot transition ${from_state} → ${to_state} per §2.8`
    );
    this.name = "LifecycleTransitionError";
  }
}

/** §2.9 Attestation failure — degrade-not-destroy policy applies at call sites. */
export class AttestationUnavailableError extends AgentContractError {
  constructor(
    public readonly agent_id: string,
    public readonly reason: string
  ) {
    super(
      `attestation unavailable for ${agent_id}: ${reason} — callers apply degrade-not-destroy per §2.9`
    );
    this.name = "AttestationUnavailableError";
  }
}

/**
 * §2.2 Per-agent identity binding invariant violated. E.g. root private key
 * was about to be exposed to harness address space, or per-agent key was
 * requested for an agent that has not been bound.
 */
export class IdentityBindingError extends AgentContractError {
  constructor(message: string) {
    super(message);
    this.name = "IdentityBindingError";
  }
}

/**
 * §5 Tier B adapter invariant violated — e.g. adapter attempted to promote a
 * harness sub-agent to a first-class Sanctuary identity, or root key leaked
 * into harness env.
 */
export class TierBInvariantError extends AgentContractError {
  constructor(message: string) {
    super(message);
    this.name = "TierBInvariantError";
  }
}
