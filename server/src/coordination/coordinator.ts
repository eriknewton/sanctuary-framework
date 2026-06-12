/**
 * Sanctuary v1.1 Coordination — LocalCoordinator
 *
 * Local-only agent-to-agent handoff orchestration inside ONE operator
 * fortress. Sender signs a Layer 1 record; every lifecycle transition is a
 * Layer 2 audit payload signed by the actor. Cross-operator coordination is
 * v1.3 public federation; this module MUST NOT be used as a transport for
 * cross-fortress traffic.
 *
 * The coordinator wires four collaborators, all injected:
 *
 *   - HandoffStore         — encrypted record persistence
 *   - AuditLog             — appendable encrypted L2 audit chain
 *   - CoordinationKeyResolver — public-key lookup for verification
 *   - CoordinationPolicyGate (optional) — recipient-side context-transfer gate
 *
 * Status lifecycle (from the v1.1 contract):
 *
 *     created → accepted → completed
 *           ↘ denied
 *           ↘ failed
 *           accepted → denied / failed
 *
 * The bootstrap `created` audit entry uses `previous_status: "created"` as a
 * self-loop convention, since the contract enum has no pre-create sentinel.
 * Verifiers reconstruct the chain by checking
 * `chain[i].previous_status === chain[i-1].new_status` for i > 0.
 */

import type { AuditLog } from "../l2-operational/audit-log.js";
import { toBase64url } from "../core/encoding.js";
import { randomBytes } from "../core/random.js";
import {
  SIGNATURE_SCHEME_V1,
  type HandoffStatus,
} from "../contracts/v1.1/constants.js";
import type {
  LocalHandoffAuditPayload,
  LocalHandoffContextReference,
  LocalHandoffRecord,
  LocalHandoffTaskScope,
} from "../contracts/v1.1/handoff-records.js";
import { HandoffStore, type HandoffStoreFilter } from "./handoff-store.js";
import {
  signAuditPayload,
  signHandoffRecord,
  verifyHandoffRecord,
  type CoordinationKeyResolver,
  type CoordinationSigner,
} from "./signing.js";
import {
  HandoffActorError,
  HandoffNotFoundError,
  HandoffPolicyDenialError,
  HandoffSignatureError,
  HandoffStateError,
} from "./errors.js";

export type HandoffReasonClass = NonNullable<
  LocalHandoffRecord["status_reason_class"]
>;

/**
 * Coarse policy-gate decision for context transfer at handoff create time.
 * Mirrors the policy-engine slot-gate decision shape so production wiring is
 * a one-line adapter.
 */
export interface CoordinationGateDecision {
  decision: "allow" | "deny";
  reason_code: string;
}

/**
 * Recipient-side policy gate adapter. Coordination is decoupled from the
 * policy-engine so production can plug in `evaluateGate` from
 * `server/src/policy-engine/gates/` and tests can pass a deterministic
 * fixture.
 *
 * The gate evaluates whether the recipient may accept the requested context
 * transfer from the sender. A deny short-circuits handoff creation: no
 * `LocalHandoffRecord` is persisted; the audit chain receives a single
 * `denied` event whose `actor_role: "policy_gate"` is signed by the
 * operator.
 */
export interface CoordinationPolicyGate {
  evaluateContextTransfer(input: {
    sender_agent_id: string;
    recipient_agent_id: string;
    identity_id: string;
    requested_capabilities: string[];
  }): CoordinationGateDecision;
}

export interface ProposeHandoffInput {
  sender: CoordinationSigner;
  recipient_agent_id: string;
  identity_id: string;
  task_scope: LocalHandoffTaskScope;
  context_reference: LocalHandoffContextReference;
  /**
   * Operator signer. Required when a denial may originate from the policy
   * gate (the operator's identity binds the denial to the fortress owner).
   * Absent → policy-gate denial is unavailable for this proposal.
   */
  operator?: CoordinationSigner;
}

export interface AcceptHandoffInput {
  handoff_id: string;
  recipient: CoordinationSigner;
}

export interface DenyHandoffInput {
  handoff_id: string;
  /**
   * Actor causing the denial. Must be the recipient agent or the operator
   * (policy gate). Sender-side cancellation is `failHandoff`, not deny.
   */
  actor: CoordinationSigner;
  actor_role: "recipient" | "policy_gate";
  reason_class: HandoffReasonClass;
}

export interface CompleteHandoffInput {
  handoff_id: string;
  recipient: CoordinationSigner;
  /**
   * Optional foreign key to the work-completion audit chain entry that
   * preceded the handoff close-out. Surfaced on the audit payload.
   */
  completion_audit_ref?: string;
}

export interface FailHandoffInput {
  handoff_id: string;
  actor: CoordinationSigner;
  actor_role: "sender" | "recipient";
  reason_class: HandoffReasonClass;
}

export interface ProposeHandoffResult {
  status: "created" | "denied";
  record?: LocalHandoffRecord;
  audit_payload: LocalHandoffAuditPayload;
}

const HANDOFF_AUDIT_OPERATION = "v1.1_local_handoff";

function newHandoffId(): string {
  return `lh-${Date.now()}-${toBase64url(randomBytes(8))}`;
}

function newAuditEventId(): string {
  return `lhe-${Date.now()}-${toBase64url(randomBytes(6))}`;
}

export interface LocalCoordinatorConfig {
  store: HandoffStore;
  auditLog: AuditLog;
  keyResolver: CoordinationKeyResolver;
  policyGate?: CoordinationPolicyGate;
  /** Injectable clock for deterministic tests. */
  now?: () => Date;
}

export class LocalCoordinator {
  private readonly store: HandoffStore;
  private readonly auditLog: AuditLog;
  private readonly keyResolver: CoordinationKeyResolver;
  private readonly policyGate?: CoordinationPolicyGate;
  private readonly now: () => Date;

  constructor(config: LocalCoordinatorConfig) {
    this.store = config.store;
    this.auditLog = config.auditLog;
    this.keyResolver = config.keyResolver;
    this.policyGate = config.policyGate;
    this.now = config.now ?? (() => new Date());
  }

  // ── Read API ────────────────────────────────────────────────────────────

  async getHandoff(handoffId: string): Promise<LocalHandoffRecord | undefined> {
    return this.store.get(handoffId);
  }

  async listHandoffs(
    filter?: HandoffStoreFilter,
  ): Promise<LocalHandoffRecord[]> {
    return this.store.list(filter);
  }

  // ── Lifecycle API ───────────────────────────────────────────────────────

  /**
   * Create + sign a new handoff. Runs the recipient policy gate (when
   * configured) before persisting. On gate denial, no record is stored; a
   * single `denied` audit event is emitted with `actor_role: "policy_gate"`.
   */
  async proposeHandoff(input: ProposeHandoffInput): Promise<ProposeHandoffResult> {
    if (input.sender.identity_id === input.recipient_agent_id) {
      throw new HandoffActorError("sender and recipient must be distinct agents");
    }
    if (
      this.keyResolver.lookupAgentPublicKey(input.sender.identity_id) ===
      undefined
    ) {
      throw new HandoffActorError(
        `sender agent ${input.sender.identity_id} not registered with key resolver`,
      );
    }
    if (
      this.keyResolver.lookupAgentPublicKey(input.recipient_agent_id) ===
      undefined
    ) {
      throw new HandoffActorError(
        `recipient agent ${input.recipient_agent_id} not registered with key resolver`,
      );
    }

    if (this.policyGate) {
      const gateDecision = this.policyGate.evaluateContextTransfer({
        sender_agent_id: input.sender.identity_id,
        recipient_agent_id: input.recipient_agent_id,
        identity_id: input.identity_id,
        requested_capabilities: input.task_scope.requested_capabilities,
      });
      if (gateDecision.decision === "deny") {
        if (!input.operator) {
          throw new HandoffPolicyDenialError(gateDecision.reason_code);
        }
        const denialPayload = await this.emitAuditPayload(
          {
            handoff_id: newHandoffId(),
            sender_agent_id: input.sender.identity_id,
            recipient_agent_id: input.recipient_agent_id,
            identity_id: input.identity_id,
            previous_status: "created",
            new_status: "denied",
            actor: input.operator,
            actor_role: "policy_gate",
            reason_class: "policy_deny",
          },
          "failure",
        );
        return { status: "denied", audit_payload: denialPayload };
      }
    }

    const createdAt = this.now().toISOString();
    const handoffId = newHandoffId();
    const unsigned: Omit<LocalHandoffRecord, "signature"> = {
      version: "1.1",
      handoff_id: handoffId,
      created_at: createdAt,
      sender_agent_id: input.sender.identity_id,
      recipient_agent_id: input.recipient_agent_id,
      identity_id: input.identity_id,
      task_scope: input.task_scope,
      context_reference: input.context_reference,
      status: "created",
      status_changed_at: createdAt,
      signature_scheme: SIGNATURE_SCHEME_V1,
    };
    const record = signHandoffRecord(unsigned, input.sender);

    await this.store.put(record);

    const auditPayload = await this.emitAuditPayload({
      handoff_id: handoffId,
      sender_agent_id: record.sender_agent_id,
      recipient_agent_id: record.recipient_agent_id,
      identity_id: record.identity_id,
      previous_status: "created",
      new_status: "created",
      actor: input.sender,
      actor_role: "sender",
    });

    return { status: "created", record, audit_payload: auditPayload };
  }

  /**
   * Recipient signs acceptance. Rejects if the handoff is not in `created`
   * state, if the signer's identity does not match the recipient agent, or
   * if the persisted record's Layer 1 signature fails verification.
   */
  async acceptHandoff(
    input: AcceptHandoffInput,
  ): Promise<LocalHandoffAuditPayload> {
    const record = await this.requireHandoff(input.handoff_id);
    this.requireState(record, ["created"]);
    this.requireActor(input.recipient, record.recipient_agent_id, "recipient");
    this.assertLayer1Signature(record);

    const updated: LocalHandoffRecord = {
      ...record,
      status: "accepted",
      status_changed_at: this.now().toISOString(),
    };
    await this.store.put(updated);

    return this.emitAuditPayload({
      handoff_id: record.handoff_id,
      sender_agent_id: record.sender_agent_id,
      recipient_agent_id: record.recipient_agent_id,
      identity_id: record.identity_id,
      previous_status: "created",
      new_status: "accepted",
      actor: input.recipient,
      actor_role: "recipient",
    });
  }

  /**
   * Recipient or operator denies a handoff. Allowed from `created` or
   * `accepted`; the second case covers operator-initiated rescinding after
   * acceptance. Audit payload encodes who denied it via `actor_role`.
   */
  async denyHandoff(
    input: DenyHandoffInput,
  ): Promise<LocalHandoffAuditPayload> {
    const record = await this.requireHandoff(input.handoff_id);
    this.requireState(record, ["created", "accepted"]);
    if (input.actor_role === "recipient") {
      this.requireActor(input.actor, record.recipient_agent_id, "recipient");
    } else {
      this.requireActor(input.actor, record.identity_id, "policy_gate");
    }

    const updated: LocalHandoffRecord = {
      ...record,
      status: "denied",
      status_changed_at: this.now().toISOString(),
      status_reason_class: input.reason_class,
    };
    await this.store.put(updated);

    return this.emitAuditPayload(
      {
        handoff_id: record.handoff_id,
        sender_agent_id: record.sender_agent_id,
        recipient_agent_id: record.recipient_agent_id,
        identity_id: record.identity_id,
        previous_status: record.status,
        new_status: "denied",
        actor: input.actor,
        actor_role: input.actor_role,
        reason_class: input.reason_class,
      },
      "failure",
    );
  }

  /**
   * Recipient signs handoff completion. Allowed only from `accepted`.
   */
  async completeHandoff(
    input: CompleteHandoffInput,
  ): Promise<LocalHandoffAuditPayload> {
    const record = await this.requireHandoff(input.handoff_id);
    this.requireState(record, ["accepted"]);
    this.requireActor(input.recipient, record.recipient_agent_id, "recipient");

    const updated: LocalHandoffRecord = {
      ...record,
      status: "completed",
      status_changed_at: this.now().toISOString(),
    };
    await this.store.put(updated);

    return this.emitAuditPayload({
      handoff_id: record.handoff_id,
      sender_agent_id: record.sender_agent_id,
      recipient_agent_id: record.recipient_agent_id,
      identity_id: record.identity_id,
      previous_status: "accepted",
      new_status: "completed",
      actor: input.recipient,
      actor_role: "recipient",
      completion_audit_ref: input.completion_audit_ref,
    });
  }

  /**
   * Either side surfaces a failure (recipient unreachable, context
   * unavailable, etc.). Allowed from `created` or `accepted`.
   */
  async failHandoff(
    input: FailHandoffInput,
  ): Promise<LocalHandoffAuditPayload> {
    const record = await this.requireHandoff(input.handoff_id);
    this.requireState(record, ["created", "accepted"]);
    const expectedActor =
      input.actor_role === "sender"
        ? record.sender_agent_id
        : record.recipient_agent_id;
    this.requireActor(input.actor, expectedActor, input.actor_role);

    const updated: LocalHandoffRecord = {
      ...record,
      status: "failed",
      status_changed_at: this.now().toISOString(),
      status_reason_class: input.reason_class,
    };
    await this.store.put(updated);

    return this.emitAuditPayload(
      {
        handoff_id: record.handoff_id,
        sender_agent_id: record.sender_agent_id,
        recipient_agent_id: record.recipient_agent_id,
        identity_id: record.identity_id,
        previous_status: record.status,
        new_status: "failed",
        actor: input.actor,
        actor_role: input.actor_role,
        reason_class: input.reason_class,
      },
      "failure",
    );
  }

  // ── Internals ───────────────────────────────────────────────────────────

  private async requireHandoff(
    handoffId: string,
  ): Promise<LocalHandoffRecord> {
    const record = await this.store.get(handoffId);
    if (!record) throw new HandoffNotFoundError(handoffId);
    return record;
  }

  private requireState(
    record: LocalHandoffRecord,
    expected: readonly HandoffStatus[],
  ): void {
    if (!expected.includes(record.status)) {
      throw new HandoffStateError(record.status, expected);
    }
  }

  private requireActor(
    signer: CoordinationSigner,
    expectedId: string,
    role: LocalHandoffAuditPayload["actor_role"],
  ): void {
    if (signer.identity_id !== expectedId) {
      throw new HandoffActorError(
        `actor ${signer.identity_id} does not match expected ${role} ${expectedId}`,
      );
    }
  }

  private assertLayer1Signature(record: LocalHandoffRecord): void {
    if (!verifyHandoffRecord(record, this.keyResolver)) {
      throw new HandoffSignatureError(
        `Layer 1 signature on handoff ${record.handoff_id} failed verification`,
      );
    }
  }

  private async emitAuditPayload(
    args: {
      handoff_id: string;
      sender_agent_id: string;
      recipient_agent_id: string;
      identity_id: string;
      previous_status: HandoffStatus;
      new_status: HandoffStatus;
      actor: CoordinationSigner;
      actor_role: LocalHandoffAuditPayload["actor_role"];
      reason_class?: LocalHandoffAuditPayload["reason_class"];
      completion_audit_ref?: string;
    },
    result: "success" | "failure" = "success",
  ): Promise<LocalHandoffAuditPayload> {
    const eventId = newAuditEventId();
    const emittedAt = this.now().toISOString();
    const unsigned: Omit<LocalHandoffAuditPayload, "actor_signature"> = {
      version: "1.1",
      event_id: eventId,
      emitted_at: emittedAt,
      handoff_id: args.handoff_id,
      previous_status: args.previous_status,
      new_status: args.new_status,
      sender_agent_id: args.sender_agent_id,
      recipient_agent_id: args.recipient_agent_id,
      identity_id: args.identity_id,
      actor_id: args.actor.identity_id,
      actor_role: args.actor_role,
      reason_class: args.reason_class,
      signature_scheme: SIGNATURE_SCHEME_V1,
    };
    const signed = signAuditPayload(unsigned, args.actor);
    const auditDetails: Record<string, unknown> = { ...signed };
    if (args.completion_audit_ref !== undefined) {
      auditDetails.completion_audit_ref = args.completion_audit_ref;
    }
    await this.auditLog.append(
      "l2",
      HANDOFF_AUDIT_OPERATION,
      args.identity_id,
      auditDetails,
      result,
    );
    return signed;
  }
}
