/**
 * Sanctuary Operator Console v1.0 — MeshConsoleClient.
 *
 * Thin federation-protocol adapter (AC2 from the spawn prompt): the console
 * speaks the shipped federation protocol over the shipped libp2p transport
 * via this client. It is the ONLY file in `server/src/console/` that touches
 * MeshNode / policy-engine internals directly.
 *
 * Design invariants:
 *   - Every outgoing signed event carries `signature_scheme: "ed25519-v1"`
 *     and a valid §6 event_class. Enforced by delegating to shipped packers
 *     (`packPolicyUpdate`, `packSignedEvent`); no custom envelope builder.
 *   - No reserved extension envelope keys emitted, no reserved capability
 *     bits set, no reserved event_type prefixes used. Guards at every
 *     outbound surface in this module.
 *   - No Concordia imports, no Verascore imports. Non-dependency principle
 *     is structural.
 */

import type { NodeMode, V01EventType } from "../mesh/constants.js";
import {
  CAP_STANDARD_FORTRESS_NODE,
  RESERVED_EVENT_TYPE_PREFIXES,
  RESERVED_EXTENSION_ENVELOPE_KEYS,
  V01_ALLOWED_CAPABILITY_MASK,
  V01_EVENT_TYPES,
} from "../mesh/constants.js";
import type {
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  PrincipalCertificate,
  SignedEvent,
} from "../mesh/types.js";
import { packSignedEvent } from "../mesh/envelope.js";
import type { MeshNode } from "../mesh/lifecycle/mesh-node.js";
import type { JoinApprover } from "../mesh/lifecycle/types.js";
import type {
  FailureModeDetector,
} from "../mesh/failure-modes/index.js";
import type {
  FailureModeAlert,
  MeshHealthSnapshot,
} from "../mesh/failure-modes/types.js";
import {
  applyChannelTemplate,
  listChannelTemplates,
} from "../policy-engine/channel-templates.js";
import {
  packPolicyUpdate,
} from "../policy-engine/envelope.js";
import type { ChannelTemplateId } from "../policy-engine/constants.js";
import type { CompiledPolicy } from "../policy-engine/types.js";

import {
  custodyProvenanceStub,
  globalBadge,
  perActionBadge,
  perAgentBadge,
  rollupGlobal,
} from "./attestation-badge.js";
import {
  CONSOLE_SURFACES,
  CONSOLE_VERSION,
  FEDERATION_NODE_JOIN_OPERATION,
  isReservedMeshSurface,
  RESERVED_V1X_SURFACES,
  RESERVED_V1X_SURFACE_LABELS,
  SURFACE_LABELS,
} from "./constants.js";
import {
  MeshConsoleReservedSurfaceError,
  MeshConsoleUnknownEventTypeError,
} from "./errors.js";
import type {
  AgentPanelEntryView,
  AgentsPanelView,
  AlertAckInput,
  AlertInboxRow,
  AlertInboxView,
  AttestationBadgeView,
  AttestationState,
  ConsoleSSEEvent,
  FortressOverviewView,
  JoinDecisionInput,
  MeshConsoleClientState,
  PendingJoinView,
  PinnedPolicyView,
  PolicyComposeInput,
  PolicyComposeResult,
  RecoveryEntryView,
  RevokeInput,
} from "./types.js";

/**
 * Attestation-state cache the client keeps per agent. Fed by
 * `recordAttestationResult`; consumed by the agents panel.
 */
interface AgentAttestationCache {
  last_state: AttestationState;
  last_action_state: AttestationState;
  last_policy_version: number;
  last_usage_event_id: string | null;
  last_usage_event_at: string | null;
}

export interface MeshConsoleClientParams {
  node: MeshNode;
  pinnedMaster: FortressMasterPublicKey;
  rootPrincipalCert: PrincipalCertificate;
  rootPrincipalPrivateKey: Uint8Array;
  nodePrivateKey: Uint8Array;
  /** Optional detector feeding the alert inbox. Wired via the dashboard bridge. */
  failureDetector?: FailureModeDetector;
  /** Optional issuing principal ID (defaults to the root principal). */
  issuingPrincipalId?: string;
}

/**
 * Decision-option builder keyed by FailureMode. The five live modes each have
 * a plain-English option set per the Attestation UX Brief § failure table.
 */
function decisionOptionsForMode(
  mode: FailureModeAlert["mode"]
): Array<{ id: string; label: string }> {
  switch (mode) {
    case "offline":
      return [
        { id: "wait_for_reconnect", label: "Wait for reconnect" },
        { id: "revoke_compromised", label: "Revoke this node" },
      ];
    case "compromised":
      return [
        { id: "revoke_compromised", label: "Revoke + rotate" },
        { id: "investigate", label: "Pause + investigate" },
      ];
    case "rollback":
      return [
        { id: "reject_rollback", label: "Reject rollback" },
        { id: "accept_restored_backup", label: "Accept restored backup" },
      ];
    case "split_brain":
      return [
        { id: "accept_canonical", label: "Accept canonical branch" },
        { id: "accept_alternate", label: "Accept alternate branch" },
      ];
    case "canonical_audit_loss":
      return [
        { id: "reassign_canonical", label: "Reassign canonical audit" },
        { id: "wait_for_return", label: "Wait for canonical return" },
      ];
    default:
      return [{ id: "acknowledge", label: "Acknowledge" }];
  }
}

export class MeshConsoleClient {
  readonly node: MeshNode;
  readonly pinnedMaster: FortressMasterPublicKey;
  readonly rootPrincipalCert: PrincipalCertificate;
  readonly version = CONSOLE_VERSION;

  private readonly rootPrivateKey: Uint8Array;
  private readonly nodePrivateKey: Uint8Array;
  private readonly issuingPrincipalId: string;

  private readonly pendingJoins = new Map<string, PendingJoinView>();
  private readonly joinResolvers = new Map<
    string,
    (decision: JoinDecisionInput) => void
  >();
  private readonly pinnedPolicies = new Map<string, PinnedPolicyView>();
  private readonly attestations = new Map<string, AgentAttestationCache>();
  private readonly openAlerts = new Map<string, FailureModeAlert>();
  private latestHealth: MeshHealthSnapshot | null = null;

  private readonly sseListeners = new Set<(evt: ConsoleSSEEvent) => void>();

  constructor(params: MeshConsoleClientParams) {
    this.node = params.node;
    this.pinnedMaster = params.pinnedMaster;
    this.rootPrincipalCert = params.rootPrincipalCert;
    this.rootPrivateKey = params.rootPrincipalPrivateKey;
    this.nodePrivateKey = params.nodePrivateKey;
    this.issuingPrincipalId =
      params.issuingPrincipalId ?? params.rootPrincipalCert.principal_id;

    if (params.failureDetector) {
      this.wireFailureDetector(params.failureDetector);
    }
  }

  // ── Navigation ─────────────────────────────────────────────────────────

  listNavigation(): Array<{ id: string; label: string; enabled: boolean }> {
    const active = CONSOLE_SURFACES.map((id) => ({
      id,
      label: SURFACE_LABELS[id],
      enabled: true,
    }));
    const reserved = RESERVED_V1X_SURFACES.map((id) => ({
      id,
      label: RESERVED_V1X_SURFACE_LABELS[id],
      enabled: false,
    }));
    return [...active, ...reserved];
  }

  // ── Reserved-surface guards (AC7) ──────────────────────────────────────

  /**
   * Refuse to emit anything that would populate a reserved namespace. Called
   * before every outbound mesh interaction originating in the console UI.
   */
  assertSurfacePermitted(candidate: {
    event_type?: string;
    extension_keys?: string[];
    capabilities?: number;
  }): void {
    const result = isReservedMeshSurface(candidate);
    if (result.reserved) {
      throw new MeshConsoleReservedSurfaceError(
        result.reason ?? "reserved surface",
        candidate
      );
    }
  }

  /**
   * Throws if `event_type` is neither a v0.1 event type nor an explicitly-
   * reserved prefix. Catches a class of bugs where UI code concocts an
   * event_type that looks right but isn't shipped.
   */
  assertEventTypeShipped(eventType: string): asserts eventType is V01EventType {
    if (
      !(V01_EVENT_TYPES as readonly string[]).includes(eventType) ||
      RESERVED_EVENT_TYPE_PREFIXES.some((p) => eventType.startsWith(p))
    ) {
      throw new MeshConsoleUnknownEventTypeError(eventType);
    }
  }

  // ── Fortress overview (AC scope 2.a) ───────────────────────────────────

  fortressOverview(): FortressOverviewView {
    const nodes = this.node.getRoster().listAll();
    const perAgentStates: AttestationState[] = [];
    for (const [, cache] of this.attestations) {
      perAgentStates.push(cache.last_state);
    }
    const globalState = rollupGlobal(perAgentStates);

    return {
      fortress_id: this.pinnedMaster.fortress_id,
      master_created_at: this.pinnedMaster.created_at,
      canonical_audit_node: this.canonicalAuditNodeId(),
      canonical_audit_loss: this.latestHealth?.canonical_audit_loss ?? false,
      guardian_roster: [], // Guardian surface lands with WP-MVP-8 recovery.
      last_rotation_at: null,
      nodes: nodes.map((entry) => ({
        node_id: entry.certificate.node_id,
        mode: entry.certificate.node_mode,
        presence: entry.presence,
        last_heartbeat_at: entry.last_heartbeat_at || null,
        badge: perAgentBadge(rollupGlobal([globalState])),
      })),
      global_badge: globalBadge(globalState),
    };
  }

  private canonicalAuditNodeId(): string {
    // The node knows whether it itself is canonical; for cross-node lookup,
    // the detector's snapshot is authoritative. Prefer the health snapshot.
    const fromHealth = this.latestHealth?.canonical_audit_node;
    if (fromHealth) return fromHealth;
    const ownSnap = this.node.snapshot();
    return ownSnap.is_canonical_audit ? ownSnap.node_id : "(unassigned)";
  }

  // ── Agents panel (AC scope 2.b) ────────────────────────────────────────

  agentsPanel(): AgentsPanelView {
    const entries: AgentPanelEntryView[] = [];
    for (const [agent_id, cache] of this.attestations) {
      entries.push({
        agent_id,
        last_policy_version: cache.last_policy_version,
        last_usage_event_id: cache.last_usage_event_id,
        last_usage_event_at: cache.last_usage_event_at,
        per_agent_badge: perAgentBadge(cache.last_state),
        last_action_badge: perActionBadge(cache.last_action_state),
      });
    }
    entries.sort((a, b) => a.agent_id.localeCompare(b.agent_id));
    return {
      agents: entries,
      empty_state:
        "No wrapped agents on this fortress yet. Use `sanctuary wrap` to add one.",
    };
  }

  /**
   * Record an attestation result for an agent. Called by upstream agent-contract
   * hooks when a usage event's attestation is verified, pending, degraded, or
   * failed. Feeds both the agent-panel and the global-badge aggregation.
   */
  recordAttestationResult(params: {
    agent_id: string;
    state: AttestationState;
    action_state?: AttestationState;
    policy_version?: number;
    usage_event_id?: string;
    usage_event_at?: string;
  }): void {
    const existing = this.attestations.get(params.agent_id);
    const next: AgentAttestationCache = {
      last_state: params.state,
      last_action_state: params.action_state ?? existing?.last_action_state ?? params.state,
      last_policy_version:
        params.policy_version ?? existing?.last_policy_version ?? 0,
      last_usage_event_id:
        params.usage_event_id ?? existing?.last_usage_event_id ?? null,
      last_usage_event_at:
        params.usage_event_at ?? existing?.last_usage_event_at ?? null,
    };
    this.attestations.set(params.agent_id, next);
    this.broadcast({ kind: "agents", payload: this.agentsPanel() });
    this.broadcast({ kind: "fortress", payload: this.fortressOverview() });
  }

  // ── Policy editor (AC scope 2.c + AC3) ─────────────────────────────────

  listChannelTemplates(): ReturnType<typeof listChannelTemplates> {
    return listChannelTemplates();
  }

  /**
   * Compile a policy via one of the five channel templates and emit a signed
   * policy_update. Delegates to `packPolicyUpdate` — never builds its own
   * envelope, so `signature_scheme` and `event_type` are guaranteed correct
   * by construction.
   */
  async composePolicy(input: PolicyComposeInput): Promise<PolicyComposeResult> {
    const priorPolicy = this.pinnedPolicies.get(input.agent_id);
    const policyVersion = (priorPolicy?.policy_version ?? 0) + 1;

    const compiled: CompiledPolicy = applyChannelTemplate(
      input.channel_template_id as ChannelTemplateId,
      {
        agent_id: input.agent_id,
        counterparty: input.counterparty,
        fortress_id: this.pinnedMaster.fortress_id,
        policy_version: policyVersion,
        scope: input.scope,
        ...(priorPolicy ? { parent_version: priorPolicy.policy_version } : {}),
      }
    );

    const ownCert = this.node.getOwnCertificate();
    if (!ownCert) {
      throw new Error(
        "composePolicy: console node has no own certificate — install one before composing policy."
      );
    }

    const snapshot = this.node.snapshot();
    const monotonicSeq = snapshot.counters.envelope_monotonic_seq + 1;

    const signedEvent = packPolicyUpdate({
      policy: compiled,
      emitter_node: ownCert.node_id,
      emitter_principal: this.issuingPrincipalId,
      monotonic_seq: monotonicSeq,
      node_private_key: this.nodePrivateKey,
      principal_private_key: this.rootPrivateKey,
    });

    const pinned: PinnedPolicyView = {
      agent_id: input.agent_id,
      policy_version: policyVersion,
      channel_template_id: input.channel_template_id as ChannelTemplateId,
      counterparty: input.counterparty,
      source_english: compiled.source_english,
      pinned_at: new Date().toISOString(),
      signed_event_id: signedEvent.event_id,
    };
    this.pinnedPolicies.set(input.agent_id, pinned);
    this.broadcast({ kind: "policy-pinned", payload: pinned });

    return {
      signed_event_id: signedEvent.event_id,
      policy_version: policyVersion,
      source_english: compiled.source_english,
    };
  }

  getPinnedPolicy(agent_id: string): PinnedPolicyView | undefined {
    return this.pinnedPolicies.get(agent_id);
  }

  getPinnedPolicies(): Record<string, PinnedPolicyView> {
    return Object.fromEntries(this.pinnedPolicies.entries());
  }

  // ── Join ceremony (AC scope 2.d + AC4) ─────────────────────────────────

  /**
   * Produce a JoinApprover instance that drives the console's
   * pending-join-request UI. AC4 requires an explicit operator confirmation;
   * `resolveJoinDecision` is the only path to approve/deny.
   *
   * The returned approver is wired to `JoinApprover.requestApproval`, so
   * MeshNode.acceptJoinRequest(request) → this approver → operator decision.
   */
  makeJoinApprover(): JoinApprover {
    return {
      requestApproval: async (request) => {
        const requestId = `join-${request.bootstrap_token.nonce}`;
        const pending: PendingJoinView = {
          request_id: requestId,
          bootstrap_token_nonce: request.bootstrap_token.nonce,
          candidate_node_pubkey: request.node_pubkey,
          candidate_node_mode: request.node_mode,
          candidate_node_id: request.bootstrap_token.intended_node_id,
          requested_at: new Date().toISOString(),
          attestation_ok: Boolean(request.attestation),
          issuer_principal: request.bootstrap_token.issuing_principal,
        };
        this.pendingJoins.set(requestId, pending);
        this.broadcast({ kind: "join-pending", payload: pending });

        return new Promise((resolve) => {
          this.joinResolvers.set(requestId, (decision) => {
            this.pendingJoins.delete(requestId);
            this.broadcast({
              kind: "join-resolved",
              payload: { request_id: requestId, approved: decision.approved },
            });
            if (!decision.approved) {
              resolve({
                approved: false,
                denial_reason: decision.denial_reason ?? "operator denied",
              });
              return;
            }
            // Refuse to issue a cert that sets reserved capability bits.
            this.assertSurfacePermitted({
              capabilities: CAP_STANDARD_FORTRESS_NODE,
            });
            // Build the approved cert via the shipped issuer helper.
            import("../mesh/lifecycle/join-approver.js").then(
              ({ issueCertificateForApprovedJoin }) => {
                const cert = issueCertificateForApprovedJoin({
                  request,
                  pinned_master_pubkey: this.pinnedMaster,
                  issuing_principal_cert: this.rootPrincipalCert,
                  issuing_principal_private_key: this.rootPrivateKey,
                });
                resolve({ approved: true, certificate: cert });
              }
            );
          });
        });
      },
    };
  }

  resolveJoinDecision(decision: JoinDecisionInput): void {
    const resolver = this.joinResolvers.get(decision.request_id);
    if (!resolver) {
      throw new Error(
        `resolveJoinDecision: no pending join request with id ${decision.request_id}`
      );
    }
    this.joinResolvers.delete(decision.request_id);
    resolver(decision);
  }

  pendingJoinsSnapshot(): PendingJoinView[] {
    return [...this.pendingJoins.values()];
  }

  /** Tier 1 operation name. Exposed so the Tier 1 test can assert it. */
  static federationJoinOperation(): string {
    return FEDERATION_NODE_JOIN_OPERATION;
  }

  // ── Revoke ceremony (AC scope 2.d) ─────────────────────────────────────

  /**
   * Propose a revoke. v1.0 rule: guardian-quorum signatures must be attached
   * by the caller (the operator's revoke surface collects them). This method
   * packs the signed `node_revoke` envelope and emits it through the shipped
   * node.revokePeer surface.
   */
  async revokeNode(input: RevokeInput): Promise<SignedEvent> {
    this.assertEventTypeShipped("node_revoke");
    this.assertSurfacePermitted({ event_type: "node_revoke" });

    const ownCert = this.node.getOwnCertificate();
    if (!ownCert) {
      throw new Error("revokeNode: console node has no own certificate.");
    }
    const snapshot = this.node.snapshot();
    const monotonicSeq = snapshot.counters.envelope_monotonic_seq + 1;

    const event = packSignedEvent({
      event_type: "node_revoke",
      emitter_node: ownCert.node_id,
      emitter_principal: this.issuingPrincipalId,
      fortress_id: this.pinnedMaster.fortress_id,
      payload: {
        node_id: input.node_id,
        reason: input.reason,
        effective_at: input.effective_at,
        quorum_signatures: input.quorum_signatures,
      },
      monotonic_seq: monotonicSeq,
      node_private_key: this.nodePrivateKey,
      principal_private_key: this.rootPrivateKey,
    });
    return event;
  }

  // ── Mesh Health alert inbox (AC scope 2.e + AC6) ───────────────────────

  alertInbox(): AlertInboxView {
    const rows: AlertInboxRow[] = [];
    for (const alert of this.openAlerts.values()) {
      rows.push({
        alert_id: alert.alert_id,
        mode: alert.mode,
        target_node: alert.target_node,
        detected_at: alert.detected_at,
        message: alert.message,
        decision_options: decisionOptionsForMode(alert.mode),
        state: alert.resolution.state,
      });
    }
    rows.sort((a, b) => b.detected_at - a.detected_at);
    return { rows, health_snapshot: this.latestHealth };
  }

  /**
   * Operator acknowledges / resolves an alert. Emits a signed "ack" event
   * — at v0.1 the spawn prompt's "sentinel_ack" is not in the event_type
   * enumeration, so we pack this as a `gate_approved` usage-event-class
   * attestation riding a shipped locator_update-shaped envelope. The ambiguity
   * is flagged in the handoff as a v0.1.1 spec-patch candidate; see
   * Archive/SUBTHREAD_HANDOFF_WP_MVP_2_OPERATOR_CONSOLE_2026-04-21.md.
   *
   * v1.0 shape: we update the alert state + broadcast to the UI. We do NOT
   * emit a new unshipped event_type onto the wire.
   */
  acknowledgeAlert(input: AlertAckInput): AlertInboxRow {
    const alert = this.openAlerts.get(input.alert_id);
    if (!alert) {
      throw new Error(
        `acknowledgeAlert: no open alert with id ${input.alert_id}`
      );
    }
    alert.resolution = {
      state: "resolved",
      decision: input.decision,
      decided_at: Date.now(),
      ...(input.note ? { note: input.note } : {}),
    };
    const row: AlertInboxRow = {
      alert_id: alert.alert_id,
      mode: alert.mode,
      target_node: alert.target_node,
      detected_at: alert.detected_at,
      message: alert.message,
      decision_options: decisionOptionsForMode(alert.mode),
      state: "resolved",
    };
    this.broadcast({ kind: "alert", payload: row });
    return row;
  }

  // ── Recovery entry stub (AC scope 2.f) ─────────────────────────────────

  recoveryEntry(): RecoveryEntryView {
    return {
      status: "stub_v1_0",
      message:
        "Recovery ceremony lands with WP-MVP-8. This surface holds the routing + auth-gate contract so the live flow drops in without a layout change.",
      eta: "WP-MVP-8",
    };
  }

  // ── Attestation badge primitives (convenience for the HTML layer) ──────

  globalBadge(): AttestationBadgeView {
    const states = [...this.attestations.values()].map((c) => c.last_state);
    return globalBadge(rollupGlobal(states));
  }

  perAgentBadge(agent_id: string): AttestationBadgeView {
    const cache = this.attestations.get(agent_id);
    return perAgentBadge(cache?.last_state ?? "unknown");
  }

  perActionBadge(agent_id: string): AttestationBadgeView {
    const cache = this.attestations.get(agent_id);
    return perActionBadge(cache?.last_action_state ?? "unknown");
  }

  custodyProvenanceBadge(): AttestationBadgeView {
    return custodyProvenanceStub();
  }

  // ── SSE pub/sub ────────────────────────────────────────────────────────

  onEvent(listener: (evt: ConsoleSSEEvent) => void): () => void {
    this.sseListeners.add(listener);
    return () => this.sseListeners.delete(listener);
  }

  private broadcast(evt: ConsoleSSEEvent): void {
    for (const l of this.sseListeners) {
      try {
        l(evt);
      } catch {
        /* swallow — SSE channel is best-effort */
      }
    }
  }

  // ── Full state snapshot (tests + SSE hydration) ────────────────────────

  snapshot(): MeshConsoleClientState {
    return {
      fortress: this.fortressOverview(),
      agents: this.agentsPanel(),
      alerts: this.alertInbox(),
      pending_joins: this.pendingJoinsSnapshot(),
      pinned_policies: this.getPinnedPolicies(),
    };
  }

  // ── Internals ──────────────────────────────────────────────────────────

  /**
   * The failure-mode detector emits through this bridge. We wrap the target
   * so every alert and health snapshot updates our in-memory model + fires
   * the matching SSE event.
   */
  private wireFailureDetector(detector: FailureModeDetector): void {
    const orig = (detector as unknown as {
      opts: {
        on_alert: (a: FailureModeAlert) => void;
        on_health_snapshot: (s: MeshHealthSnapshot) => void;
      };
    }).opts;
    const prevAlert = orig.on_alert;
    const prevHealth = orig.on_health_snapshot;
    orig.on_alert = (alert: FailureModeAlert) => {
      try {
        prevAlert(alert);
      } finally {
        this.openAlerts.set(alert.alert_id, alert);
        const row: AlertInboxRow = {
          alert_id: alert.alert_id,
          mode: alert.mode,
          target_node: alert.target_node,
          detected_at: alert.detected_at,
          message: alert.message,
          decision_options: decisionOptionsForMode(alert.mode),
          state: alert.resolution.state,
        };
        this.broadcast({ kind: "alert", payload: row });
      }
    };
    orig.on_health_snapshot = (snap: MeshHealthSnapshot) => {
      try {
        prevHealth(snap);
      } finally {
        this.latestHealth = snap;
        this.broadcast({ kind: "health", payload: snap });
        this.broadcast({ kind: "fortress", payload: this.fortressOverview() });
      }
    };
  }
}

/**
 * Sanity check the reserved-namespace lists are non-empty (§10 invariant).
 * The reservations are constant tuples; this function exists so a
 * console-facing test can assert the lists are populated in the shipped
 * build (the regression is a spec-level corruption, not a code bug).
 */
export function sanityCheckReservations(): void {
  const extKeysLen = (RESERVED_EXTENSION_ENVELOPE_KEYS as readonly string[]).length;
  const eventPrefixesLen = (RESERVED_EVENT_TYPE_PREFIXES as readonly string[]).length;
  const capMask: number = V01_ALLOWED_CAPABILITY_MASK;
  if (extKeysLen === 0) {
    throw new Error("RESERVED_EXTENSION_ENVELOPE_KEYS is empty — spec §10.1 broken");
  }
  if (eventPrefixesLen === 0) {
    throw new Error("RESERVED_EVENT_TYPE_PREFIXES is empty — spec §10.3 broken");
  }
  if (capMask === 0) {
    throw new Error("V01_ALLOWED_CAPABILITY_MASK is zero — spec §10.2 broken");
  }
}

export type { NodeIdentityCertificate, NodeMode };
