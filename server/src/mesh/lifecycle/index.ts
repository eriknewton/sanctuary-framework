/**
 * Sanctuary Federation Protocol v0.1 — Lifecycle Orchestrator
 *
 * Public surface for the WP-MVP-3 lifecycle orchestrator. Wires the mesh
 * primitives (server/src/mesh/) into runtime state-machine behavior:
 *   - MeshNode: per-node lifecycle state machine (bootstrap / join / sync /
 *     heartbeat / leave / revoke / rejoin).
 *   - NodeRoster: active-node set, drop-out detection.
 *   - AuditBuffer + CanonicalAuditLog: audit-batch buffering on emitters,
 *     authoritative log on the canonical-audit node.
 *   - PolicyBundleStore + LocatorTableStore + NodeLifecycleEventLog:
 *     replicated state shipped via sync.
 *   - JoinApprover: gate-wrapping abstraction for the operator-decision step.
 *   - Per-node key binding (Q8): wrap/unwrap per-node Ed25519 private keys.
 *   - Sync RPC + Q6 agent-state-transfer wrapping.
 *
 * The lifecycle module is additive on top of the mesh foundation. It does not
 * mutate any primitives in server/src/mesh/, does not introduce new v0.1
 * message classes, and does not consume the v1.x reservation slots (§10).
 */

export * from "./constants.js";
export * from "./types.js";
export {
  NO_AUTHENTICATED_PEER,
  REJECTION_REASON_CLASS,
  authenticatedPeer,
  classifyAdmissionRefusal,
  isCompromiseSignal,
  type AuthenticatedPeer,
  type RejectionOrigin,
  type RejectionReasonClass,
} from "./envelope-rejection.js";
export {
  InMemoryCounterStore,
} from "./counters.js";
export {
  deriveNodeKeyWrappingKey,
  wrapNodePrivateKey,
  unwrapNodePrivateKey,
  InMemoryNodeKeyStore,
} from "./node-key-binding.js";
export {
  FileNodeKeyStore,
  FileCounterStore,
} from "./file-stores.js";
export {
  MeshBootstrapTokenError,
  issueBootstrapToken,
  verifyBootstrapToken,
  computeJoinHkdfSaltProof,
  verifyJoinHkdfSaltProof,
} from "./bootstrap-token.js";
export {
  createAutoApproveJoinApprover,
  createAutoDenyJoinApprover,
  issueCertificateForApprovedJoin,
  generateNodeKeypair,
} from "./join-approver.js";
export {
  OperatorCloudProvisionClaimStore,
  createOperatorCloudJoinApprover,
  OPERATOR_CLOUD_CLAIM_STORE_NAMESPACE,
  OPERATOR_CLOUD_CLAIM_STORE_KEY,
  OPERATOR_CLOUD_CLAIM_STORE_HKDF_INFO,
  type OperatorCloudProvisionClaim,
  type RecordProvisionClaimParams,
  type OperatorCloudJoinApproverParams,
} from "./operator-cloud-join-approver.js";
export {
  BootstrapNonceStore,
  createStandaloneJoinApprover,
  BOOTSTRAP_NONCE_STORE_NAMESPACE,
  BOOTSTRAP_NONCE_STORE_KEY,
  BOOTSTRAP_NONCE_STORE_HKDF_INFO,
  type StandaloneJoinApproverParams,
} from "./standalone-join-approver.js";
export {
  DurableSpentSetStore,
  DurableSpentSetStoreError,
} from "./durable-spent-set-store.js";
export {
  DurableClaimSetStore,
  DurableClaimSetStoreError,
  type PersistedClaimSet,
} from "./durable-claim-set-store.js";
export {
  NodeRoster,
  type DropoutListener,
  type PresenceChangeListener,
  type NodeRosterOptions,
} from "./node-roster.js";
export {
  AuditBuffer,
  CanonicalAuditLog,
  type AuditBufferOptions,
} from "./canonical-audit.js";
export {
  PolicyBundleStore,
  LocatorTableStore,
  NodeLifecycleEventLog,
} from "./local-state.js";
export {
  buildSyncResponse,
  applySyncResponse,
  deriveAgentStateTransferKey,
  wrapAgentSnapshot,
  unwrapAgentSnapshot,
  type SyncResponderState,
  type ApplySyncResult,
} from "./sync.js";
export { MeshNode, type FirstNodeBootstrap } from "./mesh-node.js";
