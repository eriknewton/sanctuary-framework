/**
 * MeshNode - the federation lifecycle state machine.
 *
 * Owns the join / sync / heartbeat-emit / leave / rejoin / revoke / bootstrap
 * flows for a single node. Wires together every other lifecycle module:
 *
 *   - NodeRoster (active-node set + drop-out detection)
 *   - InMemoryCounterStore (per-node monotonic counters)
 *   - AuditBuffer + (optional) CanonicalAuditLog (canonical-audit-node duties)
 *   - PolicyBundleStore + LocatorTableStore + NodeLifecycleEventLog (replicated state)
 *   - JoinApprover (operator approval gate wrapping)
 *   - NodeKeyStore (Q8 node-key binding)
 *
 * Wire-format and crypto live in mesh primitives (server/src/mesh/*); the
 * MeshNode is pure orchestration on top.
 *
 * Spec §3 (lifecycle), §5 (audit), §6 (locator), §7.2 (revoke), §9 (recovery).
 */

import { fromBase64url, toBase64url } from "../../core/encoding.js";
import { randomBytes } from "../../core/random.js";
import {
  DEFAULTS,
  type NodeMode,
} from "../constants.js";
import {
  MeshError,
  MeshChainError,
  MeshReservedCapabilityBitError,
  MeshReservedEventTypeError,
  MeshReservedExtensionKeyError,
  MeshRollbackDetectedError,
} from "../errors.js";
import { packSignedEvent } from "../envelope.js";
import { verifySignedEvent } from "../envelope.js";
import {
  assertQuorumContextFresh,
  buildGuardianRevokeQuorumInput,
  computeRevokeAuthorizationKey,
  parseGuardianRevokeQuorumContext,
  verifyGuardianQuorum,
  verifyGuardianRoster,
  type FreshnessMode,
  type GuardianQuorumProof,
  type GuardianRevokeQuorumContext,
  type GuardianRoster,
} from "../guardian/index.js";
import { receiveAuditBatch, type MeshTransport } from "../in-memory-transport.js";
import { MeshRouter } from "../router.js";
import {
  deriveNodeAuditChainKey,
  deriveNodeTransportKey,
  generateFortressId,
  issuePrincipalCertificate,
  verifyCertChain,
} from "../trust-root.js";
import type {
  AuditEntry,
  FortressMasterPublicKey,
  HeartbeatPayload,
  LocatorUpdatePayload,
  NodeIdentityCertificate,
  NodeJoinPayload,
  NodeLeavePayload,
  NodeLifecyclePayload,
  NodeRevokePayload,
  PolicyUpdatePayload,
  PrincipalCertificate,
  SignedEvent,
} from "../types.js";
import { sealAuditEntry } from "../audit-batch.js";
import { generateKeypair } from "../../core/identity.js";
import {
  AuditBuffer,
  CanonicalAuditLog,
} from "./canonical-audit.js";
import {
  computeJoinHkdfSaltProof,
  issueBootstrapToken,
  verifyBootstrapToken,
  verifyJoinHkdfSaltProof,
} from "./bootstrap-token.js";
import { issueCertificateForApprovedJoin } from "./join-approver.js";
import {
  unwrapNodePrivateKey,
  wrapNodePrivateKey,
} from "./node-key-binding.js";
import {
  LocatorTableStore,
  NodeLifecycleEventLog,
  PolicyBundleStore,
  type PolicyBundleAuditEvent,
  type PolicyBundleUpsertResult,
} from "./local-state.js";
import { NodeRoster } from "./node-roster.js";
import { InMemoryCounterStore } from "./counters.js";
import {
  MAX_OUTSTANDING_SYNC_REQUESTS,
  REVOKE_DENIAL_AUDIT_GLOBAL_MAX,
  REVOKE_DENIAL_AUDIT_PER_EMITTER_MAX,
  REVOKE_DENIAL_AUDIT_WINDOW_MS,
  SYNC_REQUEST_ID_BYTES,
  SYNC_REQUEST_ID_EXPIRY_MS,
} from "./constants.js";
import { DenialAuditGovernor } from "./denial-audit-governor.js";
import {
  applySyncResponse,
  buildSyncResponse,
} from "./sync.js";
import type { CanonicalAuditChangePayload } from "../types.js";
import type {
  BootstrapToken,
  CounterStore,
  JoinApprover,
  JoinRequest,
  MeshNodeConfig,
  MeshNodeSnapshot,
  NodeKeyStore,
  ReceivedEventLog,
  SyncRequestPayload,
  SyncResponsePayload,
} from "./types.js";
import type { MeshNodeState } from "./constants.js";

/**
 * Bootstrap result for the very first node in a fortress (§3.7).
 *
 * Returns the assets the operator's encrypted state store must persist:
 *   - fortress-master-public-key (pinned by every future node)
 *   - root principal certificate
 *   - per-node certificate for this self-bootstrapped node
 *
 * The fortress-master PRIVATE key is also returned so the caller (the
 * orchestrating console) can hand it directly to the operator's encrypted state store for
 * passphrase-wrapped persistence. After persisting, the caller MUST zero
 * this buffer.
 */
export interface FirstNodeBootstrap {
  master_public: FortressMasterPublicKey;
  master_private_key: Uint8Array;
  root_principal_certificate: PrincipalCertificate;
  root_principal_private_key: Uint8Array;
  node_certificate: NodeIdentityCertificate;
  node_private_key: Uint8Array;
}

export class MeshNode {
  private config: MeshNodeConfig;
  private readonly transport: MeshTransport;
  private approver: JoinApprover;
  private readonly keyStore: NodeKeyStore;
  private readonly counters: CounterStore;
  /**
   * In-memory fortress-master secret used for HKDF re-derivation. Swapped on
   * master rotation (installMasterRotation). Caller MUST zero the old buffer
   * after rotation.
   */
  private fortressMasterSecret: Uint8Array;

  private readonly roster = new NodeRoster();
  private readonly policyBundle: PolicyBundleStore;
  private readonly locatorTable = new LocatorTableStore();
  private readonly lifecycleLog = new NodeLifecycleEventLog();
  private readonly principalRoster = new Map<string, PrincipalCertificate>();
  private readonly lastReceivedMonotonicSeq = new Map<string, number>();
  private guardianRoster: GuardianRoster | null = null;
  private readonly router = new MeshRouter();
  private readonly auditBuffer: AuditBuffer;
  private readonly canonicalAudit?: CanonicalAuditLog;

  private nodePrivateKey: Uint8Array | null = null;
  private certificate: NodeIdentityCertificate | null = null;
  private state: MeshNodeState = "unbooted";
  private oldestPendingEntryAt: number | null = null;
  private receivedLog: ReceivedEventLog[] = [];
  /**
   * C12-REPLAY (§3.3 point 7): correlation ids of sync_requests THIS node has
   * issued and not yet consumed, keyed by id -> expiry ms. A sync_response is
   * applied only when it echoes an outstanding, unexpired id, and the match
   * CONSUMES the id. Ids are minted solely here, so an external peer can neither
   * insert nor evict — the set is not externally gameable.
   */
  private readonly outstandingSyncRequests = new Map<string, number>();
  /**
   * C12-REPLAY (§2.5): bounds revoke-denial audit writes (per-emitter + global
   * ceiling) so the guaranteed-denial incentive freshness creates cannot become
   * an audit-write amplifier.
   */
  private readonly denialAuditGovernor = new DenialAuditGovernor(
    REVOKE_DENIAL_AUDIT_PER_EMITTER_MAX,
    REVOKE_DENIAL_AUDIT_GLOBAL_MAX,
    REVOKE_DENIAL_AUDIT_WINDOW_MS
  );
  /**
   * Sibling governor for the uncorrelated-`sync_response` refusal audit path.
   * That refusal is GUARANTEED for any unsolicited response, so without a cap
   * it is a zero-cost audit-write amplifier for any in-roster peer (the same
   * rule-8 incentive shape as the revoke-denial path). Separate instance so
   * the two paths' budgets and saturation summaries never conflate.
   */
  private readonly uncorrelatedSyncAuditGovernor = new DenialAuditGovernor(
    REVOKE_DENIAL_AUDIT_PER_EMITTER_MAX,
    REVOKE_DENIAL_AUDIT_GLOBAL_MAX,
    REVOKE_DENIAL_AUDIT_WINDOW_MS
  );
  /**
   * Third sibling governor, for the master-rotation broadcast refusal path
   * (QI-SIBLING-02 fix round). QI-SIBLING-02 made refusal the GUARANTEED
   * outcome for every stale or replayed rotation broadcast, which is precisely
   * the rule-8 incentive shape the first two governors exist for: without a
   * ceiling, an in-roster peer converts harvested-but-expired rotation quorums
   * into zero-cost audit writes. Separate instance so the three paths' budgets
   * and saturation summaries never conflate. Fed by
   * `auditMasterRotationDenied` and drained by `flushRevokeDenialSaturation`.
   */
  private readonly masterRotationDenialAuditGovernor = new DenialAuditGovernor(
    REVOKE_DENIAL_AUDIT_PER_EMITTER_MAX,
    REVOKE_DENIAL_AUDIT_GLOBAL_MAX,
    REVOKE_DENIAL_AUDIT_WINDOW_MS
  );

  /**
   * Callback hooks - Follow-up #3 (failure-mode operator surfaces) wires these.
   *
   * The third `kind`, `"sync_admitted_out_of_window"`, is the S2 detectability
   * marker (design §3.2): a revoke admitted through the sync channel AFTER its
   * collection window lapsed on this node's clock. It is the operator-visible
   * half of the S2 residual — such an admission is legitimate for a late
   * joiner but is also the only laundering channel left to an attacker, so it
   * is never silent.
   */
  onLifecycleEvent: (
    evt: SignedEvent<NodeLifecyclePayload>,
    kind: "received" | "emitted" | "sync_admitted_out_of_window"
  ) => void = () => {};
  onPolicyUpdate: (
    evt: SignedEvent<PolicyUpdatePayload>,
    result: PolicyBundleUpsertResult
  ) => void = () => {};
  onPolicyBundleRejected: (event: PolicyBundleAuditEvent) => void = () => {};
  onLocatorUpdate: (
    evt: SignedEvent<LocatorUpdatePayload>,
    result: "applied" | "older" | "conflict"
  ) => void = () => {};
  onAuditBatchEmitted: (info: {
    batch_seq: number;
    entry_count: number;
  }) => void = () => {};
  /** Follow-up #3: surfaces rollback / chain-discontinuity / signature failures
   *  that the canonical audit node would otherwise silently drop. The detector
   *  module subscribes here to fire `sentinel_alert` to operators. */
  onAuditBatchRejected: (info: {
    error: Error;
    emitter_node?: string;
  }) => void = () => {};
  /** Follow-up #3: surfaces envelope verification failures (signature mismatch,
   *  unknown emitter, cross-operator isolation violation). Same purpose as
   *  onAuditBatchRejected - convert silent drop to observable alarm. */
  onEnvelopeRejected: (info: {
    error: Error;
    event_type: string;
    emitter_node?: string;
  }) => void = () => {};
  /** Follow-up #3: surfaces every received heartbeat after envelope verification
   *  succeeds. The compromised-node aggregator inspects monotonic_seq +
   *  policy-version vector skew here without re-implementing receive plumbing. */
  onHeartbeatReceived: (info: {
    emitter_node: string;
    monotonic_seq: number;
    policy_version_vector: Record<string, number>;
    audit_seq: number;
    advertised_state: string;
  }) => void = () => {};

  constructor(
    config: MeshNodeConfig,
    deps: {
      transport: MeshTransport;
      approver: JoinApprover;
      key_store: NodeKeyStore;
      counters?: CounterStore;
      fortress_master_secret: Uint8Array;
    }
  ) {
    this.config = config;
    this.transport = deps.transport;
    this.approver = deps.approver;
    this.keyStore = deps.key_store;
    this.counters = deps.counters ?? new InMemoryCounterStore();
    this.fortressMasterSecret = deps.fortress_master_secret;
    this.guardianRoster = config.pinned_guardian_roster ?? null;
    this.policyBundle = new PolicyBundleStore({
      onAuditEvent: (event) => this.onPolicyBundleRejected(event),
    });
    this.auditBuffer = new AuditBuffer({
      audit_batch_interval_ms: config.audit_batch_interval_ms,
      audit_batch_max_entries: config.audit_batch_max_entries,
    });
    if (config.is_canonical_audit_node) {
      this.canonicalAudit = new CanonicalAuditLog();
    }

    // Subscribe to broadcast traffic - verify, then dispatch through the router.
    this.transport.subscribe((evt, _wireBytes) => {
      void this.handleIncomingBroadcast(evt);
    });
    // Subscribe to unicast direct-stream traffic (RPC + audit batches).
    this.transport.subscribeUnicast((to, message) => {
      // Only process unicasts addressed to us.
      if (to !== config.node_id) return;
      void this.handleIncomingUnicast(message);
    });

    this.registerCoreHandlers();
  }

  // ═════════════════════════════════════════════════════════════════════
  // BOOTSTRAP - first node (§3.7)
  // ═════════════════════════════════════════════════════════════════════

  /**
   * Bootstrap the very first node in a fortress.
   *
   * Generates the fortress-master keypair, issues the Root principal cert
   * (signed by master), generates this node's keypair, self-issues this
   * node's NodeIdentityCertificate (signed by the just-issued Root principal).
   * Designates this node as canonical-audit by default (operator-overridable
   * in subsequent operation; v0.1 default per §5.2).
   *
   * The returned `FirstNodeBootstrap` carries the secrets that callers MUST
   * persist into the encrypted state store (master + root principal) and zero from memory
   * after persistence.
   */
  static async bootstrapFirstNode(params: {
    fortress_id?: string;
    node_id: string;
    node_mode: NodeMode;
    root_principal_id?: string;
    transport: MeshTransport;
    approver: JoinApprover;
    key_store: NodeKeyStore;
    counters?: CounterStore;
  }): Promise<{ node: MeshNode; bootstrap: FirstNodeBootstrap }> {
    const fortressId = params.fortress_id ?? generateFortressId();

    const masterKp = generateKeypair();
    const rootPrincipalKp = generateKeypair();
    const nodeKp = generateKeypair();

    const masterPublic: FortressMasterPublicKey = {
      public_key: toBase64url(masterKp.publicKey),
      fortress_id: fortressId,
      created_at: new Date().toISOString(),
    };
    const rootPrincipalCert = issuePrincipalCertificate({
      principal_id: params.root_principal_id ?? "root",
      principal_pubkey: rootPrincipalKp.publicKey,
      role: "root",
      fortress_id: fortressId,
      master_private_key: masterKp.privateKey,
    });
    const nodeCert = issueCertificateForApprovedJoin({
      request: {
        bootstrap_token: {
          intended_node_id: params.node_id,
          intended_node_mode: params.node_mode,
          fortress_id: fortressId,
          issuing_principal: rootPrincipalCert.principal_id,
          issued_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 60_000).toISOString(),
          nonce: "self-bootstrap",
          signature_scheme: "ed25519-v1",
          signature: "self-bootstrap",
        },
        node_pubkey: toBase64url(nodeKp.publicKey),
        node_mode: params.node_mode,
        hkdf_salt_proof: "self-bootstrap",
      },
      pinned_master_pubkey: masterPublic,
      issuing_principal_cert: rootPrincipalCert,
      issuing_principal_private_key: rootPrincipalKp.privateKey,
      master_private_key: masterKp.privateKey,
    });

    const node = new MeshNode(
      {
        node_id: params.node_id,
        node_mode: params.node_mode,
        fortress_id: fortressId,
        pinned_master_pubkey: masterPublic,
        is_canonical_audit_node: true,
        system_principal_id: rootPrincipalCert.principal_id,
        heartbeat_interval_ms: DEFAULTS.HEARTBEAT_INTERVAL_MS,
        heartbeat_missed_threshold: DEFAULTS.HEARTBEAT_MISSED_THRESHOLD,
        max_offline_window_ms: DEFAULTS.MAX_OFFLINE_WINDOW_MS,
      },
      {
        transport: params.transport,
        approver: params.approver,
        key_store: params.key_store,
        counters: params.counters,
        fortress_master_secret: masterKp.privateKey,
      }
    );

    node.principalRoster.set(rootPrincipalCert.principal_id, rootPrincipalCert);
    node.roster.add(nodeCert);
    node.roster.markActive(nodeCert.node_id);
    node.lifecycleLog.append(
      // The bootstrap node's join is recorded as a system-issued node_join
      // event so a sync to a future joining node correctly conveys this
      // node's certificate. Signed by the node itself; emitter_principal is
      // the Root principal that issued the cert.
      packSignedEvent<NodeJoinPayload>({
        event_type: "node_join",
        emitter_node: nodeCert.node_id,
        emitter_principal: rootPrincipalCert.principal_id,
        fortress_id: fortressId,
        payload: {
          certificate: nodeCert,
          bootstrap_token_ref: "self-bootstrap",
        },
        monotonic_seq: node.counters.next("envelope_monotonic_seq"),
        node_private_key: nodeKp.privateKey,
        principal_private_key: rootPrincipalKp.privateKey,
      })
    );
    node.certificate = nodeCert;
    node.nodePrivateKey = nodeKp.privateKey;
    node.state = "active";

    // Wrap and persist this node's private key per Q8.
    const wrapped = wrapNodePrivateKey({
      node_private_key: nodeKp.privateKey,
      fortress_master_secret: masterKp.privateKey,
      node_id: nodeCert.node_id,
    });
    await params.key_store.save(nodeCert.node_id, wrapped);

    return {
      node,
      bootstrap: {
        master_public: masterPublic,
        master_private_key: masterKp.privateKey,
        root_principal_certificate: rootPrincipalCert,
        root_principal_private_key: rootPrincipalKp.privateKey,
        node_certificate: nodeCert,
        node_private_key: nodeKp.privateKey,
      },
    };
  }

  // ═════════════════════════════════════════════════════════════════════
  // JOIN - non-first node (§3.1)
  // ═════════════════════════════════════════════════════════════════════

  /**
   * On a node that has just been provisioned: generate keypair, store wrapped
   * key, prepare the JoinRequest. Caller hands the JoinRequest to the
   * canonical audit / console side (`acceptJoinRequest`).
   */
  async prepareJoinRequest(params: {
    bootstrap_token: BootstrapToken;
  }): Promise<JoinRequest> {
    if (this.state !== "unbooted") {
      throw new MeshError(
        `prepareJoinRequest: node is in state ${this.state}, expected unbooted`
      );
    }
    this.state = "joining";
    const kp = generateKeypair();
    this.nodePrivateKey = kp.privateKey;

    const wrapped = wrapNodePrivateKey({
      node_private_key: kp.privateKey,
      fortress_master_secret: this.fortressMasterSecret,
      node_id: this.config.node_id,
    });
    await this.keyStore.save(this.config.node_id, wrapped);

    const transportKey = deriveNodeTransportKey({
      fortress_master_secret: this.fortressMasterSecret,
      node_id: this.config.node_id,
      node_mode: this.config.node_mode,
    });
    const proof = computeJoinHkdfSaltProof({
      intended_node_id: this.config.node_id,
      node_mode: this.config.node_mode,
      node_transport_key: transportKey,
    });

    return {
      bootstrap_token: params.bootstrap_token,
      node_pubkey: toBase64url(kp.publicKey),
      node_mode: this.config.node_mode,
      hkdf_salt_proof: proof,
    };
  }

  /**
   * On the joining node: install the approved certificate returned by the
   * canonical-audit / approver side. After this call, the joining node is
   * fully provisioned and may emit signed events.
   */
  installApprovedCertificate(params: {
    certificate: NodeIdentityCertificate;
    issuing_principal_cert: PrincipalCertificate;
  }): void {
    if (this.state !== "joining") {
      throw new MeshError(
        `installApprovedCertificate: node state is ${this.state}, expected joining`
      );
    }
    if (params.certificate.node_id !== this.config.node_id) {
      throw new MeshError(
        `installApprovedCertificate: cert node_id=${params.certificate.node_id} does not match this node ${this.config.node_id}`
      );
    }
    verifyCertChain(
      params.certificate,
      params.issuing_principal_cert,
      this.config.pinned_master_pubkey
    );
    this.principalRoster.set(
      params.issuing_principal_cert.principal_id,
      params.issuing_principal_cert
    );
    this.certificate = params.certificate;
    this.roster.add(params.certificate);
    this.roster.markActive(params.certificate.node_id);
    this.state = "syncing";
  }

  /** Mark sync as complete and transition to active. */
  markSyncComplete(): void {
    if (this.state === "syncing") {
      this.state = "active";
    }
  }

  /**
   * Replace the JoinApprover after construction.
   *
   * In bootstrapFirstNode, the approver is supplied at construction time
   * but the materials it needs (principal cert + keys) are only available
   * AFTER bootstrap. Production wires its real approver here. Tests
   * likewise replace the placeholder approver after bootstrapFirstNode
   * returns the principal materials.
   */
  setApprover(approver: JoinApprover): void {
    this.approver = approver;
  }

  /**
   * On the canonical-audit / approver side: verify the bootstrap token,
   * verify the HKDF salt proof (defeats stolen-token-without-master), then
   * surface to the operator approval gate. On approve, broadcast the
   * `node_join` event with the freshly-issued certificate; on deny, return
   * the denial.
   */
  async acceptJoinRequest(request: JoinRequest): Promise<{
    approved: boolean;
    certificate?: NodeIdentityCertificate;
    denial_reason?: string;
  }> {
    const issuingPrincipal = this.principalRoster.get(
      request.bootstrap_token.issuing_principal
    );
    if (!issuingPrincipal) {
      return {
        approved: false,
        denial_reason: `unknown issuing principal ${request.bootstrap_token.issuing_principal}`,
      };
    }
    verifyBootstrapToken({
      token: request.bootstrap_token,
      expected_fortress_id: this.config.fortress_id,
      issuing_principal_cert: issuingPrincipal,
    });
    if (request.node_mode !== request.bootstrap_token.intended_node_mode) {
      return {
        approved: false,
        denial_reason: `node_mode ${request.node_mode} does not match bootstrap token intended_node_mode ${request.bootstrap_token.intended_node_mode}`,
      };
    }
    const expectedTransportKey = deriveNodeTransportKey({
      fortress_master_secret: this.fortressMasterSecret,
      node_id: request.bootstrap_token.intended_node_id,
      node_mode: request.node_mode,
    });
    const proofOk = verifyJoinHkdfSaltProof({
      intended_node_id: request.bootstrap_token.intended_node_id,
      node_mode: request.node_mode,
      node_transport_key: expectedTransportKey,
      proof: request.hkdf_salt_proof,
    });
    if (!proofOk) {
      return {
        approved: false,
        denial_reason: "hkdf_salt_proof failed - token holder lacks master-derived transport key",
      };
    }

    const result = await this.approver.requestApproval(request);
    if (!result.approved || !result.certificate) {
      return result;
    }

    // Add cert to roster, broadcast node_join.
    this.roster.add(result.certificate);
    const evt = await this.emitLifecycleEvent("node_join", {
      certificate: result.certificate,
      bootstrap_token_ref: request.bootstrap_token.nonce,
    } as NodeJoinPayload);
    this.lifecycleLog.append(evt as SignedEvent<NodeLifecyclePayload>);

    return result;
  }

  // ═════════════════════════════════════════════════════════════════════
  // BOOT FROM PERSISTED STATE - rejoin / restart (§3.5)
  // ═════════════════════════════════════════════════════════════════════

  /**
   * On a node that already has a persisted certificate + wrapped private key:
   * unwrap the key, restore in-memory state, rejoin.
   *
   * Caller supplies the prior certificate (loaded from disk in production).
   */
  async bootFromPersistedState(params: {
    certificate: NodeIdentityCertificate;
    issuing_principal_cert: PrincipalCertificate;
  }): Promise<void> {
    if (this.state !== "unbooted") {
      throw new MeshError(
        `bootFromPersistedState: node is in state ${this.state}`
      );
    }
    verifyCertChain(
      params.certificate,
      params.issuing_principal_cert,
      this.config.pinned_master_pubkey
    );
    const wrapped = await this.keyStore.load(this.config.node_id);
    if (!wrapped) {
      throw new MeshError(
        `bootFromPersistedState: no wrapped private key found for ${this.config.node_id}`
      );
    }
    const privateKey = unwrapNodePrivateKey({
      wrapped,
      fortress_master_secret: this.fortressMasterSecret,
      node_id: this.config.node_id,
    });
    this.nodePrivateKey = privateKey;
    this.certificate = params.certificate;
    this.principalRoster.set(
      params.issuing_principal_cert.principal_id,
      params.issuing_principal_cert
    );
    this.roster.add(params.certificate);
    this.roster.markActive(params.certificate.node_id);
    this.state = "active";
  }

  // ═════════════════════════════════════════════════════════════════════
  // PEER ADMISSION - observed `node_join` event from a peer
  // ═════════════════════════════════════════════════════════════════════

  /**
   * When a peer broadcasts a `node_join`, we add the new node's cert to our
   * local roster (after chain validation). Tests use this to wire two nodes
   * to know about each other when there isn't an end-to-end transport
   * delivering the broadcast.
   */
  admitPeerCertificate(params: {
    certificate: NodeIdentityCertificate;
    issuing_principal_cert: PrincipalCertificate;
  }): void {
    verifyCertChain(
      params.certificate,
      params.issuing_principal_cert,
      this.config.pinned_master_pubkey
    );
    this.principalRoster.set(
      params.issuing_principal_cert.principal_id,
      params.issuing_principal_cert
    );
    this.roster.add(params.certificate);
  }

  /**
   * Add a principal cert to the roster (e.g., for verifying bootstrap tokens
   * issued by a non-root principal).
   */
  registerPrincipal(principal: PrincipalCertificate): void {
    this.principalRoster.set(principal.principal_id, principal);
  }

  /** Pin or refresh the guardian roster used to verify guardian revokes. */
  registerGuardianRoster(roster: GuardianRoster): void {
    verifyGuardianRoster(roster, this.config.pinned_master_pubkey);
    this.guardianRoster = roster;
  }

  // ═════════════════════════════════════════════════════════════════════
  // HEARTBEAT (§3.3)
  // ═════════════════════════════════════════════════════════════════════

  async emitHeartbeat(params: {
    node_state?: HeartbeatPayload["node_state"];
    agent_count?: number;
    uptime_seconds?: number;
  } = {}): Promise<SignedEvent<HeartbeatPayload>> {
    this.requireKeyed();
    const payload: HeartbeatPayload = {
      node_state: params.node_state ?? this.advertisedState(),
      policy_version_vector: this.policyBundle.versionVector(),
      audit_seq: this.counters.peek("audit_batch_seq"),
      agent_count: params.agent_count ?? 0,
      uptime_seconds: params.uptime_seconds ?? 0,
    };
    const evt = packSignedEvent<HeartbeatPayload>({
      event_type: "heartbeat",
      emitter_node: this.config.node_id,
      emitter_principal: "system",
      fortress_id: this.config.fortress_id,
      payload,
      monotonic_seq: this.counters.next("envelope_monotonic_seq"),
      node_private_key: this.nodePrivateKey!,
    });
    this.counters.next("heartbeat_seq");
    await this.transport.broadcast(evt);
    return evt;
  }

  // ═════════════════════════════════════════════════════════════════════
  // LEAVE (§3.4)
  // ═════════════════════════════════════════════════════════════════════

  async leave(reason: NodeLeavePayload["reason"] = "graceful"): Promise<void> {
    this.requireKeyed();
    if (this.state === "left") return;
    this.state = "draining";
    const drainEvt = await this.emitLifecycleEvent("node_leave", {
      node_id: this.config.node_id,
      reason,
    } as NodeLeavePayload);
    this.lifecycleLog.append(drainEvt as SignedEvent<NodeLifecyclePayload>);
    this.roster.markLeft(this.config.node_id);
    this.state = "left";
  }

  // ═════════════════════════════════════════════════════════════════════
  // REVOKE (§3.6 + §3.6.1)
  // ═════════════════════════════════════════════════════════════════════

  /**
   * Operator-initiated revocation of a peer node. Caller MUST be authorized
   * to issue this - gated through the principal-policy gate at the console.
   * v0.1 mesh enforces the cryptographic invariants; the policy-gating
   * decision is the console thread's concern.
   *
   * Node-revoke authority invariant: a node signature only proves which node
   * emitted the envelope. The revoke authority itself MUST come from an
   * operator principal signature or a verified guardian quorum before anything
   * is broadcast to peers.
   */
  async revokePeer(params: {
    target_node_id: string;
    reason: string;
    principal_private_key?: Uint8Array;
    emitter_principal?: string;
    quorum_signatures?: NodeRevokePayload["quorum_signatures"];
    /** C12-REPLAY: the freshness context the guardians signed (quorum path). */
    quorum_context?: GuardianRevokeQuorumContext;
  }): Promise<SignedEvent<NodeRevokePayload>> {
    this.requireKeyed();
    if (!params.principal_private_key && !params.quorum_signatures?.length) {
      throw new MeshError(
        "node_revoke requires either an operator principal signature or guardian quorum signatures"
      );
    }
    const payload: NodeRevokePayload = {
      node_id: params.target_node_id,
      reason: params.reason,
      effective_at: new Date().toISOString(),
      quorum_signatures: params.quorum_signatures,
      // Present iff quorum_signatures is (presence pairing). A quorum revoke
      // without a context is the retired v1 shape and would be refused.
      quorum_context:
        params.quorum_signatures?.length && params.quorum_context
          ? {
              input_schema: "sanctuary.guardian-revoke-quorum.v2",
              ceremony_id: params.quorum_context.ceremony_id,
              initiated_at: params.quorum_context.initiated_at,
              expires_at: params.quorum_context.expires_at,
            }
          : undefined,
    };
    // Pre-broadcast guardian invariant: every quorum revoke verifies its
    // guardian signatures AND its freshness window here, with this node's own
    // clock, before emitLifecycleEvent can surface or broadcast the envelope —
    // so a compromised local ceremony whose window has lapsed cannot even emit.
    // There is no trusted-caller bypass: a ceremony that verified a quorum over
    // a broader ceremony payload has NOT obtained authorization for this
    // revocation, because that quorum never examined this node_revoke payload.
    // Callers present quorum signatures over THIS payload's input (recovery
    // flows collect them via deviceRecoveryRevokeQuorumInput), and
    // receivers independently
    // re-check node_revoke authority before any peer roster mutation.
    if (!params.principal_private_key) {
      this.assertNodeRevokePayloadQuorumAuthorized(payload, {
        mode: "strict",
        now: new Date(),
      });
    }
    const evt = await this.emitLifecycleEvent("node_revoke", payload, {
      emitter_principal: params.emitter_principal,
      principal_private_key: params.principal_private_key,
    });
    // Post-emit re-check + single admission (append + markRevoked) share the
    // ONE chokepoint every receiver uses; strict clock on this live path.
    this.admitRevoke(evt as SignedEvent<NodeRevokePayload>, {
      mode: "strict",
      now: new Date(),
    });
    return evt as SignedEvent<NodeRevokePayload>;
  }

  // ═════════════════════════════════════════════════════════════════════
  // POLICY + LOCATOR - emit (§5.1, §6.3)
  // ═════════════════════════════════════════════════════════════════════

  async publishPolicyUpdate(params: {
    payload: PolicyUpdatePayload;
    principal_private_key: Uint8Array;
    emitter_principal: string;
  }): Promise<SignedEvent<PolicyUpdatePayload>> {
    this.requireKeyed();
    const evt = packSignedEvent<PolicyUpdatePayload>({
      event_type: "policy_update",
      emitter_node: this.config.node_id,
      emitter_principal: params.emitter_principal,
      fortress_id: this.config.fortress_id,
      payload: params.payload,
      monotonic_seq: this.counters.next("envelope_monotonic_seq"),
      node_private_key: this.nodePrivateKey!,
      principal_private_key: params.principal_private_key,
    });
    const result = this.policyBundle.upsert(evt);
    this.onPolicyUpdate(evt, result);
    if (result !== "applied") {
      throw new MeshError(`policy_update rejected before publish: ${result}`);
    }
    await this.transport.broadcast(evt);
    return evt;
  }

  async publishLocatorUpdate(params: {
    payload: LocatorUpdatePayload;
    principal_private_key: Uint8Array;
    emitter_principal: string;
  }): Promise<SignedEvent<LocatorUpdatePayload>> {
    this.requireKeyed();
    this.counters.next("locator_update_seq");
    const evt = packSignedEvent<LocatorUpdatePayload>({
      event_type: "locator_update",
      emitter_node: this.config.node_id,
      emitter_principal: params.emitter_principal,
      fortress_id: this.config.fortress_id,
      payload: params.payload,
      monotonic_seq: this.counters.next("envelope_monotonic_seq"),
      node_private_key: this.nodePrivateKey!,
      principal_private_key: params.principal_private_key,
    });
    const result = this.locatorTable.upsert(evt);
    this.onLocatorUpdate(evt, result);
    await this.transport.broadcast(evt);
    return evt;
  }

  // ═════════════════════════════════════════════════════════════════════
  // AUDIT - push entry into local buffer (§5.2)
  // ═════════════════════════════════════════════════════════════════════

  pushAuditEntry(params: {
    emitter_agent: string;
    emitter_principal: string;
    policy_version: number;
    attestation_state: string;
    payload: unknown;
  }): AuditEntry {
    this.requireKeyed();
    const entry = sealAuditEntry({
      emitter_node: this.config.node_id,
      emitter_agent: params.emitter_agent,
      emitter_principal: params.emitter_principal,
      policy_version: params.policy_version,
      attestation_state: params.attestation_state,
      payload: params.payload,
      node_private_key: this.nodePrivateKey!,
    });
    if (this.oldestPendingEntryAt === null) {
      this.oldestPendingEntryAt = Date.now();
    }
    this.auditBuffer.push(entry);
    return entry;
  }

  /**
   * Force-flush the audit buffer to the canonical audit node. Production
   * wires this to a periodic timer (Follow-up #2 schedules); tests call
   * directly.
   */
  async flushAuditBuffer(canonicalAuditNodeId: string): Promise<void> {
    this.requireKeyed();
    const auditChainKey = deriveNodeAuditChainKey({
      fortress_master_secret: this.fortressMasterSecret,
      node_id: this.config.node_id,
    });
    const flushed = this.auditBuffer.flush({
      emitter_node: this.config.node_id,
      counters: this.counters,
      node_audit_chain_key: auditChainKey,
      node_private_key: this.nodePrivateKey!,
    });
    if (!flushed) return;
    this.oldestPendingEntryAt = null;
    this.onAuditBatchEmitted({
      batch_seq: flushed.flushed.batch_seq,
      entry_count: flushed.flushed.entry_count,
    });
    await this.transport.unicast(
      canonicalAuditNodeId,
      JSON.stringify({ kind: "audit_batch", batch: flushed.batch })
    );
  }

  /**
   * Canonical-audit-node side: receive + verify a batch, append to the log.
   * Throws on rollback or chain discontinuity (§8.3 alarms).
   */
  ingestAuditBatch(message: string): void {
    if (!this.canonicalAudit) {
      throw new MeshError(
        `ingestAuditBatch: ${this.config.node_id} is not the canonical audit node`
      );
    }
    const parsed = JSON.parse(message) as { kind: string; batch: import("../types.js").AuditBatch };
    if (parsed.kind !== "audit_batch") {
      throw new MeshError(`ingestAuditBatch: unknown unicast kind ${parsed.kind}`);
    }
    const auditChainKey = deriveNodeAuditChainKey({
      fortress_master_secret: this.fortressMasterSecret,
      node_id: parsed.batch.emitter_node,
    });
    receiveAuditBatch(parsed.batch, {
      pinnedMasterPubkey: this.config.pinned_master_pubkey,
      lookupNodeCert: (id) => this.roster.lookupActiveNodeCert(id),
      lookupPrincipalCert: (id) => this.principalRoster.get(id),
      lookupAuditChainKey: () => auditChainKey,
      lookupPreviousBatch: (id) =>
        this.canonicalAudit!.lookupPreviousBatch(id),
    });
    this.canonicalAudit.append(parsed.batch);
  }

  // ═════════════════════════════════════════════════════════════════════
  // SYNC (§3.2 + §3.5)
  // ═════════════════════════════════════════════════════════════════════

  async requestSyncFromPeer(params: {
    peer_node_id: string;
    kind: "initial_sync" | "delta_sync" | "agent_state_transfer";
  }): Promise<void> {
    this.requireKeyed();
    // Mint a fresh correlation id and record it as outstanding. Only a
    // sync_response echoing this id (before it expires) will be applied, and the
    // match consumes it — the initiator owns retry with a FRESH id (§3.3 pt 7).
    const requestId = this.mintSyncRequestId();
    this.registerOutstandingSyncRequest(requestId);
    const payload: SyncRequestPayload = {
      kind: params.kind,
      request_id: requestId,
      since_policy_versions: this.policyBundle.versionVector(),
      since_locator_version: this.locatorTable.highest(),
      since_audit_seqs: {},
    };
    const evt = packSignedEvent<SyncRequestPayload>({
      event_type: "sync_request",
      emitter_node: this.config.node_id,
      emitter_principal: this.config.system_principal_id ?? "system",
      fortress_id: this.config.fortress_id,
      payload,
      monotonic_seq: this.counters.next("envelope_monotonic_seq"),
      node_private_key: this.nodePrivateKey!,
    });
    await this.transport.unicast(
      params.peer_node_id,
      JSON.stringify({ kind: "sync_request", evt })
    );
  }

  /**
   * Server-side sync handler. Returns a (synchronous) response payload that
   * the caller broadcasts back via unicast. Pure function over the local
   * stores - the transport layer wires the round-trip.
   */
  handleSyncRequest(payload: SyncRequestPayload): SyncResponsePayload {
    return buildSyncResponse(payload, {
      policy_bundle: this.policyBundle,
      locator_table: this.locatorTable,
      lifecycle_log: this.lifecycleLog,
      audit_log: this.canonicalAudit,
    });
  }

  /**
   * Apply a sync response received from a peer.
   *
   * SYNC-APPEND-01 (design §3.3): the ordering invariant is that parse,
   * freshness, verification, and authorization ALL complete BEFORE any
   * `lifecycleLog.append` — a refused event must never be persisted, because
   * anything appended here is re-served to every future sync consumer by
   * handleSyncRequest, and appending garbage would turn the attacker's dead
   * bytes into a self-propagating relay through honest nodes. And each event is
   * isolated: one malformed or refused event is dropped-and-audited and the loop
   * CONTINUES, so it never costs the legitimate revokes behind it in the same
   * response batch.
   */
  async applySync(
    payload: SyncResponsePayload,
    now: Date = new Date()
  ): Promise<void> {
    // Verify policy/locator events up front (they are applied by
    // applySyncResponse). TRUTHFUL SCOPE: a throw here aborts the WHOLE
    // response — the lifecycle loop below is never reached, so one poison
    // policy_update or locator_update costs this response's lifecycle events
    // too (and the correlation id was already consumed, so the initiator must
    // retry with a fresh sync_request). The per-event isolation below governs
    // only the lifecycle loop. Pre-existing shape; tracked as register row
    // C12-SYNC-ORDER-01 (fix shape: per-table isolation or verify-after-
    // lifecycle).
    for (const evt of payload.policy_updates ?? []) {
      this.verifyOrThrow(evt);
    }
    for (const evt of payload.locator_updates ?? []) {
      this.verifyOrThrow(evt);
    }
    for (const evt of payload.node_lifecycle_events ?? []) {
      try {
        if (evt.event_type === "node_join") {
          const join = this.verifyNodeJoinBeforeRosterMutation(
            evt as SignedEvent<NodeJoinPayload>
          );
          this.roster.add(join.payload.certificate);
          this.lifecycleLog.append(evt);
        } else if (evt.event_type === "node_revoke") {
          this.verifyOrThrow(evt);
          // sync_anchored is the ONLY place this mode is passed (T9 pins it):
          // a committed revoke must outlive its collection window for a late
          // joiner, so freshness anchors to the emitter-stamped effective_at.
          const rev = evt as SignedEvent<NodeRevokePayload>;
          const outcome = this.admitRevoke(rev, {
            mode: "sync_anchored",
            now,
            effective_at: rev.payload.effective_at,
          });
          // S2 detectability (design §3.2/§5-F9): an admission the strict
          // clock would have refused (now past expires_at) is the sync-only
          // laundering channel the S2 residual concedes, so it is NEVER
          // silent — distinct sealed audit entry + distinct operator-visible
          // lifecycle marker, at this admission site. Fires only on a REAL
          // admission (state change), not on an idempotent same-authorization
          // drop, so a replay flood of an already-admitted event cannot use
          // this entry as an ungoverned write amplifier.
          if (outcome === "admitted") {
            this.recordSyncOutOfWindowAdmission(rev, now);
          }
        } else if (evt.event_type === "node_leave") {
          this.verifyOrThrow(evt);
          this.lifecycleLog.append(evt);
          this.roster.markLeft(
            (evt as SignedEvent<NodeLeavePayload>).payload.node_id
          );
        } else {
          this.verifyOrThrow(evt);
          this.lifecycleLog.append(evt);
        }
      } catch (e) {
        // Per-event isolation (§3.3 point 6): drop and audit, never abort the
        // batch. A refused event is NOT appended, so it is never re-served.
        const error = e instanceof Error ? e : new Error(String(e));
        if (evt.event_type === "node_revoke") {
          this.auditNodeRevokeDenied(
            evt as SignedEvent<NodeRevokePayload>,
            error,
            now
          );
        }
        this.onEnvelopeRejected({
          error,
          event_type: evt.event_type,
          emitter_node: evt.emitter_node,
        });
        continue;
      }
    }
    // Policy + locator tables only — lifecycle events already appended above by
    // the SINGLE append site, so pass an empty lifecycle list (no double-append).
    const result = applySyncResponse(
      { ...payload, node_lifecycle_events: [] },
      {
        policy_bundle: this.policyBundle,
        locator_table: this.locatorTable,
        lifecycle_log: this.lifecycleLog,
        audit_log: this.canonicalAudit,
        on_policy_update: (evt, updateResult) =>
          this.onPolicyUpdate(evt, updateResult),
      }
    );
    void result; // observability hooks left for Follow-up #3
  }

  /**
   * The single admission point for a verified revoke (the receive router,
   * applySync, and revokePeer's post-emit re-check all funnel here). Asserts
   * authority + freshness, then applies the authorization-keyed dedupe bound to
   * roster state (SYNC-APPEND-01 §3.3 point 4, re-gate RG3-1):
   *
   *   - a same-authorization revoke of a target that is CURRENTLY REVOKED is a
   *     true replay of the standing state: idempotent at the roster, DROPPED at
   *     the log (never replace-in-place — the retained entry keeps its original
   *     order so late joiners replay what live nodes saw);
   *   - a same-authorization revoke of a target that is NOT currently revoked
   *     (it was re-admitted after the authorization's ceremony) is REFUSED
   *     loudly (throws into the caller's denial path): a quorum context
   *     authorizes at most one revocation epoch of its target, and the
   *     authorization dies when the target is re-admitted. Accepting-and-
   *     dropping it would mutate the roster with no retained log witness, so
   *     late joiners would diverge and fail open.
   *
   * Throws on any auth/freshness/re-admission failure; the caller audits.
   * Returns whether state changed ("admitted") or the event was an idempotent
   * same-authorization drop, so the sync site can scope its S2 detectability
   * entry to real admissions.
   */
  private admitRevoke(
    rev: SignedEvent<NodeRevokePayload>,
    freshness: FreshnessMode
  ): "admitted" | "idempotent_drop" {
    this.assertNodeRevokeAuthorized(rev, freshness);
    const target = rev.payload.node_id;
    const authKey = this.revokeAuthorizationKey(rev);
    if (this.lifecycleLog.hasRetainedRevokeAuthorization(authKey)) {
      if (this.roster.presenceOf(target) === "revoked") {
        // Idempotent true replay — roster already revoked, drop from the log.
        return "idempotent_drop";
      }
      throw new MeshError(
        "node_revoke denied: authorization does not survive re-admission of its target"
      );
    }
    this.lifecycleLog.appendRevoke(rev as SignedEvent<NodeLifecyclePayload>, {
      target_node_id: target,
      authorization_key: authKey,
    });
    this.roster.markRevoked(target);
    return "admitted";
  }

  /**
   * S2 detectability (design §3.2/§5-F9): when a quorum revoke is admitted via
   * the sync_anchored channel at a moment the strict clock would have refused
   * (this node's `now` is past the context's `expires_at`), seal the DISTINCT
   * audit entry `node_revoke_admitted_via_sync_out_of_window` and fire the
   * distinct `onLifecycleEvent` marker. This is the operator-visible half of
   * the S2 residual: the out-of-window sync admission is legitimate for a late
   * joiner AND is the one laundering channel the design concedes, so it must
   * never be silent. In-window sync admissions and every live-path admission
   * emit nothing here. Principal-signed revokes carry no context and are out
   * of S2's scope.
   */
  private recordSyncOutOfWindowAdmission(
    rev: SignedEvent<NodeRevokePayload>,
    now: Date
  ): void {
    const wireContext = rev.payload.quorum_context;
    if (!wireContext) return;
    const parsed = parseGuardianRevokeQuorumContext(wireContext);
    // The admission already re-parsed and verified this context; a parse
    // failure here is unreachable, and detectability must not invent one.
    if (!parsed.ok) return;
    if (now.getTime() <= parsed.context.expires_at_ms) return;
    if (this.nodePrivateKey) {
      const entry = sealAuditEntry({
        emitter_node: this.config.node_id,
        emitter_agent: "mesh",
        emitter_principal: this.config.system_principal_id ?? "system",
        policy_version: 0,
        attestation_state: "present",
        payload: {
          operation: "node_revoke_admitted_via_sync_out_of_window",
          peer_node: rev.emitter_node,
          target_node: rev.payload.node_id,
          ceremony_id: parsed.context.ceremony_id,
          effective_at: rev.payload.effective_at,
          expires_at: wireContext.expires_at,
        },
        node_private_key: this.nodePrivateKey,
      });
      if (this.oldestPendingEntryAt === null) {
        this.oldestPendingEntryAt = Date.now();
      }
      this.auditBuffer.push(entry);
    }
    this.onLifecycleEvent(
      rev as SignedEvent<NodeLifecyclePayload>,
      "sync_admitted_out_of_window"
    );
  }

  /**
   * Compute the authorization dedupe key for a verified revoke. NEVER keys on
   * `event_id` (attacker-chosen inside the signed body): keys on the ceremony_id
   * for quorum revokes and on sha256(DECODED principal-signature bytes) for
   * principal revokes — the artifact the attacker cannot mint fresh.
   */
  private revokeAuthorizationKey(
    rev: SignedEvent<NodeRevokePayload>
  ): string {
    if (rev.principal_signature) {
      // Decode the base64url wire string to raw bytes BEFORE hashing, so an
      // encoding-variant duplicate cannot re-enter through a lenient decoder.
      return computeRevokeAuthorizationKey({
        target_node_id: rev.payload.node_id,
        principal_signature_bytes: fromBase64url(rev.principal_signature),
      });
    }
    const ceremonyId = rev.payload.quorum_context?.ceremony_id;
    if (ceremonyId === undefined) {
      // Should be unreachable: assertNodeRevokeAuthorized has already required
      // a context on the quorum path. Fail closed rather than key on nothing.
      throw new MeshError(
        "node_revoke authorization key: quorum revoke missing ceremony_id"
      );
    }
    return computeRevokeAuthorizationKey({
      target_node_id: rev.payload.node_id,
      ceremony_id: ceremonyId,
    });
  }

  // ═════════════════════════════════════════════════════════════════════
  // OPERATOR-FACING UTILITIES
  // ═════════════════════════════════════════════════════════════════════

  /** Issue a bootstrap token authorizing a new node to request membership. */
  issueBootstrapToken(params: {
    intended_node_id: string;
    intended_node_mode: NodeMode;
    issuing_principal: string;
    principal_private_key: Uint8Array;
    ttl_ms?: number;
  }): BootstrapToken {
    return issueBootstrapToken({
      intended_node_id: params.intended_node_id,
      intended_node_mode: params.intended_node_mode,
      fortress_id: this.config.fortress_id,
      issuing_principal: params.issuing_principal,
      principal_private_key: params.principal_private_key,
      ttl_ms: params.ttl_ms,
    });
  }

  /**
   * Apply a master-rotation cascade locally (§9.4 + §9.5).
   *
   * Caller (the failure-mode detector + ceremony orchestrator) constructs the
   * inputs by calling `acceptMasterRotation` (verifies guardian quorum) and
   * `rekeyOnMasterRotation` (re-issues per-node certs + re-derives per-node
   * subkeys under the new master). This method installs the result on this
   * node and emits the audit-continuity boundary entry.
   *
   * NOT a wire-level message - this is the local cascade hook that the
   * `master_rotation` SignedEvent dispatch path calls into. Idempotent on
   * (rotated_at, new_master_pubkey): if the rotation has already been applied,
   * subsequent calls return without effect.
   *
   * Spec: §9.4 (cascade implications), §9.5 (audit continuity boundary).
   */
  installMasterRotation(params: {
    payload: import("../types.js").MasterRotationPayload;
    new_master_secret: Uint8Array;
    re_issued_self_cert: NodeIdentityCertificate;
    new_root_principal_cert: PrincipalCertificate;
  }): { boundary_entry: AuditEntry } {
    const { payload, new_master_secret, re_issued_self_cert, new_root_principal_cert } = params;
    if (
      payload.new_master_pubkey.public_key === this.config.pinned_master_pubkey.public_key
    ) {
      // Already installed - idempotent return.
      const noop = sealAuditEntry({
        emitter_node: this.config.node_id,
        emitter_agent: "system",
        emitter_principal: this.config.system_principal_id ?? "system",
        policy_version: 0,
        attestation_state: "present",
        payload: { kind: "master_rotation_boundary_noop", rotated_at: payload.rotated_at },
        node_private_key: this.nodePrivateKey!,
      });
      return { boundary_entry: noop };
    }
    if (re_issued_self_cert.node_id !== this.config.node_id) {
      throw new MeshError(
        `installMasterRotation: re_issued_self_cert.node_id=${re_issued_self_cert.node_id} does not match this node ${this.config.node_id}`
      );
    }
    if (
      re_issued_self_cert.parent_chain.fortress_master_pubkey !==
      payload.new_master_pubkey.public_key
    ) {
      throw new MeshError(
        `installMasterRotation: re_issued_self_cert does not chain to the new master pubkey`
      );
    }
    // Swap the in-memory master secret + pinned pubkey + principal cert + own cert.
    this.fortressMasterSecret = new_master_secret;
    this.config = {
      ...this.config,
      pinned_master_pubkey: payload.new_master_pubkey,
    };
    this.principalRoster.set(
      new_root_principal_cert.principal_id,
      new_root_principal_cert
    );
    this.certificate = re_issued_self_cert;
    // Replace own roster cert (keeps presence + heartbeat history intact -
    // see NodeRoster.add cert-rotation path).
    this.roster.add(re_issued_self_cert);

    // Audit-continuity boundary entry - the operator-visible record of the
    // rotation. Verifiers walking the audit log encounter this and pivot from
    // pre-rotation pubkey lookups to post-rotation lookups.
    const boundaryPayload = {
      kind: "master_rotation_boundary" as const,
      old_master_pubkey: payload.old_master_pubkey,
      new_master_pubkey: payload.new_master_pubkey.public_key,
      guardian_quorum_signatures: payload.quorum_signatures,
      rotated_at: payload.rotated_at,
    };
    const entry = sealAuditEntry({
      emitter_node: this.config.node_id,
      emitter_agent: "system",
      emitter_principal: this.config.system_principal_id ?? "system",
      policy_version: 0,
      attestation_state: "present",
      payload: boundaryPayload,
      node_private_key: this.nodePrivateKey!,
    });
    if (this.oldestPendingEntryAt === null) {
      this.oldestPendingEntryAt = Date.now();
    }
    this.auditBuffer.push(entry);
    return { boundary_entry: entry };
  }

  /**
   * Read this node's currently-pinned fortress-master public key.
   * Used by the failure-mode detector for diagnostic surfaces.
   */
  getPinnedMaster(): FortressMasterPublicKey {
    return this.config.pinned_master_pubkey;
  }

  /**
   * Read this node's current certificate (after any rotations applied).
   * Used by tests + the cascade orchestrator to verify post-rotation state.
   */
  getOwnCertificate(): NodeIdentityCertificate | null {
    return this.certificate;
  }

  /** Designate a new canonical audit node (§5.4 replica election). */
  async designateCanonicalAudit(params: {
    new_canonical_node: string;
    principal_private_key: Uint8Array;
    emitter_principal: string;
  }): Promise<SignedEvent<CanonicalAuditChangePayload>> {
    this.requireKeyed();
    const payload: CanonicalAuditChangePayload = {
      new_canonical_node: params.new_canonical_node,
      previous_canonical_node: this.config.is_canonical_audit_node
        ? this.config.node_id
        : undefined,
    };
    const evt = packSignedEvent<CanonicalAuditChangePayload>({
      event_type: "canonical_audit_change",
      emitter_node: this.config.node_id,
      emitter_principal: params.emitter_principal,
      fortress_id: this.config.fortress_id,
      payload,
      monotonic_seq: this.counters.next("envelope_monotonic_seq"),
      node_private_key: this.nodePrivateKey!,
      principal_private_key: params.principal_private_key,
    });
    await this.transport.broadcast(evt);
    return evt;
  }

  // ═════════════════════════════════════════════════════════════════════
  // INTROSPECTION
  // ═════════════════════════════════════════════════════════════════════

  snapshot(): MeshNodeSnapshot {
    return {
      node_id: this.config.node_id,
      state: this.state,
      is_canonical_audit: !!this.canonicalAudit,
      roster_size: this.roster.size(),
      counters: {
        envelope_monotonic_seq: this.counters.peek("envelope_monotonic_seq"),
        heartbeat_seq: this.counters.peek("heartbeat_seq"),
        audit_batch_seq: this.counters.peek("audit_batch_seq"),
        locator_update_seq: this.counters.peek("locator_update_seq"),
      },
      pending_audit_entries: this.auditBuffer.size(),
      cert_present: this.certificate !== null,
    };
  }

  getRoster(): NodeRoster {
    return this.roster;
  }

  getPolicyBundle(): PolicyBundleStore {
    return this.policyBundle;
  }

  getLocatorTable(): LocatorTableStore {
    return this.locatorTable;
  }

  /**
   * Read-only view of the audit entries buffered but not yet flushed to the
   * canonical audit node. Diagnostic/test surface: lets an operator console or
   * a wired-consumer test assert WHICH entries are pending (e.g. the S2
   * out-of-window admission entry or a governor saturation summary), not just
   * how many. Never mutates the buffer.
   */
  peekPendingAuditEntries(): readonly AuditEntry[] {
    return this.auditBuffer.peekPending();
  }

  getLifecycleLog(): NodeLifecycleEventLog {
    return this.lifecycleLog;
  }

  getReceivedLog(): readonly ReceivedEventLog[] {
    return this.receivedLog;
  }

  getCanonicalAuditLog(): CanonicalAuditLog | undefined {
    return this.canonicalAudit;
  }

  /** Canonical audit log size on the canonical node (0 elsewhere). */
  getCanonicalAuditSize(): number {
    return this.canonicalAudit?.size() ?? 0;
  }

  // ═════════════════════════════════════════════════════════════════════
  // INTERNALS
  // ═════════════════════════════════════════════════════════════════════

  private requireKeyed(): void {
    if (!this.nodePrivateKey || !this.certificate) {
      throw new MeshError(
        `node ${this.config.node_id} has no in-memory private key - call bootstrapFirstNode / prepareJoinRequest+approve / bootFromPersistedState first`
      );
    }
  }

  private advertisedState(): HeartbeatPayload["node_state"] {
    if (this.state === "draining") return "draining";
    return "active";
  }

  private async emitLifecycleEvent(
    eventType:
      | "node_join"
      | "node_leave"
      | "node_revoke"
      | "node_attestation_refresh"
      | "canonical_audit_change"
      | "master_rotation",
    payload: NodeLifecyclePayload,
    auth: {
      principal_private_key?: Uint8Array;
      emitter_principal?: string;
    } = {}
  ): Promise<SignedEvent<NodeLifecyclePayload>> {
    const evt = packSignedEvent<NodeLifecyclePayload>({
      event_type: eventType,
      emitter_node: this.config.node_id,
      emitter_principal:
        auth.emitter_principal ?? this.config.system_principal_id ?? "system",
      fortress_id: this.config.fortress_id,
      payload,
      monotonic_seq: this.counters.next("envelope_monotonic_seq"),
      node_private_key: this.nodePrivateKey!,
      principal_private_key: auth.principal_private_key,
    });
    this.onLifecycleEvent(evt, "emitted");
    await this.transport.broadcast(evt);
    return evt;
  }

  private registerCoreHandlers(): void {
    this.router.register("heartbeat", (evt) => {
      const payload = evt.payload as HeartbeatPayload;
      this.roster.recordHeartbeat({
        node_id: evt.emitter_node,
        at_ms: Date.now(),
        policy_versions: payload.policy_version_vector,
        audit_seq: payload.audit_seq,
        advertised_state: payload.node_state,
      });
      this.onHeartbeatReceived({
        emitter_node: evt.emitter_node,
        monotonic_seq: evt.monotonic_seq,
        policy_version_vector: payload.policy_version_vector,
        audit_seq: payload.audit_seq,
        advertised_state: payload.node_state,
      });
    });
    this.router.register("policy_update", (evt) => {
      const result = this.policyBundle.upsert(
        evt as SignedEvent<PolicyUpdatePayload>
      );
      this.onPolicyUpdate(evt as SignedEvent<PolicyUpdatePayload>, result);
    });
    this.router.register("locator_update", (evt) => {
      const result = this.locatorTable.upsert(
        evt as SignedEvent<LocatorUpdatePayload>
      );
      this.onLocatorUpdate(evt as SignedEvent<LocatorUpdatePayload>, result);
    });
    this.router.register("node_join", (evt) => {
      const join = evt as SignedEvent<NodeJoinPayload>;
      this.roster.add(join.payload.certificate);
      this.lifecycleLog.append(join as SignedEvent<NodeLifecyclePayload>);
      this.onLifecycleEvent(join as SignedEvent<NodeLifecyclePayload>, "received");
    });
    this.router.register("node_leave", (evt) => {
      const lv = evt as SignedEvent<NodeLeavePayload>;
      this.roster.markLeft(lv.payload.node_id);
      this.lifecycleLog.append(lv as SignedEvent<NodeLifecyclePayload>);
      this.onLifecycleEvent(lv as SignedEvent<NodeLifecyclePayload>, "received");
    });
    this.router.register("node_revoke", (evt) => {
      const rev = evt as SignedEvent<NodeRevokePayload>;
      try {
        // Live receive path — strict clock (this node's own). admitRevoke
        // asserts authority + freshness, applies the authorization-keyed dedupe
        // bound to roster state, then appends (once) + markRevoked.
        this.admitRevoke(rev, { mode: "strict", now: new Date() });
      } catch (e) {
        const error = e instanceof Error ? e : new Error(String(e));
        this.auditNodeRevokeDenied(rev, error);
        this.onEnvelopeRejected({
          error,
          event_type: rev.event_type,
          emitter_node: rev.emitter_node,
        });
        return;
      }
      this.onLifecycleEvent(rev as SignedEvent<NodeLifecyclePayload>, "received");
    });
    this.router.register("canonical_audit_change", (evt) => {
      this.lifecycleLog.append(evt as SignedEvent<NodeLifecyclePayload>);
      this.onLifecycleEvent(evt as SignedEvent<NodeLifecyclePayload>, "received");
    });
    this.router.register("master_rotation", (evt) => {
      this.lifecycleLog.append(evt as SignedEvent<NodeLifecyclePayload>);
      this.onLifecycleEvent(evt as SignedEvent<NodeLifecyclePayload>, "received");
    });
    this.router.register("node_attestation_refresh", (evt) => {
      this.lifecycleLog.append(evt as SignedEvent<NodeLifecyclePayload>);
      this.onLifecycleEvent(evt as SignedEvent<NodeLifecyclePayload>, "received");
    });
  }

  private async handleIncomingBroadcast(evt: SignedEvent): Promise<void> {
    // Bootstrap case: a `node_join` event carries the joining node's cert
    // in its payload. The cert MUST be added to the local roster (after
    // chain validation) before envelope verification, because envelope
    // verification looks the emitter cert up in the roster.
    if (evt.event_type === "node_join") {
      try {
        const join = this.verifyNodeJoinBeforeRosterMutation(
          evt as SignedEvent<NodeJoinPayload>
        );
        this.roster.add(join.payload.certificate);
      } catch {
        return;
      }
    }
    // Forward-compat: a v1.x extension event reaching v0.1. Verification will
    // either fail (cross-operator isolation) or pass with unknown extension
    // keys; the router drops at dispatch.
    try {
      this.verifyOrThrow(evt);
      this.enforceReceivedMonotonicSeq(evt);
    } catch (e) {
      this.auditPeerProtocolViolation({
        error: e instanceof Error ? e : new Error(String(e)),
        event_type: evt.event_type,
        emitter_node: evt.emitter_node,
      });
      this.onEnvelopeRejected({
        error: e instanceof Error ? e : new Error(String(e)),
        event_type: evt.event_type,
        emitter_node: evt.emitter_node,
      });
      return;
    }
    this.receivedLog.push({
      event_type: evt.event_type,
      emitter_node: evt.emitter_node,
      emitter_principal: evt.emitter_principal,
      monotonic_seq: evt.monotonic_seq,
      event_id: evt.event_id,
      at: Date.now(),
    });
    this.router.dispatch(evt);
  }

  private enforceReceivedMonotonicSeq(evt: SignedEvent): void {
    const last = this.lastReceivedMonotonicSeq.get(evt.emitter_node);
    if (last !== undefined && evt.monotonic_seq <= last) {
      throw new MeshRollbackDetectedError(
        evt.emitter_node,
        `non-monotonic envelope monotonic_seq (got ${evt.monotonic_seq}, last seen ${last})`
      );
    }
    this.lastReceivedMonotonicSeq.set(evt.emitter_node, evt.monotonic_seq);
  }

  private assertNodeRevokeAuthorized(
    evt: SignedEvent<NodeRevokePayload>,
    freshness: FreshnessMode
  ): void {
    // Presence pairing (design §2.1 / review F-10), enforced at all sites: no
    // dead attacker-controlled field may ride a verified event. An orphan
    // context (context present, signatures absent) is rejected loudly rather
    // than ignored, even on a principal-signed revoke.
    if (evt.payload.quorum_context && !evt.payload.quorum_signatures?.length) {
      throw new MeshError(
        "node_revoke denied: quorum_context present without quorum_signatures (orphan context rejected)"
      );
    }
    // Receive-path invariant: verifyOrThrow already validated peer envelopes,
    // and local emit paths use packSignedEvent. A principal signature therefore
    // carries revoke authority; otherwise reduce to the same guardian quorum
    // proof (and freshness window) used by the pre-broadcast direct path.
    if (evt.principal_signature) {
      return;
    }

    this.assertNodeRevokePayloadQuorumAuthorized(evt.payload, freshness);
  }

  private assertNodeRevokePayloadQuorumAuthorized(
    payload: NodeRevokePayload,
    freshness: FreshnessMode
  ): void {
    const quorumSignatures = payload.quorum_signatures ?? [];
    if (quorumSignatures.length === 0) {
      throw new MeshError(
        "node_revoke denied: missing operator principal signature or guardian quorum"
      );
    }
    // M1 clean break (design §4): a quorum revoke with NO context is exactly the
    // retired v1 unbounded-lifetime shape. Refuse it with a version-
    // distinguishing internal reason so a skewed-fleet operator can tell version
    // skew from clock skew. Never softened — accepting v1 bytes accepts the very
    // bearer capability this design exists to kill.
    if (!payload.quorum_context) {
      throw new MeshError(
        "node_revoke denied: v1-shape quorum revoke (no v2 freshness context) refused under M1 clean break"
      );
    }
    if (!this.guardianRoster) {
      throw new MeshError(
        "node_revoke denied: guardian quorum present but no pinned guardian roster is installed"
      );
    }

    // Element-level parse (rules 5/11): a malformed context fails closed HERE
    // with a typed reason, never as a downstream TypeError.
    const parsed = parseGuardianRevokeQuorumContext(payload.quorum_context);
    if (!parsed.ok) {
      throw new MeshError(
        `node_revoke denied: malformed quorum context (${parsed.reason})`
      );
    }
    // Relying-side freshness (rule 10) with THIS site's own clock — hard fail,
    // never a warning. strict on every live path; sync_anchored only in applySync.
    assertQuorumContextFresh(parsed.context, freshness);

    const signatures = quorumSignatures.map((sig) => {
      const guardian = this.guardianRoster!.guardians.find(
        (g) => g.public_key === sig.guardian_pubkey
      );
      if (!guardian) {
        throw new MeshError(
          `node_revoke denied: unknown guardian pubkey ${sig.guardian_pubkey}`
        );
      }
      return {
        guardian_id: guardian.guardian_id,
        signature: sig.signature,
      };
    });
    const proof: GuardianQuorumProof = {
      roster_version: this.guardianRoster.version,
      signatures,
    };
    // The ONE shared builder recomputes the canonical bytes from the payload's
    // echoed context + target + reason + fortress_id. No hand-mirror to drift
    // (the retired nodeRevokeQuorumInput copy was deleted with its pin comment).
    verifyGuardianQuorum({
      input: buildGuardianRevokeQuorumInput({
        context: {
          ceremony_id: parsed.context.ceremony_id,
          initiated_at: parsed.context.initiated_at,
          expires_at: parsed.context.expires_at,
        },
        target_node_id: payload.node_id,
        reason: payload.reason,
        fortress_id: this.config.fortress_id,
      }),
      proof,
      pinned_roster: this.guardianRoster,
    });
  }

  private auditNodeRevokeDenied(
    evt: SignedEvent<NodeRevokePayload>,
    error: Error,
    now: Date = new Date()
  ): void {
    if (!this.nodePrivateKey) {
      return;
    }
    // Audit-write governance is FORENSIC-ONLY: the deny decision was already
    // made and applied by the caller; this only decides whether to WRITE the
    // individual denial entry, and never affects accept/deny (invariant, §2.5).
    const decision = this.denialAuditGovernor.consider(
      evt.emitter_node,
      now.getTime()
    );
    if (decision.saturationSummary) {
      // A prior interval's suppressions are summarized once here — a sealed
      // summary that degrades attribution granularity under flood but never
      // erases how many denials or how many distinct authentic emitters.
      this.pushDenialSaturationSummary(decision.saturationSummary);
    }
    if (!decision.writeIndividual) {
      return;
    }
    const entry = sealAuditEntry({
      emitter_node: this.config.node_id,
      emitter_agent: "mesh",
      emitter_principal: this.config.system_principal_id ?? "system",
      policy_version: 0,
      attestation_state: "peer_protocol_violation",
      payload: {
        operation: "node_revoke_denied",
        event_type: evt.event_type,
        peer_node: evt.emitter_node,
        target_node: evt.payload.node_id,
        reason: error.message,
      },
      node_private_key: this.nodePrivateKey,
    });
    if (this.oldestPendingEntryAt === null) {
      this.oldestPendingEntryAt = Date.now();
    }
    this.auditBuffer.push(entry);
  }

  /**
   * Flush any pending audit-governor saturation summaries (revoke denials AND
   * uncorrelated sync_response refusals) without waiting for their windows to
   * roll. Production wiring: `FailureModeDetector.tick()` calls this on every
   * periodic tick (MeshNode owns no timer of its own; the detector's interval
   * is the mesh's periodic tick). Tests may also call it directly.
   */
  flushRevokeDenialSaturation(): void {
    const summary = this.denialAuditGovernor.flushSaturationSummary();
    if (summary) this.pushDenialSaturationSummary(summary);
    const syncSummary =
      this.uncorrelatedSyncAuditGovernor.flushSaturationSummary();
    if (syncSummary) {
      this.pushUncorrelatedSyncSaturationSummary(syncSummary);
    }
    // Third governor drains through the SAME production tick as its two
    // siblings (QI-SIBLING-02 fix round). A governor whose summary only lands
    // on the next `consider()` call would let an attacker who floods and then
    // STOPS strand the suppressed-count until the next refusal, which is the
    // "saturation never blinds forensics" invariant failing quietly.
    const rotationSummary =
      this.masterRotationDenialAuditGovernor.flushSaturationSummary();
    if (rotationSummary) {
      this.pushMasterRotationDenialSaturationSummary(rotationSummary);
    }
  }

  private pushDenialSaturationSummary(summary: {
    suppressed_count: number;
    distinct_emitter_count: number;
  }): void {
    if (!this.nodePrivateKey) return;
    const entry = sealAuditEntry({
      emitter_node: this.config.node_id,
      emitter_agent: "mesh",
      emitter_principal: this.config.system_principal_id ?? "system",
      policy_version: 0,
      attestation_state: "peer_protocol_violation",
      payload: {
        operation: "node_revoke_denied_saturation_summary",
        suppressed_count: summary.suppressed_count,
        distinct_emitter_count: summary.distinct_emitter_count,
      },
      node_private_key: this.nodePrivateKey,
    });
    if (this.oldestPendingEntryAt === null) {
      this.oldestPendingEntryAt = Date.now();
    }
    this.auditBuffer.push(entry);
  }

  /**
   * Record a REFUSED `master_rotation` broadcast (QI-SIBLING-02 fix round).
   *
   * Called by `MasterRotationReceiver` when the relying-side window, the
   * quorum, or the receiver's own bounded pending map refuses a broadcast, so
   * an operator can tell a node that REFUSED a rotation from one that never
   * received the broadcast. Before this existed the refusal path was silent
   * except for a thrown promise the reference wiring discarded with `void`.
   *
   * `emitter_node` MUST be the AUTHENTICATED emitter — the `emitter_node` of a
   * SignedEvent that already passed `verifyOrThrow` on the receive path, never
   * a string lifted from the payload. Keying a per-origin budget on an
   * attacker-supplied field would let one peer exhaust every other peer's
   * bucket, which is the live defect class this repo already carries a rule for.
   *
   * Write-governed (rule 8) for the same reason as its two siblings: the
   * refusal DECISION happened in the caller and is unaffected by suppression;
   * this governs only whether the individual entry is written.
   */
  auditMasterRotationDenied(params: {
    emitter_node: string;
    rotated_at: string;
    error: Error;
    now?: Date;
  }): void {
    if (!this.nodePrivateKey) return;
    const decision = this.masterRotationDenialAuditGovernor.consider(
      params.emitter_node,
      (params.now ?? new Date()).getTime()
    );
    if (decision.saturationSummary) {
      this.pushMasterRotationDenialSaturationSummary(decision.saturationSummary);
    }
    if (!decision.writeIndividual) return;
    const entry = sealAuditEntry({
      emitter_node: this.config.node_id,
      emitter_agent: "mesh",
      emitter_principal: this.config.system_principal_id ?? "system",
      policy_version: 0,
      attestation_state: "peer_protocol_violation",
      payload: {
        operation: "master_rotation_denied",
        event_type: "master_rotation",
        peer_node: params.emitter_node,
        rotated_at: params.rotated_at,
        reason: params.error.message,
      },
      node_private_key: this.nodePrivateKey,
    });
    if (this.oldestPendingEntryAt === null) {
      this.oldestPendingEntryAt = Date.now();
    }
    this.auditBuffer.push(entry);
  }

  private pushMasterRotationDenialSaturationSummary(summary: {
    suppressed_count: number;
    distinct_emitter_count: number;
  }): void {
    if (!this.nodePrivateKey) return;
    const entry = sealAuditEntry({
      emitter_node: this.config.node_id,
      emitter_agent: "mesh",
      emitter_principal: this.config.system_principal_id ?? "system",
      policy_version: 0,
      attestation_state: "peer_protocol_violation",
      payload: {
        operation: "master_rotation_denied_saturation_summary",
        suppressed_count: summary.suppressed_count,
        distinct_emitter_count: summary.distinct_emitter_count,
      },
      node_private_key: this.nodePrivateKey,
    });
    if (this.oldestPendingEntryAt === null) {
      this.oldestPendingEntryAt = Date.now();
    }
    this.auditBuffer.push(entry);
  }

  private pushUncorrelatedSyncSaturationSummary(summary: {
    suppressed_count: number;
    distinct_emitter_count: number;
  }): void {
    if (!this.nodePrivateKey) return;
    const entry = sealAuditEntry({
      emitter_node: this.config.node_id,
      emitter_agent: "mesh",
      emitter_principal: this.config.system_principal_id ?? "system",
      policy_version: 0,
      attestation_state: "peer_protocol_violation",
      payload: {
        operation: "sync_response_uncorrelated_saturation_summary",
        suppressed_count: summary.suppressed_count,
        distinct_emitter_count: summary.distinct_emitter_count,
      },
      node_private_key: this.nodePrivateKey,
    });
    if (this.oldestPendingEntryAt === null) {
      this.oldestPendingEntryAt = Date.now();
    }
    this.auditBuffer.push(entry);
  }

  /**
   * Record an uncorrelated / expired / replayed sync_response refusal with a
   * DISTINCT internal audit reason (never an MCP/public string) so a skewed or
   * slow-link fleet is diagnosable: repeated entries on a joiner are the tell of
   * a too-small SYNC_REQUEST_ID_EXPIRY_MS against real transfer time.
   *
   * Write-governed (rule 8): the refusal is GUARANTEED for any unsolicited
   * response, so an ungoverned entry per refusal would let any in-roster peer
   * spam zero-cost audit writes. The refusal DECISION is unaffected by
   * suppression — this governs only whether the individual entry is written.
   */
  private auditUncorrelatedSyncResponse(peerNode: string): void {
    if (!this.nodePrivateKey) return;
    const decision = this.uncorrelatedSyncAuditGovernor.consider(
      peerNode,
      Date.now()
    );
    if (decision.saturationSummary) {
      this.pushUncorrelatedSyncSaturationSummary(decision.saturationSummary);
    }
    if (!decision.writeIndividual) return;
    const entry = sealAuditEntry({
      emitter_node: this.config.node_id,
      emitter_agent: "mesh",
      emitter_principal: this.config.system_principal_id ?? "system",
      policy_version: 0,
      attestation_state: "peer_protocol_violation",
      payload: {
        operation: "sync_response_uncorrelated",
        peer_node: peerNode,
      },
      node_private_key: this.nodePrivateKey,
    });
    if (this.oldestPendingEntryAt === null) {
      this.oldestPendingEntryAt = Date.now();
    }
    this.auditBuffer.push(entry);
  }

  // ── C12-REPLAY sync-request correlation (§3.3 point 7) ────────────────

  private mintSyncRequestId(): string {
    const bytes = randomBytes(SYNC_REQUEST_ID_BYTES);
    let hex = "";
    for (const b of bytes) hex += b.toString(16).padStart(2, "0");
    return hex;
  }

  private registerOutstandingSyncRequest(
    requestId: string,
    now: number = Date.now()
  ): void {
    // Evict expired ids opportunistically, then bound the set (self-inflicted
    // growth only — ids are minted solely here). Evict oldest if still full.
    for (const [id, expiry] of this.outstandingSyncRequests) {
      if (expiry <= now) this.outstandingSyncRequests.delete(id);
    }
    while (this.outstandingSyncRequests.size >= MAX_OUTSTANDING_SYNC_REQUESTS) {
      const oldest = this.outstandingSyncRequests.keys().next().value;
      if (oldest === undefined) break;
      this.outstandingSyncRequests.delete(oldest);
    }
    this.outstandingSyncRequests.set(
      requestId,
      now + SYNC_REQUEST_ID_EXPIRY_MS
    );
  }

  /**
   * Consume an outstanding sync-request id iff it is present and unexpired. An
   * expired id is deliberately INDISTINGUISHABLE from a never-issued id (no
   * tombstone set) — a stated choice, not an accident. Returns true only when
   * the response is correlated to a live outstanding request.
   */
  private consumeOutstandingSyncRequest(
    requestId: string | undefined,
    now: number = Date.now()
  ): boolean {
    if (requestId === undefined) return false;
    const expiry = this.outstandingSyncRequests.get(requestId);
    if (expiry === undefined) return false;
    // Match consumes the id, so a second response reusing it is refused.
    this.outstandingSyncRequests.delete(requestId);
    if (expiry <= now) return false;
    return true;
  }

  private auditPeerProtocolViolation(info: {
    error: Error;
    event_type: string;
    emitter_node?: string;
  }): void {
    if (
      !(info.error instanceof MeshReservedEventTypeError) &&
      !(info.error instanceof MeshReservedExtensionKeyError) &&
      !(info.error instanceof MeshReservedCapabilityBitError)
    ) {
      return;
    }
    if (!this.nodePrivateKey) {
      return;
    }
    const entry = sealAuditEntry({
      emitter_node: this.config.node_id,
      emitter_agent: "mesh",
      emitter_principal: this.config.system_principal_id ?? "system",
      policy_version: 0,
      attestation_state: "peer_protocol_violation",
      payload: {
        operation: "peer_protocol_violation",
        event_type: info.event_type,
        peer_node: info.emitter_node,
        error_name: info.error.name,
        reason: info.error.message,
      },
      node_private_key: this.nodePrivateKey,
    });
    if (this.oldestPendingEntryAt === null) {
      this.oldestPendingEntryAt = Date.now();
    }
    this.auditBuffer.push(entry);
  }

  private async handleIncomingUnicast(message: string): Promise<void> {
    let parsed: { kind: string; evt?: SignedEvent; batch?: unknown };
    try {
      parsed = JSON.parse(message);
    } catch {
      return;
    }
    if (parsed.kind === "audit_batch") {
      try {
        this.ingestAuditBatch(message);
      } catch (e) {
        const emitterNode =
          (parsed.batch as { emitter_node?: string } | undefined)?.emitter_node;
        this.onAuditBatchRejected({
          error: e instanceof Error ? e : new Error(String(e)),
          emitter_node: emitterNode,
        });
      }
      return;
    }
    if (parsed.kind === "sync_request" && parsed.evt) {
      try {
        const verified = this.verifyOrThrow(parsed.evt);
        const reqPayload = verified.payload as SyncRequestPayload;
        const responsePayload = this.handleSyncRequest(reqPayload);
        const responseEvt = packSignedEvent<SyncResponsePayload>({
          event_type: "sync_response",
          emitter_node: this.config.node_id,
          emitter_principal: this.config.system_principal_id ?? "system",
          fortress_id: this.config.fortress_id,
          payload: responsePayload,
          monotonic_seq: this.counters.next("envelope_monotonic_seq"),
          node_private_key: this.nodePrivateKey!,
        });
        await this.transport.unicast(
          verified.emitter_node,
          JSON.stringify({ kind: "sync_response", evt: responseEvt })
        );
      } catch {
        // ignore
      }
      return;
    }
    if (parsed.kind === "sync_response" && parsed.evt) {
      try {
        const verified = this.verifyOrThrow(parsed.evt);
        const respPayload = verified.payload as SyncResponsePayload;
        // C12-REPLAY (§3.3 point 7): apply ONLY when the response correlates to
        // an outstanding request this node issued. Envelope verification
        // (verifyOrThrow above) deliberately runs FIRST, so the refusal's
        // audit entry attributes to an AUTHENTIC in-roster peer — an
        // unverified emitter string would let anyone pollute the audit trail
        // with forged attribution. After that, an uncorrelated (or expired, or
        // replayed) response is refused BEFORE applySync — no payload parse,
        // no log or roster mutation — so the weaker sync_anchored freshness
        // channel is never an always-on unsolicited surface (it runs only
        // during a sync this node itself initiated).
        if (!this.consumeOutstandingSyncRequest(respPayload.request_id)) {
          this.auditUncorrelatedSyncResponse(verified.emitter_node);
          this.onEnvelopeRejected({
            error: new MeshError(
              "sync_response refused: no matching outstanding sync_request (uncorrelated, expired, or replayed)"
            ),
            event_type: "sync_response",
            emitter_node: verified.emitter_node,
          });
          return;
        }
        await this.applySync(respPayload);
      } catch {
        // ignore
      }
      return;
    }
  }

  private verifyOrThrow(evt: SignedEvent): SignedEvent {
    // For envelope verification we use lookupActiveNodeCert so revoked nodes
    // are rejected immediately. New node_join events are verified through a
    // temporary lookup before roster mutation.
    const result = verifySignedEvent(evt, {
      pinnedMasterPubkey: this.config.pinned_master_pubkey,
      lookupNodeCert: (id) => this.roster.lookupActiveNodeCert(id),
      lookupPrincipalCert: (id) => this.principalRoster.get(id),
    });
    return result.event;
  }

  private verifyNodeJoinBeforeRosterMutation(
    evt: SignedEvent<NodeJoinPayload>
  ): SignedEvent<NodeJoinPayload> {
    const certificate = evt.payload.certificate;
    const issuerPrincipalCert = this.principalRoster.get(
      certificate.parent_chain.principal_id
    );
    if (!issuerPrincipalCert) {
      throw new MeshChainError(
        `node_join certificate issuer principal ${certificate.parent_chain.principal_id} is not in local roster`
      );
    }
    verifyCertChain(
      certificate,
      issuerPrincipalCert,
      this.config.pinned_master_pubkey
    );
    const result = verifySignedEvent(evt, {
      pinnedMasterPubkey: this.config.pinned_master_pubkey,
      lookupNodeCert: (id) => {
        if (id === certificate.node_id) return certificate;
        return this.roster.lookupActiveNodeCert(id);
      },
      lookupPrincipalCert: (id) => this.principalRoster.get(id),
    });
    return result.event as SignedEvent<NodeJoinPayload>;
  }
}
