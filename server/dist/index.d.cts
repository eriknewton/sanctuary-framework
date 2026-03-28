import { Server } from '@modelcontextprotocol/sdk/server/index.js';

/**
 * Sanctuary MCP Server — Configuration
 *
 * Loads and validates server configuration from file or environment variables.
 */
interface SanctuaryConfig {
    version: string;
    storage_path: string;
    principal_id?: string;
    state: {
        encryption: "aes-256-gcm";
        key_protection: "passphrase" | "hardware-key" | "none";
        key_derivation: "argon2id";
        integrity: "merkle-sha256";
        identity_provider: "ed25519";
    };
    execution: {
        environment: "local-process" | "docker" | "tee";
        attestation: boolean;
        resource_limits: {
            max_memory_mb: number;
            max_storage_mb: number;
            max_cpu_percent: number;
        };
    };
    disclosure: {
        proof_system: "groth16" | "plonk" | "commitment-only";
        default_policy: "minimum-necessary" | "withhold-all";
    };
    reputation: {
        mode: "self-custodied" | "service-mediated";
        attestation_format: "eas-compatible";
        export_format: "SANCTUARY_REP_V1";
        service_endpoints: string[];
    };
    transport: "stdio" | "http";
    http_port: number;
}
/**
 * Load configuration from file, falling back to defaults.
 */
declare function loadConfig(configPath?: string): Promise<SanctuaryConfig>;

/**
 * Sanctuary MCP Server — Storage Backend Interface
 *
 * Abstract interface for persistent storage. All state flows through this
 * interface, making the storage backend pluggable (filesystem, IPFS, S3, etc.).
 *
 * The storage backend deals in raw bytes — encryption/decryption happens
 * in the StateStore layer above.
 */
/** Metadata about a stored entry */
interface StorageEntryMeta {
    key: string;
    namespace: string;
    size_bytes: number;
    modified_at: string;
}
/** Abstract storage backend interface */
interface StorageBackend {
    /**
     * Write raw bytes to storage.
     * @param namespace - Logical grouping
     * @param key - Entry key within namespace
     * @param data - Raw bytes to store
     */
    write(namespace: string, key: string, data: Uint8Array): Promise<void>;
    /**
     * Read raw bytes from storage.
     * @returns The stored bytes, or null if not found
     */
    read(namespace: string, key: string): Promise<Uint8Array | null>;
    /**
     * Delete an entry from storage.
     * @param secureOverwrite - If true, overwrite with random bytes before deletion
     */
    delete(namespace: string, key: string, secureOverwrite?: boolean): Promise<boolean>;
    /**
     * List all entries in a namespace.
     */
    list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]>;
    /**
     * Check if an entry exists.
     */
    exists(namespace: string, key: string): Promise<boolean>;
    /**
     * Get the total size of all stored data.
     */
    totalSize(): Promise<number>;
}

/**
 * Sanctuary MCP Server — AES-256-GCM Encryption
 *
 * All state encryption in Sanctuary uses AES-256-GCM (authenticated encryption).
 * This provides both confidentiality and integrity — a modified ciphertext will
 * fail authentication, detecting tampering.
 *
 * Security invariants:
 * - Every encryption uses a unique 12-byte IV (NIST SP 800-38D)
 * - The 16-byte authentication tag is always verified on decryption
 * - Keys are 256 bits (32 bytes)
 */
/** Encrypted payload structure stored on disk */
interface EncryptedPayload {
    /** Format version */
    v: number;
    /** Algorithm identifier */
    alg: "aes-256-gcm";
    /** Initialization vector (base64url) */
    iv: string;
    /** Ciphertext (base64url) */
    ct: string;
    /** Authentication tag (base64url) — included in ciphertext by @noble/ciphers */
    /** Timestamp */
    ts: string;
}

/**
 * Sanctuary MCP Server — L1 Cognitive Sovereignty: StateStore
 *
 * The encrypted state store is the foundation of Sanctuary.
 * Every read and write goes through here. All data is encrypted
 * with namespace-specific keys. All writes are signed by an identity.
 * All reads verify integrity via Merkle proofs.
 *
 * Security invariants:
 * - Plaintext never touches the filesystem
 * - Every write gets a unique IV
 * - Every write is signed (non-repudiation)
 * - Monotonic version numbers prevent rollback
 * - Merkle tree verifies namespace integrity
 * - Secure deletion overwrites before unlinking
 */

/** Result of a state write operation */
interface WriteResult {
    key: string;
    namespace: string;
    version: number;
    merkle_root: string;
    written_at: string;
    size_bytes: number;
    integrity_hash: string;
}
/** Result of a state read operation */
interface ReadResult {
    key: string;
    namespace: string;
    value: string;
    version: number;
    integrity_verified: boolean;
    merkle_proof: string[];
    written_at: string;
    written_by: string;
}
/** Options for state write */
interface WriteOptions {
    content_type?: string;
    ttl_seconds?: number;
    tags?: string[];
}
declare class StateStore {
    private storage;
    private masterKey;
    private versionCache;
    private contentHashes;
    constructor(storage: StorageBackend, masterKey: Uint8Array);
    private versionKey;
    /**
     * Get or initialize the content hash map for a namespace.
     */
    private getNamespaceHashes;
    /**
     * Write encrypted state.
     *
     * @param namespace - Logical grouping
     * @param key - State key
     * @param value - Plaintext value (will be encrypted)
     * @param identityId - Identity performing the write
     * @param encryptedPrivateKey - Identity's encrypted private key (for signing)
     * @param identityEncryptionKey - Key to decrypt the identity's private key
     * @param options - Optional metadata
     */
    write(namespace: string, key: string, value: string, identityId: string, encryptedPrivateKey: EncryptedPayload, identityEncryptionKey: Uint8Array, options?: WriteOptions): Promise<WriteResult>;
    /**
     * Read and decrypt state.
     *
     * @param namespace - Logical grouping
     * @param key - State key
     * @param signerPublicKey - Expected signer's public key (for signature verification)
     * @param verifyIntegrity - Whether to verify Merkle proof (default: true)
     */
    read(namespace: string, key: string, signerPublicKey?: Uint8Array, verifyIntegrity?: boolean): Promise<ReadResult | null>;
    /**
     * List keys in a namespace (metadata only — no decryption).
     */
    list(namespace: string, prefix?: string, tags?: string[], limit?: number, offset?: number): Promise<{
        keys: Array<{
            key: string;
            version: number;
            size_bytes: number;
            written_at: string;
            tags: string[];
        }>;
        total: number;
        merkle_root: string;
    }>;
    /**
     * Securely delete state (overwrite with random bytes before removal).
     */
    delete(namespace: string, key: string): Promise<{
        deleted: boolean;
        key: string;
        namespace: string;
        new_merkle_root: string;
        deleted_at: string;
    }>;
    /**
     * Export all state for a namespace as an encrypted bundle.
     */
    export(namespace?: string): Promise<{
        bundle: string;
        namespaces: string[];
        total_keys: number;
        bundle_hash: string;
        exported_at: string;
    }>;
    /**
     * Import a previously exported state bundle.
     */
    import(bundleBase64: string, conflictResolution?: "skip" | "overwrite" | "version"): Promise<{
        imported_keys: number;
        skipped_keys: number;
        conflicts: number;
        namespaces: string[];
        imported_at: string;
    }>;
}

/**
 * Sanctuary MCP Server — L2 Operational Isolation: Audit Log
 *
 * Append-only log of all sovereignty-relevant operations.
 * Stored encrypted under L1 sovereignty.
 *
 * Every tool invocation that modifies state, generates proofs,
 * or records reputation produces an audit entry. The human principal
 * can inspect what their agent has done.
 */

interface AuditEntry {
    timestamp: string;
    layer: "l1" | "l2" | "l3" | "l4";
    operation: string;
    identity_id: string;
    result: "success" | "failure";
    details?: Record<string, unknown>;
}
declare class AuditLog {
    private storage;
    private encryptionKey;
    private entries;
    private counter;
    constructor(storage: StorageBackend, masterKey: Uint8Array);
    /**
     * Append an audit entry.
     */
    append(layer: AuditEntry["layer"], operation: string, identityId: string, details?: Record<string, unknown>, result?: "success" | "failure"): void;
    private persistEntry;
    /**
     * Query the audit log with filtering.
     */
    query(options: {
        since?: string;
        layer?: AuditEntry["layer"];
        operation_type?: string;
        limit?: number;
    }): Promise<{
        entries: AuditEntry[];
        total: number;
    }>;
    private loadPersistedEntries;
    /**
     * Get total number of entries.
     */
    get size(): number;
}

/**
 * Sanctuary MCP Server — L3 Selective Disclosure: Commitment Schemes
 *
 * Cryptographic commitments allow an agent to commit to a value
 * without revealing it, then later prove what was committed.
 *
 * This is the MVS approach to selective disclosure — simpler than
 * full ZK proofs but still cryptographically sound. The commitment
 * is SHA-256(value || blinding_factor), which is:
 * - Hiding: the commitment reveals nothing about the value
 * - Binding: the committer cannot change the value after committing
 *
 * Security invariants:
 * - Blinding factors are cryptographically random (32 bytes)
 * - Commitments are stored encrypted under L1 sovereignty
 * - Revealed values are verified via constant-time comparison
 */

/** A cryptographic commitment */
interface Commitment {
    /** The commitment hash: SHA-256(value || blinding_factor) as base64url */
    commitment: string;
    /** The blinding factor (must be stored securely for later reveal) */
    blinding_factor: string;
    /** When the commitment was created */
    committed_at: string;
}
/** Stored commitment metadata (encrypted at rest) */
interface StoredCommitment {
    commitment: string;
    blinding_factor: string;
    value: string;
    committed_at: string;
    revealed: boolean;
    revealed_at?: string;
}
/**
 * Commitment store — manages commitments encrypted under L1 sovereignty.
 */
declare class CommitmentStore {
    private storage;
    private encryptionKey;
    constructor(storage: StorageBackend, masterKey: Uint8Array);
    /**
     * Store a commitment (encrypted) for later reference.
     */
    store(commitment: Commitment, value: string): Promise<string>;
    /**
     * Retrieve a stored commitment by ID.
     */
    get(id: string): Promise<StoredCommitment | null>;
    /**
     * Mark a commitment as revealed.
     */
    markRevealed(id: string): Promise<void>;
}

/**
 * Sanctuary MCP Server — L3 Selective Disclosure: Disclosure Policies
 *
 * Disclosure policies define what an agent will and will not disclose
 * in different interaction contexts. Policies are evaluated against
 * incoming disclosure requests to produce per-field decisions.
 *
 * This is the agent's "privacy preferences" layer — it codifies the
 * human principal's intent about what information can flow where.
 *
 * Security invariants:
 * - Policies are stored encrypted under L1 sovereignty
 * - Default action is always "withhold" unless explicitly overridden
 * - Policy evaluation is deterministic (same request → same decision)
 */

/** A single disclosure rule within a policy */
interface DisclosureRule {
    /** Interaction context this rule applies to */
    context: string;
    /** Fields/claims the agent MAY disclose */
    disclose: string[];
    /** Fields/claims the agent MUST NOT disclose */
    withhold: string[];
    /** Fields that require proof rather than plain disclosure */
    proof_required: string[];
}
/** A complete disclosure policy */
interface DisclosurePolicy {
    policy_id: string;
    policy_name: string;
    rules: DisclosureRule[];
    default_action: "withhold" | "ask-principal";
    identity_id?: string;
    created_at: string;
    updated_at: string;
}
/**
 * Policy store — manages disclosure policies encrypted under L1 sovereignty.
 */
declare class PolicyStore {
    private storage;
    private encryptionKey;
    private policies;
    constructor(storage: StorageBackend, masterKey: Uint8Array);
    /**
     * Create and store a new disclosure policy.
     */
    create(policyName: string, rules: DisclosureRule[], defaultAction: "withhold" | "ask-principal", identityId?: string): Promise<DisclosurePolicy>;
    /**
     * Get a policy by ID.
     */
    get(policyId: string): Promise<DisclosurePolicy | null>;
    /**
     * List all policies.
     */
    list(): Promise<DisclosurePolicy[]>;
    /**
     * Load all persisted policies into memory.
     */
    private loadAll;
    private persist;
}

/**
 * Sanctuary MCP Server — Ed25519 Identity Management
 *
 * Sovereign identity based on Ed25519 keypairs.
 * Private keys are always encrypted at rest — never stored in plaintext.
 *
 * Security invariants:
 * - Private keys never appear in any MCP tool response
 * - Private keys are encrypted with identity-specific keys derived from the master key
 * - Key rotation produces a signed rotation event (verifiable chain)
 */

/** Public identity information (safe to share) */
interface PublicIdentity {
    identity_id: string;
    label: string;
    public_key: string;
    did: string;
    created_at: string;
    key_type: "ed25519";
    key_protection: "passphrase" | "hardware-key" | "recovery-key";
}
/** Stored identity (private key is encrypted) */
interface StoredIdentity extends PublicIdentity {
    encrypted_private_key: EncryptedPayload;
    /** Previous public keys (for rotation chain verification) */
    rotation_history: Array<{
        old_public_key: string;
        new_public_key: string;
        rotation_event: string;
        rotated_at: string;
    }>;
}

/**
 * Sanctuary MCP Server — L4 Verifiable Reputation: Reputation Store
 *
 * Records interaction outcomes as signed attestations, queries aggregated
 * reputation data, and supports export/import for cross-platform portability.
 *
 * Attestation format is EAS-compatible (Ethereum Attestation Service) to
 * enable future on-chain anchoring without requiring blockchain for MVS.
 *
 * Security invariants:
 * - All attestations are signed by the recording identity
 * - Attestations are stored encrypted under L1 sovereignty
 * - Reputation queries return aggregates, never raw interaction data
 * - Export bundles include all signatures for independent verification
 * - Import verifies every signature before accepting attestations
 */

/** Interaction outcome for recording */
interface InteractionOutcome {
    type: "transaction" | "negotiation" | "service" | "dispute" | "custom";
    result: "completed" | "partial" | "failed" | "disputed";
    metrics?: Record<string, number>;
}
/** A signed attestation of an interaction */
interface Attestation {
    attestation_id: string;
    schema: "sanctuary-interaction-v1";
    data: {
        interaction_id: string;
        participant_did: string;
        counterparty_did: string;
        outcome_type: string;
        outcome_result: string;
        metrics: Record<string, number>;
        context: string;
        timestamp: string;
    };
    signature: string;
    signer: string;
}
/** Stored attestation (encrypted at rest) */
interface StoredAttestation {
    attestation: Attestation;
    counterparty_attestation?: string;
    counterparty_confirmed: boolean;
    recorded_at: string;
}
/** Aggregated metric statistics */
interface MetricAggregate {
    mean: number;
    median: number;
    min: number;
    max: number;
    count: number;
}
/** Reputation query result */
interface ReputationSummary {
    total_interactions: number;
    completed: number;
    partial: number;
    failed: number;
    disputed: number;
    contexts: string[];
    time_range: {
        start: string;
        end: string;
    };
    aggregate_metrics: Record<string, MetricAggregate>;
}
/** Portable reputation bundle */
interface ReputationBundle {
    version: "SANCTUARY_REP_V1";
    attestations: Attestation[];
    exported_at: string;
    exporter_did: string;
    bundle_signature: string;
}
/** Escrow for trust bootstrapping */
interface Escrow {
    escrow_id: string;
    transaction_terms: string;
    terms_hash: string;
    collateral_amount?: number;
    counterparty_did: string;
    creator_did: string;
    created_at: string;
    expires_at: string;
    status: "pending" | "active" | "released" | "disputed" | "expired";
}
/** Principal guarantee for a new agent */
interface Guarantee {
    guarantee_id: string;
    principal_did: string;
    agent_did: string;
    scope: string;
    max_liability?: number;
    valid_until: string;
    certificate: string;
    created_at: string;
}
declare class ReputationStore {
    private storage;
    private encryptionKey;
    constructor(storage: StorageBackend, masterKey: Uint8Array);
    /**
     * Record an interaction outcome as a signed attestation.
     */
    record(interactionId: string, counterpartyDid: string, outcome: InteractionOutcome, context: string, identity: StoredIdentity, identityEncryptionKey: Uint8Array, counterpartyAttestation?: string): Promise<StoredAttestation>;
    /**
     * Query reputation data with filtering.
     * Returns aggregates only — not raw interaction data.
     */
    query(options: {
        context?: string;
        time_range?: {
            start: string;
            end: string;
        };
        metrics?: string[];
        counterparty_did?: string;
    }): Promise<ReputationSummary>;
    /**
     * Export attestations as a portable reputation bundle.
     */
    exportBundle(identity: StoredIdentity, identityEncryptionKey: Uint8Array, context?: string): Promise<ReputationBundle>;
    /**
     * Import attestations from a reputation bundle.
     * Verifies signatures if requested (default: true).
     *
     * @param publicKeys - Map of DID → public key bytes for signature verification
     */
    importBundle(bundle: ReputationBundle, verifySignatures: boolean, publicKeys: Map<string, Uint8Array>): Promise<{
        imported: number;
        invalid: number;
        contexts: string[];
    }>;
    /**
     * Create an escrow for trust bootstrapping.
     */
    createEscrow(transactionTerms: string, counterpartyDid: string, timeoutSeconds: number, creatorDid: string, collateralAmount?: number): Promise<Escrow>;
    /**
     * Get an escrow by ID.
     */
    getEscrow(escrowId: string): Promise<Escrow | null>;
    /**
     * Create a principal's guarantee for a new agent.
     */
    createGuarantee(principalIdentity: StoredIdentity, agentDid: string, scope: string, durationSeconds: number, identityEncryptionKey: Uint8Array, maxLiability?: number): Promise<Guarantee>;
    private loadAll;
}

/**
 * Sanctuary MCP Server — In-Memory Storage Backend
 *
 * Used for testing. Implements the same interface as filesystem storage
 * but stores everything in memory. Data does not persist across restarts.
 */

declare class MemoryStorage implements StorageBackend {
    private store;
    private storageKey;
    write(namespace: string, key: string, data: Uint8Array): Promise<void>;
    read(namespace: string, key: string): Promise<Uint8Array | null>;
    delete(namespace: string, key: string, _secureOverwrite?: boolean): Promise<boolean>;
    list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]>;
    exists(namespace: string, key: string): Promise<boolean>;
    totalSize(): Promise<number>;
    /** Clear all stored data (useful in tests) */
    clear(): void;
}

/**
 * Sanctuary MCP Server — Filesystem Storage Backend
 *
 * Default storage backend using the local filesystem.
 * Files are stored as: {basePath}/{namespace}/{key}.enc
 *
 * Security invariants:
 * - Secure deletion overwrites file content with random bytes before unlinking
 * - Directory creation uses restrictive permissions (0o700)
 * - File creation uses restrictive permissions (0o600)
 */

declare class FilesystemStorage implements StorageBackend {
    private basePath;
    constructor(basePath: string);
    private entryPath;
    private namespacePath;
    write(namespace: string, key: string, data: Uint8Array): Promise<void>;
    read(namespace: string, key: string): Promise<Uint8Array | null>;
    delete(namespace: string, key: string, secureOverwrite?: boolean): Promise<boolean>;
    list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]>;
    exists(namespace: string, key: string): Promise<boolean>;
    totalSize(): Promise<number>;
}

/**
 * Sanctuary MCP Server — Principal Policy Types
 *
 * Type definitions for the Principal Policy system.
 * The Principal Policy is the human-controlled, agent-immutable
 * configuration that gates operations through approval tiers.
 */
/** Tier 2 anomaly action: what to do when an anomaly is detected */
type AnomalyAction = "approve" | "log" | "allow";
/** Tier 2 anomaly detection configuration */
interface Tier2Config {
    /** Action when agent accesses a namespace it hasn't used before */
    new_namespace_access: AnomalyAction;
    /** Action when agent interacts with an unknown counterparty DID */
    new_counterparty: AnomalyAction;
    /** Tool call frequency multiplier that triggers anomaly */
    frequency_spike_multiplier: number;
    /** Maximum signing operations per minute before triggering */
    max_signs_per_minute: number;
    /** Reading more than N keys in a namespace within 60 seconds */
    bulk_read_threshold: number;
    /** Policy for first session when no baseline exists */
    first_session_policy: AnomalyAction;
}
/** Approval channel configuration */
interface ApprovalChannelConfig {
    type: "stderr" | "webhook" | "callback";
    timeout_seconds: number;
    auto_deny: boolean;
    webhook_url?: string;
    webhook_secret?: string;
}
/** Complete Principal Policy */
interface PrincipalPolicy {
    version: number;
    /** Operations that always require human approval */
    tier1_always_approve: string[];
    /** Behavioral anomaly detection configuration */
    tier2_anomaly: Tier2Config;
    /** Operations that never require approval (audit only) */
    tier3_always_allow: string[];
    /** How approval requests reach the human */
    approval_channel: ApprovalChannelConfig;
}
/** Approval request sent to the human */
interface ApprovalRequest {
    operation: string;
    tier: 1 | 2;
    reason: string;
    context: Record<string, unknown>;
    timestamp: string;
}
/** Approval response from the human */
interface ApprovalResponse {
    decision: "approve" | "deny";
    decided_at: string;
    decided_by: "human" | "timeout" | "auto";
}
/** Result of the approval gate evaluation */
interface GateResult {
    allowed: boolean;
    tier: 1 | 2 | 3;
    reason: string;
    approval_required: boolean;
    approval_response?: ApprovalResponse;
}
/** Behavioral baseline for anomaly detection */
interface SessionProfile {
    /** Namespaces accessed (read or write) */
    known_namespaces: string[];
    /** Counterparty DIDs seen in reputation operations */
    known_counterparties: string[];
    /** Tool call counts per tool name (lifetime in session) */
    tool_call_counts: Record<string, number>;
    /** Whether this is the first session (no prior baseline) */
    is_first_session: boolean;
    /** Session start time */
    started_at: string;
    /** When the baseline was last saved */
    saved_at?: string;
}

/**
 * Sanctuary MCP Server — Approval Channel
 *
 * Out-of-band communication with the human principal for operation approval.
 * The default channel uses stderr (outside MCP's stdin/stdout protocol),
 * ensuring the agent cannot intercept or forge approval responses.
 *
 * Security invariant:
 * - Approval prompts go through a channel the agent cannot access.
 * - Timeouts result in denial by default (fail closed).
 */

/** Abstract approval channel interface */
interface ApprovalChannel {
    requestApproval(request: ApprovalRequest): Promise<ApprovalResponse>;
}
/**
 * Stderr approval channel — writes prompts to stderr, waits for response.
 *
 * In the MCP stdio model:
 * - stdin/stdout carry the MCP protocol (JSON-RPC)
 * - stderr is available for out-of-band human communication
 *
 * Since many harnesses do not support interactive stdin during tool calls,
 * this channel uses a timeout-based model: the prompt is displayed, and
 * if no response is received within the timeout, the default action applies.
 *
 * For MVS, the channel auto-resolves based on the auto_deny setting.
 * Interactive stdin reading is deferred to a future version with harness support.
 */
declare class StderrApprovalChannel implements ApprovalChannel {
    private config;
    constructor(config: ApprovalChannelConfig);
    requestApproval(request: ApprovalRequest): Promise<ApprovalResponse>;
    private formatPrompt;
}
/**
 * Programmatic approval channel — for testing and API integration.
 */
declare class CallbackApprovalChannel implements ApprovalChannel {
    private callback;
    constructor(callback: (request: ApprovalRequest) => Promise<ApprovalResponse>);
    requestApproval(request: ApprovalRequest): Promise<ApprovalResponse>;
}
/**
 * Auto-approve channel — for testing. Approves everything.
 */
declare class AutoApproveChannel implements ApprovalChannel {
    requestApproval(_request: ApprovalRequest): Promise<ApprovalResponse>;
}

/**
 * Sanctuary MCP Server — Behavioral Baseline Tracker
 *
 * Tracks the agent's behavioral profile during a session and persists
 * it for cross-session anomaly detection. The baseline defines "normal"
 * so that deviations can trigger Tier 2 approval.
 *
 * Security invariants:
 * - Baseline is stored encrypted under L1 sovereignty
 * - Baseline changes are audit-logged
 * - Baseline is integrity-verified via L1 Merkle tree
 * - No MCP tool can directly modify the baseline
 */

declare class BaselineTracker {
    private storage;
    private encryptionKey;
    private profile;
    /** Sliding window: timestamps of tool calls per tool name (last 60s) */
    private callWindows;
    /** Sliding window: read counts per namespace (last 60s) */
    private readWindows;
    /** Sliding window: sign call timestamps (last 60s) */
    private signWindow;
    constructor(storage: StorageBackend, masterKey: Uint8Array);
    /**
     * Load the previous session's baseline from storage.
     * If none exists, this is a first session.
     */
    load(): Promise<void>;
    /**
     * Save the current baseline to storage (encrypted).
     * Called at session end or periodically.
     */
    save(): Promise<void>;
    /**
     * Record a tool call for baseline tracking.
     * Returns anomaly information if applicable.
     */
    recordToolCall(toolName: string): void;
    /**
     * Record a namespace access.
     * @returns true if this is a new namespace (not in baseline)
     */
    recordNamespaceAccess(namespace: string): boolean;
    /**
     * Record a namespace read for bulk-read detection.
     * @returns the number of reads in the current 60-second window
     */
    recordNamespaceRead(namespace: string): number;
    /**
     * Record a counterparty DID interaction.
     * @returns true if this is a new counterparty (not in baseline)
     */
    recordCounterparty(did: string): boolean;
    /**
     * Record a signing operation.
     * @returns the number of signs in the current 60-second window
     */
    recordSign(): number;
    /**
     * Get the current call rate for a tool (calls per minute).
     */
    getCallRate(toolName: string): number;
    /**
     * Get the average call rate across all tools in the baseline.
     */
    getAverageCallRate(): number;
    /** Whether this is the first session */
    get isFirstSession(): boolean;
    /** Get a read-only view of the current profile */
    getProfile(): SessionProfile;
}

/**
 * Sanctuary MCP Server — Approval Gate
 *
 * The three-tier approval gate sits between the MCP router and tool handlers.
 * Every tool call passes through the gate before execution.
 *
 * Evaluation order:
 * 1. Tier 1: Is this operation in the always-approve list? → Request approval.
 * 2. Tier 2: Does this call represent a behavioral anomaly? → Request approval.
 * 3. Tier 3 / default: Allow with audit logging.
 *
 * Security invariants:
 * - The gate cannot be bypassed — it wraps every tool handler.
 * - Denial responses do not reveal policy details to the agent.
 * - All gate decisions (approve, deny, allow) are audit-logged.
 */

declare class ApprovalGate {
    private policy;
    private baseline;
    private channel;
    private auditLog;
    constructor(policy: PrincipalPolicy, baseline: BaselineTracker, channel: ApprovalChannel, auditLog: AuditLog);
    /**
     * Evaluate a tool call against the Principal Policy.
     *
     * @param toolName - Full MCP tool name (e.g., "sanctuary/state_export")
     * @param args - Tool call arguments (for context extraction)
     * @returns GateResult indicating whether the call is allowed
     */
    evaluate(toolName: string, args: Record<string, unknown>): Promise<GateResult>;
    /**
     * Detect Tier 2 behavioral anomalies.
     */
    private detectAnomaly;
    /**
     * Request approval from the human principal.
     */
    private requestApproval;
    /**
     * Summarize tool arguments for the approval prompt.
     * Strips potentially large values to keep the prompt readable.
     */
    private summarizeArgs;
    /** Get the baseline tracker for saving at session end */
    getBaseline(): BaselineTracker;
}

/**
 * Sanctuary MCP Server — Principal Policy Loader
 *
 * Loads the Principal Policy from a YAML file at server startup.
 * The policy is immutable at runtime — no MCP tool can modify it.
 *
 * Security invariant:
 * - The policy is loaded ONCE at startup and frozen.
 * - No code path exists to modify the policy during a session.
 * - If no policy file exists, a sensible default is generated and saved.
 */

/**
 * Load the Principal Policy from disk.
 * If no policy file exists, generate the default and save it.
 * The returned policy is frozen — immutable at runtime.
 */
declare function loadPrincipalPolicy(storagePath: string): Promise<PrincipalPolicy>;

/**
 * Sanctuary MCP Server — L1 Cognitive Sovereignty: Tool Definitions
 *
 * MCP tool wrappers for StateStore and IdentityRoot operations.
 * These tools are the public API that agents interact with.
 */

/** Manages all identities — provides storage and retrieval */
declare class IdentityManager {
    private storage;
    private masterKey;
    private identities;
    private primaryIdentityId;
    constructor(storage: StorageBackend, masterKey: Uint8Array);
    private get encryptionKey();
    /** Load identities from storage on startup */
    load(): Promise<void>;
    /** Save an identity to storage */
    save(identity: StoredIdentity): Promise<void>;
    get(id: string): StoredIdentity | undefined;
    getDefault(): StoredIdentity | undefined;
    list(): PublicIdentity[];
}

/**
 * Sanctuary MCP Server — Sovereignty Health Report (SHR) Types
 *
 * Machine-readable, signed, versioned sovereignty capability advertisement.
 * An agent presents its SHR to counterparties to prove its sovereignty posture.
 * The SHR is signed by one of the instance's Ed25519 identities and can be
 * independently verified by any party without trusting the presenter.
 *
 * SHR version: 1.0
 */
type LayerStatus = "active" | "degraded" | "inactive";
type DegradationSeverity = "info" | "warning" | "critical";
type DegradationCode = "NO_TEE" | "PROCESS_ISOLATION_ONLY" | "COMMITMENT_ONLY" | "NO_ZK_PROOFS" | "SELF_REPORTED_ATTESTATION" | "NO_SELECTIVE_DISCLOSURE" | "BASIC_SYBIL_ONLY";
interface SHRLayerL1 {
    status: LayerStatus;
    encryption: string;
    key_custody: "self" | "delegated" | "platform";
    integrity: string;
    identity_type: string;
    state_portable: boolean;
}
interface SHRLayerL2 {
    status: LayerStatus;
    isolation_type: string;
    attestation_available: boolean;
}
interface SHRLayerL3 {
    status: LayerStatus;
    proof_system: string;
    selective_disclosure: boolean;
}
interface SHRLayerL4 {
    status: LayerStatus;
    reputation_mode: string;
    attestation_format: string;
    reputation_portable: boolean;
}
interface SHRDegradation {
    layer: "l1" | "l2" | "l3" | "l4";
    code: DegradationCode;
    severity: DegradationSeverity;
    description: string;
    mitigation?: string;
}
interface SHRCapabilities {
    handshake: boolean;
    shr_exchange: boolean;
    reputation_verify: boolean;
    encrypted_channel: boolean;
}
/**
 * The SHR body — the content that gets signed.
 * Canonical form: JSON with sorted keys, no whitespace.
 */
interface SHRBody {
    shr_version: "1.0";
    instance_id: string;
    generated_at: string;
    expires_at: string;
    layers: {
        l1: SHRLayerL1;
        l2: SHRLayerL2;
        l3: SHRLayerL3;
        l4: SHRLayerL4;
    };
    capabilities: SHRCapabilities;
    degradations: SHRDegradation[];
}
/**
 * The complete signed SHR — body + signature envelope.
 */
interface SignedSHR {
    body: SHRBody;
    signed_by: string;
    signature: string;
}
interface SHRVerificationResult {
    valid: boolean;
    errors: string[];
    warnings: string[];
    sovereignty_level: "full" | "degraded" | "minimal";
    counterparty_id: string;
    expires_at: string;
}

/**
 * Sanctuary MCP Server — SHR Generator
 *
 * Generates a Sovereignty Health Report from current server state,
 * signs it with a specified identity, and returns the complete signed SHR.
 */

interface SHRGeneratorOptions {
    config: SanctuaryConfig;
    identityManager: IdentityManager;
    masterKey: Uint8Array;
    /** Override validity window (milliseconds). Default: 1 hour. */
    validityMs?: number;
}
/**
 * Generate and sign a Sovereignty Health Report.
 *
 * @param identityId - Which identity to sign with (defaults to primary)
 * @param opts - Generator dependencies
 * @returns The signed SHR, or an error string
 */
declare function generateSHR(identityId: string | undefined, opts: SHRGeneratorOptions): SignedSHR | string;

/**
 * Sanctuary MCP Server — SHR Verifier
 *
 * Verifies a counterparty's Sovereignty Health Report:
 * - Signature validity (Ed25519 over canonical body)
 * - Temporal validity (not expired)
 * - Schema completeness
 * - Sovereignty level assessment
 */

/**
 * Verify a signed SHR.
 *
 * @param shr - The signed SHR to verify
 * @param now - Optional override for current time (for testing)
 * @returns Verification result with validity, errors, warnings, and sovereignty assessment
 */
declare function verifySHR(shr: SignedSHR, now?: Date): SHRVerificationResult;

/**
 * Sanctuary MCP Server — Sovereignty Handshake Types
 *
 * The sovereignty handshake is a mutual verification protocol between
 * two Sanctuary instances. Each party presents its SHR and proves
 * liveness via nonce challenge-response.
 *
 * Protocol:
 *   A → B: HandshakeChallenge (A's SHR + nonce)
 *   B → A: HandshakeResponse (B's SHR + B's nonce + signature over A's nonce)
 *   A → B: HandshakeCompletion (signature over B's nonce)
 *   Result: Both hold a HandshakeResult with verified counterparty status
 */

/** Trust tier derived from sovereignty handshake */
type TrustTier = "verified-sovereign" | "verified-degraded" | "unverified";
/** Sovereignty level from SHR assessment */
type SovereigntyLevel = "full" | "degraded" | "minimal" | "unverified";
/**
 * Step 1: Initiator sends challenge
 */
interface HandshakeChallenge {
    protocol_version: "1.0";
    shr: SignedSHR;
    nonce: string;
    initiated_at: string;
}
/**
 * Step 2: Responder sends response
 */
interface HandshakeResponse {
    protocol_version: "1.0";
    shr: SignedSHR;
    responder_nonce: string;
    initiator_nonce_signature: string;
    responded_at: string;
}
/**
 * Step 3: Initiator sends completion
 */
interface HandshakeCompletion {
    protocol_version: "1.0";
    responder_nonce_signature: string;
    completed_at: string;
}
/**
 * Final result: both parties hold this after a successful handshake
 */
interface HandshakeResult {
    counterparty_id: string;
    counterparty_shr: SignedSHR;
    verified: boolean;
    sovereignty_level: SovereigntyLevel;
    trust_tier: TrustTier;
    completed_at: string;
    expires_at: string;
    errors: string[];
}
/**
 * In-progress handshake state (stored on initiator side)
 */
interface HandshakeSession {
    session_id: string;
    role: "initiator" | "responder";
    state: "initiated" | "responded" | "completed" | "failed";
    our_nonce: string;
    their_nonce?: string;
    our_shr: SignedSHR;
    their_shr?: SignedSHR;
    initiated_at: string;
    result?: HandshakeResult;
}

/**
 * Sanctuary MCP Server — Sovereignty Handshake Protocol
 *
 * Core handshake logic: initiate, respond, complete.
 * Nonce-based challenge-response prevents replay attacks.
 * SHR signatures are verified at each step.
 */

/**
 * Step 1: Initiate a handshake.
 * Generates a challenge containing our SHR and a nonce.
 */
declare function initiateHandshake(ourSHR: SignedSHR): {
    challenge: HandshakeChallenge;
    session: HandshakeSession;
};
/**
 * Step 2: Respond to a handshake challenge.
 * Verifies the initiator's SHR, signs their nonce, generates our nonce.
 */
declare function respondToHandshake(challenge: HandshakeChallenge, ourSHR: SignedSHR, identityManager: IdentityManager, masterKey: Uint8Array, identityId?: string): {
    response: HandshakeResponse;
    session: HandshakeSession;
} | {
    error: string;
};
/**
 * Step 3: Complete the handshake (initiator side).
 * Verifies the responder's SHR and nonce signature, signs responder's nonce.
 */
declare function completeHandshake(response: HandshakeResponse, session: HandshakeSession, identityManager: IdentityManager, masterKey: Uint8Array, identityId?: string): {
    completion: HandshakeCompletion;
    result: HandshakeResult;
} | {
    error: string;
};
/**
 * Step 4: Verify completion (responder side).
 * Verifies the initiator signed our nonce correctly.
 */
declare function verifyCompletion(completion: HandshakeCompletion, session: HandshakeSession): HandshakeResult;

/**
 * Sanctuary MCP Server — Main Entry Point
 *
 * Initializes and exports the Sanctuary MCP server.
 * Wires together: config → storage → crypto core → L1-L4 tools → MCP server
 */

interface SanctuaryServer {
    server: Server;
    config: SanctuaryConfig;
}
/**
 * Initialize the Sanctuary MCP Server.
 *
 * @param options - Configuration overrides and initialization options
 * @returns The configured MCP server, ready to connect to a transport
 */
declare function createSanctuaryServer(options?: {
    configPath?: string;
    passphrase?: string;
    storage?: StorageBackend;
}): Promise<SanctuaryServer>;

export { ApprovalGate, AuditLog, AutoApproveChannel, BaselineTracker, CallbackApprovalChannel, CommitmentStore, FilesystemStorage, type GateResult, type HandshakeChallenge, type HandshakeCompletion, type HandshakeResponse, type HandshakeResult, MemoryStorage, PolicyStore, type PrincipalPolicy, ReputationStore, type SHRBody, type SHRVerificationResult, type SanctuaryConfig, type SanctuaryServer, type SignedSHR, StateStore, StderrApprovalChannel, completeHandshake, createSanctuaryServer, generateSHR, initiateHandshake, loadConfig, loadPrincipalPolicy, respondToHandshake, verifyCompletion, verifySHR };
