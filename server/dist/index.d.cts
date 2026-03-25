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

export { AuditLog, CommitmentStore, FilesystemStorage, MemoryStorage, PolicyStore, ReputationStore, type SanctuaryConfig, type SanctuaryServer, StateStore, createSanctuaryServer, loadConfig };
