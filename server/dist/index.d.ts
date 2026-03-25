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

export { AuditLog, FilesystemStorage, MemoryStorage, type SanctuaryConfig, type SanctuaryServer, StateStore, createSanctuaryServer, loadConfig };
