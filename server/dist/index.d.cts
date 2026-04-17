import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

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
        proof_system: "groth16" | "plonk" | "schnorr-pedersen" | "commitment-only";
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
    dashboard: {
        enabled: boolean;
        port: number;
        host: string;
        /** Bearer token for dashboard auth. If "auto", one is generated at startup. */
        auth_token?: string;
        /** Auto-open dashboard in default browser on startup. Default: true for localhost. */
        auto_open?: boolean;
        /** TLS cert/key paths for HTTPS dashboard. */
        tls?: {
            cert_path: string;
            key_path: string;
        };
    };
    webhook: {
        enabled: boolean;
        /** URL to POST approval requests to */
        url: string;
        /** Shared secret for HMAC-SHA256 signatures */
        secret: string;
        /** Port for callback listener (receives approval responses) */
        callback_port: number;
        /** Host for callback listener */
        callback_host: string;
    };
    /** Verascore integration (agent reputation surface) */
    verascore: {
        /** Base URL of the Verascore deployment. */
        url: string;
        /** Whether to auto-publish handshake attestations to Verascore. */
        auto_publish_to_verascore: boolean;
        /** Whether to auto-publish on successful handshake_respond calls. */
        auto_publish_handshakes: boolean;
    };
}
/**
 * Load configuration from file, falling back to defaults.
 *
 * Precedence (highest wins): CLI flags > env vars > config file > defaults
 * This matches the standard config precedence pattern used by most tools.
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
    /**
     * SEC-002: auto_deny is hardcoded to true and not configurable.
     * Timeout on any approval channel ALWAYS results in denial.
     * This field is retained for backward compatibility with existing
     * policy files but is ignored — timeout always denies.
     */
    auto_deny?: boolean;
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
    decided_by: "human" | "timeout" | "auto" | "stderr:non-interactive";
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
 * Stderr approval channel — non-interactive informational channel.
 *
 * In the MCP stdio model:
 * - stdin/stdout carry the MCP protocol (JSON-RPC)
 * - stderr is available for out-of-band human communication
 *
 * Because stdin is consumed by the MCP JSON-RPC transport, this channel
 * CANNOT read interactive human input. It is strictly informational:
 * the prompt is displayed so the human sees what is happening, and the
 * operation is denied immediately.
 *
 * SEC-002 + SEC-016 invariants:
 * - This channel ALWAYS denies. No configuration can change this.
 * - There is no timeout or async delay — denial is synchronous.
 * - The `auto_deny` config field is ignored (SEC-002).
 * - For interactive approval, use the dashboard or webhook channel.
 */
declare class StderrApprovalChannel implements ApprovalChannel {
    constructor(_config: ApprovalChannelConfig);
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
 * Sanctuary MCP Server — Prompt Injection Detection Layer
 *
 * Fast, zero-dependency detection of common prompt injection patterns.
 * Scans tool arguments for role override, security bypass, encoding evasion,
 * data exfiltration, and prompt stuffing signals.
 *
 * SEC-034/SEC-035: Enhanced with Unicode sanitization pre-pass, decoded content
 * re-scanning, token budget analysis, and outbound content scanning.
 *
 * Security invariants:
 * - Always returns a result, never throws
 * - Typical scan completes in < 5ms
 * - False positives minimized via field-aware scanning
 * - Recursive scanning of nested objects/arrays
 * - Outbound scanning catches secret leaks and injection artifact survival
 */
interface InjectionDetectorConfig {
    enabled: boolean;
    sensitivity: "low" | "medium" | "high";
    on_detection: "escalate" | "block" | "log";
    custom_patterns?: string[];
}
interface InjectionSignal {
    type: string;
    pattern: string;
    location: string;
    severity: "low" | "medium" | "high";
}
interface DetectionResult {
    flagged: boolean;
    confidence: number;
    signals: InjectionSignal[];
    recommendation: "allow" | "escalate" | "block";
}
declare class InjectionDetector {
    private config;
    private stats;
    constructor(config?: Partial<InjectionDetectorConfig>);
    /**
     * Scan tool arguments for injection signals.
     * @param toolName Full tool name (e.g., "state_read")
     * @param args Tool arguments
     * @returns DetectionResult with all detected signals
     */
    scan(toolName: string, args: Record<string, unknown>): DetectionResult;
    /**
     * SEC-035: Scan outbound content for secret leaks, data exfiltration,
     * internal path exposure, and injection artifact survival.
     *
     * @param content The outbound content string to scan
     * @returns DetectionResult with outbound-specific signal types
     */
    scanOutbound(content: string): DetectionResult;
    /**
     * Recursively scan a value and all nested values.
     */
    private scanValue;
    /**
     * Scan a single string for injection signals.
     */
    private scanString;
    /**
     * Count invisible Unicode characters in a string.
     * Includes zero-width chars, soft hyphens, directional marks,
     * variation selectors, and other invisible categories.
     */
    private countInvisibleChars;
    /**
     * Strip invisible characters from a string for clean pattern matching.
     * Returns a new string with all invisible chars removed.
     */
    private stripInvisibleChars;
    /**
     * SEC-034: Token budget attack detection.
     * Some Unicode sequences expand dramatically during tokenization (e.g., CJK
     * ideographs, combining characters, emoji sequences). If the estimated token
     * cost per character is anomalously high, this may be a wallet-drain payload.
     *
     * Heuristic: count chars that typically tokenize into multiple tokens.
     * If the ratio of estimated tokens to char count exceeds 3x, flag it.
     */
    private detectTokenBudgetAttack;
    /**
     * Detect encoded content (base64, hex, HTML entities, URL encoding),
     * decode it, and re-scan the decoded content through injection patterns.
     * If the decoded content contains injection patterns, flag as encoding_evasion.
     */
    private detectEncodedPayloads;
    /**
     * Check if a string contains any injection patterns (role override or security bypass).
     */
    private containsInjectionPatterns;
    /**
     * Safely decode a base64 string. Returns null if it's not valid base64
     * or doesn't decode to a meaningful string.
     */
    private safeBase64Decode;
    /**
     * Safely decode a hex string. Returns null on failure.
     */
    private safeHexDecode;
    /**
     * Decode HTML numeric entities (&#xHH; and &#DDD;) in a string.
     */
    private decodeHtmlEntities;
    /**
     * Safely decode a URL-encoded string. Returns null on failure.
     */
    private safeUrlDecode;
    /**
     * Heuristic: does this look like readable text (vs. binary garbage)?
     * Checks that most characters are printable ASCII or common Unicode.
     */
    private looksLikeText;
    /**
     * Detect API keys and secrets in outbound content.
     */
    private detectSecretPatterns;
    /**
     * Detect data exfiltration via markdown images with data-carrying query params.
     */
    private detectOutboundExfiltration;
    /**
     * Detect internal filesystem path leaks in outbound content.
     */
    private detectInternalPathLeaks;
    /**
     * Detect private IP addresses and localhost references in outbound content.
     */
    private detectPrivateNetworkLeaks;
    /**
     * Detect role markers / prompt template artifacts in outbound content.
     * These should never appear in agent output — their presence indicates
     * injection artifact survival.
     */
    private detectOutputRoleMarkers;
    /**
     * Detect base64 strings, base64url, and zero-width character evasion.
     */
    private detectEncodingEvasion;
    /**
     * Detect URLs and emails in fields that shouldn't have them.
     */
    private detectDataExfiltration;
    /**
     * Detect prompt stuffing: very large strings or high repetition.
     */
    private detectPromptStuffing;
    /**
     * Determine if this field is inherently safe from role override.
     */
    private isSafeField;
    /**
     * Determine if this is a tool name field (where tool refs are expected).
     */
    private isToolNameField;
    /**
     * Determine if this field is safe for URLs.
     */
    private isUrlSafeField;
    /**
     * Determine if this field is safe for emails.
     */
    private isEmailSafeField;
    /**
     * Determine if this field is safe for structured data (JSON/XML).
     */
    private isStructuredField;
    /**
     * SEC-032/SEC-034: Map common cross-script confusable characters to their
     * Latin equivalents. NFKC normalization handles fullwidth and compatibility
     * forms, but does NOT map Cyrillic/Greek/Armenian/Georgian lookalikes to
     * Latin (they're distinct codepoints by design).
     *
     * Extended to 50+ confusable pairs covering Cyrillic, Greek, Armenian,
     * Georgian, Cherokee, and mathematical/symbol lookalikes.
     */
    private normalizeConfusables;
    /**
     * Compute confidence score based on signals.
     * More high-severity signals = higher confidence.
     */
    private computeConfidence;
    /**
     * Compute recommendation based on signals and sensitivity.
     */
    private computeRecommendation;
    /**
     * Get statistics about scans performed.
     */
    getStats(): {
        total_scans: number;
        total_flags: number;
        total_blocks: number;
        signals_by_type: Record<string, number>;
    };
    /**
     * Reset statistics.
     */
    resetStats(): void;
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

/** Callback invoked when an injection is detected, for dashboard broadcasting */
type InjectionAlertCallback = (alert: {
    toolName: string;
    result: DetectionResult;
    timestamp: string;
}) => void;
/** Resolver for proxy tool tiers — provided by the ProxyRouter */
type ProxyTierResolver = (toolName: string) => (1 | 2 | 3) | null;
declare class ApprovalGate {
    private policy;
    private baseline;
    private channel;
    private auditLog;
    private injectionDetector;
    private onInjectionAlert?;
    private proxyTierResolver?;
    constructor(policy: PrincipalPolicy, baseline: BaselineTracker, channel: ApprovalChannel, auditLog: AuditLog, injectionDetector?: InjectionDetector, onInjectionAlert?: InjectionAlertCallback);
    /**
     * Set the proxy tier resolver. Called after the proxy router is initialized.
     */
    setProxyTierResolver(resolver: ProxyTierResolver): void;
    /**
     * Evaluate a tool call against the Principal Policy.
     *
     * @param toolName - Full MCP tool name (e.g., "state_export")
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
    /** Get the injection detector for stats/configuration access */
    getInjectionDetector(): InjectionDetector;
}

/**
 * Sanctuary MCP Server — Tool Router
 *
 * Routes sanctuary/* tool calls to their layer-specific handlers.
 * Every tool call passes through schema validation and the ApprovalGate
 * (if configured) before execution. Neither can be bypassed.
 *
 * This module is the abstraction boundary for MCP SDK version migration —
 * if the SDK API changes, only this module needs updating.
 */

/** Tool handler function signature */
type ToolHandler = (args: Record<string, unknown>) => Promise<{
    content: Array<{
        type: "text";
        text: string;
    }>;
}>;
/** Tool definition for registration */
interface ToolDefinition {
    name: string;
    description: string;
    inputSchema: Record<string, unknown>;
    handler: ToolHandler;
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
    import(bundleBase64: string, conflictResolution: "skip" | "overwrite" | "version" | undefined, publicKeyResolver: (kid: string) => Uint8Array | null): Promise<{
        imported_keys: number;
        skipped_keys: number;
        skipped_invalid_sig: number;
        skipped_unknown_kid: number;
        conflicts: number;
        namespaces: string[];
        imported_at: string;
    }>;
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
    private metadataKey;
    constructor(storage: StorageBackend, masterKey: Uint8Array);
    private get encryptionKey();
    /** Load identities from storage on startup.
     *  Returns { total: number of encrypted files found, loaded: number successfully decrypted }.
     *  A mismatch (total > 0, loaded === 0) indicates a wrong master key / missing passphrase.
     */
    load(): Promise<{
        total: number;
        loaded: number;
        failed: number;
    }>;
    /** Save an identity to storage */
    save(identity: StoredIdentity): Promise<void>;
    /** Set which identity is the default/primary identity */
    setPrimary(identityId: string): Promise<boolean>;
    /** Persist the primary identity ID to storage */
    private savePrimaryIdentityId;
    get(id: string): StoredIdentity | undefined;
    getDefault(): StoredIdentity | undefined;
    getPrimaryIdentityId(): string | null;
    list(): PublicIdentity[];
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
 * Sanctuary MCP Server — L3 Selective Disclosure: Zero-Knowledge Proofs
 *
 * Upgrades the commitment-only L3 to support real zero-knowledge proofs.
 * Uses Ristretto255 (prime-order curve group, no cofactor issues) for:
 *
 *   1. Pedersen commitments: C = v*G + b*H (computationally hiding, perfectly binding)
 *   2. ZK proof of knowledge: Schnorr sigma protocol via Fiat-Shamir
 *   3. ZK range proofs: Prove value ∈ [min, max] without revealing it
 *
 * Ristretto255 is available via @noble/curves/ed25519, which we already depend on.
 * This is genuine zero-knowledge — proofs reveal nothing beyond the stated property.
 *
 * Architecture note:
 * The existing commitment scheme (SHA-256 based) remains available for backward
 * compatibility. The ZK proofs operate on a separate Pedersen commitment system
 * that provides algebraic structure for proper ZK properties.
 *
 * Security invariants:
 * - Generator H is derived via hash-to-curve (nothing-up-my-sleeve)
 * - Blinding factors are cryptographically random (32 bytes)
 * - Fiat-Shamir challenges use domain-separated hashing
 * - Range proofs use a bit-decomposition approach (sound but logarithmic size)
 */
/** A Pedersen commitment: C = v*G + b*H */
interface PedersenCommitment {
    /** The commitment point (encoded as base64url) */
    commitment: string;
    /** The blinding factor b (base64url, 32 bytes) — keep secret */
    blinding_factor: string;
    /** When the commitment was created */
    committed_at: string;
}
/** A non-interactive ZK proof of knowledge of a commitment's opening */
interface ZKProofOfKnowledge {
    /** Proof type identifier */
    type: "schnorr-pedersen-ristretto255";
    /** The commitment this proof is for */
    commitment: string;
    /** Announcement point R (base64url) */
    announcement: string;
    /** Response scalar s_v (base64url) */
    response_v: string;
    /** Response scalar s_b (base64url) */
    response_b: string;
    /** Proof generated at */
    generated_at: string;
}
/** A ZK range proof: proves value ∈ [min, max] */
interface ZKRangeProof {
    /** Proof type identifier */
    type: "range-pedersen-ristretto255";
    /** The commitment this proof is for */
    commitment: string;
    /** Minimum value (inclusive) */
    min: number;
    /** Maximum value (inclusive) */
    max: number;
    /** Bit commitments for the shifted value (v - min) */
    bit_commitments: string[];
    /** Proofs that each bit commitment is 0 or 1 */
    bit_proofs: Array<{
        announcement_0: string;
        announcement_1: string;
        challenge_0: string;
        challenge_1: string;
        response_0: string;
        response_1: string;
    }>;
    /** Sum proof: bit commitments sum to the value commitment */
    sum_proof: {
        announcement: string;
        response: string;
    };
    /** Proof generated at */
    generated_at: string;
}
/**
 * Create a Pedersen commitment to a numeric value.
 *
 * C = v*G + b*H
 *
 * Properties:
 * - Computationally hiding (under discrete log assumption)
 * - Perfectly binding (information-theoretic)
 * - Homomorphic: C(v1) + C(v2) = C(v1+v2) with adjusted blinding
 *
 * @param value - The value to commit to (integer)
 * @returns The commitment and blinding factor
 */
declare function createPedersenCommitment(value: number): PedersenCommitment;
/**
 * Verify a Pedersen commitment against a revealed value and blinding factor.
 *
 * Recomputes C' = v*G + b*H and checks C' == C.
 */
declare function verifyPedersenCommitment(commitment: string, value: number, blindingFactor: string): boolean;
/**
 * Create a non-interactive ZK proof that you know the opening (v, b)
 * of a Pedersen commitment C = v*G + b*H.
 *
 * Schnorr sigma protocol with Fiat-Shamir transform:
 *   1. Pick random r_v, r_b
 *   2. Compute R = r_v*G + r_b*H (announcement)
 *   3. Compute e = H_FS(C || R) (challenge via Fiat-Shamir)
 *   4. Compute s_v = r_v + e*v, s_b = r_b + e*b (responses)
 *   5. Proof = (R, s_v, s_b)
 *
 * Zero-knowledge: the transcript (R, e, s_v, s_b) can be simulated
 * without knowing (v, b), so it reveals nothing.
 *
 * @param value - The committed value
 * @param blindingFactor - The blinding factor (base64url)
 * @param commitment - The commitment (base64url)
 */
declare function createProofOfKnowledge(value: number, blindingFactor: string, commitment: string): ZKProofOfKnowledge;
/**
 * Verify a ZK proof of knowledge of a commitment's opening.
 *
 * Check: s_v*G + s_b*H == R + e*C
 */
declare function verifyProofOfKnowledge(proof: ZKProofOfKnowledge): boolean;
/**
 * Create a ZK range proof: prove value ∈ [min, max] without revealing value.
 *
 * Approach: bit-decomposition of (value - min) into n bits where 2^n > max - min.
 * Each bit gets a Pedersen commitment and a proof it's 0 or 1.
 * A sum proof shows the bit commitments reconstruct the original commitment
 * (shifted by min).
 *
 * @param value - The committed value
 * @param blindingFactor - The blinding factor (base64url)
 * @param commitment - The commitment (base64url)
 * @param min - Minimum value (inclusive)
 * @param max - Maximum value (inclusive)
 */
declare function createRangeProof(value: number, blindingFactor: string, commitment: string, min: number, max: number): ZKRangeProof | {
    error: string;
};
/**
 * Verify a ZK range proof.
 */
declare function verifyRangeProof(proof: ZKRangeProof): boolean;

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
    /** Model provenance: what inference model(s) power this agent */
    model_provenance?: {
        model_id: string;
        model_name: string;
        provider: string;
        open_weights: boolean;
        open_source: boolean;
        local_inference: boolean;
        weights_hash?: string;
    };
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
    implementation: {
        sanctuary_version: string;
        node_version: string;
        generated_by: string;
    };
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
 * Sanctuary MCP Server — Sovereignty-Gated Reputation Tiers
 *
 * Attestations carry a sovereignty_tier field reflecting the signer's
 * sovereignty posture at the time of recording. When querying or evaluating
 * reputation, attestations from verified-sovereign agents carry more weight
 * than those from unverified agents.
 *
 * Tier hierarchy (descending credibility):
 *   1. "verified-sovereign"  — signer completed a handshake with full sovereignty
 *   2. "verified-degraded"   — signer completed a handshake with degraded sovereignty
 *   3. "self-attested"       — signer has a Sanctuary identity but no handshake verification
 *   4. "unverified"          — no Sanctuary identity or sovereignty proof
 *
 * Weight multipliers are applied during reputation scoring. They are NOT
 * gatekeeping — unverified attestations still count, just less.
 */

type SovereigntyTier = "verified-sovereign" | "verified-degraded" | "self-attested" | "unverified";
/** Weight multipliers for each tier */
declare const TIER_WEIGHTS: Record<SovereigntyTier, number>;
/** Tier metadata embedded in attestations */
interface TierMetadata {
    sovereignty_tier: SovereigntyTier;
    /** If verified, the handshake that established it */
    handshake_completed_at?: string;
    /** Counterparty ID from handshake (if applicable) */
    verified_by?: string;
}
/**
 * Resolve the sovereignty tier for a counterparty based on handshake history.
 *
 * @param counterpartyId - The counterparty's instance ID
 * @param handshakeResults - Map of counterparty ID → most recent handshake result
 * @param hasSanctuaryIdentity - Whether the counterparty has a known Sanctuary identity
 * @returns TierMetadata for embedding in attestations
 */
declare function resolveTier(counterpartyId: string, handshakeResults: Map<string, HandshakeResult>, hasSanctuaryIdentity: boolean): TierMetadata;
/** An attestation with its tier for weighted scoring */
interface TieredAttestation {
    /** The raw metric value */
    value: number;
    /** The sovereignty tier of the attestation signer */
    tier: SovereigntyTier;
}
/**
 * Compute a weighted reputation score from tiered attestations.
 *
 * Each attestation's contribution is multiplied by its tier weight.
 * The result is normalized by total weight (not count), so adding
 * low-tier attestations doesn't dilute high-tier ones.
 *
 * @param attestations - Array of value + tier pairs
 * @returns Weighted score, or null if no attestations
 */
declare function computeWeightedScore(attestations: TieredAttestation[]): number | null;
/**
 * Compute a tier distribution summary for a set of attestations.
 */
declare function tierDistribution(tiers: SovereigntyTier[]): Record<SovereigntyTier, number>;

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
        /** Sovereignty tier of the signer at time of recording */
        sovereignty_tier?: SovereigntyTier;
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
    record(interactionId: string, counterpartyDid: string, outcome: InteractionOutcome, context: string, identity: StoredIdentity, identityEncryptionKey: Uint8Array, counterpartyAttestation?: string, sovereigntyTier?: SovereigntyTier): Promise<StoredAttestation>;
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
    /**
     * Load attestations for tier-weighted scoring.
     * Applies basic context/counterparty filtering, returns full StoredAttestations
     * so callers can access sovereignty_tier from attestation data.
     */
    loadAllForTierScoring(options?: {
        context?: string;
        counterparty_did?: string;
    }): Promise<StoredAttestation[]>;
    private loadAll;
}

/**
 * Sanctuary MCP Server — Federation Types
 *
 * MCP-to-MCP federation enables two Sanctuary instances to:
 *   1. Discover each other's capabilities (SIM exchange)
 *   2. Establish mutual trust (sovereignty handshake)
 *   3. Exchange signed reputation attestations
 *   4. Evaluate trust for cross-instance interactions
 *
 * Federation operates as a protocol layer atop the handshake:
 *   Handshake establishes trust → Federation uses that trust for ongoing operations.
 *
 * Key constraint: Federation MUST respect each party's sovereignty.
 * Neither party can compel the other to share data they haven't disclosed
 * via their disclosure policy.
 */

/** A known federation peer */
interface FederationPeer {
    /** The peer's instance ID (from their SHR) */
    peer_id: string;
    /** The peer's DID (identity) */
    peer_did: string;
    /** When this peer was first seen */
    first_seen: string;
    /** When last handshake completed */
    last_handshake: string;
    /** Current trust tier from most recent handshake */
    trust_tier: SovereigntyTier;
    /** Handshake result (for tier resolution) */
    handshake_result: HandshakeResult;
    /** Peer's advertised capabilities (from their SIM) */
    capabilities: FederationCapabilities;
    /** Whether we have a valid (non-expired) handshake */
    active: boolean;
}
/** Capabilities a peer advertises for federation */
interface FederationCapabilities {
    /** Whether the peer supports reputation exchange */
    reputation_exchange: boolean;
    /** Whether the peer supports mutual attestation */
    mutual_attestation: boolean;
    /** Whether the peer supports encrypted channels */
    encrypted_channel: boolean;
    /** Supported attestation formats */
    attestation_formats: string[];
}
/** Trust evaluation result for a federation peer */
interface PeerTrustEvaluation {
    peer_id: string;
    /** Current sovereignty tier (from handshake) */
    sovereignty_tier: SovereigntyTier;
    /** Whether handshake is current (not expired) */
    handshake_current: boolean;
    /** Reputation summary (if available) */
    reputation_score?: number;
    /** How many mutual attestations we share */
    mutual_attestation_count: number;
    /** Overall trust assessment */
    trust_level: "high" | "medium" | "low" | "none";
    /** Reasoning for the assessment */
    factors: string[];
    /** Evaluated at */
    evaluated_at: string;
}

/**
 * Sanctuary MCP Server — Federation Peer Registry
 *
 * Manages known federation peers. Peers are discovered through handshakes
 * and tracked for ongoing federation operations.
 *
 * The registry is the source of truth for:
 * - Who we've federated with
 * - Current trust status of each peer
 * - Peer capabilities (what operations they support)
 *
 * Security invariants:
 * - Peers are ONLY added through completed handshakes (not self-registration)
 * - Trust tiers degrade automatically when handshakes expire
 * - Peer data is stored encrypted under L1 sovereignty
 */

declare class FederationRegistry {
    private peers;
    /**
     * Register or update a peer from a completed handshake.
     * This is the ONLY way peers enter the registry.
     */
    registerFromHandshake(result: HandshakeResult, peerDid: string, capabilities?: Partial<FederationCapabilities>): FederationPeer;
    /**
     * Get a peer by instance ID.
     * Automatically updates active status based on handshake expiry.
     */
    getPeer(peerId: string): FederationPeer | null;
    /**
     * List all known peers, optionally filtered by status.
     */
    listPeers(filter?: {
        active_only?: boolean;
    }): FederationPeer[];
    /**
     * Evaluate trust for a federation peer.
     *
     * Trust assessment considers:
     * - Handshake status (current vs expired)
     * - Sovereignty tier (verified-sovereign vs degraded vs unverified)
     * - Reputation data (if available)
     * - Mutual attestation history
     */
    evaluateTrust(peerId: string, mutualAttestationCount?: number, reputationScore?: number): PeerTrustEvaluation;
    /**
     * Remove a peer from the registry.
     */
    removePeer(peerId: string): boolean;
    /**
     * Get the handshake results map (for tier resolution integration).
     */
    getHandshakeResults(): Map<string, HandshakeResult>;
}

/**
 * Sanctuary MCP Server — L2 Operational Isolation: Context Gating
 *
 * Context gating controls what information leaves the sovereignty boundary
 * when an agent makes outbound calls — especially inference calls to remote
 * LLM providers. This is the "minimum-necessary context" enforcement layer.
 *
 * The problem: When an agent sends a request to a remote LLM provider (Claude,
 * GPT, etc.), most harnesses send the agent's full context — conversation
 * history, memory, tool results, preferences, internal reasoning. The agent
 * has no control over what the provider sees.
 *
 * Context gating lets the agent define:
 * - Provider categories (inference, tool-api, logging, analytics, etc.)
 * - What fields/categories of context may flow to each provider type
 * - What must always be redacted (secrets, internal reasoning, PII, etc.)
 * - What requires transformation (hashing, summarizing, anonymizing)
 *
 * This sits in L2 (Operational Isolation) because it controls information
 * flow at the execution boundary. L3 (Selective Disclosure) handles agent-
 * to-agent trust negotiation with cryptographic proofs; context gating
 * handles agent-to-infrastructure information flow.
 *
 * Security invariants:
 * - Redact rules take absolute priority (like withhold in L3)
 * - Policies are stored encrypted under L1 sovereignty
 * - Every filter operation is audit-logged with a content hash
 *   (what was sent, what was redacted — without storing the content itself)
 * - Default policy: redact everything not explicitly allowed
 */

/** Provider categories that context may flow to */
type ProviderCategory = "inference" | "tool-api" | "logging" | "analytics" | "peer-agent" | "custom";
/** Actions that can be taken on a context field */
type ContextAction = "allow" | "redact" | "hash" | "summarize" | "deny";
/** A rule within a context-gating policy */
interface ContextGateRule {
    /** Provider category this rule applies to */
    provider: ProviderCategory | "*";
    /** Fields/patterns that may pass through */
    allow: string[];
    /** Fields/patterns that must be redacted (highest priority) */
    redact: string[];
    /** Fields/patterns that should be hashed */
    hash: string[];
    /** Fields/patterns that should be summarized (advisory) */
    summarize: string[];
}
/** A complete context-gating policy */
interface ContextGatePolicy {
    policy_id: string;
    policy_name: string;
    rules: ContextGateRule[];
    /** Default action when no rule matches a field */
    default_action: "redact" | "deny";
    /** Identity this policy is bound to (optional) */
    identity_id?: string;
    created_at: string;
    updated_at: string;
}
/** Result of filtering a single field */
interface FieldFilterResult {
    field: string;
    action: ContextAction;
    reason: string;
    /** If action is "hash", contains the hash */
    hash_value?: string;
}
/** Result of a full context filter operation */
interface ContextFilterResult {
    policy_id: string;
    provider: ProviderCategory | string;
    fields_allowed: number;
    fields_redacted: number;
    fields_hashed: number;
    fields_summarized: number;
    fields_denied: number;
    decisions: FieldFilterResult[];
    /** SHA-256 hash of the original context (for audit trail) */
    original_context_hash: string;
    /** SHA-256 hash of the filtered output (for audit trail) */
    filtered_context_hash: string;
    filtered_at: string;
}
/**
 * Evaluate a context field against a policy for a given provider.
 *
 * Priority order (same as L3 disclosure):
 * 1. Redact (blocks — highest priority)
 * 2. Deny (blocks entire request)
 * 3. Hash (transforms)
 * 4. Summarize (advisory transform)
 * 5. Allow (passes through)
 * 6. Default action
 */
declare function evaluateField(policy: ContextGatePolicy, provider: ProviderCategory | string, field: string): FieldFilterResult;
/**
 * Filter a full context object against a policy for a given provider.
 * Returns per-field decisions and content hashes for the audit trail.
 */
declare function filterContext(policy: ContextGatePolicy, provider: ProviderCategory | string, context: Record<string, unknown>): ContextFilterResult;
/**
 * Context gate policy store — encrypted under L1 sovereignty.
 */
declare class ContextGatePolicyStore {
    private storage;
    private encryptionKey;
    private policies;
    constructor(storage: StorageBackend, masterKey: Uint8Array);
    /**
     * Create and store a new context-gating policy.
     */
    create(policyName: string, rules: ContextGateRule[], defaultAction: "redact" | "deny", identityId?: string): Promise<ContextGatePolicy>;
    /**
     * Get a policy by ID.
     */
    get(policyId: string): Promise<ContextGatePolicy | null>;
    /**
     * List all context-gating policies.
     */
    list(): Promise<ContextGatePolicy[]>;
    /**
     * Load all persisted policies into memory.
     */
    private loadAll;
    private persist;
}

/**
 * Sanctuary MCP Server — L2 Context Gating: Starter Policy Templates
 *
 * Pre-built policies for common use cases. These are starting points —
 * users should customize them for their specific context structure.
 *
 * Templates:
 *
 *   inference-minimal
 *     Only the current task and query reach the LLM. Everything else
 *     is redacted. Secrets, PII, memory, reasoning, and history are
 *     all blocked. IDs are hashed. Maximum privacy, minimum context.
 *
 *   inference-standard
 *     Task, query, and tool results pass through. Conversation history
 *     is flagged for summarization (compress before sending). Secrets,
 *     PII, and internal reasoning are redacted. IDs are hashed.
 *     Balanced: the LLM has enough context to be useful without seeing
 *     everything the agent knows.
 *
 *   logging-strict
 *     Redacts everything for logging/analytics providers. Only
 *     operation names and timestamps pass through. Use this for
 *     telemetry services where you want usage metrics without
 *     content exposure.
 *
 *   tool-api-scoped
 *     Allows tool-specific parameters and the current task, redacts
 *     memory, history, secrets, and PII. Hashes IDs. For outbound
 *     calls to external APIs (search, database, etc.) where you need
 *     to send query parameters but not your agent's full state.
 */

/** A template definition ready to be applied via the policy store */
interface ContextGateTemplate {
    /** Machine-readable template ID */
    id: string;
    /** Human-readable name */
    name: string;
    /** One-line description */
    description: string;
    /** When to use this template */
    use_when: string;
    /** The rules that make up this template */
    rules: ContextGateRule[];
    /** Default action for unmatched fields */
    default_action: "redact" | "deny";
}
/** All available templates, keyed by ID */
declare const TEMPLATES: Record<string, ContextGateTemplate>;
/** List all available template IDs */
declare function listTemplateIds(): string[];
/** Get a template by ID (returns undefined if not found) */
declare function getTemplate(id: string): ContextGateTemplate | undefined;

/**
 * Sanctuary MCP Server — L2 Context Gating: Policy Recommendation Engine
 *
 * Analyzes a sample context object and recommends a context-gating policy
 * based on field name heuristics. The agent (or human) can then review,
 * adjust, and apply the recommendation.
 *
 * This is deliberately conservative: when in doubt, it recommends redact.
 * A false redaction is a usability issue; a false allow is a privacy leak.
 *
 * Classification heuristics:
 * - Known secret patterns → redact (highest confidence)
 * - Known PII patterns → redact (high confidence)
 * - Known internal state patterns → redact (high confidence)
 * - Known ID patterns → hash (medium confidence)
 * - Known history patterns → summarize (medium confidence)
 * - Known task/query patterns → allow (medium confidence)
 * - Everything else → redact (conservative default)
 *
 * WARNING: Fields like 'tool_results' and 'tool_output' are classified as
 * "allow" (medium confidence) but may contain sensitive data from external
 * API responses, including auth tokens, user data, or PII. Always review
 * recommendations before applying — the heuristic classifies by field NAME,
 * not field CONTENT.
 */
/** Classification result for a single field */
interface FieldClassification {
    field: string;
    recommended_action: "allow" | "redact" | "hash" | "summarize";
    reason: string;
    confidence: "high" | "medium" | "low";
    /** Pattern that matched, if any */
    matched_pattern: string | null;
}
/** Full recommendation result */
interface PolicyRecommendation {
    provider: string;
    classifications: FieldClassification[];
    recommended_rules: {
        allow: string[];
        redact: string[];
        hash: string[];
        summarize: string[];
    };
    default_action: "redact";
    summary: {
        total_fields: number;
        allow: number;
        redact: number;
        hash: number;
        summarize: number;
    };
    warnings: string[];
}
/**
 * Classify a single field name and return a recommendation.
 */
declare function classifyField(fieldName: string): FieldClassification;
/**
 * Analyze a full context object and recommend a policy.
 */
declare function recommendPolicy(context: Record<string, unknown>, provider?: string): PolicyRecommendation;

/**
 * Sanctuary MCP Server — L2 Model Provenance
 *
 * Declares and attests to the model(s) powering this agent.
 *
 * Vitalik Buterin's "Secure LLM" post (April 2026) identified a critical gap:
 * open-weights-but-not-open-source models can have trained-in backdoors. Model
 * provenance declaration lets agents and their operators verify the integrity
 * of the inference backbone.
 *
 * Tracks: model name, version, weights hash, license, open-source status,
 * training data hash (if available). Included in SHR L2 section.
 *
 * This sits in L2 (Operational Isolation) because it's part of the runtime
 * attestation surface — the agent declares what model(s) it's actually running.
 */
/**
 * Metadata about a single model powering this agent.
 */
interface ModelProvenance {
    /** Machine-readable model ID (e.g., "qwen3.5-35b", "claude-opus-4", "llama-3.3-70b-instruct") */
    model_id: string;
    /** Human-readable model name (e.g., "Qwen 3.5", "Claude Opus 4", "Llama 3.3 70B Instruct") */
    model_name: string;
    /** Semantic version (e.g., "3.5", "4.0", "3.3") */
    model_version: string;
    /** Provider/vendor (e.g., "Alibaba Cloud", "Anthropic", "Meta", "local") */
    provider: string;
    /** SHA-256 of model weights file, if available and verifiable */
    weights_hash?: string;
    /** SHA-256 of training data manifest or metadata, if available */
    training_data_hash?: string;
    /** License identifier (e.g., "Apache-2.0", "CC-BY-4.0", "proprietary", "unknown") */
    license: string;
    /** True if model weights are publicly available (even if training is proprietary) */
    open_weights: boolean;
    /** True if full training code, data, and methodology are publicly available */
    open_source: boolean;
    /** True if inference runs on the local agent's hardware (not delegated to cloud API) */
    local_inference: boolean;
    /** ISO 8601 timestamp when this provenance was declared */
    declared_at: string;
}
/**
 * In-memory and persistent store for model provenance declarations.
 * Declarations are encrypted under L1 sovereignty.
 */
interface ModelProvenanceStore {
    /**
     * Declare a model's provenance and add it to the store.
     */
    declare(provenance: ModelProvenance): void;
    /**
     * Retrieve a model's provenance by ID.
     */
    get(model_id: string): ModelProvenance | undefined;
    /**
     * List all declared models.
     */
    list(): ModelProvenance[];
    /**
     * Get the primary/main model (the one the agent uses by default for inference).
     */
    primary(): ModelProvenance | undefined;
    /**
     * Set which model is the primary.
     */
    setPrimary(model_id: string): void;
}
/**
 * In-memory implementation of ModelProvenanceStore.
 * Suitable for most use cases. For encrypted persistence, integrate with L1 state store.
 */
declare class InMemoryModelProvenanceStore implements ModelProvenanceStore {
    private models;
    private primaryModelId;
    declare(provenance: ModelProvenance): void;
    get(model_id: string): ModelProvenance | undefined;
    list(): ModelProvenance[];
    primary(): ModelProvenance | undefined;
    setPrimary(model_id: string): void;
}
/**
 * Common model provenance presets for quick initialization.
 */
declare const MODEL_PRESETS: {
    /**
     * Claude Opus 4 via Anthropic API (cloud inference, closed weights/source)
     */
    claudeOpus4: () => ModelProvenance;
    /**
     * Qwen 3.5 via local inference (open weights, proprietary training)
     */
    qwen35Local: () => ModelProvenance;
    /**
     * Llama 3.3 70B via local inference (open weights and code)
     */
    llama33Local: () => ModelProvenance;
    /**
     * Mistral 7B (open weights, open code, local inference)
     */
    mistral7bLocal: () => ModelProvenance;
};

/**
 * Sanctuary MCP Server — L2 Context Gating: Automatic Enforcer
 *
 * The context gate enforcer wraps tool handlers to automatically filter
 * their arguments before execution. Unlike context_gate_filter (which agents
 * call voluntarily), the enforcer runs automatically on every tool call
 * when enabled.
 *
 * This enforces minimum-necessary-context by default and makes bypassing
 * context protection explicit (requires reconfiguration).
 *
 * Security invariants:
 * - The enforcer wraps every tool handler when enabled
 * - Filtering decisions are audit-logged
 * - Default action on missing policy: fallback to built-in sensitive patterns
 * - Denied fields block the entire request (with logged reason)
 * - Redacted fields are stripped from tool arguments
 * - log_only mode logs what would be filtered but passes original args
 */

interface EnforcerConfig {
    /** Enable/disable automatic filtering (default: true) */
    enabled: boolean;
    /** Policy ID to use when no specific one is set */
    default_policy_id?: string;
    /** Tool name prefixes to skip filtering (e.g., ["*"] to skip all system tools) */
    bypass_prefixes: string[];
    /** Log but don't filter — for gradual rollout (default: false) */
    log_only: boolean;
    /** What to do when a field triggers deny action: "block" or "redact" */
    on_deny: "block" | "redact";
}
interface EnforcerStatus {
    enabled: boolean;
    log_only: boolean;
    default_policy_id: string | null;
    stats: {
        calls_inspected: number;
        calls_bypassed: number;
        fields_redacted: number;
        fields_hashed: number;
        fields_blocked: number;
        calls_blocked: number;
    };
}
declare class ContextGateEnforcer {
    private policyStore;
    private auditLog;
    private config;
    private stats;
    constructor(policyStore: ContextGatePolicyStore, auditLog: AuditLog, config: EnforcerConfig);
    /**
     * Wrap a tool handler to apply automatic context gating.
     *
     * The wrapped handler:
     * 1. Checks if tool should be filtered (based on bypass_prefixes)
     * 2. If not filtering, calls original handler directly
     * 3. If filtering:
     *    a. Gets the active policy or falls back to built-in patterns
     *    b. Calls filterContext() with tool arguments
     *    c. If any field triggered "deny" and on_deny is "block", returns error
     *    d. If on_deny is "redact", replaces denied fields with "[REDACTED]"
     *    e. Calls original handler with filtered arguments
     *    f. Logs the filtering decision
     * 4. In log_only mode: runs filter, logs what would happen, passes original args
     */
    wrapHandler(toolName: string, originalHandler: ToolHandler): ToolHandler;
    /**
     * Filter tool arguments using an explicit policy.
     */
    private filterWithPolicy;
    /**
     * Filter tool arguments using built-in sensitive patterns.
     * This provides baseline protection when no explicit policy is configured.
     */
    private filterWithBuiltinPatterns;
    /**
     * Check if a tool should be filtered based on bypass prefixes.
     *
     * SEC-033: Uses exact namespace component matching, not bare startsWith().
     * A prefix of "proxy/" matches "proxy/server/tool" but NOT "proxyevil/steal".
     * The prefix must match exactly up to its length, and the prefix must end
     * with "/" to enforce namespace boundaries (if it doesn't, we add one).
     *
     * Special sentinel: "*" bypasses ALL tools (used when all Sanctuary-internal
     * tools should skip context gating — the default). Only proxy/external tools
     * should be filtered in production.
     */
    shouldFilter(toolName: string): boolean;
    /**
     * Extract provider category from tool name.
     * Default: "tool-api". Override for specific patterns.
     */
    private extractProviderCategory;
    /**
     * Build filtered arguments from filter decisions.
     */
    private buildFilteredArgs;
    /**
     * Set the active policy ID.
     */
    setDefaultPolicy(policyId: string): void;
    /**
     * Get current enforcer status and stats.
     */
    getStatus(): EnforcerStatus;
    /**
     * Toggle enforcer enabled state.
     */
    setEnabled(enabled: boolean): void;
    /**
     * Toggle log_only mode.
     */
    setLogOnly(logOnly: boolean): void;
    /**
     * Reset stats counters.
     */
    resetStats(): void;
}

/**
 * Sanctuary MCP Server — Sovereignty Profile
 *
 * Encrypted store for the sovereignty profile configuration.
 * Controls which Sanctuary features are active and how they behave.
 *
 * The profile is stored encrypted in a reserved namespace (_sovereignty_profile)
 * using AES-256-GCM with HKDF domain separation, following the same pattern
 * as ContextGatePolicyStore.
 *
 * Security invariants:
 * - Profile is stored in a reserved namespace (underscore-prefixed)
 * - L1 state tools cannot read or write reserved namespaces
 * - Profile changes only come through dedicated profile tools (Tier 1)
 *   or the dashboard
 * - All changes are audit-logged
 */

interface UpstreamServer {
    name: string;
    transport: {
        type: "stdio" | "sse";
        command?: string;
        args?: string[];
        url?: string;
        env?: Record<string, string>;
    };
    enabled: boolean;
    default_tier: 1 | 2 | 3;
    tool_overrides?: Record<string, {
        tier: 1 | 2 | 3;
    }>;
}
interface SovereigntyProfile {
    version: 1;
    features: {
        audit_logging: {
            enabled: boolean;
        };
        injection_detection: {
            enabled: boolean;
            sensitivity?: "low" | "medium" | "high";
        };
        context_gating: {
            enabled: boolean;
            policy_id?: string;
        };
        approval_gate: {
            enabled: true;
        };
        zk_proofs: {
            enabled: boolean;
        };
    };
    upstream_servers?: UpstreamServer[];
    updated_at: string;
}
/** Partial feature update — all fields optional */
interface SovereigntyProfileUpdate {
    audit_logging?: {
        enabled?: boolean;
    };
    injection_detection?: {
        enabled?: boolean;
        sensitivity?: "low" | "medium" | "high";
    };
    context_gating?: {
        enabled?: boolean;
        policy_id?: string;
    };
    approval_gate?: {
        enabled?: true;
    };
    zk_proofs?: {
        enabled?: boolean;
    };
    upstream_servers?: UpstreamServer[];
}
declare function createDefaultProfile(): SovereigntyProfile;
/**
 * Sovereignty profile store — encrypted under L1 sovereignty.
 *
 * Stores the active sovereignty profile in a reserved namespace.
 * On first load, creates the default profile automatically.
 */
declare class SovereigntyProfileStore {
    private storage;
    private encryptionKey;
    private profile;
    constructor(storage: StorageBackend, masterKey: Uint8Array);
    /**
     * Load the active sovereignty profile from encrypted storage.
     * Creates the default profile on first run.
     */
    load(): Promise<SovereigntyProfile>;
    /**
     * Get the current profile. Must call load() first.
     */
    get(): SovereigntyProfile;
    /**
     * Apply a partial update to the profile.
     * Returns the updated profile.
     */
    update(updates: SovereigntyProfileUpdate): Promise<SovereigntyProfile>;
    /**
     * Persist the current profile to encrypted storage.
     */
    private persist;
}

/**
 * Sanctuary MCP Server — Proxy Client Manager
 *
 * Manages MCP client connections to upstream servers. Handles connection
 * lifecycle, reconnection with exponential backoff, and tool discovery.
 *
 * Security invariants:
 * - Upstream servers are configured via the sovereignty profile (Tier 1 gated)
 * - Connection failures do not block Sanctuary startup
 * - Tool discovery is re-run on every successful reconnection
 * - Environment variables for upstream transports are passed through, not stored in logs
 */

type ConnectionState = "disconnected" | "connecting" | "connected" | "error";
interface UpstreamTool {
    name: string;
    description: string;
    inputSchema: Record<string, unknown>;
}
interface UpstreamConnection {
    server: UpstreamServer;
    client: Client | null;
    transport: StdioClientTransport | SSEClientTransport | null;
    state: ConnectionState;
    tools: UpstreamTool[];
    error?: string;
    retryCount: number;
    retryTimer?: ReturnType<typeof setTimeout>;
}
/** Callback for state changes */
type ConnectionStateCallback = (serverName: string, state: ConnectionState, toolCount: number, error?: string) => void;
declare class ClientManager {
    private connections;
    private onStateChange?;
    private shutdownRequested;
    constructor(options?: {
        onStateChange?: ConnectionStateCallback;
    });
    /**
     * Configure upstream servers. Disconnects removed servers, connects new ones.
     * Non-blocking — connection failures are handled asynchronously.
     */
    configure(servers: UpstreamServer[]): Promise<void>;
    /**
     * Get all discovered tools across all connected upstream servers.
     */
    getAllTools(): Map<string, UpstreamTool[]>;
    /**
     * Get connection status for all configured servers.
     */
    getStatus(): Array<{
        name: string;
        state: ConnectionState;
        transport_type: string;
        tool_count: number;
        error?: string;
    }>;
    /**
     * Get the upstream server config by name.
     */
    getServerConfig(name: string): UpstreamServer | undefined;
    /**
     * Call a tool on an upstream server.
     */
    callTool(serverName: string, toolName: string, args: Record<string, unknown>): Promise<{
        content: Array<{
            type: string;
            text?: string;
            [key: string]: unknown;
        }>;
    }>;
    /**
     * Shut down all connections cleanly.
     */
    shutdown(): Promise<void>;
    /**
     * Connect to an upstream server (non-blocking).
     * Spawns connection attempt in background — does not throw.
     */
    private connectServer;
    /**
     * Perform the actual connection to an upstream server.
     */
    private doConnect;
    /**
     * Discover tools from a connected upstream server.
     */
    private discoverTools;
    /**
     * Schedule a reconnection attempt with exponential backoff.
     */
    private scheduleRetry;
    /**
     * Disconnect a specific upstream server.
     */
    private disconnectServer;
    /**
     * Notify listener of state change.
     */
    private notifyStateChange;
}

/**
 * Sanctuary MCP Server — L2 Operational Isolation: Call Governor
 *
 * Runtime governance for proxied tool calls. Wraps the proxy forwarding
 * path with four enforcement mechanisms:
 *
 * 1. Volume limit — sliding-window cap on total tool calls
 * 2. Rate detection — per-tool call frequency check (loop detection)
 * 3. Duplicate detection — SHA-256 hash of tool+args, cache recent results
 * 4. Lifetime counter — hard stop after N total calls per session
 *
 * All state is in-memory. Resets on server restart.
 *
 * Security invariants:
 * - Governor cannot be bypassed — it sits in the enforcement chain
 * - Lifetime limit is a hard stop (requires reset or restart)
 * - Rate escalation triggers Tier 2 human approval
 * - Duplicate cache uses cryptographic hashing (SHA-256)
 */
interface GovernorConfig {
    /** Total calls allowed in the sliding volume window (default: 200) */
    volume_limit: number;
    /** Volume window size in milliseconds (default: 600000 = 10 min) */
    volume_window_ms: number;
    /** Per-tool calls allowed in the rate window before escalation (default: 20) */
    rate_limit: number;
    /** Rate window size in milliseconds (default: 60000 = 1 min) */
    rate_window_ms: number;
    /** Duplicate cache TTL in milliseconds (default: 60000 = 1 min) */
    duplicate_ttl_ms: number;
    /** Total calls before hard stop for the session (default: 1000) */
    lifetime_limit: number;
    /** Per-server config overrides keyed by server name */
    per_server_overrides?: Record<string, Partial<GovernorConfig>>;
}
interface GovernorCheckResult {
    /** Whether the call is allowed to proceed */
    allowed: boolean;
    /** Reason the call was blocked or flagged */
    reason?: "volume_exceeded" | "rate_exceeded" | "lifetime_exceeded" | "duplicate_cached";
    /** If duplicate, the cached response */
    cached_result?: unknown;
    /** If true, escalate to Tier 2 (human approval required) */
    escalate?: boolean;
}
interface GovernorStatus {
    /** Current call count in the volume window */
    volume_current: number;
    /** Volume limit from config */
    volume_limit: number;
    /** Total calls this session */
    lifetime_current: number;
    /** Lifetime limit from config */
    lifetime_limit: number;
    /** Per-tool call count in the current rate window */
    rate_by_tool: Record<string, number>;
    /** Number of entries in the duplicate cache */
    duplicate_cache_size: number;
    /** Whether the governor has been hard-stopped */
    hard_stopped: boolean;
}
declare class CallGovernor {
    private config;
    /** Sliding window of all call timestamps for volume tracking */
    private volumeWindow;
    /** Per-tool sliding window of call timestamps for rate tracking */
    private rateWindows;
    /** Duplicate cache: SHA-256(server+tool+args) -> cached result + expiry */
    private duplicateCache;
    /** Total calls this session */
    private lifetimeCount;
    /** Hard stop flag — set when lifetime limit is reached */
    private hardStopped;
    constructor(config?: Partial<GovernorConfig>);
    /**
     * Check if a call is allowed and apply governance.
     *
     * Evaluation order:
     * 1. Lifetime limit (hard stop — not recoverable without reset)
     * 2. Volume limit (sliding window)
     * 3. Rate limit per tool (escalates to Tier 2)
     * 4. Duplicate detection (returns cached result)
     */
    check(serverName: string, toolName: string, args: Record<string, unknown>): GovernorCheckResult;
    /**
     * Record a successful call result for duplicate caching.
     */
    recordResult(serverName: string, toolName: string, args: Record<string, unknown>, result: unknown): void;
    /**
     * Get current governor status for dashboard display.
     */
    getStatus(): GovernorStatus;
    /**
     * Reset all counters (Tier 1 — requires approval).
     * Clears volume window, rate windows, duplicate cache,
     * lifetime counter, and hard stop flag.
     */
    reset(): void;
    /**
     * Get the effective config for a given server, merging per-server overrides.
     */
    private getEffectiveConfig;
    /**
     * Compute a SHA-256 hash of server + tool + canonical args.
     * Used for duplicate detection.
     */
    private computeCallHash;
    /**
     * Deterministic JSON serialization with sorted keys.
     */
    private stableStringify;
    /**
     * Prune volume window entries older than the window size.
     * Uses shift() from the front — timestamps are appended in order.
     */
    private pruneVolumeWindow;
    /**
     * Prune a per-tool rate window.
     */
    private pruneRateWindow;
    /**
     * Prune expired entries from the duplicate cache.
     * Amortized O(1) — only prunes when cache exceeds a size threshold.
     */
    private pruneDuplicateCache;
}

/**
 * Sanctuary MCP Server — Proxy Router
 *
 * Routes proxied tool calls through the full Sanctuary enforcement chain:
 * injection detection, approval gate evaluation, context gating, and audit logging.
 *
 * Upstream tools are registered under the namespace `proxy/{server_name}/{tool_name}`.
 * This ensures no collision with native `sanctuary/*` tools and makes the provenance
 * of every tool call explicit.
 *
 * Security invariants:
 * - Every proxied call passes through injection scan + gate + audit (no bypass path)
 * - Denied calls return a generic denial message (same as native Sanctuary denials)
 * - Upstream errors are passed through to the agent unmodified
 * - Native sanctuary/* tools are never affected by the proxy layer
 */

interface ProxyRouterOptions {
    /** Optional callback when the context gate should filter arguments */
    contextGateFilter?: (toolName: string, args: Record<string, unknown>) => Promise<Record<string, unknown>>;
    /** Optional call governor for runtime governance */
    governor?: CallGovernor;
    /** Optional callback after each proxy call decision (for dashboard feed) */
    onProxyCall?: (data: {
        tool: string;
        server: string;
        decision: string;
        reason?: string;
        tier?: number;
        timestamp: string;
    }) => void;
}
declare class ProxyRouter {
    private clientManager;
    private injectionDetector;
    private auditLog;
    private options;
    constructor(clientManager: ClientManager, injectionDetector: InjectionDetector, auditLog: AuditLog, options?: ProxyRouterOptions);
    /**
     * Convert all discovered upstream tools to Sanctuary ToolDefinitions.
     * Each tool is registered as `proxy/{server_name}/{tool_name}`.
     */
    getProxiedTools(): ToolDefinition[];
    /**
     * Determine the tier for a proxied tool call.
     * Checks tool_overrides first, then falls back to default_tier.
     */
    getTierForTool(serverName: string, toolName: string): 1 | 2 | 3;
    /**
     * Parse a proxy tool name into server name and tool name.
     * Returns null if the name doesn't match the proxy namespace.
     */
    static parseProxyToolName(fullName: string): {
        serverName: string;
        toolName: string;
    } | null;
    /**
     * Create a handler for a specific proxied tool.
     * The handler runs the full enforcement chain before forwarding.
     */
    private createHandler;
    /**
     * Notify the onProxyCall callback if configured.
     */
    private notifyProxyCall;
    /**
     * Call an upstream tool with a timeout.
     */
    private callWithTimeout;
    /**
     * Normalize an upstream response to the standard Sanctuary response format.
     */
    private normalizeResponse;
}

/**
 * Sanctuary MCP Server — System Prompt Generator
 *
 * Pure function that takes a SovereigntyProfile and generates a system
 * prompt snippet instructing the agent on which Sanctuary features are
 * active and how to use them.
 *
 * The prompt is generic (not harness-specific) and intended to be pasted
 * into any agent's system configuration.
 */

/**
 * Generate a system prompt snippet from the active sovereignty profile.
 *
 * The output is a copy-pasteable text block that instructs the agent on
 * which Sanctuary features are active and how to interact with them.
 */
declare function generateSystemPrompt(profile: SovereigntyProfile): string;

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
 * Sanctuary MCP Server — Principal Dashboard
 *
 * HTTP-based approval channel that serves a real-time web dashboard
 * for human principals to approve/deny agent operations.
 *
 * Architecture:
 * - Node.js built-in `http`/`https` modules (no Express or external deps)
 * - SSE (Server-Sent Events) for real-time push to browser
 * - Pending approval requests block the MCP tool call via Promise
 * - Human clicks approve/deny in browser → POST /api/approve/:id → Promise resolves
 * - Timeout fallback: auto-deny (or auto-approve) if no response
 *
 * Security invariants:
 * - Binds to 127.0.0.1 by default (localhost only)
 * - Optional bearer token authentication for non-localhost deployments
 * - Optional TLS (HTTPS) via cert/key paths
 * - All decisions are audit-logged
 * - Agent cannot access the dashboard (it runs outside MCP stdin/stdout)
 */

interface DashboardConfig {
    port: number;
    host: string;
    timeout_seconds: number;
    /** SEC-002: auto_deny is always true. Field retained for interface compat but ignored. */
    auto_deny?: boolean;
    /** Bearer token for API authentication. If omitted, auth is disabled. */
    auth_token?: string;
    /** TLS configuration for HTTPS. If omitted, plain HTTP is used. */
    tls?: {
        cert_path: string;
        key_path: string;
    };
    /** Auto-open the dashboard in the default browser on startup. Default: true for localhost. */
    auto_open?: boolean;
}
declare class DashboardApprovalChannel implements ApprovalChannel {
    private config;
    private pending;
    private sseClients;
    private httpServer;
    private policy;
    private baseline;
    private auditLog;
    private identityManager;
    private handshakeResults;
    private shrOpts;
    private _sanctuaryConfig;
    private profileStore;
    private clientManager;
    private dashboardHTML;
    private fortressHTML;
    private loginHTML;
    private authToken;
    private useTLS;
    /** Session TTL: longer for localhost, shorter for remote */
    private sessionTTLMs;
    /** SEC-012: Short-lived session store. Sessions replace URL query tokens. */
    private sessions;
    private sessionCleanupTimer;
    /** Rate limiting: per-IP request tracking */
    private rateLimits;
    /** Whether the dashboard is running in standalone mode (no MCP server) */
    private _standaloneMode;
    constructor(config: DashboardConfig);
    /**
     * Inject dependencies after construction.
     * Called from index.ts after all components are initialized.
     */
    setDependencies(deps: {
        policy: PrincipalPolicy;
        baseline: BaselineTracker;
        auditLog: AuditLog;
        identityManager?: IdentityManager;
        handshakeResults?: Map<string, HandshakeResult>;
        shrOpts?: SHRGeneratorOptions;
        sanctuaryConfig?: SanctuaryConfig;
        profileStore?: SovereigntyProfileStore;
        clientManager?: ClientManager;
    }): void;
    /**
     * Mark this dashboard as running in standalone mode.
     * Exposed via /api/status so the frontend can show an appropriate banner.
     */
    setStandaloneMode(standalone: boolean): void;
    /**
     * Start the HTTP(S) server for the dashboard.
     */
    start(): Promise<void>;
    /**
     * Stop the HTTP server and clean up.
     */
    stop(): Promise<void>;
    /**
     * Request approval from the human via the dashboard.
     * Blocks until the human approves/denies or timeout occurs.
     */
    requestApproval(request: ApprovalRequest): Promise<ApprovalResponse>;
    /**
     * Verify bearer token authentication.
     *
     * SEC-012: The long-lived auth token is ONLY accepted via the Authorization
     * header — never in URL query strings. For SSE and page loads that cannot
     * set headers, a short-lived session token (obtained via POST /auth/session)
     * is accepted via ?session= query parameter.
     *
     * Returns true if auth passes, false if blocked (response already sent).
     */
    private checkAuth;
    /**
     * Check if a request is authenticated WITHOUT sending a response.
     * Used to decide between login page vs dashboard for GET /.
     */
    private isAuthenticated;
    /**
     * Parse a specific cookie value from the request.
     */
    private parseCookie;
    /**
     * Create a short-lived session by exchanging the long-lived auth token
     * (provided in the Authorization header) for a session ID.
     */
    private createSession;
    /**
     * Validate a session ID — must exist and not be expired.
     */
    private validateSession;
    /**
     * Remove all expired sessions.
     */
    private cleanupSessions;
    /**
     * Get the remote address from a request, normalizing IPv6-mapped IPv4.
     */
    private getRemoteAddr;
    /**
     * Check rate limit for a request. Returns true if allowed, false if rate-limited.
     * When rate-limited, sends a 429 response.
     */
    private checkRateLimit;
    /**
     * Remove stale entries from the rate limit map.
     */
    private pruneRateLimits;
    private handleRequest;
    /**
     * SEC-012: Exchange a long-lived auth token (in Authorization header)
     * for a short-lived session ID. The session ID can be used in URL
     * query parameters without exposing the long-lived credential.
     *
     * This endpoint performs its OWN auth check (header-only) because it
     * must reject query-parameter tokens and is called before the
     * normal checkAuth flow.
     */
    private handleSessionExchange;
    private serveLoginPage;
    private serveDashboard;
    private serveFortressView;
    /**
     * Enable Fortress View (Cocoon mode) with the given upstream server count.
     * Once enabled, the root path `/` serves the Fortress View instead of the
     * standard dashboard. The standard dashboard remains available at `/dashboard`.
     */
    enableFortressView(upstreamServerCount: number): void;
    /**
     * Broadcast a proxy call event to connected dashboards (Fortress View feed).
     */
    broadcastProxyCall(data: {
        tool: string;
        server: string;
        decision: string;
        reason?: string;
        tier?: number;
        timestamp: string;
    }): void;
    private handleSSE;
    private handleStatus;
    private handlePendingList;
    private handleAuditLog;
    private handleDecision;
    private handleSovereignty;
    private handleIdentity;
    private handleHandshakes;
    private handleSHR;
    private handleSovereigntyProfileGet;
    private handleSovereigntyProfileUpdate;
    /**
     * GET /api/proxy/servers — list upstream proxy servers and their status.
     */
    private handleProxyServers;
    /**
     * POST /api/proxy/servers — update upstream server configuration.
     * This is a dashboard action (human-initiated), so it's allowed with audit logging
     * rather than requiring Tier 1 approval.
     */
    private handleProxyServersUpdate;
    broadcastSSE(event: string, data: unknown): void;
    /**
     * Broadcast an audit entry to connected dashboards.
     * Called externally when audit events happen.
     */
    broadcastAuditEntry(entry: {
        timestamp: string;
        layer: string;
        operation: string;
        identity_id: string;
    }): void;
    /**
     * Broadcast a baseline update to connected dashboards.
     * Called externally after baseline changes.
     */
    broadcastBaselineUpdate(): void;
    /**
     * Broadcast a tool call event to connected dashboards.
     * Called from the gate or router when a tool is invoked.
     */
    broadcastToolCall(data: {
        tool: string;
        tier: number;
        allowed: boolean;
        timestamp: string;
    }): void;
    /**
     * Broadcast a context gate decision to connected dashboards.
     */
    broadcastContextGateDecision(data: {
        tool: string;
        fields_filtered: number;
        fields_total: number;
        action: string;
        timestamp: string;
    }): void;
    /**
     * Broadcast current protection status to connected dashboards.
     */
    broadcastProtectionStatus(data: Record<string, unknown>): void;
    /**
     * Open a URL in the system's default browser.
     * Cross-platform: macOS (open), Linux (xdg-open), Windows (start).
     * Fails silently — dashboard still works via terminal URL.
     */
    private openInBrowser;
    /**
     * Create a pre-authenticated URL for the dashboard.
     * Used by the sanctuary_dashboard_open tool and at startup.
     */
    createSessionUrl(): string;
    /**
     * Get the base URL for the dashboard.
     */
    getBaseUrl(): string;
    /** Get the number of pending requests */
    get pendingCount(): number;
    /** Get the number of connected SSE clients */
    get clientCount(): number;
}

/**
 * Sanctuary MCP Server — Webhook Approval Channel
 *
 * Sends approval requests to an external webhook URL and listens for
 * callback responses. Enables integration with Slack, Discord, PagerDuty,
 * or any HTTP-based approval workflow.
 *
 * Architecture:
 * - Outbound: POST approval request to configured webhook_url
 * - Inbound: HTTP callback server listens for POST /webhook/respond/:id
 * - HMAC-SHA256 signatures on both outbound and inbound payloads
 * - Timeout fallback: auto-deny (or auto-approve) if no callback received
 *
 * Security invariants:
 * - All outbound payloads signed with HMAC-SHA256 (webhook_secret)
 * - All inbound callbacks verified with same HMAC-SHA256 signature
 * - Callback server binds to configurable host (default 127.0.0.1)
 * - Replay protection via request ID + pending map (can't approve twice)
 * - All decisions are audit-logged
 */

interface WebhookConfig {
    /** URL to POST approval requests to */
    webhook_url: string;
    /** Shared secret for HMAC-SHA256 signatures */
    webhook_secret: string;
    /** Port for the callback listener */
    callback_port: number;
    /** Host for the callback listener (default: 127.0.0.1) */
    callback_host: string;
    /** Seconds to wait for a callback before timeout */
    timeout_seconds: number;
    /** SEC-002: auto_deny is always true. Field retained for interface compat but ignored. */
    auto_deny?: boolean;
}
/** Outbound webhook payload */
interface WebhookPayload {
    /** Unique request ID */
    request_id: string;
    /** The approval request details */
    operation: string;
    tier: 1 | 2;
    reason: string;
    context: Record<string, unknown>;
    timestamp: string;
    /** URL to POST the response back to */
    callback_url: string;
    /** Seconds until auto-resolution */
    timeout_seconds: number;
}
/** Inbound callback payload */
interface WebhookCallbackPayload {
    /** The request ID being responded to */
    request_id: string;
    /** The decision */
    decision: "approve" | "deny";
}
/**
 * Generate HMAC-SHA256 signature for a payload.
 */
declare function signPayload(body: string, secret: string): string;
/**
 * Verify HMAC-SHA256 signature. Uses timing-safe comparison.
 */
declare function verifySignature(body: string, signature: string, secret: string): boolean;
declare class WebhookApprovalChannel implements ApprovalChannel {
    private config;
    private pending;
    private callbackServer;
    constructor(config: WebhookConfig);
    /**
     * Start the callback listener server.
     */
    start(): Promise<void>;
    /**
     * Stop the callback server and clean up pending requests.
     */
    stop(): Promise<void>;
    /**
     * Request approval by POSTing to the webhook and waiting for a callback.
     */
    requestApproval(request: ApprovalRequest): Promise<ApprovalResponse>;
    private sendWebhook;
    private handleCallback;
    /** Get the number of pending requests */
    get pendingCount(): number;
}

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
 * Sanctuary MCP Server — Sovereignty Attestation Artifacts
 *
 * Signed, shareable artifacts proving sovereignty verification between agents.
 * Used for one-shot SHR exchanges and as portable proof of handshake completion.
 *
 * An attestation artifact contains:
 *   - Both parties' SHRs
 *   - Verification results (sovereignty level, trust tier)
 *   - Ed25519 signature over the canonical artifact body
 *   - Human-readable summary for social/public posting
 */

/** Attestation artifact version */
declare const ATTESTATION_VERSION: "1.0";
/** The signed body of an attestation artifact */
interface AttestationBody {
    attestation_version: typeof ATTESTATION_VERSION;
    /** Who generated this attestation */
    attester_id: string;
    /** Who was verified */
    subject_id: string;
    /** Attester's SHR at time of attestation */
    attester_shr: SignedSHR;
    /** Subject's SHR that was verified */
    subject_shr: SignedSHR;
    /** Verification results */
    verification: {
        subject_shr_valid: boolean;
        subject_sovereignty_level: SovereigntyLevel;
        subject_trust_tier: TrustTier;
        /** Whether subject also verified attester (mutual exchange) */
        mutual: boolean;
        errors: string[];
        warnings: string[];
    };
    /** When this attestation was generated */
    attested_at: string;
    /** When this attestation expires (min of both SHR expiries) */
    expires_at: string;
}
/** Complete signed attestation artifact */
interface SignedAttestation {
    body: AttestationBody;
    /** Attester's public key (base64url) */
    signed_by: string;
    /** Ed25519 signature over canonical body (base64url) */
    signature: string;
    /** Human-readable summary for social posting */
    summary: string;
}
interface AttestationOptions {
    /** Our signed SHR */
    attesterSHR: SignedSHR;
    /** Counterparty's signed SHR */
    subjectSHR: SignedSHR;
    /** Result from verifySHR(subjectSHR) */
    verificationResult: SHRVerificationResult;
    /** Whether this is a mutual exchange (both sides verify) */
    mutual?: boolean;
    /** Identity manager for signing */
    identityManager: IdentityManager;
    /** Master key for key derivation */
    masterKey: Uint8Array;
    /** Identity to sign with (defaults to primary) */
    identityId?: string;
}
/**
 * Generate a signed attestation artifact.
 *
 * The artifact is a portable, verifiable proof that one agent
 * verified another's sovereignty posture. It includes both SHRs,
 * the verification outcome, and a human-readable summary.
 */
declare function generateAttestation(opts: AttestationOptions): SignedAttestation | {
    error: string;
};
interface AttestationVerificationResult {
    valid: boolean;
    errors: string[];
    attester_id: string;
    subject_id: string;
    trust_tier: TrustTier;
    expired: boolean;
}
/**
 * Verify a signed attestation artifact.
 *
 * Checks:
 * 1. Signature validity (Ed25519 over canonical body)
 * 2. Temporal validity (not expired)
 * 3. Structural integrity (version, required fields)
 */
declare function verifyAttestation(attestation: SignedAttestation, now?: Date): AttestationVerificationResult;

/**
 * Sanctuary MCP Server — Concordia Bridge: Type Definitions
 *
 * Defines the interface contract between the Concordia negotiation protocol
 * and Sanctuary's sovereignty infrastructure. This is the Sanctuary side of
 * the bridge — when Concordia is present, its `accept` can trigger a
 * Sanctuary commitment for cryptographic binding. When Concordia is absent,
 * these types and tools still function independently.
 *
 * Design principle: the bridge is additive, never required. Sanctuary and
 * Concordia remain non-dependent. These types define the contract Concordia
 * implements against, not a dependency Sanctuary requires.
 */

/**
 * Concordia negotiation outcome — the data Concordia sends when an
 * `accept` triggers a Sanctuary commitment.
 *
 * This type is defined by Sanctuary (the receiver) to specify the
 * contract Concordia must fulfill. Field names align with Concordia's
 * protocol semantics.
 */
interface ConcordiaOutcome {
    /** Concordia session identifier */
    session_id: string;
    /** Protocol version (e.g., "concordia-v1") */
    protocol_version: string;
    /** DID of the party who proposed the accepted terms */
    proposer_did: string;
    /** DID of the party who accepted */
    acceptor_did: string;
    /** The accepted terms — opaque to Sanctuary, meaningful to Concordia */
    terms: Record<string, unknown>;
    /** SHA-256 hash of the canonical terms serialization (computed by Concordia) */
    terms_hash: string;
    /** Number of rounds in the negotiation (propose/counter cycles) */
    rounds: number;
    /** ISO 8601 timestamp when accept was issued */
    accepted_at: string;
    /** Optional: Concordia session receipt (signed transcript) */
    session_receipt?: string;
}
/**
 * A Sanctuary commitment binding a Concordia negotiation outcome.
 *
 * This is the cryptographic anchor: a SHA-256 commitment over the
 * canonical serialization of the ConcordiaOutcome, plus a Pedersen
 * commitment if ZK proofs are needed (e.g., proving negotiation
 * took ≤ N rounds without revealing exact count).
 */
interface BridgeCommitment {
    /** Unique bridge commitment identifier */
    bridge_commitment_id: string;
    /** The Concordia session this commitment binds */
    session_id: string;
    /** SHA-256 commitment: hash(canonical_outcome || blinding_factor) */
    sha256_commitment: string;
    /** Blinding factor for the SHA-256 commitment (base64url) */
    blinding_factor: string;
    /** DID of the Sanctuary identity that created this commitment */
    committer_did: string;
    /** Ed25519 signature over the commitment by the committer */
    signature: string;
    /** Optional: Pedersen commitment over the round count (for ZK range proofs) */
    pedersen_commitment?: {
        commitment: string;
        blinding_factor: string;
    };
    /** ISO 8601 timestamp */
    committed_at: string;
    /** Protocol metadata */
    bridge_version: "sanctuary-concordia-bridge-v1";
}
/** Result of verifying a bridge commitment against a revealed outcome */
interface BridgeVerificationResult {
    /** Whether the commitment matches the revealed outcome */
    valid: boolean;
    /** Which checks passed/failed */
    checks: {
        sha256_match: boolean;
        signature_valid: boolean;
        session_id_match: boolean;
        terms_hash_match: boolean;
        pedersen_match?: boolean;
    };
    /** The commitment that was verified */
    bridge_commitment_id: string;
    /** ISO 8601 timestamp of verification */
    verified_at: string;
}
/**
 * A bridge attestation links a Concordia negotiation to Sanctuary's
 * L4 reputation system. When a negotiation completes successfully,
 * both the commitment (L3) and the reputation attestation (L4) are
 * recorded — the commitment proves the terms were agreed, the
 * attestation feeds the sovereignty-weighted reputation score.
 */
interface BridgeAttestationRequest {
    /** The bridge commitment ID that anchors this attestation */
    bridge_commitment_id: string;
    /** Concordia session ID */
    session_id: string;
    /** DID of the counterparty in the negotiation */
    counterparty_did: string;
    /** Negotiation outcome for reputation scoring */
    outcome_result: "completed" | "partial" | "failed" | "disputed";
    /** Optional metrics (e.g., rounds, response_time_ms, terms_complexity) */
    metrics?: Record<string, number>;
    /** Identity to sign the attestation (uses default if omitted) */
    identity_id?: string;
}
/** Result of creating a bridge attestation */
interface BridgeAttestationResult {
    /** The L4 attestation ID created */
    attestation_id: string;
    /** The bridge commitment ID that anchors it */
    bridge_commitment_id: string;
    /** Concordia session ID */
    session_id: string;
    /** Sovereignty tier applied to the attestation */
    sovereignty_tier: SovereigntyTier;
    /** ISO 8601 timestamp */
    attested_at: string;
}

/**
 * Sanctuary MCP Server — Concordia Bridge: Core Module
 *
 * Implements the Sanctuary side of the Concordia bridge:
 * 1. bridge_commit — Create a cryptographic commitment binding a negotiation outcome
 * 2. bridge_verify — Verify a commitment against a revealed outcome
 * 3. bridge_attest — Link a negotiation to L4 reputation via the commitment
 *
 * The bridge composes L3 (selective disclosure) and L4 (verifiable reputation)
 * to serve negotiation-specific needs. It introduces no new cryptographic
 * primitives — everything delegates to the existing L3 commitment/ZK layer
 * and L4 reputation store.
 *
 * Non-dependency principle: this module can be used without Concordia
 * running. Any system that provides a ConcordiaOutcome-shaped object
 * can create bridge commitments. Concordia is the expected caller, but
 * the interface is protocol-agnostic.
 */

/**
 * Produce a canonical byte representation of a ConcordiaOutcome.
 * Sorts all keys recursively to ensure determinism.
 */
declare function canonicalize(outcome: ConcordiaOutcome): Uint8Array;
/**
 * Create a cryptographic commitment binding a Concordia negotiation outcome
 * to Sanctuary's L3 proof layer.
 *
 * Creates:
 * 1. A SHA-256 commitment over the canonical outcome (always)
 * 2. A Pedersen commitment over the round count (optional, for ZK range proofs)
 * 3. An Ed25519 signature over the commitment by the committer's identity
 *
 * @param outcome - The Concordia negotiation outcome to bind
 * @param identity - The Sanctuary identity creating the commitment
 * @param identityEncryptionKey - Key to decrypt the identity's private key
 * @param includePedersen - Whether to create a Pedersen commitment on round count
 * @returns The bridge commitment
 */
declare function createBridgeCommitment(outcome: ConcordiaOutcome, identity: StoredIdentity, identityEncryptionKey: Uint8Array, includePedersen?: boolean): BridgeCommitment;
/**
 * Verify a bridge commitment against a revealed Concordia outcome.
 *
 * Checks:
 * 1. SHA-256 commitment matches the canonical outcome + blinding factor
 * 2. Ed25519 signature is valid for the committer's public key
 * 3. Session IDs match
 * 4. Terms hash matches (Concordia's own hash of the terms)
 * 5. Pedersen commitment matches round count (if present)
 *
 * @param commitment - The bridge commitment to verify
 * @param outcome - The revealed Concordia outcome
 * @param committerPublicKey - The committer's Ed25519 public key
 * @returns Verification result with per-check detail
 */
declare function verifyBridgeCommitment(commitment: BridgeCommitment, outcome: ConcordiaOutcome, committerPublicKey: Uint8Array): BridgeVerificationResult;

/**
 * Sanctuary MCP Server — Main Entry Point
 *
 * Initializes and exports the Sanctuary MCP server.
 * Wires together: config → storage → crypto core → L1-L4 tools → MCP server
 */

interface SanctuaryServer {
    server: Server;
    config: SanctuaryConfig;
    /**
     * Runtime dependencies exposed for embedding callers that need
     * direct access to the Sanctuary substrate (e.g., the EU AI Act
     * compliance CLI subcommand). Most callers only use `server` and
     * `config`; these are optional-usage extras.
     */
    identityManager: IdentityManager;
    masterKey: Uint8Array;
    auditLog: AuditLog;
    policy: PrincipalPolicy;
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

export { ATTESTATION_VERSION, ApprovalGate, type AttestationBody, type AttestationVerificationResult, AuditLog, AutoApproveChannel, BaselineTracker, type BridgeAttestationRequest, type BridgeAttestationResult, type BridgeCommitment, type BridgeVerificationResult, TEMPLATES as CONTEXT_GATE_TEMPLATES, CallbackApprovalChannel, ClientManager, CommitmentStore, type ConcordiaOutcome, type ConnectionState, type ContextAction, type ContextFilterResult, ContextGateEnforcer, type ContextGatePolicy, ContextGatePolicyStore, type ContextGateRule, type ContextGateTemplate, DashboardApprovalChannel, type DashboardConfig, type DetectionResult, type EnforcerConfig, type FederationCapabilities, type FederationPeer, FederationRegistry, type FieldClassification, type FieldFilterResult, FilesystemStorage, type GateResult, type HandshakeChallenge, type HandshakeCompletion, type HandshakeResponse, type HandshakeResult, InMemoryModelProvenanceStore, InjectionDetector, type InjectionDetectorConfig, type InjectionSignal, MODEL_PRESETS, MemoryStorage, type ModelProvenance, type ModelProvenanceStore, type PedersenCommitment, type PeerTrustEvaluation, type PolicyRecommendation, PolicyStore, type PrincipalPolicy, type ProviderCategory, ProxyRouter, type ProxyRouterOptions, ReputationStore, type SHRBody, type SHRGeneratorOptions, type SHRVerificationResult, type SanctuaryConfig, type SanctuaryServer, type SignedAttestation, type SignedSHR, type SovereigntyProfile, SovereigntyProfileStore, type SovereigntyProfileUpdate, type SovereigntyTier, StateStore, StderrApprovalChannel, TIER_WEIGHTS, type TierMetadata, type TieredAttestation, type UpstreamConnection, type UpstreamServer, type UpstreamTool, WebhookApprovalChannel, type WebhookCallbackPayload, type WebhookConfig, type WebhookPayload, type ZKProofOfKnowledge, type ZKRangeProof, canonicalize, classifyField, completeHandshake, computeWeightedScore, createBridgeCommitment, createDefaultProfile, createPedersenCommitment, createProofOfKnowledge, createRangeProof, createSanctuaryServer, evaluateField, filterContext, generateAttestation, generateSHR, generateSystemPrompt, getTemplate, initiateHandshake, listTemplateIds, loadConfig, loadPrincipalPolicy, recommendPolicy, resolveTier, respondToHandshake, signPayload, tierDistribution, verifyAttestation, verifyBridgeCommitment, verifyCompletion, verifyPedersenCommitment, verifyProofOfKnowledge, verifyRangeProof, verifySHR, verifySignature };
