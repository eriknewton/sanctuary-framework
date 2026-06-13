/**
 * Sanctuary MCP Server — Main Entry Point
 *
 * Initializes and exports the Sanctuary MCP server.
 * Wires together: config → storage → crypto core → L1-L4 tools → MCP server
 */

import { mkdir } from "node:fs/promises";
import { tightenStoragePermissions } from "./storage/permissions.js";
import { loadConfig, saveConfig, type SanctuaryConfig } from "./config.js";
import { FilesystemStorage } from "./storage/filesystem.js";
import type { StorageBackend } from "./storage/interface.js";
import { StateStore } from "./l1-cognitive/state-store.js";
import { createL1Tools, createInternalIdentitySigningHelpers } from "./l1-cognitive/tools.js";
import { createDistressTools } from "./distress/tools.js";
import { readDistressConfig } from "./distress/config.js";
import { deliverDistressLocally } from "./distress/local-delivery.js";
import { loadOrCreateLocalListenerSecret } from "./distress/local-secret.js";
import { AuditLog, type AuditEntry } from "./l2-operational/audit-log.js";
import { createL3Tools } from "./l3-disclosure/tools.js";
import { createL4Tools } from "./l4-reputation/tools.js";
import { loadPrincipalPolicy, MalformedPrincipalPolicyError } from "./principal-policy/loader.js";
import type { IdentityManager } from "./l1-cognitive/tools.js";
import type { PrincipalPolicy } from "./principal-policy/types.js";
import { BaselineTracker } from "./principal-policy/baseline.js";
import { StderrApprovalChannel } from "./principal-policy/approval-channel.js";
import { DashboardApprovalChannel } from "./principal-policy/dashboard.js";
import { WebhookApprovalChannel } from "./principal-policy/webhook.js";
import { ApprovalGate } from "./principal-policy/gate.js";
import {
  ApprovalAggregator,
  type ApprovalGateEvent,
} from "./principal-policy/approval-aggregator.js";
import {
  AggregatorBackedChannel,
  makeRedirectResolverFromPolicySupplier,
} from "./principal-policy/channels/aggregator-backed-channel.js";
import { AggregatorPayloadStore } from "./principal-policy/aggregator-store.js";
import { SentinelFindingStore } from "./sentinel/sentinel-finding-store.js";
import { SentinelRegistry } from "./sentinel/sentinel-registry.js";
import { SentinelDispatcher } from "./sentinel/sentinel-dispatcher.js";
import { AnomalyPipelineDispatcher } from "./anomaly-detection/anomaly-pipeline.js";
import { ThresholdConfigStore } from "./auto-trigger/threshold-config-store.js";
import {
  ActionDispatcher,
  AutoTriggerActionRegistry,
} from "./auto-trigger/action-dispatcher.js";
import { CalibrationSuggester } from "./auto-trigger/calibration-suggester.js";
import { UnifiedInboxBridge } from "./principal-policy/unified-inbox-bridge.js";
import { UnifiedInboxPrefsStore } from "./principal-policy/unified-inbox-prefs-store.js";
import { UnifiedInboxStore } from "./principal-policy/unified-inbox-store.js";
import {
  UnifiedInboxRetentionPolicyStore,
} from "./principal-policy/unified-inbox-retention-policy.js";
import { UnifiedInboxScheduler } from "./principal-policy/unified-inbox-scheduler.js";
import { HandoffLog } from "./coordination/handoff-log.js";
import { HandoffEventBridge } from "./coordination/handoff-routes.js";
import { WorkflowStateTracker } from "./coordination/workflow-state-tracker.js";
import { TrapRegistry } from "./honeypot/trap-registry.js";
import { TrapStore } from "./honeypot/trap-store.js";
import { ToolCallTrapRuntime } from "./honeypot/tool-call-trap-runtime.js";
import { CredentialTrapRuntime } from "./honeypot/credential-trap-runtime.js";
import { HONEYPOT_AUDIT_OPS } from "./honeypot/types.js";
import { PHI1_BASELINE_CATALOG } from "./sentinel/sentinels/index.js";
import { loadSentinelSubscriptions } from "./sentinel/subscription-store.js";
import { createPrincipalPolicyTools } from "./principal-policy/tools.js";
import { createServer, type ToolDefinition } from "./router.js";
import { toolResult } from "./router.js";
import {
  ApprovalProofStore,
  fingerprintIdentityId,
  type SessionBinding,
} from "./agent-native/safety-base.js";
import { createAgentNativeCooperativeTools } from "./agent-native/cooperative-surface.js";
import { createSHRTools } from "./shr/tools.js";
import { createHandshakeTools } from "./handshake/tools.js";
import { createFederationTools } from "./federation/tools.js";
import { createBridgeTools } from "./bridge/tools.js";
import { createAuditTools } from "./audit/tools.js";
import {
  consumeResetHistoryMarker,
  ResetHistoryMalformedError,
} from "./audit/reset-history.js";
import { createSIEMTools } from "./audit/siem-tools.js";
import {
  bindContextGateEnforcerToProfileStore,
  createContextGateTools,
  initializeContextGateEnforcerFromProfile,
} from "./l2-operational/context-gate-tools.js";
import { createL2HardeningTools } from "./l2-operational/hardening-tools.js";
import { SovereigntyProfileStore } from "./sovereignty-profile.js";
import { createSovereigntyProfileTools } from "./sovereignty-profile-tools.js";
import { InjectionDetector } from "./security/injection-detector.js";
import { ClientManager } from "./proxy/client-manager.js";
import { ProxyRouter } from "./proxy/proxy-router.js";
import {
  DynamicProxyToolRegistry,
  enableToolListChangedNotifications,
} from "./proxy/dynamic-proxy.js";
import { CallGovernor } from "./l2-operational/call-governor.js";
import { createGovernorTools } from "./l2-operational/governor-tools.js";
import { createSanctuaryTools } from "./sanctuary-tools.js";
import { createMemoryAttestTools } from "./l1-cognitive/memory-attest.js";
import { createComplianceTools } from "./compliance/eu_ai_act/generator.js";
import { createErc8004Tools } from "./key-17/erc8004-tools.js";
import { DefaultPolicyGate } from "./key-17/policy-gate.js";
import {
  establishMaster,
  checkCastlePinCustody,
} from "./core/master-custody.js";
import { discloseRecoveryKey } from "./wrap/recovery-key-disclosure.js";
import {
  buildV11Bindings,
  fortressIdFromStoragePath,
} from "./dashboard/v1_1/wiring.js";
import { SubstrateSelector } from "./intelligence/selector.js";

import type { Server } from "@modelcontextprotocol/sdk/server/index.js";

const AUDIT_AGENT_REDACTED = "[redacted]";
const AUDIT_AGENT_REDACT_DETAIL_KEYS = new Set([
  "decided_by",
  "identity_id",
  "operatorId",
  "operator_id",
  "resolved_by",
  "policy_rule_id",
  // Castle Wall matched-rule id (#381). Written to the stored audit entry for
  // operator attribution; redacted here so an agent querying audit entries
  // cannot learn which allow/deny rule matched and map the essentials list by
  // probing (property #11, no-policy-inference).
  "rule_id",
  "policy_match",
  "policy_decision",
  "policy_tier",
  "tier",
]);

function redactAuditValueForAgent(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => redactAuditValueForAgent(item));
  }
  if (value && typeof value === "object") {
    const redacted: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
      redacted[key] = AUDIT_AGENT_REDACT_DETAIL_KEYS.has(key)
        ? AUDIT_AGENT_REDACTED
        : redactAuditValueForAgent(nested);
    }
    return redacted;
  }
  return value;
}

function redactAuditEntryForAgent(entry: AuditEntry): AuditEntry {
  return {
    ...entry,
    identity_id: AUDIT_AGENT_REDACTED,
    details: entry.details
      ? (redactAuditValueForAgent(entry.details) as Record<string, unknown>)
      : undefined,
  };
}

export interface SanctuaryServer {
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
export async function createSanctuaryServer(options?: {
  configPath?: string;
  passphrase?: string;
  storage?: StorageBackend;
}): Promise<SanctuaryServer> {
  // 1. Load configuration
  const config = await loadConfig(options?.configPath);

  // 2. Ensure storage directory exists with correct permissions
  await mkdir(config.storage_path, { recursive: true, mode: 0o700 });
  await tightenStoragePermissions(config.storage_path);

  // 3. Initialize storage backend
  const storage = options?.storage ?? new FilesystemStorage(
    `${config.storage_path}/state`
  );

  // 4. Establish the master key through the unified custody path: one
  // master per fortress, stored only as wraps in the custody envelope.
  // Legacy fortresses (key-params / recovery-key-hash markers) migrate in
  // place on this unlock — same master, no data re-encryption, markers
  // kept (an interrupted migration leaves a pure-legacy fortress).
  const passphrase = options?.passphrase ?? process.env.SANCTUARY_PASSPHRASE;
  const envRecoveryKey = process.env.SANCTUARY_RECOVERY_KEY;

  const custody = await establishMaster({
    storage,
    ...(passphrase ? { passphrase } : {}),
    ...(envRecoveryKey ? { recoveryKey: envRecoveryKey } : {}),
    // The MCP server stdio boot is non-interactive by definition (the host
    // harness owns stdin), so first runs here are a distinct, audited
    // degraded install mode. A fresh recovery key — a wrap of the one true
    // master — is minted and disclosed below regardless of credential mode,
    // so the captured artifact always unlocks everything.
    firstRun: { installMode: "stdio-server", mintRecoveryKey: true },
    storagePathHint: config.storage_path,
  });
  const masterKey = custody.masterKey;
  const keyProtection: "passphrase" | "hardware-key" | "recovery-key" =
    custody.keyProtection;
  const recoveryKey = custody.mintedRecoveryKey;

  // 5. Initialize audit log
  const auditLog = new AuditLog(storage, masterKey);

  // 5pre. Custody audit trail: record envelope creation/migration (never key
  // material — wrap types and install mode only), and surface the dual-path
  // damage signature (Castle pin wrapped under a master nobody can produce,
  // the 2026-06-12 incident shape) instead of silently carrying it.
  if (custody.origin !== "envelope") {
    await auditLog.appendCritical({
      layer: "l2",
      operation:
        custody.origin === "first-run"
          ? "custody_envelope_created"
          : custody.origin === "legacy-deferred"
            ? "custody_migration_deferred"
            : "custody_legacy_migrated",
      identity_id: fortressIdFromStoragePath(config.storage_path),
      result: "success",
      details: custody.envelope
        ? {
            install_mode: custody.envelope.install_mode,
            wrap_types: custody.envelope.wraps.map((w) => w.type),
            verified_wraps: custody.envelope.wraps.filter((w) => w.verified)
              .length,
            origin: custody.origin,
          }
        : {
            origin: custody.origin,
            reason:
              "existing data could not be evidence-checked against this master; envelope not written",
          },
    });
    const pinCustody = await checkCastlePinCustody(
      config.storage_path,
      masterKey
    );
    if (pinCustody === "mismatch") {
      await auditLog.appendCritical({
        layer: "l2",
        operation: "castle_pin_custody_mismatch",
        identity_id: fortressIdFromStoragePath(config.storage_path),
        result: "failure",
        details: {
          message:
            "Castle Wall pinned private key does not decrypt under the established master",
        },
      });
      // SAFETY: stderr is the operator-facing channel for boot diagnostics.
      console.error(
        "\nSanctuary: WARNING — the Castle Wall pinned key at this fortress does NOT\n" +
          "decrypt under the master your credential unlocks. This fortress was touched\n" +
          "by two different custody paths in the past. The wall cannot sign with this\n" +
          "pin; re-provision it with 'sanctuary castle-wall re-pin' when ready.\n"
      );
    }
  }

  // 5a. Reset-history continuity (v1.0.2 item a). If a prior nuke left a
  // `.reset-history.log` marker beside the storage path, append one
  // `fortress_recovered_from_reset` audit entry per marker line, bind the
  // marker hash into the entry, then delete the marker. Idempotent: re-runs
  // see no marker and no-op. Refuses to continue if the marker is malformed.
  try {
    await consumeResetHistoryMarker({
      storagePath: config.storage_path,
      auditLog,
    });
  } catch (err) {
    if (err instanceof ResetHistoryMalformedError) {
      throw new Error(
        `Sanctuary: ${err.message}\n` +
          `Refusing to start the fortress while the reset-history marker is unreadable.`,
        { cause: err }
      );
    }
    throw err;
  }

  // 6. Initialize state store
  const stateStore = new StateStore(storage, masterKey);
  const currentSessionBinding = (): SessionBinding | undefined => {
    const identityId = process.env.SANCTUARY_SESSION_IDENTITY_ID;
    if (!identityId) return undefined;
    return {
      identity_id: identityId,
      requester_identity_fingerprint: fingerprintIdentityId(identityId),
    };
  };

  // 7. Create L1 tools
  const { tools: l1Tools, identityManager, namespaceRegistry } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    keyProtection,
    auditLog,
    { currentSessionBinding }
  );

  // 8. Load existing identities
  const loadResult = await identityManager.load();

  // 8a. Warn loudly if encrypted identity files exist but none could be decrypted
  if (loadResult.total > 0 && loadResult.loaded === 0) {
    // SAFETY: no structured logger module is wired in server/src/ yet; until one lands, raw stderr is the runtime warning channel for this site.
    console.error(
      "\n╔══════════════════════════════════════════════════════════════╗\n" +
      "║  ⚠  WARNING: Encrypted identities found but NONE loaded     ║\n" +
      "╠══════════════════════════════════════════════════════════════╣\n" +
      `║  ${loadResult.total} encrypted identity file(s) found on disk              ║\n` +
      "║  0 could be decrypted with the current master key            ║\n" +
      "║                                                              ║\n" +
      "║  This usually means SANCTUARY_PASSPHRASE is missing or       ║\n" +
      "║  incorrect. The server will start but with NO identity data. ║\n" +
      "║                                                              ║\n" +
      "║  To fix: set SANCTUARY_PASSPHRASE to the passphrase used     ║\n" +
      "║  when this Sanctuary instance was first configured.          ║\n" +
      "╚══════════════════════════════════════════════════════════════╝\n"
    );
  } else if (loadResult.failed > 0) {
    // SAFETY: no structured logger module is wired in server/src/ yet; until one lands, raw stderr is the runtime warning channel for this site.
    console.error(
      `Warning: ${loadResult.failed} of ${loadResult.total} identity files could not be decrypted (possibly corrupted).`
    );
  }

  // 9. Create L2 monitoring tools
  const l2Tools: ToolDefinition[] = [
    {
      name: "exec_attest",
      description:
        "Generate an attestation of the current execution environment, " +
        "including sovereignty assessment and degradation report.",
      inputSchema: {
        type: "object",
        properties: {
          include_hardware: { type: "boolean", default: true },
          include_software: { type: "boolean", default: true },
          include_network: { type: "boolean", default: true },
        },
      },
      handler: async () => {
        const { buildHealthEvidenceReport } = await import("./health/evidence.js");
        const evidence = buildHealthEvidenceReport({
          config,
          identityCount: identityManager.list().length,
          storageBackendName: storage.constructor.name,
        });

        return toolResult({
          sanctuary_version: evidence.sanctuary_version,
          mcp_sdk_version: evidence.mcp_sdk_version,
          castle_wall: evidence.castle_wall,
          audit: evidence.audit,
          state: evidence.state,
          egress: evidence.egress,
          layers: evidence.layers,
          attestation: {
            environment_type: config.execution.environment,
            hardware: {
              cpu_vendor: process.arch,
              tee_available: false,
              tee_type: undefined,
            },
            software: {
              os: `${process.platform}-${process.arch}`,
              runtime: `node-${process.version}`,
              sanctuary_version: evidence.sanctuary_version,
              mcp_sdk_version: evidence.mcp_sdk_version,
            },
            network: {
              internet_accessible: "unknown",
              listening_ports: [],
              egress_restricted: evidence.egress.enforcement,
              evidence: evidence.egress.evidence,
            },
            isolation_level: "process",
            sovereignty_assessment: {
              l1_state_encrypted: true,
              l1_status: evidence.layers.l1.status,
              l2_execution_isolated: evidence.layers.l2.status,
              l2_isolation_type: "process-level",
              l3_proofs_available: true,
              l4_reputation_status: evidence.layers.l4.status,
              overall_level: "mvs",
              degradations: evidence.degradations.map((d) => d.description),
            },
          },
          attested_at: new Date().toISOString(),
        });
      },
    },

    {
      name: "monitor_health",
      description:
        "Sanctuary Health Report (SHR) — standardized sovereignty status.",
      inputSchema: { type: "object", properties: {} },
      handler: async () => {
        const { buildHealthEvidenceReport } = await import("./health/evidence.js");
        const storageSizeBytes = await storage.totalSize();
        const evidence = buildHealthEvidenceReport({
          config,
          identityCount: identityManager.list().length,
          storageBackendName: storage.constructor.name,
        });

        return toolResult({
          status: evidence.degradations.some((d) => d.severity === "critical")
            ? "compromised"
            : evidence.degradations.some((d) => d.severity === "warning")
              ? "degraded"
              : "healthy",
          sanctuary_version: evidence.sanctuary_version,
          mcp_sdk_version: evidence.mcp_sdk_version,
          castle_wall: evidence.castle_wall,
          audit: evidence.audit,
          state: evidence.state,
          egress: evidence.egress,
          storage_bytes: storageSizeBytes,
          layers: evidence.layers,
          degradations: evidence.degradations,
          checked_at: new Date().toISOString(),
        });
      },
    },

    {
      name: "monitor_audit_log",
      description: "Query the sovereignty audit log.",
      inputSchema: {
        type: "object",
        properties: {
          since: { type: "string", description: "ISO 8601 timestamp" },
          layer: {
            type: "string",
            enum: ["l1", "l2", "l3", "l4"],
          },
          operation_type: { type: "string" },
          limit: { type: "number", default: 50 },
        },
      },
      handler: async (args) => {
        const result = await auditLog.query({
          since: args.since as string | undefined,
          layer: args.layer as "l1" | "l2" | "l3" | "l4" | undefined,
          operation_type: args.operation_type as string | undefined,
          limit: (args.limit as number) ?? 50,
        });
        return toolResult({
          ...result,
          entries: result.entries.map((entry) => redactAuditEntryForAgent(entry)),
        });
      },
    },
  ];

  // 10. Create SIM manifest tool
  const manifestTool: ToolDefinition = {
    name: "manifest",
    description:
      "Generate the Sanctuary Interface Manifest (SIM) — " +
      "a machine-readable declaration of this server's capabilities.",
    inputSchema: { type: "object", properties: {} },
    handler: async () => {
      return toolResult({
        sanctuary_version: "0.2",
        implementation: {
          name: "@sanctuary-framework/mcp-server",
          version: config.version,
          language: "typescript",
          license: "Apache-2.0",
        },
        layers: {
          l1: {
            implemented: true,
            interfaces: ["StateStore", "IdentityRoot"],
            encryption: ["aes-256-gcm"],
            identity: ["ed25519"],
            properties: {
              "S1.1_participant_held_keys": "full",
              "S1.2_encryption_at_rest": "full",
              "S1.3_integrity_verification": "full",
              "S1.4_selective_state_sharing": "full",
              "S1.5_state_portability": "full",
              "S1.6_deletion_rights": "full",
              "S1.7_identity_anchoring": "partial",
            },
          },
          l2: {
            implemented: true,
            interfaces: ["ExecutionEnvironment", "RuntimeMonitor"],
            isolation_types: [config.execution.environment],
            properties: {
              "S2.1_execution_confidentiality": "documented",
              "S2.2_verifiable_execution": "self-reported",
              "S2.5_attestation": "self-reported",
            },
          },
          l3: {
            implemented: true,
            interfaces: ["ProofEngine", "DisclosurePolicy"],
            proof_systems: [config.disclosure.proof_system],
            properties: {
              "S3.1_minimum_disclosure": "policy-based",
              "S3.3_proof_without_revelation": "commitment",
            },
          },
          l4: {
            implemented: true,
            interfaces: ["ReputationStore", "TrustBootstrap"],
            modes: [config.reputation.mode],
            properties: {
              "S4.1_earned_reputation": "full",
              "S4.2_participant_owned": "full",
              "S4.5_sybil_resistance": "basic",
              "S4.7_trust_bootstrapping": "full",
            },
          },
        },
        composition: {
          sim_version: "1.0",
          spf_supported: false,
          shr_supported: true,
          delegation_depth: 1,
        },
        limitations: [
          "L1 identity uses ed25519 only; KERI support planned for v0.2.0",
          "L2 isolation is process-level only; TEE support planned for a future release",
          "L3 uses commitment schemes only; ZK proofs planned for v0.2.0",
          "L4 Sybil resistance is escrow-based only",
          "Spec license: CC-BY-4.0 | Code license: Apache-2.0",
        ],
      });
    },
  };

  // 11. Create L3 tools
  const { tools: l3Tools } = createL3Tools(storage, masterKey, auditLog);

  // 12. Create Handshake tools (sovereignty handshake protocol)
  // Must be created before L4 so handshakeResults can feed tier resolution
  const { tools: handshakeTools, handshakeResults } = createHandshakeTools(
    config,
    identityManager,
    masterKey,
    auditLog,
    {
      autoPublishHandshakes: config.verascore.auto_publish_handshakes,
      verascoreUrl: config.verascore.url,
    }
  );

  // 13. Create L4 tools (reputation with sovereignty-gated tiers)
  // Produces the ReputationStore that feeds SHR L4 evidence, so create
  // this before the SHR tools.
  const { tools: l4Tools, reputationStore } = createL4Tools(
    storage,
    masterKey,
    identityManager,
    auditLog,
    handshakeResults,
    config.verascore.url
  );

  // 14. Create SHR tools (machine-readable sovereignty health report).
  // Receives the reputationStore so the generator can emit L4 degradation
  // evidence (NO_REPUTATION_HISTORY, LOW_TIER_DOMINANCE, STALE_REPUTATION,
  // DISPUTE_ON_RECORD, NO_VERASCORE_LINK).
  const { tools: shrTools } = createSHRTools(
    config,
    identityManager,
    masterKey,
    auditLog,
    reputationStore
  );

  // 14b. Create Federation tools (MCP-to-MCP)
  const { tools: federationTools } = createFederationTools(
    auditLog,
    handshakeResults
  );

  // 14c. Create Bridge tools (Concordia integration)
  const { tools: bridgeTools } = createBridgeTools(
    storage,
    masterKey,
    identityManager,
    auditLog,
    handshakeResults
  );

  // 14d. Create Sovereignty Audit tools (read-only diagnostic)
  const { tools: auditTools } = createAuditTools(config, auditLog);

  // 14d2. Create SIEM Export tools (Tier 2 — CEF and OCSF export)
  const { tools: siemTools } = createSIEMTools(auditLog);

  // 14e. Initialize Sovereignty Profile store. Its context_gating subsection is
  // the persisted source of truth for the runtime context gate enforcer.
  const profileStore = new SovereigntyProfileStore(storage, masterKey);
  const loadedProfile = await profileStore.load();

  // 14f. Create Context Gating tools (L2 outbound context control) and bind
  // the live enforcer to the persisted profile state before any proxy tools are
  // registered.
  const { tools: contextGateTools, enforcer: contextGateEnforcer } =
    createContextGateTools(storage, masterKey, auditLog, {
      privacyFilter: config.privacy_filter,
      getProfile: () => profileStore.get(),
    });
  initializeContextGateEnforcerFromProfile(contextGateEnforcer, loadedProfile);
  bindContextGateEnforcerToProfileStore(profileStore, auditLog, contextGateEnforcer);

  // 14g. Create L2 Process Hardening tools
  const hardeningTools = createL2HardeningTools(config.storage_path, auditLog);

  // 14h. Create Sovereignty Profile tools
  const { tools: profileTools } = createSovereigntyProfileTools(profileStore, auditLog);

  // 15. Load Principal Policy and create approval gate
  let policy: PrincipalPolicy;
  try {
    policy = await loadPrincipalPolicy(config.storage_path);
  } catch (err) {
    if (err instanceof MalformedPrincipalPolicyError) {
      // SAFETY: no structured logger module is wired in server/src/ yet; until one lands, raw stderr is the runtime warning channel for this site.
      console.error(`\nSanctuary cannot start.\n${err.message}\n`);
      process.exit(1);
    }
    throw err;
  }
  const baseline = new BaselineTracker(storage, masterKey);
  await baseline.load();

  // Choose approval channel: dashboard (web UI), webhook (external), or stderr (auto-deny)
  let approvalChannel: StderrApprovalChannel | DashboardApprovalChannel | WebhookApprovalChannel;
  let dashboard: DashboardApprovalChannel | undefined;

  // WP-V1.3-5 Pi-2: the Intelligence Substrate Selector is hoisted to
  // outer function scope so the honeypot wiring below (after the
  // dashboard/webhook/stderr branch closes) can pass it into
  // `setHoneypotRegistry`. Pi-1 deferred this forwarding because the
  // selector was scoped to the `if (config.dashboard.enabled)` block;
  // the boot-path persistence work in Pi-2 needs the selector in scope
  // alongside the trap registry + trap store, so the declaration moves
  // here and the dashboard branch only assigns to it.
  let intelligenceSelector: SubstrateSelector | undefined;

  if (config.dashboard.enabled) {
    // Resolve auth token: "auto" generates a random 32-byte hex token
    let authToken = config.dashboard.auth_token;
    if (authToken === "auto") {
      const { randomBytes: rb } = await import("node:crypto");
      authToken = rb(32).toString("hex");
    }

    dashboard = new DashboardApprovalChannel({
      port: config.dashboard.port,
      host: config.dashboard.host,
      timeout_seconds: policy.approval_channel.timeout_seconds,
      // SEC-002: auto_deny removed — timeout always denies
      auth_token: authToken,
      tls: config.dashboard.tls,
      auto_open: config.dashboard.auto_open,
    });
    dashboard.setDependencies({
      policy,
      baseline,
      auditLog,
      identityManager,
      handshakeResults,
      shrOpts: { config, identityManager, masterKey },
      sanctuaryConfig: config,
      profileStore,
    });
    // v1.1.1 hotfix: bind the v1.1 dashboard at /v1.1 + hub API at
    // /api/hub/* on the embedded dashboard path so operators see the
    // v1.1 surface whether they boot via `sanctuary --dashboard` or
    // `sanctuary dashboard` (standalone). Legacy routes at / continue
    // to serve.
    const embeddedHubIdentityId =
      identityManager.getPrimaryIdentityId() ??
      `fortress:${config.storage_path}`;
    // WP-V1.2-5: construct the Intelligence Substrate Selector against the
    // unlocked fortress. The selector reads / writes its config under the
    // fortress storage namespace `_intelligence`, encrypted with the
    // master key. Best-effort: any construction failure degrades to a
    // selector-less binding (Intelligence panel surfaces "not configured").
    // Pi-2: the declaration moved to outer function scope so the honeypot
    // wiring below can pick it up; the dashboard branch only constructs.
    try {
      intelligenceSelector = new SubstrateSelector({
        storage,
        masterKey,
        auditLog,
        identityId: embeddedHubIdentityId,
      });
      await intelligenceSelector.load();
    } catch (err) {
      // SAFETY: no structured logger module is wired in server/src/ yet; until one lands, raw stderr is the runtime warning channel for this site.
      console.error(
        `  Note: Intelligence panel unavailable (${(err as Error).message}). ` +
          `Run \`sanctuary dashboard\` and pick a substrate.`,
      );
      intelligenceSelector = undefined;
    }
    dashboard.setV11Bindings(
      buildV11Bindings({
        identityId: embeddedHubIdentityId,
        fortressId: fortressIdFromStoragePath(config.storage_path),
        auditLog,
        // v1.1.5 (Finding Z): rehydrate the hub agent registry from
        // `<storagePath>/state/_hub/local-agents.json` so the embedded
        // dashboard surfaces wraps performed by prior `sanctuary wrap`
        // invocations against this same fortress.
        storagePath: config.storage_path,
        ...(intelligenceSelector ? { intelligenceSelector } : {}),
        // WP-V1.2-4: forward storage + master key so chat service is
        // constructed and the /api/hub/chat/* routes light up.
        storage,
        masterKey,
        identityManager,
        reputationStore,
        policy,
        config,
      }),
    );
    await dashboard.start();
    approvalChannel = dashboard;
  } else if (config.webhook.enabled && config.webhook.url && config.webhook.secret) {
    const webhook = new WebhookApprovalChannel({
      webhook_url: config.webhook.url,
      webhook_secret: config.webhook.secret,
      callback_port: config.webhook.callback_port,
      callback_host: config.webhook.callback_host,
      timeout_seconds: policy.approval_channel.timeout_seconds,
      // SEC-002: auto_deny removed — timeout always denies
    });
    await webhook.start();
    approvalChannel = webhook;
  } else {
    approvalChannel = new StderrApprovalChannel(policy.approval_channel);
  }

  // 15b. Create injection detector
  const injectionDetector = new InjectionDetector({
    enabled: true,
    sensitivity: "medium",
    on_detection: "escalate",
  });

  // Wire injection alerts to dashboard SSE if dashboard is active
  const onInjectionAlert = dashboard
    ? (alert: { toolName: string; result: import("./security/injection-detector.js").DetectionResult; timestamp: string }) => {
        dashboard!.broadcastSSE("injection-alert", {
          tool: alert.toolName,
          confidence: alert.result.confidence,
          signals: alert.result.signals.map(s => ({
            type: s.type,
            location: s.location,
            severity: s.severity,
          })),
          recommendation: alert.result.recommendation,
          timestamp: alert.timestamp,
        });
      }
    : undefined;

  // v1.3 WP-V1.3-10 Upsilon-1: construct the cross-harness approval
  // aggregator BEFORE the gate so Upsilon-2's AggregatorBackedChannel can
  // wrap the underlying approval channel with aggregator-driven
  // resolution. The aggregator remains a passive subscriber to gate
  // lifecycle events; the channel wrap is the additional Upsilon-2
  // surface that lets operator decisions through the inbox actually
  // resolve a blocked Tier 1/2 gate call.
  const fortressIdForAggregator = fortressIdFromStoragePath(config.storage_path);
  const aggregatorIdentityId =
    identityManager.getPrimaryIdentityId() ?? `fortress:${config.storage_path}`;
  // v1.3 WP-V1.3-10 Upsilon-3: at-rest payload persistence so the operator
  // can replay full request payloads after a server restart. AAD-bound to
  // aggregator_id; isolated per fortress via the master-key-derived HKDF
  // subkey. Default 30-day retention mirrors the audit-log envelope.
  const aggregatorPayloadStore = new AggregatorPayloadStore({
    storage,
    masterKey,
    fortressId: fortressIdForAggregator,
  });
  const approvalAggregator = new ApprovalAggregator({
    storage,
    masterKey,
    auditLog,
    identityId: aggregatorIdentityId,
    fortressId: fortressIdForAggregator,
    payloadStore: aggregatorPayloadStore,
  });

  // v1.3 WP-V1.3-7 Nu-3: Auto-Trigger Ladder runtime. The promotion
  // suggester is advisory only; it evaluates local action history and emits
  // recommendations. Rung changes happen only via operator accept/promote
  // routes, never from the scheduled tick.
  const autoTriggerStore = new ThresholdConfigStore({
    storage,
    masterKey,
    fortressId: fortressIdForAggregator,
  });
  const autoTriggerAction = AutoTriggerActionRegistry.withDefaults(
    auditLog,
    aggregatorIdentityId,
    fortressIdForAggregator,
  );
  const autoTriggerDispatcher = new ActionDispatcher({
    store: autoTriggerStore,
    action: autoTriggerAction,
    auditLog,
    fortressId: fortressIdForAggregator,
    identityId: aggregatorIdentityId,
  });
  const autoTriggerSuggester = new CalibrationSuggester({
    store: autoTriggerStore,
    dispatcher: autoTriggerDispatcher,
    auditLog,
    fortressId: fortressIdForAggregator,
    identityId: aggregatorIdentityId,
  });
  autoTriggerSuggester.start();

  const unifiedInboxStore = new UnifiedInboxStore({
    storage,
    masterKey,
    fortressId: fortressIdForAggregator,
  });
  const unifiedInboxBridge = new UnifiedInboxBridge({
    auditLog,
    identityId: aggregatorIdentityId,
    fortressId: fortressIdForAggregator,
    store: unifiedInboxStore,
  });
  await unifiedInboxBridge.rehydratePendingFromStore();
  const unifiedInboxRetentionPolicyStore =
    new UnifiedInboxRetentionPolicyStore({
      storage,
      masterKey,
      fortressId: fortressIdForAggregator,
    });
  const unifiedInboxRetentionPolicy =
    await unifiedInboxRetentionPolicyStore.load();
  const unifiedInboxPrefsStore = new UnifiedInboxPrefsStore({
    storage,
    masterKey,
    fortressId: fortressIdForAggregator,
    operatorId: aggregatorIdentityId,
  });
  const unifiedInboxScheduler = new UnifiedInboxScheduler({
    bridge: unifiedInboxBridge,
  });
  unifiedInboxScheduler.start();

  // v1.3 WP-V1.3-10 Upsilon-2: wrap the approval channel with the
  // aggregator-backed channel. When `approval_redirect.enabled` is false
  // (default), the wrapper short-circuits to underlying-passthrough; the
  // wire-up is unconditional so operators can flip the toggle via
  // `sanctuary agents config --approval-redirect=true` without restarting
  // the server. Mode `replace` bypasses the underlying channel; mode
  // `notify` races both paths (Mastra-class fallback).
  const wrappedApprovalChannel = new AggregatorBackedChannel({
    underlying: approvalChannel,
    aggregator: approvalAggregator,
    resolveRedirect: makeRedirectResolverFromPolicySupplier(() => policy),
    replaceModeTimeoutMs: policy.approval_channel.timeout_seconds * 1000,
  });

  const approvalProofStore = new ApprovalProofStore();
  const gate = new ApprovalGate(
    policy,
    baseline,
    wrappedApprovalChannel,
    auditLog,
    injectionDetector,
    onInjectionAlert,
    undefined,
    { currentSessionBinding, approvalProofStore }
  );

  gate.setApprovalEventCallback((event) => {
    void approvalAggregator.ingest(event as unknown as ApprovalGateEvent);
  });
  if (dashboard) {
    dashboard.setApprovalAggregator(approvalAggregator);
    dashboard.setUnifiedInbox({
      bridge: unifiedInboxBridge,
      retentionPolicy: unifiedInboxRetentionPolicy,
      retentionPolicyStore: unifiedInboxRetentionPolicyStore,
      prefsStore: unifiedInboxPrefsStore,
      fortressId: fortressIdForAggregator,
      identityId: aggregatorIdentityId,
    });
  }

  // v1.3 WP-V1.3-1 Phi-1: Sentinel Baseline Pack (Castle Layer 2 anchor).
  // Construct the per-fortress dispatcher + finding store, register the
  // Phi-1 catalog, and re-subscribe whatever the operator opted into on
  // a prior boot. The dispatcher's auto-tick is enabled so subscribed
  // sentinels run periodically; tick interval is fixed at the
  // coordinator-CTO default until per-fortress override lands. No new
  // outbound surface; sentinels read server-local audit data only.
  const sentinelFindingStore = new SentinelFindingStore({
    storage,
    masterKey,
    fortressId: fortressIdForAggregator,
  });
  const sentinelRegistry = new SentinelRegistry();
  for (const entry of PHI1_BASELINE_CATALOG) {
    sentinelRegistry.register(entry);
  }
  const sentinelDispatcher = new SentinelDispatcher({
    registry: sentinelRegistry,
    findingStore: sentinelFindingStore,
    auditLog,
    fortressId: fortressIdForAggregator,
    identityId: aggregatorIdentityId,
  });
  try {
    const persistedSubscriptions = await loadSentinelSubscriptions(
      config.storage_path,
    );
    for (const sentinelId of persistedSubscriptions) {
      try {
        await sentinelDispatcher.subscribeSentinel(sentinelId);
      } catch {
        // Unknown sentinel id from a prior version: skip silently.
      }
    }
  } catch {
    // Subscription file missing or unreadable: dispatcher starts empty.
  }
  sentinelDispatcher.start();
  sentinelDispatcher.onEvent((event) => {
    if (event.type !== "finding") return;
    void autoTriggerDispatcher.handleFinding(event.finding, "sentinel");
  });
  if (dashboard) {
    dashboard.setSentinelDispatcher(sentinelDispatcher);
    dashboard.setAutoTrigger({
      store: autoTriggerStore,
      dispatcher: autoTriggerDispatcher,
      suggester: autoTriggerSuggester,
    });
  }

  // v1.3 WP-V1.3-2 Chi-1: Anomaly Detection Pipeline (Castle Layer 2
  // statistical-drift complement to the rule-based Sentinel pack).
  // Construct the per-fortress dispatcher; reuse Phi-1 finding store
  // so anomaly findings flow through the same operator surface.
  // Detectors are NOT auto-registered; operator-visible registration
  // UI ships with Chi-3. Sovereignty invariant: classifier state
  // stays per-fortress, encrypted at rest, never centrally aggregated.
  const anomalyDispatcher = new AnomalyPipelineDispatcher({
    findingStore: sentinelFindingStore,
    auditLog,
    storage,
    masterKey,
    fortressId: fortressIdForAggregator,
    identityId: aggregatorIdentityId,
  });
  anomalyDispatcher.start();
  anomalyDispatcher.onEvent((event) => {
    if (event.type !== "finding") return;
    void autoTriggerDispatcher.handleFinding(event.finding, "anomaly");
  });
  // Keep a reference so the GC doesn't collect the dispatcher even
  // when no detectors are registered. Tests that need access mount
  // their own; runtime callers reach the dispatcher via the future
  // dashboard-side accessor (Chi-3).
  void anomalyDispatcher;

  // v1.3 WP-V1.3-3 Omega-1: Coordination Handoff Visualization.
  // Read-only data API + dashboard view over the existing audit log.
  // No new outbound surface; new audit ops are operator-action
  // observability only.
  const handoffLog = new HandoffLog({
    auditLog,
    fortressId: fortressIdForAggregator,
  });
  const handoffEventBridge = new HandoffEventBridge();
  // v1.3 WP-V1.3-3 Omega-3 workflow state tracker. Per-fortress
  // instance so transition emissions stay scoped to the fortress that
  // observed them. The HandoffLog instance is already per-fortress;
  // the tracker rides the same scope.
  const workflowStateTracker = new WorkflowStateTracker();
  if (dashboard) {
    dashboard.setHandoffLog({
      handoffLog,
      eventBridge: handoffEventBridge,
      auditLog,
      operatorId: aggregatorIdentityId,
      workflowStateTracker,
    });
  }

  // v1.3 WP-V1.3-5 Pi-1/Pi-2: Honeypot Authoring. Construct the per-
  // fortress trap registry, encrypted at-rest trap store, and bind to
  // the dashboard alongside the existing sentinel finding store +
  // audit log.
  //
  // Pi-2 closes Pi-1's two deferred items:
  //   (a) Boot-path selector forwarding. `intelligenceSelector` is now
  //       hoisted to outer function scope and is in scope here; we
  //       forward it to the management routes so the LLM compile path
  //       fires from the API surface AND from any embedded caller.
  //   (b) Fortress-config persistence. A `TrapStore` encrypts deployed
  //       TrapSpecs under an HKDF subkey of the fortress master key
  //       (info string `l2-honeypot-trap-v1`, AAD bound to trap_id),
  //       parallels the Phi-1 SentinelFindingStore shape, and lets the
  //       fortress restore deployed traps after restart. We call
  //       `store.loadAll()` to repopulate the in-memory registry
  //       BEFORE binding to the dashboard so trap dispatch is live
  //       from the first request the dashboard serves.
  //
  // Boot reload is best-effort: a store error (storage corruption,
  // missing namespace) logs to stderr and the registry stays empty;
  // operators can re-deploy via the management API. A registry with
  // no specs is operationally indistinguishable from a fresh fortress.
  const honeypotRegistry = new TrapRegistry();
  const honeypotStore = new TrapStore({
    storage,
    masterKey,
    fortressId: fortressIdForAggregator,
  });
  const toolCallTrapRuntime = new ToolCallTrapRuntime({
    registry: honeypotRegistry,
    findingStore: sentinelFindingStore,
    auditLog,
    operatorId: aggregatorIdentityId,
    fortressId: fortressIdForAggregator,
  });
  const credentialTrapRuntime = new CredentialTrapRuntime({
    registry: honeypotRegistry,
    findingStore: sentinelFindingStore,
    auditLog,
    operatorId: aggregatorIdentityId,
    fortressId: fortressIdForAggregator,
  });
  try {
    const persistedSpecs = await honeypotStore.loadAll();
    for (const spec of persistedSpecs) {
      honeypotRegistry.deploy(spec);
    }
    if (persistedSpecs.length > 0) {
      await auditLog.append(
        "l2",
        HONEYPOT_AUDIT_OPS.LOADED,
        aggregatorIdentityId,
        {
          fortress_id: fortressIdForAggregator,
          trap_count: persistedSpecs.length,
        },
      );
    }
  } catch (err) {
    // SAFETY: same logging story as the intelligence selector site;
    // raw stderr until a structured logger lands.
    console.error(
      `  Note: honeypot trap store unavailable (${(err as Error).message}). ` +
        `Deployed traps from prior runs will not be restored; re-deploy via the management API.`,
    );
  }
  if (dashboard) {
    dashboard.setHoneypotRegistry({
      registry: honeypotRegistry,
      findingStore: sentinelFindingStore,
      auditLog,
      operatorId: aggregatorIdentityId,
      fortressId: fortressIdForAggregator,
      ...(intelligenceSelector ? { selector: intelligenceSelector } : {}),
      store: honeypotStore,
      toolCallRuntime: toolCallTrapRuntime,
      credentialRuntime: credentialTrapRuntime,
    });
  }

  // 16. Create Principal Policy tools (read-only)
  const policyTools = createPrincipalPolicyTools(policy, baseline, auditLog);

  // 16a. Create Sanctuary bootstrap + identity + policy-status tools
  const { tools: sanctuaryMetaTools } = createSanctuaryTools({
    config,
    identityManager,
    masterKey,
    auditLog,
    policy,
    keyProtection,
    reputationStore,
  });

  // 16b. Create memory attestation tools (L1 cognitive sovereignty)
  const { tools: memoryAttestTools } = createMemoryAttestTools(
    identityManager,
    masterKey,
    auditLog
  );

  // 16b2. Create EU AI Act compliance bundle tools (Tier 3 auto-allow —
  // read-only; emits Annex IV/Art. 12/13/14/15/26 artifacts signed by
  // the primary identity)
  const { tools: complianceTools } = createComplianceTools({
    config,
    identityManager,
    masterKey,
    auditLog,
    policy,
  });

  // 16b. ERC-8004 Identity Registry operator UX (Key 17 PR 3)
  const erc8004PolicyGate = new DefaultPolicyGate({
    global_default: "operator_approval_required",
    erc8004: {
      default_decision: "operator_approval_required",
      counterparty_rules: [],
    },
  });
  const { tools: erc8004Tools } = createErc8004Tools({
    masterKey,
    policyGate: erc8004PolicyGate,
    auditLog,
    identityId: aggregatorIdentityId,
    operatorId: aggregatorIdentityId,
    inboxBridge: unifiedInboxBridge,
    fortressId: fortressIdForAggregator,
  });

  const { tools: agentNativeTools } = createAgentNativeCooperativeTools({
    identityManager,
    namespaceRegistry,
    auditLog,
    currentSessionBinding,
    primitiveTools: l1Tools,
    storage,
    approvalProofStore,
  });

  // 16c. HABEAS PORT distress emission surface (agent-side sovereignty,
  // ratified 2026-06-12). The lane config is operator-owned and loaded once,
  // frozen — like the Principal Policy. A present-but-invalid distress.json
  // aborts startup (fail closed) rather than silently running a different
  // lane shape than the operator configured.
  const distressLaneConfig = await readDistressConfig(config.storage_path);
  // HABEAS PORT local-listener delivery. The MCP server is the emitter; if a
  // long-lived operator dashboard is running its local listener on
  // 127.0.0.1:8741, hand it each (post-audit) envelope so it surfaces in the
  // operator inbox. Loading the operator-uid-only shared secret is best-effort:
  // if it fails (e.g. a bad secret mode), local delivery is simply not wired
  // and emission behaves exactly as it shipped (stderr + audit). The secret is
  // never logged.
  let distressLocalSecret: Uint8Array | undefined;
  try {
    distressLocalSecret = await loadOrCreateLocalListenerSecret(config.storage_path);
  } catch (err) {
    // SAFETY: stderr is the operator-facing console channel here.
    console.error(
      `[SANCTUARY DISTRESS] local-listener delivery disabled: ` +
        `${err instanceof Error ? err.message : String(err)} ` +
        `(in-process lane — stderr + audit — is unaffected)`,
    );
    distressLocalSecret = undefined;
  }
  const { tools: distressTools } = createDistressTools({
    auditLog,
    signingHelpers: createInternalIdentitySigningHelpers(
      identityManager,
      masterKey,
      auditLog
    ),
    config: distressLaneConfig,
    fortressPath: config.storage_path,
    currentActorId: () => currentSessionBinding()?.identity_id,
    ...(distressLocalSecret !== undefined
      ? {
          localDeliver: ({ envelope, envelopeHash }) =>
            deliverDistressLocally({
              envelope,
              envelopeHash,
              localSecret: distressLocalSecret!,
            }),
        }
      : {}),
  });

  // 17. Assemble all tools
  let allTools: ToolDefinition[] = [
    ...l1Tools,
    ...l2Tools,
    ...l3Tools,
    ...l4Tools,
    ...policyTools,
    ...shrTools,
    ...handshakeTools,
    ...federationTools,
    ...bridgeTools,
    ...auditTools,
    ...siemTools,
    ...contextGateTools,
    ...hardeningTools,
    ...profileTools,
    ...sanctuaryMetaTools,
    ...memoryAttestTools,
    ...complianceTools,
    ...erc8004Tools,
    ...agentNativeTools,
    ...distressTools,
    manifestTool,
  ];

  // 17a. Initialize proxy layer for upstream MCP servers (if configured)
  let clientManager: ClientManager | undefined;
  let proxyRouter: ProxyRouter | undefined;
  let refreshProxyTools: (() => void) | undefined;
  let notifyProxyToolListChanged: (() => Promise<void>) | undefined;
  const governor = new CallGovernor();

  // 17a. Create governor tools
  const { tools: governorTools } = createGovernorTools(governor, auditLog);
  allTools.push(...governorTools);
  allTools = classifyMcpTools(allTools);

  const profile = profileStore.get();
  if (profile.upstream_servers && profile.upstream_servers.length > 0) {
    const enabledServers = profile.upstream_servers.filter(s => s.enabled);
    if (enabledServers.length > 0) {
      clientManager = new ClientManager({
        onStateChange: (serverName, state, toolCount, error) => {
          // Broadcast status to dashboard if available
          if (dashboard) {
            dashboard.broadcastSSE("proxy-server-status", {
              server: serverName,
              state,
              tool_count: toolCount,
              error,
              timestamp: new Date().toISOString(),
            });
          }
          // Log state changes
          void auditLog.append("l2", `proxy_server_${state}`, "system", {
            server: serverName,
            tool_count: toolCount,
            error,
          });
        },
        onToolListChanged: () => {
          refreshProxyTools?.();
        },
      });

      proxyRouter = new ProxyRouter(
        clientManager,
        injectionDetector,
        auditLog,
        {
          contextGateFilter: async (_toolName, args) => {
            const activeProfile = profileStore.get();
            if (activeProfile.features.context_gating.enabled) {
              return contextGateEnforcer.filterArgs(_toolName, args, {
                respectBypass: false,
              });
            }
            return args;
          },
          governor,
          onProxyCall: (data) => {
            // Broadcast proxy call events to the dashboard Fortress View feed
            if (dashboard) {
              dashboard.broadcastProxyCall(data);
            }
          },
        }
      );

      // Start connecting to upstream servers (non-blocking)
      clientManager.configure(enabledServers).catch(err => {
        // SAFETY: no structured logger module is wired in server/src/ yet; until one lands, raw stderr is the runtime warning channel for this site.
        console.error(`[Sanctuary] Failed to configure upstream servers: ${err instanceof Error ? err.message : "unknown error"}`);
      });

      // Wire client manager to dashboard for SSE status updates
      if (dashboard) {
        dashboard.setDependencies({
          policy,
          baseline,
          auditLog,
          clientManager,
        });
        // Enable Fortress View (proxy mode) when upstream servers are configured
        dashboard.enableFortressView(enabledServers.length);
      }
    }
  }

  // 17b. Wrap all tool handlers with context gate enforcer
  allTools = allTools.map((tool) => ({
    ...tool,
    handler: contextGateEnforcer.wrapHandler(tool.name, tool.handler),
  }));

  let dynamicProxyRegistry: DynamicProxyToolRegistry | undefined;
  if (proxyRouter) {
    dynamicProxyRegistry = new DynamicProxyToolRegistry({
      tools: allTools,
      proxyRouter,
      notifyListChanged: async () => {
        await notifyProxyToolListChanged?.();
      },
    });
    refreshProxyTools = () => {
      dynamicProxyRegistry?.refresh();
    };
    refreshProxyTools();
  }

  // 18. Wire proxy tier resolver into the approval gate
  if (proxyRouter) {
    gate.setProxyTierResolver((toolName: string) => {
      const parsed = ProxyRouter.parseProxyToolName(toolName);
      if (!parsed) return null;
      return proxyRouter!.getTierForTool(parsed.serverName, parsed.toolName);
    });
  }

  // 19. Create MCP server with approval gate (proxy tools are included in allTools)
  const server = createServer(allTools, {
    gate,
    auditLog,
    toolCallTrapRuntime,
    currentAgentId: () => process.env.SANCTUARY_AGENT_ID,
    currentSessionBinding,
  });
  if (proxyRouter) {
    enableToolListChangedNotifications(server);
    notifyProxyToolListChanged = async () => {
      await server.sendToolListChanged();
    };
  }

  // 20. Save config if this is first run
  await saveConfig(config);

  // 21. Register baseline save and proxy shutdown on process exit
  const cleanup = () => {
    unifiedInboxScheduler.stop();
    baseline.save().catch(() => {});
    if (clientManager) {
      clientManager.shutdown().catch(() => {});
    }
  };
  process.on("SIGINT", cleanup);
  process.on("SIGTERM", cleanup);

  // 22. Disclose the full recovery key if generated (shown once, never again).
  // The MCP server stdio path is not interactive (the host harness owns
  // stdin), so we disclose via banner + recovery-key.txt file but skip the
  // confirmation prompt. Operators who want the prompt should run
  // `sanctuary init` first instead of letting the stdio server first-run
  // generate the key.
  if (recoveryKey) {
    await discloseRecoveryKey({
      recoveryKey,
      storagePath: config.storage_path,
      mode: "stdio-server",
    });
  }

  return {
    server,
    config,
    identityManager,
    masterKey,
    auditLog,
    policy,
  };
}

const WRITE_MCP_TOOLS: ReadonlySet<string> = new Set([
  "audit_export_siem",
  "bootstrap_create_escrow",
  "bootstrap_provide_guarantee",
  "bridge_attest",
  "bridge_commit",
  "compliance_generate_eu_ai_act_bundle",
  "context_gate_enforcer_configure",
  "context_gate_filter",
  "disclosure_evaluate",
  "disclosure_set_policy",
  "federation_trust_evaluate",
  "governor_reset",
  "handshake_abort",
  "handshake_complete",
  "handshake_exchange",
  "handshake_initiate",
  "handshake_respond",
  "handshake_verify_attestation",
  "identity_create",
  "identity_import",
  "identity_rotate",
  "identity_set_primary",
  "identity_sign",
  "memory_attest",
  "proof_reveal",
  "reputation_export",
  "reputation_import",
  "reputation_publish",
  "reputation_record",
  "sanctuary/sign_erc8004_identity",
  "sanctuary_bootstrap",
  "sanctuary_export_identity_bundle",
  "sanctuary_link_to_human",
  "sanctuary_sign_challenge",
  "shr_gateway_export",
  "shr_generate",
  "state_delete",
  "state_export",
  "state_import",
  "state_write",
  "sovereignty_profile_generate_prompt",
  "sovereignty_profile_update",
  "zk_commit",
  "zk_prove",
  "zk_range_prove",
] as const);

const OPERATOR_TERMINAL_ONLY_MCP_TOOLS: ReadonlySet<string> = new Set([
  "context_gate_apply_template",
  "context_gate_set_policy",
] as const);

const READ_MCP_TOOLS: ReadonlySet<string> = new Set([
  "bridge_verify",
  "compliance_eu_ai_act_annex_iii_classify",
  "context_gate_enforcer_status",
  "context_gate_list_policies",
  "context_gate_recommend",
  "exec_attest",
  "federation_peers",
  "federation_status",
  "governor_status",
  "handshake_status",
  "identity_list",
  "identity_verify",
  "l2_hardening_status",
  "l2_verify_isolation",
  "manifest",
  "monitor_audit_log",
  "monitor_health",
  "principal_baseline_view",
  "principal_policy_view",
  "proof_commitment",
  "reputation_query",
  "reputation_query_weighted",
  "sanctuary_policy_status",
  "shr_verify",
  "sovereignty_audit",
  "sovereignty_profile_get",
  "state_list",
  "state_read",
  "zk_range_verify",
  "zk_verify",
] as const);

function classifyMcpTools(tools: ToolDefinition[]): ToolDefinition[] {
  return tools.map((tool) => {
    if (tool.name.startsWith("proxy/")) {
      return { ...tool, tool_class: "write" };
    }
    if (WRITE_MCP_TOOLS.has(tool.name)) {
      return { ...tool, tool_class: "write" };
    }
    if (OPERATOR_TERMINAL_ONLY_MCP_TOOLS.has(tool.name)) {
      return { ...tool, tool_class: "write" };
    }
    if (READ_MCP_TOOLS.has(tool.name)) {
      return { ...tool, tool_class: "read" };
    }
    if (tool.tool_class === "read" || tool.tool_class === "write") {
      return tool;
    }
    throw new Error(`No MCP tool_class classification for registered tool: ${tool.name}`);
  });
}

export { loadConfig, type SanctuaryConfig } from "./config.js";
export { StateStore } from "./l1-cognitive/state-store.js";
export { AuditLog } from "./l2-operational/audit-log.js";
export { CommitmentStore } from "./l3-disclosure/commitments.js";
export {
  createPedersenCommitment,
  verifyPedersenCommitment,
  createProofOfKnowledge,
  verifyProofOfKnowledge,
  createRangeProof,
  verifyRangeProof,
} from "./l3-disclosure/zk-proofs.js";
export type {
  PedersenCommitment,
  ZKProofOfKnowledge,
  ZKRangeProof,
} from "./l3-disclosure/zk-proofs.js";
export { PolicyStore } from "./l3-disclosure/policies.js";
export { ReputationStore } from "./l4-reputation/reputation-store.js";
export {
  resolveTier,
  computeWeightedScore,
  tierDistribution,
  TIER_WEIGHTS,
} from "./l4-reputation/tiers.js";
export type { SovereigntyTier, TierMetadata, TieredAttestation } from "./l4-reputation/tiers.js";
export { FederationRegistry } from "./federation/registry.js";
export type {
  FederationPeer,
  FederationCapabilities,
  PeerTrustEvaluation,
} from "./federation/types.js";
export { ContextGatePolicyStore } from "./l2-operational/context-gate.js";
export {
  TEMPLATES as CONTEXT_GATE_TEMPLATES,
  getTemplate,
  listTemplateIds,
} from "./l2-operational/context-gate-templates.js";
export type { ContextGateTemplate } from "./l2-operational/context-gate-templates.js";
export {
  classifyField,
  recommendPolicy,
} from "./l2-operational/context-gate-recommend.js";
export type {
  FieldClassification,
  PolicyRecommendation,
} from "./l2-operational/context-gate-recommend.js";
export {
  InMemoryModelProvenanceStore,
  MODEL_PRESETS,
} from "./l2-operational/model-provenance.js";
export type {
  ModelProvenance,
  ModelProvenanceStore,
} from "./l2-operational/model-provenance.js";
export {
  evaluateField,
  filterContext,
} from "./l2-operational/context-gate.js";
export type {
  ContextGatePolicy,
  ContextGateRule,
  ContextFilterResult,
  FieldFilterResult,
  ProviderCategory,
  ContextAction,
} from "./l2-operational/context-gate.js";
export { InjectionDetector } from "./security/injection-detector.js";
export type {
  InjectionDetectorConfig,
  DetectionResult,
  InjectionSignal,
} from "./security/injection-detector.js";
export { ContextGateEnforcer } from "./l2-operational/context-gate-enforcer.js";
export type { EnforcerConfig } from "./l2-operational/context-gate-enforcer.js";
export { SovereigntyProfileStore, createDefaultProfile } from "./sovereignty-profile.js";
export type { SovereigntyProfile, SovereigntyProfileUpdate, UpstreamServer } from "./sovereignty-profile.js";
export { ClientManager } from "./proxy/client-manager.js";
export type { ConnectionState, UpstreamConnection, UpstreamTool } from "./proxy/client-manager.js";
export { ProxyRouter } from "./proxy/proxy-router.js";
export type { ProxyRouterOptions } from "./proxy/proxy-router.js";
export { generateSystemPrompt } from "./system-prompt-generator.js";
export { MemoryStorage } from "./storage/memory.js";
export { FilesystemStorage } from "./storage/filesystem.js";
export * from "./exit/index.js";
export { ApprovalGate } from "./principal-policy/gate.js";
export { BaselineTracker } from "./principal-policy/baseline.js";
export { loadPrincipalPolicy, MalformedPrincipalPolicyError } from "./principal-policy/loader.js";
export type { PrincipalPolicy, GateResult } from "./principal-policy/types.js";
export {
  StderrApprovalChannel,
  CallbackApprovalChannel,
  AutoApproveChannel,
} from "./principal-policy/approval-channel.js";
export { DashboardApprovalChannel } from "./principal-policy/dashboard.js";
export type { DashboardConfig } from "./principal-policy/dashboard.js";
export { WebhookApprovalChannel, signPayload, verifySignature } from "./principal-policy/webhook.js";
export type { WebhookConfig, WebhookPayload, WebhookCallbackPayload } from "./principal-policy/webhook.js";
export { generateSHR } from "./shr/generator.js";
export { verifySHR } from "./shr/verifier.js";
export type { SignedSHR, SHRBody, SHRVerificationResult } from "./shr/types.js";
export {
  initiateHandshake,
  respondToHandshake,
  completeHandshake,
  verifyCompletion,
} from "./handshake/protocol.js";
export type {
  HandshakeChallenge,
  HandshakeResponse,
  HandshakeCompletion,
  HandshakeResult,
} from "./handshake/types.js";
export {
  generateAttestation,
  verifyAttestation,
  ATTESTATION_VERSION,
} from "./handshake/attestation.js";
export type { SHRGeneratorOptions } from "./shr/generator.js";
export type {
  SignedAttestation,
  AttestationBody,
  AttestationVerificationResult,
} from "./handshake/attestation.js";
export {
  createBridgeCommitment,
  verifyBridgeCommitment,
  canonicalize,
} from "./bridge/bridge.js";
export type {
  ConcordiaOutcome,
  BridgeCommitment,
  BridgeVerificationResult,
  BridgeAttestationRequest,
  BridgeAttestationResult,
} from "./bridge/types.js";

// ── Sovereignty Dashboard ───────────────────────────────────────────
export {
  startDashboard,
  startDashboardServer,
  getProtectionSnapshot,
  renderDashboardHTML,
  HERO_COPY,
} from "./dashboard/index.js";
export type {
  StartDashboardOptions,
  DashboardHandle,
  DashboardServerOptions,
  ProtectionSnapshot,
  ActivityEntry,
  PendingApproval,
  ReputationLookup,
  AggregatorSources,
  L1Status,
  L2Status,
  L3Status,
  L4Status,
  ApprovalHandlers,
  StreamEvent,
} from "./dashboard/index.js";
