/**
 * Sanctuary MCP Server — Main Entry Point
 *
 * Initializes and exports the Sanctuary MCP server.
 * Wires together: config → storage → crypto core → L1-L4 tools → MCP server
 */

import { mkdir } from "node:fs/promises";
import { loadConfig, saveConfig, type SanctuaryConfig } from "./config.js";
import { FilesystemStorage } from "./storage/filesystem.js";
import type { StorageBackend } from "./storage/interface.js";
import { StateStore } from "./l1-cognitive/state-store.js";
import { createL1Tools } from "./l1-cognitive/tools.js";
import { AuditLog } from "./l2-operational/audit-log.js";
import { createL3Tools } from "./l3-disclosure/tools.js";
import { createL4Tools } from "./l4-reputation/tools.js";
import { loadPrincipalPolicy } from "./principal-policy/loader.js";
import { BaselineTracker } from "./principal-policy/baseline.js";
import { StderrApprovalChannel } from "./principal-policy/approval-channel.js";
import { DashboardApprovalChannel } from "./principal-policy/dashboard.js";
import { WebhookApprovalChannel } from "./principal-policy/webhook.js";
import { ApprovalGate } from "./principal-policy/gate.js";
import { createPrincipalPolicyTools } from "./principal-policy/tools.js";
import { createServer, type ToolDefinition } from "./router.js";
import { toolResult } from "./router.js";
import { createSHRTools } from "./shr/tools.js";
import { createHandshakeTools } from "./handshake/tools.js";
import { createFederationTools } from "./federation/tools.js";
import { createBridgeTools } from "./bridge/tools.js";
import { createAuditTools } from "./audit/tools.js";
import { createContextGateTools } from "./l2-operational/context-gate-tools.js";
import { createL2HardeningTools } from "./l2-operational/hardening-tools.js";
import { InjectionDetector } from "./security/injection-detector.js";
import { deriveMasterKey, type KeyDerivationParams } from "./core/key-derivation.js";
import { generateRandomKey } from "./core/random.js";
import { toBase64url } from "./core/encoding.js";

import type { Server } from "@modelcontextprotocol/sdk/server/index.js";

export interface SanctuaryServer {
  server: Server;
  config: SanctuaryConfig;
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

  // 2. Ensure storage directory exists
  await mkdir(config.storage_path, { recursive: true, mode: 0o700 });

  // 3. Initialize storage backend
  const storage = options?.storage ?? new FilesystemStorage(
    `${config.storage_path}/state`
  );

  // 4. Derive or generate master key
  let masterKey: Uint8Array;
  let keyProtection: "passphrase" | "hardware-key" | "recovery-key";
  let recoveryKey: string | undefined;

  const passphrase = options?.passphrase ?? process.env.SANCTUARY_PASSPHRASE;

  if (passphrase) {
    // Passphrase path: derive master key via Argon2id
    keyProtection = "passphrase";

    // Check for existing derivation params
    let existingParams: KeyDerivationParams | undefined;
    try {
      const raw = await storage.read("_meta", "key-params");
      if (raw) {
        const { bytesToString } = await import("./core/encoding.js");
        existingParams = JSON.parse(bytesToString(raw));
      }
    } catch {
      // No existing params — first run
    }

    const result = await deriveMasterKey(passphrase, existingParams);
    masterKey = result.key;

    // Store derivation params (not the key!) for re-derivation
    if (!existingParams) {
      const { stringToBytes } = await import("./core/encoding.js");
      await storage.write(
        "_meta",
        "key-params",
        stringToBytes(JSON.stringify(result.params))
      );
    }
  } else {
    // Recovery key path
    keyProtection = "recovery-key";

    const { hashToString } = await import("./core/hashing.js");
    const { stringToBytes, bytesToString } = await import("./core/encoding.js");
    const { fromBase64url } = await import("./core/encoding.js");
    const { constantTimeEqual } = await import("./core/encoding.js");

    // Check if we already have a stored recovery key hash (existing installation)
    const existingHash = await storage.read("_meta", "recovery-key-hash");
    if (existingHash) {
      // Existing installation — require the recovery key to proceed
      const envRecoveryKey = process.env.SANCTUARY_RECOVERY_KEY;
      if (!envRecoveryKey) {
        throw new Error(
          "Sanctuary: Existing encrypted data found but no credentials provided.\n" +
          "This installation was previously set up with a recovery key.\n\n" +
          "To start the server, provide one of:\n" +
          "  - SANCTUARY_PASSPHRASE (if you later configured a passphrase)\n" +
          "  - SANCTUARY_RECOVERY_KEY (the recovery key shown at first run)\n\n" +
          "Without the correct credentials, encrypted state cannot be accessed.\n" +
          "Refusing to start to prevent silent data loss."
        );
      }

      // Decode and verify the recovery key against the stored hash
      let recoveryKeyBytes: Uint8Array;
      try {
        recoveryKeyBytes = fromBase64url(envRecoveryKey);
      } catch {
        throw new Error(
          "Sanctuary: SANCTUARY_RECOVERY_KEY is not valid base64url. " +
          "The recovery key should be the exact string shown at first run."
        );
      }

      if (recoveryKeyBytes.length !== 32) {
        throw new Error(
          "Sanctuary: SANCTUARY_RECOVERY_KEY has incorrect length. " +
          "The recovery key should be the exact string shown at first run."
        );
      }

      const providedHash = hashToString(recoveryKeyBytes);
      const storedHash = bytesToString(existingHash);

      // Constant-time comparison to prevent timing attacks on the hash
      const providedHashBytes = stringToBytes(providedHash);
      const storedHashBytes = stringToBytes(storedHash);
      if (!constantTimeEqual(providedHashBytes, storedHashBytes)) {
        throw new Error(
          "Sanctuary: Recovery key does not match the stored key hash.\n" +
          "The recovery key provided via SANCTUARY_RECOVERY_KEY is incorrect.\n" +
          "Use the exact recovery key that was displayed at first run."
        );
      }

      // Recovery key verified — use it as the master key
      masterKey = recoveryKeyBytes;
      // Do NOT set recoveryKey — this is not a first run, no banner should display
    } else {
      // First run — but check for orphaned encrypted data as a safety net
      const existingNamespaces = await storage.list("_meta");
      const hasKeyParams = existingNamespaces.some(e => e.key === "key-params");
      if (hasKeyParams) {
        throw new Error(
          "Sanctuary: Found existing key derivation parameters but no recovery key hash.\n" +
          "This indicates a corrupted or incomplete installation.\n" +
          "If you previously used a passphrase, set SANCTUARY_PASSPHRASE to start."
        );
      }

      // Genuine first run: generate random master key and store its hash
      masterKey = generateRandomKey();
      recoveryKey = toBase64url(masterKey);

      const keyHash = hashToString(masterKey);
      await storage.write(
        "_meta",
        "recovery-key-hash",
        stringToBytes(keyHash)
      );
    }
  }

  // 5. Initialize audit log
  const auditLog = new AuditLog(storage, masterKey);

  // 6. Initialize state store
  const stateStore = new StateStore(storage, masterKey);

  // 7. Create L1 tools
  const { tools: l1Tools, identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    keyProtection,
    auditLog
  );

  // 8. Load existing identities
  await identityManager.load();

  // 9. Create L2 monitoring tools
  const l2Tools: ToolDefinition[] = [
    {
      name: "sanctuary/exec_attest",
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
        const degradations: string[] = [];

        // L2 is self-reported in MVS
        degradations.push(
          "L2 isolation is process-level only; no TEE available"
        );

        // L3 is commitment-only in MVS
        if (config.disclosure.proof_system === "commitment-only") {
          degradations.push(
            "L3 proofs are commitment-based only; ZK proofs not yet available"
          );
        }

        return toolResult({
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
              sanctuary_version: config.version,
              mcp_sdk_version: "1.26.0",
            },
            network: {
              internet_accessible: true, // Conservative assumption
              listening_ports: [],
              egress_restricted: false,
            },
            isolation_level: "process",
            sovereignty_assessment: {
              l1_state_encrypted: true,
              l2_execution_isolated: false,
              l2_isolation_type: "process-level",
              l3_proofs_available:
                config.disclosure.proof_system !== "commitment-only",
              l4_reputation_active: true,
              overall_level: "mvs",
              degradations,
            },
          },
          attested_at: new Date().toISOString(),
        });
      },
    },

    {
      name: "sanctuary/monitor_health",
      description:
        "Sanctuary Health Report (SHR) — standardized sovereignty status.",
      inputSchema: { type: "object", properties: {} },
      handler: async () => {
        const storageSizeBytes = await storage.totalSize();
        const degradations: Array<{
          layer: string;
          description: string;
          severity: string;
          mitigation: string;
        }> = [];

        degradations.push({
          layer: "l2",
          description: "Process-level isolation only (no TEE)",
          severity: "warning",
          mitigation: "TEE support planned for a future release",
        });

        if (config.disclosure.proof_system === "commitment-only") {
          degradations.push({
            layer: "l3",
            description: "Commitment schemes only (no ZK proofs)",
            severity: "info",
            mitigation: "ZK proof support planned for v0.2.0",
          });
        }

        return toolResult({
          status: degradations.some((d) => d.severity === "critical")
            ? "compromised"
            : degradations.some((d) => d.severity === "warning")
              ? "degraded"
              : "healthy",
          storage_bytes: storageSizeBytes,
          layers: {
            l1: {
              status: "active",
              encryption_algorithm: "aes-256-gcm",
              key_count: identityManager.list().length,
              state_integrity: "verified",
              last_integrity_check: new Date().toISOString(),
            },
            l2: {
              status: "degraded",
              isolation_type: "process-level",
              attestation_available: true,
              last_attestation: new Date().toISOString(),
            },
            l3: {
              status:
                config.disclosure.proof_system === "commitment-only"
                  ? "degraded"
                  : "active",
              proof_system: config.disclosure.proof_system,
              circuits_loaded: 0,
              proofs_generated_total: 0,
            },
            l4: {
              status: "active",
              mode: config.reputation.mode,
              interaction_count: 0, // TODO: track from reputation store
              reputation_exportable: true,
            },
          },
          degradations,
          checked_at: new Date().toISOString(),
        });
      },
    },

    {
      name: "sanctuary/monitor_audit_log",
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
        return toolResult(result);
      },
    },
  ];

  // 10. Create SIM manifest tool
  const manifestTool: ToolDefinition = {
    name: "sanctuary/manifest",
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

  // 12. Create SHR tools (machine-readable sovereignty health report)
  const { tools: shrTools } = createSHRTools(
    config,
    identityManager,
    masterKey,
    auditLog
  );

  // 13. Create Handshake tools (sovereignty handshake protocol)
  // Must be created before L4 so handshakeResults can feed tier resolution
  const { tools: handshakeTools, handshakeResults } = createHandshakeTools(
    config,
    identityManager,
    masterKey,
    auditLog
  );

  // 14. Create L4 tools (reputation with sovereignty-gated tiers)
  const { tools: l4Tools, reputationStore: _reputationStore } = createL4Tools(
    storage,
    masterKey,
    identityManager,
    auditLog,
    handshakeResults
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
  const { tools: auditTools } = createAuditTools(config);

  // 14e. Create Context Gating tools (L2 outbound context control)
  const { tools: contextGateTools, enforcer: contextGateEnforcer } =
    createContextGateTools(storage, masterKey, auditLog);

  // 14f. Create L2 Process Hardening tools
  const hardeningTools = createL2HardeningTools(config.storage_path, auditLog);

  // 15. Load Principal Policy and create approval gate
  const policy = await loadPrincipalPolicy(config.storage_path);
  const baseline = new BaselineTracker(storage, masterKey);
  await baseline.load();

  // Choose approval channel: dashboard (web UI), webhook (external), or stderr (auto-deny)
  let approvalChannel: StderrApprovalChannel | DashboardApprovalChannel | WebhookApprovalChannel;
  let dashboard: DashboardApprovalChannel | undefined;

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
    });
    dashboard.setDependencies({ policy, baseline, auditLog });
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

  const gate = new ApprovalGate(policy, baseline, approvalChannel, auditLog, injectionDetector, onInjectionAlert);

  // 16. Create Principal Policy tools (read-only)
  const policyTools = createPrincipalPolicyTools(policy, baseline, auditLog);

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
    ...contextGateTools,
    ...hardeningTools,
    manifestTool,
  ];

  // 17a. Wrap all tool handlers with context gate enforcer
  allTools = allTools.map((tool) => ({
    ...tool,
    handler: contextGateEnforcer.wrapHandler(tool.name, tool.handler),
  }));

  // 18. Create MCP server with approval gate
  const server = createServer(allTools, { gate });

  // 19. Save config if this is first run
  await saveConfig(config);

  // 20. Register baseline save on process exit
  const saveBaseline = () => {
    baseline.save().catch(() => {});
  };
  process.on("SIGINT", saveBaseline);
  process.on("SIGTERM", saveBaseline);

  // 21. Log the recovery key if generated (shown once, never again)
  if (recoveryKey) {
    console.error(
      "╔══════════════════════════════════════════════════════════╗\n" +
      "║  SANCTUARY: First Run — Recovery Key Generated          ║\n" +
      "║                                                          ║\n" +
      `║  Recovery Key: ${recoveryKey.slice(0, 20)}...             ║\n` +
      "║                                                          ║\n" +
      "║  SAVE THIS KEY. It will not be shown again.              ║\n" +
      "║  Without it, your encrypted state is unrecoverable.      ║\n" +
      "╚══════════════════════════════════════════════════════════╝"
    );
  }

  return { server, config };
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
export { MemoryStorage } from "./storage/memory.js";
export { FilesystemStorage } from "./storage/filesystem.js";
export { ApprovalGate } from "./principal-policy/gate.js";
export { BaselineTracker } from "./principal-policy/baseline.js";
export { loadPrincipalPolicy } from "./principal-policy/loader.js";
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
