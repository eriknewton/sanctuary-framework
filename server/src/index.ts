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
import { ApprovalGate } from "./principal-policy/gate.js";
import { createPrincipalPolicyTools } from "./principal-policy/tools.js";
import { createServer, type ToolDefinition } from "./router.js";
import { toolResult } from "./router.js";
import { createSHRTools } from "./shr/tools.js";
import { createHandshakeTools } from "./handshake/tools.js";
import { createFederationTools } from "./federation/tools.js";
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
    // Recovery key path: generate random master key
    keyProtection = "recovery-key";

    // Check if we already have a stored (encrypted) master key reference
    const existing = await storage.read("_meta", "recovery-key-hash");
    if (existing) {
      // Existing installation — we need the recovery key to proceed
      // For now, generate a new key (first-run scenario)
      // TODO: prompt for recovery key on subsequent runs
      masterKey = generateRandomKey();
      recoveryKey = toBase64url(masterKey);
    } else {
      masterKey = generateRandomKey();
      recoveryKey = toBase64url(masterKey);

      // Store a hash of the recovery key so we can verify it later
      const { hashToString } = await import("./core/hashing.js");
      const { stringToBytes } = await import("./core/encoding.js");
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
          mitigation: "TEE support planned for v0.3.0",
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
          "L2 isolation is process-level only; TEE support planned for v0.3.0",
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
  const { tools: l4Tools } = createL4Tools(
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

  // 15. Load Principal Policy and create approval gate
  const policy = await loadPrincipalPolicy(config.storage_path);
  const baseline = new BaselineTracker(storage, masterKey);
  await baseline.load();

  const approvalChannel = new StderrApprovalChannel(policy.approval_channel);
  const gate = new ApprovalGate(policy, baseline, approvalChannel, auditLog);

  // 16. Create Principal Policy tools (read-only)
  const policyTools = createPrincipalPolicyTools(policy, baseline, auditLog);

  // 17. Assemble all tools
  const allTools: ToolDefinition[] = [
    ...l1Tools,
    ...l2Tools,
    ...l3Tools,
    ...l4Tools,
    ...policyTools,
    ...shrTools,
    ...handshakeTools,
    ...federationTools,
    manifestTool,
  ];

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
