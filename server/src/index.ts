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
import { StateStore } from "./cognitive/state-store.js";
import { createCognitiveTools, createInternalIdentitySigningHelpers } from "./cognitive/tools.js";
import { createDistressTools } from "./distress/tools.js";
import { readDistressConfig } from "./distress/config.js";
import { deliverDistressLocally } from "./distress/local-delivery.js";
import { loadOrCreateLocalListenerSecret } from "./distress/local-secret.js";
import { AuditLog } from "./operational/audit-log.js";
import { createDisclosureTools } from "./disclosure/tools.js";
import { createReputationTools } from "./reputation/tools.js";
import { loadPrincipalPolicy, MalformedPrincipalPolicyError } from "./principal-policy/loader.js";
import type { IdentityManager } from "./cognitive/tools.js";
import type {
  ApprovalRequest,
  ApprovalResponse,
  PrincipalPolicy,
} from "./principal-policy/types.js";
import { BaselineTracker } from "./principal-policy/baseline.js";
import type { ApprovalChannel } from "./principal-policy/approval-channel.js";
import { DashboardApprovalChannel } from "./principal-policy/dashboard.js";
import { selectApprovalChannelByPolicy } from "./principal-policy/channel-selection.js";
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
import { buildServerInstructions } from "./agent-native/capabilities-catalog.js";
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
} from "./operational/context-gate-tools.js";
import { createOperationalHardeningTools } from "./operational/hardening-tools.js";
import { SovereigntyProfileStore } from "./sovereignty-profile.js";
import { createSovereigntyProfileTools } from "./sovereignty-profile-tools.js";
import { InjectionDetector } from "./security/injection-detector.js";
import { ClientManager } from "./proxy/client-manager.js";
import { ProxyRouter } from "./proxy/proxy-router.js";
import {
  DynamicProxyToolRegistry,
  enableToolListChangedNotifications,
} from "./proxy/dynamic-proxy.js";
import { CallGovernor } from "./operational/call-governor.js";
import { createGovernorTools } from "./operational/governor-tools.js";
import { createSanctuaryTools } from "./sanctuary-tools.js";
import { createMemoryAttestTools } from "./cognitive/memory-attest.js";
import { createSdwMemoryTools, memoryInsertApprovalArgs } from "./sdw/memory-tools.js";
import { createSdwMemoryFileTools } from "./sdw/memory-file-tools.js";
import { createMultiAgentIsolationGuard } from "./sdw/memory-isolation.js";
import { createSdwMemoryProvenanceTool } from "./sdw/memory-provenance-tool.js";
import { SdwMemoryBackendAdapter } from "./sdw/adapters/sdw-memory-backend.js";
import { createComplianceTools } from "./compliance/eu_ai_act/generator.js";
import { createErc8004Tools } from "./key-17/erc8004-tools.js";
import { createErc8004ResolveTools } from "./key-17/erc8004-resolve.js";
import {
  erc8004RpcDestination,
  type Erc8004RegistryEgressGate,
} from "./key-17/erc8004-registry-confirm.js";
import { DefaultPolicyGate } from "./key-17/policy-gate.js";
import { evaluateEgressGate } from "./policy-engine/egress-gate.js";
import { buildNullPolicy } from "./policy-engine/null-policy.js";
import {
  establishMaster,
  checkCastlePinCustody,
  readEnvelopeEpoch,
} from "./core/master-custody.js";
import { decrypt } from "./core/encryption.js";
import { derivePurposeKey } from "./core/key-derivation.js";
import {
  observeWitnessEpoch,
  evaluateAndEnforceRollback,
  evaluateAndEnforceRekorCounterFloor,
} from "./core/anti-rollback.js";
import { crossCheckConfigBaseline } from "./core/config-baseline.js";
import {
  readCustodyEpochCount,
  probeAuditHeadAnchor,
  deriveAuditEpochKeys,
} from "./operational/audit-log.js";
import { escrowBootRecoveryKey } from "./wrap/boot-recovery-escrow.js";
import { detectCustodyFactorOrphan } from "./wrap/orphan-detection.js";
import {
  buildV11Bindings,
  fortressIdFromStoragePath,
} from "./dashboard/v1_1/wiring.js";
import { OperatorAuthorizationSpentStore } from "./v1/operator-authorization-spent-store.js";
import { SubstrateSelector } from "./intelligence/selector.js";
import { installConsentGatedRedactor } from "./intelligence/privacy-tier2-redactor.js";
// Agent-facing audit redaction (property #11, no-policy-inference). Single-sourced
// in operational/agent-audit-redaction.ts so the redact-key set is shared by
// the agent-facing audit READ here (monitor_audit_log) and the agent-facing audit
// SEARCH in the cooperative surface. The OPERATOR audit path stays full-fidelity.
import { redactAuditEntryForAgent } from "./operational/agent-audit-redaction.js";

import type { Server } from "@modelcontextprotocol/sdk/server/index.js";

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
  /**
   * Embedding-only implementation for approval_channel.type: callback. The MCP
   * stdio server has no native callback transport, so callback policy selection
   * without this hook is a startup error.
   */
  approvalCallback?: (request: ApprovalRequest) => Promise<ApprovalResponse>;
}): Promise<SanctuaryServer> {
  // 1. Load configuration
  const config = await loadConfig(options?.configPath);

  // 2. Ensure storage directory exists with correct permissions
  await mkdir(config.storage_path, { recursive: true, mode: 0o700 });
  await tightenStoragePermissions(config.storage_path);

  // 3. Initialize storage backend. When the CALLER injects a storage backend
  // (embedding / in-memory test harness), the caller owns key custody and the
  // boot path does not impose the off-host escrow gate. The escrow gate exists
  // to protect the REAL-HOST filesystem first run (where a minted recovery key
  // would otherwise be orphaned inside the fortress dir); it only applies when
  // the boot path owns a filesystem fortress.
  const bootOwnsStorage = options?.storage === undefined;
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

  // 5rb. Anti-rollback Stage 1 boot cross-check. Compare the on-disk custody
  // epoch against the surviving on-disk witnesses (the #501 rotation epoch
  // record + the authenticated epoch witness). A regression — or any tampered
  // witness — WARNS LOUD, emits a P1-shaped `custody_rollback_suspected` audit
  // finding, and FREEZES trust-bearing writes (enforced at enforceCustodyFloor)
  // until an audited `restore-attest`. Boot is NEVER refused (F3: a false-
  // positive rollback detector that bricks legitimate restores is worse than
  // the attack). An OK verdict advances the monotonic witness forward.
  try {
    const epochKeys = deriveAuditEpochKeys(masterKey);
    let rotationEpochCount = 0;
    let rotationEpochTampered = false;
    try {
      const epochRecord = await readCustodyEpochCount(storage, {
        epochMacKey: epochKeys.epochMacKey,
      });
      if (epochRecord.status === "present") {
        rotationEpochCount = epochRecord.count;
      } else if (epochRecord.status === "tampered") {
        rotationEpochTampered = true;
      }
    } finally {
      epochKeys.epochWrapKey.fill(0);
      epochKeys.epochMacKey.fill(0);
    }
    // SPLICE witness: the audit head anchor probed under the unlocked master.
    // A present-but-unauthenticated head anchor is the custody-files-only
    // splice signature (it survives even if the attacker deleted the epoch
    // witnesses) — codex r1 HIGH fix.
    const headAnchorProbe = await probeAuditHeadAnchor(storage, masterKey);
    const observation = await observeWitnessEpoch({
      storage,
      master: masterKey,
      rotationEpochCount,
      rotationEpochTampered,
      headAnchor: { status: headAnchorProbe.status },
    });
    const envelopeEpoch = await readEnvelopeEpoch(storage);
    const rollback = await evaluateAndEnforceRollback({
      storage,
      master: masterKey,
      envelopeEpoch,
      observation,
    });
    if (rollback.verdict.kind === "rollback-suspected") {
      await auditLog.appendCritical({
        layer: "l2",
        operation: "custody_rollback_suspected",
        identity_id: fortressIdFromStoragePath(config.storage_path),
        result: "failure",
        details: {
          observed_epoch: rollback.verdict.observedEpoch,
          witnessed_epoch: rollback.verdict.witnessedEpoch,
          witness_source: rollback.verdict.witnessSource,
          notes: rollback.verdict.notes,
          trust_bearing_writes_frozen: true,
          remediation: "sanctuary restore-attest (fortress passphrase required)",
        },
      });
    }
    if (rollback.banner) {
      // SAFETY: stderr is the operator-facing channel for boot diagnostics.
      console.error(rollback.banner);
    }
  } catch (err) {
    // The detector must never block boot. A failure to RUN the cross-check is
    // logged (it does not by itself freeze writes — only a positive detection
    // does), so a detector bug cannot become a lockout generator.
    console.error(
      "Sanctuary: anti-rollback boot cross-check could not complete: " +
        (err instanceof Error ? err.message : String(err))
    );
  }

  // 5rb2. Anti-rollback Stage 2 boot cross-check (Rekor counter-floor).
  // Applies when transparency anchoring is ENABLED *or* anchor receipts are
  // present on disk (so a disk-write attacker cannot dodge Stage 2 by deleting
  // or rolling back the config while preserving receipts). Compares the on-disk
  // transparency counter floor against the highest LOCALLY-RECORDED anchored
  // counter (the highest counter for which a valid local anchor receipt — whose
  // counter the external Rekor log also remembers — survives on disk; resolved
  // OFFLINE, no network). A floor below it is a transparency-floor rollback of
  // an anchored fortress that preserved its receipts; it WARNS LOUD, emits the
  // same P1-shaped `custody_rollback_suspected` finding, and FREEZES
  // trust-bearing writes via the SAME marker Stage 1 uses (cleared by
  // `restore-attest`). Boot is NEVER refused. OFFLINE-ONLY: a coordinated
  // rollback that also deletes the higher receipts needs online Rekor
  // enumeration (Stage 2b) or Stage-4 hardware. Composes with the Stage 1
  // cross-check above; either freeze gates enforceCustodyFloor.
  try {
    const rekorFloor = await evaluateAndEnforceRekorCounterFloor({
      storage,
      master: masterKey,
      fortressId: fortressIdFromStoragePath(config.storage_path),
    });
    if (rekorFloor.verdict.kind === "rollback-suspected") {
      await auditLog.appendCritical({
        layer: "l2",
        operation: "custody_rollback_suspected",
        identity_id: fortressIdFromStoragePath(config.storage_path),
        result: "failure",
        details: {
          stage: 2,
          witness_source: "external Rekor transparency counter floor",
          on_disk_transparency_floor: rekorFloor.verdict.onDiskFloor,
          highest_externally_anchored_counter:
            rekorFloor.verdict.highestAnchoredCounter,
          notes: rekorFloor.verdict.notes,
          trust_bearing_writes_frozen: true,
          remediation: "sanctuary restore-attest (fortress passphrase required)",
        },
      });
      // SAFETY: stderr is the operator-facing channel for boot diagnostics.
      if (rekorFloor.banner) console.error(rekorFloor.banner);
    }
  } catch (err) {
    // Same fail-safe as Stage 1: a failure to RUN the Stage 2 cross-check must
    // never block boot (it does not by itself freeze writes — only a positive
    // detection does).
    console.error(
      "Sanctuary: anti-rollback Stage 2 (Rekor counter-floor) boot cross-check " +
        "could not complete: " +
        (err instanceof Error ? err.message : String(err))
    );
  }

  // 5rc. Config-security-baseline cross-check (the custody-MAC config-downgrade
  // gate; replaces #791's forgeable adjacent `.security-baseline.json`). The
  // baseline is authenticated with a MAC keyed by the master key, so forging it
  // requires the master key the on-host attacker lacks. This MUST run AFTER the
  // master key is established (loadConfig at step 1 has no key, so the check
  // cannot live there); it is adjacent to the 5rb/5rb2 anti-rollback checks.
  //
  // Unlike anti-rollback (which never refuses boot), this gate FAILS CLOSED and
  // REFUSES boot on a detected downgrade OR any baseline authentication anomaly
  // (tampered MAC, stripped marker, unparseable, schema mismatch). Refusing is
  // correct here: a weakened/forged security posture is exactly what Sanctuary
  // invariant #5 forbids us from silently accepting. A genuine first run (no
  // prior baseline) seeds the current posture (the only accept path).
  const configBaselineOutcome = await crossCheckConfigBaseline({
    storage,
    master: masterKey,
    config,
  });
  await auditLog.appendCritical({
    layer: "l2",
    operation: "config_security_baseline_checked",
    identity_id: fortressIdFromStoragePath(config.storage_path),
    result: "success",
    details: {
      outcome: configBaselineOutcome.kind,
    },
  });

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

  // 5orphan. Custody-factor orphan detection (element 5): WARN before lockout.
  // If the envelope enrolled an OS-keyring custody factor but that keyring item
  // is now GONE (reachable keyring, missing item), the operator is one factor
  // away from needing the recovery key. Boot is NEVER refused on this signal
  // (F3: a warn, not a brick); a locked/unreachable keyring is inconclusive and
  // raises no alarm. Best-effort: a detector error never blocks boot.
  try {
    const orphan = await detectCustodyFactorOrphan(storage, config.storage_path);
    if (orphan.verdict === "orphaned") {
      await auditLog.appendCritical({
        layer: "l2",
        operation: "custody_factor_orphan_detected",
        identity_id: fortressIdFromStoragePath(config.storage_path),
        result: "failure",
        details: {
          custody_service: orphan.custodyService,
          recovery_escrow: orphan.recoveryEscrow,
        },
      });
      // SAFETY: stderr is the operator-facing channel for boot diagnostics.
      console.error(`\nSanctuary: ${orphan.message}\n`);
    }
  } catch (err) {
    console.error(
      "Sanctuary: custody-factor orphan check could not complete: " +
        (err instanceof Error ? err.message : String(err))
    );
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
  const { tools: l1Tools, identityManager, namespaceRegistry } = createCognitiveTools(
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
              // Honesty (audit seam #4): these were literal `true`s asserting
              // runtime-verified encryption and available proofs on config
              // presence. Derive from real config and surface the unverified
              // posture: encryption is *configured* (no runtime integrity check
              // proves bytes on disk are encrypted), and zero-knowledge proofs
              // are only "available" when a ZK proof system is configured
              // (commitment-only has none). The verification status is unknown.
              l1_state_encrypted: config.state.encryption === "aes-256-gcm",
              l1_state_encryption_verified: "unknown",
              l1_status: evidence.layers.l1.status,
              l2_execution_isolated: evidence.layers.l2.status,
              l2_isolation_type: "process-level",
              l3_proofs_available:
                config.disclosure.proof_system !== "commitment-only",
              l3_status: evidence.layers.l3.status,
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
      // Honesty (audit seam #4): the prior copy promised a "live Castle Wall
      // enforcement state" that no detector feeds. Castle Wall status reflects
      // whatever runtime snapshot is wired in (often "unknown" when none is),
      // and the disclosure/reputation layers report configured-vs-verified, not
      // observed enforcement. Describe what the tool actually returns.
      description:
        "Report this instance's health and sovereignty posture: overall state (healthy/degraded/compromised), versions, Castle Wall status (active/unknown/not_configured depending on what runtime detector is wired in), and audit/state/egress posture, plus any active degradations. Disclosure and reputation layers report configured-but-unverified posture, not observed enforcement. Read-only, unsigned local status: for a signed, shareable sovereignty advertisement use shr_generate instead.",
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
      description: "Query your OWN identity's sovereignty audit entries, filtered by since, layer (l1-l4), operation_type, and limit (default 50). Use to inspect operations you performed. Read-only; only your own entries are visible (system/gate entries are never returned), and each entry is reduced to a fixed safe view ({ timestamp, operation, result, has_details }) — no details, identity, or policy attribution.",
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
        // OWN-IDENTITY FILTER (CISO MED-3, property #11): an agent may only read
        // its OWN audit entries. Entries attributed to `system` (every gate /
        // policy decision, anomaly escalation, injection block) carry operator-
        // only context and are written with identity_id === "system", so the
        // own-identity filter alone keeps them off the agent-facing read — the
        // threshold-bearing free-text `reason` on a `gate_*` entry never reaches
        // an agent, both because it is a `system` entry AND because the redacted
        // view drops `details` entirely (defence in depth). Mirrors
        // sanctuary_audit_search's own_signed scope.
        const binding = currentSessionBinding();
        // No bound session identity → fail closed (return nothing) rather than
        // exposing other identities' (or system) entries. Never degrade open.
        if (!binding) {
          return toolResult({ entries: [], count: 0 });
        }
        const limit = Math.max(1, (args.limit as number) ?? 50);
        // Filter to the caller's identity BEFORE the limit (AuditLog.query
        // applies identity_id before its slice), so `limit` bounds the caller's
        // OWN entries — a caller with many other-identity entries ahead of theirs
        // in the window no longer gets undercounted (CISO LOW, 2026-06-16).
        const result = await auditLog.query({
          since: args.since as string | undefined,
          layer: args.layer as "l1" | "l2" | "l3" | "l4" | undefined,
          operation_type: args.operation_type as string | undefined,
          identity_id: binding.identity_id,
          limit,
        });
        const own = result.entries.map((entry) => redactAuditEntryForAgent(entry));
        return toolResult({ entries: own, count: own.length });
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
              // Honest grade: deletion is best-effort random-byte overwrite
              // before unlink; on copy-on-write/SSD media original bytes may
              // survive, so at-rest confidentiality rests on encryption, not on
              // the overwrite. The live delete tools (state_delete,
              // sanctuary_forget, memory_delete) describe it this way and there
              // is no "proven" ASSURANCE_MATRIX row backing a "full"
              // right-to-deletion claim, so "partial" is the honest level.
              "S1.6_deletion_rights": "partial",
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
              // Honest grades: the reputation/SHR/attestation surfaces now
              // report "unknown" when telemetry is unavailable, and there is no
              // "proven" ASSURANCE_MATRIX row for earned-reputation or
              // trust-bootstrapping. "partial" matches the live surfaces rather
              // than over-declaring a fully-realized capability the human-facing
              // tools were just corrected to stop claiming.
              "S4.1_earned_reputation": "partial",
              "S4.2_participant_owned": "full",
              "S4.5_sybil_resistance": "basic",
              "S4.7_trust_bootstrapping": "partial",
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
  const { tools: l3Tools } = createDisclosureTools(storage, masterKey, auditLog);

  // 12. Create Handshake tools (sovereignty handshake protocol)
  // Must be created before L4 so handshakeResults can feed tier resolution
  const { tools: handshakeTools, handshakeResults, handshakeResultWriterOrigins } = createHandshakeTools(
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
  const { tools: l4Tools, reputationStore } = createReputationTools(
    storage,
    masterKey,
    identityManager,
    auditLog,
    handshakeResults,
    config.verascore.url,
    config
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
    handshakeResults,
    identityManager,
    handshakeResultWriterOrigins
  );

  // 14c. Create Bridge tools (Concordia integration). `reputationStore` is
  // the SAME instance createReputationTools (step 13) constructed and
  // returned — NOT a second `new ReputationStore(...)` (LD3 gate
  // fix-round-2, MUST-FIX 2). Before this fix, createBridgeTools built its
  // own ReputationStore internally, so this live server ran TWO independent
  // in-memory admission locks and quota views over the SAME `_reputation`
  // storage backend: a concurrent reputation_record (through step 13's
  // store) and bridge_attest (through this factory's OWN, separate store)
  // could each observe pre-write headroom on their own store's view and
  // both write, overshooting MAX_REPUTATION_RECORDS(_PER_ORIGIN) together —
  // a per-instance admission lock only serializes callers that share the
  // SAME instance. Injecting the one store built at step 13 makes this the
  // only ReputationStore construction reachable in the live server's
  // composition graph.
  const { tools: bridgeTools } = createBridgeTools(
    storage,
    masterKey,
    identityManager,
    auditLog,
    reputationStore,
    handshakeResults
  );

  // 14d2. Create SIEM Export tools (Tier 2 — CEF and OCSF export)
  const { tools: siemTools } = createSIEMTools(auditLog, currentSessionBinding);

  // 14e. Initialize Sovereignty Profile store. Its context_gating subsection is
  // the persisted source of truth for the runtime context gate enforcer.
  const profileStore = new SovereigntyProfileStore(storage, masterKey);
  const loadedProfile = await profileStore.load();

  // 14d (moved below profile load). Create Sovereignty Audit tools (read-only
  // diagnostic). Honesty (audit seam #5): the audit reads the LIVE profile so
  // it credits context-gating and zero-knowledge proofs only when they are
  // actually enabled (both default OFF) rather than from a hardcoded
  // sanctuary_installed flag. Moved after profileStore.load() so the getter is
  // bound to the live store; auditTools is only consumed in the tool registry
  // far below, so the reorder is behavior-preserving.
  const { tools: auditTools } = createAuditTools(config, auditLog, {
    getRuntimeSignals: () => {
      const p = profileStore.get();
      return {
        contextGatingEnabled: p.features.context_gating.enabled,
        zkProofsEnabled: p.features.zk_proofs.enabled,
      };
    },
  });

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
  const hardeningTools = createOperationalHardeningTools(config.storage_path, auditLog);

  // 14h. Create Sovereignty Profile tools
  const { tools: profileTools } = createSovereigntyProfileTools(profileStore, auditLog);

  // 14i. Construct the per-fortress Sentinel/Anomaly finding store HERE,
  // ahead of both the embedded-dashboard wiring below (which used to
  // construct its OWN independent instance inside `buildV11Bindings`) and
  // the sentinel-dispatch boot path further down (step "v1.3 WP-V1.3-1
  // Phi-1"). MUST-FIX 5 (fix-round-2 RECHECK): those were previously TWO
  // separate `SentinelFindingStore` objects reading/writing the SAME
  // storage namespace for the SAME fortress, each with its own in-memory
  // filter index (sentinel-finding-store.ts's `this.index`) — a write
  // through one instance never updated the other's index, so a query
  // against whichever instance did NOT receive the write (e.g. the
  // dashboard's anomaly binding reading findings the boot-path sentinel
  // dispatcher persisted, or vice versa) silently missed them. One shared
  // instance closes this: every production consumer of this fortress's
  // finding store now reads/writes the SAME index. `fortressIdFromStoragePath`
  // is a pure function of `config.storage_path` (used identically at both
  // this store's original construction site and in `buildV11Bindings`'s
  // call below), so calling it here ahead of `fortressIdForAggregator`
  // (declared later) is behavior-preserving — same value either way.
  const sentinelFindingStore = new SentinelFindingStore({
    storage,
    masterKey,
    fortressId: fortressIdFromStoragePath(config.storage_path),
    auditLog,
  });
  // Register Z-HNY-02: fire-and-forget at construction, mirroring the
  // conciergeMemory.pruneExpired() pattern in dashboard/v1_1/wiring.ts, so
  // the fortress-unlock cycle drops expired findings before any honeypot or
  // sentinel activity accumulates on top of them.
  void sentinelFindingStore.pruneExpired().catch(() => {
    // Best-effort: a transient storage hiccup should not block boot. The
    // next unlock re-runs the prune.
  });

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

  let approvalChannel: ApprovalChannel;
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
  // Rho-2.5: whether the consent-gated Tier B redactor was installed on
  // the selector above. Threaded into the v1.1 PII binding so the
  // `/api/query-anonymity/pii` route reports the truthful
  // `effective_tier_b_enabled`. Stays false when the selector failed to
  // construct (the route then honestly reports inactive).
  let tierBPiiRedactorInstalled = false;

  const selectedApprovalChannel = selectApprovalChannelByPolicy({
    config,
    policy,
    ...(options?.approvalCallback
      ? { approvalCallback: options.approvalCallback }
      : {}),
  });
  switch (selectedApprovalChannel.type) {
  case "dashboard": {
    dashboard = selectedApprovalChannel.channel;
    dashboard.setDependencies({
      policy,
      baseline,
      auditLog,
      identityManager,
      handshakeResults,
      shrOpts: { config, identityManager, masterKey },
      sanctuaryConfig: config,
      profileStore,
      // Recognition panel (P5): storage for the local bridge-commitment list +
      // local attestation-store reputation evidence (counts, never a score).
      storage,
    });
    await dashboard.setOperatorAuthorizationSpentStore(
      OperatorAuthorizationSpentStore.durableFromBoot(storage, masterKey),
    );
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
      // Rho-2.5: install the consent-gated Tier B PII redactor on the
      // production selector via THE shared chokepoint. The fortressId MUST
      // match the one threaded into buildV11Bindings below so the route's
      // PATCH and the live scrub read the same encrypted config.
      tierBPiiRedactorInstalled = installConsentGatedRedactor({
        selector: intelligenceSelector,
        storage,
        masterKey,
        fortressId: fortressIdFromStoragePath(config.storage_path),
      });
    } catch (err) {
      // SAFETY: no structured logger module is wired in server/src/ yet; until one lands, raw stderr is the runtime warning channel for this site.
      console.error(
        `  Note: Intelligence panel unavailable (${(err as Error).message}). ` +
          `Run \`sanctuary dashboard\` and pick a substrate.`,
      );
      intelligenceSelector = undefined;
      // tierBPiiRedactorInstalled stays false (its initialized value): the
      // install assignment above only completes when the try did not throw.
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
        // MUST-FIX 5 (fix-round-2): share the ONE SentinelFindingStore
        // instance constructed above (step 14i) rather than letting
        // `buildV11Bindings` construct its own — see that construction
        // site's comment for why a second independent instance silently
        // hides findings from whichever one did not receive a given write.
        sentinelFindingStore,
        // Rho-2.5: the consent-gated Tier B redactor is installed on the
        // selector above, so the /api/query-anonymity/pii route reports
        // the truthful `effective_tier_b_enabled`.
        tierBPiiRedactorInstalled,
      }),
    );
    // Loopback auto-auth (parity with `sanctuary dashboard`,
    // dashboard-standalone.ts): the master key that unlocked this fortress
    // above is strictly stronger than the in-memory dashboard bearer token, so
    // a loopback caller after a successful unlock should not be re-challenged.
    // Without this, the embedded native posture surface (castle-wall-macos,
    // which boots the server via `sanctuary --dashboard`) gets 401'd on its
    // tokenless loopback reads whenever an operator configures a dashboard auth
    // token, leaving the badge stuck and the embed rendering a raw 401 page.
    // Gated identically to the standalone path (loopback host AND at least one
    // identity decrypted), so the threat model is unchanged. State-changing
    // approval-decision routes remain token-gated via `requireToken` regardless.
    const dashboardHostIsLoopback =
      config.dashboard.host === "127.0.0.1" ||
      config.dashboard.host === "::1" ||
      config.dashboard.host === "localhost";
    if (dashboardHostIsLoopback && loadResult.loaded > 0) {
      dashboard.setAutoAuthLocalhost(true);
    }
    await selectedApprovalChannel.start();
    approvalChannel = dashboard;
    break;
  }
  case "webhook":
    await selectedApprovalChannel.start();
    approvalChannel = selectedApprovalChannel.channel;
    break;
  case "callback":
    approvalChannel = selectedApprovalChannel.channel;
    break;
  case "stderr":
    approvalChannel = selectedApprovalChannel.channel;
    break;
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
    // Feature-health observability raise path: on the operator-inbox cadence,
    // recompute the feature-health panel from the integrity-judged audit read and
    // raise the 3 ratified fault classes (deduped via the bridge). Additive +
    // display-only; feeds NOTHING back into enforcement. The dashboard owns the
    // raiser (it has the producer-key load + panel builder); a missing dashboard
    // or locked log makes this a no-op.
    //
    // ALERT LATENCY (operator-facing honesty): the raise rides this existing
    // ~60s UnifiedInboxScheduler tick, so a feature fault can take up to one
    // scheduler cycle (best-effort ~60s, not instant) to surface as a
    // notification. This path adds NO faster heartbeat/poll; it deliberately
    // reuses the inbox cadence to inherit the integrity-judged audit read.
    onTick: () => dashboard?.evaluateFeatureFaults(),
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
  // Construct the per-fortress dispatcher, register the Phi-1 catalog, and
  // re-subscribe whatever the operator opted into on a prior boot. The
  // dispatcher's auto-tick is enabled so subscribed sentinels run
  // periodically; tick interval is fixed at the coordinator-CTO default
  // until per-fortress override lands. No new outbound surface; sentinels
  // read server-local audit data only. `sentinelFindingStore` itself is
  // constructed earlier (step 14i, MUST-FIX 5 fix-round-2) and shared with
  // the embedded dashboard's anomaly binding — do not construct a second
  // instance here.
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

  // 16b1. SDW sovereign-memory substrate (company-brain phase 1, wired
  // 2026-06-18). Exposes the shipped passage store (PR #484) over MCP so a
  // fleet agent on THIS machine can reach its own sovereign passages. This is
  // LOCAL-ONLY: the LMDB/filesystem-backed custody store never leaves the
  // machine. The Anthropic Memory bridge (a real API round-trip, MUST-NEVER
  // #1) is a SEPARATE, Erik-present phase and is deliberately NOT wired here.
  //
  // owner_ref scopes these passages to one engine instance under this fortress
  // (SDW identifier grammar, no '.'); a single-machine substrate uses one
  // stable scope. memory_insert/memory_delete are Tier-1 in DEFAULT_POLICY
  // (the delete additionally force-pinned, un-relaxable); memory_insert's body
  // is redacted from the approval channel below (Hard Constraint #1).
  const sdwMemoryAdapter = new SdwMemoryBackendAdapter({
    storage,
    masterKey,
    fortressId: fortressIdFromStoragePath(config.storage_path),
    ownerRef: "fleet-self",
  });
  // Fail-closed multi-agent isolation guard: the adapter above is bound to ONE
  // shared `fleet-self` owner scope reused for every caller, so SDW memory has
  // no per-agent custody isolation yet. Resolving the SAME caller identity the
  // router uses (`SANCTUARY_AGENT_ID`) lets the guard pin the single identity
  // the shared scope serves and REFUSE any second, distinct wrapped-agent
  // identity until real per-agent isolation lands. For single-coordinator use
  // this resolves a stable value (or stable undefined) and is a strict NO-OP.
  //
  // ONE guard instance is shared by every tool family that reaches this scope
  // (read/write tools AND the memory-file transcode tools). A per-family guard
  // pins each family's own first caller, so the agent refused by memory_get
  // would be the FIRST caller of memory_emit and could dump the whole shared
  // corpus as plaintext files.
  const sdwMemoryIdentity = (): string | undefined => process.env.SANCTUARY_AGENT_ID;
  const sdwMemoryIsolationGuard = createMultiAgentIsolationGuard(sdwMemoryIdentity);
  const sdwMemoryTools = createSdwMemoryTools({
    adapter: sdwMemoryAdapter,
    auditLog,
    isolationGuard: sdwMemoryIsolationGuard,
  }).map((tool) =>
    tool.name === "memory_insert"
      ? {
          ...tool,
          // Hard Constraint #1 / C4: redact the passage body from the approval
          // channel. memoryInsertApprovalArgs projects to operation metadata
          // only (the body and self-asserted taint are dropped). Shared with
          // the redaction regression test so the wiring and the test never
          // drift.
          approvalTargetArgs: memoryInsertApprovalArgs,
        }
      : tool,
  );
  const sdwMemoryProvenanceTool = createSdwMemoryProvenanceTool({
    adapter: sdwMemoryAdapter,
    auditLog,
  });
  const sdwMemoryFileTools = createSdwMemoryFileTools({
    adapter: sdwMemoryAdapter,
    auditLog,
    // Same resolver AND the same guard instance as the read/write tools above:
    // memory_emit materializes the entire shared corpus as plaintext, so it has
    // to sit behind the identical pin, and the approval projection uses the
    // resolver to tell the operator whose memory a dump moves.
    ownerIdentity: sdwMemoryIdentity,
    isolationGuard: sdwMemoryIsolationGuard,
  });

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

  const erc8004RegistryEgressGate: Erc8004RegistryEgressGate = (req) => {
    const registryConfig = config.erc8004.registry_confirmation;
    const configuredDestination = erc8004RpcDestination(registryConfig.rpc_url);
    if (!registryConfig.enabled || !configuredDestination) {
      return {
        decision: "deny",
        reason_code: "egress_rpc_not_configured",
        explanation: "ERC-8004 registry confirmation RPC is not enabled/configured",
      };
    }
    if (req.destination !== configuredDestination) {
      return {
        decision: "deny",
        reason_code: "egress_destination_denied",
        explanation: "ERC-8004 registry confirmation RPC destination is not allowlisted",
      };
    }

    const identity = identityManager.getDefault();
    if (!identity) {
      return {
        decision: "deny",
        reason_code: "egress_gate_identity_unavailable",
        explanation: "No primary identity is available to sign the egress gate receipt",
      };
    }

    const identityEncryptionKey = derivePurposeKey(masterKey, "identity-encryption");
    const nodeSigningKey = decrypt(
      identity.encrypted_private_key,
      identityEncryptionKey,
    );
    try {
      const gatePolicy = buildNullPolicy({
        agent_id: aggregatorIdentityId,
        fortress_id: fortressIdForAggregator,
      });
      gatePolicy.policy_version = 1;
      gatePolicy.source_english =
        "ERC-8004 registry confirmation may POST only to the operator-configured RPC destination.";
      gatePolicy.egress = {
        allowlist: [{ destination: configuredDestination, methods: ["POST"] }],
      };

      const gateResult = evaluateEgressGate(
        {
          policy: gatePolicy,
          nodeSigningKey,
          nodeId: identity.identity_id,
          fortressId: fortressIdForAggregator,
        },
        {
          agent_id: aggregatorIdentityId,
          destination: req.destination,
          method: req.method,
        },
      );

      return {
        decision: gateResult.decision === "allow" ? "allow" : "deny",
        reason_code: gateResult.reason_code,
        explanation: gateResult.explanation,
      };
    } finally {
      nodeSigningKey.fill(0);
      identityEncryptionKey.fill(0);
    }
  };

  // 16b-read. ERC-8004 Identity verifier (read side). Default is fully local:
  // verifies a presented record's signature/shape with NO outbound surface. If
  // the operator enables registry confirmation and sets an RPC endpoint, it
  // performs a gated Verascore-derived ownerOf read and reports it separately.
  const { tools: erc8004ResolveTools } = createErc8004ResolveTools({
    auditLog,
    identityId: aggregatorIdentityId,
    fortressId: fortressIdForAggregator,
    registryConfirmation: config.erc8004.registry_confirmation,
    egressGate: erc8004RegistryEgressGate,
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
    ...sdwMemoryTools,
    sdwMemoryProvenanceTool,
    ...sdwMemoryFileTools,
    ...complianceTools,
    ...erc8004Tools,
    ...erc8004ResolveTools,
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
    instructions: buildServerInstructions(),
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

  // 22. Escrow the full recovery key off-host if one was generated on this
  // first run (the durable fix). The recovery key is NEVER written inside the
  // fortress dir and NEVER printed to stdout/stderr/log (the MCP host harness
  // captures those streams): it is disclosed ONLY on the controlling terminal
  // (/dev/tty) for the human to store in their password manager, and/or
  // escrowed to an explicit off-host target. The MCP stdio host owns stdin, so
  // the tty confirmation is skipped (noConfirm); the hard provisioning gate
  // then requires an off-host escrow target (SANCTUARY_RECOVERY_OUT, or a
  // passphrase for OS-keyring escrow) and FAILS CLOSED otherwise rather than
  // leaving the freshly minted key uncaptured. Operators who want the
  // interactive confirmation should run `sanctuary init` first.
  if (recoveryKey && bootOwnsStorage) {
    const escrowOpts: Parameters<typeof escrowBootRecoveryKey>[0] = {
      recoveryKey,
      storagePath: config.storage_path,
      fortressId: fortressIdFromStoragePath(config.storage_path),
      // The host harness owns stdin, so there is no interactive confirmation
      // (noConfirm). The hard provisioning gate then requires a DURABLE
      // off-host target and fails closed otherwise. When a passphrase is in
      // play we escrow the recovery key to the OS keyring (best-effort,
      // read-back-verified) exactly as `sanctuary init` does, so a
      // passphrase-provisioned fortress gets a recoverable second factor; with
      // no passphrase the operator must supply SANCTUARY_RECOVERY_OUT (or run
      // interactively) or boot fails closed rather than minting an uncaptured
      // sole-factor key.
      noConfirm: true,
      attemptKeychainEscrow: !!passphrase,
    };
    await escrowBootRecoveryKey(escrowOpts);
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
  "memory_delete",
  "memory_insert",
  // `proof_commitment` mints a new commitment record and persists it to the
  // encrypted commitment store, so it belongs with the other commitment-minting
  // verbs (`zk_commit`, `zk_prove`, `zk_range_prove`, all below) rather than
  // with the verifiers. Classification is what the router's audit-integrity
  // gate keys on, so this entry is the line that decides whether a
  // state-creating call still runs while the audit chain has findings; the
  // answer for anything that creates new persisted state is no. This one
  // correction was established by reading the handler; the systematic
  // reconciliation of the whole read set against what each handler can reach is
  // a separate change and has not landed. Two distinct claims, kept apart on
  // purpose: this entry's MEMBERSHIP is frozen by
  // `test/structure/mcp-commitment-verb-classification.test.ts`, so moving it
  // back to the read table reds; whether the read table is CORRECT against what
  // its handlers actually reach is unchecked (ABC-READCLASS-01, open).
  "proof_commitment",
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

/**
 * Tools the router may run while the audit chain reports integrity findings, so
 * an operator can always introspect a fortress that is in trouble. Membership
 * here is therefore a claim that the tool's handler introspects and does not
 * create or destroy persisted state.
 *
 * Must match the bypass site in `router.ts` (`tool.tool_class === "read"`),
 * which is the only place membership here has an effect. Adding a name is a
 * security decision made at that site, not a taxonomy entry made at this one.
 *
 * WHAT IS AND IS NOT CHECKED, stated plainly so a reader assumes neither more
 * nor less than ships. CHECKED: the membership of the six commitment and
 * verifier verbs is frozen by
 * `test/structure/mcp-commitment-verb-classification.test.ts` — move one of
 * them across, or add a minting verb here, and it reds. NOT CHECKED: every
 * other name in this table. Adding one without reading its handler widens what
 * may run against a fortress whose audit chain has findings, and no test reds.
 * Reconciling the whole table against what each handler's call graph
 * can actually reach is tracked as ABC-READCLASS-01, which stays OPEN: it is
 * deferred to its own change and is not closed by the one correction that
 * shipped with this comment.
 *
 * THIS TABLE IS ONLY HALF THE READ SET. `classifyMcpTools` below also honors an
 * inline `tool_class: "read"` on a tool literal, and those tools get exactly the
 * same bypass without ever appearing here. Any future reconciliation has to
 * cover both halves; a review that reads only this table has read half the set.
 */
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
  "memory_count",
  "memory_get",
  "memory_list",
  "memory_search",
  "monitor_audit_log",
  "monitor_health",
  "principal_baseline_view",
  "principal_policy_view",
  "reputation_query",
  "reputation_query_weighted",
  "sanctuary_policy_status",
  "sdw_memory_provenance",
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
export { StateStore } from "./cognitive/state-store.js";
export { AuditLog } from "./operational/audit-log.js";
export { CommitmentStore } from "./disclosure/commitments.js";
export {
  createPedersenCommitment,
  verifyPedersenCommitment,
  createProofOfKnowledge,
  verifyProofOfKnowledge,
  createRangeProof,
  verifyRangeProof,
} from "./disclosure/zk-proofs.js";
export type {
  PedersenCommitment,
  ZKProofOfKnowledge,
  ZKRangeProof,
} from "./disclosure/zk-proofs.js";
export { PolicyStore } from "./disclosure/policies.js";
export { ReputationStore } from "./reputation/reputation-store.js";
export {
  resolveTier,
  computeWeightedScore,
  tierDistribution,
  TIER_WEIGHTS,
} from "./reputation/tiers.js";
export type { SovereigntyTier, TierMetadata, TieredAttestation } from "./reputation/tiers.js";
export { FederationRegistry } from "./federation/registry.js";
export type {
  FederationPeer,
  FederationCapabilities,
  PeerTrustEvaluation,
} from "./federation/types.js";
export { ContextGatePolicyStore } from "./operational/context-gate.js";
export {
  TEMPLATES as CONTEXT_GATE_TEMPLATES,
  getTemplate,
  listTemplateIds,
} from "./operational/context-gate-templates.js";
export type { ContextGateTemplate } from "./operational/context-gate-templates.js";
export {
  classifyField,
  recommendPolicy,
} from "./operational/context-gate-recommend.js";
export type {
  FieldClassification,
  PolicyRecommendation,
} from "./operational/context-gate-recommend.js";
export {
  InMemoryModelProvenanceStore,
  MODEL_PRESETS,
} from "./operational/model-provenance.js";
export type {
  ModelProvenance,
  ModelProvenanceStore,
} from "./operational/model-provenance.js";
export {
  evaluateField,
  filterContext,
} from "./operational/context-gate.js";
export type {
  ContextGatePolicy,
  ContextGateRule,
  ContextFilterResult,
  FieldFilterResult,
  ProviderCategory,
  ContextAction,
} from "./operational/context-gate.js";
export { InjectionDetector } from "./security/injection-detector.js";
export type {
  InjectionDetectorConfig,
  DetectionResult,
  InjectionSignal,
} from "./security/injection-detector.js";
export { ContextGateEnforcer } from "./operational/context-gate-enforcer.js";
export type { EnforcerConfig } from "./operational/context-gate-enforcer.js";
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
  CognitiveStatus,
  OperationalStatus,
  DisclosureStatus,
  ReputationStatus,
  // Back-compat aliases (L1-L4 rename PR-3): kept exported so downstream
  // imports keep working.
  L1Status,
  L2Status,
  L3Status,
  L4Status,
  ApprovalHandlers,
  StreamEvent,
} from "./dashboard/index.js";
