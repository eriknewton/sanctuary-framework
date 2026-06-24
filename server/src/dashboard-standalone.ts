/**
 * Sanctuary MCP Server - Standalone Dashboard
 *
 * Starts the Principal Dashboard as a persistent HTTP server without
 * the MCP server or stdio transport. Designed for deployments where:
 *
 * - The MCP server is launched on-demand via stdio (e.g., OpenClaw)
 * - The dashboard needs to persist between MCP sessions
 * - A launchd/systemd service manages the dashboard lifecycle
 *
 * The standalone dashboard reads from the same ~/.sanctuary/ storage
 * as the MCP server, providing:
 * - Audit log history (encrypted, decrypted with master key)
 * - Policy status and configuration
 * - Baseline behavioral profile
 * - Authentication (same token/session model as co-located dashboard)
 *
 * Limitation: Live SSE events for tool calls and injection alerts are
 * NOT available in standalone mode - those require the dashboard and
 * MCP server to share a process. The standalone dashboard serves
 * historical data via the audit log API.
 */

import { mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { loadConfig, SANCTUARY_VERSION } from "./config.js";
import { FilesystemStorage } from "./storage/filesystem.js";
import { AuditLog } from "./operational/audit-log.js";
import {
  consumeResetHistoryMarker,
  ResetHistoryMalformedError,
} from "./audit/reset-history.js";
import { loadPrincipalPolicy, MalformedPrincipalPolicyError } from "./principal-policy/loader.js";
import type { PrincipalPolicy } from "./principal-policy/types.js";
import { BaselineTracker } from "./principal-policy/baseline.js";
import { DashboardApprovalChannel } from "./principal-policy/dashboard.js";
import { derivePurposeKey } from "./core/key-derivation.js";
import {
  establishMaster,
  readCustodyEnvelope,
  readEnrolledFactors,
  buildActionableUnlockMessage,
  CustodyUnlockError,
  CustodyMigrationRefusedError,
  type EstablishMasterResult,
} from "./core/master-custody.js";
import { IdentityManager } from "./cognitive/tools.js";
import { StateStore } from "./cognitive/state-store.js";
import { createIdentity } from "./core/identity.js";
import { TaskService } from "./operational/task-coordination/index.js";
import type { HandshakeResult } from "./handshake/types.js";
import { SovereigntyProfileStore } from "./sovereignty-profile.js";
import { writeTenantRuntime, clearTenantRuntime } from "./cli/agents/runtime.js";
import {
  readStoredPassphrase,
  keychainServiceFor,
  PassphraseUnreadableError,
} from "./wrap/passphrase.js";
import {
  escrowBootRecoveryKey,
  BootRecoveryKeyEscrowRequiredError,
  BootRecoveryKeyCaptureDeclinedError,
} from "./wrap/boot-recovery-escrow.js";
import { probeKeychainCustodyKey } from "./wrap/keychain-custody.js";
import { detectCustodyFactorOrphan } from "./wrap/orphan-detection.js";
import {
  discoverTenants,
  findTenant,
  type DiscoveryOptions,
  type TenantDescriptor,
} from "./cli/agents/discovery.js";
import {
  buildV11Bindings,
  fortressIdFromStoragePath,
} from "./dashboard/v1_1/wiring.js";
import { readPersistedLocalAgents } from "./hub/agent-registry-persistence.js";
import { SubstrateSelector } from "./intelligence/selector.js";
import { DistressInbox } from "./distress/inbox.js";
import { DistressListener } from "./distress/listener.js";
import {
  loadOrCreateLocalListenerSecret,
  DistressLocalSecretError,
} from "./distress/local-secret.js";
import { provisionOrLoadFederationTrustRoot } from "./mesh/federation-trust-root-store.js";
import { loadFederationJoinerTrustRoot } from "./mesh/federation-joiner-trust-root-store.js";
import {
  BootstrapNonceStore,
  createStandaloneJoinApprover,
} from "./mesh/lifecycle/index.js";

export interface StandaloneDashboardOptions {
  passphrase?: string;
  port?: number;
  host?: string;
  configPath?: string;
  /**
   * Resolve a tenant by the human-readable name printed by `sanctuary agents`
   * and boot against its storage path. Wins over `SANCTUARY_STORAGE_PATH`
   * because the operator typed it explicitly. Throws when no tenant matches.
   */
  tenant?: string;
  /**
   * Skip the interactive off-host-capture confirmation when the standalone
   * dashboard generates a fresh recovery key on first run. Required for non-TTY
   * (CI/launchd/systemd) callers. When set, an off-host escrow target MUST be
   * provided (recoveryOut / SANCTUARY_RECOVERY_OUT, or a passphrase for OS-keyring
   * escrow); otherwise the boot fails closed rather than leaving the key
   * uncaptured (the durable-fix posture: never co-locate the recovery key with
   * the fortress).
   */
  noConfirm?: boolean;
  /**
   * On a first-run mint, write the plaintext recovery key to this exact path
   * OUTSIDE the fortress directory (durable off-host escrow). Honors
   * SANCTUARY_RECOVERY_OUT when absent. Never written inside the fortress dir.
   */
  recoveryOut?: string;
  /**
   * Optional tenant-discovery scope override for tests. Production callers
   * leave this undefined so discovery still scans the real ~/.sanctuary root.
   */
  discoveryOptions?: DiscoveryOptions;
}

/**
 * List the tenants visible on this host that the operator could boot against
 * other than the storage path the current process is already configured for.
 *
 * Returns an empty list when no tenants exist or when the current path is the
 * only thing on disk. Filters out the configured storage path itself so the
 * "did you mean?" hint never suggests the tenant the user is already pointed
 * at.
 *
 * `discoveryOptions` forwards to `discoverTenants()`. Production callers leave
 * it undefined so discovery scans the real `~/.sanctuary/`. Tests pass
 * `{ root, home }` overrides to isolate from the developer's home directory;
 * without that isolation, a developer machine that has run `sanctuary wrap`
 * for real would surface its own `~/.sanctuary/default/` tenant in test runs
 * and break assertions that expect the discovery scope to be empty.
 */
export async function discoverableSubTenants(
  currentStoragePath: string,
  discoveryOptions?: DiscoveryOptions
): Promise<TenantDescriptor[]> {
  let all: TenantDescriptor[];
  try {
    all = await discoverTenants(discoveryOptions);
  } catch {
    return [];
  }
  return all.filter((t) => t.storage_path !== currentStoragePath && t.initialized);
}

/**
 * Render the multi-tenant "did you mean?" message that v0.10.4 surfaces
 * instead of the misleading legacy "set SANCTUARY_PASSPHRASE" hint.
 *
 * Exported for unit tests; the wording is part of the contract - operators
 * have to be able to copy a remediation command out of it.
 */
export function renderTenantDiscoveryHint(tenants: TenantDescriptor[]): string {
  if (tenants.length === 0) {
    return (
      `No wrapped tenants discovered on this host.\n` +
      `Run \`sanctuary wrap\` to create one, or set SANCTUARY_STORAGE_PATH\n` +
      `if your tenant lives outside ~/.sanctuary/.`
    );
  }
  const lines = tenants.map((t) => {
    const runtime = t.runtime ? ` (running on :${t.runtime.dashboard_port})` : "";
    return `  • ${t.name}${runtime}\n      storage: ${t.storage_path}\n      keychain: ${t.keychain_service}`;
  });
  if (tenants.length === 1) {
    return (
      `Detected 1 wrapped tenant on this host:\n` +
      lines.join("\n") +
      `\n\nBoot the dashboard against it with:\n` +
      `  sanctuary dashboard --tenant ${tenants[0]!.name}\n`
    );
  }
  return (
    `Detected ${tenants.length} wrapped tenants on this host:\n` +
    lines.join("\n") +
    `\n\nPick one explicitly:\n` +
    `  sanctuary dashboard --tenant <name>\n\n` +
    `Or browse all of them in the multi-tenant overview (no decryption):\n` +
    `  sanctuary dashboard --multi\n`
  );
}

/**
 * Start the dashboard as a standalone HTTP server.
 *
 * Initializes storage, derives master key, loads policy and baseline,
 * then starts the dashboard HTTP server. Returns the dashboard instance
 * for testing/cleanup purposes.
 */
export async function startStandaloneDashboard(
  options: StandaloneDashboardOptions = {}
): Promise<DashboardApprovalChannel> {
  // Force dashboard enabled for this mode
  process.env.SANCTUARY_DASHBOARD_ENABLED = "true";

  // 0. Resolve --tenant before loadConfig so the rest of the boot path picks
  //    up the per-tenant storage path. Operator-typed --tenant beats env var.
  if (options.tenant !== undefined) {
    const match = await findTenant(options.tenant, options.discoveryOptions);
    if (!match) {
      const available = await discoverTenants(options.discoveryOptions);
      const names = available.map((t) => t.name).join(", ") || "(none - run `sanctuary wrap`)";
      throw new Error(
        `Sanctuary Dashboard: --tenant "${options.tenant}" did not match any wrapped tenant.\n` +
          `Available tenants: ${names}\n` +
          `List details with \`sanctuary agents\`.`
      );
    }
    process.env.SANCTUARY_STORAGE_PATH = match.storage_path;
  }

  // 1. Load configuration
  const config = await loadConfig(options.configPath);

  // 2. Ensure storage directory exists
  await mkdir(config.storage_path, { recursive: true, mode: 0o700 });

  // 3. Initialize storage backend
  const storage = new FilesystemStorage(`${config.storage_path}/state`);

  // 4. Derive or load master key (same logic as index.ts)
  //
  // v0.10.2: when no explicit passphrase is given via options or env var,
  // fall back to the per-tenant Keychain / fallback-file lookup keyed off
  // `config.storage_path` (same path `sanctuary wrap` and the broker use).
  // This lets `sanctuary dashboard` boot against a wrapped tenant without
  // forcing the user to re-type - or re-paste - the passphrase the wrap
  // already persisted. Multi-tenant hosts with N per-tenant Keychain items
  // (service `sanctuary-passphrase-<12hex>`) no longer require a single
  // `SANCTUARY_PASSPHRASE` that can only unlock one tenant.
  let passphrase = options.passphrase ?? process.env.SANCTUARY_PASSPHRASE;
  let passphraseSource: "option" | "env" | "keychain" | "fallback-file" | null = null;
  if (passphrase) {
    passphraseSource = options.passphrase !== undefined ? "option" : "env";
  } else {
    try {
      const stored = await readStoredPassphrase({
        storagePath: config.storage_path,
      });
      if (stored) {
        passphrase = stored.value;
        passphraseSource = stored.source === "keychain" ? "keychain" : "fallback-file";
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `Passphrase: loaded from ${stored.location} (service ${keychainServiceFor(config.storage_path, homedir())})`
        );
      }
    } catch (err) {
      if (err instanceof PassphraseUnreadableError) {
        // Never auto-regenerate - rethrow so the operator sees the same
        // remediation steps the wrap CLI prints.
        throw err;
      }
      // Non-fatal: fall through to the recovery-key path below.
    }
  }

  // Unified custody path (core/master-custody.ts): envelope-first, legacy
  // markers migrated in place, first runs create the envelope. The dashboard
  // can no longer derive a different master than the MCP server or the
  // castle-wall CLI for the same fortress.
  //
  // v0.10.4 hints preserved: before failing against a tenant we cannot
  // unlock, surface discoverable sub-tenants - the common Mini1 failure mode
  // is `sanctuary dashboard` run against a default root while sub-tenants
  // hold their own keychain entries.
  const envRecoveryKey = process.env.SANCTUARY_RECOVERY_KEY;
  const isFirstRun =
    (await readCustodyEnvelope(storage)) === null &&
    (await storage.read("_meta", "key-params")) === null &&
    (await storage.read("_meta", "recovery-key-hash")) === null;

  if (isFirstRun && !passphrase && !envRecoveryKey) {
    // v0.10.4: refuse to silently fresh-install over a host that already
    // has wrapped tenants. Pre-fix the dashboard would generate a brand-new
    // recovery key in the default root, which made the operator think they
    // had just lost access to N other tenants.
    const otherTenants = await discoverableSubTenants(
      config.storage_path,
      options.discoveryOptions,
    );
    if (otherTenants.length > 0) {
      throw new Error(
        `Sanctuary Dashboard: ${config.storage_path} has no Sanctuary state, but other wrapped tenants exist on this host.\n` +
        `Refusing to generate a new recovery key over the default root - that would obscure the existing tenants.\n\n` +
        renderTenantDiscoveryHint(otherTenants)
      );
    }
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      "Warning: No existing Sanctuary data found. The standalone dashboard\n" +
      "is typically started after the MCP server has been run at least once.\n" +
      "Generating a new master key for this installation.\n"
    );
  }

  let custody: EstablishMasterResult;
  try {
    custody = await establishMaster({
      storage,
      ...(passphrase ? { passphrase } : {}),
      ...(envRecoveryKey ? { recoveryKey: envRecoveryKey } : {}),
      // The standalone dashboard is a service boot, not a custody-setup
      // ceremony (no re-entry verification flow) - first runs here are the
      // audited degraded install mode, same as the MCP stdio boot. A fresh
      // recovery key (a wrap of the one true master) is minted and
      // disclosed below regardless of credential mode.
      firstRun: {
        installMode: options.noConfirm ? "headless" : "stdio-server",
        mintRecoveryKey: true,
      },
      storagePathHint: config.storage_path,
    });
  } catch (err) {
    // A SUPPLIED credential that fails to verify stays fail-closed (no boot
    // with a wrong master - that silently splits state). Carry the v0.10.4
    // diagnostics in the error: the per-tenant Keychain service name and the
    // canonical schema doc, never a bare SANCTUARY_PASSPHRASE=<your-passphrase>
    // hint (misleading on multi-tenant hosts).
    if (
      (err instanceof CustodyUnlockError ||
        err instanceof CustodyMigrationRefusedError) &&
      (passphrase || envRecoveryKey)
    ) {
      throw new Error(
        `Sanctuary Dashboard: Encrypted identities found but NONE loaded - the supplied\n` +
        `credential does not unlock the fortress at ${config.storage_path}.\n` +
        `Refusing to start with a wrong master key (that would split state, not recover it).\n\n` +
        `This tenant's Keychain service: ${keychainServiceFor(config.storage_path, homedir())}\n` +
        `Retrieve the stored passphrase with:\n` +
        `  security find-generic-password -s ${keychainServiceFor(config.storage_path, homedir())} -w\n\n` +
        `See server/docs/keychain-schema.md for the keychain layout and recovery options.`,
        { cause: err }
      );
    }
    // Re-shape credential-missing failures with an ACTIONABLE diagnostic
    // (element 2): which factors are enrolled, whether the OS keyring is locked
    // vs the item missing (element 3), the GUI-unlock step, and the literal
    // SANCTUARY_RECOVERY_KEY recovery command - plus the dashboard's tenant
    // discovery hints (v0.10.4 behavior). Never prints an on-disk key location.
    if (err instanceof CustodyUnlockError && !passphrase && !envRecoveryKey) {
      const factors = await readEnrolledFactors(storage);
      let keychainReachability: "found" | "not-found" | "unreachable" | undefined;
      if (factors.hasKeychainFactor) {
        try {
          const probe = await probeKeychainCustodyKey(config.storage_path);
          keychainReachability = probe.status;
        } catch {
          keychainReachability = undefined;
        }
      }
      const actionable = buildActionableUnlockMessage({
        ...factors,
        ...(keychainReachability !== undefined ? { keychainReachability } : {}),
        storagePathHint: config.storage_path,
        keychainServiceHint: keychainServiceFor(config.storage_path, homedir()),
      });
      const otherTenants = await discoverableSubTenants(
        config.storage_path,
        options.discoveryOptions,
      );
      throw new Error(
        `Sanctuary Dashboard:\n${actionable}\n\n` +
        (otherTenants.length > 0 ? renderTenantDiscoveryHint(otherTenants) + "\n" : "") +
        `See server/docs/keychain-schema.md for the keychain layout and recovery options.`,
        { cause: err }
      );
    }
    throw err;
  }
  const masterKey = custody.masterKey;

  // Durable off-host escrow for a freshly minted recovery key (the core fix).
  // The recovery key is NEVER written inside the fortress dir and NEVER printed
  // to stdout/stderr/log: it is disclosed ONLY on the controlling terminal
  // (/dev/tty) for the human to store in their password manager, and/or
  // escrowed to an explicit off-host target (--recovery-out / OS keyring). A
  // hard provisioning gate fails closed if non-interactive AND no escrow target
  // was provided, rather than silently leaving the key uncaptured.
  if (custody.mintedRecoveryKey) {
    try {
      const escrowOpts: Parameters<typeof escrowBootRecoveryKey>[0] = {
        recoveryKey: custody.mintedRecoveryKey,
        storagePath: config.storage_path,
        fortressId: fortressIdFromStoragePath(config.storage_path),
        // Durability comes from the controlling-terminal disclosure (the human
        // stores it in their password manager, confirmed interactively) and/or
        // an explicit off-host target (--recovery-out / SANCTUARY_RECOVERY_OUT).
        // When a passphrase is in play we ALSO escrow the recovery key to the
        // OS keyring (best-effort, read-back-verified) exactly as
        // `sanctuary init` does, giving a passphrase-provisioned fortress a
        // recoverable second factor. Under --no-confirm the gate then requires
        // one of those durable targets and fails closed otherwise.
        attemptKeychainEscrow: !!passphrase,
      };
      if (options.recoveryOut !== undefined) {
        escrowOpts.recoveryOut = options.recoveryOut;
      }
      if (options.noConfirm) escrowOpts.noConfirm = true;
      await escrowBootRecoveryKey(escrowOpts);
    } catch (err) {
      if (
        err instanceof BootRecoveryKeyEscrowRequiredError ||
        err instanceof BootRecoveryKeyCaptureDeclinedError
      ) {
        // SAFETY: stderr is the operator-facing CLI channel for this subcommand.
        // The error message NEVER contains the recovery key itself.
        console.error(`\nSanctuary Dashboard: ${err.message}\n`);
        process.exit(2);
      }
      throw err;
    }
  }

  // 5. Initialize audit log (for reading historical entries)
  const auditLog = new AuditLog(storage, masterKey);

  // 5pre. Custody audit trail (mirrors the MCP server boot): record
  // envelope creation / migration / deferral - wrap types and install mode
  // only, never key material.
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
            source: "dashboard-standalone",
          }
        : {
            origin: custody.origin,
            source: "dashboard-standalone",
            reason:
              "existing data could not be evidence-checked against this master; envelope not written",
          },
    });
  }

  // 5orphan. Custody-factor orphan detection (element 5): WARN before lockout.
  // Mirrors the MCP server boot path. Boot is NEVER refused on this signal
  // (F3); a locked/unreachable keyring is inconclusive and raises no alarm.
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
          source: "dashboard-standalone",
        },
      });
      // SAFETY: stderr is the operator-facing channel for boot diagnostics.
      console.error(`\nSanctuary Dashboard: ${orphan.message}\n`);
    }
  } catch (err) {
    console.error(
      "Sanctuary Dashboard: custody-factor orphan check could not complete: " +
        (err instanceof Error ? err.message : String(err))
    );
  }

  // 5a. Reset-history continuity (v1.0.2 item a). Same one-shot marker
  // consumption as the MCP server boot path (server/src/index.ts) so the
  // first fortress-unlock after `reset-passphrase --nuke` records continuity
  // regardless of whether that unlock is the MCP server or the standalone
  // dashboard.
  try {
    await consumeResetHistoryMarker({
      storagePath: config.storage_path,
      auditLog,
    });
  } catch (err) {
    if (err instanceof ResetHistoryMalformedError) {
      throw new Error(
        `Sanctuary Dashboard: ${err.message}\n` +
          `Refusing to start the dashboard while the reset-history marker is unreadable.`,
        { cause: err }
      );
    }
    throw err;
  }

  // 6. Load principal policy and baseline
  let policy: PrincipalPolicy;
  try {
    policy = await loadPrincipalPolicy(config.storage_path);
  } catch (err) {
    if (err instanceof MalformedPrincipalPolicyError) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\nSanctuary cannot start.\n${err.message}\n`);
      process.exit(1);
    }
    throw err;
  }
  const baseline = new BaselineTracker(storage, masterKey);
  await baseline.load();

  // 7. Resolve dashboard config
  const dashboardPort = options.port ?? config.dashboard.port;
  const dashboardHost = options.host ?? config.dashboard.host;

  let authToken = config.dashboard.auth_token;
  if (authToken === "auto") {
    const { randomBytes } = await import("node:crypto");
    authToken = randomBytes(32).toString("hex");
  }

  // 8. Create and start the dashboard
  const dashboard = new DashboardApprovalChannel({
    port: dashboardPort,
    host: dashboardHost,
    timeout_seconds: policy.approval_channel.timeout_seconds,
    auth_token: authToken,
    tls: config.dashboard.tls,
    auto_open: config.dashboard.auto_open ?? true, // Default to auto-open in standalone mode
  });

  // 9. Initialize IdentityManager (reads existing identities from encrypted storage)
  const identityManager = new IdentityManager(storage, masterKey);
  const loadResult = await identityManager.load();

  // 10. Construct SHR generator options (enables /api/sovereignty and /api/shr)
  const shrOpts = { config, identityManager, masterKey };

  // 11. Empty handshake results - handshakes are in-memory per MCP session
  // and cannot be recovered in standalone mode.
  const handshakeResults = new Map<string, HandshakeResult>();

  // 11b. Initialize Sovereignty Profile store
  const profileStore = new SovereigntyProfileStore(storage, masterKey);
  await profileStore.load();

  dashboard.setDependencies({
    policy,
    baseline,
    auditLog,
    identityManager,
    handshakeResults,
    shrOpts,
    sanctuaryConfig: config,
    profileStore,
    // Recognition panel (P5): storage for the local bridge-commitment list +
    // local attestation-store reputation evidence (counts, never a score).
    // Mirrors the embedded path (index.ts) so the standalone dashboard does
    // not silently degrade the committed-receipt count / reputation row to
    // the audit-event lower bound when composition is enabled.
    storage,
  });
  dashboard.setStandaloneMode(true);

  // Federation Slice 1: production boot is LOAD-ONLY. A persisted trust root
  // provisions /v1/federation/*; absence leaves federation honestly off.
  const federationRoot = await provisionOrLoadFederationTrustRoot({
    storage,
    masterKey,
    mint: false,
    audit: async (event) => {
      try {
        await auditLog.append(
          "l2",
          event.operation,
          "federation",
          event.details,
          event.result,
        );
      } catch {
        // Federation remains fail-closed; dashboard boot should still report
        // provisioned:false rather than crash or mint a replacement root.
      }
    },
  });
  if (federationRoot !== null) {
    // The real operator-approval gate for a LOCAL / sovereign_tee join. Model:
    // token-as-approval: the operator's live Tier-1 decision already happened at
    // the OPERATOR_SIGNED `authorize/init` that minted the bootstrap token, and
    // by the time this approver runs the ceremony has verified token signature +
    // fortress binding + expiry + node_mode + revocation + HKDF possession proof.
    // The approver ADDS the one control the ceremony lacks (single-use nonce
    // consumption, so a valid local join is NOT replayable for the token TTL),
    // denies operator_cloud (those route through the operator-cloud approver),
    // and fails closed on any missing / invalid input. It never auto-approves a
    // token-less or forged join. The nonce store is DURABLE (encrypted at rest
    // under the custody master), so a spent nonce survives a daemon restart and
    // a replay is denied for the whole token TTL even across a restart.
    // (createAutoApprove / createAutoDeny are tests-only and must never appear
    // here.)
    const nonceStore = BootstrapNonceStore.durableFromBoot(storage, masterKey);
    dashboard.setFederationContext({
      ...federationRoot.context,
      approver: createStandaloneJoinApprover({
        pinned_master_pubkey: federationRoot.context.pinnedMasterPubkey,
        issuing_principal_cert: federationRoot.context.issuingPrincipalCert,
        getIssuingPrincipalPrivateKey:
          federationRoot.context.getIssuingPrincipalPrivateKey,
        getMasterPrivateKey: federationRoot.context.getMasterPrivateKey,
        nonceStore,
      }),
    });
  } else {
    // Federation Slice 3a: the JOINER half. A second machine that ran a real
    // join persists a NON-ISSUER joiner trust root; production boot loads it
    // (never mints; a joiner has no master to mint from) into a non-issuer
    // context with NO approver. This provisions /v1/federation reads and
    // /sync/peer (cert-chain verified) but structurally refuses issuance.
    // Issuer precedence: only attempted when no issuer root exists (Q3). A
    // malformed/tampered joiner record fails closed (load returns null) and
    // leaves federation honestly off; boot never crashes, never mints.
    const joinerRoot = await loadFederationJoinerTrustRoot({
      storage,
      masterKey,
      audit: async (event) => {
        try {
          await auditLog.append(
            "l2",
            event.operation,
            "federation",
            event.details,
            event.result,
          );
        } catch {
          // Federation remains fail-closed; dashboard boot reports
          // provisioned:false rather than crash or mint a replacement root.
        }
      },
    });
    if (joinerRoot !== null) {
      // No approver: a joiner is a non-issuer and cannot run the approval gate.
      dashboard.setFederationContext(joinerRoot.context);
    }
  }

  // v1.1.1 hotfix: light up the v1.1 dashboard at /v1.1 plus the operator
  // hub API at /api/hub/*. Legacy routes at / continue to serve. The
  // primary identity (if any) scopes the hub; an empty identity registry
  // falls back to a synthesized fortress-local label so the API surface
  // stays consistent across boots without any identity unlocked.
  const hubIdentityId =
    identityManager.getPrimaryIdentityId() ??
    `fortress:${config.storage_path}`;
  // WP-V1.2-5: construct + load the Intelligence Substrate Selector against
  // the unlocked fortress so the v1.1 dashboard's Intelligence panel has
  // a live config to render. Best-effort: any failure degrades to a
  // selector-less binding (panel surfaces "not configured").
  let intelligenceSelector: SubstrateSelector | undefined;
  try {
    intelligenceSelector = new SubstrateSelector({
      storage,
      masterKey,
      auditLog,
      identityId: hubIdentityId,
    });
    await intelligenceSelector.load();
  } catch (err) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  Note: Intelligence panel unavailable (${(err as Error).message}).`,
    );
    intelligenceSelector = undefined;
  }
  const v11Bindings = buildV11Bindings({
    identityId: hubIdentityId,
    fortressId: fortressIdFromStoragePath(config.storage_path),
    auditLog,
    // v1.1.5 (Finding Z): rehydrate the hub agent registry from
    // `<storagePath>/state/_hub/local-agents.json` so the standalone
    // dashboard surfaces wraps performed by prior `sanctuary wrap`
    // invocations against this same fortress.
    storagePath: config.storage_path,
    ...(intelligenceSelector ? { intelligenceSelector } : {}),
    // WP-V1.2-4: forward the storage backend + master key so
    // buildV11Bindings constructs the operator chat service. The
    // chat surfaces (concierge + direct-agent) depend on these for
    // encrypted at-rest persistence under the reserved `_chat`
    // namespace.
    storage,
    masterKey,
    identityManager,
    policy,
    config,
  });
  dashboard.setV11Bindings(v11Bindings);

  // v1.3 cycle 2: wire TaskService into the hub so `sanctuary task`
  // CLI commands (which hit /api/hub/tasks/*) work in standalone mode.
  // TaskService needs a signing identity; if none exists yet (fresh
  // fortress from `sanctuary init` with no prior MCP session), create
  // a fortress-local identity so TaskService can function immediately.
  const idEncKey = derivePurposeKey(masterKey, "identity-encryption");
  let signingIdentity = identityManager.getDefault();
  if (!signingIdentity) {
    const { storedIdentity } = createIdentity(
      `fortress:${config.storage_path}`,
      idEncKey,
      passphrase ? "passphrase" : "recovery-key",
    );
    await identityManager.save(storedIdentity);
    signingIdentity = storedIdentity;
  }
  {
    const stateStore = new StateStore(storage, masterKey);
    const { hubService } = v11Bindings;
    const taskService = new TaskService({
      stateStore,
      auditLog,
      fortressId: fortressIdFromStoragePath(config.storage_path),
      identityId: hubIdentityId,
      signingIdentity,
      identityEncryptionKey: idEncKey,
      enqueueReviewApproval: (task, actor) =>
        hubService.enqueueTaskReviewApproval(task, actor),
    });
    hubService.setTaskService(taskService);
  }

  // v0.10.2 - loopback auto-auth: the passphrase that unlocked at least
  // one identity above is strictly stronger than the dashboard bearer
  // token (which lives only in memory and is re-generated on restart).
  // Once terminal-side auth has succeeded, requiring the operator to paste
  // that same passphrase into a browser form on localhost is pure friction
  // and trains the wrong habit. Skip the login prompt for loopback callers
  // when (a) the dashboard binds a loopback interface AND (b) at least one
  // identity decrypted. Remote callers keep the bearer-token requirement.
  const hostIsLoopback =
    dashboardHost === "127.0.0.1" ||
    dashboardHost === "::1" ||
    dashboardHost === "localhost";
  if (hostIsLoopback && loadResult.loaded > 0) {
    dashboard.setAutoAuthLocalhost(true);
  }

  // HABEAS PORT local distress lane. The standalone dashboard is the
  // long-lived operator process on the machine (launchd/systemd), so it is
  // where the local listener belongs - the MCP server is launched on-demand
  // via stdio and is not reliably up when an agent emits distress. The
  // listener binds 127.0.0.1:8741 (the reserved habeas port), authenticates
  // deliveries against an operator-uid-only secret, and persists received
  // signals to the encrypted, operator-readable distress inbox. The dashboard
  // surfaces that inbox read-only at /api/distress/* behind its existing auth.
  //
  // Everything here is additive and best-effort: a secret-mode error or a port
  // conflict logs loudly and leaves the dashboard running. The in-process
  // distress lane (stderr + audit, emitted server-side) is never affected.
  const distressInbox = new DistressInbox(storage, masterKey);
  await distressInbox.load();
  dashboard.setDistressInbox(distressInbox);

  let distressListener: DistressListener | undefined;
  try {
    const localSecret = await loadOrCreateLocalListenerSecret(config.storage_path);
    distressListener = new DistressListener({
      inbox: distressInbox,
      auditLog,
      localSecret,
      identityId: fortressIdFromStoragePath(config.storage_path),
    });
    await distressListener.start();
  } catch (err) {
    // A bad secret mode (group/world-readable) or any setup failure must not
    // stop the dashboard; the in-process lane still holds.
    const detail =
      err instanceof DistressLocalSecretError
        ? err.message
        : err instanceof Error
          ? err.message
          : String(err);
    // SAFETY: stderr is the operator-facing console for this service boot.
    console.error(
      `[SANCTUARY DISTRESS] local listener not started: ${detail}\n` +
        `  The in-process distress lane (stderr + audit) is unaffected.`,
    );
    distressListener = undefined;
  }

  await dashboard.start();

  // Advertise this tenant's dashboard to `sanctuary agents` + multi-agent
  // aggregator. Best-effort, cleaned up on graceful shutdown.
  await writeTenantRuntime(config.storage_path, {
    version: SANCTUARY_VERSION,
    pid: process.pid,
    started_at: new Date().toISOString(),
    dashboard_host: dashboardHost,
    dashboard_port: dashboardPort,
    ...(typeof config.webhook?.callback_port === "number"
      ? {
          webhook_callback_port: config.webhook.callback_port,
          webhook_callback_host: config.webhook.callback_host,
        }
      : {}),
    mode: "standalone",
  });
  const clearRuntime = () => {
    clearTenantRuntime(config.storage_path).catch(() => {});
    distressListener?.stop().catch(() => {});
  };
  process.once("SIGINT", clearRuntime);
  process.once("SIGTERM", clearRuntime);
  process.once("exit", clearRuntime);

  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(`Sanctuary Dashboard v${SANCTUARY_VERSION} (standalone mode)`);
  console.error(`Storage: ${config.storage_path}`);
  console.error(`Identities loaded: ${loadResult.loaded}`);
  // v1.1.5 (Finding Z): surface the v1.1 hub-layer agent count alongside
  // the L1 identity count. The two layers describe different concerns:
  // L1 identities are master-key-derived Ed25519 keys created lazily on
  // first fortress-unlock; the hub agent registry tracks what `sanctuary
  // wrap` has registered. Both lines are valid; reading 0 on either is
  // not a failure mode, just a state of the fortress at boot.
  const persistedAgentsCount = readPersistedLocalAgents(
    config.storage_path,
  ).length;
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(`Local agents loaded: ${persistedAgentsCount}`);
  console.error(`Listening: http://${dashboardHost}:${dashboardPort}`);

  // 9a. Warn loudly if encrypted identity files exist but none could be decrypted
  if (loadResult.total > 0 && loadResult.loaded === 0) {
    const service = keychainServiceFor(config.storage_path, homedir());
    const sourceLabel =
      passphraseSource === "option"
        ? "--passphrase option"
        : passphraseSource === "env"
        ? "SANCTUARY_PASSPHRASE env var"
        : passphraseSource === "keychain"
        ? `${process.platform === "linux" ? "Linux Secret Service" : "macOS Keychain"} (service ${service})`
        : passphraseSource === "fallback-file"
        ? "encrypted fallback file"
        : "recovery key";
    const otherTenants = await discoverableSubTenants(
      config.storage_path,
      options.discoveryOptions,
    );
    const hint =
      otherTenants.length > 0
        ? `\n     ${renderTenantDiscoveryHint(otherTenants).split("\n").join("\n     ")}\n`
        : "";
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `\n  ⚠  WARNING: Encrypted identities found but NONE loaded\n` +
        `     ${loadResult.total} encrypted identity file(s) in ${config.storage_path}/state/_identities/\n` +
        `     0 could be decrypted with the master key derived from the ${sourceLabel}.\n\n` +
        `     The dashboard will show empty panels. Each wrapped tenant has its\n` +
        `     own passphrase under its own per-tenant Keychain service\n` +
        `     (this tenant's service: ${service}) - there is no global master\n` +
        `     credential. Setting SANCTUARY_PASSPHRASE here will not help unless\n` +
        `     that value is the passphrase that originally encrypted the\n` +
        `     identity files at this storage path.\n` +
        hint +
        `\n     Diagnostic recipes: server/docs/keychain-schema.md\n` +
        `     Sanctuary will never auto-regenerate - that would permanently\n` +
        `     destroy the data encrypted under the prior key.\n`
    );
  } else if (loadResult.failed > 0) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `Warning: ${loadResult.failed} of ${loadResult.total} identity files could not be decrypted (possibly corrupted).`
    );
  }

  // 12. Save baseline on exit
  const saveBaseline = () => {
    baseline.save().catch(() => {});
  };
  process.on("SIGINT", saveBaseline);
  process.on("SIGTERM", saveBaseline);

  return dashboard;
}
