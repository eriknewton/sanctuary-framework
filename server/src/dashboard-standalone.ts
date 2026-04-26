/**
 * Sanctuary MCP Server — Standalone Dashboard
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
 * NOT available in standalone mode — those require the dashboard and
 * MCP server to share a process. The standalone dashboard serves
 * historical data via the audit log API.
 */

import { mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { loadConfig, SANCTUARY_VERSION } from "./config.js";
import { FilesystemStorage } from "./storage/filesystem.js";
import { AuditLog } from "./l2-operational/audit-log.js";
import {
  consumeResetHistoryMarker,
  ResetHistoryMalformedError,
} from "./audit/reset-history.js";
import { loadPrincipalPolicy } from "./principal-policy/loader.js";
import { BaselineTracker } from "./principal-policy/baseline.js";
import { DashboardApprovalChannel } from "./principal-policy/dashboard.js";
import { deriveMasterKey, type KeyDerivationParams } from "./core/key-derivation.js";
import { generateRandomKey } from "./core/random.js";
import { toBase64url } from "./core/encoding.js";
import { IdentityManager } from "./l1-cognitive/tools.js";
import type { HandshakeResult } from "./handshake/types.js";
import { SovereigntyProfileStore } from "./sovereignty-profile.js";
import { writeTenantRuntime, clearTenantRuntime } from "./cli/agents/runtime.js";
import {
  readStoredPassphrase,
  keychainServiceFor,
  PassphraseUnreadableError,
} from "./cocoon/passphrase.js";
import {
  discloseRecoveryKey,
  RecoveryKeyConfirmationDeclinedError,
  RecoveryKeyConfirmationNonInteractiveError,
} from "./cocoon/recovery-key-disclosure.js";
import { discoverTenants, findTenant, type TenantDescriptor } from "./cli/agents/discovery.js";

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
   * Skip the interactive confirmation prompt when the standalone dashboard
   * generates a fresh recovery key on first run. Required for non-TTY
   * (CI/launchd/systemd) callers that would otherwise refuse to start.
   */
  noConfirm?: boolean;
}

/**
 * List the tenants visible on this host that the operator could boot against
 * other than the storage path the current process is already configured for.
 *
 * Returns an empty list when no tenants exist or when the current path is the
 * only thing on disk. Filters out the configured storage path itself so the
 * "did you mean?" hint never suggests the tenant the user is already pointed
 * at.
 */
export async function discoverableSubTenants(
  currentStoragePath: string
): Promise<TenantDescriptor[]> {
  let all: TenantDescriptor[];
  try {
    all = await discoverTenants();
  } catch {
    return [];
  }
  return all.filter((t) => t.storage_path !== currentStoragePath && t.initialized);
}

/**
 * Render the multi-tenant "did you mean?" message that v0.10.4 surfaces
 * instead of the misleading legacy "set SANCTUARY_PASSPHRASE" hint.
 *
 * Exported for unit tests; the wording is part of the contract — operators
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
    const match = await findTenant(options.tenant);
    if (!match) {
      const available = await discoverTenants();
      const names = available.map((t) => t.name).join(", ") || "(none — run `sanctuary wrap`)";
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
  // forcing the user to re-type — or re-paste — the passphrase the wrap
  // already persisted. Multi-tenant hosts with N per-tenant Keychain items
  // (service `sanctuary-passphrase-<12hex>`) no longer require a single
  // `SANCTUARY_PASSPHRASE` that can only unlock one tenant.
  let masterKey: Uint8Array;
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
        console.error(
          `Passphrase: loaded from ${stored.location} (service ${keychainServiceFor(config.storage_path, homedir())})`
        );
      }
    } catch (err) {
      if (err instanceof PassphraseUnreadableError) {
        // Never auto-regenerate — rethrow so the operator sees the same
        // remediation steps the wrap CLI prints.
        throw err;
      }
      // Non-fatal: fall through to the recovery-key path below.
    }
  }

  if (passphrase) {
    // Passphrase path: derive master key via Argon2id
    let existingParams: KeyDerivationParams | undefined;
    try {
      const raw = await storage.read("_meta", "key-params");
      if (raw) {
        const { bytesToString } = await import("./core/encoding.js");
        existingParams = JSON.parse(bytesToString(raw));
      }
    } catch {
      // No existing params
    }

    const result = await deriveMasterKey(passphrase, existingParams);
    masterKey = result.key;

    // v0.10.2: persist derivation params on first run, matching the MCP
    // server (index.ts) and broker (l3-disclosure/broker/open.ts) paths.
    // The standalone dashboard used to assume the MCP server would write
    // `_meta/key-params` first, so it only ever READ them. With the new
    // Keychain-autoload boot path `sanctuary dashboard` can now be the
    // first component to run on a machine — if it derives against a
    // random salt without persisting, the next boot will derive a
    // DIFFERENT master key from the same passphrase and fail to decrypt
    // everything this boot just wrote.
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
    const { hashToString } = await import("./core/hashing.js");
    const { stringToBytes, bytesToString, fromBase64url, constantTimeEqual } =
      await import("./core/encoding.js");

    // v0.10.4: before falling into recovery-key handling against a tenant we
    // could not unlock, check whether the operator probably meant a different
    // tenant. The most common moltbook failure mode is `sanctuary dashboard`
    // run with no flag against a default root that has orphan state but no
    // resolvable passphrase, while sub-tenants exist with their own keychain
    // entries. Surface those sub-tenants instead of the misleading
    // "set SANCTUARY_PASSPHRASE" hint that v0.10.1–v0.10.3 produced.
    const otherTenants = await discoverableSubTenants(config.storage_path);

    const existingHash = await storage.read("_meta", "recovery-key-hash");
    if (existingHash) {
      // Recovery key path: existing installation with recovery key
      const envRecoveryKey = process.env.SANCTUARY_RECOVERY_KEY;
      if (!envRecoveryKey) {
        throw new Error(
          `Sanctuary Dashboard: Existing encrypted data found at ${config.storage_path} but no credentials provided.\n` +
          `Provide SANCTUARY_PASSPHRASE or SANCTUARY_RECOVERY_KEY to start the dashboard against this storage path.\n\n` +
          (otherTenants.length > 0 ? renderTenantDiscoveryHint(otherTenants) + "\n" : "") +
          `See server/docs/keychain-schema.md for the keychain layout.`
        );
      }

      let recoveryKeyBytes: Uint8Array;
      try {
        recoveryKeyBytes = fromBase64url(envRecoveryKey);
      } catch {
        throw new Error(
          "Sanctuary Dashboard: SANCTUARY_RECOVERY_KEY is not valid base64url."
        );
      }

      if (recoveryKeyBytes.length !== 32) {
        throw new Error(
          "Sanctuary Dashboard: SANCTUARY_RECOVERY_KEY has incorrect length."
        );
      }

      const providedHash = hashToString(recoveryKeyBytes);
      const storedHash = bytesToString(existingHash);
      const providedHashBytes = stringToBytes(providedHash);
      const storedHashBytes = stringToBytes(storedHash);

      if (!constantTimeEqual(providedHashBytes, storedHashBytes)) {
        throw new Error(
          "Sanctuary Dashboard: Recovery key does not match. Use the exact recovery key from first run."
        );
      }

      masterKey = recoveryKeyBytes;
    } else {
      // Check if a passphrase was previously used (key-params exist without recovery-key-hash)
      const existingNamespaces = await storage.list("_meta");
      const hasKeyParams = existingNamespaces.some(e => e.key === "key-params");
      if (hasKeyParams) {
        throw new Error(
          `Sanctuary Dashboard: Existing encrypted data found at ${config.storage_path} (passphrase-protected).\n` +
          `No passphrase was supplied via --passphrase, SANCTUARY_PASSPHRASE,\n` +
          `or the per-tenant Keychain item ${keychainServiceFor(config.storage_path, homedir())}.\n\n` +
          (otherTenants.length > 0 ? renderTenantDiscoveryHint(otherTenants) + "\n" : "") +
          `See server/docs/keychain-schema.md for the keychain layout and recovery options.`
        );
      }

      // v0.10.4: refuse to silently fresh-install over a host that already
      // has wrapped tenants. Pre-fix the dashboard would generate a brand-new
      // recovery key in the default root, which made the operator think they
      // had just lost access to N other tenants.
      if (otherTenants.length > 0) {
        throw new Error(
          `Sanctuary Dashboard: ${config.storage_path} has no Sanctuary state, but other wrapped tenants exist on this host.\n` +
          `Refusing to generate a new recovery key over the default root — that would obscure the existing tenants.\n\n` +
          renderTenantDiscoveryHint(otherTenants)
        );
      }

      // No existing data — first run. Generate a key, but warn that this is unusual
      // for standalone dashboard (normally you'd run the MCP server first).
      console.error(
        "Warning: No existing Sanctuary data found. The standalone dashboard\n" +
        "is typically started after the MCP server has been run at least once.\n" +
        "Generating a new master key for this installation.\n"
      );
      masterKey = generateRandomKey();
      const recoveryKey = toBase64url(masterKey);
      const keyHash = hashToString(masterKey);
      await storage.write("_meta", "recovery-key-hash", stringToBytes(keyHash));

      try {
        await discloseRecoveryKey({
          recoveryKey,
          storagePath: config.storage_path,
          mode: options.noConfirm ? "no-confirm" : "interactive",
        });
      } catch (err) {
        if (
          err instanceof RecoveryKeyConfirmationDeclinedError ||
          err instanceof RecoveryKeyConfirmationNonInteractiveError
        ) {
          console.error(`\nSanctuary Dashboard: ${err.message}\n`);
          process.exit(2);
        }
        throw err;
      }
    }
  }

  // 5. Initialize audit log (for reading historical entries)
  const auditLog = new AuditLog(storage, masterKey);

  // 5a. Reset-history continuity (v1.0.2 item a). Same one-shot marker
  // consumption as the MCP server boot path (server/src/index.ts) so the
  // first cocoon-unlock after `reset-passphrase --nuke` records continuity
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
          `Refusing to start the dashboard while the reset-history marker is unreadable.`
      );
    }
    throw err;
  }

  // 6. Load principal policy and baseline
  const policy = await loadPrincipalPolicy(config.storage_path);
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

  // 11. Empty handshake results — handshakes are in-memory per MCP session
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
  });
  dashboard.setStandaloneMode(true);

  // v0.10.2 — loopback auto-auth: the passphrase that unlocked at least
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
  };
  process.once("SIGINT", clearRuntime);
  process.once("SIGTERM", clearRuntime);
  process.once("exit", clearRuntime);

  console.error(`Sanctuary Dashboard v${SANCTUARY_VERSION} (standalone mode)`);
  console.error(`Storage: ${config.storage_path}`);
  console.error(`Identities loaded: ${loadResult.loaded}`);
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
    const otherTenants = await discoverableSubTenants(config.storage_path);
    const hint =
      otherTenants.length > 0
        ? `\n     ${renderTenantDiscoveryHint(otherTenants).split("\n").join("\n     ")}\n`
        : "";
    console.error(
      `\n  ⚠  WARNING: Encrypted identities found but NONE loaded\n` +
        `     ${loadResult.total} encrypted identity file(s) in ${config.storage_path}/state/_identities/\n` +
        `     0 could be decrypted with the master key derived from the ${sourceLabel}.\n\n` +
        `     The dashboard will show empty panels. Each wrapped tenant has its\n` +
        `     own passphrase under its own per-tenant Keychain service\n` +
        `     (this tenant's service: ${service}) — there is no global master\n` +
        `     credential. Setting SANCTUARY_PASSPHRASE here will not help unless\n` +
        `     that value is the passphrase that originally encrypted the\n` +
        `     identity files at this storage path.\n` +
        hint +
        `\n     Diagnostic recipes: server/docs/keychain-schema.md\n` +
        `     Sanctuary will never auto-regenerate — that would permanently\n` +
        `     destroy the data encrypted under the prior key.\n`
    );
  } else if (loadResult.failed > 0) {
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
