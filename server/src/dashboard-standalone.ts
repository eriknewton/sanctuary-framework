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
import { loadConfig, SANCTUARY_VERSION } from "./config.js";
import { FilesystemStorage } from "./storage/filesystem.js";
import { AuditLog } from "./l2-operational/audit-log.js";
import { loadPrincipalPolicy } from "./principal-policy/loader.js";
import { BaselineTracker } from "./principal-policy/baseline.js";
import { DashboardApprovalChannel } from "./principal-policy/dashboard.js";
import { deriveMasterKey, type KeyDerivationParams } from "./core/key-derivation.js";
import { generateRandomKey } from "./core/random.js";
import { toBase64url } from "./core/encoding.js";

export interface StandaloneDashboardOptions {
  passphrase?: string;
  port?: number;
  host?: string;
  configPath?: string;
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

  // 1. Load configuration
  const config = await loadConfig(options.configPath);

  // 2. Ensure storage directory exists
  await mkdir(config.storage_path, { recursive: true, mode: 0o700 });

  // 3. Initialize storage backend
  const storage = new FilesystemStorage(`${config.storage_path}/state`);

  // 4. Derive or load master key (same logic as index.ts)
  let masterKey: Uint8Array;
  const passphrase = options.passphrase ?? process.env.SANCTUARY_PASSPHRASE;

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
  } else {
    // Recovery key path
    const { hashToString } = await import("./core/hashing.js");
    const { stringToBytes, bytesToString, fromBase64url, constantTimeEqual } =
      await import("./core/encoding.js");

    const existingHash = await storage.read("_meta", "recovery-key-hash");
    if (existingHash) {
      // Recovery key path: existing installation with recovery key
      const envRecoveryKey = process.env.SANCTUARY_RECOVERY_KEY;
      if (!envRecoveryKey) {
        throw new Error(
          "Sanctuary Dashboard: Existing encrypted data found but no credentials provided.\n" +
          "Provide SANCTUARY_PASSPHRASE or SANCTUARY_RECOVERY_KEY to start the dashboard.\n" +
          "The dashboard needs the same credentials as the MCP server to read encrypted data."
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
          "Sanctuary Dashboard: Existing encrypted data found (passphrase-protected).\n" +
          "Provide SANCTUARY_PASSPHRASE to start the dashboard.\n" +
          "The dashboard needs the same credentials as the MCP server to read encrypted data."
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

      console.error(
        "╔══════════════════════════════════════════════════════════╗\n" +
        "║  SANCTUARY: First Run — Recovery Key Generated          ║\n" +
        "║                                                          ║\n" +
        `║  Recovery Key: ${recoveryKey.slice(0, 20)}...             ║\n` +
        "║                                                          ║\n" +
        "║  SAVE THIS KEY. It will not be shown again.              ║\n" +
        "╚══════════════════════════════════════════════════════════╝\n"
      );
    }
  }

  // 5. Initialize audit log (for reading historical entries)
  const auditLog = new AuditLog(storage, masterKey);

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

  dashboard.setDependencies({ policy, baseline, auditLog });
  await dashboard.start();

  console.error(`Sanctuary Dashboard v${SANCTUARY_VERSION} (standalone mode)`);
  console.error(`Storage: ${config.storage_path}`);
  console.error(`Listening: http://${dashboardHost}:${dashboardPort}`);

  // 9. Save baseline on exit
  const saveBaseline = () => {
    baseline.save().catch(() => {});
  };
  process.on("SIGINT", saveBaseline);
  process.on("SIGTERM", saveBaseline);

  return dashboard;
}
