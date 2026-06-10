/**
 * Sanctuary MCP Server — L3 Secret Broker: Open Helper
 *
 * Lightweight bootstrap used by the `sanctuary secrets` CLI and the
 * broker MCP server. Opens a ready-to-use Broker without spinning up the
 * full createSanctuaryServer() — we only need the master key, storage,
 * audit log, keychain backend, and policy-loaded grants.
 *
 * Passphrase resolution reuses the existing fortress pattern (keychain or
 * encrypted fallback file), so the user does NOT manage a separate
 * broker passphrase — it's the same passphrase that protects the main
 * Sanctuary master key.
 */

import { readFile, writeFile, mkdir, chmod } from "node:fs/promises";
import { join } from "node:path";
import { FilesystemStorage } from "../../storage/filesystem.js";
import { loadConfig } from "../../config.js";
import { deriveMasterKey, type KeyDerivationParams } from "../../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../../core/encoding.js";
import { AuditLog } from "../../l2-operational/audit-log.js";
import { getOrCreatePassphrase } from "../../wrap/passphrase.js";
import { KeychainBackend } from "./keychain-backend.js";
import { Broker } from "./broker.js";
import { parseBrokerPolicy } from "./policy.js";
import type { Backend } from "./backend-interface.js";

export interface OpenBrokerOptions {
  /** Override passphrase (otherwise resolved via keychain/passphrase). */
  passphrase?: string;
  /** Override storage path (otherwise config.storage_path). */
  storagePath?: string;
  /** Override principal identity id (otherwise "broker-cli" + version). */
  principalIdentityId?: string;
  /** Optional injected backend (for tests). */
  backend?: Backend;
}

export async function openBroker(opts: OpenBrokerOptions = {}): Promise<{
  broker: Broker;
  close: () => Promise<void>;
}> {
  // 1. Resolve or load Sanctuary config for storage path
  const config = await loadConfig();
  const storagePath = opts.storagePath ?? config.storage_path;
  const storage = new FilesystemStorage(`${storagePath}/state`);

  // 2. Resolve passphrase — same resolution the wrap CLI uses.
  let passphrase = opts.passphrase ?? process.env.SANCTUARY_PASSPHRASE;
  if (!passphrase) {
    const resolved = await getOrCreatePassphrase({ storagePath });
    passphrase = resolved.value;
  }

  // 3. Derive master key.
  let existingParams: KeyDerivationParams | undefined;
  try {
    const raw = await storage.read("_meta", "key-params");
    if (raw) {
      existingParams = JSON.parse(bytesToString(raw));
    }
  } catch {
    /* first run — params not yet persisted */
  }
  const { key: masterKey, params } = await deriveMasterKey(passphrase, existingParams);
  if (!existingParams) {
    await storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify(params))
    );
  }

  // 4. Audit log — shares storage with the main server so `sanctuary audit`
  //    sees broker entries alongside L1/L2/L4 entries.
  const auditLog = new AuditLog(storage, masterKey);

  // 5. Keychain backend (macOS only; throws BackendUnavailableError elsewhere).
  const backend = opts.backend ?? new KeychainBackend({ storagePath });
  await backend.ensureInitialized(passphrase);

  // 6. Load broker grants from policy file if present.
  const grants = await loadBrokerGrants(storagePath);

  const broker = new Broker({
    backend,
    auditLog,
    grants,
    principalIdentityId: opts.principalIdentityId ?? "sanctuary-broker",
  });

  // Hardening wave 6 finding #86: fortress-unlock fires expiry pruning so
  // any tokens that survived a prior process restart-as-cache scenario
  // are dropped before the operator can issue or read against them.
  // pruneExpired is idempotent and synchronous; failures bubble (none
  // expected, purely in-memory map iteration).
  broker.pruneExpiredTokens();

  return {
    broker,
    close: async () => {
      // Drain pending audit writes before the caller exits — without this,
      // CLI invocations that call `process.exit()` immediately after a
      // broker mutation drop the audit entry mid-write. Storage is FS so
      // no socket close is needed.
      await auditLog.flush();
    },
  };
}

/** Path where broker policy is stored. JSON for now — YAML coverage is
 * added in v0.10.1 alongside a proper policy parser. Kept separate from
 * principal-policy.yaml so existing policy tooling is unaffected. */
export function brokerPolicyPath(storagePath: string): string {
  return join(storagePath, "broker-policy.json");
}

async function loadBrokerGrants(storagePath: string) {
  const policyPath = brokerPolicyPath(storagePath);
  try {
    const raw = await readFile(policyPath, "utf8");
    return parseBrokerPolicy(JSON.parse(raw));
  } catch {
    return [];
  }
}

export async function saveBrokerPolicy(
  storagePath: string,
  skills: Array<{
    name: string;
    secrets: Array<{ name: string; scope?: "read" | "rotate"; ttl?: number }>;
  }>
): Promise<void> {
  await mkdir(storagePath, { recursive: true });
  const path = brokerPolicyPath(storagePath);
  const body = JSON.stringify({ skills }, null, 2);
  await writeFile(path, body);
  try {
    await chmod(path, 0o600);
  } catch {
    /* non-POSIX filesystems */
  }
}

export async function loadBrokerPolicyRaw(
  storagePath: string
): Promise<{ skills: Array<{ name: string; secrets: Array<{ name: string; scope?: "read" | "rotate"; ttl?: number }> }> }> {
  const policyPath = brokerPolicyPath(storagePath);
  try {
    const raw = await readFile(policyPath, "utf8");
    const parsed = JSON.parse(raw);
    if (parsed && Array.isArray(parsed.skills)) return parsed;
    return { skills: [] };
  } catch {
    return { skills: [] };
  }
}
