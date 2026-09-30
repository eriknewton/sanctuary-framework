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

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { writeFileCustody } from "../../storage/custody-fs.js";
import { FilesystemStorage } from "../../storage/filesystem.js";
import { loadConfig } from "../../config.js";
import { resolveCliMasterKey } from "../../core/master-custody.js";
import { AuditLog } from "../../operational/audit-log.js";
import { getOrCreatePassphrase } from "../../wrap/passphrase.js";
import { KeychainBackend } from "./keychain-backend.js";
import { Broker } from "./broker.js";
import {
  SurrogatePolicyError,
  parseBrokerPolicy,
  parseSurrogatePolicyDocument,
  type SurrogatePolicyDocument,
  type SurrogatePolicyFailureClass,
} from "./policy.js";
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
  /**
   * The shared audit log the broker writes to (same storage the main server
   * uses). Threaded out so the long-running `broker-server` daemon can append
   * its liveness heartbeat / stand-down through the SAME chain the broker's
   * token decisions land on, without re-opening storage. The per-invocation
   * `sanctuary secrets` CLI ignores it.
   */
  auditLog: AuditLog;
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

  // 3. Resolve master key.
  // Unified custody (master-custody.ts): never derive a fortress master verb-locally.
  const masterKey = await resolveCliMasterKey(storage, {
    passphrase,
    bootstrap: true,
    storagePathHint: storagePath,
  });

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
    auditLog,
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
    // Missing or malformed broker policy resolves to zero grants, so load failure denies access instead of allowing all.
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
  const path = brokerPolicyPath(storagePath);
  const body = JSON.stringify({ skills }, null, 2);
  // Owner-only from the FIRST byte (O_EXCL temp at 0600 + rename), never
  // default-mode-then-chmod: this file is a direct fortress-root child, and
  // once a file-grant fortress traverse ACE is live the agent uid can open
  // root children by known name during a lax-creation window. It holds
  // broker grant policy metadata (secret NAMES, scopes, TTLs). Parent is
  // created 0700. See the FORTRESS-DIR TRAVERSAL note in
  // file-grant/fs-ops.ts.
  await writeFileCustody(path, body, { mode: 0o600, parentMode: 0o700 });
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

// ---------------------------------------------------------------------------
// Surrogate policy file: a SEPARATE document old writers never touch
// ---------------------------------------------------------------------------
//
// `brokerPolicyPath` above, `saveBrokerPolicy`, `loadBrokerPolicyRaw` and the
// `secrets grant` / `secrets revoke` writers in `cli/secrets.ts` all read and
// write `broker-policy.json` ONLY. Keeping bindings out of that file is what makes
// a rollback safe: an old build keeps serving ordinary grants and simply never
// sees surrogacy (design v2.1 section 3.3, round-2 finding A2-B2).

/**
 * Path of the surrogate binding policy, beside `broker-policy.json` and never
 * inside it.
 */
export function surrogatePolicyPath(storagePath: string): string {
  return join(storagePath, "surrogate-policy.json");
}

/**
 * Write the surrogate policy owner-only from the first byte.
 *
 * Mode and parent mode match `saveBrokerPolicy` above for the same reason stated
 * there: this file is a direct fortress-root child, and once a file-grant fortress
 * traverse ACE is live the agent uid can open root children by known name during a
 * lax-creation window. It holds secret NAMES, env names, bound headers and
 * destination hosts, which together are a map of which credential is spent where.
 */
export async function saveSurrogatePolicy(
  storagePath: string,
  document: SurrogatePolicyDocument,
): Promise<void> {
  // Re-parse before writing, so a caller cannot persist a document that the
  // loader, root arming and the helper would then refuse. The write side and the
  // read side share one grammar.
  const validated = parseSurrogatePolicyDocument(document);
  await writeFileCustody(surrogatePolicyPath(storagePath), JSON.stringify(validated, null, 2), {
    mode: 0o600,
    parentMode: 0o700,
  });
}

/**
 * Outcome of a surrogate policy load.
 *
 * THE ENOENT SPLIT (round-2 finding B2-S6). An absent file and a present broken
 * file are different events and must not share a branch, which is the defect in
 * the bare `catch` that `loadBrokerGrants` above still uses for broker grants:
 *   - `absent`: the normal "this fortress has no bindings" case. Zero bindings,
 *     and the caller writes NO audit line. Auditing it would put a line in the
 *     chain on every load for every fortress that never used surrogacy.
 *   - `failed`: a file that IS there and could not be read or parsed. Zero
 *     bindings, and the caller writes `BROKER_OPS.POLICY_LOAD_FAILED` carrying
 *     `failureClass` and nothing else. Never a partial binding set: arming from
 *     half a document would give an agent a destination map nobody wrote.
 */
export type SurrogatePolicyLoadResult =
  | { outcome: "absent" }
  | { outcome: "loaded"; document: SurrogatePolicyDocument }
  | { outcome: "failed"; failureClass: SurrogatePolicyFailureClass };

/**
 * Load and parse the surrogate policy, classifying the failure instead of
 * collapsing every cause into zero bindings.
 *
 * Returns a result rather than throwing, because every caller needs the same
 * three-way decision and none of them may treat "broken" as "absent". The
 * failure class is fixed; no parser message text is ever returned, so a caller
 * cannot log the document's contents by logging the error.
 */
export async function loadSurrogatePolicyDocument(
  storagePath: string,
): Promise<SurrogatePolicyLoadResult> {
  const path = surrogatePolicyPath(storagePath);
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code === "ENOENT") return { outcome: "absent" };
    return { outcome: "failed", failureClass: "read_error" };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { outcome: "failed", failureClass: "json_error" };
  }
  try {
    return { outcome: "loaded", document: parseSurrogatePolicyDocument(parsed) };
  } catch (err) {
    if (err instanceof SurrogatePolicyError) {
      return { outcome: "failed", failureClass: err.failureClass };
    }
    return { outcome: "failed", failureClass: "schema_error" };
  }
}
