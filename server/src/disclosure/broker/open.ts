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
import { AuditLog, BROKER_OPS } from "../../operational/audit-log.js";
import { getOrCreatePassphrase } from "../../wrap/passphrase.js";
import { KeychainBackend } from "./keychain-backend.js";
import { Broker } from "./broker.js";
import { SurrogateValueStore } from "./surrogate-store.js";
import {
  SurrogatePolicyError,
  findSurrogateGrantConflicts,
  parseBrokerPolicy,
  parseSurrogatePolicyDocument,
  surrogateBoundSecretNames,
  type SurrogatePolicyDocument,
  type SurrogatePolicyFailureClass,
} from "./policy.js";
import type { SkillSecretGrant } from "./token-issuer.js";
import type { SurrogateBinding } from "../../credential-surrogate/binding.js";
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

/**
 * Steps 1 to 4 shared by `openBroker` and `openSurrogateStore`: config, the
 * fortress passphrase, the master key and the audit log.
 *
 * Factored out rather than copied because the two verbs must resolve the SAME
 * passphrase and write to the SAME chain. Two copies would be two places for a
 * surrogate verb to drift onto a different fortress than the broker it is
 * supposed to be keeping a secret away from, and a value bound in one fortress
 * while the conflict check ran against another would read as safe when it is
 * not.
 */
async function openFortressContext(opts: OpenBrokerOptions): Promise<{
  storagePath: string;
  passphrase: string;
  auditLog: AuditLog;
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

  return { storagePath, passphrase, auditLog };
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
  const { storagePath, passphrase, auditLog } = await openFortressContext(opts);

  // 5. Keychain backend (macOS only; throws BackendUnavailableError elsewhere).
  const backend = opts.backend ?? new KeychainBackend({ storagePath });
  await backend.ensureInitialized(passphrase);

  // 6. Load BOTH policy files and reconcile them before any grant reaches the
  //    issuer. The audit log is already built (step 4), which is why the loads
  //    live here: a load failure has to be recordable, and a broker that cannot
  //    say why it served nothing is indistinguishable from one that had nothing
  //    to serve.
  const { grants, bindings } = await loadBrokerAndSurrogatePolicies(storagePath, auditLog, {
    principalIdentityId: opts.principalIdentityId ?? "sanctuary-broker",
  });

  const broker = new Broker({
    backend,
    auditLog,
    grants,
    // Required, never optional (AGENTS.md rule 3): the set is how the broker
    // refuses a bound name even when a policy file somehow names it. An empty
    // set is the honest "no bindings" value and still has to be passed.
    surrogateBoundSecrets: surrogateBoundSecretNames(bindings),
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

/**
 * Outcome of a broker grant load, classified the same three ways the surrogate
 * loader classifies its own (see `SurrogatePolicyLoadResult` below).
 *
 * THE ENOENT SPLIT (round-2 finding B2-S6). The previous shape was one bare
 * `catch` returning `[]`, which is correct for access but silent about cause: a
 * fortress that never granted anything and a fortress whose policy file was
 * truncated by a half-finished write both read as "zero grants", so an operator
 * whose grants stopped working had nothing to look at. Absence stays silent
 * (auditing it would append a line on every load for every fortress that never
 * used the broker); a file that IS there and cannot be read or parsed gets one
 * `POLICY_LOAD_FAILED` line carrying a fixed class.
 *
 * Either way the grant set is EMPTY, never partial: serving the half of a
 * document that happened to parse is how a revocation gets silently undone.
 */
type BrokerGrantLoadResult =
  | { outcome: "absent" }
  | { outcome: "loaded"; grants: SkillSecretGrant[] }
  | { outcome: "failed"; failureClass: SurrogatePolicyFailureClass };

/**
 * Load and parse `broker-policy.json`, classifying the failure instead of
 * collapsing every cause into zero grants.
 *
 * Exported for the wired-consumer test; `openBroker` is the production caller.
 */
export async function loadBrokerGrantsClassified(
  storagePath: string,
): Promise<BrokerGrantLoadResult> {
  const policyPath = brokerPolicyPath(storagePath);
  let raw: string;
  try {
    raw = await readFile(policyPath, "utf8");
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
    return { outcome: "loaded", grants: parseBrokerPolicy(parsed) };
  } catch {
    // `parseBrokerPolicy` throws plain `Error`s whose text quotes the offending
    // policy entry, so the class is all that may cross into the chain.
    return { outcome: "failed", failureClass: "schema_error" };
  }
}

/**
 * Read both policy files, apply the conflict rule, and return the grant set the
 * issuer may have plus the bindings the broker must refuse against.
 *
 * Fail-closed in three separate ways, each of which yields ZERO grants:
 *  - `broker-policy.json` present and unreadable or unparseable;
 *  - `surrogate-policy.json` present and unreadable or unparseable (a fortress
 *    that meant to bind a secret away from the broker must not fall back to the
 *    broker serving it because the binding file broke);
 *  - a secret named by a binding AND by a `read` or `rotate` grant (design v2.1
 *    section 3.3 conflict rule).
 *
 * Exported for the wired-consumer test; `openBroker` is the production caller.
 */
export async function loadBrokerAndSurrogatePolicies(
  storagePath: string,
  auditLog: AuditLog,
  opts: { principalIdentityId: string },
): Promise<{ grants: SkillSecretGrant[]; bindings: SurrogateBinding[] }> {
  const auditLoadFailure = async (
    file: "broker" | "surrogate",
    failureClass: SurrogatePolicyFailureClass,
  ): Promise<void> => {
    // `append`, not `appendCritical` (round-2 finding B2-S6): a broken policy
    // file denies by itself, so the load must not be blocked on a chain write.
    // The detail carries the file and the fixed class ONLY: this path just read
    // something it could not trust, so none of it may be echoed into the chain.
    await auditLog.append("l3", BROKER_OPS.POLICY_LOAD_FAILED, opts.principalIdentityId, {
      file,
      failure_class: failureClass,
    });
  };

  const surrogateResult = await loadSurrogatePolicyDocument(storagePath);
  if (surrogateResult.outcome === "failed") {
    await auditLoadFailure("surrogate", surrogateResult.failureClass);
    // ZERO grants, not "the grants minus the bindings". A fortress that
    // deliberately moved a secret out of the broker's reach must not fall back
    // to the broker serving it, or anything else, because the binding file
    // broke: that would turn one unreadable file into the broker handing out
    // exactly the credential surrogacy exists to withhold.
    return { grants: [], bindings: [] };
  }
  const bindings =
    surrogateResult.outcome === "loaded" ? surrogateResult.document.bindings : [];

  const grantResult = await loadBrokerGrantsClassified(storagePath);
  if (grantResult.outcome === "failed") {
    await auditLoadFailure("broker", grantResult.failureClass);
    return { grants: [], bindings };
  }
  const grants = grantResult.outcome === "loaded" ? grantResult.grants : [];

  const conflicts = findSurrogateGrantConflicts(bindings, grants);
  if (conflicts.length > 0) {
    // Zero grants, not "drop the conflicting ones": a policy in this state was
    // written by two callers who disagreed about where a secret lives, and
    // serving the rest of it would make the disagreement invisible. The names
    // are already in the chain via SECRET_GRANTED, so listing them here adds no
    // disclosure and is what lets the operator find the row to delete.
    await auditLog.append("l3", BROKER_OPS.POLICY_LOAD_FAILED, opts.principalIdentityId, {
      file: "surrogate",
      failure_class: "conflict" satisfies SurrogatePolicyFailureClass,
      secrets: conflicts,
    });
    return { grants: [], bindings };
  }

  return { grants, bindings };
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

export interface OpenSurrogateStoreOptions extends OpenBrokerOptions {
  /** Home directory override for tests, threaded to the identity derivation. */
  home?: string;
}

/**
 * Open the surrogate value store: the operator-side counterpart of `openBroker`,
 * on the SAME fortress, the SAME passphrase and the SAME audit chain, against a
 * DIFFERENT keychain label.
 *
 * It returns no `Broker` and constructs none. Nothing on the token path is built
 * here, which is the point: the only way to reach a bound value is to be the
 * operator running a surrogate verb, and from there the value goes straight to
 * the root helper over the unlock socket.
 *
 * `storagePath` is threaded out so the caller reaches `surrogate-policy.json`
 * for the same fortress rather than re-resolving config and possibly landing on
 * another one.
 */
export async function openSurrogateStore(opts: OpenSurrogateStoreOptions = {}): Promise<{
  store: SurrogateValueStore;
  storagePath: string;
  auditLog: AuditLog;
  close: () => Promise<void>;
}> {
  const { storagePath, passphrase, auditLog } = await openFortressContext(opts);

  const store = new SurrogateValueStore({
    storagePath,
    home: opts.home,
    backend: opts.backend,
  });
  await store.ensureInitialized(passphrase);

  return {
    store,
    storagePath,
    auditLog,
    // Drains pending audit writes for the same reason `openBroker.close` does:
    // a surrogate verb that calls `process.exit()` right after `SURROGATE_BOUND`
    // would otherwise drop the entry mid-write.
    close: async () => {
      await auditLog.flush();
    },
  };
}
