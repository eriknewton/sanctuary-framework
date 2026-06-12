/**
 * Sanctuary Verifiable Transparency, anchoring orchestration (PR-2).
 *
 * Connects the pure anchor format (anchor.ts) to fortress storage, the
 * audit log, and the Rekor client. The behavioral contract, in order of
 * precedence:
 *
 *   1. OPT-IN, DEFAULT OFF (hard constraint #1). With no consent record,
 *      or consent disabled, nothing is transmitted, ever. Enabling
 *      requires the operator's explicit confirmation; the consent moment
 *      is recorded in the MAC'd config AND in the audit log.
 *   2. FAIL LOUD, NEVER SILENTLY SKIP (hard constraint #5 shape). When
 *      anchoring is enabled and an anchor attempt fails, the failure is
 *      (a) persisted as a failure receipt beside the checkpoint store,
 *      (b) written to the audit log via appendCritical, and (c) returned
 *      to the caller for operator-console surfacing. Local checkpoint
 *      emission is NEVER blocked by a Rekor outage: the local evidence
 *      chain must not depend on a third party's uptime.
 *   3. TAMPERED CONFIG REFUSES, in BOTH directions. The config envelope is
 *      MAC'd with a master-key-derived purpose key. A config that fails
 *      authentication is neither "enabled" (an attacker must not be able
 *      to switch transmission on) nor "disabled" (an attacker must not be
 *      able to silently switch evidence anchoring off): it is an error the
 *      operator must resolve.
 *   4. HASH-ONLY anchors: see anchor.ts. The only bytes handed to the
 *      Rekor client are the salted digest, the P-256 signature, and the
 *      derived anchoring public key.
 */

import {
  bytesToString,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../core/encoding.js";
import { hmacSha256 } from "../core/hashing.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { randomBytes } from "../core/random.js";
import type { AuditLog } from "../l2-operational/audit-log.js";
import type {
  FilesystemStorageCapabilities,
  StorageBackend,
} from "../storage/interface.js";
import {
  DEFAULT_REKOR_URL,
  TRANSPARENCY_ANCHOR_CONFIG_MAC_PURPOSE,
  TRANSPARENCY_ANCHOR_SCHEMA_VERSION,
  anchorCommitmentDigestHex,
  anchorCommitmentPreimage,
  anchorConfigMacInput,
  anchorPublicKeyPem,
  buildHashedRekordProposal,
  consentTextSha256,
  deriveAnchorSigningKey,
  isAnchorConfigData,
  isAnchorReceipt,
  signAnchorPreimage,
  type AnchorConfigData,
  type AnchorReceipt,
  type AnchoredReceipt,
  type FailedAnchorReceipt,
} from "./anchor.js";
import {
  checkpointPayloadOf,
  computeCheckpointHash,
  type EnforcementCheckpointRecord,
} from "./checkpoint.js";
import { readPersistedCheckpoints } from "./emitter.js";
import { HttpRekorClient, type FetchLike, type RekorClient } from "./rekor-client.js";

export const TRANSPARENCY_ANCHOR_NAMESPACE = "_transparency_anchors";
export const TRANSPARENCY_ANCHOR_RECEIPT_PREFIX = "anchor-";
export const TRANSPARENCY_ANCHOR_CONFIG_META_KEY =
  "transparency-anchor-config-v1";

const ANCHOR_CONFIG_MARKER = "__sanctuary_transparency_anchor_config_v1";

/**
 * The plain-language consent text shown at enable time. Its SHA-256 is
 * recorded in the MAC'd config and in the audit log, so what the operator
 * agreed to is reconstructable. Changing this text changes the recorded
 * hash for NEW consents only.
 */
export const ANCHOR_CONSENT_TEXT =
  "Transparency anchoring publishes a small fingerprint of each enforcement " +
  "checkpoint to the public Sigstore Rekor transparency log. What is " +
  "published: a salted SHA-256 hash (64 hex characters), a signature over " +
  "it from a dedicated derived anchoring key, and that key's public half " +
  "(a pseudonym). What is NEVER published: checkpoint contents, enforcement " +
  "counts, policy data, rule details, audit-log data, fortress identifiers, " +
  "or any state content. Observers of the public log can see that some " +
  "pseudonymous party anchored at these times, and nothing else. This is " +
  "the only network transmission the transparency feature performs, and it " +
  "stays off unless you enable it. Anchoring makes the enforcement history " +
  "fork-evident and freshness-bounded: once anchored, even this machine " +
  "cannot quietly rewrite or withhold it.";

export class TransparencyAnchorError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TransparencyAnchorError";
  }
}

// ---- Config read / write ------------------------------------------------------

export type AnchorConfigState =
  | { status: "absent" }
  | { status: "disabled"; config: AnchorConfigData }
  | { status: "enabled"; config: AnchorConfigData };

interface AnchorKeyInput {
  storage: StorageBackend;
  masterKey: Uint8Array;
}

/**
 * Read and AUTHENTICATE the anchoring config. Absent means anchoring was
 * never configured (the default-off state). A config that fails MAC
 * authentication throws: it must not silently read as enabled OR disabled.
 */
export async function readAnchorConfig(
  input: AnchorKeyInput
): Promise<AnchorConfigState> {
  let raw: Uint8Array | null;
  try {
    raw = await input.storage.read("_meta", TRANSPARENCY_ANCHOR_CONFIG_META_KEY);
  } catch (err) {
    throw new TransparencyAnchorError(
      `anchoring config could not be read: ${errorMessage(err)}`
    );
  }
  if (!raw) return { status: "absent" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToString(raw));
  } catch {
    throw tamperError();
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    (parsed as Record<string, unknown>)[ANCHOR_CONFIG_MARKER] !== true
  ) {
    throw tamperError();
  }
  const envelope = parsed as Record<string, unknown>;
  const data = envelope.data;
  const mac = envelope.mac;
  if (!isAnchorConfigData(data) || typeof mac !== "string") {
    throw tamperError();
  }
  const macKey = derivePurposeKey(
    input.masterKey,
    TRANSPARENCY_ANCHOR_CONFIG_MAC_PURPOSE
  );
  try {
    let provided: Uint8Array;
    try {
      provided = fromBase64url(mac);
    } catch {
      throw tamperError();
    }
    if (!constantTimeEqual(provided, hmacSha256(macKey, anchorConfigMacInput(data)))) {
      throw tamperError();
    }
  } finally {
    macKey.fill(0);
  }
  return data.enabled
    ? { status: "enabled", config: data }
    : { status: "disabled", config: data };
}

function tamperError(): TransparencyAnchorError {
  return new TransparencyAnchorError(
    "anchoring config failed authentication (tampered, forged, or wrong key). " +
      "Refusing to treat it as either enabled or disabled; re-run " +
      "'sanctuary transparency anchor enable' or 'disable' to rewrite it."
  );
}

async function writeAnchorConfig(
  input: AnchorKeyInput,
  data: AnchorConfigData
): Promise<void> {
  const macKey = derivePurposeKey(
    input.masterKey,
    TRANSPARENCY_ANCHOR_CONFIG_MAC_PURPOSE
  );
  try {
    const envelope = {
      [ANCHOR_CONFIG_MARKER]: true,
      data,
      mac: toBase64url(hmacSha256(macKey, anchorConfigMacInput(data))),
    };
    await writeRecordDurable(
      input.storage,
      "_meta",
      TRANSPARENCY_ANCHOR_CONFIG_META_KEY,
      stringToBytes(JSON.stringify(envelope))
    );
  } finally {
    macKey.fill(0);
  }
}

export interface EnableAnchoringInput extends AnchorKeyInput {
  auditLog: AuditLog;
  fortressId: string;
  rekorUrl?: string;
  now?: () => Date;
}

/**
 * The RECOVERY read used only by the explicit operator verbs: a tampered
 * config is treated as absent so the operator's enable/disable command
 * rewrites it cleanly (the tamper error message promises exactly this).
 * Automatic paths (anchorCheckpoint) never use this; they refuse.
 */
async function readAnchorConfigForRewrite(
  input: AnchorKeyInput
): Promise<{ state: AnchorConfigState; recoveredFromTamper: boolean }> {
  try {
    return { state: await readAnchorConfig(input), recoveredFromTamper: false };
  } catch (err) {
    if (err instanceof TransparencyAnchorError) {
      return { state: { status: "absent" }, recoveredFromTamper: true };
    }
    throw err;
  }
}

/**
 * Record operator consent and switch anchoring ON. The commitment salt is
 * generated on first enable and preserved across disable/re-enable cycles
 * so previously published anchors remain verifiable. A config that fails
 * authentication is rewritten from scratch (fresh salt) under this
 * explicit operator action.
 */
export async function enableAnchoring(
  input: EnableAnchoringInput
): Promise<AnchorConfigData> {
  const { state: existing, recoveredFromTamper } =
    await readAnchorConfigForRewrite(input);
  const salt =
    existing.status === "absent"
      ? Buffer.from(randomBytes(32)).toString("hex")
      : existing.config.salt;
  const rekorUrl =
    input.rekorUrl ??
    (existing.status === "absent" ? DEFAULT_REKOR_URL : existing.config.rekor_url);
  validateRekorUrl(rekorUrl);
  const data: AnchorConfigData = {
    enabled: true,
    salt,
    rekor_url: rekorUrl,
    consent: {
      accepted_at: (input.now?.() ?? new Date()).toISOString(),
      text_sha256: consentTextSha256(ANCHOR_CONSENT_TEXT),
    },
  };
  await writeAnchorConfig(input, data);
  await input.auditLog.appendCritical({
    layer: "l2",
    operation: "transparency_anchoring_enabled",
    identity_id: input.fortressId,
    result: "success",
    details: {
      rekor_url: rekorUrl,
      consent_text_sha256: data.consent.text_sha256,
      consent_accepted_at: data.consent.accepted_at,
      ...(recoveredFromTamper ? { recovered_from_tampered_config: true } : {}),
    },
  });
  return data;
}

export interface DisableAnchoringInput extends AnchorKeyInput {
  auditLog: AuditLog;
  fortressId: string;
  now?: () => Date;
}

/**
 * Switch anchoring OFF (salt and consent history are preserved). A
 * tampered config is replaced by a clean disabled one (fresh salt) under
 * this explicit operator action.
 */
export async function disableAnchoring(
  input: DisableAnchoringInput
): Promise<AnchorConfigData> {
  const { state: existing, recoveredFromTamper } =
    await readAnchorConfigForRewrite(input);
  if (existing.status === "absent" && !recoveredFromTamper) {
    throw new TransparencyAnchorError(
      "anchoring was never enabled on this fortress (it is off by default)"
    );
  }
  const data: AnchorConfigData =
    existing.status === "absent"
      ? {
          enabled: false,
          salt: Buffer.from(randomBytes(32)).toString("hex"),
          rekor_url: DEFAULT_REKOR_URL,
          consent: {
            accepted_at: (input.now?.() ?? new Date()).toISOString(),
            text_sha256: consentTextSha256(ANCHOR_CONSENT_TEXT),
          },
        }
      : { ...existing.config, enabled: false };
  await writeAnchorConfig(input, data);
  await input.auditLog.appendCritical({
    layer: "l2",
    operation: "transparency_anchoring_disabled",
    identity_id: input.fortressId,
    result: "success",
    details: {
      rekor_url: data.rekor_url,
      ...(recoveredFromTamper ? { recovered_from_tampered_config: true } : {}),
    },
  });
  return data;
}

function validateRekorUrl(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new TransparencyAnchorError(`invalid Rekor URL: ${url}`);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new TransparencyAnchorError(
      `Rekor URL must be http(s), got ${parsed.protocol}`
    );
  }
}

// ---- Receipts -------------------------------------------------------------------

export function anchorReceiptStorageKey(counter: number): string {
  return `${TRANSPARENCY_ANCHOR_RECEIPT_PREFIX}${String(counter).padStart(20, "0")}`;
}

/** Read every persisted anchor receipt, sorted by counter ascending. */
export async function readAnchorReceipts(
  storage: StorageBackend
): Promise<AnchorReceipt[]> {
  let metas;
  try {
    metas = await storage.list(
      TRANSPARENCY_ANCHOR_NAMESPACE,
      TRANSPARENCY_ANCHOR_RECEIPT_PREFIX
    );
  } catch (err) {
    throw new TransparencyAnchorError(
      `anchor receipt store could not be listed: ${errorMessage(err)}`
    );
  }
  const receipts: AnchorReceipt[] = [];
  for (const meta of metas) {
    const raw = await storage.read(TRANSPARENCY_ANCHOR_NAMESPACE, meta.key);
    if (!raw) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(bytesToString(raw));
    } catch {
      throw new TransparencyAnchorError(
        `anchor receipt ${meta.key} is not valid JSON (store corrupted or tampered)`
      );
    }
    if (!isAnchorReceipt(parsed)) {
      throw new TransparencyAnchorError(
        `anchor receipt ${meta.key} is malformed (store corrupted or tampered)`
      );
    }
    receipts.push(parsed);
  }
  receipts.sort((a, b) => a.counter - b.counter);
  return receipts;
}

async function persistReceipt(
  storage: StorageBackend,
  receipt: AnchorReceipt
): Promise<void> {
  // A success receipt is immutable evidence; never let a later failure
  // (or a duplicate success) overwrite it.
  const key = anchorReceiptStorageKey(receipt.counter);
  const existingRaw = await storage.read(TRANSPARENCY_ANCHOR_NAMESPACE, key);
  if (existingRaw) {
    try {
      const existing = JSON.parse(bytesToString(existingRaw)) as unknown;
      if (isAnchorReceipt(existing) && existing.status === "anchored") {
        if (receipt.status === "anchored") return; // already anchored; keep first
        throw new TransparencyAnchorError(
          `refusing to overwrite the success receipt for checkpoint ${receipt.counter} with a failure record`
        );
      }
    } catch (err) {
      if (err instanceof TransparencyAnchorError) throw err;
      // Unparseable existing receipt: overwrite with the new evidence.
    }
  }
  await writeRecordDurable(
    storage,
    TRANSPARENCY_ANCHOR_NAMESPACE,
    key,
    stringToBytes(JSON.stringify(receipt))
  );
}

// ---- Anchoring a checkpoint -------------------------------------------------------

export interface AnchorCheckpointInput extends AnchorKeyInput {
  auditLog: AuditLog;
  record: EnforcementCheckpointRecord;
  /** Injected client (tests). Defaults to HttpRekorClient over config URL. */
  client?: RekorClient;
  /** Injected fetch for the default client (tests). */
  fetchFn?: FetchLike;
  now?: () => Date;
}

export type AnchorOutcome =
  | { status: "disabled" }
  | { status: "already_anchored"; receipt: AnchoredReceipt }
  | { status: "anchored"; receipt: AnchoredReceipt; duplicate: boolean }
  | { status: "failed"; receipt: FailedAnchorReceipt; error: string };

/**
 * Anchor one emitted checkpoint, honoring the opt-in config. Never throws
 * on transport failure (fail-loud contract: a failure outcome plus a
 * persisted failure receipt plus an appendCritical audit entry); DOES
 * throw on config tampering or storage failure.
 */
export async function anchorCheckpoint(
  input: AnchorCheckpointInput
): Promise<AnchorOutcome> {
  const state = await readAnchorConfig(input);
  if (state.status !== "enabled") return { status: "disabled" };
  const config = state.config;

  const counter = input.record.counter;
  const checkpointHash = computeCheckpointHash(checkpointPayloadOf(input.record));

  // Idempotence: a checkpoint that already carries a success receipt is
  // done; re-anchoring would only churn the public log.
  const existingRaw = await input.storage.read(
    TRANSPARENCY_ANCHOR_NAMESPACE,
    anchorReceiptStorageKey(counter)
  );
  if (existingRaw) {
    try {
      const existing = JSON.parse(bytesToString(existingRaw)) as unknown;
      if (isAnchorReceipt(existing) && existing.status === "anchored") {
        return { status: "already_anchored", receipt: existing };
      }
    } catch {
      // Fall through: a malformed receipt is replaced by a fresh attempt.
    }
  }

  const preimage = anchorCommitmentPreimage({
    saltHex: config.salt,
    counter,
    checkpointHash,
  });
  const digestHex = anchorCommitmentDigestHex(preimage);

  const client =
    input.client ??
    new HttpRekorClient({
      baseUrl: config.rekor_url,
      ...(input.fetchFn ? { fetchFn: input.fetchFn } : {}),
    });

  const base = {
    anchor_kind: "transparency-anchor-receipt" as const,
    schema_version: TRANSPARENCY_ANCHOR_SCHEMA_VERSION as 1,
    counter,
    checkpoint_hash: checkpointHash,
    commitment_digest: digestHex,
    rekor_url: client.baseUrl,
  };

  try {
    const key = deriveAnchorSigningKey(input.masterKey);
    let proposal;
    try {
      proposal = buildHashedRekordProposal({
        digestHex,
        signatureDer: signAnchorPreimage(key.privateKey, preimage),
        publicKeyPem: anchorPublicKeyPem(key.publicKey),
      });
    } finally {
      key.privateKey.fill(0);
    }
    const result = await client.submit(proposal);
    const receipt: AnchoredReceipt = {
      ...base,
      status: "anchored",
      anchored_at: (input.now?.() ?? new Date()).toISOString(),
      rekor: result.entry,
    };
    await persistReceipt(input.storage, receipt);
    await input.auditLog.appendCritical({
      layer: "l2",
      operation: "transparency_checkpoint_anchored",
      identity_id: input.record.fortress_id,
      result: "success",
      details: {
        counter,
        commitment_digest: digestHex,
        rekor_log_index: result.entry.log_index,
        rekor_uuid: result.entry.uuid,
        rekor_url: client.baseUrl,
        duplicate: result.duplicate,
      },
    });
    return { status: "anchored", receipt, duplicate: result.duplicate };
  } catch (err) {
    if (err instanceof TransparencyAnchorError) throw err;
    const message = errorMessage(err);
    const receipt: FailedAnchorReceipt = {
      ...base,
      status: "failed",
      failed_at: (input.now?.() ?? new Date()).toISOString(),
      error: message,
    };
    await persistReceipt(input.storage, receipt);
    await input.auditLog.appendCritical({
      layer: "l2",
      operation: "transparency_anchor_failed",
      identity_id: input.record.fortress_id,
      result: "failure",
      details: {
        counter,
        commitment_digest: digestHex,
        rekor_url: client.baseUrl,
        error: message,
      },
    });
    return { status: "failed", receipt, error: message };
  }
}

export interface AnchorPendingInput extends AnchorKeyInput {
  auditLog: AuditLog;
  client?: RekorClient;
  fetchFn?: FetchLike;
  now?: () => Date;
}

export interface AnchorPendingResult {
  outcomes: Array<{ counter: number; outcome: AnchorOutcome }>;
  anchored: number;
  already_anchored: number;
  failed: number;
}

/**
 * Catch-up pass for `sanctuary transparency anchor now`: anchor every
 * persisted checkpoint that does not yet carry a success receipt (e.g.
 * after a Rekor outage). Stops early when anchoring is disabled.
 */
export async function anchorPendingCheckpoints(
  input: AnchorPendingInput
): Promise<AnchorPendingResult | { status: "disabled" }> {
  const state = await readAnchorConfig(input);
  if (state.status !== "enabled") return { status: "disabled" };
  const checkpoints = await readPersistedCheckpoints(input.storage);
  const result: AnchorPendingResult = {
    outcomes: [],
    anchored: 0,
    already_anchored: 0,
    failed: 0,
  };
  for (const record of checkpoints) {
    const outcome = await anchorCheckpoint({ ...input, record });
    result.outcomes.push({ counter: record.counter, outcome });
    if (outcome.status === "anchored") result.anchored++;
    else if (outcome.status === "already_anchored") result.already_anchored++;
    else if (outcome.status === "failed") result.failed++;
  }
  return result;
}

// ---- Small helpers ----------------------------------------------------------------

async function writeRecordDurable(
  storage: StorageBackend,
  namespace: string,
  key: string,
  bytes: Uint8Array
): Promise<void> {
  const candidate = storage as Partial<FilesystemStorageCapabilities>;
  if (
    typeof candidate.namespacePath === "function" &&
    typeof candidate.writeDurable === "function"
  ) {
    await (candidate as FilesystemStorageCapabilities).writeDurable(
      namespace,
      key,
      bytes
    );
    return;
  }
  await storage.write(namespace, key, bytes);
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
