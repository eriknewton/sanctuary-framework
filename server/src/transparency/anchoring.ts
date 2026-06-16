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
import type { AuditLog } from "../operational/audit-log.js";
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
  TRANSPARENCY_ANCHORS_EXPORT_FORMAT,
  verifyAnchorEvidence,
  type ExportedAnchorReceipt,
  type TransparencyAnchorsExport,
} from "./anchor-verify.js";
import {
  checkpointPayloadOf,
  computeCheckpointHash,
  type EnforcementCheckpointRecord,
} from "./checkpoint.js";
import { readPersistedCheckpoints } from "./emitter.js";
import { isVerifierCheckpointRecord } from "./verify.js";
import {
  HttpRekorClient,
  RekorEntryNotFoundError,
  type FetchLike,
  type RekorClient,
} from "./rekor-client.js";

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
  /**
   * SSRF escape hatch (--allow-unsafe-rekor-url) for local/dev Rekor
   * instances. Must be passed explicitly at EVERY enable; it is never
   * inherited from a previous config. Recorded in the MAC'd config, the
   * enable audit entry, and `anchor status` output.
   */
  allowUnsafeRekorUrl?: boolean;
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
  // The unsafe override is NEVER inherited: each enable must state it
  // explicitly, so a previously-unsafe URL fails closed on a plain re-enable.
  const allowUnsafeUrl = input.allowUnsafeRekorUrl === true;
  validateRekorUrl(rekorUrl, allowUnsafeUrl);
  const data: AnchorConfigData = {
    enabled: true,
    salt,
    rekor_url: rekorUrl,
    allow_unsafe_url: allowUnsafeUrl,
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
      allow_unsafe_rekor_url: allowUnsafeUrl,
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
          allow_unsafe_url: false,
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

/**
 * SSRF guard for the operator-configurable Rekor URL. The configured URL
 * is an outbound POST target, so without validation it is an
 * operator-configurable request primitive against loopback services,
 * RFC1918/link-local hosts, and cloud metadata endpoints. The contract:
 *
 *   - https is required (a plaintext log URL invites on-path tampering
 *     AND downgrades the guard).
 *   - Hostnames that are IP LITERALS in loopback / private / link-local /
 *     CGNAT / reserved ranges are rejected, as are well-known metadata
 *     hostnames (169.254.169.254, metadata.google.internal, *.internal)
 *     and localhost names.
 *   - DELIBERATELY no DNS resolution here: resolving-then-checking is
 *     TOCTOU theater (the answer can change between validation and the
 *     POST). The contract is literal/range checks + https + the recorded
 *     unsafe flag; the residual (a hostile log operator's hostname
 *     rebinding to an internal address) is documented in
 *     docs/transparency-checkpoints.md.
 *   - Escape hatch for local/dev Rekor instances: allowUnsafe skips the
 *     https and address checks (NOT the http(s)-scheme check). It is only
 *     set by an explicit --allow-unsafe-rekor-url at enable time and is
 *     recorded in the MAC'd config, the audit log, and status output.
 *
 * Enforced fail-closed at config-set time (enable) AND re-checked on every
 * anchor attempt (`now`, emission, scheduler), so a config written by an
 * older build or copied from elsewhere cannot re-arm an unsafe URL.
 */
export function validateRekorUrl(url: string, allowUnsafe: boolean): void {
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
  if (allowUnsafe) return;
  if (parsed.protocol !== "https:") {
    throw new TransparencyAnchorError(
      `Rekor URL must use https, got ${parsed.protocol.slice(0, -1)}. ` +
        UNSAFE_HATCH_HINT
    );
  }
  // Trailing dots are stripped so absolute-FQDN spellings of blocked names
  // (e.g. "metadata.google.internal.") cannot dodge the checks.
  const hostname = parsed.hostname.toLowerCase().replace(/\.+$/, "");
  if (isBlockedRekorHostname(hostname)) {
    throw new TransparencyAnchorError(
      `Rekor URL host ${hostname} is a loopback, private, link-local, reserved, or metadata address; refusing (SSRF guard). ` +
        UNSAFE_HATCH_HINT
    );
  }
}

const UNSAFE_HATCH_HINT =
  "For a local/dev Rekor instance, re-run enable with --allow-unsafe-rekor-url " +
  "(the override is recorded in the MAC'd config, the audit log, and 'anchor status').";

/** Well-known metadata / local hostnames blocked by the default guard. */
const BLOCKED_REKOR_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
  "metadata.goog",
]);

function isBlockedRekorHostname(hostname: string): boolean {
  if (
    BLOCKED_REKOR_HOSTNAMES.has(hostname) ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".internal")
  ) {
    return true;
  }
  // WHATWG URL parsing already normalized decimal/octal/hex IPv4 forms
  // (e.g. http://0x7f000001) to dotted-quad, so a literal check on the
  // parsed hostname covers the encoded variants.
  const ipv4 = parseIpv4Literal(hostname);
  if (ipv4) return isBlockedIpv4(ipv4);
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    return isBlockedIpv6(hostname.slice(1, -1));
  }
  return false;
}

function parseIpv4Literal(hostname: string): number[] | null {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(hostname);
  if (!match) return null;
  const octets = match.slice(1).map(Number);
  return octets.every((octet) => octet <= 255) ? octets : null;
}

function isBlockedIpv4(octets: number[]): boolean {
  const [a, b] = octets as [number, number, number, number];
  return (
    a === 0 || // 0.0.0.0/8 "this network"
    a === 10 || // RFC1918
    a === 127 || // loopback
    (a === 100 && b >= 64 && b <= 127) || // 100.64.0.0/10 CGNAT
    (a === 169 && b === 254) || // link-local, incl. 169.254.169.254 metadata
    (a === 172 && b >= 16 && b <= 31) || // RFC1918
    (a === 192 && b === 0) || // 192.0.0.0/24 IETF + 192.0.2.0/24 TEST-NET-1
    (a === 192 && b === 88 && octets[2] === 99) || // 192.88.99.0/24 6to4 relay anycast
    (a === 192 && b === 168) || // RFC1918
    (a === 198 && (b === 18 || b === 19)) || // 198.18.0.0/15 benchmarking
    (a === 198 && b === 51 && octets[2] === 100) || // 198.51.100.0/24 TEST-NET-2
    (a === 203 && b === 0 && octets[2] === 113) || // 203.0.113.0/24 TEST-NET-3
    a >= 224 // multicast + 240/4 reserved + broadcast
  );
}

function isBlockedIpv6(host: string): boolean {
  const h = host.toLowerCase();
  if (h === "::" || h === "::1") return true; // unspecified / loopback
  if (/^fe[89ab]/.test(h)) return true; // fe80::/10 link-local
  if (/^f[cd]/.test(h)) return true; // fc00::/7 unique-local
  if (h.startsWith("2001:db8:") || h === "2001:db8") return true; // 2001:db8::/32 documentation
  if (h.startsWith("ff")) return true; // ff00::/8 multicast
  if (h.startsWith("::ffff:")) {
    // IPv4-mapped: recover the embedded IPv4 and apply the IPv4 ranges.
    // WHATWG URL serializes the tail as two hex groups (::ffff:7f00:1).
    const tail = h.slice("::ffff:".length);
    const dotted = parseIpv4Literal(tail);
    if (dotted) return isBlockedIpv4(dotted);
    const groups = tail.split(":");
    if (groups.length === 2 && groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) {
      const hi = Number.parseInt(groups[0]!, 16);
      const lo = Number.parseInt(groups[1]!, 16);
      return isBlockedIpv4([hi >> 8, hi & 0xff, lo >> 8, lo & 0xff]);
    }
    return true; // unparseable mapped form: fail closed
  }
  return false;
}

// ---- Receipts -------------------------------------------------------------------

export function anchorReceiptStorageKey(counter: number): string {
  return `${TRANSPARENCY_ANCHOR_RECEIPT_PREFIX}${String(counter).padStart(20, "0")}`;
}

/**
 * Whether ANY anchor receipt is present on disk (anti-rollback Stage 2 FIX 1).
 * A cheap listing that does NOT parse the receipts: it answers only
 * "present vs genuinely absent". A present-but-MALFORMED store is reported as
 * present (true) here — the malformed-store freeze is the caller's job via the
 * parsing path (computeHighestVerifiedAnchoredCounter / readAnchorReceipts),
 * which fails toward freeze. An unlistable namespace is treated as PRESENT
 * (true): we cannot prove the store is empty, so Stage 2 should apply (fail
 * toward running the check, never toward skipping it). A genuinely empty/absent
 * namespace returns false → Stage 2 does not apply on that basis alone.
 */
export async function anchorReceiptsPresentOnDisk(
  storage: StorageBackend
): Promise<boolean> {
  try {
    const metas = await storage.list(
      TRANSPARENCY_ANCHOR_NAMESPACE,
      TRANSPARENCY_ANCHOR_RECEIPT_PREFIX
    );
    return metas.length > 0;
  } catch {
    // Cannot list the store → cannot prove it is empty → treat as present so
    // Stage 2 still applies (the parsing path then fails toward freeze).
    return true;
  }
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

  // Re-run the SSRF guard on every anchor attempt (fail closed): a config
  // written by an older build, or copied in from elsewhere, must not
  // re-arm an unsafe URL just because it authenticates. The recorded
  // allow_unsafe_url override is honored because it sits under the same
  // MAC and was set by an explicit operator action.
  validateRekorUrl(config.rekor_url, config.allow_unsafe_url);

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
  // Fail closed before any work, even with zero pending checkpoints
  // (anchorCheckpoint re-checks per attempt as well).
  validateRekorUrl(state.config.rekor_url, state.config.allow_unsafe_url);
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

// ---- Anchors evidence export (PR-3 auditor handoff) -------------------------------

export interface BuildAnchorsExportInput extends AnchorKeyInput {
  fortressId: string;
  now?: () => Date;
}

/**
 * Build the SANCTUARY_TRANSPARENCY_ANCHORS_V1 evidence file an auditor
 * needs to verify anchors (`verify-transparency --check-anchors`). It is
 * assembled ENTIRELY from local state: the MAC-authenticated config (salt,
 * log URL), the derived anchoring public key, and the local receipts.
 * Nothing here performs network I/O, and the salt never travels to the
 * log; it travels only inside this file, when the operator deliberately
 * hands it to an auditor. Handing the file out links the pseudonymous
 * public anchors to this fortress's checkpoint history for the recipient;
 * that is its purpose, and the CLI says so on export.
 *
 * Works with anchoring currently DISABLED too (the salt and receipts are
 * preserved across disable), so historical anchors stay auditable.
 */
export async function buildAnchorsExport(
  input: BuildAnchorsExportInput
): Promise<TransparencyAnchorsExport> {
  const state = await readAnchorConfig(input);
  if (state.status === "absent") {
    throw new TransparencyAnchorError(
      "anchoring was never enabled on this fortress; there is no anchor evidence to export"
    );
  }
  const receipts = await readAnchorReceipts(input.storage);
  const key = deriveAnchorSigningKey(input.masterKey);
  let publicKeyPem: string;
  try {
    publicKeyPem = anchorPublicKeyPem(key.publicKey);
  } finally {
    key.privateKey.fill(0);
  }
  return {
    format: TRANSPARENCY_ANCHORS_EXPORT_FORMAT,
    exported_at: (input.now?.() ?? new Date()).toISOString(),
    fortress_id: input.fortressId,
    salt: state.config.salt,
    anchor_public_key_pem: publicKeyPem,
    rekor_url: state.config.rekor_url,
    receipts,
  };
}

// ---- Highest externally-anchored counter (anti-rollback Stage 2) ------------------

/**
 * The result of resolving the highest counter that is BOTH locally present
 * AND cryptographically tied to an external Rekor anchor, offline.
 */
export interface HighestAnchoredCounterResult {
  /**
   * Highest checkpoint counter whose local anchor receipt passes every
   * OFFLINE anchor check (commitment binding to the bundle's checkpoint,
   * entry binding, RFC 6962 inclusion arithmetic). 0 when nothing is
   * verifiably anchored yet (transparency on but no anchor confirmed) — a
   * clean state, NOT suspicious.
   */
  highestAnchoredCounter: number;
  /**
   * True when an anchored receipt was present but did NOT pass its offline
   * checks (tampered receipt, commitment mismatch, malformed entry/proof,
   * or an anchor for a divergent checkpoint history). Forces the FREEZE
   * direction in Stage 2: an unverifiable anchor with transparency on must
   * never silently read as "no external witness".
   */
  unverifiableAnchorPresent: boolean;
  /** Number of anchored receipts that verified (verified or consistent). */
  verifiedAnchorCount: number;
  /** Operator-facing notes (never key material). */
  notes: string[];
}

/**
 * Anti-rollback Stage 2 witness resolver: compute the HIGHEST EXTERNALLY-
 * ANCHORED COUNTER from the fortress's own locally-stored anchor receipts,
 * verified OFFLINE against the local checkpoint store.
 *
 * The external Rekor log is outside the attacker's disk, so the highest
 * counter the fortress anchored there is a freshness witness a full-snapshot
 * rollback cannot roll back. This resolves what that counter is using only
 * local evidence (the MAC-authenticated config salt, the master-derived
 * anchoring public key, and the local receipts) cross-checked against the
 * local persisted checkpoints — the SAME offline arithmetic the auditor-side
 * `verify-transparency --check-anchors` runs (verifyAnchorEvidence), so the
 * fail-direction matches: a receipt that does not bind to a real local
 * checkpoint is unverifiable, never a silent witness.
 *
 * NO NETWORK: this never queries the log. The receipt-embedded entry body +
 * inclusion proof carry everything the offline checks need. A receipt that
 * is "consistent" (all offline checks pass, no pinned log key) counts as an
 * external witness for the floor comparison — its commitment is bound to a
 * real local checkpoint counter and a real Rekor leaf, which is exactly the
 * witness the floor must not regress below. (Full "verified" status would
 * additionally require a pinned log key; the floor comparison does not need
 * log-attested time, only that the counter was anchored.)
 */
export async function computeHighestVerifiedAnchoredCounter(
  input: AnchorKeyInput & { fortressId: string }
): Promise<HighestAnchoredCounterResult> {
  const records = (await readPersistedCheckpoints(input.storage)).filter(
    isVerifierCheckpointRecord
  );
  const anchorsDoc = await buildAnchorsExport(input);
  const result = verifyAnchorEvidence(records, anchorsDoc);
  let highestAnchoredCounter = 0;
  let verifiedAnchorCount = 0;
  let unverifiableAnchorPresent = false;
  const notes: string[] = [];
  for (const status of result.coverage.statuses) {
    if (status.status === "verified" || status.status === "consistent") {
      verifiedAnchorCount++;
      if (status.counter > highestAnchoredCounter) {
        highestAnchoredCounter = status.counter;
      }
    } else if (status.status === "invalid") {
      unverifiableAnchorPresent = true;
      notes.push(
        `anchor receipt for checkpoint ${status.counter} did not pass offline ` +
          `verification (${status.detail}); cannot trust it as an external witness`
      );
    }
    // "unverified" (receipt lacks an embedded body/proof) and "unanchored"
    // (no receipt for that checkpoint) are NOT failures: a fortress simply
    // has not anchored every checkpoint. They never lower the floor and
    // never force freeze on their own.
  }
  // A receipt that names a counter BEYOND the local checkpoint bundle is the
  // withheld-suffix signature (verifyAnchorEvidence surfaces it as an
  // anchor_beyond_bundle finding): the fortress anchored a checkpoint it no
  // longer holds on disk — exactly a rolled-back checkpoint store.
  for (const finding of result.findings) {
    if (finding.kind === "anchor_beyond_bundle") {
      unverifiableAnchorPresent = true;
      if (typeof finding.counter === "number" && finding.counter > highestAnchoredCounter) {
        highestAnchoredCounter = finding.counter;
      }
      notes.push(
        `an anchor proves checkpoint ${finding.counter ?? "?"} was externally ` +
          "anchored, but the local checkpoint store does not contain it: the " +
          "newest checkpoints appear to have been rolled back off disk"
      );
    }
  }
  return {
    highestAnchoredCounter,
    unverifiableAnchorPresent,
    verifiedAnchorCount,
    notes,
  };
}

/** Outcome of one live entry fetch in `--fetch-anchors` mode. */
export type AnchorEntryFetchOutcome =
  | { counter: number; status: "fetched"; entry: import("./anchor.js").RekorEntryRef }
  | { counter: number; status: "not_found"; uuid: string; message: string }
  | { counter: number; status: "unreachable"; message: string };

/**
 * Fetch fresh entry material from the log for every anchored receipt
 * (`verify-transparency --check-anchors --fetch-anchors`). The caller
 * validates the log URL with validateRekorUrl BEFORE constructing the
 * client (same SSRF posture as anchoring itself). Outcomes are explicit:
 * "not_found" is verification-grade evidence (the log denies the entry);
 * "unreachable" is an outage the auditor can retry, reported, never
 * silently treated as either verified or refuted.
 */
export async function fetchAnchorEntries(input: {
  receipts: ExportedAnchorReceipt[];
  client: RekorClient;
}): Promise<AnchorEntryFetchOutcome[]> {
  const outcomes: AnchorEntryFetchOutcome[] = [];
  for (const receipt of input.receipts) {
    if (receipt.status !== "anchored") continue;
    try {
      const entry = await input.client.fetchEntry(receipt.rekor.uuid);
      outcomes.push({ counter: receipt.counter, status: "fetched", entry });
    } catch (err) {
      if (err instanceof RekorEntryNotFoundError) {
        outcomes.push({
          counter: receipt.counter,
          status: "not_found",
          uuid: receipt.rekor.uuid,
          message: err.message,
        });
      } else {
        outcomes.push({
          counter: receipt.counter,
          status: "unreachable",
          message: err instanceof Error ? err.message : String(err),
        });
      }
    }
  }
  return outcomes;
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
