/**
 * Sanctuary WP-V1.x-RECOGNITION-LAYER Path C primary: did:web foundation.
 *
 * Closes Principle 5 (Recognition + Portability) recognition arm via
 * the smallest-buildable surface against the largest existing operator-
 * recognition substrate: the web's DNS + TLS trust chain.
 *
 * Foundation build ships three pure capabilities:
 *
 *   1. issueDidWeb  - generate a W3C-DID-Core-conformant did:web
 *      identifier + DID Document bound to a Sanctuary fortress's
 *      existing Ed25519 public key. No outbound; pure construction.
 *
 *   2. resolveDidWeb - HTTPS fetch + JSON parse + verificationMethod
 *      sanity check for a peer-presented did:web identifier. Outbound
 *      HTTPS by definition; opt-in load-bearing via the caller-supplied
 *      allowed_hosts allowlist. Empty allowlist means resolution
 *      refuses to leave the fortress, preserving no-outbound-by-default.
 *
 *   3. publishDidWebDocument - return the JSON artifact bytes + the
 *      publication URL the operator must serve from their own HTTPS
 *      authority host. Sanctuary does not operate the HTTPS server;
 *      it generates the artifact and tells the operator where to put
 *      it. v1.x+ may add Sanctuary-managed publish via dashboard.
 *
 * Castle-walking discipline:
 *
 *   - Issuance is offline: no network surface. A fortress with no
 *     authority_host configured never gets a did:web identifier and
 *     never reaches this module.
 *   - Resolution is opt-in: callers must thread an `allowed_hosts`
 *     allowlist; an empty allowlist returns `host_not_allowed`
 *     synchronously without ever opening a socket. The operator's
 *     existing Castle Wall egress filter handles the kernel-level
 *     enforcement of the same allowlist; this module is the
 *     application-level coordinator.
 *   - Publication is a pure function: returns artifact bytes and a
 *     target URL; the operator publishes via their own infrastructure.
 *
 * DID Web spec (https://w3c-ccg.github.io/did-method-web/):
 *
 *   did:web:<authority-host>                                → https://<host>/.well-known/did.json
 *   did:web:<authority-host>:fortress:<fid>:agent:<alabel>  → https://<host>/fortress/<fid>/agent/<alabel>/did.json
 *
 * verificationMethod uses JsonWebKey2020 + Ed25519 OKP JWK. This
 * keeps the module dependency-light (no base58btc needed; the
 * existing toBase64url helper covers the JWK `x` field).
 */

import { lookup } from "node:dns/promises";
import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { join } from "node:path";

import { sha256 } from "@noble/hashes/sha256";
import { ed25519 } from "@noble/curves/ed25519";

import { fromBase64url, toBase64url, stringToBytes } from "../core/encoding.js";
import { hashToString } from "../core/hashing.js";
import { generateKeypair } from "../core/identity.js";

// ── Public types ─────────────────────────────────────────────────────

export interface VerificationMethod {
  id: string;
  type: "JsonWebKey2020";
  controller: string;
  publicKeyJwk: {
    kty: "OKP";
    crv: "Ed25519";
    x: string;
  };
  /**
   * Build 4 rotation metadata. DID Core allows additional verification
   * method properties; resolvers use these timestamps to select the key
   * that was valid for a historical assertion without changing the
   * stable did:web identifier.
   */
  status?: "active" | "previous" | "revoked";
  valid_from?: string;
  valid_until?: string;
  drop_after?: string;
  rotation_reason?: DidWebRotationReason;
}

export interface DidDocument {
  "@context": string[];
  id: string;
  verificationMethod: VerificationMethod[];
  authentication: string[];
  assertionMethod: string[];
}

export interface DidWebIdentifier {
  /** The did:web URI string. */
  did: string;
  /** W3C DID Document for the identifier. */
  did_document: DidDocument;
  /** The Ed25519 public key bound to this identifier. */
  public_key: Uint8Array;
  /** ISO 8601 timestamp at issuance. */
  created_at: string;
  /** The HTTPS authority host that publishes the document. */
  authority_host: string;
  /** Fortress id this identifier belongs to (always present). */
  fortress_id: string;
  /** Optional agent label for agent-scoped identifiers. */
  agent_label?: string;
}

export type DidWebRotationReason = "periodic" | "compromised" | "manual";

export interface RotationOptions {
  reason: DidWebRotationReason;
  /**
   * Number of days the old verification method remains in the DID
   * Document for historical verification. Defaults to 90.
   */
  preserve_old_key_for?: number;
  /** Optional deterministic clock for tests. */
  now?: () => Date;
  /**
   * Optional caller-supplied new public key. The CLI supplies this after
   * rotating the encrypted fortress identity so the DID Document and the
   * local signing identity stay in lock-step. Pure tests can omit it and
   * let this module generate the public side of a fresh Ed25519 keypair.
   */
  new_public_key?: Uint8Array;
}

export interface RotationResult {
  did: string;
  old_verification_method_id: string;
  new_verification_method_id: string;
  old_public_key_b64u: string;
  new_public_key_b64u: string;
  new_did_document: DidDocument;
  rotated_at: string;
  rotation_reason: DidWebRotationReason;
  preserve_old_key_for: number;
}

export interface DidWebRotationHistoryEntry {
  rotated_at: string;
  reason: DidWebRotationReason;
  old_verification_method_id: string;
  new_verification_method_id: string;
  old_public_key_b64u: string;
  new_public_key_b64u: string;
  preserve_old_key_for: number;
}

export interface DropExpiredDidWebKeysResult {
  did_document: DidDocument;
  dropped: Array<{
    verification_method_id: string;
    public_key_b64u: string;
    dropped_at: string;
  }>;
}

export interface DidWebHealthSnapshot {
  configured: boolean;
  identifier?: string;
  authority_host?: string;
  current_verification_method_id?: string;
  last_rotation?: DidWebRotationHistoryEntry;
  key_history: DidWebRotationHistoryEntry[];
  recommended_periodic_days: number;
  days_until_recommended_rotation?: number;
}

export interface IssueDidWebOpts {
  fortress_id: string;
  authority_host: string;
  agent_label?: string;
  /** Operator's fortress Ed25519 public key (32 bytes). */
  public_key: Uint8Array;
  /** Wall-clock provider for deterministic tests. */
  now?: () => Date;
}

export interface ResolveDidWebOpts {
  /**
   * Hosts the operator has explicitly allowed for outbound did:web
   * resolution. Empty array means resolution is disabled and the
   * call returns synchronously with `host_not_allowed`. This is
   * the load-bearing opt-in surface for the no-outbound-by-default
   * rule; the kernel-level Castle Wall egress filter enforces the
   * same allowlist independently.
   */
  allowed_hosts: string[];
  /** Resolution timeout. Defaults to 5000ms. */
  timeout_ms?: number;
  /**
   * Optional fetcher override for tests. Defaults to globalThis.fetch.
   * Production callers should leave this undefined.
   */
  fetcher?: (url: string, init?: { signal?: AbortSignal }) => Promise<{
    ok: boolean;
    status: number;
    headers?: { get(name: string): string | null };
    body?: ReadableStream<Uint8Array> | null;
    text?: () => Promise<string>;
    json?: () => Promise<unknown>;
  }>;
  /**
   * Optional expected Ed25519 public key. When set, the resolved
   * document's verificationMethod[0].publicKeyJwk.x must match
   * (base64url-encoded). Mismatch returns `signature_mismatch`.
   */
  expected_public_key?: Uint8Array;
  /**
   * Signing time of the assertion being checked. When set, resolution
   * accepts a matching historical key only if its rotation metadata
   * covers this time.
   */
  assertion_time?: string | Date;
}

export type ResolveResult =
  | {
      ok: true;
      did_document: DidDocument;
      url: string;
      verification_methods: VerificationMethod[];
      selected_verification_method_id?: string;
      historical_verification_used?: boolean;
    }
  | {
      ok: false;
      failure:
        | "host_not_allowed"
        | "fetch_failed"
        | "timeout"
        | "not_found"
        | "invalid_json"
        | "signature_mismatch";
      message: string;
      url: string;
    };

export interface PublishDidWebOpts {
  /**
   * Override the canonical publication path. By default the
   * spec-mandated path is computed from the identifier shape; a
   * caller may override only with operator awareness that
   * non-canonical paths will not resolve via standard did:web
   * resolvers.
   */
  publish_path?: string;
}

export interface PublishedArtifact {
  /** Full HTTPS URL the operator must serve at. */
  url: string;
  /** Path component (the operator hosts at this path on their host). */
  publish_path: string;
  /** Canonical JSON serialization of the DID Document. */
  artifact: string;
  /** Hex-encoded SHA-256 of the artifact bytes. */
  sha256: string;
}

// ── Constants ────────────────────────────────────────────────────────

export const DID_WEB_AUDIT_OPS = {
  ISSUED: "did_web_issued",
  RESOLVED: "did_web_resolved",
  PUBLISHED: "did_web_published",
  KEY_ROTATED: "did_web_key_rotated",
  OLD_KEY_DROPPED: "did_web_old_key_dropped",
  HISTORICAL_VERIFICATION_USED: "did_web_historical_verification_used",
} as const;

export type DidWebAuditOp =
  (typeof DID_WEB_AUDIT_OPS)[keyof typeof DID_WEB_AUDIT_OPS];

/** W3C DID Core + DID Web v0.3 + ed25519-2020 context URIs. */
const DID_CONTEXT = [
  "https://www.w3.org/ns/did/v1",
  "https://w3id.org/security/suites/jws-2020/v1",
] as const;

const DEFAULT_TIMEOUT_MS = 5000;
const MAX_DID_DOC_BYTES = 256 * 1024;
const DEFAULT_PRESERVE_OLD_KEY_DAYS = 90;
const DEFAULT_RECOMMENDED_PERIODIC_DAYS = 365;
const MS_PER_DAY = 24 * 60 * 60 * 1000;

const HOST_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;
const FORTRESS_LABEL_RE = /^[a-zA-Z0-9_-]{1,64}$/;
const AGENT_LABEL_RE = /^[a-zA-Z0-9_-]{1,64}$/;
const METADATA_AUTHORITY_HOSTS = new Set([
  "metadata.google.internal",
  "metadata.goog",
]);

// ── Issuance ─────────────────────────────────────────────────────────

export async function issueDidWeb(
  opts: IssueDidWebOpts,
): Promise<DidWebIdentifier> {
  if (!opts.authority_host || !HOST_RE.test(opts.authority_host)) {
    throw new Error(
      `did-web: authority_host '${opts.authority_host}' is not a valid DNS host`,
    );
  }
  if (!FORTRESS_LABEL_RE.test(opts.fortress_id)) {
    throw new Error(
      `did-web: fortress_id '${opts.fortress_id}' is not a valid label`,
    );
  }
  if (opts.agent_label !== undefined && !AGENT_LABEL_RE.test(opts.agent_label)) {
    throw new Error(
      `did-web: agent_label '${opts.agent_label}' is not a valid label`,
    );
  }
  if (opts.public_key.length !== 32) {
    throw new Error(
      `did-web: public_key must be exactly 32 bytes (Ed25519), got ${opts.public_key.length}`,
    );
  }

  const now = (opts.now ?? (() => new Date()))();
  const createdAt = now.toISOString();
  const did = buildDid(opts);
  const verificationMethodId = `${did}#key-1`;
  const verificationMethod: VerificationMethod = {
    id: verificationMethodId,
    type: "JsonWebKey2020",
    controller: did,
    publicKeyJwk: {
      kty: "OKP",
      crv: "Ed25519",
      x: toBase64url(opts.public_key),
    },
    status: "active",
    valid_from: createdAt,
  };
  const didDocument: DidDocument = {
    "@context": [...DID_CONTEXT],
    id: did,
    verificationMethod: [verificationMethod],
    authentication: [verificationMethodId],
    assertionMethod: [verificationMethodId],
  };

  return {
    did,
    did_document: didDocument,
    public_key: opts.public_key,
    created_at: createdAt,
    authority_host: opts.authority_host,
    fortress_id: opts.fortress_id,
    ...(opts.agent_label !== undefined ? { agent_label: opts.agent_label } : {}),
  };
}

// ── Publication ──────────────────────────────────────────────────────

export function publishDidWebDocument(
  identifier: DidWebIdentifier,
  opts: PublishDidWebOpts = {},
): PublishedArtifact {
  const path = opts.publish_path ?? canonicalPublishPath(identifier);
  const artifact = canonicalSerializeDidDocument(identifier.did_document);
  const digest = sha256(stringToBytes(artifact));
  const url = `https://${identifier.authority_host}${path}`;
  return {
    url,
    publish_path: path,
    artifact,
    sha256: hashToString(digest),
  };
}

// ── Key rotation ──────────────────────────────────────────────────────

export async function rotateDidWebKey(
  identifier: DidWebIdentifier,
  opts: RotationOptions,
): Promise<RotationResult> {
  const preserveDays = opts.preserve_old_key_for ?? DEFAULT_PRESERVE_OLD_KEY_DAYS;
  if (!Number.isFinite(preserveDays) || preserveDays < 0) {
    throw new Error("did-web: preserve_old_key_for must be a non-negative number of days");
  }
  const rotatedAt = (opts.now ?? (() => new Date()))().toISOString();
  const activeMethodId =
    identifier.did_document.authentication[0] ??
    identifier.did_document.assertionMethod[0] ??
    identifier.did_document.verificationMethod.at(-1)?.id;
  const activeMethod = identifier.did_document.verificationMethod.find(
    (vm) => vm.id === activeMethodId,
  );
  if (!activeMethod) {
    throw new Error("did-web: cannot rotate identifier without an active verification method");
  }

  const generated = opts.new_public_key ? undefined : generateKeypair();
  const newPublicKey = opts.new_public_key ?? generated!.publicKey;
  generated?.privateKey.fill(0);
  if (newPublicKey.length !== 32) {
    throw new Error(
      `did-web: new public key must be exactly 32 bytes (Ed25519), got ${newPublicKey.length}`,
    );
  }

  const newMethodId = nextVerificationMethodId(identifier.did, identifier.did_document);
  const dropAfter = addDaysIso(rotatedAt, preserveDays);
  const oldStatus = opts.reason === "compromised" ? "revoked" : "previous";
  const oldValidUntil =
    opts.reason === "compromised" ? rotatedAt : addDaysIso(rotatedAt, preserveDays);

  const demotedOld: VerificationMethod = {
    ...activeMethod,
    status: oldStatus,
    valid_from: activeMethod.valid_from ?? identifier.created_at,
    valid_until: oldValidUntil,
    drop_after: dropAfter,
    rotation_reason: opts.reason,
  };
  const newMethod: VerificationMethod = {
    id: newMethodId,
    type: "JsonWebKey2020",
    controller: identifier.did,
    publicKeyJwk: {
      kty: "OKP",
      crv: "Ed25519",
      x: toBase64url(newPublicKey),
    },
    status: "active",
    valid_from: rotatedAt,
  };
  const verificationMethod = identifier.did_document.verificationMethod.map(
    (vm) => (vm.id === activeMethod.id ? demotedOld : vm),
  );
  verificationMethod.push(newMethod);

  const newDidDocument: DidDocument = {
    ...identifier.did_document,
    verificationMethod,
    authentication: [newMethodId],
    assertionMethod: [newMethodId],
  };

  return {
    did: identifier.did,
    old_verification_method_id: activeMethod.id,
    new_verification_method_id: newMethodId,
    old_public_key_b64u: activeMethod.publicKeyJwk.x,
    new_public_key_b64u: newMethod.publicKeyJwk.x,
    new_did_document: newDidDocument,
    rotated_at: rotatedAt,
    rotation_reason: opts.reason,
    preserve_old_key_for: preserveDays,
  };
}

export function dropExpiredDidWebKeys(
  identifier: DidWebIdentifier,
  opts: { now?: () => Date } = {},
): DropExpiredDidWebKeysResult {
  const nowMs = (opts.now ?? (() => new Date()))().getTime();
  const activeIds = new Set([
    ...identifier.did_document.authentication,
    ...identifier.did_document.assertionMethod,
  ]);
  const dropped: DropExpiredDidWebKeysResult["dropped"] = [];
  const verificationMethod = identifier.did_document.verificationMethod.filter((vm) => {
    if (activeIds.has(vm.id)) return true;
    if (!vm.drop_after) return true;
    const dropAt = Date.parse(vm.drop_after);
    if (Number.isNaN(dropAt) || dropAt > nowMs) return true;
    dropped.push({
      verification_method_id: vm.id,
      public_key_b64u: vm.publicKeyJwk.x,
      dropped_at: new Date(nowMs).toISOString(),
    });
    return false;
  });

  return {
    did_document: {
      ...identifier.did_document,
      verificationMethod,
    },
    dropped,
  };
}

// ── Resolution ───────────────────────────────────────────────────────

export async function resolveDidWeb(
  did: string,
  opts: ResolveDidWebOpts,
): Promise<ResolveResult> {
  const parsed = parseDidWeb(did);
  const url = didToUrl(parsed);
  const unsafeHost = unsafeAuthorityHostReason(parsed.authority_host);
  if (unsafeHost !== undefined) {
    return {
      ok: false,
      failure: "host_not_allowed",
      message: `did-web: authority_host '${parsed.authority_host}' is not allowed for resolution (${unsafeHost})`,
      url,
    };
  }

  if (!opts.allowed_hosts.includes(parsed.authority_host)) {
    return {
      ok: false,
      failure: "host_not_allowed",
      message: `did-web: authority_host '${parsed.authority_host}' is not in the operator's allowed_hosts allowlist; resolution refused (no-outbound-by-default)`,
      url,
    };
  }

  if (opts.fetcher === undefined) {
    const resolvedHostFailure = await resolvedHostNotPublicReason(parsed.authority_host);
    if (resolvedHostFailure !== undefined) {
      return {
        ok: false,
        failure: "host_not_allowed",
        message: `did-web: authority_host '${parsed.authority_host}' is not allowed for resolution (${resolvedHostFailure})`,
        url,
      };
    }
  }

  const timeoutMs = opts.timeout_ms ?? DEFAULT_TIMEOUT_MS;
  const fetcher = opts.fetcher ?? defaultFetcher;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let response: {
    ok: boolean;
    status: number;
    headers?: { get(name: string): string | null };
    body?: ReadableStream<Uint8Array> | null;
    text?: () => Promise<string>;
    json?: () => Promise<unknown>;
  };
  try {
    response = await fetcher(url, { signal: controller.signal });
  } catch (err) {
    clearTimeout(timer);
    const message = err instanceof Error ? err.message : String(err);
    if (controller.signal.aborted) {
      return {
        ok: false,
        failure: "timeout",
        message: `did-web: resolution exceeded ${timeoutMs}ms`,
        url,
      };
    }
    return {
      ok: false,
      failure: "fetch_failed",
      message: `did-web: fetch error: ${message}`,
      url,
    };
  }
  clearTimeout(timer);

  if (response.status === 404) {
    return {
      ok: false,
      failure: "not_found",
      message: `did-web: 404 from authority host`,
      url,
    };
  }
  if (!response.ok) {
    return {
      ok: false,
      failure: "fetch_failed",
      message: `did-web: authority host returned ${response.status}`,
      url,
    };
  }

  let body: unknown;
  try {
    body = await readCappedJsonResponse(response);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      failure: "invalid_json",
      message: `did-web: invalid JSON: ${message}`,
      url,
    };
  }

  if (!isDidDocument(body, did)) {
    return {
      ok: false,
      failure: "invalid_json",
      message: `did-web: response body is not a valid DID Document for ${did}`,
      url,
    };
  }

  if (opts.expected_public_key !== undefined) {
    const expectedX = toBase64url(opts.expected_public_key);
    const selected = selectVerificationMethod(
      body,
      expectedX,
      opts.assertion_time,
    );
    if (!selected) {
      return {
        ok: false,
        failure: "signature_mismatch",
        message: `did-web: verificationMethod public key does not match expected key`,
        url,
      };
    }
    return {
      ok: true,
      did_document: body,
      url,
      verification_methods: body.verificationMethod,
      selected_verification_method_id: selected.id,
      historical_verification_used:
        selected.status === "previous" || selected.status === "revoked",
    };
  }

  return { ok: true, did_document: body, url, verification_methods: body.verificationMethod };
}

// ── Helpers ──────────────────────────────────────────────────────────

interface ParsedDidWeb {
  authority_host: string;
  fortress_id?: string;
  agent_label?: string;
}

export function parseDidWeb(did: string): ParsedDidWeb {
  if (!did.startsWith("did:web:")) {
    throw new Error(`did-web: '${did}' is not a did:web identifier`);
  }
  const rest = did.slice("did:web:".length);
  // Per spec, the colon-delimited path segments after the host are
  // decoded into URL path segments. Sanctuary's shape is either
  // `did:web:<host>` (fortress-level) or
  // `did:web:<host>:fortress:<fid>:agent:<alabel>`.
  const segments = rest.split(":");
  const authorityHost = segments[0]!;
  if (!HOST_RE.test(authorityHost)) {
    throw new Error(`did-web: '${authorityHost}' is not a valid DNS host`);
  }
  const parsed: ParsedDidWeb = { authority_host: authorityHost };
  if (segments.length === 1) return parsed;
  if (
    segments.length === 5 &&
    segments[1] === "fortress" &&
    segments[3] === "agent"
  ) {
    const fortressId = segments[2]!;
    const agentLabel = segments[4]!;
    if (!FORTRESS_LABEL_RE.test(fortressId)) {
      throw new Error(
        `did-web: fortress_id '${fortressId}' is not a valid label`,
      );
    }
    if (!AGENT_LABEL_RE.test(agentLabel)) {
      throw new Error(
        `did-web: agent_label '${agentLabel}' is not a valid label`,
      );
    }
    parsed.fortress_id = fortressId;
    parsed.agent_label = agentLabel;
    return parsed;
  }
  throw new Error(
    `did-web: '${did}' does not match the supported shapes (bare did:web:<host> or did:web:<host>:fortress:<fid>:agent:<alabel>)`,
  );
}

export function didToUrl(parsed: ParsedDidWeb): string {
  if (parsed.fortress_id === undefined || parsed.agent_label === undefined) {
    return `https://${parsed.authority_host}/.well-known/did.json`;
  }
  return `https://${parsed.authority_host}/fortress/${parsed.fortress_id}/agent/${parsed.agent_label}/did.json`;
}

function buildDid(opts: IssueDidWebOpts): string {
  if (opts.agent_label === undefined) {
    return `did:web:${opts.authority_host}`;
  }
  return `did:web:${opts.authority_host}:fortress:${opts.fortress_id}:agent:${opts.agent_label}`;
}

function canonicalPublishPath(identifier: DidWebIdentifier): string {
  if (identifier.agent_label === undefined) {
    return "/.well-known/did.json";
  }
  return `/fortress/${identifier.fortress_id}/agent/${identifier.agent_label}/did.json`;
}

function nextVerificationMethodId(did: string, doc: DidDocument): string {
  let max = 0;
  for (const vm of doc.verificationMethod) {
    const prefix = `${did}#key-`;
    if (!vm.id.startsWith(prefix)) continue;
    const n = Number.parseInt(vm.id.slice(prefix.length), 10);
    if (Number.isFinite(n) && n > max) max = n;
  }
  return `${did}#key-${max + 1}`;
}

function addDaysIso(iso: string, days: number): string {
  return new Date(Date.parse(iso) + days * MS_PER_DAY).toISOString();
}

function assertionTimeMs(assertionTime: string | Date | undefined): number | undefined {
  if (assertionTime === undefined) return undefined;
  const ms =
    assertionTime instanceof Date
      ? assertionTime.getTime()
      : Date.parse(assertionTime);
  return Number.isNaN(ms) ? undefined : ms;
}

function methodCoversAssertionTime(
  vm: VerificationMethod,
  timeMs: number | undefined,
): boolean {
  if (timeMs === undefined) {
    return vm.status === undefined || vm.status === "active";
  }
  const fromMs = vm.valid_from ? Date.parse(vm.valid_from) : undefined;
  const untilMs = vm.valid_until ? Date.parse(vm.valid_until) : undefined;
  if (fromMs !== undefined && !Number.isNaN(fromMs) && timeMs < fromMs) {
    return false;
  }
  if (untilMs !== undefined && !Number.isNaN(untilMs) && timeMs > untilMs) {
    return false;
  }
  return true;
}

function selectVerificationMethod(
  doc: DidDocument,
  expectedPublicKeyB64u: string,
  assertionTime: string | Date | undefined,
): VerificationMethod | undefined {
  const timeMs = assertionTimeMs(assertionTime);
  const matches = doc.verificationMethod.filter(
    (vm) =>
      vm.publicKeyJwk.x === expectedPublicKeyB64u &&
      methodCoversAssertionTime(vm, timeMs),
  );
  if (matches.length === 0) return undefined;
  const activeIds = new Set([...doc.authentication, ...doc.assertionMethod]);
  return (
    matches.find((vm) => activeIds.has(vm.id)) ??
    matches.find((vm) => vm.status === "previous" || vm.status === "revoked") ??
    matches[0]
  );
}

/**
 * Canonical JSON serialization for the DID Document. Sorts top-level
 * keys deterministically; nested objects are written as-is (their key
 * order is stable by construction). Used for the published artifact
 * SHA-256 so two issuances of the same identifier produce
 * byte-identical artifacts.
 */
function canonicalSerializeDidDocument(doc: DidDocument): string {
  return JSON.stringify(
    {
      "@context": doc["@context"],
      id: doc.id,
      verificationMethod: doc.verificationMethod,
      authentication: doc.authentication,
      assertionMethod: doc.assertionMethod,
    },
    null,
    2,
  );
}

function isDidDocument(value: unknown, expectedDid: string): value is DidDocument {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  if (v["id"] !== expectedDid) return false;
  if (!Array.isArray(v["@context"])) return false;
  const vm = v["verificationMethod"];
  if (!Array.isArray(vm) || vm.length === 0) return false;
  const first = vm[0] as Record<string, unknown> | undefined;
  if (!first || typeof first["id"] !== "string") return false;
  const jwk = first["publicKeyJwk"] as Record<string, unknown> | undefined;
  if (!jwk || jwk["kty"] !== "OKP" || jwk["crv"] !== "Ed25519") return false;
  if (typeof jwk["x"] !== "string") return false;
  if (!Array.isArray(v["authentication"])) return false;
  if (!Array.isArray(v["assertionMethod"])) return false;
  return true;
}

async function defaultFetcher(
  url: string,
  init?: { signal?: AbortSignal },
): Promise<Response> {
  return fetch(url, init);
}

async function readCappedJsonResponse(response: {
  headers?: { get(name: string): string | null };
  body?: ReadableStream<Uint8Array> | null;
  text?: () => Promise<string>;
  json?: () => Promise<unknown>;
}): Promise<unknown> {
  const contentLength = response.headers?.get("content-length");
  if (contentLength !== undefined && contentLength !== null) {
    const parsedLength = Number.parseInt(contentLength, 10);
    if (Number.isFinite(parsedLength) && parsedLength > MAX_DID_DOC_BYTES) {
      throw new Error(
        `response body exceeds ${MAX_DID_DOC_BYTES} byte did:web document limit`,
      );
    }
  }

  if (response.body !== undefined && response.body !== null) {
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value === undefined) continue;
        total += value.byteLength;
        if (total > MAX_DID_DOC_BYTES) {
          await reader.cancel();
          throw new Error(
            `response body exceeds ${MAX_DID_DOC_BYTES} byte did:web document limit`,
          );
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return JSON.parse(new TextDecoder().decode(bytes));
  }

  if (response.text !== undefined) {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > MAX_DID_DOC_BYTES) {
      throw new Error(
        `response body exceeds ${MAX_DID_DOC_BYTES} byte did:web document limit`,
      );
    }
    return JSON.parse(text);
  }

  if (response.json !== undefined) {
    return response.json();
  }

  throw new Error("response body is not readable");
}

function unsafeAuthorityHostReason(authorityHost: string): string | undefined {
  const host = authorityHost.toLowerCase();
  if (METADATA_AUTHORITY_HOSTS.has(host)) {
    return "metadata authority host";
  }

  const normalized = normalizeIpLiteral(authorityHost);
  if (normalized !== undefined && isIP(normalized) !== 0) {
    return "IP literal authority host";
  }
  return undefined;
}

async function resolvedHostNotPublicReason(
  authorityHost: string,
): Promise<string | undefined> {
  let addresses: Array<{ address: string }>;
  try {
    addresses = await lookup(authorityHost, { all: true, verbatim: true });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return `DNS resolution failed: ${message}`;
  }
  if (addresses.length === 0) return "DNS resolution returned no addresses";
  for (const { address } of addresses) {
    if (!isPublicIpAddress(address)) {
      return `DNS resolved to non-public address ${address}`;
    }
  }
  return undefined;
}

function normalizeIpLiteral(authorityHost: string): string | undefined {
  try {
    const parsed = new URL(`http://${authorityHost}`);
    return parsed.hostname.replace(/^\[/, "").replace(/\]$/, "");
  } catch {
    return undefined;
  }
}

// Exported for SSRF regression tests (pure classifier; no I/O). Returns false for
// any non-public destination, including IPv4-mapped/compatible IPv6 and NAT64.
export function isPublicIpAddress(address: string): boolean {
  const version = isIP(address);
  if (version === 4) return isPublicIpv4(address);
  if (version === 6) return isPublicIpv6(address);
  return false;
}

function isPublicIpv4(address: string): boolean {
  const octets = address.split(".").map((part) => Number.parseInt(part, 10));
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part))) {
    return false;
  }
  const [a, b] = octets;
  if (a === 10) return false;
  if (a === 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 0) return false;
  if (a >= 224) return false;
  return true;
}

function isPublicIpv6(address: string): boolean {
  const lower = address.toLowerCase();
  if (lower === "::1") return false; // loopback
  if (lower === "::") return false; // unspecified
  if (lower.startsWith("fe80:")) return false; // link-local
  // NAT64 well-known (64:ff9b::/96) + local-use (64:ff9b:1::/48): an embedded
  // IPv4 reached via a translator must not be treated as a public destination.
  if (lower.startsWith("64:ff9b:")) return false;
  // IPv4-mapped (::ffff:a.b.c.d / ::ffff:hhhh:hhhh) and IPv4-compatible (::a.b.c.d):
  // re-classify the embedded IPv4 so a mapped loopback/private/link-local/metadata
  // address is rejected instead of slipping through as "public IPv6".
  const embedded = embeddedIpv4(lower);
  if (embedded !== null) return isPublicIpv4(embedded);
  const firstHextet = Number.parseInt(lower.split(":")[0] || "0", 16);
  if ((firstHextet & 0xfe00) === 0xfc00) return false; // ULA fc00::/7
  return true;
}

// Extract an embedded IPv4 from an IPv4-mapped or IPv4-compatible IPv6 address,
// else null. Handles ::ffff:a.b.c.d, ::a.b.c.d, and the all-hex ::ffff:hhhh:hhhh.
function embeddedIpv4(lower: string): string | null {
  const dotted = lower.match(/^::(?:ffff:)?((?:\d{1,3}\.){3}\d{1,3})$/);
  if (dotted && isIP(dotted[1]) === 4) return dotted[1];
  const hex = lower.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hex) {
    const hi = Number.parseInt(hex[1], 16);
    const lo = Number.parseInt(hex[2], 16);
    return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
  }
  return null;
}

// ── Fortress-config persistence (build 3) ────────────────────────────

/**
 * Canonical relative path (inside a fortress's `storage_path`) where
 * the issued did:web identifier record is persisted. `did-web issue`
 * writes this file; downstream surfaces (exit-bundle export, status
 * displays) read it for auto-inclusion / display.
 *
 * The act of issuing IS the registration: there is exactly one
 * fortress-level did:web record per storage path, and per-fortress
 * isolation is structural (different storage_path means different
 * file). The companion `did.json` artifact (operator-publishable DID
 * Document) is colocated at the same directory.
 */
export const FORTRESS_DID_WEB_REGISTRY_PATH = "recognition/did-web.json";

/**
 * Parsed shape of the persisted record `did-web issue` writes. Mirrors
 * the literal JSON shape the foundation CLI emits; callers should not
 * depend on extra top-level keys appearing here.
 */
export interface FortressDidWebRecord {
  version: 1;
  identifier: {
    did: string;
    created_at: string;
    authority_host: string;
    fortress_id: string;
    agent_label?: string;
    did_document: DidDocument;
  };
  artifact: {
    url: string;
    publish_path: string;
    sha256: string;
  };
  key_history?: DidWebRotationHistoryEntry[];
  rotation_policy?: {
    recommended_periodic_days?: number;
  };
}

/**
 * Load the fortress's persisted did:web record, if any.
 *
 * Returns `null` when no record has been issued (file absent). Throws
 * when the file exists but is malformed; callers that prefer a soft
 * miss can use `tryLoadFortressDidWebRecord` instead.
 *
 * Pure local filesystem read; no outbound network surface. The record
 * is the operator-sovereign source of truth for "this fortress has a
 * registered did:web identifier"; auto-inclusion in exit bundles
 * keys off this file's presence, not off any external registry.
 */
export async function loadFortressDidWebRecord(
  storagePath: string,
): Promise<FortressDidWebRecord | null> {
  const persistPath = join(storagePath, FORTRESS_DID_WEB_REGISTRY_PATH);
  let raw: string;
  try {
    raw = await readFile(persistPath, "utf-8");
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return null;
    throw err;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    throw new Error(
      `did-web: fortress-config record at ${persistPath} is not valid JSON: ${message}`,
    );
  }
  if (!isFortressDidWebRecord(parsed)) {
    throw new Error(
      `did-web: fortress-config record at ${persistPath} is malformed (expected version: 1 with identifier.did + identifier.authority_host)`,
    );
  }
  return parsed;
}

/**
 * Soft-miss variant: returns `null` whether the file is absent OR
 * malformed. Use only on display paths where surfacing a fortress in
 * a degraded state is preferable to refusing to render.
 */
export async function tryLoadFortressDidWebRecord(
  storagePath: string,
): Promise<FortressDidWebRecord | null> {
  try {
    return await loadFortressDidWebRecord(storagePath);
  } catch {
    return null;
  }
}

function isFortressDidWebRecord(value: unknown): value is FortressDidWebRecord {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  if (v["version"] !== 1) return false;
  const id = v["identifier"] as Record<string, unknown> | undefined;
  if (!id || typeof id !== "object") return false;
  if (typeof id["did"] !== "string" || !id["did"].startsWith("did:web:")) {
    return false;
  }
  if (typeof id["authority_host"] !== "string") return false;
  if (typeof id["fortress_id"] !== "string") return false;
  if (typeof id["created_at"] !== "string") return false;
  if (!id["did_document"] || typeof id["did_document"] !== "object") {
    return false;
  }
  const artifact = v["artifact"] as Record<string, unknown> | undefined;
  if (!artifact || typeof artifact !== "object") return false;
  if (typeof artifact["url"] !== "string") return false;
  if (typeof artifact["publish_path"] !== "string") return false;
  if (typeof artifact["sha256"] !== "string") return false;
  return true;
}

export function identifierFromFortressDidWebRecord(
  record: FortressDidWebRecord,
): DidWebIdentifier {
  const activeMethodId =
    record.identifier.did_document.authentication[0] ??
    record.identifier.did_document.assertionMethod[0];
  const activeMethod = record.identifier.did_document.verificationMethod.find(
    (vm) => vm.id === activeMethodId,
  );
  const publicKeyB64u =
    activeMethod?.publicKeyJwk.x ??
    record.identifier.did_document.verificationMethod[0]?.publicKeyJwk.x;
  if (!publicKeyB64u) {
    throw new Error("did-web: fortress-config record has no verification method public key");
  }
  return {
    did: record.identifier.did,
    did_document: record.identifier.did_document,
    public_key: fromBase64url(publicKeyB64u),
    created_at: record.identifier.created_at,
    authority_host: record.identifier.authority_host,
    fortress_id: record.identifier.fortress_id,
    ...(record.identifier.agent_label !== undefined
      ? { agent_label: record.identifier.agent_label }
      : {}),
  };
}

export function applyDidWebRotationToRecord(
  record: FortressDidWebRecord,
  rotation: RotationResult,
  artifact: PublishedArtifact,
): FortressDidWebRecord {
  const historyEntry: DidWebRotationHistoryEntry = {
    rotated_at: rotation.rotated_at,
    reason: rotation.rotation_reason,
    old_verification_method_id: rotation.old_verification_method_id,
    new_verification_method_id: rotation.new_verification_method_id,
    old_public_key_b64u: rotation.old_public_key_b64u,
    new_public_key_b64u: rotation.new_public_key_b64u,
    preserve_old_key_for: rotation.preserve_old_key_for,
  };
  return {
    ...record,
    identifier: {
      ...record.identifier,
      did_document: rotation.new_did_document,
    },
    artifact: {
      url: artifact.url,
      publish_path: artifact.publish_path,
      sha256: artifact.sha256,
    },
    key_history: [...(record.key_history ?? []), historyEntry],
  };
}

export function buildDidWebHealthSnapshot(
  record: FortressDidWebRecord | null,
  opts: { now?: () => Date } = {},
): DidWebHealthSnapshot {
  if (!record) {
    return {
      configured: false,
      key_history: [],
      recommended_periodic_days: DEFAULT_RECOMMENDED_PERIODIC_DAYS,
    };
  }
  const history = record.key_history ?? [];
  const recommendedDays =
    record.rotation_policy?.recommended_periodic_days ??
    DEFAULT_RECOMMENDED_PERIODIC_DAYS;
  const anchor =
    history.at(-1)?.rotated_at ?? record.identifier.created_at;
  const nowMs = (opts.now ?? (() => new Date()))().getTime();
  const nextMs = Date.parse(anchor) + recommendedDays * MS_PER_DAY;
  const currentMethodId =
    record.identifier.did_document.authentication[0] ??
    record.identifier.did_document.assertionMethod[0];
  return {
    configured: true,
    identifier: record.identifier.did,
    authority_host: record.identifier.authority_host,
    current_verification_method_id: currentMethodId,
    last_rotation: history.at(-1),
    key_history: history,
    recommended_periodic_days: recommendedDays,
    days_until_recommended_rotation: Math.ceil((nextMs - nowMs) / MS_PER_DAY),
  };
}

// ── Derivation convenience ───────────────────────────────────────────

/**
 * Convenience: derive a DidWebIdentifier from a fortress's Ed25519
 * private key seed. Exposed for cases where callers want to verify
 * the issued DID against a known private key (e.g. exit-bundle
 * round-trip tests). Pure; no outbound surface.
 */
export async function deriveDidWebFromPrivateKey(opts: {
  fortress_id: string;
  authority_host: string;
  agent_label?: string;
  private_key: Uint8Array;
  now?: () => Date;
}): Promise<DidWebIdentifier> {
  if (opts.private_key.length !== 32) {
    throw new Error("did-web: private_key must be 32-byte Ed25519 seed");
  }
  const publicKey = ed25519.getPublicKey(opts.private_key);
  return issueDidWeb({
    fortress_id: opts.fortress_id,
    authority_host: opts.authority_host,
    public_key: publicKey,
    ...(opts.agent_label !== undefined ? { agent_label: opts.agent_label } : {}),
    ...(opts.now !== undefined ? { now: opts.now } : {}),
  });
}
