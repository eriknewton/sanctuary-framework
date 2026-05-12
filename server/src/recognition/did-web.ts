/**
 * Sanctuary WP-V1.x-RECOGNITION-LAYER Path C primary: did:web foundation.
 *
 * Closes Principle 5 (Recognition + Portability) recognition arm via
 * the smallest-buildable surface against the largest existing operator-
 * recognition substrate: the web's DNS + TLS trust chain.
 *
 * Foundation build ships three pure capabilities:
 *
 *   1. issueDidWeb  — generate a W3C-DID-Core-conformant did:web
 *      identifier + DID Document bound to a Sanctuary fortress's
 *      existing Ed25519 public key. No outbound; pure construction.
 *
 *   2. resolveDidWeb — HTTPS fetch + JSON parse + verificationMethod
 *      sanity check for a peer-presented did:web identifier. Outbound
 *      HTTPS by definition; opt-in load-bearing via the caller-supplied
 *      allowed_hosts allowlist. Empty allowlist means resolution
 *      refuses to leave the fortress, preserving no-outbound-by-default.
 *
 *   3. publishDidWebDocument — return the JSON artifact bytes + the
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

import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { sha256 } from "@noble/hashes/sha256";
import { ed25519 } from "@noble/curves/ed25519";

import { toBase64url, stringToBytes } from "../core/encoding.js";
import { hashToString } from "../core/hashing.js";

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
    json: () => Promise<unknown>;
  }>;
  /**
   * Optional expected Ed25519 public key. When set, the resolved
   * document's verificationMethod[0].publicKeyJwk.x must match
   * (base64url-encoded). Mismatch returns `signature_mismatch`.
   */
  expected_public_key?: Uint8Array;
}

export type ResolveResult =
  | { ok: true; did_document: DidDocument; url: string }
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
} as const;

export type DidWebAuditOp =
  (typeof DID_WEB_AUDIT_OPS)[keyof typeof DID_WEB_AUDIT_OPS];

/** W3C DID Core + DID Web v0.3 + ed25519-2020 context URIs. */
const DID_CONTEXT = [
  "https://www.w3.org/ns/did/v1",
  "https://w3id.org/security/suites/jws-2020/v1",
] as const;

const DEFAULT_TIMEOUT_MS = 5000;

const HOST_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;
const FORTRESS_LABEL_RE = /^[a-zA-Z0-9_-]{1,64}$/;
const AGENT_LABEL_RE = /^[a-zA-Z0-9_-]{1,64}$/;

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
  };
  const didDocument: DidDocument = {
    "@context": [...DID_CONTEXT],
    id: did,
    verificationMethod: [verificationMethod],
    authentication: [verificationMethodId],
    assertionMethod: [verificationMethodId],
  };

  const now = (opts.now ?? (() => new Date()))();

  return {
    did,
    did_document: didDocument,
    public_key: opts.public_key,
    created_at: now.toISOString(),
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

// ── Resolution ───────────────────────────────────────────────────────

export async function resolveDidWeb(
  did: string,
  opts: ResolveDidWebOpts,
): Promise<ResolveResult> {
  const parsed = parseDidWeb(did);
  const url = didToUrl(parsed);

  if (!opts.allowed_hosts.includes(parsed.authority_host)) {
    return {
      ok: false,
      failure: "host_not_allowed",
      message: `did-web: authority_host '${parsed.authority_host}' is not in the operator's allowed_hosts allowlist; resolution refused (no-outbound-by-default)`,
      url,
    };
  }

  const timeoutMs = opts.timeout_ms ?? DEFAULT_TIMEOUT_MS;
  const fetcher = opts.fetcher ?? defaultFetcher;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let response: { ok: boolean; status: number; json: () => Promise<unknown> };
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
    body = await response.json();
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
    const actualX = body.verificationMethod[0]?.publicKeyJwk.x;
    if (actualX !== expectedX) {
      return {
        ok: false,
        failure: "signature_mismatch",
        message: `did-web: verificationMethod public key does not match expected key`,
        url,
      };
    }
  }

  return { ok: true, did_document: body, url };
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
    parsed.fortress_id = segments[2];
    parsed.agent_label = segments[4];
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
): Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }> {
  const response = await fetch(url, init);
  return {
    ok: response.ok,
    status: response.status,
    json: () => response.json(),
  };
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
