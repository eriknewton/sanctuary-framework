/**
 * Q5 Rung 2: inert catalog, index, and operator-overlay wire contracts.
 *
 * This module is deliberately pure. It parses closed signed structures,
 * canonicalizes their bodies, and exposes verified-envelope entry points. It
 * performs no network access, host reads, state writes, selection, or model
 * activation.
 */

import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { ed25519 } from "@noble/curves/ed25519";
import {
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
} from "../core/crypto-suite-registry.js";
import { fromBase64urlStrict, stringToBytes, toBase64url } from "../core/encoding.js";
import { parseStrictJson } from "../substrate/strict-json.js";
import { SubstrateError } from "../substrate/errors.js";
import { PINNED_MODEL_MANIFEST_SIGNING_PUBLIC_KEY_B64URL } from "./model-manifest.js";
import { SURFACES, type Surface } from "./surfaces.js";
import {
  SPDX_GENERATED_EXCEPTION_ROWS,
  SPDX_GENERATED_LICENSE_ROWS,
  SPDX_GENERATED_LIST_VERSION,
  SPDX_GENERATED_TABLE_SHA256,
} from "./catalog-v3/spdx/spdx-tables.generated.js";

export const CATALOG_V3_DOMAIN = "sanctuary.model-catalog.v3";
export const CATALOG_INDEX_V1_DOMAIN = "sanctuary.model-catalog-index.v1";
export const OVERLAY_V1_DOMAIN = "sanctuary.model-overlay.v1";
export const SIGNATURE_DOMAIN_DELIMITER = "\n";
export const OLLAMA_REGISTRY_V3 = "registry.ollama.ai" as const;

export const MAX_CATALOG_ENTRIES = 32;
export const MAX_OVERLAY_ENTRIES = 64;
export const MAX_INDEX_SEGMENT_ENTRIES = 64;
export const CATALOG_SIGNING_BODY_MAX_BYTES = 32_768;
export const CATALOG_INDEX_SIGNING_BODY_MAX_BYTES = 32_768;
export const OVERLAY_SIGNING_BODY_MAX_BYTES = 32_768;
export const MAX_CATALOG_WIRE_JSON_BYTES = 65_536;
export const MAX_SIGNED_VERSION = 2_147_483_647;
// 86 = base64url length (no padding) of a 64-byte raw Ed25519 signature:
// ceil(64 bytes * 8 bits / 6 bits-per-base64-char) = ceil(85.33) = 86.
const ED25519_SIGNATURE_BASE64URL_CHARS = 86;
export const CATALOG_SURFACE_ORDER: readonly Surface[] = Object.freeze([
  "concierge",
  "direct-agent-gate-advisor",
  "sentinel-scoring",
  "gate-explanation",
  "privacy-filter-tier-2",
  "template-suggestion",
]);

export const ASSURANCES = Object.freeze(["light", "immune"] as const);
export type Assurance = (typeof ASSURANCES)[number];
export const HARDWARE_TIERS = Object.freeze(["baseline", "mid", "pro"] as const);
export type HardwareTier = (typeof HARDWARE_TIERS)[number];

export const ASSURANCE_RANK: Readonly<Record<Assurance, number>> = Object.freeze({
  light: 0,
  immune: 1,
});

export const COMPILED_SURFACE_ASSURANCE_FLOOR: Readonly<Record<Surface, Assurance>> =
  Object.freeze({
    concierge: "light",
    "direct-agent-gate-advisor": "light",
    "sentinel-scoring": "immune",
    "gate-explanation": "light",
    "privacy-filter-tier-2": "immune",
    "template-suggestion": "light",
  });

export interface TierSpecV3 {
  readonly min_ram_gib: number;
  readonly description: string;
}

export interface TierTableV3 {
  readonly schema: "tier-table.v1";
  readonly tiers: Readonly<Record<HardwareTier, TierSpecV3>>;
}

export interface SurfaceDefaultV3 {
  readonly tier: HardwareTier;
  readonly assurance: Assurance;
}

export interface SurfaceDefaultsV3 {
  readonly schema: "surface-defaults.v1";
  readonly defaults: Readonly<Record<Surface, SurfaceDefaultV3>>;
}

/** Reviewed advisory hardware bands; trust is carried by signed roots, not descriptions. */
export const TIER_TABLE_V3: Readonly<TierTableV3> = Object.freeze({
  schema: "tier-table.v1",
  tiers: Object.freeze({
    baseline: Object.freeze({ min_ram_gib: 8, description: "Baseline local model hardware" }),
    mid: Object.freeze({ min_ram_gib: 16, description: "Mid-tier local model hardware" }),
    pro: Object.freeze({ min_ram_gib: 32, description: "Pro local model hardware" }),
  }),
});

/**
 * Complete immutable source-transform defaults. A signed catalog body's
 * surface_defaults must canonicalize to exactly these bytes (parseCatalogBodyV3
 * below rejects any other value with "invalid_value"); a catalog cannot raise,
 * lower, or otherwise vary the compiled defaults, only reproduce them exactly.
 */
export const SURFACE_DEFAULTS_V3: Readonly<SurfaceDefaultsV3> = Object.freeze({
  schema: "surface-defaults.v1",
  defaults: Object.freeze({
    concierge: Object.freeze({ tier: "baseline", assurance: "light" }),
    "direct-agent-gate-advisor": Object.freeze({ tier: "baseline", assurance: "light" }),
    "sentinel-scoring": Object.freeze({ tier: "mid", assurance: "immune" }),
    "gate-explanation": Object.freeze({ tier: "baseline", assurance: "light" }),
    "privacy-filter-tier-2": Object.freeze({ tier: "mid", assurance: "immune" }),
    "template-suggestion": Object.freeze({ tier: "baseline", assurance: "light" }),
  }),
});

export interface SignedOllamaIdentityV3 {
  readonly registry: typeof OLLAMA_REGISTRY_V3;
  readonly namespace: string;
  readonly model: string;
  readonly tag: string;
  readonly ollama_manifest_sha256: string;
}

export interface LicenseEvidenceV3 {
  readonly spdx: string;
  readonly custom_name?: string;
  readonly source_url: string;
  readonly evidence_sha256: string;
}

export interface CatalogModelEntryV3 {
  readonly model_id: string;
  readonly identity: SignedOllamaIdentityV3;
  readonly assurance: Assurance;
  readonly license: LicenseEvidenceV3;
  readonly hardware_tier: HardwareTier;
}

export interface CatalogBodyV3 {
  readonly schema: typeof CATALOG_V3_DOMAIN;
  readonly catalog_version: number;
  readonly issued_at: string;
  readonly source_commit: string;
  readonly previous_catalog_body_sha256: string | null;
  readonly models: readonly CatalogModelEntryV3[];
  readonly tiers: TierTableV3;
  readonly surface_defaults: SurfaceDefaultsV3;
}

export interface SignedCatalogV3 {
  readonly body: CatalogBodyV3;
  readonly signature: string;
  readonly signing_key_id: string;
}

export interface OverlayModelEntryV1 {
  readonly model_id: string;
  readonly identity: SignedOllamaIdentityV3;
  readonly assurance: Assurance;
  readonly surface_authorization: readonly Surface[];
}

export interface OverlayBodyV1 {
  readonly schema: typeof OVERLAY_V1_DOMAIN;
  readonly overlay_version: number;
  /** Random fortress-local binding id; S2 persists and authenticates the expected value. */
  readonly overlay_binding_id: string;
  readonly issued_at: string;
  readonly entries: readonly OverlayModelEntryV1[];
}

export interface SignedOverlayV1 {
  readonly body: OverlayBodyV1;
  readonly signature: string;
  readonly signer_key_id: string;
}

export interface CatalogIndexEntryV1 {
  readonly catalog_version: number;
  readonly catalog_release_id: number;
  readonly catalog_asset_id: number;
  readonly envelope_sha256: string;
  readonly body_sha256: string;
  readonly catalog_key_epoch: number;
}

export interface CatalogIndexBodyV1 {
  readonly schema: typeof CATALOG_INDEX_V1_DOMAIN;
  readonly index_version: number;
  readonly previous_index_body_sha256: string | null;
  readonly segment_number: number;
  readonly segment_base_index_version: number;
  readonly first_catalog_version: number;
  readonly highest_catalog_version: number;
  readonly issued_at: string;
  readonly entries: readonly CatalogIndexEntryV1[];
}

export interface SignedCatalogIndexSegmentV1 {
  readonly body: CatalogIndexBodyV1;
  readonly signature: string;
  readonly signing_key_id: string;
}

export interface UntrustedCatalogContinuityObservationV3 {
  readonly status: "observed" | "revoked";
  readonly last_admitted_envelope: SignedCatalogV3;
  readonly last_admitted_catalog_version: number;
  readonly last_admitted_body_sha256: string;
  readonly last_admitted_previous_body_sha256: string | null;
  readonly catalog_key_epoch: number;
  readonly catalog_version_floor: number;
}

/** Structurally coherent retained evidence. S2 must authenticate persistence/rollback. */
export interface UntrustedCatalogIndexContinuityObservationV1 {
  readonly index_continuity_status: "observed" | "revoked";
  readonly index_envelope: SignedCatalogIndexSegmentV1;
  readonly index_version_floor: number;
  readonly index_body_sha256: string;
  readonly index_key_epoch: number;
}

export interface CatalogKeyEpoch {
  readonly epoch: number;
  readonly signing_key_id: string;
  readonly pubkey: string;
  readonly min_catalog_version: number;
  readonly max_catalog_version: number | null;
  readonly min_index_version: number;
  readonly max_index_version: number | null;
  readonly status: "active" | "retired" | "revoked";
}

export interface CompiledIndexCheckpoint {
  readonly index_version: number;
  readonly index_body_sha256: string | null;
  readonly highest_catalog_version: number;
  readonly highest_catalog_body_sha256: string | null;
  readonly signing_key_id: string;
}

export const COMPILED_CATALOG_KEYRING: readonly CatalogKeyEpoch[] = Object.freeze([
  Object.freeze({
    epoch: 1,
    signing_key_id: "cat-epoch-1",
    pubkey: PINNED_MODEL_MANIFEST_SIGNING_PUBLIC_KEY_B64URL,
    min_catalog_version: 1,
    max_catalog_version: null,
    min_index_version: 1,
    max_index_version: null,
    status: "active",
  }),
]);

// Epoch 1 deliberately reuses the historical model-manifest signing key only
// for bootstrap distribution. Signature preimages are separated by the
// frozen catalog/index domains plus a newline, so a valid manifest signature
// cannot verify as either new contract. A future key rotation must add a
// successor epoch in the same compiled update before retiring or revoking the
// current epoch. "retired" preserves verification of its historical version
// range but cannot sign the successor range. "revoked" intentionally makes
// even historical signatures unverifiable after key compromise. The final
// epoch must remain active, so there is no fail-open "trust nothing" state.

export const COMPILED_INDEX_CHECKPOINT: Readonly<CompiledIndexCheckpoint> = Object.freeze({
  index_version: 0,
  index_body_sha256: null,
  highest_catalog_version: 0,
  highest_catalog_body_sha256: null,
  signing_key_id: "cat-epoch-1",
});
// This all-null record is a bootstrap/genesis sentinel, not evidence that a
// remote index has been authenticated. S2 owns admission and durable floors.

export type CatalogV3RefusalReason =
  | "manifest_too_large"
  | "malformed_json"
  | "duplicate_key"
  | "prototype_key"
  | "missing_key"
  | "unknown_key"
  | "invalid_type"
  | "invalid_value"
  | "invalid_order"
  | "duplicate_entry"
  | "empty_collection"
  | "too_many_entries"
  | "invalid_spdx"
  | "bad_signature_encoding"
  | "bad_signature_length"
  | "zero_signature"
  | "bad_signature"
  | "bad_pinned_key_length"
  | "zero_pinned_key"
  | "unknown_signing_key"
  | "signing_key_out_of_range"
  | "signing_key_revoked"
  | "unauthenticated_input"
  | "catalog_trust_root_mismatch"
  | "overlay_signer_mismatch"
  | "overlay_binding_mismatch"
  | "overlay_rollback"
  | "overlay_collision"
  | "overlay_escalation";

export type CatalogV3ParseResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly reason: CatalogV3RefusalReason };

const fail = <T>(reason: CatalogV3RefusalReason): CatalogV3ParseResult<T> => ({ ok: false, reason });
const SHA256_HEX = /^[0-9a-f]{64}$/;
const SOURCE_COMMIT = /^[0-9a-f]{40}$/;
const BINDING_ID = /^(?!0{32}$)[0-9a-f]{32}$/;
const COMPONENT = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const CATALOG_KEY_ID = /^cat-epoch-[1-9][0-9]{0,8}$/;
// A 32-byte value encodes to 43 unpadded base64url characters. The final
// character carries four data bits followed by two zero pad bits, so its
// alphabet index must be divisible by four (the 16 characters below).
const OVERLAY_KEY_ID = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
const SIGNED_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const ASCII_TEXT = /^[\x20-\x7e]+$/;
// This is a loose structural prefilter, not the full grammar; validSourceUrl below
// does the real DNS-shape, scheme, and traversal checks. The path quantifier
// {0,246} is derived from the overall 256-character source_url cap enforced there:
// 256 - 8 ("https://") - 1 (shortest possible host, one character) - 1 (the
// mandatory "/" separator) = 246, leaving room for the smallest legal host and the
// largest legal path within the same 256-character budget.
const SOURCE_URL = /^https:\/\/[a-z0-9.-]{1,253}(?::[0-9]{1,5})?\/[A-Za-z0-9._~%!$&'()*+,;=:@/-]{0,246}$/;
const ZERO_SHA256 = "0".repeat(64);

const CATALOG_BODY_KEYS = ["schema", "catalog_version", "issued_at", "source_commit", "previous_catalog_body_sha256", "models", "tiers", "surface_defaults"] as const;
const CATALOG_ENTRY_KEYS = ["model_id", "identity", "assurance", "license", "hardware_tier"] as const;
const IDENTITY_KEYS = ["registry", "namespace", "model", "tag", "ollama_manifest_sha256"] as const;
const LICENSE_REQUIRED_KEYS = ["spdx", "source_url", "evidence_sha256"] as const;
const TIER_TABLE_KEYS = ["schema", "tiers"] as const;
const TIER_SPEC_KEYS = ["min_ram_gib", "description"] as const;
const SURFACE_DEFAULTS_KEYS = ["schema", "defaults"] as const;
const SURFACE_DEFAULT_KEYS = ["tier", "assurance"] as const;
const OVERLAY_BODY_KEYS = ["schema", "overlay_version", "overlay_binding_id", "issued_at", "entries"] as const;
const OVERLAY_ENTRY_KEYS = ["model_id", "identity", "assurance", "surface_authorization"] as const;
const ENVELOPE_KEYS = ["body", "signature", "signing_key_id"] as const;
const OVERLAY_ENVELOPE_KEYS = ["body", "signature", "signer_key_id"] as const;
const INDEX_BODY_KEYS = ["schema", "index_version", "previous_index_body_sha256", "segment_number", "segment_base_index_version", "first_catalog_version", "highest_catalog_version", "issued_at", "entries"] as const;
const INDEX_ENTRY_KEYS = ["catalog_version", "catalog_release_id", "catalog_asset_id", "envelope_sha256", "body_sha256", "catalog_key_epoch"] as const;
const CATALOG_CONTINUITY_KEYS = ["status", "last_admitted_envelope", "last_admitted_catalog_version", "last_admitted_body_sha256", "last_admitted_previous_body_sha256", "catalog_key_epoch", "catalog_version_floor"] as const;
const INDEX_CONTINUITY_KEYS = ["index_continuity_status", "index_envelope", "index_version_floor", "index_body_sha256", "index_key_epoch"] as const;
const CATALOG_KEY_EPOCH_KEYS = ["epoch", "signing_key_id", "pubkey", "min_catalog_version", "max_catalog_version", "min_index_version", "max_index_version", "status"] as const;

type JsonSnapshotResult =
  | { readonly ok: true; readonly value: unknown }
  | { readonly ok: false };
// 4096 = a generous power-of-two ceiling on total snapshotted JSON nodes (every
// object, array, and scalar counts as one), independent of MAX_CATALOG_WIRE_JSON_BYTES
// above: a deeply nested but low-byte-count payload can exhaust node-walk work without
// ever approaching the byte cap, so this bound exists to stop that class on its own.
const MAX_JSON_SNAPSHOT_NODES = 4096;
const SIGNING_BODY_MAX_BYTES_BY_DOMAIN: Readonly<Record<string, number>> = Object.freeze({
  [CATALOG_V3_DOMAIN]: CATALOG_SIGNING_BODY_MAX_BYTES,
  [CATALOG_INDEX_V1_DOMAIN]: CATALOG_INDEX_SIGNING_BODY_MAX_BYTES,
  [OVERLAY_V1_DOMAIN]: OVERLAY_SIGNING_BODY_MAX_BYTES,
});

/**
 * Snapshot hostile JavaScript input without executing accessors. Reflective
 * proxy traps may run, but their result is copied once into ordinary data and
 * every exception, accessor, cycle, sparse/decorated array, or exotic
 * prototype is rejected before contract parsing observes it.
 */
function snapshotJsonInput(
  value: unknown,
  depth = 0,
  seen = new WeakSet<object>(),
  budget = { remaining: MAX_JSON_SNAPSHOT_NODES },
): JsonSnapshotResult {
  try {
    // 64 here duplicates MAX_CANONICAL_JSON_DEPTH further below (kept as a bare
    // literal because this snapshot pass runs before canonicalization exists as a
    // concept and has no dependency on that constant); if the two ever need to
    // diverge, this bound and MAX_CANONICAL_JSON_DEPTH still describe the same
    // "how deep can hostile input nest" limit and should be changed together.
    if (depth > 64 || budget.remaining-- <= 0) return { ok: false };
    if (value === null || typeof value === "string" || typeof value === "boolean") {
      return { ok: true, value };
    }
    if (typeof value === "number") return Number.isFinite(value) ? { ok: true, value } : { ok: false };
    if (typeof value !== "object" || seen.has(value)) return { ok: false };
    seen.add(value);

    const prototype = Object.getPrototypeOf(value);
    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.some((key) => typeof key !== "string")) return { ok: false };

    if (Array.isArray(value)) {
      if (prototype !== Array.prototype) return { ok: false };
      const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
      if (!lengthDescriptor || !("value" in lengthDescriptor)
        || !Number.isSafeInteger(lengthDescriptor.value) || lengthDescriptor.value < 0) return { ok: false };
      const length = lengthDescriptor.value as number;
      if (length > budget.remaining || ownKeys.length !== length + 1 || !ownKeys.includes("length")) return { ok: false };
      const result: unknown[] = [];
      for (let index = 0; index < length; index++) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) return { ok: false };
        const nested = snapshotJsonInput(descriptor.value, depth + 1, seen, budget);
        if (!nested.ok) return nested;
        result.push(nested.value);
      }
      return { ok: true, value: result };
    }

    if (prototype !== Object.prototype && prototype !== null) return { ok: false };
    if (ownKeys.length > budget.remaining) return { ok: false };
    const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const key of ownKeys as string[]) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) return { ok: false };
      const nested = snapshotJsonInput(descriptor.value, depth + 1, seen, budget);
      if (!nested.ok) return nested;
      result[key] = nested.value;
    }
    return { ok: true, value: result };
  } catch {
    return { ok: false };
  }
}

function snapshotForParse<T>(value: unknown): CatalogV3ParseResult<T> | { readonly ok: true; readonly value: unknown } {
  const snapshot = snapshotJsonInput(value);
  return snapshot.ok ? snapshot : fail("invalid_value");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function matchesEntire(pattern: RegExp, value: string): boolean {
  const match = pattern.exec(value);
  return match !== null && match[0] === value;
}

function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): CatalogV3RefusalReason | null {
  for (const key of required) if (!Object.hasOwn(value, key)) return "missing_key";
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) if (!allowed.has(key)) return "unknown_key";
  return null;
}

function canonicalReconstructionMatches(received: unknown, reconstructed: unknown): boolean {
  try {
    return canonicalizeJson(received) === canonicalizeJson(reconstructed);
  } catch {
    return false;
  }
}

function positiveVersion(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= MAX_SIGNED_VERSION;
}

function positiveSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1;
}

function validTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || !matchesEntire(SIGNED_TIMESTAMP, value)) return false;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString().replace(".000Z", "Z") === value;
}

function validDigest(value: unknown, rejectZero = false): value is string {
  return typeof value === "string" && matchesEntire(SHA256_HEX, value) && (!rejectZero || value !== ZERO_SHA256);
}

function validSourceUrl(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 1 || value.length > 256
    || !matchesEntire(ASCII_TEXT, value) || !matchesEntire(SOURCE_URL, value)) return false;
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash || parsed.search) return false;
    const authority = value.slice("https://".length, value.indexOf("/", "https://".length));
    const rawHostname = authority.replace(/:[0-9]{1,5}$/, "");
    if (parsed.hostname !== rawHostname || parsed.hostname !== parsed.hostname.toLowerCase()
      || isIP(parsed.hostname) !== 0) return false;
    const labels = parsed.hostname.split(".");
    if (labels.length < 2 || labels.some((label) => label.length < 1 || label.length > 63
      || label.startsWith("xn--") || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))
      || !/^[a-z]{2,63}$/.test(labels.at(-1)!)) return false;
    if (parsed.port !== "" && (!/^[0-9]{1,5}$/.test(parsed.port)
      || Number(parsed.port) < 1 || Number(parsed.port) > 65_535)) return false;
    for (let index = 0; index < parsed.pathname.length; index++) {
      if (parsed.pathname[index] === "%"
        && !/^[0-9A-F]{2}$/.test(parsed.pathname.slice(index + 1, index + 3))) return false;
    }
    for (const segment of parsed.pathname.split("/")) {
      const decoded = decodeURIComponent(segment);
      const containsAsciiControl = [...decoded].some((character) => {
        const codePoint = character.codePointAt(0)!;
        return codePoint <= 0x1f || codePoint === 0x7f;
      });
      if (decoded === "." || decoded === ".." || /[\\/]/.test(decoded) || containsAsciiControl) return false;
    }
    return parsed.href === value || (parsed.pathname === "/" && `${parsed.origin}/` === value);
  } catch {
    return false;
  }
}

export function parseModelId(value: unknown): CatalogV3ParseResult<string> {
  return typeof value === "string" && matchesEntire(COMPONENT, value) ? { ok: true, value } : fail("invalid_value");
}

export function parseAssurance(value: unknown): CatalogV3ParseResult<Assurance> {
  return value === "light" || value === "immune" ? { ok: true, value } : fail("invalid_value");
}

function parseHardwareTier(value: unknown): CatalogV3ParseResult<HardwareTier> {
  return value === "baseline" || value === "mid" || value === "pro" ? { ok: true, value } : fail("invalid_value");
}

export function parseSurfaceList(value: unknown): CatalogV3ParseResult<Surface[]> {
  const snapshot = snapshotForParse<Surface[]>(value); if (!snapshot.ok) return snapshot;
  value = snapshot.value;
  if (!Array.isArray(value)) return fail("invalid_type");
  if (value.length < 1) return fail("empty_collection");
  if (value.length > CATALOG_SURFACE_ORDER.length) return fail("too_many_entries");
  const result: Surface[] = [];
  let prior = -1;
  for (const item of value) {
    const index = CATALOG_SURFACE_ORDER.indexOf(item as Surface);
    if (index < 0) return fail("invalid_value");
    if (index <= prior) return fail(index === prior ? "duplicate_entry" : "invalid_order");
    result.push(CATALOG_SURFACE_ORDER[index]!);
    prior = index;
  }
  return { ok: true, value: result };
}

export function parseSignedOllamaIdentityV3(value: unknown): CatalogV3ParseResult<SignedOllamaIdentityV3> {
  const snapshot = snapshotForParse<SignedOllamaIdentityV3>(value); if (!snapshot.ok) return snapshot;
  value = snapshot.value;
  if (!isRecord(value)) return fail("invalid_type");
  const keys = exactKeys(value, IDENTITY_KEYS);
  if (keys) return fail(keys);
  if (value.registry !== OLLAMA_REGISTRY_V3) return fail("invalid_value");
  for (const key of ["namespace", "model", "tag"] as const) {
    if (typeof value[key] !== "string" || !matchesEntire(COMPONENT, value[key])) return fail("invalid_value");
  }
  if (!validDigest(value.ollama_manifest_sha256, true)) return fail("invalid_value");
  return { ok: true, value: {
    registry: OLLAMA_REGISTRY_V3,
    namespace: value.namespace as string,
    model: value.model as string,
    tag: value.tag as string,
    ollama_manifest_sha256: value.ollama_manifest_sha256,
  } };
}

const SPDX_LICENSES = new Map(SPDX_GENERATED_LICENSE_ROWS.map(([canonical, deprecated]) => [
  canonical.toLowerCase(),
  { canonical, deprecated },
]));
const SPDX_EXCEPTIONS = new Map(SPDX_GENERATED_EXCEPTION_ROWS.map(([canonical, deprecated]) => [
  canonical.toLowerCase(),
  { canonical, deprecated },
]));
export const SPDX_LICENSE_LIST_VERSION = "3.28.0";
/** Independent raw-byte trust root for schemas/schema-digests.json. */
export const CATALOG_V3_ASSET_DIGEST_MANIFEST_SHA256 = "2260260fdcd5dc5687e8328f2751fffdd38926b130e1ff340833d3ebee5c15b8";
export const SPDX_EXPRESSION_ABNF_SHA256 = "f449ffcf2e6d206442c11b77f8d47568a8ac5f0abeeb01eec16d68fceccb68fe";

type SpdxToken = { kind: "atom" | "op" | "lparen" | "rparen"; text: string };
// Sanctuary SPDX expression profile v1 is deliberately narrower than the
// complete SPDX 3.0.1 grammar. Its pinned ABNF requires horizontal whitespace
// around operators and accepts only all-uppercase or all-lowercase operator
// spellings. Listed IDs match case-insensitively, deprecated IDs refuse, and
// signed catalog values must already equal the canonical list spelling.
function tokenizeSpdx(source: string): SpdxToken[] | null {
  const tokens: SpdxToken[] = [];
  let index = 0;
  while (index < source.length) {
    if (source[index] === " " || source[index] === "\t") { index++; continue; }
    if (source[index] === "(" || source[index] === ")") {
      tokens.push({ kind: source[index] === "(" ? "lparen" : "rparen", text: source[index]! }); index++; continue;
    }
    let end = index;
    while (end < source.length && source[end] !== " " && source[end] !== "\t" && source[end] !== "(" && source[end] !== ")") end++;
    const text = source.slice(index, end);
    if (!text || /[\r\n]/.test(text)) return null;
    const kind = ["AND", "and", "OR", "or", "WITH", "with"].includes(text) ? "op" : "atom";
    if (kind === "op" && (index === 0 || end === source.length || !/[ \t]/.test(source[index - 1]!) || !/[ \t]/.test(source[end]!))) return null;
    tokens.push({ kind, text });
    index = end;
  }
  return tokens;
}

const IDSTRING = "[A-Za-z0-9.-]+";
const LICENSE_REF = new RegExp(`^(?:DocumentRef-${IDSTRING}:)?LicenseRef-${IDSTRING}$`);
const ADDITION_REF = new RegExp(`^(?:DocumentRef-${IDSTRING}:)?AdditionRef-${IDSTRING}$`);

function canonicalUserRef(value: string): string {
  const match = /^(?:(DocumentRef-)([A-Za-z0-9.-]+):)?(LicenseRef-|AdditionRef-)([A-Za-z0-9.-]+)$/.exec(value);
  if (!match) throw new TypeError("invalid SPDX user reference");
  const document = match[2] === undefined ? "" : `DocumentRef-${match[2].toLowerCase()}:`;
  return `${document}${match[3]}${match[4]!.toLowerCase()}`;
}

class SpdxParser {
  private cursor = 0;
  public constructor(private readonly tokens: readonly SpdxToken[]) {}
  public parse(): string | null {
    const value = this.parseOr();
    return value !== null && this.cursor === this.tokens.length ? value : null;
  }
  private peek(text?: string): SpdxToken | undefined {
    const token = this.tokens[this.cursor];
    return text === undefined || token?.text === text ? token : undefined;
  }
  private take(): SpdxToken | undefined { return this.tokens[this.cursor++]; }
  private parseOr(): string | null {
    let left = this.parseAnd(); if (left === null) return null;
    while (this.peek("OR") || this.peek("or")) { this.take(); const right = this.parseAnd(); if (right === null) return null; left = `${left} OR ${right}`; }
    return left;
  }
  private parseAnd(): string | null {
    let left = this.parseWith(); if (left === null) return null;
    while (this.peek("AND") || this.peek("and")) { this.take(); const right = this.parseWith(); if (right === null) return null; left = `${left} AND ${right}`; }
    return left;
  }
  private parseWith(): string | null {
    const left = this.parsePrimary(); if (left === null) return null;
    if (!(this.peek("WITH") || this.peek("with"))) return left;
    if (left.startsWith("(")) return null;
    this.take();
    const token = this.take();
    if (!token || token.kind !== "atom") return null;
    const exception = SPDX_EXCEPTIONS.get(token.text.toLowerCase());
    const addition = ADDITION_REF.test(token.text) ? canonicalUserRef(token.text) : null;
    return (exception && !exception.deprecated) || addition
      ? `${left} WITH ${exception?.canonical ?? addition}`
      : null;
  }
  private parsePrimary(): string | null {
    if (this.peek()?.kind === "lparen") {
      this.take(); const nested = this.parseOr();
      if (nested === null || this.peek()?.kind !== "rparen") return null;
      this.take(); return `(${nested})`;
    }
    const token = this.take();
    if (!token || token.kind !== "atom") return null;
    const plus = token.text.endsWith("+");
    const atom = plus ? token.text.slice(0, -1) : token.text;
    const listed = SPDX_LICENSES.get(atom.toLowerCase());
    if (listed && !listed.deprecated) return `${listed.canonical}${plus ? "+" : ""}`;
    if (!plus && LICENSE_REF.test(atom)) return canonicalUserRef(atom);
    return null;
  }
}

export function parseSpdxExpression(value: unknown): CatalogV3ParseResult<string> {
  // UTF-16 code units provide a cheap size preflight before allocating a UTF-8
  // encoding. The exact byte check follows only after the primitive string/type
  // boundary is closed.
  if (typeof value !== "string" || value === "custom" || value.length === 0
    || value.length > 128 || value.trim() !== value || /[\r\n]/.test(value)
    || stringToBytes(value).length > 128) return fail("invalid_spdx");
  const tokens = tokenizeSpdx(value);
  if (!tokens || tokens.length === 0) return fail("invalid_spdx");
  const canonical = new SpdxParser(tokens).parse();
  return canonical === null ? fail("invalid_spdx") : { ok: true, value: canonical };
}

function parseLicenseEvidence(value: unknown): CatalogV3ParseResult<LicenseEvidenceV3> {
  if (!isRecord(value)) return fail("invalid_type");
  const keys = exactKeys(value, LICENSE_REQUIRED_KEYS, ["custom_name"]);
  if (keys) return fail(keys);
  if (typeof value.spdx !== "string" || !validSourceUrl(value.source_url) || !validDigest(value.evidence_sha256, true)) return fail("invalid_value");
  if (value.spdx === "custom") {
    if (typeof value.custom_name !== "string" || value.custom_name.length < 1 || value.custom_name.length > 120 || !matchesEntire(ASCII_TEXT, value.custom_name)) return fail("invalid_value");
    return { ok: true, value: { spdx: "custom", custom_name: value.custom_name, source_url: value.source_url, evidence_sha256: value.evidence_sha256 } };
  }
  if (Object.hasOwn(value, "custom_name")) return fail("unknown_key");
  const spdx = parseSpdxExpression(value.spdx); if (!spdx.ok) return spdx;
  if (spdx.value !== value.spdx) return fail("invalid_spdx");
  return { ok: true, value: { spdx: spdx.value, source_url: value.source_url as string, evidence_sha256: value.evidence_sha256 } };
}

function parseTierTable(value: unknown): CatalogV3ParseResult<TierTableV3> {
  if (!isRecord(value)) return fail("invalid_type");
  const keys = exactKeys(value, TIER_TABLE_KEYS); if (keys) return fail(keys);
  if (value.schema !== "tier-table.v1" || !isRecord(value.tiers)) return fail("invalid_value");
  const tierKeys = exactKeys(value.tiers, HARDWARE_TIERS); if (tierKeys) return fail(tierKeys);
  const tiers = {} as Record<HardwareTier, TierSpecV3>;
  for (const tier of HARDWARE_TIERS) {
    const spec = value.tiers[tier]; if (!isRecord(spec)) return fail("invalid_type");
    const specKeys = exactKeys(spec, TIER_SPEC_KEYS); if (specKeys) return fail(specKeys);
    if (typeof spec.min_ram_gib !== "number" || !Number.isInteger(spec.min_ram_gib) || spec.min_ram_gib < 1 || spec.min_ram_gib > 4096 || typeof spec.description !== "string" || spec.description.length < 1 || spec.description.length > 120 || !matchesEntire(ASCII_TEXT, spec.description)) return fail("invalid_value");
    tiers[tier] = { min_ram_gib: spec.min_ram_gib, description: spec.description };
  }
  // Tier names are strict ordinal bands. Equality is rejected so two labels
  // cannot collapse to the same hardware threshold.
  if (!(tiers.baseline.min_ram_gib < tiers.mid.min_ram_gib
    && tiers.mid.min_ram_gib < tiers.pro.min_ram_gib)) {
    return fail("invalid_order");
  }
  return { ok: true, value: { schema: "tier-table.v1", tiers } };
}

function parseSurfaceDefaults(value: unknown): CatalogV3ParseResult<SurfaceDefaultsV3> {
  if (!isRecord(value)) return fail("invalid_type");
  const keys = exactKeys(value, SURFACE_DEFAULTS_KEYS); if (keys) return fail(keys);
  if (value.schema !== "surface-defaults.v1" || !isRecord(value.defaults)) return fail("invalid_value");
  const defaultKeys = exactKeys(value.defaults, CATALOG_SURFACE_ORDER); if (defaultKeys) return fail(defaultKeys);
  const defaults = {} as Record<Surface, SurfaceDefaultV3>;
  for (const surface of CATALOG_SURFACE_ORDER) {
    const candidate = value.defaults[surface]; if (!isRecord(candidate)) return fail("invalid_type");
    const candidateKeys = exactKeys(candidate, SURFACE_DEFAULT_KEYS); if (candidateKeys) return fail(candidateKeys);
    const tier = parseHardwareTier(candidate.tier); if (!tier.ok) return tier;
    const assurance = parseAssurance(candidate.assurance); if (!assurance.ok) return assurance;
    defaults[surface] = { tier: tier.value, assurance: assurance.value };
  }
  return { ok: true, value: { schema: "surface-defaults.v1", defaults } };
}

function identityTuple(identity: SignedOllamaIdentityV3): string { return `${identity.registry}\0${identity.namespace}\0${identity.model}\0${identity.tag}`; }
function runtimeTag(identity: SignedOllamaIdentityV3): string { return `${identity.namespace}/${identity.model}:${identity.tag}`; }

export function parseCatalogBodyV3(value: unknown): CatalogV3ParseResult<CatalogBodyV3> {
  const snapshot = snapshotForParse<CatalogBodyV3>(value); if (!snapshot.ok) return snapshot;
  value = snapshot.value;
  if (!isRecord(value)) return fail("invalid_type");
  const keys = exactKeys(value, CATALOG_BODY_KEYS); if (keys) return fail(keys);
  if (value.schema !== CATALOG_V3_DOMAIN || !positiveVersion(value.catalog_version) || !validTimestamp(value.issued_at) || typeof value.source_commit !== "string" || !matchesEntire(SOURCE_COMMIT, value.source_commit)) return fail("invalid_value");
  if (value.catalog_version === 1 ? value.previous_catalog_body_sha256 !== null : !validDigest(value.previous_catalog_body_sha256, true)) return fail("invalid_value");
  if (!Array.isArray(value.models)) return fail("invalid_type");
  if (value.models.length < 1) return fail("empty_collection");
  if (value.models.length > MAX_CATALOG_ENTRIES) return fail("too_many_entries");
  const models: CatalogModelEntryV3[] = [];
  const ids = new Set<string>(); const identities = new Set<string>(); const tags = new Set<string>();
  let priorId: string | null = null;
  for (const candidate of value.models) {
    if (!isRecord(candidate)) return fail("invalid_type");
    const candidateKeys = exactKeys(candidate, CATALOG_ENTRY_KEYS); if (candidateKeys) return fail(candidateKeys);
    const modelId = parseModelId(candidate.model_id); if (!modelId.ok) return modelId;
    if (priorId !== null && modelId.value <= priorId) return fail(modelId.value === priorId ? "duplicate_entry" : "invalid_order");
    const identity = parseSignedOllamaIdentityV3(candidate.identity); if (!identity.ok) return identity;
    const assurance = parseAssurance(candidate.assurance); if (!assurance.ok) return assurance;
    const license = parseLicenseEvidence(candidate.license); if (!license.ok) return license;
    const tier = parseHardwareTier(candidate.hardware_tier); if (!tier.ok) return tier;
    const tuple = identityTuple(identity.value); const tag = runtimeTag(identity.value);
    if (ids.has(modelId.value) || identities.has(tuple) || tags.has(tag)) return fail("duplicate_entry");
    ids.add(modelId.value); identities.add(tuple); tags.add(tag); priorId = modelId.value;
    models.push({ model_id: modelId.value, identity: identity.value, assurance: assurance.value, license: license.value, hardware_tier: tier.value });
  }
  const tiers = parseTierTable(value.tiers); if (!tiers.ok) return tiers;
  const defaults = parseSurfaceDefaults(value.surface_defaults); if (!defaults.ok) return defaults;
  if (canonicalizeJson(tiers.value) !== canonicalizeJson(TIER_TABLE_V3)
    || canonicalizeJson(defaults.value) !== canonicalizeJson(SURFACE_DEFAULTS_V3)) return fail("invalid_value");
  const body: CatalogBodyV3 = { schema: CATALOG_V3_DOMAIN, catalog_version: value.catalog_version, issued_at: value.issued_at, source_commit: value.source_commit, previous_catalog_body_sha256: value.previous_catalog_body_sha256 as string | null, models, tiers: tiers.value, surface_defaults: defaults.value };
  // Signatures are checked over the reconstructed, normalized body. Keep a
  // runtime completeness fence so a future accepted field cannot be omitted
  // from that signed preimage by an incomplete parser update.
  if (!canonicalReconstructionMatches(value, body)) return fail("invalid_value");
  if (!isDomainSignaturePreimageWithinLimit(CATALOG_V3_DOMAIN, body)) return fail("manifest_too_large");
  return { ok: true, value: body };
}

export function parseOverlayBodyV1(value: unknown): CatalogV3ParseResult<OverlayBodyV1> {
  const snapshot = snapshotForParse<OverlayBodyV1>(value); if (!snapshot.ok) return snapshot;
  value = snapshot.value;
  if (!isRecord(value)) return fail("invalid_type");
  const keys = exactKeys(value, OVERLAY_BODY_KEYS); if (keys) return fail(keys);
  if (value.schema !== OVERLAY_V1_DOMAIN || !positiveVersion(value.overlay_version) || typeof value.overlay_binding_id !== "string" || !matchesEntire(BINDING_ID, value.overlay_binding_id) || !validTimestamp(value.issued_at)) return fail("invalid_value");
  if (!Array.isArray(value.entries)) return fail("invalid_type");
  if (value.entries.length > MAX_OVERLAY_ENTRIES) return fail("too_many_entries");
  const entries: OverlayModelEntryV1[] = []; const ids = new Set<string>(); const identities = new Set<string>(); const tags = new Set<string>(); let priorId: string | null = null;
  for (const candidate of value.entries) {
    if (!isRecord(candidate)) return fail("invalid_type");
    const candidateKeys = exactKeys(candidate, OVERLAY_ENTRY_KEYS); if (candidateKeys) return fail(candidateKeys);
    const modelId = parseModelId(candidate.model_id); if (!modelId.ok) return modelId;
    if (priorId !== null && modelId.value <= priorId) return fail(modelId.value === priorId ? "duplicate_entry" : "invalid_order");
    const identity = parseSignedOllamaIdentityV3(candidate.identity); if (!identity.ok) return identity;
    const assurance = parseAssurance(candidate.assurance); if (!assurance.ok) return assurance;
    const surfaces = parseSurfaceList(candidate.surface_authorization); if (!surfaces.ok) return surfaces;
    const tuple = identityTuple(identity.value); const tag = runtimeTag(identity.value);
    if (ids.has(modelId.value) || identities.has(tuple) || tags.has(tag)) return fail("duplicate_entry");
    ids.add(modelId.value); identities.add(tuple); tags.add(tag); priorId = modelId.value;
    entries.push({ model_id: modelId.value, identity: identity.value, assurance: assurance.value, surface_authorization: surfaces.value });
  }
  const body: OverlayBodyV1 = { schema: OVERLAY_V1_DOMAIN, overlay_version: value.overlay_version, overlay_binding_id: value.overlay_binding_id, issued_at: value.issued_at, entries };
  if (!canonicalReconstructionMatches(value, body)) return fail("invalid_value");
  if (!isDomainSignaturePreimageWithinLimit(OVERLAY_V1_DOMAIN, body)) return fail("manifest_too_large");
  return { ok: true, value: body };
}

export function parseCatalogIndexBodyV1(value: unknown): CatalogV3ParseResult<CatalogIndexBodyV1> {
  const snapshot = snapshotForParse<CatalogIndexBodyV1>(value); if (!snapshot.ok) return snapshot;
  value = snapshot.value;
  if (!isRecord(value)) return fail("invalid_type");
  const keys = exactKeys(value, INDEX_BODY_KEYS); if (keys) return fail(keys);
  if (value.schema !== CATALOG_INDEX_V1_DOMAIN || !positiveVersion(value.index_version) || !positiveVersion(value.segment_number) || !positiveVersion(value.segment_base_index_version) || value.segment_base_index_version > value.index_version || !positiveVersion(value.first_catalog_version) || !positiveVersion(value.highest_catalog_version) || !validTimestamp(value.issued_at)) return fail("invalid_value");
  if (value.index_version === 1 ? value.previous_index_body_sha256 !== null : !validDigest(value.previous_index_body_sha256, true)) return fail("invalid_value");
  if (!Array.isArray(value.entries)) return fail("invalid_type");
  if (value.entries.length < 1) return fail("empty_collection");
  if (value.entries.length > MAX_INDEX_SEGMENT_ENTRIES) return fail("too_many_entries");
  const entries: CatalogIndexEntryV1[] = [];
  const releaseIds = new Set<number>();
  const assetIds = new Set<number>();
  const assetDigests = new Set<string>();
  for (let index = 0; index < value.entries.length; index++) {
    const entry = value.entries[index]; if (!isRecord(entry)) return fail("invalid_type");
    const entryKeys = exactKeys(entry, INDEX_ENTRY_KEYS); if (entryKeys) return fail(entryKeys);
    if (!positiveVersion(entry.catalog_version) || !positiveSafeInteger(entry.catalog_release_id) || !positiveSafeInteger(entry.catalog_asset_id) || !validDigest(entry.envelope_sha256, true) || !validDigest(entry.body_sha256, true) || !positiveVersion(entry.catalog_key_epoch)) return fail("invalid_value");
    if (index > 0 && entry.catalog_version !== entries[index - 1]!.catalog_version + 1) return fail("invalid_order");
    if (entry.envelope_sha256 === entry.body_sha256
      || releaseIds.has(entry.catalog_release_id)
      || assetIds.has(entry.catalog_asset_id)
      || assetDigests.has(entry.envelope_sha256)
      || assetDigests.has(entry.body_sha256)) return fail("duplicate_entry");
    releaseIds.add(entry.catalog_release_id);
    assetIds.add(entry.catalog_asset_id);
    assetDigests.add(entry.envelope_sha256);
    assetDigests.add(entry.body_sha256);
    entries.push({ catalog_version: entry.catalog_version, catalog_release_id: entry.catalog_release_id, catalog_asset_id: entry.catalog_asset_id, envelope_sha256: entry.envelope_sha256, body_sha256: entry.body_sha256, catalog_key_epoch: entry.catalog_key_epoch });
  }
  if (entries[0]!.catalog_version !== value.first_catalog_version || entries.at(-1)!.catalog_version !== value.highest_catalog_version) return fail("invalid_value");
  // Catalog and index versions start together at one and advance once per
  // publication. A segment snapshot therefore covers exactly the dense range
  // from its base index/catalog version through its current index/catalog
  // version. Cross-release append/rollover continuity remains an S5 concern.
  if (value.first_catalog_version !== value.segment_base_index_version
    || value.highest_catalog_version !== value.index_version
    || entries.length !== value.index_version - value.segment_base_index_version + 1
    || value.segment_number > value.segment_base_index_version
    || ((value.segment_number === 1) !== (value.segment_base_index_version === 1))) {
    return fail("invalid_value");
  }
  const body: CatalogIndexBodyV1 = { schema: CATALOG_INDEX_V1_DOMAIN, index_version: value.index_version, previous_index_body_sha256: value.previous_index_body_sha256 as string | null, segment_number: value.segment_number, segment_base_index_version: value.segment_base_index_version, first_catalog_version: value.first_catalog_version, highest_catalog_version: value.highest_catalog_version, issued_at: value.issued_at, entries };
  if (!canonicalReconstructionMatches(value, body)) return fail("invalid_value");
  if (!isDomainSignaturePreimageWithinLimit(CATALOG_INDEX_V1_DOMAIN, body)) return fail("manifest_too_large");
  return { ok: true, value: body };
}

function parseEnvelope<T>(value: unknown, bodyParser: (body: unknown) => CatalogV3ParseResult<T>, keyName: "signing_key_id" | "signer_key_id", keyPattern: RegExp): CatalogV3ParseResult<{ body: T; signature: string; keyId: string }> {
  const snapshot = snapshotForParse<{ body: T; signature: string; keyId: string }>(value); if (!snapshot.ok) return snapshot;
  value = snapshot.value;
  if (!isRecord(value)) return fail("invalid_type");
  const keys = exactKeys(value, keyName === "signing_key_id" ? ENVELOPE_KEYS : OVERLAY_ENVELOPE_KEYS); if (keys) return fail(keys);
  const body = bodyParser(value.body); if (!body.ok) return body;
  const keyId = value[keyName];
  if (typeof value.signature !== "string" || typeof keyId !== "string" || !matchesEntire(keyPattern, keyId)) return fail("invalid_value");
  if (value.signature.length !== ED25519_SIGNATURE_BASE64URL_CHARS) return fail("bad_signature_length");
  let signatureBytes: Uint8Array;
  try { signatureBytes = fromBase64urlStrict(value.signature); } catch { return fail("bad_signature_encoding"); }
  if (signatureBytes.length !== ED25519_SIGNATURE_BYTES) return fail("bad_signature_length");
  if (signatureBytes.every((byte) => byte === 0)) return fail("zero_signature");
  return { ok: true, value: { body: body.value, signature: value.signature, keyId } };
}

function parseUnverifiedSignedCatalogV3(value: unknown): CatalogV3ParseResult<SignedCatalogV3> {
  const parsed = parseEnvelope(value, parseCatalogBodyV3, "signing_key_id", CATALOG_KEY_ID); return parsed.ok ? { ok: true, value: { body: parsed.value.body, signature: parsed.value.signature, signing_key_id: parsed.value.keyId } } : parsed;
}
function parseUnverifiedSignedOverlayV1(value: unknown): CatalogV3ParseResult<SignedOverlayV1> {
  const parsed = parseEnvelope(value, parseOverlayBodyV1, "signer_key_id", OVERLAY_KEY_ID); return parsed.ok ? { ok: true, value: { body: parsed.value.body, signature: parsed.value.signature, signer_key_id: parsed.value.keyId } } : parsed;
}
function parseUnverifiedSignedCatalogIndexSegmentV1(value: unknown): CatalogV3ParseResult<SignedCatalogIndexSegmentV1> {
  const parsed = parseEnvelope(value, parseCatalogIndexBodyV1, "signing_key_id", CATALOG_KEY_ID); return parsed.ok ? { ok: true, value: { body: parsed.value.body, signature: parsed.value.signature, signing_key_id: parsed.value.keyId } } : parsed;
}

export function parseUntrustedCatalogContinuityObservationV3(value: unknown): CatalogV3ParseResult<UntrustedCatalogContinuityObservationV3> {
  const snapshot = snapshotForParse<UntrustedCatalogContinuityObservationV3>(value); if (!snapshot.ok) return snapshot;
  value = snapshot.value;
  if (!isRecord(value)) return fail("invalid_type");
  const keys = exactKeys(value, CATALOG_CONTINUITY_KEYS); if (keys) return fail(keys);
  if (value.status !== "observed" && value.status !== "revoked") return fail("invalid_value");
  const envelope = parseUnverifiedSignedCatalogV3(value.last_admitted_envelope); if (!envelope.ok) return envelope;
  if (!positiveVersion(value.last_admitted_catalog_version) || !validDigest(value.last_admitted_body_sha256, true) || (value.last_admitted_previous_body_sha256 !== null && !validDigest(value.last_admitted_previous_body_sha256, true)) || !positiveVersion(value.catalog_key_epoch) || !positiveVersion(value.catalog_version_floor)) return fail("invalid_value");
  if (value.last_admitted_catalog_version !== envelope.value.body.catalog_version || value.catalog_version_floor !== value.last_admitted_catalog_version || value.last_admitted_previous_body_sha256 !== envelope.value.body.previous_catalog_body_sha256 || value.last_admitted_body_sha256 !== computeCanonicalSha256(envelope.value.body) || envelope.value.signing_key_id !== `cat-epoch-${value.catalog_key_epoch}`) return fail("invalid_value");
  return { ok: true, value: { status: value.status, last_admitted_envelope: envelope.value, last_admitted_catalog_version: value.last_admitted_catalog_version, last_admitted_body_sha256: value.last_admitted_body_sha256, last_admitted_previous_body_sha256: value.last_admitted_previous_body_sha256, catalog_key_epoch: value.catalog_key_epoch, catalog_version_floor: value.catalog_version_floor } };
}

export function parseUntrustedCatalogIndexContinuityObservationV1(value: unknown): CatalogV3ParseResult<UntrustedCatalogIndexContinuityObservationV1> {
  const snapshot = snapshotForParse<UntrustedCatalogIndexContinuityObservationV1>(value); if (!snapshot.ok) return snapshot;
  value = snapshot.value;
  if (!isRecord(value)) return fail("invalid_type");
  const keys = exactKeys(value, INDEX_CONTINUITY_KEYS); if (keys) return fail(keys);
  if (value.index_continuity_status !== "observed" && value.index_continuity_status !== "revoked") return fail("invalid_value");
  const envelope = parseUnverifiedSignedCatalogIndexSegmentV1(value.index_envelope); if (!envelope.ok) return envelope;
  if (!positiveVersion(value.index_version_floor) || !validDigest(value.index_body_sha256, true) || !positiveVersion(value.index_key_epoch)) return fail("invalid_value");
  if (value.index_version_floor !== envelope.value.body.index_version || value.index_body_sha256 !== computeCanonicalSha256(envelope.value.body) || envelope.value.signing_key_id !== `cat-epoch-${value.index_key_epoch}`) return fail("invalid_value");
  return { ok: true, value: { index_continuity_status: value.index_continuity_status, index_envelope: envelope.value, index_version_floor: value.index_version_floor, index_body_sha256: value.index_body_sha256, index_key_epoch: value.index_key_epoch } };
}

function rejectNonIntegerNumberLexemes(text: string): boolean {
  let inString = false; let escaped = false;
  for (let index = 0; index < text.length; index++) {
    const char = text[index]!;
    if (inString) { if (escaped) escaped = false; else if (char === "\\") escaped = true; else if (char === '"') inString = false; continue; }
    if (char === '"') { inString = true; continue; }
    if (char === "-" || /[0-9]/.test(char)) {
      let end = index + 1; while (end < text.length && /[0-9eE+.-]/.test(text[end]!)) end++;
      const lexeme = text.slice(index, end);
      if (!/^(?:0|[1-9][0-9]*)$/.test(lexeme)) return true;
      index = end - 1;
    }
  }
  return false;
}

const MAX_CANONICAL_JSON_DEPTH = 64;

export function parseCatalogJson<T>(text: unknown, maxBytes: number, parser: (value: unknown) => CatalogV3ParseResult<T>): CatalogV3ParseResult<T> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) return fail("invalid_value");
  const boundedMaxBytes = Math.min(maxBytes, MAX_CATALOG_WIRE_JSON_BYTES);
  if (typeof text !== "string") return fail("invalid_type");
  // Reject obviously oversized input before allocating its UTF-8 encoding.
  // Every UTF-16 code unit contributes at least one UTF-8 byte.
  if (text.length > boundedMaxBytes) return fail("manifest_too_large");
  if (stringToBytes(text).length > boundedMaxBytes) return fail("manifest_too_large");
  if (rejectNonIntegerNumberLexemes(text)) return fail("invalid_value");
  let parsed: unknown;
  try { parsed = parseStrictJson(text); }
  catch (error) {
    if (error instanceof SubstrateError && error.reason === "json_duplicate_key") return fail("duplicate_key");
    if (error instanceof SubstrateError && error.reason === "json_prototype_key") return fail("prototype_key");
    return fail("malformed_json");
  }
  return parser(parsed);
}

function validUnicodeScalarString(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function canonicalizeJsonAtDepth(value: unknown, depth: number): string {
  if (depth > MAX_CANONICAL_JSON_DEPTH) throw new TypeError("canonical JSON depth exceeded");
  if (value === null) return "null";
  if (typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") {
    if (!validUnicodeScalarString(value)) throw new TypeError("non-I-JSON string");
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new TypeError("non-canonical JSON number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    const keys = Object.keys(value);
    if (keys.length !== value.length || keys.some((key, index) => key !== String(index))) {
      throw new TypeError("sparse or decorated array");
    }
    return `[${value.map((item) => canonicalizeJsonAtDepth(item, depth + 1)).join(",")}]`;
  }
  if (typeof value !== "object" || value === null || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) throw new TypeError("non-plain JSON object");
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => {
    if (!validUnicodeScalarString(key) || record[key] === undefined) throw new TypeError("invalid JSON member");
    return `${JSON.stringify(key)}:${canonicalizeJsonAtDepth(record[key], depth + 1)}`;
  }).join(",")}}`;
}

/** Bounded RFC 8785-compatible canonicalization for this integer-only wire contract. */
export function canonicalizeJson(value: unknown): string {
  const snapshot = snapshotJsonInput(value);
  if (!snapshot.ok) throw new TypeError("non-JSON input");
  return canonicalizeJsonAtDepth(snapshot.value, 0);
}

/** Freeze every node in a freshly parsed, signature-verified JSON envelope. */
function deepFreezeVerified<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== "object" || seen.has(value)) return value;
  seen.add(value);
  for (const nested of Object.values(value as Record<string, unknown>)) {
    deepFreezeVerified(nested, seen);
  }
  Object.freeze(value);
  return value;
}

export function buildDomainSignaturePreimage(domain: string, body: unknown): Uint8Array {
  return stringToBytes(`${domain}${SIGNATURE_DOMAIN_DELIMITER}${canonicalizeJson(body)}`);
}

export function isDomainSignaturePreimageWithinLimit(domain: unknown, body: unknown): boolean {
  if (typeof domain !== "string") return false;
  const limit = SIGNING_BODY_MAX_BYTES_BY_DOMAIN[domain];
  if (limit === undefined) return false;
  try {
    return buildDomainSignaturePreimage(domain, body).length <= limit;
  } catch {
    return false;
  }
}

/** Reject encodings outside the canonical, non-identity prime-order subgroup. */
function strictEd25519Point(bytes: Uint8Array): boolean {
  try {
    const point = ed25519.Point.fromBytes(bytes, false);
    if (!point.isTorsionFree() || point.isSmallOrder()) return false;
    return Buffer.from(point.toBytes()).equals(Buffer.from(bytes));
  } catch {
    return false;
  }
}

function verifyDomainSignature(domain: string, body: unknown, signature: string, pubkey: Uint8Array): CatalogV3ParseResult<true> {
  if (domain !== CATALOG_V3_DOMAIN && domain !== CATALOG_INDEX_V1_DOMAIN && domain !== OVERLAY_V1_DOMAIN) return fail("invalid_value");
  if (pubkey.length !== ED25519_PUBLIC_KEY_BYTES) return fail("bad_pinned_key_length");
  if (pubkey.every((byte) => byte === 0)) return fail("zero_pinned_key");
  let decoded: Uint8Array;
  try { decoded = fromBase64urlStrict(signature); } catch { return fail("bad_signature_encoding"); }
  if (decoded.length !== ED25519_SIGNATURE_BYTES) return fail("bad_signature_length");
  if (decoded.every((byte) => byte === 0)) return fail("zero_signature");
  if (!strictEd25519Point(pubkey) || !strictEd25519Point(decoded.subarray(0, 32))) {
    return fail("bad_signature");
  }
  let preimage: Uint8Array;
  try {
    const canonicalBody = canonicalizeJson(body);
    preimage = stringToBytes(`${domain}${SIGNATURE_DOMAIN_DELIMITER}${canonicalBody}`);
  } catch {
    return fail("invalid_value");
  }
  if (preimage.length > SIGNING_BODY_MAX_BYTES_BY_DOMAIN[domain]!) return fail("manifest_too_large");
  try {
    // zip215:false is the strict RFC 8032/FIPS 186-5 verifier. ZIP-215's
    // permissive point decoding is not part of any catalog signing contract.
    return ed25519.verify(decoded, preimage, pubkey, { zip215: false })
      ? { ok: true, value: true }
      : fail("bad_signature");
  } catch {
    return fail("bad_signature");
  }
}

interface PreparedCatalogKeyring {
  readonly epochs: readonly CatalogKeyEpoch[];
  readonly epochsById: Readonly<Record<string, CatalogKeyEpoch>>;
  readonly publicKeysById: Readonly<Record<string, Uint8Array>>;
}

interface CatalogVerificationAuthority {
  readonly keyringSha256: string;
}

interface OverlayVerificationAuthority {
  readonly signerKeyId: string;
}

let compiledPreparedCatalogKeyring: PreparedCatalogKeyring | null = null;

function prepareVerificationKeyring(
  keyring: readonly CatalogKeyEpoch[],
): CatalogV3ParseResult<PreparedCatalogKeyring> {
  if (keyring === COMPILED_CATALOG_KEYRING && compiledPreparedCatalogKeyring !== null) {
    return { ok: true, value: compiledPreparedCatalogKeyring };
  }
  return prepareCatalogKeyring(keyring);
}

function resolvePreparedCatalogSigningKey(
  keyring: PreparedCatalogKeyring,
  keyId: string,
  version: number,
  kind: "catalog" | "index",
): CatalogV3ParseResult<Uint8Array> {
  const epoch = keyring.epochsById[keyId];
  if (!epoch) return fail("unknown_signing_key");
  if (epoch.status === "revoked") return fail("signing_key_revoked");
  const minimum = kind === "catalog" ? epoch.min_catalog_version : epoch.min_index_version;
  const maximum = kind === "catalog" ? epoch.max_catalog_version : epoch.max_index_version;
  if (version < minimum || (maximum !== null && version > maximum)) return fail("signing_key_out_of_range");
  const pubkey = keyring.publicKeysById[keyId];
  return pubkey ? { ok: true, value: pubkey } : fail("bad_pinned_key_length");
}

const VERIFIED_CATALOG_ENVELOPES = new WeakMap<object, CatalogVerificationAuthority>();
const VERIFIED_CATALOG_BODIES = new WeakMap<object, CatalogVerificationAuthority>();
const VERIFIED_OVERLAY_ENVELOPES = new WeakMap<object, OverlayVerificationAuthority>();
const VERIFIED_OVERLAY_BODIES = new WeakMap<object, OverlayVerificationAuthority>();

function authenticateCatalogEnvelope(
  value: SignedCatalogV3,
  keyringSha256: string,
): CatalogV3ParseResult<SignedCatalogV3> {
  const frozen = deepFreezeVerified(value);
  const authority = Object.freeze({ keyringSha256 });
  VERIFIED_CATALOG_ENVELOPES.set(frozen, authority);
  VERIFIED_CATALOG_BODIES.set(frozen.body, authority);
  return deepFreezeVerified({ ok: true as const, value: frozen });
}

function authenticateOverlayEnvelope(
  value: SignedOverlayV1,
  signerKeyId: string,
): CatalogV3ParseResult<SignedOverlayV1> {
  const frozen = deepFreezeVerified(value);
  const authority = Object.freeze({ signerKeyId });
  VERIFIED_OVERLAY_ENVELOPES.set(frozen, authority);
  VERIFIED_OVERLAY_BODIES.set(frozen.body, authority);
  return deepFreezeVerified({ ok: true as const, value: frozen });
}

function authenticatedCatalogBody(value: unknown): CatalogV3ParseResult<{
  readonly body: CatalogBodyV3;
  readonly authority: CatalogVerificationAuthority;
}> {
  if (typeof value !== "object" || value === null) return fail("unauthenticated_input");
  const bodyAuthority = VERIFIED_CATALOG_BODIES.get(value);
  if (bodyAuthority) return { ok: true, value: { body: value as CatalogBodyV3, authority: bodyAuthority } };
  const envelopeAuthority = VERIFIED_CATALOG_ENVELOPES.get(value);
  if (envelopeAuthority) return { ok: true, value: { body: (value as SignedCatalogV3).body, authority: envelopeAuthority } };
  return fail("unauthenticated_input");
}

function authenticatedOverlayBody(value: unknown): CatalogV3ParseResult<{
  readonly body: OverlayBodyV1;
  readonly authority: OverlayVerificationAuthority;
}> {
  if (typeof value !== "object" || value === null) return fail("unauthenticated_input");
  const bodyAuthority = VERIFIED_OVERLAY_BODIES.get(value);
  if (bodyAuthority) return { ok: true, value: { body: value as OverlayBodyV1, authority: bodyAuthority } };
  const envelopeAuthority = VERIFIED_OVERLAY_ENVELOPES.get(value);
  if (envelopeAuthority) return { ok: true, value: { body: (value as SignedOverlayV1).body, authority: envelopeAuthority } };
  return fail("unauthenticated_input");
}

export function deriveCatalogKeyringSha256(
  keyring: readonly CatalogKeyEpoch[] = COMPILED_CATALOG_KEYRING,
): CatalogV3ParseResult<string> {
  const prepared = prepareVerificationKeyring(keyring);
  return prepared.ok
    ? { ok: true, value: computeCanonicalSha256(prepared.value.epochs) }
    : prepared;
}

export function deriveOverlaySignerKeyId(pubkey: Uint8Array): CatalogV3ParseResult<string> {
  let key: Uint8Array;
  try {
    if (!(pubkey instanceof Uint8Array)) {
      return fail("bad_pinned_key_length");
    }
    key = Uint8Array.prototype.slice.call(pubkey) as Uint8Array;
  } catch { return fail("bad_pinned_key_length"); }
  if (key.length !== ED25519_PUBLIC_KEY_BYTES) return fail("bad_pinned_key_length");
  if (key.every((byte) => byte === 0)) return fail("zero_pinned_key");
  if (!strictEd25519Point(key)) return fail("bad_signature");
  return { ok: true, value: toBase64url(createHash("sha256").update(key).digest()) };
}

export function verifyAndParseSignedCatalogV3(
  value: unknown,
  keyring: readonly CatalogKeyEpoch[] = COMPILED_CATALOG_KEYRING,
): CatalogV3ParseResult<SignedCatalogV3> {
  const envelope = parseUnverifiedSignedCatalogV3(value); if (!envelope.ok) return envelope;
  const stableKeyring = prepareVerificationKeyring(keyring); if (!stableKeyring.ok) return stableKeyring;
  const key = resolvePreparedCatalogSigningKey(stableKeyring.value, envelope.value.signing_key_id, envelope.value.body.catalog_version, "catalog");
  if (!key.ok) return key;
  const verified = verifyDomainSignature(CATALOG_V3_DOMAIN, envelope.value.body, envelope.value.signature, key.value);
  return verified.ok
    ? authenticateCatalogEnvelope(envelope.value, computeCanonicalSha256(stableKeyring.value.epochs))
    : verified;
}

export function verifyAndParseSignedCatalogIndexSegmentV1(
  value: unknown,
  keyring: readonly CatalogKeyEpoch[] = COMPILED_CATALOG_KEYRING,
): CatalogV3ParseResult<SignedCatalogIndexSegmentV1> {
  const envelope = parseUnverifiedSignedCatalogIndexSegmentV1(value); if (!envelope.ok) return envelope;
  const stableKeyring = prepareVerificationKeyring(keyring); if (!stableKeyring.ok) return stableKeyring;
  const key = resolvePreparedCatalogSigningKey(stableKeyring.value, envelope.value.signing_key_id, envelope.value.body.index_version, "index");
  if (!key.ok) return key;
  // Authenticate the index segment before allowing attacker-selected entry
  // epochs to drive even bounded policy lookup work.
  const verified = verifyDomainSignature(CATALOG_INDEX_V1_DOMAIN, envelope.value.body, envelope.value.signature, key.value);
  if (!verified.ok) return verified;
  for (const entry of envelope.value.body.entries) {
    const catalogKey = resolvePreparedCatalogSigningKey(stableKeyring.value, `cat-epoch-${entry.catalog_key_epoch}`, entry.catalog_version, "catalog");
    if (!catalogKey.ok) return catalogKey;
  }
  return deepFreezeVerified({ ok: true as const, value: envelope.value });
}

export function verifyAndParseSignedOverlayV1(
  value: unknown,
  operatorPublicKey: Uint8Array,
): CatalogV3ParseResult<SignedOverlayV1> {
  const envelope = parseUnverifiedSignedOverlayV1(value); if (!envelope.ok) return envelope;
  let stablePublicKey: Uint8Array;
  try {
    if (!(operatorPublicKey instanceof Uint8Array)) return fail("bad_pinned_key_length");
    stablePublicKey = Uint8Array.prototype.slice.call(operatorPublicKey) as Uint8Array;
  } catch { return fail("bad_pinned_key_length"); }
  const keyId = deriveOverlaySignerKeyId(stablePublicKey); if (!keyId.ok) return keyId;
  if (envelope.value.signer_key_id !== keyId.value) return fail("unknown_signing_key");
  const verified = verifyDomainSignature(OVERLAY_V1_DOMAIN, envelope.value.body, envelope.value.signature, stablePublicKey);
  return verified.ok ? authenticateOverlayEnvelope(envelope.value, keyId.value) : verified;
}

/** Strict wire entrypoint: duplicate keys and non-integer number spellings refuse before verification. */
export function verifyAndParseSignedCatalogJsonV3(
  text: unknown,
  keyring: readonly CatalogKeyEpoch[] = COMPILED_CATALOG_KEYRING,
): CatalogV3ParseResult<SignedCatalogV3> {
  return parseCatalogJson(text, MAX_CATALOG_WIRE_JSON_BYTES, (value) => (
    verifyAndParseSignedCatalogV3(value, keyring)
  ));
}

/** Strict wire entrypoint for a signed catalog-index segment. */
export function verifyAndParseSignedCatalogIndexJsonV1(
  text: unknown,
  keyring: readonly CatalogKeyEpoch[] = COMPILED_CATALOG_KEYRING,
): CatalogV3ParseResult<SignedCatalogIndexSegmentV1> {
  return parseCatalogJson(text, MAX_CATALOG_WIRE_JSON_BYTES, (value) => (
    verifyAndParseSignedCatalogIndexSegmentV1(value, keyring)
  ));
}

/** Strict wire entrypoint for a fortress-local signed operator overlay. */
export function verifyAndParseSignedOverlayJsonV1(
  text: unknown,
  operatorPublicKey: Uint8Array,
): CatalogV3ParseResult<SignedOverlayV1> {
  return parseCatalogJson(text, MAX_CATALOG_WIRE_JSON_BYTES, (value) => (
    verifyAndParseSignedOverlayV1(value, operatorPublicKey)
  ));
}

export function validateCatalogOverlayCombination(
  catalogValue: unknown,
  overlayValue: unknown,
  expectedOverlayBindingId: unknown,
  minimumOverlayVersionExclusive: unknown,
  expectedCatalogKeyringSha256: unknown,
  expectedOverlaySignerKeyId: unknown,
): CatalogV3ParseResult<true> {
  try {
    // Parsed structures are not authority. Only objects returned by this
    // module's successful signature verifiers carry the private identity
    // brands accepted at this combination boundary.
    const catalog = authenticatedCatalogBody(catalogValue); if (!catalog.ok) return catalog;
    const overlay = authenticatedOverlayBody(overlayValue); if (!overlay.ok) return overlay;
    if (!validDigest(expectedCatalogKeyringSha256, true)) return fail("invalid_value");
    if (typeof expectedOverlaySignerKeyId !== "string"
      || !matchesEntire(OVERLAY_KEY_ID, expectedOverlaySignerKeyId)) return fail("invalid_value");
    if (catalog.value.authority.keyringSha256 !== expectedCatalogKeyringSha256) {
      return fail("catalog_trust_root_mismatch");
    }
    if (overlay.value.authority.signerKeyId !== expectedOverlaySignerKeyId) {
      return fail("overlay_signer_mismatch");
    }
    if (typeof expectedOverlayBindingId !== "string" || !matchesEntire(BINDING_ID, expectedOverlayBindingId)) return fail("invalid_value");
    if (!Number.isSafeInteger(minimumOverlayVersionExclusive) || (minimumOverlayVersionExclusive as number) < 0) return fail("invalid_value");
    if (overlay.value.body.overlay_version <= (minimumOverlayVersionExclusive as number)) return fail("overlay_rollback");
    if (overlay.value.body.overlay_binding_id !== expectedOverlayBindingId) return fail("overlay_binding_mismatch");
    const catalogIds = new Set(catalog.value.body.models.map((model) => model.model_id));
    const catalogIdentities = new Set(catalog.value.body.models.map((model) => identityTuple(model.identity)));
    const catalogTags = new Set(catalog.value.body.models.map((model) => runtimeTag(model.identity)));
    for (const entry of overlay.value.body.entries) {
      if (catalogIds.has(entry.model_id)
        || catalogIdentities.has(identityTuple(entry.identity))
        || catalogTags.has(runtimeTag(entry.identity))) return fail("overlay_collision");
      for (const surface of entry.surface_authorization) {
        // entry.assurance is a label the FORTRESS OPERATOR self-asserts in the signed
        // overlay body, not a claim Sanctuary itself attests to or has independently
        // evidenced. The overlay signature (checked in authenticatedOverlayBody above)
        // proves the operator's key signed this label; it does not prove the model
        // actually meets that assurance tier. This comparison is therefore a LABEL
        // check against the compiled floor (can the operator's declared tier clear the
        // minimum this surface requires), never an evidence check that the tier is true.
        const floor = effectiveSurfaceFloor(surface, catalog.value.body.surface_defaults.defaults[surface].assurance);
        if (!assuranceAtLeast(entry.assurance, floor)) return fail("overlay_escalation");
      }
    }
    return { ok: true, value: true };
  } catch {
    // This boundary is public JavaScript, not only a TypeScript call site.
    // Exotic objects/getters must refuse rather than escape as an exception.
    return fail("invalid_value");
  }
}

function assuranceAtLeast(actual: Assurance, minimum: Assurance): boolean {
  return ASSURANCE_RANK[actual] >= ASSURANCE_RANK[minimum];
}

export function effectiveSurfaceFloor(surface: Surface, catalogDefault: Assurance): Assurance {
  return assuranceAtLeast(catalogDefault, COMPILED_SURFACE_ASSURANCE_FLOOR[surface]) ? catalogDefault : COMPILED_SURFACE_ASSURANCE_FLOOR[surface];
}

export function computeCanonicalSha256(value: unknown): string {
  return createHash("sha256").update(stringToBytes(canonicalizeJson(value))).digest("hex");
}

/**
 * Hash only the module-owned generated SPDX tuple shape. This deliberately
 * does not share the hostile-input snapshot node budget with public parsers:
 * integrity of the complete vendored table remains checked even if that
 * public denial-of-service budget changes later.
 */
function computeTrustedSpdxTableSha256(): string {
  const trustedRowsJson = (rows: readonly (readonly [string, boolean])[]): string => {
    const encoded: string[] = [];
    for (const row of rows) {
      if (!Array.isArray(row) || row.length !== 2 || typeof row[0] !== "string"
        || typeof row[1] !== "boolean" || !Object.isFrozen(row)) {
        throw new Error("invalid generated SPDX row");
      }
      encoded.push(`[${JSON.stringify(row[0])},${row[1] ? "true" : "false"}]`);
    }
    return `[${encoded.join(",")}]`;
  };
  if (!Object.isFrozen(SPDX_GENERATED_LICENSE_ROWS)
    || !Object.isFrozen(SPDX_GENERATED_EXCEPTION_ROWS)) {
    throw new Error("generated SPDX row arrays must be frozen");
  }
  const canonical = `{"exceptions":${trustedRowsJson(SPDX_GENERATED_EXCEPTION_ROWS)},"licenses":${trustedRowsJson(SPDX_GENERATED_LICENSE_ROWS)}}`;
  return createHash("sha256").update(stringToBytes(canonical)).digest("hex");
}

function prepareCatalogKeyring(keyring: unknown): CatalogV3ParseResult<PreparedCatalogKeyring> {
  const snapshot = snapshotForParse<readonly CatalogKeyEpoch[]>(keyring); if (!snapshot.ok) return snapshot;
  if (!Array.isArray(snapshot.value) || snapshot.value.length < 1) return fail("invalid_value");
  const epochs: CatalogKeyEpoch[] = [];
  const decodedPublicKeys = new Set<string>();
  const publicKeysById: Record<string, Uint8Array> = Object.create(null) as Record<string, Uint8Array>;
  for (let index = 0; index < snapshot.value.length; index++) {
    const candidate = snapshot.value[index];
    if (!isRecord(candidate) || exactKeys(candidate, CATALOG_KEY_EPOCH_KEYS)) return fail("invalid_value");
    const epoch = candidate as unknown as CatalogKeyEpoch;
    const prior = epochs[index - 1];
    if (epoch.epoch !== index + 1 || epoch.signing_key_id !== `cat-epoch-${epoch.epoch}` || !positiveVersion(epoch.min_catalog_version) || !positiveVersion(epoch.min_index_version)) return fail("invalid_value");
    if (epoch.status !== "active" && epoch.status !== "retired" && epoch.status !== "revoked") return fail("invalid_value");
    if (typeof epoch.pubkey !== "string") return fail("invalid_value");
    try {
      const pubkey = fromBase64urlStrict(epoch.pubkey);
      if (pubkey.length !== ED25519_PUBLIC_KEY_BYTES
        || pubkey.every((byte) => byte === 0)
        || !strictEd25519Point(pubkey)) return fail("invalid_value");
      const fingerprint = Buffer.from(pubkey).toString("hex");
      if (decodedPublicKeys.has(fingerprint)) return fail("invalid_value");
      decodedPublicKeys.add(fingerprint);
      publicKeysById[epoch.signing_key_id] = pubkey;
    } catch { return fail("invalid_value"); }
    const last = index === snapshot.value.length - 1;
    if (last !== (epoch.status === "active") || last !== (epoch.max_catalog_version === null) || last !== (epoch.max_index_version === null)) return fail("invalid_value");
    if (!last && (!positiveVersion(epoch.max_catalog_version) || epoch.max_catalog_version < epoch.min_catalog_version || !positiveVersion(epoch.max_index_version) || epoch.max_index_version < epoch.min_index_version)) return fail("invalid_value");
    if (prior && (epoch.min_catalog_version !== prior.max_catalog_version! + 1 || epoch.min_index_version !== prior.max_index_version! + 1)) return fail("invalid_value");
    epochs.push({
      epoch: epoch.epoch,
      signing_key_id: epoch.signing_key_id,
      pubkey: epoch.pubkey,
      min_catalog_version: epoch.min_catalog_version,
      max_catalog_version: epoch.max_catalog_version,
      min_index_version: epoch.min_index_version,
      max_index_version: epoch.max_index_version,
      status: epoch.status,
    });
  }
  const frozenEpochs = deepFreezeVerified(epochs);
  const epochsById: Record<string, CatalogKeyEpoch> = Object.create(null) as Record<string, CatalogKeyEpoch>;
  for (const epoch of frozenEpochs) epochsById[epoch.signing_key_id] = epoch;
  // These null-prototype, frozen lookups are built once per custom-keyring
  // preparation; the compiled keyring is cached at module initialization.
  // Entry epoch resolution is O(1) and never re-snapshots the keyring.
  return {
    ok: true,
    value: Object.freeze({
      epochs: frozenEpochs,
      epochsById: Object.freeze(epochsById),
      publicKeysById: Object.freeze(publicKeysById),
    }),
  };
}

export function validateCatalogKeyring(keyring: unknown): CatalogV3ParseResult<readonly CatalogKeyEpoch[]> {
  const prepared = prepareCatalogKeyring(keyring);
  return prepared.ok
    ? deepFreezeVerified({ ok: true as const, value: prepared.value.epochs })
    : prepared;
}

export const COMPILED_CATALOG_KEY_POLICY_DIGEST = "cdc2dce6bbec11b5c931ce8a4953c66266d10d597117843aa64fa99c9384e4c8";
/** Independent reviewed digest of the generated SPDX table contents. */
export const COMPILED_SPDX_TABLE_SHA256 = "57914b8e1024c570695c621267e3462691dc0829afe5ad773113cc9fa616d7c1";

// A malformed compiled policy is a build/startup defect, never a recoverable input error.
const preparedCompiledKeyring = prepareCatalogKeyring(COMPILED_CATALOG_KEYRING);
if (!preparedCompiledKeyring.ok) throw new Error("invalid compiled catalog keyring");
compiledPreparedCatalogKeyring = preparedCompiledKeyring.value;
if (computeCanonicalSha256(COMPILED_CATALOG_KEYRING) !== COMPILED_CATALOG_KEY_POLICY_DIGEST) throw new Error("compiled catalog key policy digest mismatch");
if (canonicalizeJson(CATALOG_SURFACE_ORDER) !== canonicalizeJson(SURFACES)) throw new Error("catalog surface order drift");
if (SPDX_GENERATED_LIST_VERSION !== SPDX_LICENSE_LIST_VERSION) throw new Error("SPDX list version mismatch");
if (SPDX_GENERATED_TABLE_SHA256 !== COMPILED_SPDX_TABLE_SHA256
  || computeTrustedSpdxTableSha256() !== COMPILED_SPDX_TABLE_SHA256) {
  throw new Error("SPDX runtime table integrity mismatch");
}
