/**
 * Sanctuary MCP Server - L1 Cognitive Sovereignty: StateStore
 *
 * The encrypted state store is the foundation of Sanctuary.
 * Every read and write goes through here. All data is encrypted
 * with namespace-specific keys. All writes are signed by an identity.
 * All reads verify integrity via Merkle proofs.
 *
 * Security invariants:
 * - Plaintext never touches the filesystem
 * - Every write gets a unique IV
 * - Every write is signed (non-repudiation)
 * - Monotonic version numbers prevent rollback
 * - Merkle tree verifies namespace integrity
 * - Secure deletion overwrites before unlinking
 */

import type { StorageBackend } from "../storage/interface.js";
import { ed25519 } from "@noble/curves/ed25519";
import {
  encrypt,
  decrypt,
  type EncryptedPayload,
} from "../core/encryption.js";
import {
  hashToString,
  hmacSha256,
  computeMerkleRoot,
  generateMerkleProof,
  verifyMerkleProof,
} from "../core/hashing.js";
import { sign, verify } from "../core/identity.js";
import { deriveNamespaceKey } from "../core/key-derivation.js";
import {
  toBase64url,
  fromBase64url,
  stringToBytes,
  bytesToString,
} from "../core/encoding.js";
import type { EncryptedPayload as EncPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import type { StoredIdentity } from "../core/identity.js";
import { verifyRotationChain } from "../core/rotation-chain.js";
// Every field of a persisted entry is attacker-influenced: `JSON.parse` gives
// back whatever is on disk, so `StateEntry` is an assertion, not a guarantee.
// Diagnostics built from those fields go through this chokepoint, never a bare
// template interpolation (STATE-STORE-ERRMSG-INTERP-01); see the invariant in
// `errors/untrusted-diagnostic.ts`.
import { describeUntrusted } from "../errors/index.js";
import {
  mintProvenanceStamp,
  serializeStamp,
  type DerivedFromEdge,
  type OriginActor,
  type ProvenanceStamp,
  type SealedProvenanceStamp,
} from "../exit/memory-class.js";

const LEGACY_STATE_ENVELOPE_SCHEMA_VERSION = 2;
const STATE_ENVELOPE_SCHEMA_VERSION = 3;
const LEGACY_STATE_ENVELOPE_SIGNING_DOMAIN = "sanctuary.state-envelope.v1\n";
const STATE_ENVELOPE_SIGNING_DOMAIN_PREFIX = "sanctuary.state-envelope.v";
const STATE_ENVELOPE_PUBLIC_KEYS_KEY = "state-envelope-public-keys-v1";
const STATE_ENVELOPE_VERSION_ANCHORS_KEY = "state-envelope-version-anchors-v1";
// F1: domain-separated MAC over the version-anchor record (the rollback floor),
// which is stored plaintext. Without authentication a filesystem adversary could
// silently EDIT/LOWER a key's floor to defeat the #391 leapfrog gate; the MAC
// makes such an edit detectable (verification fails -> the read is rejected). The
// MAC binds the `_meta` key so the record cannot be replayed under another key.
// Scope note: this authenticates the version anchor only. The writer-public-key
// registry (`state-envelope-public-keys-v1`) is a plaintext legacy/migration
// hint. It is deliberately not a verification basis: read verification accepts
// only keys authenticated by `_identities` and its signed rotation history.
const STATE_META_MAC_DOMAIN = "sanctuary.meta-record-mac.v1\n";
// Distinctive envelope marker so a MAC'd record is unambiguously distinguished
// from a legacy bare record (legacy keys are versionKeys, never this).
const STATE_META_MAC_MARKER = "__sanctuary_meta_mac_v1";
const FACADE_HIDDEN_MARKER_NAMESPACE = "_facade/hidden";
const STATE_EXPORT_FORMAT = "sanctuary-v1";
const STATE_EXPORT_BUNDLE_SCHEMA_VERSION = 1;
const STATE_EXPORT_COMPLETENESS_MANIFEST_SCHEMA_VERSION = 1;
const STATE_EXPORT_BUNDLE_INTEGRITY_SCHEMA_VERSION = 1;
const STATE_EXPORT_BUNDLE_MAC_PURPOSE = "state-export-bundle-mac-v1";
const STATE_EXPORT_BUNDLE_MAC_DOMAIN =
  "sanctuary.state-export-bundle.v1\n";
const STATE_EXPORT_BUNDLE_MAC_COVERAGE =
  "sanctuary-v1-body-and-completeness-manifest";
const STATE_EXPORT_LEGACY_REJECT_MESSAGE =
  "export predates completeness verification; re-export, or re-run with allow_unverified_legacy to import without completeness guarantees";
const ISO_8601_TIMESTAMP_RE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(Z|([+-])(\d{2}):(\d{2}))$/;

export interface StateExportNamespaceManifest {
  item_count: number;
  content_sha256: string;
}

export interface StateExportCompletenessManifest {
  schema_version: number;
  format: string;
  exported_at: string;
  namespaces: string[];
  namespace_count: number;
  total_keys: number;
  namespace_items: Record<string, StateExportNamespaceManifest>;
}

export type StateExportCompletenessVerification =
  | "verified"
  | "unverified-completeness-legacy-bundle";

interface ExportedStateItem {
  key: string;
  entry: StateEntry;
}

type StateExportData = Record<string, ExportedStateItem[]>;
type StateExportBundle = Record<string, unknown>;

export type StateVerificationClassification =
  | "signature_mismatch"
  | "kid_unknown"
  | "integrity_hash_mismatch"
  | "schema_mismatch"
  | "rollback_detected"
  // "the writer could not be established", which is a DISTINCT answer from all
  // four above and must never be collapsed into one of them: the bytes are
  // intact (not `integrity_hash_mismatch`), no signature was examined and found
  // wrong (not `signature_mismatch`), the shape parsed (not `schema_mismatch`),
  // and the version is at or above its floor (not `rollback_detected`). It is
  // also distinct from `kid_unknown`, which a signed-envelope (v2+) read raises
  // when key resolution fails outright; this one is raised by the enforcing read
  // path when verification was REQUESTED and finished without establishing a
  // writer. A caller that treats them as the same value loses the one
  // distinction that tells it a migration, not a repair, is the remedy.
  | "writer_unverified"
  // "the writer COULD be established, so this caller asked the wrong path".
  // Raised only by the operator disclosure surface, which serves exactly the
  // entries the enforcing read refuses and refuses everything else, so it can
  // never become a way to skip verification on an entry that does not need it.
  // Distinct from every value above because nothing failed: this is a refusal
  // to bypass a control that would have succeeded.
  | "writer_is_establishable";

export class StateVerificationError extends Error {
  readonly classification: StateVerificationClassification;

  constructor(classification: StateVerificationClassification, message: string) {
    super(message);
    this.name = "StateVerificationError";
    this.classification = classification;
  }
}

function parseExportBundleObject(bundleBase64: string): StateExportBundle {
  const bundleBytes = fromBase64url(bundleBase64);
  const bundleJson = bytesToString(bundleBytes);
  const parsed = JSON.parse(bundleJson) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("export bundle is malformed");
  }
  return parsed as StateExportBundle;
}

function assertSupportedExportBundleSchema(bundle: StateExportBundle): void {
  const schemaVersion = bundle.sanctuary_export_version;
  if (
    typeof schemaVersion === "number" &&
    schemaVersion > STATE_EXPORT_BUNDLE_SCHEMA_VERSION
  ) {
    throw new StateVerificationError(
      "schema_mismatch",
      "State export bundle schema version is newer than this build supports"
    );
  }
}

function readExportData(bundle: StateExportBundle): StateExportData {
  const data = bundle.data;
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("export bundle data is malformed");
  }

  const result: StateExportData = {};
  for (const [namespace, entries] of Object.entries(data)) {
    if (!Array.isArray(entries)) {
      throw new Error("export bundle namespace entries are malformed");
    }
    result[namespace] = entries.map((item) => {
      if (!item || typeof item !== "object" || Array.isArray(item)) {
        throw new Error("export bundle entry is malformed");
      }
      const record = item as Record<string, unknown>;
      if (
        typeof record.key !== "string" ||
        !record.entry ||
        typeof record.entry !== "object" ||
        Array.isArray(record.entry)
      ) {
        throw new Error("export bundle entry is malformed");
      }
      return {
        key: record.key,
        entry: record.entry as StateEntry,
      };
    });
  }
  return result;
}

function assertBundleNamespaceMetadataMatches(
  bundle: StateExportBundle,
  data: StateExportData
): string[] {
  const actualNamespaces = Object.keys(data).sort();
  if (Array.isArray(bundle.namespaces)) {
    if (!bundle.namespaces.every((namespace) => typeof namespace === "string")) {
      throw new Error("export bundle namespace metadata is invalid");
    }
    const declaredNamespaces = [...bundle.namespaces].sort();
    if (JSON.stringify(declaredNamespaces) !== JSON.stringify(actualNamespaces)) {
      throw new Error("export bundle namespace metadata does not match data");
    }
  }
  return actualNamespaces;
}

export function decodeExportBundleNamespaces(bundleBase64: string): string[] {
  const bundle = parseExportBundleObject(bundleBase64);
  assertSupportedExportBundleSchema(bundle);
  const data = readExportData(bundle);
  return assertBundleNamespaceMetadataMatches(bundle, data);
}

function parseFacadeHiddenMarker(raw: Uint8Array): { namespace: string; key: string } | null {
  try {
    const marker = JSON.parse(bytesToString(raw)) as Record<string, unknown>;
    if (typeof marker.namespace !== "string" || typeof marker.key !== "string") return null;
    return { namespace: marker.namespace, key: marker.key };
  } catch {
    return null;
  }
}

export class LegacyEnvelopeWarning extends Error {
  readonly classification = "legacy_schema_1";

  constructor(message: string) {
    super(message);
    this.name = "LegacyEnvelopeWarning";
  }
}

export interface LegacyEnvelopeWarningInfo {
  name: "LegacyEnvelopeWarning";
  classification: "legacy_schema_1";
  message: string;
}

export interface SignedStateEnvelope {
  namespace: string;
  key: string;
  version: number;
  kid: string;
  metadata: {
    timestamp: string;
    schema_version: number;
    content_type?: string;
    ttl_seconds?: number;
    tags?: string[];
  };
  provenance_stamp?: ProvenanceStamp;
  integrity_hash: string;
  payload: {
    schema_version: number;
    algo: string;
    nonce: string;
    tag: string;
    ciphertext: string;
    encrypted_at: string;
  };
}

/**
 * Reserved namespace prefixes - used by internal subsystems.
 * Imported bundles MUST NOT write to these namespaces.
 *
 * RESERVED-NS-DIVERGE-01: this is the single source of truth for the curated
 * list. `cognitive/tools.ts` imports this list and `isReservedNamespace`;
 * `exit/bundle.ts` imports only `isReservedNamespace`. Neither keeps its own
 * copy, so the list cannot drift between call sites again. A structure test
 * (`test/structure/reserved-namespace-single-source.test.ts`) fails the build
 * if a second `const`/`let`/`var` array-literal or `new Set([...])`
 * initializer named `RESERVED_NAMESPACE_PREFIXES` (with or without a type
 * annotation) appears in any `.ts` file under `server/src`. It cannot catch a
 * copy under a different name, in a non-`.ts` file, or outside `server/src` -
 * see the test file's own scope note on the assertion that enforces this.
 */
export const RESERVED_NAMESPACE_PREFIXES = [
  "_identities",
  "_policies",
  "_audit",
  "_meta",
  "_principal",
  "_commitments",
  "_reputation",
  "_escrow",
  "_guarantees",
  "_bridge",
  "_federation",
  "_handshake",
  "_shr",
  "_sovereignty_profile",
  "_context_gate_policies",
  "_fortress_mode",
  "_facade",
  "_file_grants",
  "_castle_wall_observe",
] as const;

/**
 * Check whether a namespace is reserved (internal subsystem use only).
 * External callers MUST NOT read, write, list, or import these namespaces.
 *
 * RESERVED-NS-DIVERGE-01: the underscore prefix IS the contract, not the
 * curated list above - this predicate must stay correct on its own so a
 * caller who forgets to also spell `namespace.startsWith("_")` inline is
 * still safe. `RESERVED_NAMESPACE_PREFIXES` exists only to give callers that
 * want a precise label (see `getReservedNamespaceViolation` directly below)
 * something to match against; it is never the boundary itself.
 */
export function isReservedNamespace(namespace: string): boolean {
  return namespace.startsWith("_");
}

/**
 * Reserved-namespace check that also reports WHICH curated prefix matched.
 * Returns the matching reserved prefix, or null if the namespace is safe.
 *
 * RESERVED-NS-DIVERGE-01: this lives beside `RESERVED_NAMESPACE_PREFIXES` and
 * `isReservedNamespace` rather than in a consumer, because it is the same
 * contract wearing a different return type, and a label lookup that drifts from
 * the predicate it labels is the divergence that register id names. It adds
 * only the precise-label lookup that `isReservedNamespace`'s boolean return
 * cannot carry; the boundary is still the predicate. A non-curated `_foo` is
 * still reserved (it falls through to returning the namespace itself) because
 * `isReservedNamespace` applies the blanket underscore rule regardless of
 * curation.
 */
export function getReservedNamespaceViolation(namespace: string): string | null {
  if (!isReservedNamespace(namespace)) return null;
  for (const prefix of RESERVED_NAMESPACE_PREFIXES) {
    if (namespace === prefix || namespace.startsWith(prefix + "/")) {
      return prefix;
    }
  }
  return namespace;
}

/** On-disk format for an encrypted state entry */
export interface StateEntry {
  /** Format version. v1 is legacy signed-ciphertext-only; v2+ signs the full envelope. */
  v: number;
  /** Canonical state envelope signed by envelope_sig. */
  envelope?: SignedStateEnvelope;
  /** Encrypted payload */
  payload: EncryptedPayload;
  /** Version number (monotonically increasing) */
  ver: number;
  /** Legacy-compatible signature over ciphertext by the writing identity (base64url) */
  sig: string;
  /** Signature over the canonical envelope by the writing identity (base64url) */
  envelope_sig?: string;
  /**
   * Schema-3 user-state provenance stamp. Present only on new writes after
   * Exit Slice 2. Legacy schema-2 entries intentionally remain unstamped.
   */
  provenance_stamp?: ProvenanceStamp;
  /** Identity that wrote this entry */
  kid: string;
  /** SHA-256 of the plaintext value (base64url, for client-side verification) */
  integrity_hash: string;
  /** Metadata */
  metadata: {
    content_type?: string;
    ttl_seconds?: number;
    tags?: string[];
    schema_version?: number;
    written_at: string;
  };
}

export type WriterPublicKeyTrustBasis = "authenticated" | "unauthenticated";

export interface ResolvedWriterPublicKey {
  publicKey: Uint8Array;
  publicKeyBase64url: string;
  trustBasis: WriterPublicKeyTrustBasis;
  source:
    | "identity-current"
    | "identity-rotation-chain"
    | "plaintext-registry";
}

function appendResolvedWriterKey(
  keys: ResolvedWriterPublicKey[],
  seen: Set<string>,
  publicKeyBase64url: string,
  source: ResolvedWriterPublicKey["source"],
  trustBasis: WriterPublicKeyTrustBasis
): boolean {
  if (seen.has(publicKeyBase64url)) return true;
  try {
    const publicKey = fromBase64url(publicKeyBase64url);
    keys.push({ publicKey, publicKeyBase64url, trustBasis, source });
    seen.add(publicKeyBase64url);
    return true;
  } catch {
    return false;
  }
}

export function resolveAuthenticatedIdentityWriterPublicKeys(
  identity: StoredIdentity
): ResolvedWriterPublicKey[] {
  const keys: ResolvedWriterPublicKey[] = [];
  const seen = new Set<string>();
  const result = verifyRotationChain({
    identityId: identity.identity_id,
    currentPublicKey: identity.public_key,
    rotationHistory: identity.rotation_history,
  });
  if (result.status !== "verified") return [];

  for (const retired of [...result.chain.retired].reverse()) {
    if (
      !appendResolvedWriterKey(
        keys,
        seen,
        retired.public_key_base64url,
        "identity-rotation-chain",
        "authenticated"
      )
    ) {
      return [];
    }
  }
  return appendResolvedWriterKey(
    keys,
    seen,
    identity.public_key,
    "identity-current",
    "authenticated"
  )
    ? keys
    : [];
}

/** Result of a state write operation */
export interface WriteResult {
  key: string;
  namespace: string;
  version: number;
  merkle_root: string;
  written_at: string;
  size_bytes: number;
  integrity_hash: string;
}

/** Result of a state read operation */
export interface ReadResult {
  key: string;
  namespace: string;
  value: string;
  version: number;
  integrity_verified: boolean;
  signature_verified: boolean;
  merkle_proof: string[];
  written_at: string;
  written_by: string;
  warnings?: LegacyEnvelopeWarningInfo[];
}

/**
 * The exact sentence an unattributed disclosure carries at every layer. Single
 * source so the MCP tool description, the returned shape, and the CLI banner
 * cannot drift into three different strengths of the same warning; a drift
 * guard test pins that all three carry it. Written as an operator-facing
 * CAPABILITY BOUND, never as a defect description (AGENTS.md MUST-NEVER #9):
 * it states what this content is not, and what the real remedy is.
 */
export const UNATTRIBUTED_DISCLOSURE_NOTICE =
  "UNATTRIBUTED CONTENT. The writer of this entry could not be established, " +
  "so nothing here attests who wrote it or that it is unchanged since it was " +
  "written. It is not a verified read and must not be treated as one. The real " +
  "remedy is to restore the writer identity into this fortress, after which the " +
  "ordinary read verifies the entry and migrates it in place. This surface " +
  "exists for an owner who no longer holds that identity and would otherwise " +
  "have no route to their own content.";

/**
 * Result of an operator-approved unattributed disclosure.
 *
 * STRUCTURALLY DISTINCT FROM `ReadResult`, AND THAT IS THE WHOLE POINT. The
 * alternative design was `ReadResult` with a flag attached, which is the shape
 * this store just finished removing: a flag that one consumer inspected and
 * every other one dropped is indistinguishable from no flag at all, so the safe
 * outcome depended on every future caller remembering it. The type system, not
 * a convention, has to be what separates unverified content from verified
 * content.
 *
 * The separation is enforced in BOTH directions, so neither type is assignable
 * to the other and no cast-free mix-up is possible:
 *
 *   - this type has no `value`, no `signature_verified`, no `written_by`, and
 *     no `merkle_proof`, all of which `ReadResult` REQUIRES, so an
 *     `UnattributedStateDisclosure` can never be passed where a `ReadResult` is
 *     expected;
 *   - this type REQUIRES `disclosure_kind` and `writer`, which `ReadResult`
 *     does not have, so a `ReadResult` can never be passed where an
 *     `UnattributedStateDisclosure` is expected.
 *
 * `writer` is a single-inhabitant literal rather than a boolean on purpose:
 * there is no `true` spelling of it to drift to, and no consumer can flip it.
 *
 * TWO DIFFERENT PROPERTIES, TWO DIFFERENT PINS, AND THE SECOND ONE IS THE
 * SECURITY ARGUMENT. Mutual NON-ASSIGNABILITY and "this type carries no
 * `value`" are not the same statement, and pinning only the first leaves the
 * second protected by nothing:
 *
 *   - non-assignability is pinned by the paired `@ts-expect-error` directives
 *     in `test/cognitive/state-disclose-unattributed.test.ts`. On its own that
 *     pin is SATISFIED BY THE OTHER MISSING FIELDS. An adversarial gate on this
 *     change added `readonly value: string` here and populated it, and added
 *     `readonly value?: string` here and did not, and BOTH kept
 *     `npm run typecheck` green: the type still lacked `signature_verified`,
 *     `merkle_proof` and `integrity_verified`, so it was still non-assignable
 *     to `ReadResult` and the directives stayed "used";
 *   - the ABSENCE of the verified-read spellings is pinned by
 *     `DisclosureWithoutVerifiedReadFields` directly below, which
 *     `readUnattributed` constructs through. That alias collapses to `never`
 *     the moment any of those key names appears on this interface - required or
 *     optional, populated or not - so the construction site stops compiling.
 *     It is checked by `tsc --noEmit` over `src`, which is a hard failure,
 *     rather than by the tests/scripts diagnostic baseline.
 *
 * A runtime key assertion is kept as well, but it is the weaker half: an
 * optional, unpopulated widening walks straight past it.
 */
export interface UnattributedStateDisclosure {
  /** Literal discriminant. `ReadResult` carries no such field. */
  readonly disclosure_kind: "unattributed_state_content";
  readonly namespace: string;
  readonly key: string;
  /**
   * Deliberately NOT named `value`. A consumer that reaches for `.value` on
   * this object gets a compile error rather than plaintext, which is the
   * difference between a type that separates the two outcomes and a comment
   * that asks a reader to.
   */
  readonly unattributed_content: string;
  readonly version: number;
  /**
   * Deliberately NOT named `written_at`: this timestamp is the entry's own
   * unauthenticated claim, and on this path nothing establishes who made it.
   * Absent when the stored entry carries no such claim.
   */
  readonly claimed_written_at?: string;
  /**
   * The entry's own unauthenticated writer-id claim (its `kid`), carried so the
   * remedy every layer of this surface advertises - restore the writer identity
   * into this fortress - names an identity the owner can actually act on.
   * Without it the instruction has no handle: the disclosure omits the attested
   * `written_by` by design and `StateStore.list` carries no key id, so an owner
   * following the advice had nothing to look up.
   *
   * Deliberately NOT named `written_by`, and spelled with the same `claimed_`
   * discipline as `claimed_written_at`: NOTHING ON THIS PATH ESTABLISHED IT.
   * It is a string copied out of bytes whose signature did not verify, so an
   * attacker who can write the entry chooses it. Treat it as a lead to check,
   * never as attribution. Absent when the stored entry carries no such claim.
   */
  readonly claimed_writer_id?: string;
  /**
   * Single-inhabitant literal, never a boolean. The one thing this surface
   * knows about the writer is that it could not be established.
   */
  readonly writer: "not_established";
  /** `UNATTRIBUTED_DISCLOSURE_NOTICE`, carried in the payload itself. */
  readonly notice: string;
}

/**
 * The SIX EXACT FIELD NAMES a verified read owns, which this disclosure must
 * never carry. `value` is the one the security argument rests on; the rest are
 * the trust-bearing fields whose presence would let a consumer read a
 * reassuring answer off an unverified object.
 *
 * Six literal names is the whole of it, and saying so is the point: this models
 * NOTHING about meaning. A new field carrying the same plaintext under a
 * different name - `claimed_value`, say - is not caught here and cannot be.
 * That gap is real and is closed by review, not by this type.
 *
 * Exported ONLY so `test/cognitive/state-disclose-unattributed.test.ts` pins
 * the same list instead of hand-copying it. The copy drifted the day it was
 * written (it omitted `warnings`, the one optional field on `ReadResult` and
 * therefore the likeliest accidental widening), which is the same
 * hand-mirrored-registry failure this module's reserved-namespace
 * consolidation exists to prevent. One source, or the mirror lies.
 */
export type VerifiedReadFieldSpelling =
  | "value"
  | "signature_verified"
  | "integrity_verified"
  | "written_by"
  | "merkle_proof"
  | "warnings";

/**
 * `UnattributedStateDisclosure` if it carries none of those spellings, and
 * `never` if it carries any one of them.
 *
 * THIS IS THE PIN, and it is load-bearing rather than decorative because
 * `readUnattributed` builds its result THROUGH this alias. Add `value` to the
 * interface above - required or optional, populated or not - and this alias
 * becomes `never`, so the object literal in `readUnattributed` is no longer
 * assignable and `npm run typecheck` fails on `src`. `keyof` sees optional keys
 * too, which is exactly the widening a runtime `Object.keys` assertion misses.
 *
 * Adding a NEW honest field (a further `claimed_*`, say) is unaffected: only
 * these six names collapse it.
 */
type DisclosureWithoutVerifiedReadFields = [
  Extract<keyof UnattributedStateDisclosure, VerifiedReadFieldSpelling>,
] extends [never]
  ? UnattributedStateDisclosure
  : never;

/** Options for state write */
export interface WriteOptions {
  content_type?: string;
  ttl_seconds?: number;
  tags?: string[];
  provenance?: {
    /**
     * Internal, derived actor signal. `agent` is passed only from the existing
     * session-identity path; absent/unknown fails closed to operator.
     */
    origin_actor?: OriginActor;
    origin_ref?: string;
    lineage_id?: string;
    derived_from?: readonly DerivedFromEdge[];
  };
}

/** Cached namespace key with TTL */
interface CachedKey {
  key: Uint8Array;
  expiresAt: number;
}

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item));
  }

  const record = value as Record<string, unknown>;
  const canonical: Record<string, unknown> = {};
  for (const key of Object.keys(record).sort()) {
    const item = record[key];
    if (item !== undefined) {
      canonical[key] = canonicalize(item);
    }
  }
  return canonical;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function sortExportItems(entries: ExportedStateItem[]): ExportedStateItem[] {
  return [...entries]
    .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
    .map((item) => ({ key: item.key, entry: item.entry }));
}

function exportNamespaceChecksum(entries: ExportedStateItem[]): string {
  return hashToString(stringToBytes(canonicalJson(sortExportItems(entries))));
}

function buildCompletenessManifest(
  exportedAt: string,
  data: StateExportData
): StateExportCompletenessManifest {
  const namespaces = Object.keys(data).sort();
  const namespaceItems: Record<string, StateExportNamespaceManifest> = {};
  let totalKeys = 0;

  for (const namespace of namespaces) {
    const entries = data[namespace] ?? [];
    namespaceItems[namespace] = {
      item_count: entries.length,
      content_sha256: exportNamespaceChecksum(entries),
    };
    totalKeys += entries.length;
  }

  return {
    schema_version: STATE_EXPORT_COMPLETENESS_MANIFEST_SCHEMA_VERSION,
    format: STATE_EXPORT_FORMAT,
    exported_at: exportedAt,
    namespaces,
    namespace_count: namespaces.length,
    total_keys: totalKeys,
    namespace_items: namespaceItems,
  };
}

function isWellFormedIso8601Timestamp(value: string): boolean {
  const match = ISO_8601_TIMESTAMP_RE.exec(value);
  if (!match) return false;

  const [
    ,
    yearText,
    monthText,
    dayText,
    hourText,
    minuteText,
    secondText,
    fractionText,
    zoneText,
    signText,
    offsetHourText,
    offsetMinuteText,
  ] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const millisecond = Number((fractionText ?? "0").padEnd(3, "0"));
  const offsetHour = offsetHourText ? Number(offsetHourText) : 0;
  const offsetMinute = offsetMinuteText ? Number(offsetMinuteText) : 0;

  if (
    month < 1 ||
    month > 12 ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    offsetHour > 23 ||
    offsetMinute > 59
  ) {
    return false;
  }

  const localMs = Date.UTC(
    year,
    month - 1,
    day,
    hour,
    minute,
    second,
    millisecond
  );
  if (!Number.isFinite(localMs)) return false;

  const localDate = new Date(localMs);
  if (
    localDate.getUTCFullYear() !== year ||
    localDate.getUTCMonth() !== month - 1 ||
    localDate.getUTCDate() !== day ||
    localDate.getUTCHours() !== hour ||
    localDate.getUTCMinutes() !== minute ||
    localDate.getUTCSeconds() !== second ||
    localDate.getUTCMilliseconds() !== millisecond
  ) {
    return false;
  }

  const signedOffsetMinutes =
    zoneText === "Z"
      ? 0
      : (signText === "+" ? 1 : -1) * (offsetHour * 60 + offsetMinute);
  const expectedUtcMs = localMs - signedOffsetMinutes * 60 * 1000;
  return Date.parse(value) === expectedUtcMs;
}

function exportBundleMacPayload(bundle: StateExportBundle): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    sanctuary_export_version: bundle.sanctuary_export_version,
    format: bundle.format,
    exported_at: bundle.exported_at,
    namespaces: bundle.namespaces,
    data: bundle.data,
    completeness_manifest: bundle.completeness_manifest,
  };
  if (bundle.facade_hidden_markers !== undefined) {
    payload.facade_hidden_markers = bundle.facade_hidden_markers;
  }
  return payload;
}

/** Constant-time byte comparison for MAC verification (avoids timing leaks). */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

function stateEnvelopeSigningDomain(envelope: SignedStateEnvelope): string {
  const schemaVersion = envelope.metadata.schema_version;
  if (schemaVersion <= LEGACY_STATE_ENVELOPE_SCHEMA_VERSION) {
    return LEGACY_STATE_ENVELOPE_SIGNING_DOMAIN;
  }
  return `${STATE_ENVELOPE_SIGNING_DOMAIN_PREFIX}${schemaVersion}\n`;
}

function stateEnvelopeSigningBytes(envelope: SignedStateEnvelope): Uint8Array {
  return stringToBytes(stateEnvelopeSigningDomain(envelope) + canonicalJson(envelope));
}

function legacyWarning(): LegacyEnvelopeWarningInfo {
  return {
    name: "LegacyEnvelopeWarning",
    classification: "legacy_schema_1",
    message:
      "Legacy state envelope v1 loaded with ciphertext-only signature verification",
  };
}

function payloadAuthTag(payload: EncryptedPayload): string {
  const ciphertextAndTag = fromBase64url(payload.ct);
  if (ciphertextAndTag.length < 16) {
    throw new StateVerificationError(
      "schema_mismatch",
      "Encrypted payload is too short to contain an authentication tag"
    );
  }
  return toBase64url(ciphertextAndTag.slice(ciphertextAndTag.length - 16));
}

function buildSignedEnvelope(args: {
  namespace: string;
  key: string;
  version: number;
  kid: string;
  schemaVersion: number;
  metadata: StateEntry["metadata"];
  provenanceStamp?: ProvenanceStamp;
  integrityHash: string;
  payload: EncryptedPayload;
}): SignedStateEnvelope {
  return {
    namespace: args.namespace,
    key: args.key,
    version: args.version,
    kid: args.kid,
    metadata: {
      timestamp: args.metadata.written_at,
      schema_version: args.schemaVersion,
      content_type: args.metadata.content_type,
      ttl_seconds: args.metadata.ttl_seconds,
      tags: args.metadata.tags,
    },
    ...(args.provenanceStamp !== undefined
      ? { provenance_stamp: args.provenanceStamp }
      : {}),
    integrity_hash: args.integrityHash,
    payload: {
      schema_version: args.payload.v,
      algo: args.payload.alg,
      nonce: args.payload.iv,
      tag: payloadAuthTag(args.payload),
      ciphertext: args.payload.ct,
      encrypted_at: args.payload.ts,
    },
  };
}

function entryBinding(namespace: string, key: string): string {
  return `${namespace}/${key}`;
}

function resolveWriteOriginActor(actor: OriginActor | undefined): OriginActor {
  return actor === "agent" || actor === "system" ? actor : "operator";
}

function mintSerializedWriteStamp(args: {
  namespace: string;
  key: string;
  identityId: string;
  writtenAt: string;
  version: number;
  provenance?: WriteOptions["provenance"];
}): ProvenanceStamp {
  const stamp = mintProvenanceStamp({
    origin_actor: resolveWriteOriginActor(args.provenance?.origin_actor),
    origin_ref: args.provenance?.origin_ref ?? args.identityId,
    lineage_id:
      args.provenance?.lineage_id ??
      `state:${entryBinding(args.namespace, args.key)}:v${args.version}`,
    written_at: args.writtenAt,
    entry_binding: entryBinding(args.namespace, args.key),
    ...(args.provenance?.derived_from !== undefined
      ? { derived_from: args.provenance.derived_from }
      : {}),
  });
  return serializeStamp(stamp);
}

function isMemoryClass(value: unknown): value is ProvenanceStamp["memory_class"] {
  return (
    value === "operator_owned" ||
    value === "agent_owned" ||
    value === "shared_entangled"
  );
}

function isOriginActor(value: unknown): value is OriginActor {
  return value === "operator" || value === "agent" || value === "system";
}

function isStringArray(value: unknown): value is readonly string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function normalizeDerivedEdgesForRemint(
  stamp: ProvenanceStamp
): readonly DerivedFromEdge[] | null {
  if (stamp.derived_from_edges !== undefined) {
    if (!Array.isArray(stamp.derived_from_edges)) return null;
    const edges: DerivedFromEdge[] = [];
    for (const edge of stamp.derived_from_edges) {
      if (
        edge === null ||
        typeof edge !== "object" ||
        typeof (edge as { lineage_id?: unknown }).lineage_id !== "string" ||
        !isMemoryClass((edge as { memory_class?: unknown }).memory_class)
      ) {
        return null;
      }
      edges.push({
        lineage_id: (edge as { lineage_id: string }).lineage_id,
        memory_class: (edge as { memory_class: ProvenanceStamp["memory_class"] }).memory_class,
      });
    }
    return edges;
  }

  // Old serialized stamps that carried only lineage ids cannot safely
  // reconstruct a shared_entangled class. New schema-3 writes persist full
  // edges, so this path is only for defensive compatibility.
  return stamp.memory_class === "shared_entangled" ? null : [];
}

function normalizePersistedProvenanceStamp(value: unknown): ProvenanceStamp | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (
    !isMemoryClass(record.memory_class) ||
    !isOriginActor(record.origin_actor) ||
    typeof record.origin_ref !== "string" ||
    record.origin_ref.length === 0 ||
    typeof record.lineage_id !== "string" ||
    record.lineage_id.length === 0 ||
    typeof record.written_at !== "string" ||
    !isStringArray(record.derived_from)
  ) {
    return null;
  }
  if (
    record.entry_binding !== undefined &&
    (typeof record.entry_binding !== "string" || record.entry_binding.length === 0)
  ) {
    return null;
  }
  const stamp: ProvenanceStamp = {
    memory_class: record.memory_class,
    origin_actor: record.origin_actor,
    origin_ref: record.origin_ref,
    lineage_id: record.lineage_id,
    written_at: record.written_at,
    derived_from: [...record.derived_from],
    ...(record.entry_binding !== undefined
      ? { entry_binding: record.entry_binding }
      : {}),
  };
  const edges = normalizeDerivedEdgesForRemint({
    ...stamp,
    ...(record.derived_from_edges !== undefined
      ? { derived_from_edges: record.derived_from_edges as DerivedFromEdge[] }
      : {}),
  });
  if (edges === null) return null;
  return {
    ...stamp,
    ...(edges.length > 0 ? { derived_from_edges: edges } : {}),
  };
}

export class StateStore {
  private storage: StorageBackend;
  private masterKey: Uint8Array;

  // Cache of version numbers per namespace/key for anti-rollback
  private versionCache = new Map<string, number>();

  // Cache of content hashes per namespace for Merkle tree computation
  private contentHashes = new Map<string, Map<string, string>>();

  // LRU-with-TTL cache for derived namespace keys (avoids repeated HKDF)
  private namespaceKeyCache = new Map<string, CachedKey>();
  private static readonly KEY_CACHE_TTL_MS = 15 * 60 * 1000; // 15 minutes
  private static readonly KEY_CACHE_MAX_ENTRIES = 128;

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.masterKey = masterKey;
  }

  private exportBundleMacBytes(bundle: StateExportBundle): Uint8Array {
    const macKey = derivePurposeKey(
      this.masterKey,
      STATE_EXPORT_BUNDLE_MAC_PURPOSE
    );
    return hmacSha256(
      macKey,
      stringToBytes(
        STATE_EXPORT_BUNDLE_MAC_DOMAIN +
          canonicalJson(exportBundleMacPayload(bundle))
      )
    );
  }

  private createExportBundleIntegrity(
    bundle: StateExportBundle
  ): Record<string, unknown> {
    return {
      schema_version: STATE_EXPORT_BUNDLE_INTEGRITY_SCHEMA_VERSION,
      algo: "HMAC-SHA256",
      coverage: STATE_EXPORT_BUNDLE_MAC_COVERAGE,
      mac: toBase64url(this.exportBundleMacBytes(bundle)),
    };
  }

  private verifyExportBundleCompleteness(
    bundle: StateExportBundle,
    data: StateExportData,
    allowUnverifiedLegacy: boolean
  ): StateExportCompletenessVerification {
    const manifest = bundle.completeness_manifest;
    const integrity = bundle.bundle_integrity;

    if (manifest === undefined && integrity === undefined) {
      if (!allowUnverifiedLegacy) {
        throw new StateVerificationError(
          "integrity_hash_mismatch",
          STATE_EXPORT_LEGACY_REJECT_MESSAGE
        );
      }
      return "unverified-completeness-legacy-bundle";
    }

    if (
      !manifest ||
      typeof manifest !== "object" ||
      Array.isArray(manifest) ||
      !integrity ||
      typeof integrity !== "object" ||
      Array.isArray(integrity)
    ) {
      throw new StateVerificationError(
        "integrity_hash_mismatch",
        "State export bundle completeness metadata is incomplete"
      );
    }

    const manifestRecord = manifest as Record<string, unknown>;
    const integrityRecord = integrity as Record<string, unknown>;
    const manifestSchemaVersion = manifestRecord.schema_version;
    const integritySchemaVersion = integrityRecord.schema_version;

    if (
      typeof manifestSchemaVersion !== "number" ||
      typeof integritySchemaVersion !== "number"
    ) {
      throw new StateVerificationError(
        "schema_mismatch",
        "State export bundle completeness schema metadata is malformed"
      );
    }
    if (
      manifestSchemaVersion > STATE_EXPORT_COMPLETENESS_MANIFEST_SCHEMA_VERSION ||
      integritySchemaVersion > STATE_EXPORT_BUNDLE_INTEGRITY_SCHEMA_VERSION
    ) {
      throw new StateVerificationError(
        "schema_mismatch",
        "State export bundle completeness schema version is newer than this build supports"
      );
    }
    if (
      manifestSchemaVersion !== STATE_EXPORT_COMPLETENESS_MANIFEST_SCHEMA_VERSION ||
      integritySchemaVersion !== STATE_EXPORT_BUNDLE_INTEGRITY_SCHEMA_VERSION
    ) {
      throw new StateVerificationError(
        "schema_mismatch",
        "State export bundle completeness schema version is unsupported"
      );
    }

    if (
      bundle.format !== STATE_EXPORT_FORMAT ||
      typeof bundle.exported_at !== "string" ||
      manifestRecord.format !== STATE_EXPORT_FORMAT ||
      manifestRecord.exported_at !== bundle.exported_at ||
      integrityRecord.algo !== "HMAC-SHA256" ||
      integrityRecord.coverage !== STATE_EXPORT_BUNDLE_MAC_COVERAGE ||
      typeof integrityRecord.mac !== "string"
    ) {
      throw new StateVerificationError(
        "integrity_hash_mismatch",
        "State export bundle completeness metadata is malformed"
      );
    }
    if (!isWellFormedIso8601Timestamp(bundle.exported_at)) {
      throw new StateVerificationError(
        "integrity_hash_mismatch",
        "State export bundle exported_at timestamp is malformed"
      );
    }

    let providedMac: Uint8Array;
    try {
      providedMac = fromBase64url(integrityRecord.mac);
    } catch {
      throw new StateVerificationError(
        "integrity_hash_mismatch",
        "State export bundle integrity MAC is malformed"
      );
    }

    if (!constantTimeEqual(providedMac, this.exportBundleMacBytes(bundle))) {
      throw new StateVerificationError(
        "integrity_hash_mismatch",
        "State export bundle failed integrity verification"
      );
    }

    const expectedManifest = buildCompletenessManifest(bundle.exported_at, data);
    if (canonicalJson(manifestRecord) !== canonicalJson(expectedManifest)) {
      throw new StateVerificationError(
        "integrity_hash_mismatch",
        "State export bundle completeness manifest does not match contents"
      );
    }

    return "verified";
  }

  /**
   * Get or derive a namespace encryption key, with caching.
   * Cache entries expire after 15 minutes and are evicted LRU when
   * the cache exceeds 128 entries.
   */
  private getNamespaceKey(namespace: string): Uint8Array {
    const now = Date.now();
    const cached = this.namespaceKeyCache.get(namespace);
    if (cached && cached.expiresAt > now) {
      return cached.key;
    }
    if (cached) {
      // Best-effort: the entry is expired and is about to be replaced by a
      // freshly derived key below; zero the stale bytes so they are not left
      // on the V8 heap until GC (prior callers consumed the key synchronously).
      cached.key.fill(0);
    }

    // Evict expired or LRU entries if at capacity
    if (this.namespaceKeyCache.size >= StateStore.KEY_CACHE_MAX_ENTRIES) {
      // Remove oldest entry (Map iteration order = insertion order)
      const firstKey = this.namespaceKeyCache.keys().next().value;
      if (firstKey !== undefined) {
        // Best-effort: zero the derived key bytes before dropping the entry so
        // the material is not left on the V8 heap until GC (consistent with
        // identity.ts / master-custody.ts / master-rotation.ts).
        this.namespaceKeyCache.get(firstKey)?.key.fill(0);
        this.namespaceKeyCache.delete(firstKey);
      }
    }

    const derived = deriveNamespaceKey(this.masterKey, namespace);
    this.namespaceKeyCache.set(namespace, {
      key: derived,
      expiresAt: now + StateStore.KEY_CACHE_TTL_MS,
    });
    return derived;
  }

  /** Invalidate all cached namespace keys (call on master key rotation). */
  invalidateKeyCache(): void {
    // Best-effort: zero each derived key's bytes before clearing so the
    // material is not left on the V8 heap until GC.
    for (const cached of this.namespaceKeyCache.values()) {
      cached.key.fill(0);
    }
    this.namespaceKeyCache.clear();
  }

  private versionKey(namespace: string, key: string): string {
    return `${namespace}/${key}`;
  }

  private get identityEncryptionKey(): Uint8Array {
    return derivePurposeKey(this.masterKey, "identity-encryption");
  }

  private publicKeyFromEncryptedPrivateKey(
    encryptedPrivateKey: EncPayload,
    identityEncryptionKey: Uint8Array
  ): Uint8Array {
    const privateKey = decrypt(encryptedPrivateKey, identityEncryptionKey);
    try {
      return ed25519.getPublicKey(privateKey);
    } finally {
      privateKey.fill(0);
    }
  }

  private async loadJsonRecord(
    key: string
  ): Promise<Record<string, unknown>> {
    const raw = await this.storage.read("_meta", key);
    if (!raw) return {};

    try {
      const parsed = JSON.parse(bytesToString(raw));
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      // Fall through to a typed verification failure.
    }

    throw new StateVerificationError(
      "schema_mismatch",
      `State metadata record is corrupted: _meta/${key}`
    );
  }

  private async saveJsonRecord(
    key: string,
    record: Record<string, unknown>
  ): Promise<void> {
    await this.storage.write("_meta", key, stringToBytes(JSON.stringify(record)));
  }

  /**
   * MAC over the version-anchor record, keyed from the master key and bound to
   * the record key (so it cannot be replayed under another `_meta` key).
   */
  private metaRecordMacBytes(
    key: string,
    record: Record<string, unknown>
  ): Uint8Array {
    const macKey = derivePurposeKey(this.masterKey, "state-meta-mac");
    return hmacSha256(
      macKey,
      stringToBytes(STATE_META_MAC_DOMAIN + key + "\n" + canonicalJson(record))
    );
  }

  /**
   * Load the MAC-authenticated version-anchor record (the persistent rollback
   * floor - F1). Stored as a `{ marker, data, mac }` envelope:
   *   - MAC present + valid    -> return the authenticated floor.
   *   - MAC present + invalid  -> edited in place; reject (the attacker cannot
   *     silently LOWER a key's floor).
   *   - no marker (bare / marker-stripped) OR absent -> NO trusted floor
   *     (return {}). We deliberately do NOT trust or re-MAC a bare record:
   *     re-MACing it would let a filesystem adversary bypass authentication by
   *     stripping the marker and rewriting the values. Instead the floor
   *     re-establishes via observeVersion on the next read or write. That
   *     re-establishment is only as authenticated as the caller that drives it,
   *     and the two callers differ:
   *       - READ path: enforced (STATE-READ-ANCHOR-01). `readInternal` RAISES
   *         the floor only from a read whose signature actually verified; a
   *         read that could not verify leaves the floor where it is rather
   *         than pinning it from an unattested version. (The rollback CHECK is
   *         separate and still runs on every enforcing read - see
   *         `assertNotBelowVersionFloor`.)
   *       - WRITE path: NOT enforced. This is the uncovered case. `write()`
   *         derives its new version from `versionCache`, which
   *         `getNamespaceHashes` fills by parsing the namespace's raw on-disk
   *         entries with no signature check of any kind, so a legitimate write
   *         can carry an unattested on-disk version into the durable floor.
   *         Tracked as STATE-WRITE-ANCHOR-01. Do not read this block as
   *         covering the write path.
   *
   * Residual (documented, not closed here): deleting the anchor AND replacing a
   * key's entry with an older validly-signed v2 entry resets that key's floor
   * (a replay). Closing it needs a floor that does not live in a single
   * deletable file (boot-anchored / externally-attested) - out of scope for F1.
   */
  private async loadVersionAnchors(): Promise<Record<string, unknown>> {
    const raw = await this.storage.read(
      "_meta",
      STATE_ENVELOPE_VERSION_ANCHORS_KEY
    );
    if (!raw) return {};

    let parsed: unknown;
    try {
      parsed = JSON.parse(bytesToString(raw));
    } catch {
      throw new StateVerificationError(
        "schema_mismatch",
        `State metadata record is corrupted: _meta/${STATE_ENVELOPE_VERSION_ANCHORS_KEY}`
      );
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new StateVerificationError(
        "schema_mismatch",
        `State metadata record is corrupted: _meta/${STATE_ENVELOPE_VERSION_ANCHORS_KEY}`
      );
    }
    const obj = parsed as Record<string, unknown>;

    if (obj[STATE_META_MAC_MARKER] !== true) {
      // Bare / marker-stripped / legacy: untrusted. Ignore (no floor); it
      // re-derives from authenticated entries via observeVersion.
      return {};
    }

    const data = obj.data;
    const mac = obj.mac;
    if (
      !data ||
      typeof data !== "object" ||
      Array.isArray(data) ||
      typeof mac !== "string"
    ) {
      throw new StateVerificationError(
        "schema_mismatch",
        `Version-anchor record is malformed: _meta/${STATE_ENVELOPE_VERSION_ANCHORS_KEY}`
      );
    }
    const record = data as Record<string, unknown>;
    let providedMac: Uint8Array;
    try {
      providedMac = fromBase64url(mac);
    } catch {
      throw new StateVerificationError(
        "integrity_hash_mismatch",
        `Version-anchor MAC is malformed: _meta/${STATE_ENVELOPE_VERSION_ANCHORS_KEY}`
      );
    }
    if (
      !constantTimeEqual(
        providedMac,
        this.metaRecordMacBytes(STATE_ENVELOPE_VERSION_ANCHORS_KEY, record)
      )
    ) {
      throw new StateVerificationError(
        "integrity_hash_mismatch",
        `Version-anchor record failed authentication (tampered or wrong key): _meta/${STATE_ENVELOPE_VERSION_ANCHORS_KEY}`
      );
    }
    return record;
  }

  /** Persist the version-anchor record in a MAC-authenticated envelope (F1). */
  private async saveVersionAnchors(
    record: Record<string, unknown>
  ): Promise<void> {
    const envelope = {
      [STATE_META_MAC_MARKER]: true,
      data: record,
      mac: toBase64url(
        this.metaRecordMacBytes(STATE_ENVELOPE_VERSION_ANCHORS_KEY, record)
      ),
    };
    await this.storage.write(
      "_meta",
      STATE_ENVELOPE_VERSION_ANCHORS_KEY,
      stringToBytes(JSON.stringify(envelope))
    );
  }

  private async rememberWriterPublicKey(
    kid: string,
    publicKey: Uint8Array
  ): Promise<void> {
    const registry = await this.loadJsonRecord(STATE_ENVELOPE_PUBLIC_KEYS_KEY);
    const publicKeyString = toBase64url(publicKey);
    if (registry[kid] === publicKeyString) return;

    registry[kid] = publicKeyString;
    await this.saveJsonRecord(STATE_ENVELOPE_PUBLIC_KEYS_KEY, registry);
  }

  private async resolveStoredIdentity(kid: string): Promise<StoredIdentity | null> {
    try {
      const raw = await this.storage.read("_identities", kid);
      if (raw) {
        const encrypted = JSON.parse(bytesToString(raw)) as EncryptedPayload;
        const decrypted = decrypt(encrypted, this.identityEncryptionKey);
        return JSON.parse(bytesToString(decrypted)) as StoredIdentity;
      }
    } catch {
      return null;
    }

    return null;
  }

  private async resolveWriterPublicKeys(
    kid: string
  ): Promise<ResolvedWriterPublicKey[]> {
    // `kid` reaches here off disk, so the `string` annotation is an assertion,
    // not a guarantee. It is about to be used as a storage key and as a record
    // index, and BOTH coerce it with String(): a deeply nested stored value
    // overflows the stack there, replacing the real "writer key not found"
    // diagnosis with an unrelated RangeError. A non-string kid can never name a
    // resident identity, so refusing it here IS the correct answer, and the
    // caller's typed `kid_unknown` refusal is then reached and reported
    // (STATE-STORE-ERRMSG-INTERP-01).
    if (typeof kid !== "string") return [];
    const keys: ResolvedWriterPublicKey[] = [];
    const seen = new Set<string>();
    const identity = await this.resolveStoredIdentity(kid);
    if (identity) {
      for (const key of resolveAuthenticatedIdentityWriterPublicKeys(identity)) {
        if (!seen.has(key.publicKeyBase64url)) {
          keys.push(key);
          seen.add(key.publicKeyBase64url);
        }
      }
    }

    const registry = await this.loadJsonRecord(STATE_ENVELOPE_PUBLIC_KEYS_KEY);
    const publicKey = registry[kid];
    if (typeof publicKey === "string") {
      appendResolvedWriterKey(
        keys,
        seen,
        publicKey,
        "plaintext-registry",
        "unauthenticated"
      );
    }
    return keys;
  }

  private async getAnchoredVersion(
    namespace: string,
    key: string
  ): Promise<number> {
    const anchors = await this.loadVersionAnchors();
    const anchored = anchors[this.versionKey(namespace, key)];
    return typeof anchored === "number" && Number.isSafeInteger(anchored)
      ? anchored
      : 0;
  }

  /**
   * CHECK half of the version floor: reject an entry sitting BELOW the
   * MAC-authenticated anchor.
   *
   * INVARIANT: this check is an authenticated control in its own right. The
   * floor it compares against is MAC-authenticated on disk, so its authority
   * does not come from the current access being able to resolve a writer key.
   * Note the floor's authority is INTEGRITY, not provenance: a verified read
   * raises it, but so does `write()`, whose version can come from unattested
   * on-disk bytes (STATE-WRITE-ANCHOR-01). Do not restate this as "established
   * by an earlier verified write"; that is the claim this file's write-path
   * block explicitly refuses to make. Every
   * rollback-enforcing access must therefore run it, including one whose
   * signature could not be verified: gating detection on verification would
   * turn "this read cannot establish the writer" into "this read cannot detect
   * a rollback", the silent degradation to a less-secure behavior that
   * AGENTS.md MUST-NEVER #5 forbids. Regression-guarded by "detects a rollback
   * below the persisted anchor even when the read cannot verify" in
   * server/test/cognitive/state-read-durable-side-effects.test.ts.
   *
   * Returns the loaded anchor record and the current floor so a caller that
   * goes on to RAISE the floor does not have to reload it.
   */
  private async assertNotBelowVersionFloor(
    namespace: string,
    key: string,
    version: number
  ): Promise<{
    anchors: Record<string, unknown>;
    vk: string;
    lastSeen: number;
  }> {
    const anchors = await this.loadVersionAnchors();
    const vk = this.versionKey(namespace, key);
    const anchored = anchors[vk];
    const lastSeen =
      typeof anchored === "number" && Number.isSafeInteger(anchored)
        ? anchored
        : 0;

    if (version < lastSeen) {
      throw new StateVerificationError(
        "rollback_detected",
        `Rollback detected for ${namespace}/${key}: found version ${version}, expected at least ${lastSeen}`
      );
    }

    return { anchors, vk, lastSeen };
  }

  /**
   * CHECK-AND-RAISE, not a raiser. The two halves carry different trust
   * requirements: the check above is unconditional on any rollback-enforcing
   * access, while the raise is a durable, monotone, unrecoverable-if-wrong side
   * effect and is reserved for a caller that established the version's
   * provenance. Call this only from such a caller; where the provenance is
   * unproven, call `assertNotBelowVersionFloor` alone so detection survives
   * without the pin.
   */
  private async observeVersion(
    namespace: string,
    key: string,
    version: number
  ): Promise<void> {
    const { anchors, vk, lastSeen } = await this.assertNotBelowVersionFloor(
      namespace,
      key,
      version
    );

    if (version > lastSeen) {
      anchors[vk] = version;
      await this.saveVersionAnchors(anchors);
    }
  }

  /**
   * Get or initialize the content hash map for a namespace.
   */
  private async getNamespaceHashes(
    namespace: string
  ): Promise<Map<string, string>> {
    if (this.contentHashes.has(namespace)) {
      return this.contentHashes.get(namespace)!;
    }

    // Load existing entries to build the hash map
    const entries = await this.storage.list(namespace);
    const hashMap = new Map<string, string>();

    for (const entry of entries) {
      const raw = await this.storage.read(namespace, entry.key);
      if (raw) {
        try {
          const stateEntry: StateEntry = JSON.parse(bytesToString(raw));
          hashMap.set(entry.key, stateEntry.integrity_hash);
          // FOLLOW-UP, honest residual (STATE-CACHE-FLOOR-01, not closed here):
          // these versions come straight from raw on-disk bytes with no
          // signature check, and `versionCache` is consulted by the
          // anti-rollback check in `readInternal` and by the version
          // computation in `write()`. STATE-READ-ANCHOR-01 closed the DURABLE
          // half of this on the read path; the process-scoped in-memory half,
          // and the write path that reads it (STATE-WRITE-ANCHOR-01), are open.
          this.versionCache.set(
            this.versionKey(namespace, entry.key),
            stateEntry.ver
          );
        } catch {
          // Corrupted entry - skip it
        }
      }
    }

    this.contentHashes.set(namespace, hashMap);
    return hashMap;
  }

  /**
   * Write encrypted state.
   *
   * @param namespace - Logical grouping
   * @param key - State key
   * @param value - Plaintext value (will be encrypted)
   * @param identityId - Identity performing the write
   * @param encryptedPrivateKey - Identity's encrypted private key (for signing)
   * @param identityEncryptionKey - Key to decrypt the identity's private key
   * @param options - Optional metadata
   */
  async write(
    namespace: string,
    key: string,
    value: string,
    identityId: string,
    encryptedPrivateKey: EncPayload,
    identityEncryptionKey: Uint8Array,
    options: WriteOptions = {}
  ): Promise<WriteResult> {
    const namespaceKey = this.getNamespaceKey(namespace);
    const plaintext = stringToBytes(value);

    // Compute integrity hash of plaintext
    const integrityHash = hashToString(plaintext);

    // Encrypt the value
    const payload = encrypt(plaintext, namespaceKey);

    // F1: the version-anchor record is untrusted unless MAC-valid (a bare /
    // marker-stripped anchor is ignored - see loadVersionAnchors), so it cannot
    // be the sole monotonic floor: otherwise the first post-upgrade write to an
    // existing key on a cold process (empty cache + ignored bare anchor) would
    // reset its version to 1, clobbering a higher on-disk version. Populate
    // versionCache from the persisted entries first so the floor reflects the
    // real on-disk version. (getNamespaceHashes is memoized per namespace, so
    // the later call at the end of write() reuses this.)
    await this.getNamespaceHashes(namespace);

    // Determine version number (monotonically increasing)
    const vk = this.versionKey(namespace, key);
    const currentVersion = this.versionCache.get(vk) ?? 0;
    const anchoredVersion = await this.getAnchoredVersion(namespace, key);
    const newVersion = Math.max(currentVersion, anchoredVersion) + 1;

    const now = new Date().toISOString();
    const metadata: StateEntry["metadata"] = {
      content_type: options.content_type,
      ttl_seconds: options.ttl_seconds,
      tags: options.tags,
      schema_version: STATE_ENVELOPE_SCHEMA_VERSION,
      written_at: now,
    };
    const provenanceStamp = mintSerializedWriteStamp({
      namespace,
      key,
      identityId,
      writtenAt: now,
      version: newVersion,
      provenance: options.provenance,
    });
    const envelope = buildSignedEnvelope({
      namespace,
      key,
      version: newVersion,
      kid: identityId,
      schemaVersion: STATE_ENVELOPE_SCHEMA_VERSION,
      metadata,
      provenanceStamp,
      integrityHash,
      payload,
    });

    // Sign the canonical envelope, binding path, version, writer, metadata,
    // plaintext hash, and ciphertext metadata to the writer identity.
    const envelopeSignature = sign(
      stateEnvelopeSigningBytes(envelope),
      encryptedPrivateKey,
      identityEncryptionKey
    );
    const legacyCiphertextSignature = sign(
      fromBase64url(payload.ct),
      encryptedPrivateKey,
      identityEncryptionKey
    );

    const writerPublicKey = this.publicKeyFromEncryptedPrivateKey(
      encryptedPrivateKey,
      identityEncryptionKey
    );

    // Construct the state entry
    const stateEntry: StateEntry = {
      v: STATE_ENVELOPE_SCHEMA_VERSION,
      envelope,
      provenance_stamp: provenanceStamp,
      payload,
      ver: newVersion,
      sig: toBase64url(legacyCiphertextSignature),
      envelope_sig: toBase64url(envelopeSignature),
      kid: identityId,
      integrity_hash: integrityHash,
      metadata,
    };

    // Serialize and write to storage
    const serialized = stringToBytes(JSON.stringify(stateEntry));
    await this.storage.write(namespace, key, serialized);
    await this.rememberWriterPublicKey(identityId, writerPublicKey);
    await this.observeVersion(namespace, key, newVersion);

    // Update caches
    this.versionCache.set(vk, newVersion);
    const nsHashes = await this.getNamespaceHashes(namespace);
    nsHashes.set(key, integrityHash);

    // Compute new Merkle root
    const merkleRoot = computeMerkleRoot(nsHashes);

    return {
      key,
      namespace,
      version: newVersion,
      merkle_root: merkleRoot,
      written_at: now,
      size_bytes: serialized.length,
      integrity_hash: integrityHash,
    };
  }

  /**
   * Read and decrypt state with default-on envelope verification.
   *
   * This is the ENFORCING read path: it returns a value only when signature
   * verification established the writer. An entry whose writer cannot be
   * established throws `StateVerificationError` with classification
   * `writer_unverified` rather than returning the plaintext with
   * `signature_verified: false` (STATE-READ-REFUSE-01). Callers therefore no
   * longer have to inspect `signature_verified` to be safe; on this path a
   * returned result always carries it true. On a genuinely un-migrated pre-v2
   * fortress whose writer identity is absent from `_identities`, those entries
   * stop reading here until that identity is restored; `list`, `export`, and
   * `delete` do not route through this method and are unaffected. Use
   * `readUnverified` for an in-process migration flow that must reach the
   * plaintext first, and `readUnattributed` for the operator-gated, audited
   * surface that discloses such an entry in a shape no consumer can mistake for
   * a verified one.
   *
   * @param namespace - Logical grouping
   * @param key - State key
   * @param signerPublicKeyOrVerifyIntegrity - Optional expected public key for legacy callers, or verifyIntegrity boolean
   * @param verifyIntegrity - Whether to verify Merkle proof (default: true)
   */
  async read(
    namespace: string,
    key: string,
    signerPublicKeyOrVerifyIntegrity?: Uint8Array | boolean,
    verifyIntegrity = true
  ): Promise<ReadResult | null> {
    const signerPublicKey =
      signerPublicKeyOrVerifyIntegrity instanceof Uint8Array
        ? signerPublicKeyOrVerifyIntegrity
        : undefined;
    const shouldVerifyIntegrity =
      typeof signerPublicKeyOrVerifyIntegrity === "boolean"
        ? signerPublicKeyOrVerifyIntegrity
        : verifyIntegrity;

    return this.readInternal(namespace, key, {
      verifyIntegrity: shouldVerifyIntegrity,
      verifySignature: true,
      enforceRollback: true,
      signerPublicKey,
    });
  }

  /**
   * Explicit migration escape hatch for legacy state flows.
   * This skips signature and rollback verification and is intentionally not
   * exposed through MCP tools. Integrity hash and decryption authentication
   * are still checked before plaintext is returned.
   *
   * It is the ONLY way to reach the plaintext of an entry whose writer cannot
   * be established, because the enforcing `read` path refuses that entry
   * (STATE-READ-REFUSE-01). It requests no verification (`verifySignature:
   * false`), so the refusal there does not fire; that asymmetry is the whole
   * point of this method and must survive any change to `readInternal`.
   *
   * HONEST BOUND, NARROWED BUT NOT REMOVED (STATE-DISCLOSE-UNATTRIB-01): "the
   * only way" describes this class, not this method. THIS method still has no
   * production caller: no CLI verb and no MCP tool reaches it, so on its own it
   * remains a capability with no production call path (AGENTS.md assurance rule
   * 9), and it stays here for an in-process migration flow. What changed is the
   * CLASS. `readUnattributed` below is the operator-gated, audited, Tier-1
   * surface that reaches the same plaintext, and it IS wired to both a CLI verb
   * and an MCP tool, so an operator who has lost the writer identity now has a
   * shipped route to their content. It is not the same capability: it refuses
   * an entry whose writer can be established, it performs no durable side
   * effect, and it returns a structurally distinct shape rather than this
   * method's `ReadResult`. Export followed by import still does not close the
   * loop, because import re-verifies and skips an entry whose writer key it
   * cannot resolve. Kept in step with the ASSURANCE_MATRIX.md row "State
   * envelope integrity / default verify-on-read", which states the same bound.
   */
  async readUnverified(
    namespace: string,
    key: string,
    verifyIntegrity = true
  ): Promise<ReadResult | null> {
    return this.readInternal(namespace, key, {
      verifyIntegrity,
      verifySignature: false,
      enforceRollback: false,
    });
  }

  /**
   * OPERATOR DISCLOSURE SURFACE: return the content of an entry whose writer
   * cannot be established, in a shape that cannot be mistaken for a verified
   * read. This is the shipped route for the one person `readUnverified` was
   * never reachable by: an owner who NO LONGER HOLDS the writer identity, and
   * for whom no import, export, or migration restores the content.
   *
   * IT IS NOT A GENERAL BYPASS, and the refusal below is what makes that true
   * rather than merely intended. When verification SUCCEEDS - that is, when the
   * ordinary `read` would have returned this entry - this method refuses with
   * `writer_is_establishable` instead of disclosing. An operator who still holds
   * the writer identity is steered to the ordinary read, which is strictly
   * better than this surface because it RESTORES verification instead of
   * stepping around it and migrates the entry in place. So the set of entries
   * this method will serve is exactly the set the enforcing read refuses, and
   * the two sets can never overlap. Without that refusal the surface would be a
   * verification-optional read for every entry in the fortress, reachable by
   * anyone who can obtain one Tier-1 approval, which is a different capability
   * from the one the owner asked for.
   *
   * READ ONLY, ENFORCED BY THE OPTION AND NOT BY CARE. `unattributedDisclosure`
   * forces `durableSideEffectsPermitted` false in `readInternal` regardless of
   * the verification outcome, so the legacy-schema migration, the re-sign, and
   * the version-anchor RAISE are all unreachable from here. The anchor CHECK
   * still runs, and still wins: an entry that is both unattributable and below
   * its persisted floor is reported as the rollback it is, never disclosed. The
   * only write this operation performs is its own audit record, which its
   * callers make, not this method.
   *
   * The approval gate is NOT applied here. It is applied at each transport - the
   * router classifies the MCP tool Tier 1 from the non-relaxable set, and the
   * CLI evaluates the same operation name against the same set - because those
   * are the two places an operator actually is. See
   * `NON_RELAXABLE_STATE_DISCLOSURE_TIER1_OPERATIONS` in
   * `src/principal-policy/loader.ts`.
   */
  async readUnattributed(
    namespace: string,
    key: string,
    verifyIntegrity = true
  ): Promise<UnattributedStateDisclosure | null> {
    // The internal result is a `ReadResult` carrying `signature_verified:
    // false`, which is precisely the shape this change exists to keep out of
    // consumers' hands. It is converted below and never returned; that
    // conversion is the boundary, so nothing between here and the callers ever
    // holds the flagged shape.
    const internal = await this.readInternal(namespace, key, {
      verifyIntegrity,
      verifySignature: true,
      enforceRollback: true,
      unattributedDisclosure: true,
    });
    if (!internal) return null;

    if (internal.signature_verified) {
      throw new StateVerificationError(
        "writer_is_establishable",
        `Refusing to disclose ${namespace}/${key} without attribution: its writer CAN be established, so the ordinary verified read returns it and this surface does not apply`
      );
    }

    // ANNOTATED WITH THE PIN, NOT WITH THE INTERFACE. The annotation is what
    // makes `DisclosureWithoutVerifiedReadFields` load-bearing: if a later
    // change adds `value` (or any other verified-read spelling) to
    // `UnattributedStateDisclosure`, that alias resolves to `never` and this
    // assignment stops compiling. Returning the literal directly, or annotating
    // it with the interface, would leave the absence of `value` protected only
    // by a runtime key assertion that an optional field walks past.
    const disclosure: DisclosureWithoutVerifiedReadFields = {
      disclosure_kind: "unattributed_state_content",
      namespace,
      key,
      unattributed_content: internal.value,
      version: internal.version,
      ...(internal.written_at ? { claimed_written_at: internal.written_at } : {}),
      // The entry's own `kid`, unverified by construction: this path exists
      // precisely because no key resolved for it. It is carried so the
      // advertised remedy names something, and named `claimed_` so it cannot be
      // read as attribution.
      ...(internal.written_by ? { claimed_writer_id: internal.written_by } : {}),
      writer: "not_established",
      notice: UNATTRIBUTED_DISCLOSURE_NOTICE,
    };
    return disclosure;
  }

  private validateSignedEnvelope(
    entry: StateEntry,
    namespace: string,
    key: string
  ): SignedStateEnvelope {
    if (!entry.envelope) {
      throw new StateVerificationError(
        "schema_mismatch",
        `State envelope is missing for ${namespace}/${key}`
      );
    }

    if (
      entry.v !== LEGACY_STATE_ENVELOPE_SCHEMA_VERSION &&
      entry.v !== STATE_ENVELOPE_SCHEMA_VERSION
    ) {
      throw new StateVerificationError(
        "schema_mismatch",
        `Unsupported state envelope schema: ${describeUntrusted(entry.v)}`
      );
    }

    if (entry.v === LEGACY_STATE_ENVELOPE_SCHEMA_VERSION && entry.provenance_stamp !== undefined) {
      throw new StateVerificationError(
        "schema_mismatch",
        `Legacy state envelope schema ${LEGACY_STATE_ENVELOPE_SCHEMA_VERSION} cannot carry provenance for ${namespace}/${key}`
      );
    }

    if (entry.v === STATE_ENVELOPE_SCHEMA_VERSION && entry.provenance_stamp === undefined) {
      throw new StateVerificationError(
        "schema_mismatch",
        `State envelope schema ${STATE_ENVELOPE_SCHEMA_VERSION} is missing provenance for ${namespace}/${key}`
      );
    }

    const expected = buildSignedEnvelope({
      namespace,
      key,
      version: entry.ver,
      kid: entry.kid,
      schemaVersion: entry.v,
      metadata: entry.metadata,
      ...(entry.provenance_stamp !== undefined
        ? { provenanceStamp: entry.provenance_stamp }
        : {}),
      integrityHash: entry.integrity_hash,
      payload: entry.payload,
    });

    if (canonicalJson(entry.envelope) !== canonicalJson(expected)) {
      throw new StateVerificationError(
        "schema_mismatch",
        `State envelope metadata mismatch for ${namespace}/${key}`
      );
    }

    return entry.envelope;
  }

  private async verifyEntrySignature(
    entry: StateEntry,
    namespace: string,
    key: string,
    signerPublicKey?: Uint8Array
  ): Promise<{ verified: boolean; warnings?: LegacyEnvelopeWarningInfo[] }> {
    const publicKeys = signerPublicKey
      ? [signerPublicKey]
      : (await this.resolveWriterPublicKeys(entry.kid))
          .filter((resolved) => resolved.trustBasis === "authenticated")
          .map((resolved) => resolved.publicKey);

    if (entry.v === 1) {
      const warnings = [legacyWarning()];
      if (publicKeys.length === 0) {
        return { verified: false, warnings };
      }

      const sigValid = publicKeys.some((publicKey) =>
        verify(
          fromBase64url(entry.payload.ct),
          fromBase64url(entry.sig),
          publicKey
        )
      );
      if (!sigValid) {
        throw new StateVerificationError(
          "signature_mismatch",
          `Legacy state signature verification failed for ${namespace}/${key}`
        );
      }
      return { verified: true, warnings };
    }

    if (
      entry.v !== LEGACY_STATE_ENVELOPE_SCHEMA_VERSION &&
      entry.v !== STATE_ENVELOPE_SCHEMA_VERSION
    ) {
      throw new StateVerificationError(
        "schema_mismatch",
        `Unsupported state envelope schema: ${describeUntrusted(entry.v)}`
      );
    }

    if (publicKeys.length === 0) {
      throw new StateVerificationError(
        "kid_unknown",
        `Writer key not found for ${describeUntrusted(entry.kid)}`
      );
    }

    const envelope = this.validateSignedEnvelope(entry, namespace, key);
    if (!entry.envelope_sig) {
      throw new StateVerificationError(
        "schema_mismatch",
        `State envelope signature is missing for ${namespace}/${key}`
      );
    }
    if (typeof entry.sig !== "string") {
      throw new StateVerificationError(
        "schema_mismatch",
        `State envelope legacy ciphertext signature is missing for ${namespace}/${key}`
      );
    }
    const envelopeSig = fromBase64url(entry.envelope_sig);
    const legacySig = fromBase64url(entry.sig);
    const signedEnvelope = stateEnvelopeSigningBytes(envelope);
    const legacyCiphertext = fromBase64url(entry.payload.ct);
    const sigValid = publicKeys.some((publicKey) =>
      verify(signedEnvelope, envelopeSig, publicKey) &&
      verify(legacyCiphertext, legacySig, publicKey)
    );
    if (!sigValid) {
      throw new StateVerificationError(
        "signature_mismatch",
        `Signature verification failed for state envelope ${namespace}/${key}`
      );
    }

    return { verified: true };
  }

  /**
   * Verify a persisted state entry's signed envelope before re-minting its
   * provenance stamp into a live in-process seal for the exit partition. The
   * on-disk stamp is never trusted directly: schema/signature verification is
   * the durable trust anchor, then this method recomputes the class through the
   * sealed minter.
   */
  async remintVerifiedProvenanceStampForExport(
    entry: StateEntry,
    namespace: string,
    key: string
  ): Promise<
    | {
        status: "sealed";
        declaredStamp: ProvenanceStamp;
        sealedStamp: SealedProvenanceStamp;
      }
    | { status: "unstamped" }
    | { status: "unsealed"; declaredStamp?: ProvenanceStamp }
    | { status: "verification_failed"; error: StateVerificationError }
  > {
    // Legacy schema v1 signs only ciphertext, and schema v2 intentionally
    // carries no signed provenance. Any top-level provenance on either schema
    // is unsigned attacker-controlled metadata, so partitioned export must
    // treat the entry as unstamped without inspecting that field.
    if (entry.v <= LEGACY_STATE_ENVELOPE_SCHEMA_VERSION) {
      return { status: "unstamped" };
    }

    try {
      const verification = await this.verifyEntrySignature(entry, namespace, key);
      if (!verification.verified) {
        return {
          status: "verification_failed",
          error: new StateVerificationError(
            "kid_unknown",
            `Writer key not found for ${describeUntrusted(entry.kid)}`
          ),
        };
      }
    } catch (err) {
      if (err instanceof StateVerificationError) {
        return { status: "verification_failed", error: err };
      }
      throw err;
    }

    if (entry.provenance_stamp === undefined) {
      return { status: "unstamped" };
    }

    const declaredStamp = normalizePersistedProvenanceStamp(entry.provenance_stamp);
    if (declaredStamp === null) {
      return { status: "unsealed" };
    }

    const derivedEdges = normalizeDerivedEdgesForRemint(declaredStamp);
    if (derivedEdges === null) {
      return { status: "unsealed", declaredStamp };
    }

    const sealedStamp = mintProvenanceStamp({
      origin_actor: declaredStamp.origin_actor,
      origin_ref: declaredStamp.origin_ref,
      lineage_id: declaredStamp.lineage_id,
      written_at: declaredStamp.written_at,
      ...(declaredStamp.entry_binding !== undefined
        ? { entry_binding: declaredStamp.entry_binding }
        : {}),
      ...(derivedEdges.length > 0 ? { derived_from: derivedEdges } : {}),
    });

    if (sealedStamp.memory_class !== declaredStamp.memory_class) {
      return { status: "unsealed", declaredStamp };
    }

    return { status: "sealed", declaredStamp, sealedStamp };
  }

  private async migrateLegacyEntryToSchema2(
    entry: StateEntry,
    namespace: string,
    key: string
  ): Promise<StateEntry> {
    if (entry.v !== 1) return entry;

    const identity = await this.resolveStoredIdentity(entry.kid);
    if (!identity) return entry;

    const metadata: StateEntry["metadata"] = {
      ...entry.metadata,
      schema_version: LEGACY_STATE_ENVELOPE_SCHEMA_VERSION,
    };
    const envelope = buildSignedEnvelope({
      namespace,
      key,
      version: entry.ver,
      kid: entry.kid,
      schemaVersion: LEGACY_STATE_ENVELOPE_SCHEMA_VERSION,
      metadata,
      integrityHash: entry.integrity_hash,
      payload: entry.payload,
    });
    const envelopeSignature = sign(
      stateEnvelopeSigningBytes(envelope),
      identity.encrypted_private_key,
      this.identityEncryptionKey
    );
    const migrated: StateEntry = {
      ...entry,
      v: LEGACY_STATE_ENVELOPE_SCHEMA_VERSION,
      envelope,
      envelope_sig: toBase64url(envelopeSignature),
      metadata,
    };

    await this.storage.write(namespace, key, stringToBytes(JSON.stringify(migrated)));
    await this.rememberWriterPublicKey(entry.kid, fromBase64url(identity.public_key));
    return migrated;
  }

  private async readInternal(
    namespace: string,
    key: string,
    options: {
      verifyIntegrity: boolean;
      verifySignature: boolean;
      enforceRollback: boolean;
      signerPublicKey?: Uint8Array;
      /**
       * Operator disclosure mode (`readUnattributed`). Two effects, both
       * narrowing: durable side effects are withheld even when verification
       * succeeds, and the refusal below RETURNS instead of throwing so the
       * caller can convert the result into a structurally distinct shape.
       * Absent on every other path, so the enforcing read is byte-identical.
       */
      unattributedDisclosure?: boolean;
    }
  ): Promise<ReadResult | null> {
    const raw = await this.storage.read(namespace, key);
    if (!raw) return null;

    let stateEntry: StateEntry;
    try {
      stateEntry = JSON.parse(bytesToString(raw));
    } catch {
      throw new StateVerificationError(
        "schema_mismatch",
        `Corrupted state entry: ${namespace}/${key}`
      );
    }

    // Anti-rollback check
    const vk = this.versionKey(namespace, key);
    const cachedVersion = this.versionCache.get(vk);
    if (
      options.enforceRollback &&
      cachedVersion !== undefined &&
      stateEntry.ver < cachedVersion
    ) {
      throw new StateVerificationError(
        "rollback_detected",
        `Rollback detected for ${namespace}/${key}: found version ${describeUntrusted(stateEntry.ver)}, expected at least ${cachedVersion}`
      );
    }

    // F1: a legacy (v1) entry must never ADVANCE the version past an established
    // anchor. Legitimate version bumps are written as signed-envelope schemas
    // (v2+), so a v1 entry claiming a version above the persisted anchor can
    // only be a downgrade/replay forgery. The v1 signature binds the ciphertext
    // ONLY (not version/namespace/key), so the signature check below cannot catch
    // this; the persisted anchor is the discriminator. The anchor record is now
    // MAC-authenticated (loadVersionAnchors), so it can no longer be silently
    // EDITED/LOWERED to defeat this gate (an edit fails the MAC and the read is
    // rejected).
    //
    // RESIDUAL (documented, not closed here): a bare/absent anchor is treated as
    // "no trusted floor" (anchored 0), so this gate does not fire. A filesystem
    // adversary can therefore RESET the floor by deleting/stripping the anchors
    // record and then replay a forged high-version v1 entry. Closing the
    // deletion variant requires distrusting v1 on the enforced read path entirely
    // (verified:false unless re-migrated), which breaks reads of legitimate
    // un-migrated pre-v2 fortresses - a backward-compat migration decision left
    // as a follow-up. (A genuine pre-migration v1 entry sits at/below its anchor;
    // on a bare-anchor fortress it reads normally because the gate is skipped.)
    // Narrowed, not closed, by STATE-READ-ANCHOR-01: on the READ path the
    // anchor RAISE below now requires a VERIFIED read, so a reset floor can no
    // longer be re-pinned by a read that failed to verify. Two bounds survive
    // and neither is closed here: a bare/absent anchor is still no floor, so
    // the reset itself remains open exactly as described; and the WRITE path
    // still derives the floor from unverified on-disk versions
    // (STATE-WRITE-ANCHOR-01), so this narrowing covers reads only.
    if (options.enforceRollback && stateEntry.v === 1) {
      const anchoredVersion = await this.getAnchoredVersion(namespace, key);
      if (anchoredVersion > 0 && stateEntry.ver > anchoredVersion) {
        throw new StateVerificationError(
          "rollback_detected",
          `Rollback detected for ${namespace}/${key}: a legacy (v1) entry at version ${describeUntrusted(stateEntry.ver)} cannot exceed the established anchor ${anchoredVersion} (legitimate advances are written as signed-envelope schemas)`
        );
      }
    }

    let signatureVerified = false;
    let warnings: LegacyEnvelopeWarningInfo[] | undefined;
    if (options.verifySignature) {
      const verification = await this.verifyEntrySignature(
        stateEntry,
        namespace,
        key,
        options.signerPublicKey
      );
      signatureVerified = verification.verified;
      warnings = verification.warnings;
    }

    // CLASS INVARIANT (STATE-READ-MIGRATE-01, STATE-READ-ANCHOR-01): a read that
    // did not VERIFY must not mutate durable state, because every durable effect
    // below would otherwise take its input from an entry whose provenance this
    // read could not establish. `signatureVerified` is the only honest witness:
    // it stays false when verification was skipped AND when
    // `verifyEntrySignature` returns `verified: false` without throwing (the
    // legacy-schema path where no AUTHENTICATED writer key resolves), so
    // absent and unproven both read as not-verified here. Every durable side
    // effect in this function gates on this one predicate so that a third one
    // added later inherits the rule instead of being missed. Since
    // STATE-READ-REFUSE-01 this predicate ALSO decides whether a value is
    // returned at all, but only when verification was requested: the
    // `readUnverified` escape hatch passes `verifySignature: false`, so it
    // reaches the return with this predicate false, by design.
    //
    // The operator disclosure surface withholds the durable half outright, on
    // top of this predicate rather than instead of it: that surface exists to
    // let an owner READ content it cannot attribute, and a read that also
    // rewrote the entry (or raised its anchor) would be a repair the operator
    // did not ask for and cannot undo. Combining the two here, at the one
    // predicate every durable effect below already gates on, is what makes the
    // "no write but the audit entry" claim structural rather than a review
    // note: a durable effect added later inherits both halves.
    const durableSideEffectsPermitted =
      signatureVerified && options.unattributedDisclosure !== true;

    // Decrypt
    const namespaceKey = this.getNamespaceKey(namespace);
    const plaintext = decrypt(stateEntry.payload, namespaceKey);
    const value = bytesToString(plaintext);

    // Verify integrity hash
    const computedHash = hashToString(plaintext);
    if (computedHash !== stateEntry.integrity_hash) {
      throw new StateVerificationError(
        "integrity_hash_mismatch",
        `Integrity hash mismatch for ${namespace}/${key}: computed ${computedHash}, stored ${describeUntrusted(stateEntry.integrity_hash)}`
      );
    }

    // Migration re-signs the entry under a locally resolved identity and
    // OVERWRITES the original legacy bytes in place, so it must run only behind
    // a verified read: the original bytes are the only copy an operator or a
    // later verified read has to work from, and re-signing an entry this read
    // could not verify destroys that evidence and leaves an entry that fails on
    // the next read. Gated on the outcome of verification, never on the request
    // option that merely ASKED for it.
    //
    // FOLLOW-UP, honest residual (STATE-READ-MIGRATE-02, not closed here): this
    // migration is ordered BEFORE the anchor check further down, so a read that
    // verifies and is then REJECTED by that check has already rewritten the
    // entry on disk. Ordering the check above the migration is the fix and is
    // deliberately out of scope for this change.
    if (durableSideEffectsPermitted && stateEntry.v === 1) {
      stateEntry = await this.migrateLegacyEntryToSchema2(stateEntry, namespace, key);
    }

    // Merkle proof verification
    let merkleProofPath: string[] = [];
    let integrityVerified = true;

    if (options.verifyIntegrity) {
      const nsHashes = await this.getNamespaceHashes(namespace);
      const proof = generateMerkleProof(nsHashes, key);
      if (proof) {
        integrityVerified = verifyMerkleProof(proof);
        merkleProofPath = proof.path.map(
          (step) => `${step.position}:${step.hash}`
        );
      }
    }

    // The version anchor is a MAC-authenticated MONOTONE floor and a
    // CHECK-AND-RAISE. The two halves are gated differently, on purpose:
    //
    // CHECK (every enforcing read): an entry BELOW the floor is a rollback
    // whether or not this read could resolve a writer key, because the floor's
    // authority comes from the earlier access that set it, not from this one.
    // The throw is also the only signal MOST callers would get. That used to be
    // because exactly one internal consumer inspected `signature_verified` (the
    // cooperative surface's recall path, which denies on it) while every other
    // caller of `read()` dropped it. STATE-READ-REFUSE-01 removed the reliance
    // on that flag by refusing the read outright further down, but this check
    // must still run ABOVE that refusal: a rolled-back entry that also cannot
    // be attributed has to be reported as the rollback it is, not as a generic
    // failure to establish a writer, or the incident the anchor exists to make
    // detectable is downgraded to a compatibility complaint.
    //
    // RAISE (verified reads only): the floor is monotone under SEQUENTIAL
    // access, so a wrong pin is not recoverable by any ordinary later read,
    // while refusing to raise is recoverable on the next verified read. (It is
    // NOT monotone under concurrency: the anchor load-modify-store is not
    // atomic, so interleaved raises can lose one another. That race is
    // byte-identical on the pre-change path and is tracked as
    // STATE-ANCHOR-RACE-01; do not read this line as a concurrency claim.) A legacy (v1) signature binds the ciphertext alone, not
    // namespace/key/version, so an unverified read cannot attest that this
    // entry belongs at this key at this version, and adopting its claimed
    // version would pin the floor from the weakest available source during
    // exactly the incident the anchor exists to make detectable.
    if (options.enforceRollback) {
      if (durableSideEffectsPermitted) {
        await this.observeVersion(namespace, key, stateEntry.ver);
      } else {
        await this.assertNotBelowVersionFloor(namespace, key, stateEntry.ver);
      }
    }

    // REFUSAL (STATE-READ-REFUSE-01): a read that ASKED for verification and
    // could not establish who wrote the entry does not hand the value back. It
    // used to return the plaintext flagged `signature_verified: false`, which
    // made an unestablished writer indistinguishable from an established one
    // for every caller that did not read that flag, and exactly one production
    // consumer did (the cooperative surface's recall path). Returning a value
    // whose provenance this read could not establish is the silent degradation
    // to a less-secure behavior that AGENTS.md MUST-NEVER #5 forbids, and
    // making the safe outcome depend on every future caller remembering a flag
    // is the shape that guarantees the next one forgets. Refusing here moves
    // the obligation from the caller to this line.
    //
    // ORDERING MATTERS IN BOTH DIRECTIONS. This throw sits BELOW the
    // rollback checks on purpose. Those checks are authenticated controls whose
    // authority comes from the persisted floor, not from this read's ability to
    // resolve a writer key, so they must still run and must still WIN when both
    // conditions hold: a rolled-back entry that also cannot be attributed is
    // reported as `rollback_detected`, the strictly more specific and more
    // urgent finding, and refusing earlier would have suppressed detection
    // along with the value (the regression PR #1270's gate caught). It also
    // sits ABOVE the version-cache update on the same reasoning that keeps the
    // durable anchor RAISE behind a verified read. That placement is NOT a
    // claim that an unattributable version never reaches `versionCache`: it
    // still does, from `getNamespaceHashes`, which populates the cache from raw
    // on-disk versions earlier in this same read. That is the separate,
    // still-open residual STATE-CACHE-FLOOR-01 and this change does not narrow
    // it; the placement here only avoids ADDING a second write from a value
    // this line is about to refuse.
    //
    // THE TRIGGER IS "NO AUTHENTICATED WRITER KEY", which is slightly broader
    // than "the writer identity is missing". `resolveWriterPublicKeys` tags a
    // key recovered only from the plaintext registry `trustBasis:
    // "unauthenticated"`, and `verifyEntrySignature` keeps only
    // `"authenticated"` keys, so an entry whose `kid` resolves in that registry
    // and nowhere else still refuses. Written out because the narrower phrasing
    // invites a reader to conclude a registry entry is enough to satisfy this.
    //
    // COMPATIBILITY BOUND, stated plainly because it is a real cost the owner
    // accepted: on a genuinely un-migrated pre-v2 fortress with no
    // authenticated writer key for the entry (the identity is absent from
    // `_identities`, no longer decrypts, or resolves only from the plaintext
    // registry), the affected entries stop returning through `state_read` and
    // through every internal caller of `read()`. Their owner keeps every other sovereignty
    // affordance AGENTS.md MUST-NEVER #2 requires: `state_list` reads metadata
    // without decrypting, `state_export` serializes the stored entries straight
    // from the storage backend, and `state_delete` removes them, none of which
    // route through this function. The migration path is to restore the writer
    // identity into the fortress, after which the first read verifies and
    // migrates the entry to the signed-envelope schema in place;
    // `readUnverified` remains the in-process escape hatch for a migration flow
    // that must reach the plaintext first, and is deliberately not exposed
    // through MCP.
    //
    // THE ONE EXIT FROM THIS REFUSAL is the operator disclosure surface, which
    // does not skip verification (it runs above, and its outcome is what the
    // surface reports) and does not receive this shape: `readUnattributed`
    // converts the result into `UnattributedStateDisclosure` before any caller
    // sees it, so no `signature_verified: false` `ReadResult` escapes this
    // class on that path either. Conditioning on the option rather than on the
    // caller keeps the enforcing read's behavior unchanged for everyone else.
    if (
      options.verifySignature &&
      !signatureVerified &&
      options.unattributedDisclosure !== true
    ) {
      throw new StateVerificationError(
        "writer_unverified",
        `Writer could not be established for ${namespace}/${key}: the enforcing read path returns a value only when signature verification succeeds`
      );
    }

    // Update version cache. Withheld in disclosure mode for the same reason the
    // durable anchor RAISE is: a version this read could not attribute should
    // not be what a later read is measured against.
    //
    // WHAT THIS GUARD DOES NOT DO, stated because an earlier version of this
    // comment claimed it did. It does NOT make a disclosure leave the fortress
    // exactly as it found it, and it does NOT keep an unattributable version
    // out of `versionCache`. `readUnattributed` passes `verifyIntegrity: true`,
    // so `getNamespaceHashes` runs earlier in this same read and seeds the
    // cache from RAW on-disk versions for every key in the namespace, this one
    // included, before control reaches this line. A disclosure therefore can
    // and does set the in-memory floor: disclose an entry, roll it back on
    // disk, disclose again, and the second call reports `rollback_detected`.
    //
    // That is the separate, still-open residual STATE-CACHE-FLOOR-01, written
    // out identically at the refusal block roughly 200 lines above; this change
    // neither widens nor narrows it. What this placement buys is narrower and
    // real: it avoids ADDING a second cache write from a value this read
    // declined to attribute, so the disclosure path contributes nothing the
    // enforcing read would not have contributed anyway. The DURABLE half - the
    // anchor RAISE, the migration, the re-sign - is genuinely withheld, and
    // that is the "no write but the audit record" claim.
    if (options.unattributedDisclosure !== true) {
      this.versionCache.set(vk, stateEntry.ver);
    }

    return {
      key,
      namespace,
      value,
      version: stateEntry.ver,
      integrity_verified: integrityVerified,
      signature_verified: signatureVerified,
      merkle_proof: merkleProofPath,
      written_at: stateEntry.metadata.written_at,
      written_by: stateEntry.kid,
      warnings,
    };
  }

  /**
   * List keys in a namespace (metadata only - no decryption).
   */
  async list(
    namespace: string,
    prefix?: string,
    tags?: string[],
    limit = 100,
    offset = 0
  ): Promise<{
    keys: Array<{
      key: string;
      version: number;
      size_bytes: number;
      written_at: string;
      tags: string[];
    }>;
    total: number;
    merkle_root: string;
  }> {
    const storageEntries = await this.storage.list(namespace, prefix);
    const result: Array<{
      key: string;
      version: number;
      size_bytes: number;
      written_at: string;
      tags: string[];
    }> = [];

    for (const entry of storageEntries) {
      const raw = await this.storage.read(namespace, entry.key);
      if (!raw) continue;

      try {
        const stateEntry: StateEntry = JSON.parse(bytesToString(raw));

        // Filter by tags if specified
        if (tags && tags.length > 0) {
          const entryTags = stateEntry.metadata.tags ?? [];
          const hasMatchingTag = tags.some((t) => entryTags.includes(t));
          if (!hasMatchingTag) continue;
        }

        result.push({
          key: entry.key,
          version: stateEntry.ver,
          size_bytes: entry.size_bytes,
          written_at: stateEntry.metadata.written_at,
          tags: stateEntry.metadata.tags ?? [],
        });
      } catch {
        // Skip corrupted entries
      }
    }

    const nsHashes = await this.getNamespaceHashes(namespace);
    const merkleRoot = computeMerkleRoot(nsHashes);

    return {
      keys: result.slice(offset, offset + limit),
      total: result.length,
      merkle_root: merkleRoot,
    };
  }

  /**
   * Securely delete state (overwrite with random bytes before removal).
   */
  async delete(
    namespace: string,
    key: string
  ): Promise<{
    deleted: boolean;
    key: string;
    namespace: string;
    new_merkle_root: string;
    deleted_at: string;
  }> {
    const deleted = await this.storage.delete(namespace, key, true);

    // Update caches
    const vk = this.versionKey(namespace, key);
    this.versionCache.delete(vk);
    const nsHashes = await this.getNamespaceHashes(namespace);
    nsHashes.delete(key);
    const merkleRoot = computeMerkleRoot(nsHashes);

    return {
      deleted,
      key,
      namespace,
      new_merkle_root: merkleRoot,
      deleted_at: new Date().toISOString(),
    };
  }

  /**
   * Export all state for a namespace as an encrypted bundle.
   */
  async export(
    namespace?: string
  ): Promise<{
    bundle: string;
    namespaces: string[];
    total_keys: number;
    bundle_hash: string;
    exported_at: string;
    completeness_manifest: StateExportCompletenessManifest;
  }> {
    return this.exportNamespaces(
      namespace === undefined ? undefined : [namespace]
    );
  }

  listCachedExportableNamespaces(): string[] {
    return [...this.contentHashes.keys()]
      .filter((namespace) => !namespace.startsWith("_"))
      .sort();
  }

  async exportNamespaces(
    requestedNamespaces?: string[]
  ): Promise<{
    bundle: string;
    namespaces: string[];
    total_keys: number;
    bundle_hash: string;
    exported_at: string;
    completeness_manifest: StateExportCompletenessManifest;
  }> {
    const namespacesToExport: string[] = [];

    // F6: never export internal `_`-prefixed namespaces - import() rejects them
    // (so they cannot round-trip) and they are internal-subsystem state external
    // export must not expose. Filter HERE (not mid-loop) so the serialized
    // `namespaces` metadata and `data` stay consistent: the bundle never lists a
    // namespace it does not actually contain.
    if (requestedNamespaces) {
      for (const namespace of requestedNamespaces) {
        if (!namespace.startsWith("_") && !namespacesToExport.includes(namespace)) {
          namespacesToExport.push(namespace);
        }
      }
    } else {
      // Discover all namespaces from the content hash cache
      namespacesToExport.push(...this.listCachedExportableNamespaces());
    }

    const exportData: Record<
      string,
      Array<{ key: string; entry: StateEntry }>
    > = {};
    const facadeHiddenMarkers: Array<{ key: string; marker: unknown }> = [];
    let totalKeys = 0;

    for (const ns of namespacesToExport) {
      const entries = await this.storage.list(ns);
      exportData[ns] = [];

      for (const entry of entries) {
        const raw = await this.storage.read(ns, entry.key);
        if (!raw) continue;

        try {
          const stateEntry: StateEntry = JSON.parse(bytesToString(raw));
          exportData[ns]!.push({ key: entry.key, entry: stateEntry });
          totalKeys++;
        } catch {
          // Skip corrupted entries
        }
      }
    }

    const markerEntries = await this.storage.list(FACADE_HIDDEN_MARKER_NAMESPACE);
    for (const entry of markerEntries) {
      const raw = await this.storage.read(FACADE_HIDDEN_MARKER_NAMESPACE, entry.key);
      if (!raw) continue;
      const marker = parseFacadeHiddenMarker(raw);
      if (!marker || !namespacesToExport.includes(marker.namespace)) continue;
      facadeHiddenMarkers.push({
        key: entry.key,
        marker: JSON.parse(bytesToString(raw)) as unknown,
      });
    }

    const exportedAt = new Date().toISOString();
    const completenessManifest = buildCompletenessManifest(
      exportedAt,
      exportData
    );
    const bundleRecord: StateExportBundle = {
      sanctuary_export_version: STATE_EXPORT_BUNDLE_SCHEMA_VERSION,
      format: STATE_EXPORT_FORMAT,
      exported_at: exportedAt,
      namespaces: namespacesToExport,
      data: exportData,
      ...(facadeHiddenMarkers.length > 0
        ? { facade_hidden_markers: facadeHiddenMarkers }
        : {}),
      completeness_manifest: completenessManifest,
    };
    bundleRecord.bundle_integrity = this.createExportBundleIntegrity(
      bundleRecord
    );

    const bundleJson = JSON.stringify(bundleRecord);
    const bundleBytes = stringToBytes(bundleJson);
    const bundleHash = hashToString(bundleBytes);

    return {
      bundle: toBase64url(bundleBytes),
      namespaces: namespacesToExport,
      total_keys: totalKeys,
      bundle_hash: bundleHash,
      exported_at: exportedAt,
      completeness_manifest: completenessManifest,
    };
  }

  /**
   * Import a previously exported state bundle.
   */
  async import(
    bundleBase64: string,
    conflictResolution: "skip" | "overwrite" | "version" = "skip",
    publicKeyResolver: (kid: string) => Uint8Array | null,
    options: { allowUnverifiedLegacy?: boolean } = {}
  ): Promise<{
    imported_keys: number;
    skipped_keys: number;
    skipped_invalid_sig: number;
    skipped_unknown_kid: number;
    conflicts: number;
    namespaces: string[];
    imported_at: string;
    completeness_verification: StateExportCompletenessVerification;
  }> {
    const bundle = parseExportBundleObject(bundleBase64);
    assertSupportedExportBundleSchema(bundle);
    const data = readExportData(bundle);
    assertBundleNamespaceMetadataMatches(bundle, data);
    const completenessVerification = this.verifyExportBundleCompleteness(
      bundle,
      data,
      options.allowUnverifiedLegacy === true
    );

    let importedKeys = 0;
    let skippedKeys = 0;
    let skippedInvalidSig = 0;
    let skippedUnknownKid = 0;
    let conflicts = 0;
    const namespaces: string[] = [];

    for (const [ns, entries] of Object.entries(data)) {
      // Namespace firewall: skip reserved namespaces during import.
      // RESERVED-NS-DIVERGE-01: `isReservedNamespace` applies the blanket
      // underscore rule itself, so this check can't miss a newer internal
      // `_`-namespace the curated list hasn't caught up with yet. Export
      // never emits a `_`-prefixed namespace, so any in a bundle is crafted.
      if (isReservedNamespace(ns)) {
        skippedKeys += entries.length;
        continue;
      }
      namespaces.push(ns);

      for (const { key, entry } of entries) {
        // Signature verification: mandatory for all imported entries
        // Resolve the signing identity
        const signerPublicKey = publicKeyResolver(entry.kid);
        if (!signerPublicKey) {
          skippedUnknownKid++;
          skippedKeys++;
          continue;
        }

        // Verify the signature against the signed envelope or legacy ciphertext.
        try {
          if (
            entry.v !== 1 &&
            entry.v !== LEGACY_STATE_ENVELOPE_SCHEMA_VERSION &&
            entry.v !== STATE_ENVELOPE_SCHEMA_VERSION
          ) {
            skippedInvalidSig++;
            skippedKeys++;
            continue;
          }
          const signaturePayload =
            entry.v === LEGACY_STATE_ENVELOPE_SCHEMA_VERSION ||
            entry.v === STATE_ENVELOPE_SCHEMA_VERSION
              ? stateEnvelopeSigningBytes(
                  this.validateSignedEnvelope(entry, ns, key)
                )
              : fromBase64url(entry.payload.ct);
          const signature =
            entry.v === LEGACY_STATE_ENVELOPE_SCHEMA_VERSION ||
            entry.v === STATE_ENVELOPE_SCHEMA_VERSION
              ? entry.envelope_sig
              : entry.sig;
          if (!signature) {
            skippedInvalidSig++;
            skippedKeys++;
            continue;
          }
          const sigValid = verify(
            signaturePayload,
            fromBase64url(signature),
            signerPublicKey
          );
          if (!sigValid) {
            skippedInvalidSig++;
            skippedKeys++;
            continue;
          }
          if (
            entry.v === LEGACY_STATE_ENVELOPE_SCHEMA_VERSION ||
            entry.v === STATE_ENVELOPE_SCHEMA_VERSION
          ) {
            const legacySigValid = verify(
              fromBase64url(entry.payload.ct),
              fromBase64url(entry.sig),
              signerPublicKey
            );
            if (!legacySigValid) {
              skippedInvalidSig++;
              skippedKeys++;
              continue;
            }
          }
        } catch {
          // Malformed signature or ciphertext - reject
          skippedInvalidSig++;
          skippedKeys++;
          continue;
        }

        const exists = await this.storage.exists(ns, key);

        if (exists) {
          conflicts++;
          if (conflictResolution === "skip") {
            skippedKeys++;
            continue;
          }
          if (conflictResolution === "version") {
            // Only overwrite if imported version is higher
            const raw = await this.storage.read(ns, key);
            if (raw) {
              try {
                const existingEntry: StateEntry = JSON.parse(
                  bytesToString(raw)
                );
                if (entry.ver <= existingEntry.ver) {
                  skippedKeys++;
                  continue;
                }
              } catch {
                // Corrupted existing entry - overwrite
              }
            }
          }
          // conflictResolution === "overwrite" falls through
        }

        // Write the entry
        const serialized = stringToBytes(JSON.stringify(entry));
        await this.storage.write(ns, key, serialized);
        importedKeys++;

        // Update caches
        const vk = this.versionKey(ns, key);
        this.versionCache.set(vk, entry.ver);
        const nsHashes = await this.getNamespaceHashes(ns);
        nsHashes.set(key, entry.integrity_hash);
      }
    }

    if (Array.isArray(bundle.facade_hidden_markers)) {
      const importedNamespaceSet = new Set(namespaces);
      for (const item of bundle.facade_hidden_markers) {
        if (!item || typeof item !== "object" || Array.isArray(item)) continue;
        const record = item as Record<string, unknown>;
        if (typeof record.key !== "string" || record.key.includes("/") || record.key.length > 256) continue;
        const marker = record.marker;
        if (!marker || typeof marker !== "object" || Array.isArray(marker)) continue;
        const markerRecord = marker as Record<string, unknown>;
        if (
          typeof markerRecord.namespace !== "string" ||
          typeof markerRecord.key !== "string" ||
          !importedNamespaceSet.has(markerRecord.namespace)
        ) {
          continue;
        }
        await this.storage.write(
          FACADE_HIDDEN_MARKER_NAMESPACE,
          record.key,
          stringToBytes(JSON.stringify(markerRecord))
        );
      }
    }

    return {
      imported_keys: importedKeys,
      skipped_keys: skippedKeys,
      skipped_invalid_sig: skippedInvalidSig,
      skipped_unknown_kid: skippedUnknownKid,
      conflicts,
      namespaces,
      imported_at: new Date().toISOString(),
      completeness_verification: completenessVerification,
    };
  }
}

// Master-rotation helpers (core/master-rotation.ts)
//
// State entries cryptographically bind their CIPHERTEXT to the writer
// identity (the v2 envelope signs nonce/tag/ciphertext; the legacy v1 `sig`
// signs the raw ciphertext), so a master rotation cannot simply re-encrypt a
// state entry - it must re-sign with the original writer's resident private
// key. These helpers keep the canonical envelope/signature construction in
// this module (single source of truth) while the rotation engine drives the
// walk. They never relax verification: the OLD entry's signatures are
// verified BEFORE re-signing (a rotation must not launder a tampered entry
// into a freshly-signed one), and a missing writer identity fails closed.

/** Writer material the rotation engine resolved for a state entry's kid. */
export interface RotationWriterMaterial {
  /** The writer's encrypted private key (under `identityEncryptionKey`). */
  encryptedPrivateKey: EncPayload;
  /** The identity-encryption purpose key that decrypts it. */
  identityEncryptionKey: Uint8Array;
  /** The writer's current Ed25519 public key. */
  publicKey: Uint8Array;
  /**
   * Authenticated public keys for this kid: current plus valid historical
   * rotation-chain keys. Plaintext-registry keys are never placed here.
   */
  verificationPublicKeys: ResolvedWriterPublicKey[];
}

export class RotationStateEntryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RotationStateEntryError";
  }
}

export type RotateStateEntryResult =
  | { status: "already-new" }
  | { status: "verified-old" }
  | { status: "converted"; bytes: Uint8Array };

/**
 * Verify (and, unless `verifyOnly`, re-encrypt + re-sign) one persisted
 * state entry for a master rotation.
 *
 *  - Decrypts under the NEW namespace key first -> "already-new" (idempotent
 *    resume; GCM authentication decides).
 *  - Otherwise decrypts under the OLD namespace key (failure throws - the
 *    rotation preflight aborts; nothing is mutated on an undecryptable
 *    fortress).
 *  - Verifies the OLD entry's signature(s) against one authenticated key in
 *    the writer's key chain before producing anything (no laundering).
 *  - Re-encrypts the plaintext under the new key and re-signs with the
 *    writer's resident private key. Version, integrity_hash (plaintext
 *    hash), metadata, and kid are all preserved - only the ciphertext block
 *    and the signatures over it change.
 */
export async function rotateStateEntryBytes(args: {
  raw: Uint8Array;
  namespace: string;
  key: string;
  oldNamespaceKey: Uint8Array;
  newNamespaceKey: Uint8Array;
  resolveWriter: (kid: string) => Promise<RotationWriterMaterial | null>;
  verifyOnly?: boolean;
}): Promise<RotateStateEntryResult> {
  const { namespace, key } = args;
  let entry: StateEntry;
  try {
    entry = JSON.parse(bytesToString(args.raw)) as StateEntry;
  } catch {
    throw new RotationStateEntryError(
      `state entry ${namespace}/${key} is not valid JSON`
    );
  }
  if (!entry || typeof entry !== "object" || !entry.payload) {
    throw new RotationStateEntryError(
      `state entry ${namespace}/${key} has no encrypted payload`
    );
  }

  // Idempotent resume: an entry that already authenticates under the new
  // namespace key was converted before the crash.
  try {
    decrypt(entry.payload, args.newNamespaceKey).fill(0);
    return { status: "already-new" };
  } catch {
    // Not yet converted - proceed with the old key.
  }

  let plaintext: Uint8Array;
  try {
    plaintext = decrypt(entry.payload, args.oldNamespaceKey);
  } catch {
    throw new RotationStateEntryError(
      `state entry ${namespace}/${key} does not decrypt under either the old or the new master`
    );
  }

  // `entry.kid` came straight out of `JSON.parse`, so the `StateEntry`
  // annotation is an assertion. It is handed to a caller-supplied resolver that
  // will use it as a lookup key, and String() coercion of a deeply nested value
  // overflows the stack there. Refuse it with the typed rotation error the
  // operator can act on, rather than letting a RangeError escape and read as an
  // unrelated failure (STATE-STORE-ERRMSG-INTERP-01).
  if (typeof entry.kid !== "string") {
    throw new RotationStateEntryError(
      `state entry ${namespace}/${key} has a malformed writer identity (kid): ` +
        `${describeUntrusted(entry.kid)}. Rotation re-signs every state entry ` +
        `with its writer's key and cannot identify one here. Restore the entry ` +
        `from a good backup, or delete it, then retry.`
    );
  }

  try {
    const writer = await args.resolveWriter(entry.kid);
    if (!writer) {
      throw new RotationStateEntryError(
        `state entry ${namespace}/${key} was written by identity "${describeUntrusted(entry.kid)}", ` +
          `which is not resident in this fortress. Rotation re-signs every state ` +
          `entry with its writer's key and cannot proceed without it. ` +
          `Re-import the identity, or delete the orphaned entry, then retry.`
      );
    }

    const verificationPublicKeys = writer.verificationPublicKeys.map(
      (candidate) => candidate.publicKey
    );
    if (verificationPublicKeys.length === 0) {
      throw new RotationStateEntryError(
        `state entry ${namespace}/${key} has no authenticated writer key chain for identity "${describeUntrusted(entry.kid)}"; refusing to re-sign it`
      );
    }

    // Verify the OLD signatures before re-signing anything.
    if (entry.v === 1) {
      if (
        typeof entry.sig !== "string" ||
        !verificationPublicKeys.some((publicKey) =>
          verify(
            fromBase64url(entry.payload.ct),
            fromBase64url(entry.sig),
            publicKey
          )
        )
      ) {
        throw new RotationStateEntryError(
          `state entry ${namespace}/${key} failed legacy signature verification; refusing to re-sign it`
        );
      }
    } else {
      if (!entry.envelope || typeof entry.envelope_sig !== "string") {
        throw new RotationStateEntryError(
          `state entry ${namespace}/${key} is schema ${describeUntrusted(entry.v)} but is missing its signed envelope`
        );
      }
      const expected = buildSignedEnvelope({
        namespace,
        key,
        version: entry.ver,
        kid: entry.kid,
        schemaVersion: entry.v,
        metadata: entry.metadata,
        ...(entry.provenance_stamp !== undefined
          ? { provenanceStamp: entry.provenance_stamp }
          : {}),
        integrityHash: entry.integrity_hash,
        payload: entry.payload,
      });
      if (canonicalJson(entry.envelope) !== canonicalJson(expected)) {
        throw new RotationStateEntryError(
          `state entry ${namespace}/${key} envelope metadata mismatch; refusing to re-sign it`
        );
      }
      const signedEnvelope = stateEnvelopeSigningBytes(entry.envelope);
      const envelopeSig = fromBase64url(entry.envelope_sig);
      const legacyCiphertext = fromBase64url(entry.payload.ct);
      const legacySig =
        typeof entry.sig === "string" ? fromBase64url(entry.sig) : null;
      const sigValid =
        legacySig !== null &&
        verificationPublicKeys.some((publicKey) =>
          verify(signedEnvelope, envelopeSig, publicKey) &&
          verify(legacyCiphertext, legacySig, publicKey)
        );
      if (!sigValid) {
        throw new RotationStateEntryError(
          `state entry ${namespace}/${key} failed signature verification; refusing to re-sign it`
        );
      }
    }

    if (args.verifyOnly) {
      return { status: "verified-old" };
    }

    const newPayload = encrypt(plaintext, args.newNamespaceKey);
    const legacySig = sign(
      fromBase64url(newPayload.ct),
      writer.encryptedPrivateKey,
      writer.identityEncryptionKey
    );

    let rotated: StateEntry;
    if (entry.v === 1) {
      rotated = { ...entry, payload: newPayload, sig: toBase64url(legacySig) };
    } else {
      const envelope = buildSignedEnvelope({
        namespace,
        key,
        version: entry.ver,
        kid: entry.kid,
        schemaVersion: entry.v,
        metadata: entry.metadata,
        ...(entry.provenance_stamp !== undefined
          ? { provenanceStamp: entry.provenance_stamp }
          : {}),
        integrityHash: entry.integrity_hash,
        payload: newPayload,
      });
      const envelopeSig = sign(
        stateEnvelopeSigningBytes(envelope),
        writer.encryptedPrivateKey,
        writer.identityEncryptionKey
      );
      rotated = {
        ...entry,
        envelope,
        payload: newPayload,
        sig: toBase64url(legacySig),
        envelope_sig: toBase64url(envelopeSig),
      };
    }
    return {
      status: "converted",
      bytes: stringToBytes(JSON.stringify(rotated)),
    };
  } finally {
    plaintext.fill(0);
  }
}

/** `_meta` keys owned by the state store (for the rotation walker). */
export const STATE_META_PUBLIC_KEYS_KEY = STATE_ENVELOPE_PUBLIC_KEYS_KEY;
export const STATE_META_VERSION_ANCHORS_KEY = STATE_ENVELOPE_VERSION_ANCHORS_KEY;

/**
 * Re-MAC the version-anchor `_meta` record for a master rotation.
 *
 * Returns:
 *  - null            - record is bare/legacy (no MAC marker): untrusted today
 *    and left untouched; the floor re-derives from authenticated entries.
 *  - "already-new"   - MAC already verifies under the new master (resume).
 *  - bytes           - restamped record, after the OLD MAC verified.
 *
 * Throws when the record carries the marker but its MAC verifies under
 * NEITHER master - that is tampering, and a rotation must not launder it
 * into a freshly-authenticated record.
 */
export function rotateStateMetaRecordBytes(args: {
  raw: Uint8Array;
  metaKey: string;
  oldMasterKey: Uint8Array;
  newMasterKey: Uint8Array;
}): Uint8Array | "already-new" | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToString(args.raw));
  } catch {
    throw new RotationStateEntryError(
      `state meta record _meta/${args.metaKey} is not valid JSON`
    );
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new RotationStateEntryError(
      `state meta record _meta/${args.metaKey} is malformed`
    );
  }
  const obj = parsed as Record<string, unknown>;
  if (obj[STATE_META_MAC_MARKER] !== true) {
    return null; // Bare/legacy record: untrusted, leave as-is.
  }
  const data = obj.data;
  const mac = obj.mac;
  if (!data || typeof data !== "object" || Array.isArray(data) || typeof mac !== "string") {
    throw new RotationStateEntryError(
      `state meta record _meta/${args.metaKey} is malformed`
    );
  }
  const record = data as Record<string, unknown>;
  const macFor = (master: Uint8Array): Uint8Array => {
    const macKey = derivePurposeKey(master, "state-meta-mac");
    const out = hmacSha256(
      macKey,
      stringToBytes(STATE_META_MAC_DOMAIN + args.metaKey + "\n" + canonicalJson(record))
    );
    macKey.fill(0);
    return out;
  };
  let provided: Uint8Array;
  try {
    provided = fromBase64url(mac);
  } catch {
    throw new RotationStateEntryError(
      `state meta record _meta/${args.metaKey} MAC is malformed`
    );
  }
  if (constantTimeEqual(provided, macFor(args.newMasterKey))) {
    return "already-new";
  }
  if (!constantTimeEqual(provided, macFor(args.oldMasterKey))) {
    throw new RotationStateEntryError(
      `state meta record _meta/${args.metaKey} failed authentication under both masters (tampered); refusing to restamp it`
    );
  }
  const restamped = {
    [STATE_META_MAC_MARKER]: true,
    data: record,
    mac: toBase64url(macFor(args.newMasterKey)),
  };
  return stringToBytes(JSON.stringify(restamped));
}
