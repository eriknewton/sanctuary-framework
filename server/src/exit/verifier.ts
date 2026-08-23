/**
 * Sanctuary v1.1 exit-bundle verifier.
 *
 * Verifies the signed SANCTUARY_EXIT_BUNDLE_V1 manifest, every artifact hash,
 * and the exported identity / reputation signatures and exported-set
 * completeness manifests that are independently verifiable from public
 * material in the bundle.
 */

/**
 * v1.2.1 (Finding PPP): thrown when a directory is not a valid exit bundle
 * (e.g., missing manifest.json). Distinguished from verification failures
 * (signature mismatch, hash mismatch) which return `passed: false`.
 */
export class InvalidExitBundleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidExitBundleError";
  }
}

import { lstat, readdir, realpath } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";
import {
  EXIT_BUNDLE_ARTIFACT_KINDS,
  EXIT_BUNDLE_ARTIFACT_KINDS_V1_KNOWN_SIGNERS,
  EXIT_BUNDLE_MANIFEST_VERSION,
  EXIT_BUNDLE_MANIFEST_VERSION_KNOWN_SIGNERS,
  SIGNATURE_SCHEME_V1,
  type ExitBundleArtifactKind,
} from "../contracts/v1.1/constants.js";
import {
  EXIT_BUNDLE_PATH_MAX_BYTES,
  EXIT_BUNDLE_PATH_PATTERN,
  type ExitBundleArtifactEntry,
  type ExitBundleManifest,
  type ExitBundleVerifierResult,
} from "../contracts/v1.1/exit-bundle-manifest.js";
import { fromBase64url, fromBase64urlStrict, stringToBytes } from "../core/encoding.js";
import {
  SUPPORTED_PAYLOAD_VERSION,
  SUPPORTED_PAYLOAD_ALG,
  PAYLOAD_IV_BYTE_LENGTH,
} from "../core/encryption.js";
import { publicKeyToDid, publicKeyBytesEqual } from "../core/identity.js";
import { EXIT_KNOWN_SIGNERS_DOMAIN } from "../core/crypto-suite-registry.js";
import { ED25519_PUBLIC_KEY_BYTES } from "../core/crypto-suite-registry.js";
import { isReservedNamespace } from "../cognitive/state-store.js";
import {
  verifyRotationChain,
  type RotationChainInvalidReason,
} from "../core/rotation-chain.js";
import { parseKeyDerivationParams } from "../core/key-derivation.js";
import { hash } from "../core/hashing.js";
import { canonicalize, canonicalizeToBytes } from "../mesh/canonical-json.js";
import {
  reputationBundleSigningBytes,
  verifyReputationBundleCompleteness,
  type ReputationBundle,
  type ReputationBundleCompletenessVerification,
} from "../reputation/reputation-store.js";
import {
  readFileCustody,
  readFileCustodyWithStats,
} from "../storage/custody-fs.js";
import {
  readSourceCustodyState,
  type SourceCustodyState,
} from "./source-custody.js";
// an exit-bundle manifest is `JSON.parse`d from an imported archive, so every
// artifact field is attacker-supplied and goes through the untrusted-
// diagnostic chokepoint (STATE-STORE-ERRMSG-INTERP-01).
import { describeUntrusted } from "../errors/index.js";

/**
 * Which re-key material the encrypted_state artifact DECLARES it needs, read
 * from the artifact alone (no fortress access, no operator secret).
 *
 * This is deliberately a statement about the ARTIFACT, not a prediction about
 * an import. Three successive attempts to make it the latter failed the same
 * way: a classifier that has no credential cannot know whether an import will
 * succeed, and each time it claimed to, the claim was wrong for some bundle.
 * Read every member below as "the bundle says it needs X", never as "X will
 * work":
 *
 *  `bundle-rekey-key`     a well-formed `source_custody` block is present, so
 *                         the bundle re-key key minted at export is the
 *                         credential it names.
 *  `legacy-passphrase`    no custody block, but well-formed legacy
 *                         `source_key_derivation` parameters, so the bundle
 *                         names the source fortress passphrase.
 *  `none-declared`        the artifact carries state and declares NO re-key
 *                         material of either kind. Pre-envelope bundles look
 *                         like this, and for them the source recovery key IS
 *                         the master - but nothing in the artifact says so, and
 *                         inspect does not guess (see the `--legacy-source-master`
 *                         opt-in on the import branch of `cli.ts`).
 *  `no-state`             the artifact carries a readable, empty entry list, so
 *                         it declares no re-key material because there is
 *                         nothing to re-key.
 *  `damaged`              the artifact DECLARES re-key material and that
 *                         material does not have a usable shape, or its entry
 *                         list cannot be read at all. Something is wrong with
 *                         the artifact itself; this one is a statement about
 *                         damage, not about what an import would do with it.
 *
 * CONTRACT PIN (server/src/exit/source-custody.ts `isValidSourceCustody` and
 * server/src/core/key-derivation.ts `parseKeyDerivationParams`): the two
 * shape-checks are not restated here - both sides call the same validators, so
 * `valid` and `malformed` mean here exactly what they mean at the import gate.
 * Held mechanically by the custody differential in
 * server/test/exit/exit-inspect-declares.test.ts, which drives every crafted
 * block through both `exit inspect` and a real `importExitBundle` and asserts
 * they never CONTRADICT each other.
 */
export type ExitBundleDeclaredRekeyMaterial =
  | "bundle-rekey-key"
  | "legacy-passphrase"
  | "none-declared"
  | "no-state"
  | "damaged";

/**
 * What the encrypted_state artifact says about itself, read from the parsed
 * JSON without trusting any declared type. Deliberately structural: the
 * verifier must not import `ExitEncryptedStateBundle` from bundle.ts (bundle.ts
 * already imports this module, and the reverse edge would be an import cycle),
 * and a verifier that narrows untrusted JSON itself is the right posture anyway.
 */
export interface ExitEncryptedStateSummary {
  /**
   * How many state entries the artifact carries, or `null` when its `entries`
   * field is absent or is not an array.
   *
   * INVARIANT: `null` is NOT `0`, and collapsing the two is the defect this
   * field's type exists to prevent. A malformed artifact reported as zero
   * entries reads to an operator as a benign empty bundle, and the import that
   * follows dereferences `entries.length` on the same artifact and does not
   * agree. Absent is not empty; every consumer must branch on it.
   */
  entry_count: number | null;
  namespace_count: number;
  namespaces: string[];
  ownership_partitioned: boolean;
  /**
   * CONTRACT PIN (server/src/exit/bundle.ts `EXIT_EMPTY_REASONS`): the token
   * set is owned there; this field carries whatever the artifact declared,
   * verbatim, so an unknown future token surfaces rather than being erased.
   */
  empty_reason?: string;
  /**
   * True IFF the artifact carries a READABLE, EMPTY entry list and declares no
   * `empty_reason`. False when `entry_count` is `null`: an artifact whose
   * entries cannot be read is a different, louder problem, and reporting a
   * missing empty-marker for it would name the wrong defect.
   */
  empty_reason_missing: boolean;
  /**
   * EXIT-STRUCT-02, one level deeper than `entry_count === null`: true IFF
   * `entries` is a READABLE array (`entry_count !== null`) but contains at
   * least one element that fails {@link isWellFormedExitStateEntryElement} -
   * e.g. `null`, or missing/wrong-typed `namespace`/`entry`/`entry.kid`/
   * `entry.payload.ct`/`entry.sig`. Always `false` when `entry_count` is
   * `null`: that is the separate, already-covered LD2-01 case. A correctly
   * hashed and signed artifact can pass the container check this field's
   * sibling watches and still crash import at its first per-element
   * dereference; this field is what lets the aggregator catch that before
   * import ever runs.
   */
  entries_malformed: boolean;
  /**
   * G-6 (coordinator gate, 2026-08-22): WHICH problem `checkEncryptedStateStructure`
   * found, so a caller can name it (a stale `total_keys`, a reserved
   * namespace entry, an unreadable/malformed entry) instead of a single
   * generic "malformed" message that cannot distinguish them. `undefined`
   * when the artifact is structurally sound. Additive/diagnostic only -
   * `entries_malformed` and `entry_count === null` remain the gating
   * signals; this field never changes what fails closed, only what the
   * operator is told about why.
   */
  structural_problem?: EncryptedStateStructureProblem;
  legacy_kdf_params: "absent" | "valid" | "malformed";
  /**
   * The same three-state read of `source_custody` the import gate performs.
   * Reported alongside {@link declared_rekey_material} because both a damaged
   * custody block and a damaged legacy marker collapse to `damaged`, and the
   * operator needs to know WHICH block is broken to know what to re-export.
   */
  source_custody: SourceCustodyState;
  declared_rekey_material: ExitBundleDeclaredRekeyMaterial;
}

export interface ExitBundleDetailedVerifierResult
  extends ExitBundleVerifierResult {
  manifest_path: string;
  manifest_hash: string | null;
  warnings: string[];
  unsupported_artifacts: string[];
  /**
   * Additive: what the encrypted_state artifact carries and which credential
   * re-keys it. Absent when the bundle has no encrypted_state artifact or the
   * verifier failed before the artifact pass. This is a verifier-local
   * interface, NOT the frozen `ExitBundleVerifierResult` contract type.
   */
  state?: ExitEncryptedStateSummary;
  identity?: {
    signature_valid: boolean;
    identity_id?: string;
    did?: string;
    rotation?: {
      hop_count: number;
      chain_signature_verified: boolean;
      terminates_at_current: boolean;
      invalid_reason?: RotationChainInvalidReason;
      invalid_detail?: string;
      compromised_hops: number;
    };
  };
  audit?: {
    receipt_count: number;
    individual_signatures_verified: boolean;
  };
  reputation?: {
    bundle_signature_valid: boolean | "unverifiable";
    completeness:
      | ReputationBundleCompletenessVerification
      | "mismatch";
    completeness_error?: string;
    attestation_count: number;
    verified_attestations: number;
    invalid_attestations: number;
    unverifiable_attestations: number;
    first_unverifiable_signer_prefix?: string;
  };
}

export interface LoadedExitArtifact<T = unknown> {
  entry: ExitBundleArtifactEntry;
  path: string;
  json: T;
  bytes: Uint8Array;
}

type ExitBundleFailureClass =
  NonNullable<ExitBundleVerifierResult["failure_class"]>;

interface IdentityArtifactVerification {
  signature_valid: boolean;
  identity_id?: string;
  did?: string;
  public_key?: string;
  rotation_history?: unknown;
}

interface IdentityBindingVerificationResult {
  identityVerification?: IdentityArtifactVerification;
  failure_class?: ExitBundleFailureClass;
  warnings: string[];
}

const PRIVATE_MATERIAL_KEYS = new Set([
  "private_key",
  "privatekey",
  "encrypted_private_key",
  "encryptedprivatekey",
  "passphrase",
  "recovery_key",
  "recoverykey",
  "seed",
  "mnemonic",
]);

function sha256Hex(bytes: Uint8Array): string {
  return Array.from(hash(bytes))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function resultBase(
  bundleDir: string,
  manifest: ExitBundleManifest | null,
  warnings: string[] = [],
  unsupported: string[] = []
): ExitBundleDetailedVerifierResult {
  const body = manifest?.body;
  return {
    version: "1.1",
    passed: false,
    verified_at: new Date().toISOString(),
    manifest_path: join(bundleDir, "manifest.json"),
    manifest_hash: null,
    manifest_summary: {
      manifest_version:
        body?.manifest_version ?? EXIT_BUNDLE_MANIFEST_VERSION,
      fortress_id: body?.identity_binding?.fortress_id ?? "",
      identity_id: body?.identity_binding?.identity_id ?? "",
      exported_at: body?.exported_at ?? "",
      artifact_count: body?.artifacts?.length ?? 0,
    },
    artifact_results:
      body?.artifacts?.map((artifact) => ({
        path: artifact.path,
        kind: artifact.kind,
        hash_passed: false,
        size_passed: false,
      })) ?? [],
    warnings,
    unsupported_artifacts: unsupported,
  };
}

function fail(
  bundleDir: string,
  manifest: ExitBundleManifest | null,
  failureClass: NonNullable<ExitBundleVerifierResult["failure_class"]>,
  warnings: string[] = [],
  unsupported: string[] = []
): ExitBundleDetailedVerifierResult {
  return {
    ...resultBase(bundleDir, manifest, warnings, unsupported),
    failure_class: failureClass,
  };
}

function isKnownKind(kind: string): kind is ExitBundleArtifactKind {
  // Syntactic recognition only, across every manifest version - see
  // ExitBundleArtifactKind's doc comment (constants.ts). The exact
  // per-version SET (which kinds a given manifest_version must carry, no
  // more, no fewer) is enforced separately below.
  return (EXIT_BUNDLE_ARTIFACT_KINDS_V1_KNOWN_SIGNERS as readonly string[]).includes(kind);
}

function validateArtifactPath(path: string): "ok" | "unsafe" {
  if (Buffer.byteLength(path, "utf8") > EXIT_BUNDLE_PATH_MAX_BYTES) {
    return "unsafe";
  }
  if (!EXIT_BUNDLE_PATH_PATTERN.test(path)) return "unsafe";
  if (path.startsWith("/") || path.includes("\\") || path.includes("\0")) {
    return "unsafe";
  }
  const normalized = decodeURIComponentSafe(path).normalize("NFKC");
  if (normalized.split("/").some((segment) => segment === "." || segment === "..")) {
    return "unsafe";
  }
  return "ok";
}

function decodeURIComponentSafe(value: string): string {
  let current = value;
  for (let i = 0; i < 2; i++) {
    try {
      const decoded = decodeURIComponent(current);
      if (decoded === current) return decoded;
      current = decoded;
    } catch {
      return current;
    }
  }
  return current;
}

async function assertDescendant(root: string, candidate: string): Promise<boolean> {
  const rootReal = await realpath(root);
  const candidateDir = await realpath(dirname(candidate));
  const rootWithSep = rootReal.endsWith(sep) ? rootReal : rootReal + sep;
  return candidateDir === rootReal || candidateDir.startsWith(rootWithSep);
}

/**
 * Bound on how many files `listBundleFiles` will enumerate before refusing
 * (AGENTS.md rule 8: attacker-controlled input - an imported bundle - gets
 * an explicit per-request work cap, never unbounded recursion). 10,000 is
 * generous over any legitimate bundle (today's largest manifest carries 8
 * artifacts plus manifest.json); a directory this large is refused outright
 * rather than walked to completion.
 */
const MAX_BUNDLE_DIRECTORY_ENTRIES = 10_000;

/**
 * Recursively list every FILE (not directory) under `root`, as paths
 * relative to `root` in POSIX form - independent gate on #1303, item 5:
 * verification must see what is actually on disk, not only what the
 * manifest claims is there. A symlink is recorded too (never followed) so
 * an unlisted symlink is caught by the same "unlisted" check the caller
 * runs, rather than silently skipped. Returns `"too_many"` instead of a
 * partial list if the walk would exceed `maxEntries` - a truncated list
 * could let files past the cap hide as "not found", which is the opposite
 * of fail-closed.
 */
async function listBundleFiles(
  root: string,
  maxEntries: number
): Promise<string[] | "too_many"> {
  const out: string[] = [];
  async function walk(dir: string, relPrefix: string): Promise<boolean> {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      // Unreadable directory: no files to report from here. Defensive only
      // - every directory this walk descends into was itself just listed
      // by readdir a moment earlier.
      return true;
    }
    for (const entry of entries) {
      if (out.length >= maxEntries) return false;
      const relPath = relPrefix
        ? `${relPrefix}/${entry.name}`
        : entry.name;
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        const ok = await walk(fullPath, relPath);
        if (!ok) return false;
        continue;
      }
      // Files AND symlinks are both recorded (never followed) - an
      // unlisted symlink is exactly as unaccountable as an unlisted
      // regular file, and the manifest's declared artifact paths are
      // never expected to name a symlink at all (a LISTED symlink is
      // refused separately, at the per-artifact hash/read loop, via
      // `archive_contains_symlink`).
      out.push(relative(root, fullPath).split(sep).join("/"));
    }
    return true;
  }
  const complete = await walk(root, "");
  if (!complete) return "too_many";
  return out;
}

function findPrivateMaterial(value: unknown, path = "$"): string[] {
  if (value === null || typeof value !== "object") return [];
  if (Array.isArray(value)) {
    return value.flatMap((item, index) =>
      findPrivateMaterial(item, `${path}[${index}]`)
    );
  }

  const findings: string[] = [];
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const normalized = key.toLowerCase().replace(/[-\s]/g, "_");
    if (PRIVATE_MATERIAL_KEYS.has(normalized)) {
      findings.push(`${path}.${key}`);
      continue;
    }
    findings.push(...findPrivateMaterial(child, `${path}.${key}`));
  }
  return findings;
}

/**
 * TYPED PARSE RESULT (Codex gate finding, 2026-08-22; rule 11,
 * AGENTS.md): the exact shape import's state-rekey path reads BEFORE (and
 * immediately after) decrypting an entry - namespace/key/kid/sig/metadata
 * (safe-dereference fields, EXIT-STRUCT-02) PLUS the crypto-payload fields
 * `decrypt()` (server/src/core/encryption.ts) and the post-decrypt
 * integrity check both read: `payload.v`, `payload.alg`, `payload.iv`,
 * `entry.integrity_hash`. A missing `payload.iv` used to reach
 * `fromBase64url(undefined)` (a raw TypeError, swallowed only by
 * `rekeyState`'s bare per-entry `catch`); a missing `integrity_hash` made
 * `hashToString(plaintext) !== undefined` unconditionally true, silently
 * treating a structurally-damaged entry as a signature failure. Both
 * outcomes skip the entry, which then fails the whole import CLOSED after
 * staging (the same "verify PASS, import refuses post-staging" shape
 * F3/F4 close for `total_keys`/reserved-namespace). Deliberately NOT the
 * full `StateEntry` shape (server/src/cognitive/state-store.ts): a
 * value that passes this check can still fail AEAD decryption/signature
 * verification for a VALUE reason (wrong key, tampered ciphertext,
 * unsupported version/alg) - that stays import's own, separately-named,
 * credential-shaped refusal, never a crash and never silently absorbed
 * into "invalid signature".
 */
export interface WellFormedExitStateEntryElement {
  namespace: string;
  key: string;
  entry: {
    kid: string;
    sig: string;
    integrity_hash: string;
    payload: { v: number; alg: string; iv: string; ct: string };
    metadata: { tags?: string[] };
  };
}

/**
 * CONTRACT PIN (the exit-import module): the encrypted-state entries
 * guards on the import side both call this same function (via
 * `checkEncryptedStateStructure` for the pre-staging gate, and directly
 * for the defense-in-depth callers) on every element, so "malformed" here
 * means exactly what import checks for - a hand-mirrored second check
 * was the shape AGENTS.md rule 5 rules out. A type predicate
 * (`item is WellFormedExitStateEntryElement`), not a bare boolean, so
 * every caller gets real type narrowing from the same check it ran,
 * rather than a separately-hand-written cast that could drift from what
 * this function actually verified.
 */
export function isWellFormedExitStateEntryElement(
  item: unknown
): item is WellFormedExitStateEntryElement {
  if (item === null || typeof item !== "object") return false;
  const record = item as Record<string, unknown>;
  if (typeof record.namespace !== "string") return false;
  if (typeof record.key !== "string") return false;
  const entry = record.entry;
  if (entry === null || typeof entry !== "object") return false;
  const entryRecord = entry as Record<string, unknown>;
  if (typeof entryRecord.kid !== "string") return false;
  if (typeof entryRecord.sig !== "string") return false;
  if (typeof entryRecord.integrity_hash !== "string") return false;
  const payload = entryRecord.payload;
  if (payload === null || typeof payload !== "object") return false;
  const payloadRecord = payload as Record<string, unknown>;
  if (typeof payloadRecord.ct !== "string") return false;
  // G-B (coordinator gate, 2026-08-22): pinned to the EXACT values
  // `decrypt()` (core/encryption.ts) accepts, not merely their type - a
  // well-typed WRONG value (`v: 2`, `alg: "aes-128-gcm"`) used to pass
  // this check, verify PASS, and only fail post-staging inside rekeyState's
  // bare per-entry catch, misread as a signature failure rather than a
  // structural one. `SUPPORTED_PAYLOAD_VERSION`/`SUPPORTED_PAYLOAD_ALG` are
  // the SAME constants `decrypt()` checks against - CONTRACT PIN, must
  // match if either changes.
  if (payloadRecord.v !== SUPPORTED_PAYLOAD_VERSION) return false;
  if (payloadRecord.alg !== SUPPORTED_PAYLOAD_ALG) return false;
  // `payload.iv` is read by `fromBase64url` with no type guard of its own
  // (a non-string is the raw-TypeError crash risk EXIT-STRUCT-02 covers).
  // N3 (coordinator gate, 2026-08-22): `PAYLOAD_IV_BYTE_LENGTH` is the
  // exact length `encrypt()` (core/encryption.ts) always emits, not a
  // length decrypt()'s cipher itself requires - @noble/ciphers' `gcm()`
  // accepts other nonce sizes (varSizeNonce). This structural check
  // deliberately pins to the ONE length a legitimate export ever produces,
  // so a decodable-but-off-length IV is refused here as malformed rather
  // than accepted by the cipher under a nonce size this fortress never
  // actually uses. `fromBase64urlStrict` rejects any non-canonical
  // encoding first, so a lenient-decoder quirk cannot hide a length
  // mismatch from the check that follows it.
  if (typeof payloadRecord.iv !== "string") return false;
  try {
    if (fromBase64urlStrict(payloadRecord.iv).length !== PAYLOAD_IV_BYTE_LENGTH) {
      return false;
    }
  } catch {
    return false;
  }
  // EXIT-STRUCT-02 fix-round (Codex family, confirmed by probe: predicate:true
  // then TypeError): `rekeyState` (server/src/exit/bundle.ts write site) reads
  // `entry.metadata.content_type`/`.ttl_seconds` and SPREADS `entry.metadata.tags`
  // AFTER decrypt + integrity-hash pass — but `metadata` is covered by NEITHER
  // the entry signature (over `payload.ct`) NOR the integrity_hash (over the
  // decrypted plaintext), so a source-signed, decryptable bundle with `metadata`
  // stripped reaches that write and throws. `metadata` is therefore mandatory
  // for a well-formed element; a legitimate export always populates it.
  const metadata = entryRecord.metadata;
  if (metadata === null || typeof metadata !== "object") return false;
  // `tags` is optional, but when present it is spread (`...tags`); a non-array
  // value (`...5`) throws "is not iterable". Require array-when-present; absent
  // is fine (the write site defaults it with `?? []`). content_type/ttl_seconds
  // are read but never dereferenced further, so absent subfields cannot throw.
  const tags = (metadata as Record<string, unknown>).tags;
  if (tags !== undefined && !Array.isArray(tags)) return false;
  return true;
}

/**
 * The four ways an `encrypted_state` artifact's `entries`/`total_keys`
 * declaration can fail to describe itself honestly, in the order
 * {@link checkEncryptedStateStructure} checks them.
 */
export type EncryptedStateStructureProblem =
  | "entries_unreadable"
  | "entries_malformed_elements"
  | "total_keys_mismatch"
  | "reserved_namespace_entry";

export interface EncryptedStateStructureCheck {
  ok: boolean;
  problem?: EncryptedStateStructureProblem;
  detail?: string;
}

/**
 * CONTRACT PIN (AGENTS.md rule 11): the ONE structural-soundness check for
 * an encrypted_state artifact's `entries` container and `total_keys`
 * declaration, consumed by BOTH `summarizeEncryptedState` (verify, right
 * below) AND `importExitBundle`'s pre-staging gate
 * (server/src/exit/bundle.ts - search "checkEncryptedStateStructure" there)
 * so neither stage can accept an artifact the other refuses. Must match
 * that call site if this function's signature or problem set changes.
 *
 * Four checks make up the problem set: an unreadable `entries` container
 * (LD2-01), a malformed element (EXIT-STRUCT-02), a source-signed artifact
 * whose `total_keys` disagrees with its own readable `entries` length
 * (F3), and a reserved-namespace entry (F4). All four are gated HERE,
 * before any write, so `exit verify` and `exit import` always agree on
 * whether a bundle is sound. Fail closed: an artifact this function
 * cannot fully vouch for is `ok: false`, never a default `ok: true`.
 */
export function checkEncryptedStateStructure(record: {
  entries?: unknown;
  total_keys?: unknown;
}): EncryptedStateStructureCheck {
  if (!Array.isArray(record.entries)) {
    return {
      ok: false,
      problem: "entries_unreadable",
      detail: "the `entries` field is absent or is not an array",
    };
  }
  const entries = record.entries;
  for (const item of entries) {
    if (!isWellFormedExitStateEntryElement(item)) {
      return {
        ok: false,
        problem: "entries_malformed_elements",
        detail:
          "an entries element is missing or has a wrong-typed " +
          "namespace/key/entry field",
      };
    }
  }
  // F3: `total_keys` must be PRESENT as a number and agree with the
  // readable entries length. A bundle's own export always sets
  // `total_keys: entries.length` (bundle.ts exportEncryptedState); a
  // hand-crafted or truncated-then-resigned artifact is the only way this
  // can disagree.
  if (
    typeof record.total_keys !== "number" ||
    record.total_keys !== entries.length
  ) {
    return {
      ok: false,
      problem: "total_keys_mismatch",
      detail:
        `declared total_keys (${JSON.stringify(record.total_keys)}) does ` +
        `not match the readable entries count (${entries.length})`,
    };
  }
  // F4: the SAME predicate import's rekeyState (bundle.ts) uses to skip a
  // reserved-namespace entry, checked here BEFORE any write so verify and
  // import agree before staging, not after.
  const reserved = entries.find(
    (item) =>
      isWellFormedExitStateEntryElement(item) &&
      isReservedNamespace((item as { namespace: string }).namespace)
  );
  if (reserved) {
    return {
      ok: false,
      problem: "reserved_namespace_entry",
      detail:
        `entry namespace '${(reserved as { namespace: string }).namespace}' ` +
        "is a reserved namespace",
    };
  }
  return { ok: true };
}

/**
 * Summarize a parsed `artifacts/encrypted_state.json`. Pure, total, and
 * defensive: every field is narrowed from `unknown`, so a hand-crafted or
 * truncated artifact yields a conservative summary rather than throwing.
 *
 * @param artifact - the parsed encrypted_state JSON (already hash-verified
 *   against the signed manifest by the caller).
 */
export function summarizeEncryptedState(
  artifact: unknown
): ExitEncryptedStateSummary {
  const record =
    artifact !== null && typeof artifact === "object" && !Array.isArray(artifact)
      ? (artifact as Record<string, unknown>)
      : {};
  // INVARIANT: an unreadable `entries` field becomes `null`, never `[]`. The
  // substitution that reads naturally here - default to an empty array and
  // report its length - is precisely the absent-as-benign conflation: it turns
  // a corrupt artifact into a confident "0 entries" for the operator while the
  // import path, which reads `entries.length` off the same JSON, does something
  // else entirely.
  const entries: unknown[] | null = Array.isArray(record.entries)
    ? record.entries
    : null;
  // INVARIANT (EXIT-STRUCT-02, one level deeper than the LD2-01 check above;
  // extended by F3/F4, Exit V2 drill D1): `entries` being a non-null array
  // only proves the CONTAINER is readable. A `null` element, a
  // missing/wrong-typed `namespace`/`entry`/`entry.kid`/`entry.payload.ct`/
  // `entry.sig`, a stale self-declared `total_keys`, or a reserved-namespace
  // entry all pass a bare container check and either crash import
  // (`compromisedRetiredSignatureUse` in bundle.ts) or get silently applied
  // partially. Routed through `checkEncryptedStateStructure`, the SAME
  // function import's pre-staging gate uses, so "malformed" here means
  // exactly what makes import refuse. `entries === null` short-circuits this
  // to `false`: an unreadable container is the already-covered LD2-01 case,
  // not this one.
  const structureCheck = checkEncryptedStateStructure(record);
  const entriesMalformed = entries !== null && !structureCheck.ok;
  const structuralProblem: EncryptedStateStructureProblem | undefined =
    entries !== null && !structureCheck.ok ? structureCheck.problem : undefined;
  const namespaces = Array.isArray(record.namespaces)
    ? record.namespaces.filter((n): n is string => typeof n === "string")
    : [];
  const emptyReason =
    typeof record.empty_reason === "string" ? record.empty_reason : undefined;

  // CONTRACT PIN (server/src/core/key-derivation.ts parseKeyDerivationParams):
  // the same validator the export embed-gate and the import derive-gate use, so
  // "malformed" here means exactly what makes an import refuse.
  const legacyKdfParams: ExitEncryptedStateSummary["legacy_kdf_params"] =
    record.source_key_derivation === undefined
      ? "absent"
      : parseKeyDerivationParams(record.source_key_derivation).ok
        ? "valid"
        : "malformed";

  // CONTRACT PIN (server/src/exit/source-custody.ts `readSourceCustodyState`):
  // the same predicate import's `validateSourceCustody` refuses on, so
  // "malformed" here means exactly what makes an import throw
  // SOURCE_CUSTODY_MALFORMED. An object-shape check was NOT enough: it reported
  // a live re-key path for a block no import would accept.
  const sourceCustody = readSourceCustodyState(record.source_custody);

  let declared: ExitBundleDeclaredRekeyMaterial;
  if (entries === null) {
    // An unreadable entry list is damage, and it is NOT the zero-entry case:
    // reporting "no state, no credential needed" for an artifact whose entries
    // cannot be read is the absent-as-benign conflation, and the import reads
    // `entries.length` off the same JSON and does not agree.
    declared = "damaged";
  } else if (entries.length === 0) {
    declared = "no-state";
  } else if (sourceCustody === "malformed" || legacyKdfParams === "malformed") {
    declared = "damaged";
  } else if (sourceCustody === "valid") {
    declared = "bundle-rekey-key";
  } else if (legacyKdfParams === "valid") {
    declared = "legacy-passphrase";
  } else {
    declared = "none-declared";
  }

  return {
    entry_count: entries === null ? null : entries.length,
    namespace_count: namespaces.length,
    namespaces,
    ownership_partitioned: record.ownership_partitioned === true,
    ...(emptyReason !== undefined ? { empty_reason: emptyReason } : {}),
    empty_reason_missing: entries?.length === 0 && emptyReason === undefined,
    entries_malformed: entriesMalformed,
    ...(structuralProblem !== undefined
      ? { structural_problem: structuralProblem }
      : {}),
    legacy_kdf_params: legacyKdfParams,
    source_custody: sourceCustody,
    declared_rekey_material: declared,
  };
}

/**
 * Structural read-health of the encrypted_state artifact, deliberately
 * INDEPENDENT of {@link ExitBundleDeclaredRekeyMaterial} — see the
 * CRITICAL SCOPING note on the class-level fix this type belongs to.
 * `declared_rekey_material === "damaged"` also fires for a malformed
 * `source_custody`/`legacy_kdf_params` block on a bundle whose entries ARE
 * readable (`summarizeEncryptedState` above), and that bundle MUST stay
 * verify-PASS: import rejects it for a typed, actionable credential reason
 * (`SOURCE_CUSTODY_MALFORMED` / `SOURCE_KDF_PARAMS_MALFORMED`), never a
 * crash, and `test/exit/exit-credential-path.test.ts` pins that PASS
 * deliberately. `entry_count === null` is the one signal both verify and
 * import agree names an artifact whose own contents cannot be read AT ALL
 * (LD2-01), so this type is keyed on that field first.
 *
 * `entries_malformed_elements` (EXIT-STRUCT-02) is the one-level-deeper
 * sibling: the container IS readable (`entry_count !== null`) but at least
 * one ELEMENT in it is not - `entries: [null]`, or an element missing
 * `namespace`/`entry`/`entry.kid`/`entry.payload.ct`/`entry.sig`. This is
 * NOT the credential-exempt case above: a malformed element is damage to
 * the artifact itself, exactly like an unreadable container, and import
 * throws a raw TypeError on it at the same dereference LD2-01 fixed for the
 * container case, one property access deeper.
 */
export type EncryptedStateStructuralHealth =
  | "readable"
  | "entries_unreadable"
  | "entries_malformed_elements";

function classifyEncryptedStateStructuralHealth(
  state: ExitEncryptedStateSummary | undefined
): EncryptedStateStructuralHealth | undefined {
  if (state === undefined) return undefined;
  if (state.entry_count === null) return "entries_unreadable";
  if (state.entries_malformed) return "entries_malformed_elements";
  return "readable";
}

/**
 * CLASS INVARIANT (verify/import parity aggregator, LD2-01): fail CLOSED on
 * any structural health value this function does not explicitly recognize
 * as safe to pass. This is the mechanism, not a comment: three prior
 * instances of "verify reports PASS while import fails closed" (rotation
 * chain #1189, reputation-bundle signature #1194, and the damaged-entries
 * case this function closes) were each patched one at a time by adding one
 * more named boolean to a hand-written `&&` chain — a shape where a FOURTH
 * instance is silently absent-by-omission unless someone remembers to
 * extend the chain. A health value this switch does not recognize returns
 * `failed: true`, never `false`: the default arm below is the fail-closed
 * floor, held mechanically by a unit test that drives an out-of-union value
 * through this function directly (server/test/exit/exit-verifier-aggregator
 * .test.ts).
 *
 * Exported for that unit test only; it is an internal aggregator helper, not
 * an MCP-facing or CLI-facing surface.
 */
export function encryptedStateSubVerdictFailed(
  health: EncryptedStateStructuralHealth | undefined
): boolean {
  switch (health) {
    case undefined:
    case "readable":
      return false;
    case "entries_unreadable":
    case "entries_malformed_elements":
      return true;
    default: {
      // Fail closed. Exhaustiveness over the DECLARED union is enforced at
      // compile time by the `never` assignment below, but this arm is also
      // LIVE at runtime for any value this switch was not updated to
      // recognize — exactly the shape a future structural-health value
      // would take if `classifyEncryptedStateStructuralHealth` grew a new
      // case without a matching one here. Reverting this branch to
      // `return false` is the fail-open mutation this function exists to
      // rule out.
      const unreachable: never = health;
      void unreachable;
      return true;
    }
  }
}

export async function readManifest(bundleDir: string): Promise<ExitBundleManifest> {
  const bytes = await readFileCustody(join(bundleDir, "manifest.json"), {
    verifyPathIdentity: true,
  });
  return JSON.parse(Buffer.from(bytes).toString("utf8")) as ExitBundleManifest;
}

export async function loadExitArtifact<T = unknown>(
  bundleDir: string,
  manifest: ExitBundleManifest,
  kind: ExitBundleArtifactKind
): Promise<LoadedExitArtifact<T> | null> {
  const entry = manifest.body.artifacts.find((artifact) => artifact.kind === kind);
  if (!entry) return null;
  const artifactPath = join(bundleDir, entry.path);
  const bytes = await readFileCustody(artifactPath, {
    verifyPathIdentity: true,
  });
  return {
    entry,
    path: artifactPath,
    bytes: new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength),
    json: JSON.parse(Buffer.from(bytes).toString("utf8")) as T,
  };
}

function verifyIdentityArtifact(
  identityArtifact: unknown
): IdentityArtifactVerification {
  const wrapper = identityArtifact as {
    bundle?: Record<string, unknown>;
    signature?: string;
  };
  const bundle = wrapper.bundle;
  if (!bundle || typeof wrapper.signature !== "string") {
    return { signature_valid: false };
  }
  const publicKey = bundle.publicKey;
  if (typeof publicKey !== "string") {
    return { signature_valid: false };
  }
  const signatureValid = ed25519.verify(
    fromBase64url(wrapper.signature),
    canonicalizeToBytes(bundle),
    fromBase64url(publicKey)
  );
  return {
    signature_valid: signatureValid,
    identity_id:
      typeof bundle.identity_id === "string" ? bundle.identity_id : undefined,
    did: typeof bundle.did === "string" ? bundle.did : undefined,
    public_key: publicKey,
    rotation_history: bundle.rotation_history,
  };
}

function identityResult(
  verification: IdentityArtifactVerification
): NonNullable<ExitBundleDetailedVerifierResult["identity"]> {
  return {
    signature_valid: verification.signature_valid,
    identity_id: verification.identity_id,
    did: verification.did,
  };
}

function compareManifestIdentityBinding(
  manifest: ExitBundleManifest,
  identityVerification: IdentityArtifactVerification
): IdentityBindingVerificationResult {
  const warnings: string[] = [];
  const binding = manifest.body.identity_binding;
  if (!identityVerification.signature_valid) {
    return {
      identityVerification,
      failure_class: "identity_signature_invalid",
      warnings: ["public identity artifact signature is invalid"],
    };
  }
  // INVARIANT: a manifest origin is accepted only when it names the same
  // identity and public key as the self-signed public_identity artifact.
  if (binding.identity_id !== identityVerification.identity_id) {
    return {
      identityVerification,
      failure_class: "identity_binding_mismatch",
      warnings: [
        "identity_binding_mismatch: manifest identity_id does not match public_identity.bundle.identity_id",
      ],
    };
  }
  if (binding.fortress_master_pubkey !== identityVerification.public_key) {
    return {
      identityVerification,
      failure_class: "identity_binding_mismatch",
      warnings: [
        "identity_binding_mismatch: manifest fortress_master_pubkey does not match public_identity.bundle.publicKey",
      ],
    };
  }
  if (binding.did === undefined) {
    warnings.push(
      "legacy_identity_binding_did_absent: manifest identity_binding.did is absent; accepted because identity_id and fortress_master_pubkey match the signed public_identity artifact"
    );
  } else if (binding.did !== identityVerification.did) {
    return {
      identityVerification,
      failure_class: "identity_binding_mismatch",
      warnings: [
        "identity_binding_mismatch: manifest did does not match public_identity.bundle.did",
      ],
    };
  }
  return { identityVerification, warnings };
}

async function verifyIdentityBindingBeforeManifestKeyUse(
  root: string,
  manifest: ExitBundleManifest
): Promise<IdentityBindingVerificationResult> {
  const entry = manifest.body.artifacts.find(
    (artifact) => artifact.kind === "public_identity"
  );
  if (!entry) {
    return {
      failure_class: "identity_binding_mismatch",
      warnings: [
        "identity_binding_mismatch: manifest identity_binding has no public_identity artifact to support it",
      ],
    };
  }

  const artifactPath = join(root, entry.path);
  let bytes: Uint8Array;
  let fileSize: number;
  try {
    const linkStat = await lstat(artifactPath);
    if (linkStat.isSymbolicLink()) {
      return { failure_class: "archive_contains_symlink", warnings: [] };
    }
    const descends = await assertDescendant(root, artifactPath);
    if (!descends) {
      return { failure_class: "artifact_path_escapes_root", warnings: [] };
    }
    const { data: raw, stats } = await readFileCustodyWithStats(
      artifactPath,
      { verifyPathIdentity: true },
    );
    bytes = new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
    fileSize = stats.size;
  } catch {
    return { failure_class: "artifact_missing", warnings: [] };
  }

  const hashPassed = sha256Hex(bytes) === entry.hash;
  if (!hashPassed) {
    return { failure_class: "artifact_hash_mismatch", warnings: [] };
  }
  if (fileSize !== entry.size_bytes) {
    return { failure_class: "artifact_size_mismatch", warnings: [] };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    return {
      failure_class: "identity_signature_invalid",
      warnings: ["public identity artifact is not parseable JSON"],
    };
  }

  return compareManifestIdentityBinding(
    manifest,
    verifyIdentityArtifact(parsed)
  );
}

/**
 * Exit V2 drill F2 (2026-08-22/23, Erik-ratified option a): the
 * `known_signers` artifact carries a signed DID -> public key table for
 * every attestation signer the EXPORTING fortress itself verified at an
 * earlier import (see server/src/reputation/known-signers-store.ts), so a
 * re-exported (second-hop) reputation bundle stays verifiable without
 * re-deriving trust the receiving fortress has no way to establish on its
 * own. VERSION-GATED: the field is `1` today; a future version this parser
 * does not recognize is treated as unreadable (fail closed), never
 * silently accepted under different semantics.
 */
export interface KnownSignersEntry {
  did: string;
  /** base64url raw Ed25519 public key. */
  public_key: string;
  /**
   * MEDIUM-3 (independent gate on #1303, 2026-08-23): the LOCAL `_exit_imports`
   * id of the import at which the ORIGINAL exporting fortress first verified
   * this signer - informational and diagnostic ONLY, never a trust input.
   * With HIGH-1 fixed (did:key self-certification), the property this table
   * actually needs to prove - "this key derives this DID" - is carried
   * entirely by the structural check plus the table's own signature; this
   * field carries none of that weight. It is the EXPORTER's self-report,
   * unverifiable by a receiving fortress (which cannot confirm when, or
   * whether, the claimed import genuinely happened), and after N re-export
   * hops it is hearsay relayed and re-signed N times, never independently
   * re-derived. No consumer in this codebase reads its VALUE for any
   * security decision - required non-empty purely so a malformed or
   * truncated entry is still caught by the element-level structural check.
   */
  first_seen_import_id: string;
}

export interface KnownSignersArtifact {
  version: 1;
  signers: KnownSignersEntry[];
  /** base64url Ed25519 signature by the EXPORTING fortress's identity over {@link knownSignersSigningBytes}. */
  signature: string;
}

/**
 * CONTRACT PIN (AGENTS.md rule 11): element-level typed parse for one
 * `known_signers` table entry, mirroring
 * {@link isWellFormedExitStateEntryElement}'s shape - a container-only
 * check ("`signers` is an array") cannot see a malformed ELEMENT
 * (missing/wrong-typed `did`, an undecodable or wrong-length `public_key`),
 * and admitting one here would either crash a later `ed25519.verify` call
 * or silently coerce a bad key into "no key", which is the exact
 * absent-vs-malformed conflation AGENTS.md rule 11 rules out.
 * `ED25519_PUBLIC_KEY_BYTES` is the SAME constant `assertEd25519PublicKey`
 * (core/identity.ts) checks against - CONTRACT PIN, must match if either
 * changes.
 */
export function isWellFormedKnownSignersEntry(
  item: unknown
): item is KnownSignersEntry {
  if (item === null || typeof item !== "object") return false;
  const record = item as Record<string, unknown>;
  if (typeof record.did !== "string" || record.did.length === 0) return false;
  if (typeof record.first_seen_import_id !== "string" || record.first_seen_import_id.length === 0) {
    return false;
  }
  if (typeof record.public_key !== "string") return false;
  try {
    if (fromBase64urlStrict(record.public_key).length !== ED25519_PUBLIC_KEY_BYTES) {
      return false;
    }
  } catch {
    return false;
  }
  return true;
}

export type KnownSignersStructureProblem =
  | "signers_unreadable"
  | "signers_malformed_elements"
  | "signers_did_key_mismatch"
  | "signers_duplicate_did_conflict"
  | "signers_version_unsupported";

export interface KnownSignersStructureCheck {
  ok: boolean;
  problem?: KnownSignersStructureProblem;
  detail?: string;
}

/**
 * CONTRACT PIN (AGENTS.md rule 11): the ONE structural-soundness check for a
 * `known_signers` artifact's container, version, and per-element shape -
 * consumed by BOTH `resolveKnownSigners` (below, used by `verifyExitBundle`
 * here AND `importExitBundle`'s pre-staging gate in
 * server/src/exit/bundle.ts - search "resolveKnownSigners" there), so
 * `exit verify` and `exit import` can never disagree about whether a
 * known_signers table is sound. Pure and total: never throws, and does not
 * touch the table's SIGNATURE (that is a separate, caller-supplied-identity
 * check in `resolveKnownSigners`, mirroring how `checkEncryptedStateStructure`
 * stays structural-only and `verifyReputationArtifact` does its own
 * signature pass). Fail closed: `ok: false` is the default, never assumed
 * sound.
 */
export function checkKnownSignersStructure(record: {
  version?: unknown;
  signers?: unknown;
}): KnownSignersStructureCheck {
  if (record.version !== 1) {
    return {
      ok: false,
      problem: "signers_version_unsupported",
      detail: `known_signers.version is ${JSON.stringify(record.version)}, expected 1`,
    };
  }
  if (!Array.isArray(record.signers)) {
    return {
      ok: false,
      problem: "signers_unreadable",
      detail: "the `signers` field is absent or is not an array",
    };
  }
  const byDid = new Map<string, string>();
  for (const item of record.signers) {
    if (!isWellFormedKnownSignersEntry(item)) {
      return {
        ok: false,
        problem: "signers_malformed_elements",
        detail:
          "a signers element is missing or has a wrong-typed did/public_key/first_seen_import_id",
      };
    }
    // HIGH-1 (independent gate on #1303, 2026-08-23, key-substitution
    // REPRODUCED): `did:key` is SELF-CERTIFYING - the DID is a deterministic
    // encoding of the public key (publicKeyToDid, core/identity.ts) - so an
    // entry whose declared `did` does not derive from its declared
    // `public_key` is not a differently-encoded truth, it is a FORGED
    // mapping: the exporter can name ANY did on this table and pair it with
    // a key it controls, then sign attestations under that fabricated
    // pairing with `signer` set to the victim DID. Checked BEFORE the
    // duplicate-DID check below so a forged entry is refused on its own
    // demerits, not conflated with a legitimate re-assertion. `publicKeyToDid`
    // never throws here - `isWellFormedKnownSignersEntry` above already
    // proved `public_key` decodes to exactly `ED25519_PUBLIC_KEY_BYTES`,
    // the one precondition `publicKeyToDid`/`assertEd25519PublicKey` require.
    let derivedDid: string;
    try {
      derivedDid = publicKeyToDid(fromBase64urlStrict(item.public_key));
    } catch {
      return {
        ok: false,
        problem: "signers_did_key_mismatch",
        detail: `signers element for DID ${item.did} has an undecodable public_key`,
      };
    }
    if (derivedDid !== item.did) {
      return {
        ok: false,
        problem: "signers_did_key_mismatch",
        detail: `signers element claims DID ${item.did} but its public_key derives DID ${derivedDid}`,
      };
    }
    const existing = byDid.get(item.did);
    if (existing !== undefined && existing !== item.public_key) {
      return {
        ok: false,
        problem: "signers_duplicate_did_conflict",
        detail: `DID ${item.did} appears twice with two different public keys`,
      };
    }
    byDid.set(item.did, item.public_key);
  }
  return { ok: true };
}

/**
 * Canonical signing bytes for a `known_signers` table. The `signature`
 * field is deliberately excluded (it signs everything ELSE), mirroring
 * `reputationBundleSigningBytes`'s shape.
 *
 * MEDIUM-6 (independent gate on #1303, 2026-08-23): `EXIT_KNOWN_SIGNERS_DOMAIN`
 * (core/crypto-suite-registry.ts) is included as a field inside the
 * canonicalized structure - domain separation, so a signature over a
 * known_signers table can never be confused with a signature over some
 * OTHER structure that happens to canonicalize to the same
 * `{version, signers}` shape.
 */
export function knownSignersSigningBytes(table: {
  version: 1;
  signers: KnownSignersEntry[];
}): Uint8Array {
  return canonicalizeToBytes({
    domain: EXIT_KNOWN_SIGNERS_DOMAIN,
    version: table.version,
    signers: table.signers,
  });
}

export type KnownSignersResolution =
  | { ok: true; signers: Map<string, Uint8Array> }
  | {
      ok: false;
      problem:
        | KnownSignersStructureProblem
        | "signature_invalid"
        | "artifact_shape_invalid"
        | "signers_self_entry_present";
      detail?: string;
    };

/**
 * Resolve a parsed `known_signers` artifact into a DID -> public key map,
 * or report why it could not be trusted. Used identically by
 * `verifyExitBundle` (below) and `importExitBundle`
 * (server/src/exit/bundle.ts) - the ONE place either stage decides whether
 * a known_signers table's entries are admissible, so a table one stage
 * refuses can never be the one the other silently accepts (the same parity
 * `checkEncryptedStateStructure` holds for `encrypted_state`).
 *
 * Fails closed to an EMPTY resolution (never partial) on any structural
 * problem or a signature that does not verify under the EXPORTING
 * fortress's own identity key - `exportingPublicKey` is the SAME key
 * `verifyIdentityBindingBeforeManifestKeyUse` (verify) or
 * `publicKeysFromIdentityArtifact` (import) already bound to the bundle's
 * manifest identity before this function is ever called, so a table
 * "signed" by any other key is rejected as a forgery, not merely
 * unattributed.
 *
 * INVARIANT (drill F2 ruling, "the table can never introduce a signer for
 * the exporting fortress's own DID"; HARDENED to a whole-table REJECTION,
 * independent gate on #1303, 2026-08-23, item 6 - a prior revision merely
 * dropped the one offending entry, which is the wrong shape: it lets a
 * forger probe which entries get silently discarded): an entry whose `did`
 * equals `exportingDid`, OR whose `public_key` byte-equals
 * `exportingPublicKey` (checked independently of the DID string - HIGH-1,
 * same gate: a self-consistent did:key entry could otherwise carry the
 * exporter's OWN key under a DID string that does not textually match
 * `exportingDid`, e.g. a legacy encoding or a future non-did:key scheme),
 * REJECTS THE ENTIRE TABLE (`signers_self_entry_present`) even when the
 * table otherwise parses and verifies cleanly - the exporting identity's
 * own key is established by the bundle's public_identity artifact and
 * rotation chain, never by this auxiliary table, so this table can never be
 * used to shadow or override it, and a well-formed table never needs to
 * name its own exporter in the first place.
 *
 * WHAT THIS DOES NOT PROVE (HIGH-1 finding, stated so a future caller does
 * not over-read the return value): `checkKnownSignersStructure`'s did:key
 * check proves an entry's `(did, public_key)` pair is SELF-CONSISTENT -
 * that `did` is the deterministic encoding of `public_key` - never that the
 * EXPORTING fortress genuinely verified an attestation from that signer at
 * some earlier legitimate import. Self-consistency is necessary (it rules
 * out the key-substitution forgery this fix closes) but not sufficient: the
 * exporter could still mint a brand-new keypair, label its DID as a
 * "known signer," and sign fabricated attestations under it. This table is
 * therefore no stronger a trust primitive than a first-hop bundle's own
 * self-certified identity always was - a receiving fortress trusts it
 * exactly that much, no more (MEDIUM-3, same gate: each hop re-derives its
 * own trust from what its own signature chain proves, never from an
 * upstream fortress's unverifiable claim to have "checked" a signer).
 */
export function resolveKnownSigners(
  artifact: unknown,
  exportingDid: string,
  exportingPublicKey: Uint8Array
): KnownSignersResolution {
  if (artifact === null || typeof artifact !== "object" || Array.isArray(artifact)) {
    return { ok: false, problem: "artifact_shape_invalid", detail: "known_signers artifact is not a JSON object" };
  }
  const record = artifact as { version?: unknown; signers?: unknown; signature?: unknown };
  const structureCheck = checkKnownSignersStructure(record);
  if (!structureCheck.ok) {
    return { ok: false, problem: structureCheck.problem!, detail: structureCheck.detail };
  }
  if (typeof record.signature !== "string") {
    return { ok: false, problem: "artifact_shape_invalid", detail: "known_signers.signature is missing or not a string" };
  }
  const signers = record.signers as KnownSignersEntry[];
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = fromBase64urlStrict(record.signature);
  } catch {
    return { ok: false, problem: "signature_invalid", detail: "known_signers.signature is not valid base64url" };
  }
  const signatureValid = ed25519.verify(
    signatureBytes,
    knownSignersSigningBytes({ version: 1, signers }),
    exportingPublicKey
  );
  if (!signatureValid) {
    return { ok: false, problem: "signature_invalid", detail: "known_signers table signature does not verify under the bundle's exporting identity" };
  }
  const resolved = new Map<string, Uint8Array>();
  for (const entry of signers) {
    let entryKey: Uint8Array;
    try {
      entryKey = fromBase64urlStrict(entry.public_key);
    } catch {
      // Unreachable: isWellFormedKnownSignersEntry already decoded this
      // exact field successfully. Defensive only.
      return {
        ok: false,
        problem: "signers_malformed_elements",
        detail: `signers element for DID ${entry.did} has an undecodable public_key`,
      };
    }
    // Independent gate on #1303 (2026-08-23), item 6: an entry naming the
    // exporting fortress's own DID OR own key bytes (checked independently
    // of the DID string, so an equivalent legacy encoding of the SAME key
    // is caught the same way - core/identity.ts `legacyPublicKeyToDid`) is
    // a HARD REJECTION of the WHOLE table, never a silent per-entry skip. A
    // well-formed table never needs to name its own exporter - the
    // exporter's own key is established by the bundle's public_identity
    // artifact and rotation chain - so an entry that does is itself
    // evidence of malformed or adversarial construction, and admitting the
    // REST of an otherwise-plausible table while quietly dropping only this
    // one entry would let a forger probe which entries were rejected.
    if (entry.did === exportingDid || publicKeyBytesEqual(entryKey, exportingPublicKey)) {
      return {
        ok: false,
        problem: "signers_self_entry_present",
        detail: `signers element claims the exporting fortress's own identity (DID ${entry.did})`,
      };
    }
    resolved.set(entry.did, entryKey);
  }
  return { ok: true, signers: resolved };
}

function verifyReputationArtifact(
  reputationArtifact: unknown,
  publicKeysByDid: Map<string, Uint8Array>
): ExitBundleDetailedVerifierResult["reputation"] {
  const bundle = reputationArtifact as Partial<ReputationBundle>;
  const attestations = Array.isArray(bundle.attestations)
    ? bundle.attestations
    : [];

  let bundleSignatureValid: boolean | "unverifiable" = "unverifiable";
  if (
    bundle.version === "SANCTUARY_REP_V1" &&
    typeof bundle.exported_at === "string" &&
    typeof bundle.exporter_did === "string" &&
    typeof bundle.bundle_signature === "string"
  ) {
    const exporterKey = publicKeysByDid.get(bundle.exporter_did);
    if (exporterKey) {
      const signedBody = {
        version: "SANCTUARY_REP_V1" as const,
        attestations,
        exported_at: bundle.exported_at,
        exporter_did: bundle.exporter_did,
        completeness_manifest: bundle.completeness_manifest,
      };
      const signature = fromBase64url(bundle.bundle_signature);
      const currentSignatureValid = ed25519.verify(
        signature,
        reputationBundleSigningBytes(signedBody),
        exporterKey
      );
      const legacySignatureValid =
        bundle.completeness_manifest === undefined &&
        ed25519.verify(
          signature,
          stringToBytes(
            JSON.stringify({
              version: signedBody.version,
              attestations: signedBody.attestations,
              exported_at: signedBody.exported_at,
              exporter_did: signedBody.exporter_did,
            })
          ),
          exporterKey
        );
      bundleSignatureValid = currentSignatureValid || legacySignatureValid;
    }
  }

  let completeness:
    | ReputationBundleCompletenessVerification
    | "mismatch" = "mismatch";
  let completenessError: string | undefined;
  try {
    completeness = verifyReputationBundleCompleteness(bundle, {
      allowUnverifiedLegacy: true,
    });
  } catch (error) {
    completenessError =
      error instanceof Error
        ? error.message
        : "Reputation bundle completeness verification failed";
  }

  let verified = 0;
  let invalid = 0;
  let unverifiable = 0;
  let firstUnverifiableSignerPrefix: string | undefined;
  for (const attestation of attestations) {
    const signerKey = publicKeysByDid.get(attestation.signer);
    if (!signerKey) {
      unverifiable++;
      firstUnverifiableSignerPrefix ??= attestation.signer.slice(0, 24);
      continue;
    }
    const ok = ed25519.verify(
      fromBase64url(attestation.signature),
      stringToBytes(JSON.stringify(attestation.data)),
      signerKey
    );
    if (ok) verified++;
    else invalid++;
  }

  return {
    bundle_signature_valid: bundleSignatureValid,
    completeness,
    ...(completenessError !== undefined
      ? { completeness_error: completenessError }
      : {}),
    attestation_count: attestations.length,
    verified_attestations: verified,
    invalid_attestations: invalid,
    unverifiable_attestations: unverifiable,
    ...(firstUnverifiableSignerPrefix !== undefined
      ? { first_unverifiable_signer_prefix: firstUnverifiableSignerPrefix }
      : {}),
  };
}

/**
 * Caller-supplied verifier knobs. v1.0.2 / full-sweep #55.
 *
 * `acceptUnverifiableAttestations` flips the bundle verdict from strict-by-default
 * (any unverifiable attestation fails the bundle) to a relaxed verdict that
 * tolerates attestations whose signer DID is not in the bundle's published
 * identity material. Operators opt in explicitly through the CLI
 * `--accept-unverifiable-attestations` flag (Tier 1 confirmation).
 */
export interface VerifyExitBundleOptions {
  acceptUnverifiableAttestations?: boolean;
}

export async function verifyExitBundle(
  bundleDir: string,
  options: VerifyExitBundleOptions = {}
): Promise<ExitBundleDetailedVerifierResult> {
  const root = resolve(bundleDir);
  let manifest: ExitBundleManifest;
  let manifestBytes: Uint8Array;
  try {
    const raw = await readFileCustody(join(root, "manifest.json"), {
      verifyPathIdentity: true,
    });
    manifestBytes = new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
    manifest = JSON.parse(Buffer.from(raw).toString("utf8")) as ExitBundleManifest;
  } catch {
    throw new InvalidExitBundleError(
      `Not a valid SANCTUARY_EXIT_BUNDLE_V1 directory: manifest.json missing at ${join(root, "manifest.json")}`,
    );
  }

  const warnings: string[] = [];
  const unsupportedArtifacts: string[] = [];
  const body = manifest.body;
  // Independent gate on #1303 (2026-08-23), item 5: TWO manifest_version
  // literals are valid - the original frozen V1 and the known-signers
  // revision - never a widened single value. See
  // EXIT_BUNDLE_MANIFEST_VERSION_KNOWN_SIGNERS's doc comment (constants.ts)
  // for why a bundle that carries known_signers declares a DIFFERENT
  // literal rather than silently widening what "V1" means: a pre-this-
  // change verifier refuses it through this SAME, already-existing
  // manifest_unknown_version path instead of hitting an "unknown artifact
  // kind" it has no way to interpret.
  if (
    !body ||
    (body.manifest_version !== EXIT_BUNDLE_MANIFEST_VERSION &&
      body.manifest_version !== EXIT_BUNDLE_MANIFEST_VERSION_KNOWN_SIGNERS)
  ) {
    return fail(root, manifest, "manifest_unknown_version", warnings, unsupportedArtifacts);
  }
  if (body.signature_scheme !== SIGNATURE_SCHEME_V1) {
    return fail(
      root,
      manifest,
      "manifest_signature_scheme_invalid",
      warnings,
      unsupportedArtifacts
    );
  }

  const seenPaths = new Set<string>();
  const seenKinds = new Set<string>();
  for (const artifact of body.artifacts) {
    if (!isKnownKind(artifact.kind)) {
      return fail(root, manifest, "other", [`unknown artifact kind: ${describeUntrusted(artifact.kind)}`]);
    }
    if (seenPaths.has(artifact.path)) {
      return fail(root, manifest, "artifact_path_duplicate", warnings, unsupportedArtifacts);
    }
    seenPaths.add(artifact.path);
    // Independent gate, item 5: a kind repeated at a DIFFERENT path is not
    // caught by the path-duplicate check above, and every artifact kind in
    // this format is singular by design (loadExitArtifact resolves the
    // FIRST manifest entry matching a kind) - a second, differently-pathed
    // entry under the same kind is either a malformed export or an attempt
    // to smuggle a shadow artifact past whichever consumer looks it up by
    // kind.
    if (seenKinds.has(artifact.kind)) {
      return fail(root, manifest, "artifact_kind_duplicate", warnings, unsupportedArtifacts);
    }
    seenKinds.add(artifact.kind);
    if (validateArtifactPath(artifact.path) !== "ok") {
      return fail(root, manifest, "artifact_path_unsafe", warnings, unsupportedArtifacts);
    }
  }

  // Independent gate, item 5: the artifact SET must be EXACTLY the
  // contract for this manifest_version - not "a subset of recognized
  // kinds". A V1 bundle missing a required artifact, or (impossible today
  // given the isKnownKind gate above, but checked anyway as the
  // authoritative per-version boundary) carrying one outside V1's 7-kind
  // contract, is refused here.
  const expectedKindSet: readonly string[] =
    body.manifest_version === EXIT_BUNDLE_MANIFEST_VERSION_KNOWN_SIGNERS
      ? EXIT_BUNDLE_ARTIFACT_KINDS_V1_KNOWN_SIGNERS
      : EXIT_BUNDLE_ARTIFACT_KINDS;
  if (
    seenKinds.size !== expectedKindSet.length ||
    !expectedKindSet.every((kind) => seenKinds.has(kind))
  ) {
    return fail(root, manifest, "artifact_set_invalid", warnings, unsupportedArtifacts);
  }

  // Independent gate, item 5: verification must WALK the artifact
  // directory, not only trust the manifest's own declared list - a file
  // present on disk but never listed in the signed manifest is outside the
  // signature's coverage entirely (the manifest signs `artifacts[]` and the
  // aggregate hash over it, never "what happens to be on disk"), so its
  // presence is unaccountable, whatever it contains. `manifest.json` at the
  // bundle root is the one expected non-artifact file.
  const bundleFiles = await listBundleFiles(root, MAX_BUNDLE_DIRECTORY_ENTRIES);
  if (bundleFiles === "too_many") {
    return fail(root, manifest, "artifact_directory_unlisted_file", warnings, unsupportedArtifacts);
  }
  const unlisted = bundleFiles.filter(
    (relPath) => relPath !== "manifest.json" && !seenPaths.has(relPath)
  );
  if (unlisted.length > 0) {
    return fail(root, manifest, "artifact_directory_unlisted_file", warnings, unsupportedArtifacts);
  }

  const identityBindingVerification =
    await verifyIdentityBindingBeforeManifestKeyUse(root, manifest);
  warnings.push(...identityBindingVerification.warnings);
  if (identityBindingVerification.failure_class) {
    return {
      ...fail(
        root,
        manifest,
        identityBindingVerification.failure_class,
        warnings,
        unsupportedArtifacts
      ),
      ...(identityBindingVerification.identityVerification !== undefined
        ? {
            identity: identityResult(
              identityBindingVerification.identityVerification
            ),
          }
        : {}),
    };
  }

  const signatureOk = ed25519.verify(
    fromBase64url(manifest.signature),
    canonicalizeToBytes(body),
    fromBase64url(body.identity_binding.fortress_master_pubkey)
  );
  if (!signatureOk) {
    return fail(root, manifest, "manifest_signature_invalid", warnings, unsupportedArtifacts);
  }

  const expectedAggregate = sha256Hex(
    stringToBytes(canonicalize(body.artifacts))
  );
  if (expectedAggregate !== body.artifacts_aggregate_hash) {
    return fail(root, manifest, "aggregate_hash_mismatch", warnings, unsupportedArtifacts);
  }

  const artifactResults: ExitBundleVerifierResult["artifact_results"] = [];
  let artifactFailure:
    | NonNullable<ExitBundleVerifierResult["failure_class"]>
    | null = null;
  // Captured from the artifact-hash pass below rather than re-read afterwards:
  // the loop already parses every artifact for the private-material scan, and a
  // second read could observe a DIFFERENT file than the one just hash-verified.
  let encryptedStateJson: unknown;
  let sawEncryptedState = false;

  for (const artifact of body.artifacts) {
    const artifactPath = join(root, artifact.path);
    let bytes: Uint8Array;
    let fileSize: number;
    try {
      const linkStat = await lstat(artifactPath);
      if (linkStat.isSymbolicLink()) {
        artifactFailure = "archive_contains_symlink";
        artifactResults.push({
          path: artifact.path,
          kind: artifact.kind,
          hash_passed: false,
          size_passed: false,
        });
        continue;
      }
      const descends = await assertDescendant(root, artifactPath);
      if (!descends) {
        artifactFailure = "artifact_path_escapes_root";
        artifactResults.push({
          path: artifact.path,
          kind: artifact.kind,
          hash_passed: false,
          size_passed: false,
        });
        continue;
      }
      const { data: raw, stats: fileStat } = await readFileCustodyWithStats(
        artifactPath,
        { verifyPathIdentity: true },
      );
      fileSize = fileStat.size;
      bytes = new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
    } catch {
      artifactFailure = "artifact_missing";
      artifactResults.push({
        path: artifact.path,
        kind: artifact.kind,
        hash_passed: false,
        size_passed: false,
      });
      continue;
    }

    const hashPassed = sha256Hex(bytes) === artifact.hash;
    const sizePassed = fileSize === artifact.size_bytes;
    if (!hashPassed && !artifactFailure) artifactFailure = "artifact_hash_mismatch";
    if (!sizePassed && !artifactFailure) artifactFailure = "artifact_size_mismatch";
    artifactResults.push({
      path: artifact.path,
      kind: artifact.kind,
      hash_passed: hashPassed,
      size_passed: sizePassed,
    });

    try {
      const parsed = JSON.parse(Buffer.from(bytes).toString("utf8"));
      if (artifact.kind === "encrypted_state") {
        encryptedStateJson = parsed;
        sawEncryptedState = true;
      }
      const privateFindings = findPrivateMaterial(parsed);
      if (privateFindings.length > 0) {
        artifactFailure = "private_material_present";
        warnings.push(
          `${artifact.path} contains private-material field(s): ${privateFindings.join(", ")}`
        );
      }
    } catch {
      warnings.push(`${artifact.path} is not parseable JSON`);
    }
  }

  if (artifactFailure) {
    return {
      ...fail(root, manifest, artifactFailure, warnings, unsupportedArtifacts),
      manifest_hash: sha256Hex(manifestBytes),
      artifact_results: artifactResults,
    };
  }

  const stateSummary = sawEncryptedState
    ? summarizeEncryptedState(encryptedStateJson)
    : undefined;
  if (stateSummary !== undefined && stateSummary.entry_count === null) {
    warnings.push(
      "encrypted state carries no readable entries list (the `entries` field " +
        "is absent or is not an array): this artifact is signed and " +
        "hash-verified but structurally damaged, and it is NOT an empty " +
        "bundle - re-export from the source fortress"
    );
  }
  if (stateSummary?.entries_malformed === true) {
    // G-6 (coordinator gate, 2026-08-22): name the ACTUAL problem
    // (structural_problem, populated from the same checkEncryptedStateStructure
    // call that set entries_malformed) rather than a single generic message
    // that could not distinguish a stale total_keys header, a
    // reserved-namespace entry, or a genuinely malformed element.
    const problemText: Record<EncryptedStateStructureProblem, string> = {
      entries_unreadable:
        "the entries list itself cannot be read (this is the entries === null " +
        "case and should not reach this branch; reported defensively)",
      entries_malformed_elements:
        "contains a malformed entry (missing or wrong-typed namespace/key/" +
        "entry/payload fields)",
      total_keys_mismatch:
        "declares a total_keys count that does not match its readable entries",
      reserved_namespace_entry:
        "carries an entry under a reserved namespace, which is never a " +
        "legitimate export",
    };
    const problem = stateSummary.structural_problem ?? "entries_malformed_elements";
    warnings.push(
      `encrypted state entries list ${problemText[problem]}: this artifact ` +
        "is signed and hash-verified but structurally damaged, and import " +
        "would refuse it before (total_keys/reserved-namespace) or after " +
        "(a malformed element) staging - re-export from the source fortress"
    );
  }
  if (stateSummary?.empty_reason_missing === true) {
    warnings.push(
      "encrypted state carries zero entries and no empty_reason marker: " +
        "exported by a pre-marker (or buggy) exporter; cannot distinguish an " +
        "empty fortress from a broken export - verify the source fortress " +
        "before treating this as a complete exit"
    );
  }
  if (stateSummary?.legacy_kdf_params === "malformed") {
    warnings.push(
      "encrypted state carries malformed legacy re-key parameters " +
        "(source_key_derivation): the bundle is signed and intact, but its " +
        "passphrase re-key path cannot run. Re-export from the source fortress"
    );
  }
  // Previously silent: legacy_kdf_params malformed warned (above) but the
  // sibling source_custody malformed case (verifier.ts summarizeEncryptedState,
  // sourceCustody === "malformed") pushed no warning at all, even though it is
  // the SAME "signed, intact, but this re-key path is dead" fact about the
  // artifact and import refuses it with SOURCE_CUSTODY_MALFORMED.
  if (stateSummary?.source_custody === "malformed") {
    warnings.push(
      "encrypted state carries a malformed source_custody re-key block: the " +
        "bundle is signed and intact, but its bundle re-key path cannot run. " +
        "Re-export from the source fortress, or use the legacy passphrase path " +
        "if valid source_key_derivation parameters are present"
    );
  }

  // CLASS-LEVEL AGGREGATOR INPUT (LD2-01, extended by EXIT-STRUCT-02 for
  // per-element damage): the encrypted_state artifact's structural
  // read-health, computed once here so the sub-verdict below and any future
  // consumer share the same classification rather than each re-deriving
  // `entry_count === null` (container) or the per-element shape check
  // (`entries_malformed`) separately.
  const encryptedStateHealth = classifyEncryptedStateStructuralHealth(stateSummary);

  const publicKeysByDid = new Map<string, Uint8Array>();
  let identity: ExitBundleDetailedVerifierResult["identity"] | undefined;
  const identityVerification = identityBindingVerification.identityVerification;
  if (identityVerification) {
    let rotation: NonNullable<ExitBundleDetailedVerifierResult["identity"]>["rotation"];
    if (
      identityVerification.identity_id !== undefined &&
      identityVerification.public_key !== undefined
    ) {
      const rotationResult = verifyRotationChain({
        identityId: identityVerification.identity_id,
        currentPublicKey: identityVerification.public_key,
        rotationHistory: identityVerification.rotation_history,
      });
      rotation =
        rotationResult.status === "verified"
          ? {
              hop_count: rotationResult.chain.hop_count,
              chain_signature_verified: true,
              terminates_at_current: true,
              compromised_hops: rotationResult.chain.retired.filter(
                (retired) => retired.compromised
              ).length,
            }
          : {
              hop_count: Array.isArray(identityVerification.rotation_history)
                ? identityVerification.rotation_history.length
                : 0,
              chain_signature_verified: false,
              terminates_at_current:
                rotationResult.reason !== "rotation_chain_non_terminating",
              invalid_reason: rotationResult.reason,
              invalid_detail: rotationResult.detail,
              compromised_hops: 0,
            };
    }
    identity = {
      signature_valid: identityVerification.signature_valid,
      identity_id: identityVerification.identity_id,
      did: identityVerification.did,
      ...(rotation !== undefined ? { rotation } : {}),
    };
    // The pre-signature binding gate above proves this key is the manifest
    // identity's key before any reputation verifier can trust it by DID.
    if (identityVerification.did && identityVerification.public_key) {
      const currentPublicKey = fromBase64url(identityVerification.public_key);
      publicKeysByDid.set(identityVerification.did, currentPublicKey);
      if (
        identityVerification.identity_id !== undefined &&
        identityVerification.rotation_history !== undefined
      ) {
        const rotationResult = verifyRotationChain({
          identityId: identityVerification.identity_id,
          currentPublicKey: identityVerification.public_key,
          rotationHistory: identityVerification.rotation_history,
        });
        if (rotationResult.status === "verified") {
          for (const retired of rotationResult.chain.retired) {
            publicKeysByDid.set(publicKeyToDid(retired.public_key), retired.public_key);
          }
        }
      }
    }
  }

  // Exit V2 drill F2 (2026-08-22/23): resolve the optional known_signers
  // artifact into `publicKeysByDid` BEFORE reputation verification runs
  // below, so a re-exported (second-hop) bundle's foreign-signed
  // attestations can resolve through it. VERSION-GATED: a bundle exported
  // before this change carries no "known_signers" artifact kind,
  // `loadExitArtifact` returns null, and this block is a no-op - verify
  // behaves exactly as it did before this change.
  //
  // Independent gate on #1303 (2026-08-23), item 6: a PRESENT table that
  // cannot be trusted is a typed HARD FAILURE (`known_signers_invalid`)
  // returned immediately, before any further check - never a warning that
  // lets the bundle still pass when, by coincidence, no attestation in
  // this particular bundle happened to need the table. A tampered or
  // forged known_signers artifact is evidence of tampering in its own
  // right and must never be silently absorbed.
  const knownSignersArtifact = await loadExitArtifact(root, manifest, "known_signers");
  if (knownSignersArtifact) {
    if (
      identityVerification?.did === undefined ||
      identityVerification.public_key === undefined
    ) {
      // Unreachable in practice - the identity-binding gate above already
      // returned a failed result before this line whenever the identity
      // artifact/binding does not verify. Fail closed rather than silently
      // skip resolution if that invariant is ever violated by a future
      // change.
      return fail(root, manifest, "known_signers_invalid", warnings, unsupportedArtifacts);
    }
    const knownSignersResolution = resolveKnownSigners(
      knownSignersArtifact.json,
      identityVerification.did,
      fromBase64url(identityVerification.public_key)
    );
    if (!knownSignersResolution.ok) {
      warnings.push(
        `known_signers table could not be trusted (${knownSignersResolution.problem}` +
          (knownSignersResolution.detail ? `: ${knownSignersResolution.detail}` : "") +
          ")"
      );
      return fail(root, manifest, "known_signers_invalid", warnings, unsupportedArtifacts);
    }
    for (const [did, key] of knownSignersResolution.signers) {
      if (!publicKeysByDid.has(did)) publicKeysByDid.set(did, key);
    }
  }

  const auditArtifact = await loadExitArtifact(root, manifest, "audit_receipts");
  const audit = auditArtifact
    ? {
        receipt_count: Array.isArray((auditArtifact.json as { entries?: unknown[] }).entries)
          ? ((auditArtifact.json as { entries: unknown[] }).entries.length)
          : 0,
        individual_signatures_verified: false,
      }
    : undefined;
  if (auditArtifact) {
    unsupportedArtifacts.push(
      "audit_receipts: individual audit entries are not signed in the legacy L2 audit log; verifier pins them by signed manifest hash"
    );
    // Surface the export-cap truncation marker so the operator is told the
    // carried receipts are an incomplete (most-recent) slice, not the full
    // population that `total` reports.
    const auditJson = auditArtifact.json as {
      truncated?: unknown;
      omitted_count?: unknown;
    };
    if (auditJson.truncated === true) {
      const omitted =
        typeof auditJson.omitted_count === "number"
          ? auditJson.omitted_count
          : undefined;
      warnings.push(
        omitted !== undefined
          ? `audit receipts are truncated: the oldest ${omitted} entries were omitted by the export cap`
          : "audit receipts are truncated: the oldest entries were omitted by the export cap"
      );
    }
  }

  const reputationArtifact = await loadExitArtifact(root, manifest, "reputation_bundle");
  const reputation = reputationArtifact
    ? verifyReputationArtifact(reputationArtifact.json, publicKeysByDid)
    : undefined;
  if (reputation) {
    if (reputation.bundle_signature_valid === "unverifiable") {
      warnings.push("reputation bundle signature is unverifiable from included public identities");
    } else if (!reputation.bundle_signature_valid) {
      warnings.push("reputation bundle signature is invalid");
    }
    if (reputation.unverifiable_attestations > 0) {
      warnings.push(
        `${reputation.unverifiable_attestations} reputation attestation(s) have unknown signer public keys` +
          (reputation.first_unverifiable_signer_prefix !== undefined
            ? `; first signer DID prefix: ${reputation.first_unverifiable_signer_prefix}`
            : "")
      );
    }
    if (reputation.invalid_attestations > 0) {
      warnings.push(
        `${reputation.invalid_attestations} reputation attestation(s) failed signature verification`
      );
    }
    if (reputation.completeness === "mismatch") {
      warnings.push(
        reputation.completeness_error !== undefined
          ? `reputation bundle completeness mismatch: ${reputation.completeness_error}`
          : "reputation bundle completeness mismatch"
      );
    } else if (
      reputation.completeness === "unverified-completeness-legacy-bundle"
    ) {
      warnings.push(
        "reputation bundle has no completeness manifest; exported-set completeness is unverified"
      );
    }
  }

  // EXIT-PASS-01 class (loop-dry follow-up): the bundle signature is
  // `boolean | "unverifiable"`. An UNVERIFIABLE bundle signature (the exporter's
  // key is not among the included identities) used to leave `passed` true while
  // import rejected the same bundle (verifyReputationBundle throws) — the exact
  // verify-lies shape EXIT-PASS-01 fixed for the rotation chain. Fail `passed`
  // on anything that is not positively valid, but only when a reputation bundle
  // is actually present (a bundle with no reputation must still PASS). There is
  // no operator relaxation for a bad/unverifiable BUNDLE signature (unlike
  // unverifiable per-attestation signers, which `acceptUnverifiableAttestations`
  // relaxes separately below); import never admits one either.
  const reputationBundleFailed =
    reputation !== undefined && reputation.bundle_signature_valid !== true;
  const reputationAttestationFailed = (reputation?.invalid_attestations ?? 0) > 0;
  const reputationCompletenessFailed = reputation?.completeness === "mismatch";
  const identityFailed = identity ? !identity.signature_valid : false;
  // EXIT-PASS-01: a present-but-invalid rotation chain is a verifier failure,
  // not descriptive metadata. `rotation` is undefined when the bundle carries
  // no rotation history, so this only fires on a chain that exists and does
  // not verify — non-rotated bundles never false-positive. Keys on
  // chain_signature_verified, so the signed-but-compromised chain admitted via
  // --accept-compromised-rotation-keys (chain_signature_verified === true)
  // stays PASS and its policy gate is untouched. Import already fails closed on
  // the same chain (ROTATION_CHAIN_UNVERIFIABLE); this closes the verify/inspect
  // command that reported PASS on a chain it could not verify.
  const rotationFailed =
    identity?.rotation !== undefined &&
    identity.rotation.chain_signature_verified === false;
  const unverifiableCount = reputation?.unverifiable_attestations ?? 0;
  const unverifiableFailed =
    unverifiableCount > 0 && !options.acceptUnverifiableAttestations;
  if (unverifiableFailed) {
    warnings.push(
      `${unverifiableCount} reputation attestation(s) have unknown signer public keys; ` +
        `pass --accept-unverifiable-attestations to relax this read-only preview ` +
        `verdict. Import is unaffected: it always verifies strictly and never ` +
        `admits an unverifiable attestation.`
    );
  }

  const entriesUnreadableFailed = encryptedStateSubVerdictFailed(
    encryptedStateHealth
  );

  // CLASS-LEVEL AGGREGATOR (LD2-01 follow-up, type-forced 2026-08-10 fix
  // round). `passed` is a reduction over `subVerdicts`, a
  // `Record<ExitBundleFailureClass, boolean>` keyed over the ENTIRE contract
  // union, not a hand-written `&&` chain and not an array a developer can
  // extend incompletely. This absorbs the two prior one-instance fixes for
  // the same class (#1189 rotation-chain-invalid, #1194
  // reputation-bundle-signature-unverifiable) by routing them through the
  // same structure rather than leaving them as separate ad-hoc terms.
  //
  // COMPLETENESS IS NOW COMPILE-ENFORCED, not merely tested. `Record<K, V>`
  // requires every member of `K` as a key: omitting any
  // `ExitBundleFailureClass` member below is a `TS2741 property missing`
  // compile error, so a new failure_class landing in the contract union
  // (contracts/v1.1/exit-bundle-manifest.ts) forces a human to make a
  // conscious `true`/`false` wiring decision for it here before the branch
  // even typechecks — the omission-by-forgetting shape that produced three
  // prior instances of this bug is no longer expressible. (Previously this
  // was a plain array of `{ name, failed }` objects, whose `name` typing
  // rejected an invalid name but never forced every union member to be
  // present; adding a new contract member compiled clean with no entry for
  // it. That gap is what this Record closes.)
  //
  // Members below fall into two groups:
  //   1. The seven GATING sub-verdicts this aggregator actually computes,
  //      wired to their booleans above.
  //   2. Every OTHER `ExitBundleFailureClass` member, pinned to `false` with
  //      a one-line reason. Each of those classes is enforced by an EARLY
  //      RETURN elsewhere in `verifyExitBundle` (see the `fail(...)` call
  //      sites and `identityBindingVerification.failure_class` above) —
  //      execution cannot reach this line while any of those conditions
  //      holds, because the function already returned a failed result with
  //      that exact `failure_class`. They are listed and pinned, never
  //      omitted, purely so the Record stays total over the union; `"other"`
  //      is the catch-all and is never assigned by this ladder either.
  const subVerdicts: Record<ExitBundleFailureClass, boolean> = {
    // --- Gating: computed by this aggregator. Changing any line below is a
    // live behavior change and is covered by
    // server/test/exit/exit-verifier-aggregator.test.ts.
    identity_signature_invalid: identityFailed,
    rotation_chain_invalid: rotationFailed,
    reputation_bundle_signature_invalid: reputationBundleFailed,
    reputation_completeness_mismatch: reputationCompletenessFailed,
    reputation_attestation_signature_invalid: reputationAttestationFailed,
    reputation_unverifiable_attestations: unverifiableFailed,
    encrypted_state_entries_unreadable: entriesUnreadableFailed,

    // --- Non-gating for THIS ladder: already handled by an early `return
    // fail(...)` before this point in `verifyExitBundle` runs.
    manifest_unknown_version: false, // early-returned at the manifest_version gate above
    manifest_signature_scheme_invalid: false, // early-returned at the signature_scheme gate above
    artifact_path_duplicate: false, // early-returned in the per-artifact path-validation loop above
    artifact_kind_duplicate: false, // early-returned in the per-artifact path-validation loop above (independent gate, item 5)
    artifact_set_invalid: false, // early-returned by the per-manifest_version exact-set check above (independent gate, item 5)
    artifact_directory_unlisted_file: false, // early-returned by the directory-walk check above (independent gate, item 5)
    known_signers_invalid: false, // early-returned by the known_signers resolution block above (independent gate, item 6)
    artifact_path_unsafe: false, // early-returned in the per-artifact path-validation loop above
    identity_binding_mismatch: false, // early-returned by verifyIdentityBindingBeforeManifestKeyUse above
    manifest_signature_invalid: false, // early-returned at the manifest fortress-master signature gate above
    aggregate_hash_mismatch: false, // early-returned at the artifacts_aggregate_hash gate above
    archive_contains_symlink: false, // early-returned by the per-artifact symlink/hash/size loop above
    artifact_path_escapes_root: false, // early-returned by the per-artifact symlink/hash/size loop above
    artifact_missing: false, // early-returned by the per-artifact symlink/hash/size loop above
    artifact_hash_mismatch: false, // early-returned by the per-artifact symlink/hash/size loop above
    artifact_size_mismatch: false, // early-returned by the per-artifact symlink/hash/size loop above
    private_material_present: false, // early-returned by the per-artifact symlink/hash/size loop above
    other: false, // catch-all; the unknown-artifact-kind gate above returns "other" directly via an early return
  };
  const passed = Object.values(subVerdicts).every((failed) => !failed);
  // Priority order (full-sweep #77, preserved): identity
  // (cryptographic-binding broken) beats rotation-chain beats
  // reputation-bundle (provenance broken) beats completeness mismatch
  // (signed manifest does not describe the body) beats individual
  // attestation invalidity beats unverifiable signers (policy-relaxable via
  // the explicit opt-in flag) beats the encrypted-state entries-unreadable
  // class (LD2-01, least specific: the artifact's own contents cannot be
  // read at all). Kept as an explicit ordered list, read against
  // `subVerdicts`, rather than relying on object key insertion order: an
  // ordering an editor can see and reorder directly, not an incidental
  // property of how the Record literal above happens to be written.
  const FAILURE_PRIORITY: readonly ExitBundleFailureClass[] = [
    "identity_signature_invalid",
    "rotation_chain_invalid",
    "reputation_bundle_signature_invalid",
    "reputation_completeness_mismatch",
    "reputation_attestation_signature_invalid",
    "reputation_unverifiable_attestations",
    "encrypted_state_entries_unreadable",
  ];
  const detailedFailureClass = FAILURE_PRIORITY.find(
    (name) => subVerdicts[name]
  );

  return {
    version: "1.1",
    passed,
    verified_at: new Date().toISOString(),
    manifest_path: join(root, "manifest.json"),
    manifest_hash: sha256Hex(manifestBytes),
    manifest_summary: {
      manifest_version: body.manifest_version,
      fortress_id: body.identity_binding.fortress_id,
      identity_id: body.identity_binding.identity_id,
      exported_at: body.exported_at,
      artifact_count: body.artifacts.length,
    },
    artifact_results: artifactResults,
    warnings,
    unsupported_artifacts: unsupportedArtifacts,
    identity,
    audit,
    reputation,
    ...(stateSummary !== undefined ? { state: stateSummary } : {}),
    failure_class: detailedFailureClass,
  };
}
