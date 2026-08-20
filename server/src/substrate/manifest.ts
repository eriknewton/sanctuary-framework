/**
 * Plugin substrate — signed BundleDescriptor + Ed25519 SIGNATURE.json verification
 * (design §3.1a; RFC §5, §7.4).
 *
 * The signature is ONE Ed25519 signature over canonical-JSON(BundleDescriptor) — not a
 * loose hash list. The descriptor binds identity (signer_id/key_id/plugin_id/version/
 * channel), the algorithm (inside the signed bytes, tamper-detect only — the verifier is
 * selected from HOST POLICY, never from the wrapper), and the COMPLETE file set with an
 * exact bidirectional match. SIGNATURE.json is the one detached, non-cyclic exclusion.
 *
 * S1 verifies a descriptor against a provided trusted-signer pubkey + the actual on-disk
 * file set. It does NOT spawn, jail, or install (those are S2-S4). It is pure verification
 * over inputs the caller supplies, so it is fully unit-testable with a tamper suite.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";

import { canonicalizeToBytes } from "./canonical-json.js";
import { reject } from "./errors.js";
import { validateBundlePath, validateId } from "./paths.js";
// a descriptor entry comes from an untrusted bundle; `path` is type-checked
// but unbounded in length, so diagnostics go through the untrusted-diagnostic
// chokepoint (STATE-STORE-ERRMSG-INTERP-01).
import { describeUntrusted } from "../errors/index.js";

export const BUNDLE_SCHEMA = "sanctuary.plugin.bundle/v1";
export const SIGNATURE_FILENAME = "SIGNATURE.json";
export const SUPPORTED_ALG = "ed25519";

export interface BundleFileEntry {
  path: string;
  type: "file";
  mode_exec: boolean;
  size: number;
  /** lowercase hex sha256 */
  sha256: string;
}

export interface BundleDescriptor {
  schema: typeof BUNDLE_SCHEMA;
  alg: typeof SUPPORTED_ALG;
  signer_id: string;
  key_id: string;
  plugin_id: string;
  version: string;
  channel: string;
  /** sha256(canonical-JSON(governance.yaml-parsed)) */
  governance_hash: string;
  files: BundleFileEntry[];
}

/** The on-disk SIGNATURE.json wrapper. `alg` here is advisory only — NOT verifier-select. */
export interface SignatureFile {
  descriptor: BundleDescriptor;
  /** base64 Ed25519 signature over canonicalize(descriptor) bytes. */
  signature: string;
}

/** What the host knows about a bundle's actual on-disk contents (supplied by caller). */
export interface ObservedBundle {
  /** Every regular file relative path → its sha256 hex + exec bit + size. */
  files: ReadonlyArray<{ path: string; sha256: string; mode_exec: boolean; size: number }>;
  /** Relative paths of any non-regular entries (symlink/hardlink/device/dir) found. */
  nonRegular: readonly string[];
  /** The number of files named exactly SIGNATURE.json at the bundle root. */
  signatureFileCount: number;
}

/** Trusted-signer lookup result the host resolves from policy (S4 wires the registry). */
export interface TrustedSigner {
  signer_id: string;
  key_id: string;
  /** raw 32-byte Ed25519 public key */
  publicKey: Uint8Array;
}

export interface VerifyContext {
  /** Resolve a (signer_id, key_id) → pubkey from HOST POLICY only. Undefined ⇒ unknown signer. */
  resolveSigner: (signer_id: string, key_id: string) => TrustedSigner | undefined;
  /** The actual on-disk bundle contents the install enumerated. */
  observed: ObservedBundle;
  /** The expected entry-point path declared in governance.yaml. */
  entryPath: string;
  /** Optional: bind the descriptor to an expected plugin id/version/channel. */
  expect?: { plugin_id?: string; version?: string; channel?: string };
  /** Max descriptor size in bytes; default MAX_DESCRIPTOR_BYTES. */
  maxDescriptorBytes?: number;
}

export const MAX_DESCRIPTOR_BYTES = 1024 * 1024; // 1 MiB
const HEX64 = /^[0-9a-f]{64}$/;

/** Compute the lowercase-hex sha256 of bytes. */
export function sha256Hex(bytes: Uint8Array): string {
  const d = sha256(bytes);
  let s = "";
  for (const b of d) s += b.toString(16).padStart(2, "0");
  return s;
}

/** Structural validation of a parsed descriptor object. Throws a named rejection on any miss. */
export function validateDescriptorShape(raw: unknown): BundleDescriptor {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    reject("descriptor_malformed", "descriptor must be a JSON object");
  }
  const d = raw as Record<string, unknown>;

  const ALLOWED = new Set([
    "schema",
    "alg",
    "signer_id",
    "key_id",
    "plugin_id",
    "version",
    "channel",
    "governance_hash",
    "files",
  ]);
  for (const k of Object.keys(d)) {
    if (k === "__proto__" || k === "constructor" || k === "prototype") {
      reject("json_prototype_key", `descriptor has a prototype-pollution key "${k}"`);
    }
    if (!ALLOWED.has(k)) reject("descriptor_malformed", `descriptor has unknown key "${k}"`);
  }

  if (d.schema !== BUNDLE_SCHEMA) reject("descriptor_malformed", `descriptor schema must be "${BUNDLE_SCHEMA}"`);
  if (d.alg !== SUPPORTED_ALG) reject("signature_algorithm_unsupported", `descriptor alg must be "${SUPPORTED_ALG}"`);

  for (const f of ["signer_id", "key_id", "plugin_id", "version", "channel", "governance_hash"]) {
    if (typeof d[f] !== "string" || (d[f] as string).length === 0) {
      reject("descriptor_malformed", `descriptor.${f} must be a non-empty string`);
    }
  }
  validateId(d.signer_id as string, "signer");
  validateId(d.plugin_id as string, "plugin");
  if (!HEX64.test(d.governance_hash as string)) {
    reject("descriptor_malformed", "descriptor.governance_hash must be a 64-char hex sha256");
  }

  if (!Array.isArray(d.files) || d.files.length === 0) {
    reject("descriptor_malformed", "descriptor.files must be a non-empty array");
  }
  const files: BundleFileEntry[] = [];
  const seenPaths = new Set<string>();
  for (const entry of d.files as unknown[]) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      reject("descriptor_malformed", "each descriptor.files entry must be an object");
    }
    const e = entry as Record<string, unknown>;
    const EALLOWED = new Set(["path", "type", "mode_exec", "size", "sha256"]);
    for (const k of Object.keys(e)) {
      if (!EALLOWED.has(k)) reject("descriptor_malformed", `file entry has unknown key "${k}"`);
    }
    if (typeof e.path !== "string") reject("descriptor_malformed", "file.path must be a string");
    validateBundlePath(e.path);
    if (e.path === SIGNATURE_FILENAME) {
      reject("bundle_signature_file_listed", "SIGNATURE.json must not be listed in files[] (non-cyclic rule)");
    }
    if (seenPaths.has(e.path)) reject("descriptor_malformed", `duplicate file path "${describeUntrusted(e.path)}" in descriptor`);
    seenPaths.add(e.path);
    if (e.type !== "file") reject("bundle_non_regular_file", `file "${describeUntrusted(e.path)}" type must be "file"`);
    if (typeof e.mode_exec !== "boolean") reject("descriptor_malformed", `file "${describeUntrusted(e.path)}" mode_exec must be boolean`);
    if (typeof e.size !== "number" || !Number.isInteger(e.size) || e.size < 0) {
      reject("descriptor_malformed", `file "${describeUntrusted(e.path)}" size must be a non-negative integer`);
    }
    if (typeof e.sha256 !== "string" || !HEX64.test(e.sha256)) {
      reject("descriptor_malformed", `file "${describeUntrusted(e.path)}" sha256 must be a 64-char hex string`);
    }
    files.push({
      path: e.path,
      type: "file",
      mode_exec: e.mode_exec,
      size: e.size,
      sha256: e.sha256,
    });
  }

  return {
    schema: BUNDLE_SCHEMA,
    alg: SUPPORTED_ALG,
    signer_id: d.signer_id as string,
    key_id: d.key_id as string,
    plugin_id: d.plugin_id as string,
    version: d.version as string,
    channel: d.channel as string,
    governance_hash: d.governance_hash as string,
    files,
  };
}

/**
 * Verify a SIGNATURE.json against host trust + the observed on-disk bundle.
 *
 * Fail-closed at every step (CLAUDE.md MUST-NEVER #5). Returns the validated descriptor on
 * success; throws a SubstrateError with a named reason on any failure.
 */
export function verifyBundle(sig: SignatureFile, ctx: VerifyContext): BundleDescriptor {
  const descriptor = validateDescriptorShape(sig.descriptor);

  // 1. Re-derive the exact signed bytes from OUR canonicalizer (not a re-serialization of
  //    whatever the wrapper shipped) and bound their size.
  const signedBytes = canonicalizeToBytes(descriptor);
  const maxBytes = ctx.maxDescriptorBytes ?? MAX_DESCRIPTOR_BYTES;
  if (signedBytes.length > maxBytes) {
    reject("manifest_too_large", `descriptor canonical size ${signedBytes.length} exceeds ${maxBytes}`);
  }

  // 2. Resolve the verifier from HOST POLICY by (signer_id, key_id) — never from sig.alg.
  const signer = ctx.resolveSigner(descriptor.signer_id, descriptor.key_id);
  if (!signer) {
    reject("signature_signer_unknown", `no trusted signer for (${descriptor.signer_id}, ${descriptor.key_id})`);
  }
  if (signer.signer_id !== descriptor.signer_id || signer.key_id !== descriptor.key_id) {
    reject("signature_signer_mismatch", "resolved signer identity does not match the descriptor");
  }

  // 3. Verify the Ed25519 signature.
  let signature: Uint8Array;
  try {
    signature = base64ToBytes(sig.signature);
  } catch {
    reject("signature_invalid", "signature is not valid base64");
  }
  let ok: boolean;
  try {
    ok = ed25519.verify(signature, signedBytes, signer.publicKey);
  } catch {
    ok = false;
  }
  if (!ok) reject("signature_invalid", "Ed25519 signature verification failed");

  // 4. Bind expected identity if the caller pinned it (anti-re-pointing).
  if (ctx.expect?.plugin_id && ctx.expect.plugin_id !== descriptor.plugin_id) {
    reject("signature_plugin_mismatch", "descriptor plugin_id does not match expected");
  }
  if (ctx.expect?.version && ctx.expect.version !== descriptor.version) {
    reject("signature_plugin_mismatch", "descriptor version does not match expected");
  }
  if (ctx.expect?.channel && ctx.expect.channel !== descriptor.channel) {
    reject("signature_plugin_mismatch", "descriptor channel does not match expected");
  }

  // 5. Exact-set match against the observed bundle (both directions), with the one
  //    non-cyclic SIGNATURE.json exclusion.
  enforceFileSetMatch(descriptor, ctx.observed);

  // 6. Entry-point membership + executable bit.
  const entry = descriptor.files.find((f) => f.path === ctx.entryPath);
  if (!entry) {
    reject("bundle_entry_not_listed", `entry path "${ctx.entryPath}" is not a signed file`);
  }
  if (!entry.mode_exec) {
    reject("bundle_entry_not_executable", `entry path "${ctx.entryPath}" is not marked executable`);
  }

  return descriptor;
}

/** Exact bidirectional file-set match; SIGNATURE.json is the one detached exclusion. */
function enforceFileSetMatch(descriptor: BundleDescriptor, observed: ObservedBundle): void {
  if (observed.nonRegular.length > 0) {
    reject(
      "bundle_non_regular_file",
      `bundle contains non-regular entries: ${observed.nonRegular.slice(0, 5).join(", ")}`,
    );
  }
  if (observed.signatureFileCount !== 1) {
    reject(
      "bundle_duplicate_signature_file",
      `expected exactly one root SIGNATURE.json, found ${observed.signatureFileCount}`,
    );
  }

  const descByPath = new Map(descriptor.files.map((f) => [f.path, f]));
  const observedByPath = new Map<string, { sha256: string; mode_exec: boolean; size: number }>();
  for (const f of observed.files) {
    if (f.path === SIGNATURE_FILENAME) {
      // the detached wrapper is excluded from the signed set
      continue;
    }
    validateBundlePath(f.path);
    observedByPath.set(f.path, f);
  }

  // every on-disk (non-signature) file must be listed
  for (const path of observedByPath.keys()) {
    if (!descByPath.has(path)) {
      reject("bundle_unlisted_file", `on-disk file "${path}" is not in the signed file set`);
    }
  }
  // every listed file must be present AND hash/exec/size must match
  for (const entry of descriptor.files) {
    const obs = observedByPath.get(entry.path);
    if (!obs) reject("bundle_missing_listed_file", `signed file "${entry.path}" is missing on disk`);
    if (obs.sha256 !== entry.sha256) {
      reject("signature_invalid", `file "${entry.path}" hash does not match the signed descriptor`);
    }
    if (obs.mode_exec !== entry.mode_exec) {
      reject("signature_invalid", `file "${entry.path}" exec bit does not match the signed descriptor`);
    }
    if (obs.size !== entry.size) {
      reject("signature_invalid", `file "${entry.path}" size does not match the signed descriptor`);
    }
  }
}

function base64ToBytes(b64: string): Uint8Array {
  if (typeof b64 !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) {
    throw new Error("invalid base64");
  }
  return new Uint8Array(Buffer.from(b64, "base64"));
}
