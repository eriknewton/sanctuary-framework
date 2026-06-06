/**
 * Manifest publisher: signs the allowlist manifest and atomic-renames it
 * over the watched location.
 *
 * Per scope-lock §4 Option A: rule files written first, then `manifest.json`
 * written via fs.write + fs.rename so the daemon's inotify watcher only ever
 * sees a fully-signed, fully-coherent manifest. POSIX rename is atomic on
 * the same filesystem.
 *
 * Pure logic lives in `buildSignedManifest`; the filesystem write half is
 * abstracted via a `ManifestStorage` interface so unit tests can run in a
 * mock storage without touching disk.
 */

import { sha256 } from "@noble/hashes/sha256";

import { canonicalize } from "../../mesh/canonical-json.js";
import { stringToBytes, toBase64url } from "../../core/encoding.js";
import { sign as identitySign } from "../../core/identity.js";
import type { EncryptedPayload } from "../../core/encryption.js";
import {
  CASTLE_WALL_SCHEMA_VERSION_V1,
  CASTLE_WALL_SIGNATURE_SCHEME_V1,
} from "../constants.js";
import type {
  AllowlistManifest,
  ManifestRuleEntry,
  ManifestSignature,
  SignedManifest,
} from "../allowlist/manifest.js";
import { validateAgentOrigin } from "../allowlist/agent-origin.js";
import type { AllowlistRule } from "../allowlist/schema.js";
import { RuntimeManifestPublishError } from "./errors.js";

/**
 * Encrypted private-key material for the LOCAL (dev/test) signing path. Under
 * B2 the production daemon does NOT construct this — the private key lives in
 * the root signer helper and never reaches the Node process. This shape remains
 * only so the local-sign path and tests can wrap a key into a `ManifestSigner`
 * via `localManifestSigner`.
 */
export interface ManifestSigningKey {
  signingKeyId: string;
  encryptedPrivateKey: EncryptedPayload;
  encryptionKey: Uint8Array;
}

/**
 * The signing handle the publisher uses. It carries NO key material — only a
 * key id (for the manifest envelope) and a `sign` callback that turns opaque
 * canonical bytes into a raw Ed25519 signature. The callback may be async (the
 * helper path shells out to the XPC shim) or sync (the local path). This is the
 * structural fix called out in §4.3: no private-key bytes flow through here.
 */
export interface ManifestSigner {
  signingKeyId: string;
  /** Sign opaque canonical bytes → raw 64-byte Ed25519 signature. */
  sign(canonicalBytes: Uint8Array): Promise<Uint8Array> | Uint8Array;
}

/**
 * Wrap encrypted local key material into a `ManifestSigner`. Used by the
 * dev/test local-sign path and by unit tests. The production daemon uses a
 * helper-backed signer instead (see runtime/helper-signer.ts).
 */
export function localManifestSigner(key: ManifestSigningKey): ManifestSigner {
  return {
    signingKeyId: key.signingKeyId,
    sign(canonicalBytes: Uint8Array): Uint8Array {
      return identitySign(canonicalBytes, key.encryptedPrivateKey, key.encryptionKey);
    },
  };
}

/** Storage abstraction for the publish step. */
export interface ManifestStorage {
  /** Write rule file at the given relative path. Overwrites if present. */
  writeRule(filename: string, bytes: Uint8Array): Promise<void>;
  /** Atomically replace `manifest.json` with the given bytes. */
  atomicRenameManifest(bytes: Uint8Array): Promise<void>;
  /** List rule filenames currently present in the directory. */
  listRules(): Promise<string[]>;
  /** Remove a rule file. Used when an enabled rule is later disabled. */
  removeRule(filename: string): Promise<void>;
}

/** Inputs to `buildSignedManifest`. */
export interface BuildSignedManifestInput {
  fortressId: string;
  issuedAt: string;
  rules: ReadonlyArray<AllowlistRule>;
  /** Signing handle (helper-backed in prod, local-backed in dev/test). */
  signer: ManifestSigner;
  /**
   * Optional, unvalidated agent-origin candidate (config / fixture). It is
   * run through `validateAgentOrigin`; a malformed candidate is dropped (the
   * field is omitted entirely) rather than emitted half-built. This foundation
   * build sources it from config/fixtures only -- no account provisioning or
   * runtime launch happens here.
   */
  agentOrigin?: unknown;
}

/** Compute SHA-256 hex of UTF-8 bytes. */
export function sha256Hex(bytes: Uint8Array): string {
  const digest = sha256(bytes);
  let hex = "";
  for (let i = 0; i < digest.length; i++) {
    const b = digest[i] ?? 0;
    hex += b.toString(16).padStart(2, "0");
  }
  return hex;
}

/** Render a single rule to its canonical-JSON file bytes. */
export function renderRuleFile(rule: AllowlistRule): Uint8Array {
  return stringToBytes(canonicalize(rule));
}

/**
 * Produce a SignedManifest for a given rule set. The manifest object is built
 * synchronously; signing is delegated to `input.signer.sign` over the canonical
 * bytes (the daemon canonicalizes in TS and the helper signs the result blind —
 * §4.3). Async because the helper path shells out to the XPC shim.
 */
export async function buildSignedManifest(input: BuildSignedManifestInput): Promise<{
  signed: SignedManifest;
  ruleFiles: ReadonlyArray<{ filename: string; bytes: Uint8Array }>;
}> {
  if (input.rules.length === 0) {
    // PR 2a accepts an empty rule set; the daemon enforces default-deny on
    // an empty manifest. Operators may install with no curated entries.
  }
  const seen = new Set<string>();
  const entries: ManifestRuleEntry[] = [];
  const ruleFiles: { filename: string; bytes: Uint8Array }[] = [];
  for (const rule of input.rules) {
    if (!rule.id || typeof rule.id !== "string") {
      throw new RuntimeManifestPublishError("rule missing id");
    }
    if (seen.has(rule.id)) {
      throw new RuntimeManifestPublishError(`duplicate rule id: ${rule.id}`);
    }
    seen.add(rule.id);
    const filename = `${rule.id}.json`;
    const bytes = renderRuleFile(rule);
    const digest = sha256Hex(bytes);
    entries.push({ rule_id: rule.id, file: filename, sha256: digest });
    ruleFiles.push({ filename, bytes });
  }
  entries.sort((a, b) => a.rule_id.localeCompare(b.rule_id));

  const manifest: AllowlistManifest = {
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    fortress_id: input.fortressId,
    issued_at: input.issuedAt,
    rules: entries,
  };

  // Additive agent-origin descriptor. A malformed candidate is dropped (field
  // omitted) so a half-built descriptor is never signed. Omitting the field
  // keeps the canonical-JSON bytes identical to a manifest built without it.
  if (input.agentOrigin !== undefined) {
    const validated = validateAgentOrigin(input.agentOrigin);
    if (validated !== null) {
      manifest.agent_origin = validated;
    }
  }

  let signatureBytes: Uint8Array;
  try {
    const canonical = stringToBytes(canonicalize(manifest));
    signatureBytes = await input.signer.sign(canonical);
  } catch (err) {
    // Fail-closed: a signing failure (helper unreachable, shim error) must abort
    // the build, never emit an unsigned manifest (hard constraint #5).
    throw new RuntimeManifestPublishError(
      `manifest signing failed: ${(err as Error).message}`
    );
  }
  if (signatureBytes.length !== 64) {
    throw new RuntimeManifestPublishError(
      `manifest signing produced ${signatureBytes.length}-byte signature (expected 64)`
    );
  }

  const signature: ManifestSignature = {
    signature_scheme: CASTLE_WALL_SIGNATURE_SCHEME_V1,
    signing_key_id: input.signer.signingKeyId,
    signature_b64url: toBase64url(signatureBytes),
  };

  return {
    signed: { manifest, signature },
    ruleFiles,
  };
}

/** Render the SignedManifest to its on-disk JSON bytes. */
export function renderSignedManifest(signed: SignedManifest): Uint8Array {
  return stringToBytes(canonicalize(signed));
}

/**
 * Publish: write rule files, then atomic-rename `manifest.json`. Removes
 * orphaned rule files (rules that are no longer referenced) AFTER the new
 * manifest is in place per scope-lock §4 atomicity rules (rule files are
 * removed only after the manifest stops referencing them).
 */
export async function publishSignedManifest(
  input: BuildSignedManifestInput,
  storage: ManifestStorage
): Promise<{
  signed: SignedManifest;
  written_rule_filenames: string[];
  removed_rule_filenames: string[];
}> {
  const { signed, ruleFiles } = await buildSignedManifest(input);
  const newFilenames = new Set<string>(ruleFiles.map((f) => f.filename));

  for (const file of ruleFiles) {
    await storage.writeRule(file.filename, file.bytes);
  }

  await storage.atomicRenameManifest(renderSignedManifest(signed));

  const existing = await storage.listRules();
  const removedRules: string[] = [];
  for (const name of existing) {
    if (name === "manifest.json") continue;
    if (newFilenames.has(name)) continue;
    await storage.removeRule(name);
    removedRules.push(name);
  }

  return {
    signed,
    written_rule_filenames: ruleFiles.map((f) => f.filename),
    removed_rule_filenames: removedRules,
  };
}
