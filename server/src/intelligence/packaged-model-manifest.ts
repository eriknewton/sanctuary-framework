/**
 * Bounded loader for the packaged, Sanctuary-signed V2 model manifest.
 *
 * This is the production `loadManifest` dependency of the local-intelligence
 * provisioning ceremony (`wrap/local-intelligence.ts`). It reads ONE local
 * file, the signed `sanctuary.model-manifest.v2` envelope that ships inside
 * the npm package, applies a byte cap, parses it through the shared V2 parser
 * (never a second schema), verifies the Ed25519 signature against the compiled
 * model-catalog root pin, checks the build-time byte pin, and returns either
 * the verified manifest text or one typed, audited refusal.
 *
 * CAPABILITY BOUND (stated, not softened): this slice performs NO network
 * fetch. Discovery of a newer signed manifest over the network is deferred;
 * the only way to use a manifest newer than the packaged one is for the
 * operator to supply a signed file by path (`--model-manifest <path>`), which
 * is verified by exactly the same parser, byte cap, and pinned key. A packaged
 * manifest can therefore be stale but can never be silently replaced.
 *
 * Failure posture: every refusal is a closed, named state and is audited under
 * `INTEL_OPS.LOAD_INTEGRITY`; the ceremony then refuses with the same reason.
 * Absence, oversize, unparseable bytes, a bad signature, and a build-pin
 * mismatch are all refusals. None of them reads as "legacy" or "unverified".
 */

import { createHash, timingSafeEqual } from "node:crypto";
import { open } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { INTEL_OPS } from "./audit-events.js";
import { loadPinnedModelManifestKey } from "./model-manifest.js";
import { MAX_CATALOG_WIRE_JSON_BYTES } from "./model-catalog-v3.js";
import {
  computeModelManifestV2BodyDigest,
  verifyModelManifestV2WithKey,
  type ModelManifestBodyV2,
  type ModelManifestV2RefusalReason,
} from "./model-manifest-v2.js";

/**
 * Where the signed envelope lives, relative to the package root of a built
 * `dist/` tree and to `src/` in a source checkout. Must match
 * `ASSET_RELATIVE_PATH` in `server/scripts/copy-model-manifest-v2-asset.mjs`
 * and the `./intelligence/model-manifest/model-manifest.v2.json` entry in
 * `server/package.json` `exports`; the copy script asserts the package entry.
 */
export const PACKAGED_MODEL_MANIFEST_V2_ASSET_RELATIVE_PATH =
  "intelligence/model-manifest/model-manifest.v2.json";

/**
 * SHA-256 of the exact committed asset bytes, recorded when the asset is
 * signed and checked again at build (copy script) and at load (this module).
 * The envelope cannot authenticate its own bytes against replacement inside a
 * tampered package, so this reviewed constant is the independent root: a
 * package whose asset does not hash to it fails closed. Must match
 * `EXPECTED_MODEL_MANIFEST_V2_ASSET_SHA256` in
 * `server/scripts/copy-model-manifest-v2-asset.mjs`; both are rewritten only
 * by `scripts/sign-model-manifest-v2.mjs` when a new asset is produced.
 */
export const PACKAGED_MODEL_MANIFEST_V2_ASSET_SHA256 =
  "edc2091d555ee61a3ba760ef33c9bca4ba3dad5d83c44878cba2e0ba774d6b90";

/**
 * Byte cap applied before any parse. Equals the catalog wire cap
 * (`MAX_CATALOG_WIRE_JSON_BYTES`, 65,536 = 64 KiB): a full 32-model V2 body
 * canonicalizes to well under 32 KiB, so the cap leaves headroom without
 * admitting a payload the 256 KiB parser cap would also have to walk.
 */
export const PACKAGED_MODEL_MANIFEST_V2_MAX_BYTES = MAX_CATALOG_WIRE_JSON_BYTES;

/** Bound on the operator-supplied path echoed into an audit row. */
const AUDIT_PATH_MAX_CHARS = 256;

/** Closed refusal taxonomy for the asset load stage. */
export const PACKAGED_MODEL_MANIFEST_REFUSAL_REASONS = [
  "integrity_asset_absent",
  "integrity_asset_oversize",
  "integrity_asset_unparseable",
  "integrity_asset_signature_invalid",
  "integrity_asset_pin_mismatch",
] as const;
export type PackagedModelManifestRefusalReason =
  (typeof PACKAGED_MODEL_MANIFEST_REFUSAL_REASONS)[number];

export type PackagedModelManifestSource = "packaged" | "operator-path";

export const PACKAGED_MODEL_MANIFEST_AUDIT_STAGE = "packaged_manifest_load" as const;

export interface PackagedModelManifestAuditEvent {
  operation: typeof INTEL_OPS.LOAD_INTEGRITY;
  outcome: "success" | "failure";
  details: Readonly<Record<string, string | number | boolean | readonly string[]>>;
}

export type PackagedModelManifestLoadResult =
  | {
    ok: true;
    source: PackagedModelManifestSource;
    manifestText: string;
    body: ModelManifestBodyV2;
    assetSha256: string;
    bodySha256: string;
  }
  | {
    ok: false;
    source: PackagedModelManifestSource;
    reason: PackagedModelManifestRefusalReason;
    /** Closed parser/verifier reason or a short io code; never file contents. */
    detail: string;
  };

export interface LoadPackagedModelManifestV2Options {
  /**
   * Operator-supplied signed manifest path. When set, the packaged asset is
   * not consulted and the build-time byte pin does not apply (a newer signed
   * manifest cannot match a pin recorded for the older one); the signature
   * against the compiled root, the byte cap, and the shared parser still do.
   */
  assetPath?: string;
  /** Test seam; production resolves the compiled catalog root pin. */
  publicKey?: Uint8Array;
  /** Test seam; production uses `PACKAGED_MODEL_MANIFEST_V2_ASSET_SHA256`. */
  expectedAssetSha256?: string;
  /**
   * Test seam; production derives the package root from this module's own
   * directory. See `resolvePackagedModelManifestV2AssetPath`.
   */
  moduleDir?: string;
  audit?: (event: PackagedModelManifestAuditEvent) => Promise<void> | void;
}

/**
 * The ONE location of the packaged asset, derived from this module's own
 * directory. tsup bundles this module flat into `dist/cli.js` and
 * `dist/index.js` (module dir = the package `dist/` root) and into
 * `dist/intelligence/index.js` (module dir = `dist/intelligence/`); a source
 * checkout runs from `src/intelligence/`. The package root is therefore the
 * module dir, or its parent when the module dir is the `intelligence` segment,
 * and the asset lives only at `<root>/intelligence/model-manifest/...`.
 * There is no candidate list and no fallthrough: a file planted at any other
 * path, including beside a bundle entry, is never read; an absent canonical
 * file is the `integrity_asset_absent` verdict.
 */
export function resolvePackagedModelManifestV2AssetPath(
  moduleDir: string = dirname(fileURLToPath(import.meta.url)),
): string {
  const [segment] = PACKAGED_MODEL_MANIFEST_V2_ASSET_RELATIVE_PATH.split("/");
  const packageRoot = basename(moduleDir) === segment ? dirname(moduleDir) : moduleDir;
  return join(packageRoot, ...PACKAGED_MODEL_MANIFEST_V2_ASSET_RELATIVE_PATH.split("/"));
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function constantTimeHexEqual(left: string, right: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(left) || !/^[0-9a-f]{64}$/.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function ioCode(error: unknown): string {
  return typeof error === "object" && error !== null && "code" in error &&
      typeof (error as { code?: unknown }).code === "string"
    ? (error as { code: string }).code
    : "EIO";
}

type BoundedRead =
  | { ok: true; bytes: Uint8Array }
  | { ok: false; reason: "integrity_asset_absent" | "integrity_asset_oversize"; detail: string };

/**
 * Read at most `PACKAGED_MODEL_MANIFEST_V2_MAX_BYTES + 1` bytes in one call on
 * an open handle, so a file that grows between a size check and the read
 * cannot slip past the cap; one byte over the cap is the oversize signal.
 */
async function readBounded(path: string): Promise<BoundedRead> {
  let handle: Awaited<ReturnType<typeof open>>;
  try {
    handle = await open(path, "r");
  } catch (error) {
    return { ok: false, reason: "integrity_asset_absent", detail: ioCode(error) };
  }
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) {
      return { ok: false, reason: "integrity_asset_absent", detail: "not_regular_file" };
    }
    const buffer = Buffer.alloc(PACKAGED_MODEL_MANIFEST_V2_MAX_BYTES + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead > PACKAGED_MODEL_MANIFEST_V2_MAX_BYTES) {
      return { ok: false, reason: "integrity_asset_oversize", detail: "byte_cap_exceeded" };
    }
    return { ok: true, bytes: buffer.subarray(0, bytesRead) };
  } catch (error) {
    return { ok: false, reason: "integrity_asset_absent", detail: ioCode(error) };
  } finally {
    await handle.close().catch(() => undefined);
  }
}

/**
 * Collapse the shared parser/verifier taxonomy into the asset stage's closed
 * set. The signature family (including a missing signature string) is the
 * signature refusal; a wire-size refusal is oversize; everything else is a
 * body the shared schema rejected.
 */
export function mapModelManifestV2RefusalToAssetRefusal(
  reason: ModelManifestV2RefusalReason,
): PackagedModelManifestRefusalReason {
  switch (reason) {
    case "manifest_too_large":
      return "integrity_asset_oversize";
    case "absent":
    case "bad_signature_encoding":
    case "bad_signature_length":
    case "zero_signature":
    case "bad_signature":
    case "bad_pinned_key_length":
    case "zero_pinned_key":
      return "integrity_asset_signature_invalid";
    default:
      return "integrity_asset_unparseable";
  }
}

async function safeAudit(
  options: LoadPackagedModelManifestV2Options,
  event: PackagedModelManifestAuditEvent,
): Promise<void> {
  try {
    await options.audit?.(event);
  } catch {
    // An audit sink failure cannot turn a refusal into an acceptance or vice versa.
  }
}

/**
 * Load and verify the signed V2 model manifest. Order of checks: locate, byte
 * cap, build pin (packaged source only), UTF-8 decode, shared parse, signature
 * against the compiled root. The result is either the exact verified text
 * (handed unchanged to the ceremony's own verifier, which re-verifies it under
 * the same key and the persisted floor) or one refusal.
 */
export async function loadPackagedModelManifestV2(
  options: LoadPackagedModelManifestV2Options = {},
): Promise<PackagedModelManifestLoadResult> {
  const source: PackagedModelManifestSource = options.assetPath === undefined
    ? "packaged"
    : "operator-path";
  const auditBase: Record<string, string> = {
    stage: PACKAGED_MODEL_MANIFEST_AUDIT_STAGE,
    source,
    ...(options.assetPath === undefined
      ? {}
      : { path: resolve(options.assetPath).slice(0, AUDIT_PATH_MAX_CHARS) }),
  };
  const refuse = async (
    reason: PackagedModelManifestRefusalReason,
    detail: string,
  ): Promise<PackagedModelManifestLoadResult> => {
    await safeAudit(options, {
      operation: INTEL_OPS.LOAD_INTEGRITY,
      outcome: "failure",
      details: { ...auditBase, reason, detail },
    });
    return { ok: false, source, reason, detail };
  };

  let read: BoundedRead;
  if (options.assetPath !== undefined) {
    read = await readBounded(resolve(options.assetPath));
  } else {
    let canonicalPath: string;
    try {
      canonicalPath = resolvePackagedModelManifestV2AssetPath(options.moduleDir);
    } catch {
      return refuse("integrity_asset_absent", "module_location_unavailable");
    }
    read = await readBounded(canonicalPath);
  }
  if (!read.ok) return refuse(read.reason, read.detail);

  const assetSha256 = sha256Hex(read.bytes);
  if (source === "packaged") {
    // The build pin is the independent root for the shipped bytes; a signed
    // envelope that does not match it is a package that was altered after the
    // reviewed pin was recorded, however valid its signature is.
    const expected = options.expectedAssetSha256 ?? PACKAGED_MODEL_MANIFEST_V2_ASSET_SHA256;
    if (!constantTimeHexEqual(assetSha256, expected)) {
      return refuse("integrity_asset_pin_mismatch", assetSha256);
    }
  }

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(read.bytes);
  } catch {
    return refuse("integrity_asset_unparseable", "invalid_utf8");
  }
  if (text.length === 0) return refuse("integrity_asset_unparseable", "empty");

  const key = options.publicKey ?? loadPinnedModelManifestKey();
  if (key === null) return refuse("integrity_asset_signature_invalid", "pinned_key_unavailable");
  const verified = verifyModelManifestV2WithKey(text, key);
  if (!verified.ok) {
    return refuse(mapModelManifestV2RefusalToAssetRefusal(verified.reason), verified.reason);
  }
  const bodySha256 = computeModelManifestV2BodyDigest(verified.body);
  await safeAudit(options, {
    operation: INTEL_OPS.LOAD_INTEGRITY,
    outcome: "success",
    details: {
      ...auditBase,
      asset_sha256: assetSha256,
      body_sha256: bodySha256,
      manifest_version: verified.body.manifest_version,
      model_count: Object.keys(verified.body.models).length,
    },
  });
  return {
    ok: true,
    source,
    manifestText: text,
    body: verified.body,
    assetSha256,
    bodySha256,
  };
}
