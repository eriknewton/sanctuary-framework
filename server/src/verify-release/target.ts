/**
 * state_TARGET: which install is checked, and which version its records are.
 *
 * The version always comes from the target's own `package.json`. A user can
 * only confirm it with `--version`, never substitute another, so one version's
 * files are never compared against another version's records.
 */

import { constants as fsConstants } from "node:fs";
import { open, realpath } from "node:fs/promises";
import { join } from "node:path";
import { PACKAGE_NAME, VERSION_PATTERN } from "./constants.js";
import { passed, type TargetEvidence } from "./evidence.js";
import { refuse, type StepOutcome } from "./reasons.js";

/**
 * 16 x the 1.8.4 package.json (6,651 bytes) = 106,416, rounded up to 128 KiB.
 * Bounds the read of a file the target controls.
 */
const MAX_PACKAGE_JSON_BYTES = 128 * 1024;

export interface TargetRequest {
  /** `--target` as typed, or undefined for self mode. */
  target?: string;
  /** `--version` as typed, if given. */
  version?: string;
}

/** Read `<root>/package.json` through ONE no-follow descriptor; type and size come from its fstat. */
async function readPackageJson(root: string): Promise<Buffer | null> {
  let handle: Awaited<ReturnType<typeof open>>;
  try {
    handle = await open(join(root, "package.json"), fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
  } catch {
    return null;
  }
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > MAX_PACKAGE_JSON_BYTES) return null;
    const buffer = Buffer.alloc(MAX_PACKAGE_JSON_BYTES + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    return bytesRead > MAX_PACKAGE_JSON_BYTES ? null : buffer.subarray(0, bytesRead);
  } catch {
    return null;
  } finally {
    await handle.close().catch(() => undefined);
  }
}

/**
 * `selfRoot` is the running package root, from `hermesPackageRootFromEntry`
 * over cli.ts's own module URL; `runningVersion` is that copy's version.
 */
export async function state_TARGET(
  request: TargetRequest,
  selfRoot: string,
  runningVersion: string,
): Promise<StepOutcome<TargetEvidence>> {
  const mode = request.target === undefined ? "self" : "target";
  let root: string;
  try {
    // realpath once: every later read is under this resolved root, and it is what the output names.
    root = await realpath(request.target ?? selfRoot);
  } catch {
    return refuse("target-unreadable");
  }
  const bytes = await readPackageJson(root);
  if (bytes === null) return refuse("target-unreadable");
  let manifest: unknown;
  try {
    manifest = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return refuse("target-package-json-invalid");
  }
  const name = (manifest as { name?: unknown } | null)?.name;
  const version = (manifest as { version?: unknown } | null)?.version;
  if (typeof name !== "string" || typeof version !== "string") return refuse("target-package-json-invalid");
  if (name !== PACKAGE_NAME) return refuse("target-package-mismatch");
  if (!VERSION_PATTERN.test(version)) return refuse("version-malformed");
  // Self mode checks the running copy for drift; a root that is some other version is not this copy.
  if (mode === "self" && version !== runningVersion) return refuse("self-version-mismatch");
  if (request.version !== undefined && request.version !== version) return refuse("version-mismatch");
  return passed({ state: "state_TARGET", root, version, mode });
}
