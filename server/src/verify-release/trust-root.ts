/**
 * The committed Sigstore trusted root: where it is, and how its bytes are read.
 *
 * The root is production data shipped with the verifier. It is located from
 * the RUNNING verifier module, never from `--target`, so the install under
 * check cannot supply the keys it is checked against. No TUF client, no
 * `~/.sigstore` cache and no network fetch is involved: a key rotation is a
 * reviewed change to the committed file, and a release signed outside the
 * committed windows refuses as `trusted-root-stale`.
 */

import { open } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Where the root lives relative to the package's `dist/` (built) or `src/`
 * (source checkout) folder. Must match TRUSTED_ROOT_RELATIVE_PATH in
 * server/scripts/copy-verify-release-trusted-root.mjs and the source and
 * capture notes in server/src/verify-release/README.md.
 */
export const TRUSTED_ROOT_RELATIVE_PATH = "verify-release/trusted_root.json";

/** The committed root is about 7 KB; 64 KiB bounds the read with ample room for a rotation. */
const MAX_TRUSTED_ROOT_BYTES = 64 * 1024;

/**
 * The ONE location of the root. tsup bundles this module flat into
 * `dist/cli.js` (module dir `dist/`); a source checkout runs it from
 * `src/verify-release/`. The base is therefore the module dir, or its parent
 * when the module dir is this module's own folder. There is no candidate list.
 */
export function resolveTrustedRootPath(moduleUrl: string = import.meta.url): string {
  const moduleDir = dirname(fileURLToPath(moduleUrl));
  const [segment] = TRUSTED_ROOT_RELATIVE_PATH.split("/");
  const base = basename(moduleDir) === segment ? dirname(moduleDir) : moduleDir;
  return join(base, ...TRUSTED_ROOT_RELATIVE_PATH.split("/"));
}

/** Read the root through one descriptor: type and size come from that descriptor's fstat. */
export async function readTrustedRootBytes(path?: string): Promise<Buffer | null> {
  let handle: Awaited<ReturnType<typeof open>>;
  try {
    // A CommonJS build has no file URL for this module, so the root cannot be located there; that refuses.
    handle = await open(path ?? resolveTrustedRootPath(), "r");
  } catch {
    return null;
  }
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > MAX_TRUSTED_ROOT_BYTES) return null;
    const buffer = Buffer.alloc(MAX_TRUSTED_ROOT_BYTES + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead > MAX_TRUSTED_ROOT_BYTES) return null;
    return buffer.subarray(0, bytesRead);
  } catch {
    return null;
  } finally {
    await handle.close().catch(() => undefined);
  }
}
