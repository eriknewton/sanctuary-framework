import { cp, mkdtemp, realpath, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

type SubstrateModule = typeof import("../../src/substrate/index.js");

export interface IsolatedSourceTree {
  root: string;
  srcRoot: string;
  substrate: SubstrateModule;
  cleanup(): Promise<void>;
}

function requireStrictDescendant(root: string, target: string, label: string): void {
  const relative = path.relative(root, target);
  if (
    relative === "" ||
    path.isAbsolute(relative) ||
    relative === ".." ||
    relative.startsWith(`..${path.sep}`)
  ) {
    throw new Error(`${label} escapes its isolated fixture root`);
  }
}

/** Refuse mutation unless the existing bundle resolves inside the real copied source tree. */
export async function assertIsolatedBundlePath(
  tree: IsolatedSourceTree,
  bundleDir: string,
): Promise<void> {
  const realRoot = await realpath(tree.root);
  const realSrcRoot = await realpath(tree.srcRoot);
  requireStrictDescendant(realRoot, realSrcRoot, "source tree");

  const basename = path.basename(bundleDir);
  const realParent = await realpath(path.dirname(bundleDir));
  const expected = path.join(realSrcRoot, "substrate", "reference-plugin", basename);
  if (path.join(realParent, basename) !== expected || await realpath(bundleDir) !== expected) {
    throw new Error("bundle path escapes its isolated source tree");
  }
}

const serverRoot = fileURLToPath(new URL("../../", import.meta.url));
const canonicalSrcRoot = path.join(serverRoot, "src");

/**
 * Copy the production source tree so destructive loader tests exercise the real
 * import.meta.url and realpath gates without ever replacing a canonical source directory.
 */
export async function createIsolatedSourceTree(
  registerCleanup: (cleanup: () => Promise<void>) => void,
): Promise<IsolatedSourceTree> {
  // Keep the copy under the package root so Vitest transforms its TypeScript exactly
  // like project source. The hidden root is outside src/ and test/, so neither source
  // crawlers nor test-tree scanners can observe its temporary mutations.
  const root = await mkdtemp(path.join(serverRoot, ".plugin-test-fixture-"));
  let setupSettled = false;
  let settleSetup!: () => void;
  const setupDone = new Promise<void>((resolve) => { settleSetup = resolve; });
  let cleanupRequested = false;
  let cleanupPromise: Promise<void> | undefined;
  const cleanup = async (): Promise<void> => {
    cleanupRequested = true;
    if (cleanupPromise) return cleanupPromise;
    cleanupPromise = (async () => {
      await setupDone;
      await rm(root, { recursive: true, force: true });
    })();
    try {
      await cleanupPromise;
    } finally {
      // Coalesce only active removals. A timed-out test's in-flight write may finish
      // after afterEach cleanup; its own finally must remove any recreated fixture.
      cleanupPromise = undefined;
    }
  };
  const markSetupSettled = (): void => {
    if (setupSettled) return;
    setupSettled = true;
    settleSetup();
  };
  try {
    // Register before copy/import so every setup step after allocation is owned.
    registerCleanup(cleanup);
    const srcRoot = path.join(root, "src");
    await cp(canonicalSrcRoot, srcRoot, { recursive: true });
    const entry = path.join(srcRoot, "substrate", "index.ts");
    // Every root has a unique absolute path, so the module graph cannot collide in cache.
    const substrate = await import(pathToFileURL(entry).href) as SubstrateModule;
    if (cleanupRequested) throw new Error("isolated source tree was disposed during setup");
    markSetupSettled();
    return { root, srcRoot, substrate, cleanup };
  } catch (error) {
    markSetupSettled();
    try {
      await cleanup();
    } catch (cleanupError) {
      throw new AggregateError([error, cleanupError], "isolated source tree setup and cleanup failed");
    }
    throw error;
  } finally {
    markSetupSettled();
  }
}
