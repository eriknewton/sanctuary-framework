// fail-before-exempt: reconciles Castle Wall packaging inputs (tsup config, copy scripts, stage/build shell scripts, release workflow) against one shared list; the install.ts required-set pin is the only server/src edge and is asserted here alongside them.

/**
 * Whole-set parity for the sealed Castle Wall CLI runtime (rule 5 of the
 * assurance discipline: hand-mirrored registries drift; parity checks the whole
 * set, never the first entry).
 *
 * The signed app runs `Contents/Resources/cli-runtime/dist/cli.js` through its
 * sealed Node, and that bundle reaches siblings under `dist/` by path at run
 * time. Four places must agree on what those siblings are:
 *
 *   1. the build inputs: `server/tsup.config.ts` entries and the post-build
 *      `server/scripts/copy-*.{js,mjs}` asset copies (the SOURCE of the set);
 *   2. `server/scripts/sealed-cli-runtime-entries.mjs` (the shared presence
 *      gate run by the stage script, the manifest builder, and the workflow);
 *   3. `castle-wall-macos/scripts/stage-cli-runtime.sh` (the ONE copy step: it
 *      ships the whole dist tree, and its exclude list must not drop an entry);
 *   4. `server/src/cli/install.ts` (the installer's `required` set).
 *
 * This test derives (1) by parsing the inputs and asserts (2), (3), (4) and the
 * release workflow agree with it. A new tsup entry or copy script fails here
 * until the shared list is extended, which is the intended ratchet.
 */
import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  SEALED_CLI_RUNTIME_DIST_ENTRIES,
  SEALED_CLI_RUNTIME_MANIFEST_FILE_PATHS,
} from "../../scripts/sealed-cli-runtime-entries.mjs";

// server/test/structure/<file> -> repo root is four levels up.
const repoRoot = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const serverRoot = join(repoRoot, "server");
const tsupConfig = readFileSync(join(serverRoot, "tsup.config.ts"), "utf8");
const stageScript = readFileSync(
  join(repoRoot, "castle-wall-macos", "scripts", "stage-cli-runtime.sh"),
  "utf8",
);
const buildWrapped = readFileSync(
  join(repoRoot, "castle-wall-macos", "scripts", "build-wrapped.sh"),
  "utf8",
);
const manifestBuilder = readFileSync(
  join(serverRoot, "scripts", "build-castle-wall-runtime-manifest.mjs"),
  "utf8",
);
const installTs = readFileSync(join(serverRoot, "src", "cli", "install.ts"), "utf8");
const releaseWorkflow = readFileSync(
  join(repoRoot, ".github", "workflows", "castle-wall-macos-release.yml"),
  "utf8",
);

/** `entry: { key: "src/...", ... }` keys from tsup.config.ts, as `<key>.js`. */
function tsupEntryOutputs(): string[] {
  const block = tsupConfig.match(/entry:\s*\{([\s\S]*?)\}/);
  if (!block) throw new Error("tsup.config.ts entry block not found");
  const keys = [...block[1].matchAll(/^\s*(?:"([^"]+)"|([A-Za-z_$][\w$]*))\s*:\s*"/gm)]
    .map((match) => match[1] ?? match[2]);
  if (keys.length === 0) throw new Error("tsup.config.ts entry block has no keys");
  return keys.map((key) => `${key}.js`);
}

/**
 * Every `dist/<path>` a post-build copy script writes, from either the
 * `join(__dirname, "..", "dist", "<seg>", ...)` form or a `"dist/<path>"`
 * string form. The first path segment under dist/ is the directory the copy
 * populates, and the test names the set at that granularity plus any deeper
 * literal the script spells out.
 */
function copyScriptOutputs(): Map<string, string[]> {
  const outputs = new Map<string, string[]>();
  const scripts = readdirSync(join(serverRoot, "scripts"))
    .filter((name) => /^copy-.*\.(m?js)$/.test(name))
    .sort();
  if (scripts.length === 0) throw new Error("no copy-*.{js,mjs} scripts found under server/scripts");
  for (const name of scripts) {
    const source = readFileSync(join(serverRoot, "scripts", name), "utf8");
    const paths = new Set<string>();
    for (const match of source.matchAll(/"dist"\s*,\s*"([^"]+)"/g)) paths.add(match[1]);
    for (const match of source.matchAll(/["'`]dist\/([A-Za-z0-9_./-]+?)["'`]/g)) paths.add(match[1]);
    // A path ending in a template placeholder (`dist/templates/${name}`) is the
    // per-item form of the directory it lives under; keep the directory.
    outputs.set(name, [...paths].map((path) => path.replace(/\/$/, "")).sort());
  }
  return outputs;
}

/** rsync `--exclude='<pattern>'` patterns in the stage script, in order. */
function stageExcludes(): string[] {
  return [...stageScript.matchAll(/--exclude='([^']+)'/g)].map((match) => match[1]);
}

/**
 * Minimal rsync-pattern semantics for the shapes the stage script uses: a
 * leading `/` anchors to the transfer root, a trailing `/` matches only
 * directories, `*` matches within one path segment. Returns true when the
 * pattern would drop `path` (a dist-relative path) or any parent of it.
 */
function excludeMatches(pattern: string, path: string): boolean {
  const anchored = pattern.startsWith("/");
  const dirOnly = pattern.endsWith("/");
  const body = pattern.replace(/^\//, "").replace(/\/$/, "");
  const regex = new RegExp(`^${body.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*")}$`);
  const segments = path.split("/");
  for (let depth = 1; depth <= segments.length; depth++) {
    const prefix = segments.slice(0, depth).join("/");
    const isDir = depth < segments.length;
    if (dirOnly && !isDir) continue;
    if (anchored ? regex.test(prefix) : regex.test(segments[depth - 1])) return true;
  }
  return false;
}

/** The `required = new Set([...])` string literals in install.ts. */
function installRequiredSet(): string[] {
  const block = installTs.match(/const required = new Set\(\[([\s\S]*?)\]\);/);
  if (!block) throw new Error("install.ts `required` set not found");
  return [...block[1].matchAll(/"([^"]+)"/g)].map((match) => match[1]);
}

describe("sealed Castle Wall CLI runtime: whole-set parity", () => {
  const sharedFiles = SEALED_CLI_RUNTIME_DIST_ENTRIES
    .filter((entry) => entry.kind === "file")
    .map((entry) => entry.path)
    .sort();
  const sharedDirs = SEALED_CLI_RUNTIME_DIST_ENTRIES
    .filter((entry) => entry.kind === "dir")
    .map((entry) => entry.path)
    .sort();

  it("lists exactly the tsup entries as file entries", () => {
    expect(sharedFiles).toEqual(tsupEntryOutputs().sort());
  });

  it("lists exactly the copy-script dist outputs as directory entries", () => {
    const outputs = copyScriptOutputs();
    // Each copy script's outputs must be covered by a shared directory entry
    // (equal to it, or nested under it), and every shared directory entry must
    // be produced by some copy script: coverage in both directions.
    const producedRoots = new Set<string>();
    for (const [script, paths] of outputs) {
      expect(paths.length, `${script} writes nothing under dist/`).toBeGreaterThan(0);
      for (const path of paths) {
        const covering = sharedDirs.find((dir) => path === dir || path.startsWith(`${dir}/`));
        expect(covering, `${script} writes dist/${path}, which no shared directory entry covers`).toBeDefined();
        producedRoots.add(covering!);
      }
    }
    expect([...producedRoots].sort()).toEqual(sharedDirs);
    // Each shared entry names the script that produces it (a reader can trace
    // the pin without this test).
    for (const entry of SEALED_CLI_RUNTIME_DIST_ENTRIES) {
      if (entry.kind === "dir") expect([...outputs.keys()]).toContain(entry.source);
      else expect(entry.source).toBe("tsup");
    }
  });

  it("stage-cli-runtime.sh copies the whole dist tree and its excludes drop no required entry", () => {
    // The copy is the tree, not a list: one rsync of `${CLI_RUNTIME_SRC}/` into
    // `${CLI_RUNTIME_DEST}/dist/`, and no per-file `cp` of a dist entry.
    expect(stageScript).toMatch(/rsync -a[\s\S]*?"\$\{CLI_RUNTIME_SRC\}\/" "\$\{CLI_RUNTIME_DEST\}\/dist\/"/);
    expect(stageScript).not.toMatch(/cp "\$\{CLI_RUNTIME_SRC\}\/cli\.js"/);
    const excludes = stageExcludes();
    expect(excludes.length).toBeGreaterThan(0);
    for (const entry of SEALED_CLI_RUNTIME_DIST_ENTRIES) {
      for (const pattern of excludes) {
        expect(
          excludeMatches(pattern, entry.path),
          `exclude ${pattern} would drop required entry dist/${entry.path}`,
        ).toBe(false);
      }
    }
    // The excludes are the documented build-only classes and nothing else.
    expect(excludes.filter((pattern) => pattern !== ".bin").sort()).toEqual(
      ["*.cjs", "*.d.cts", "*.d.mts", "*.d.ts", "*.map", "/boot-runtime/"].sort(),
    );
    // The presence gate runs after the copy, against the staged tree.
    expect(stageScript).toContain('node "${CLI_RUNTIME_ENTRIES}" --assert "${CLI_RUNTIME_DEST}/dist"');
    expect(stageScript).toContain("server/scripts/sealed-cli-runtime-entries.mjs");
  });

  it("build-wrapped.sh stages the runtime only through stage-cli-runtime.sh", () => {
    expect(buildWrapped).toContain('CLI_RUNTIME_STAGER="${PKG_DIR}/scripts/stage-cli-runtime.sh"');
    expect(buildWrapped).toMatch(/bash "\$\{CLI_RUNTIME_STAGER\}" "\$\{CLI_RUNTIME_DIR\}"/);
    // The hand-typed copy list is gone: no direct copy of any dist entry.
    expect(buildWrapped).not.toMatch(/cp (?:-R )?"\$\{CLI_RUNTIME_SRC\}\//);
    expect(buildWrapped).not.toContain('"${CLI_RUNTIME_DIR}/templates"');
    expect(buildWrapped).not.toContain('"${CLI_RUNTIME_DIR}/reference-plugin"');
  });

  it("the manifest builder gates on the shared list and records it", () => {
    expect(manifestBuilder).toContain('from "./sealed-cli-runtime-entries.mjs"');
    expect(manifestBuilder).toContain("missingSealedCliRuntimeManifestEntries(");
    expect(manifestBuilder).toContain("dist_entries: SEALED_CLI_RUNTIME_DIST_ENTRIES.map(");
  });

  it("install.ts requires every shared file entry of the sealed runtime", () => {
    const required = installRequiredSet();
    for (const path of SEALED_CLI_RUNTIME_MANIFEST_FILE_PATHS) {
      if (path.endsWith("/index.js") || path.endsWith("/verify-transparency.js")) continue;
      expect(required, `install.ts required set lacks ${path}`).toContain(path);
    }
    // The launcher path and the worker are the two that decide "can this
    // runtime create a fortress"; both must be present.
    expect(required).toContain("Resources/cli-runtime/dist/cli.js");
    expect(required).toContain("Resources/cli-runtime/dist/directory-capability-worker.js");
  });

  it("the release workflow asserts the staged set at both verification sites", () => {
    const gateCalls = releaseWorkflow.match(/sealed-cli-runtime-entries\.mjs --assert "\$(?:CLI_RUNTIME|ARTIFACT_CLI_RUNTIME)\/dist"/g) ?? [];
    expect(gateCalls).toHaveLength(2);
    for (const variable of ["CLI_RUNTIME", "ARTIFACT_CLI_RUNTIME"]) {
      expect(releaseWorkflow).toContain(`test -s "$${variable}/dist/directory-capability-worker.js"`);
      expect(releaseWorkflow).toContain(`test -d "$${variable}/dist/templates"`);
      expect(releaseWorkflow).toContain(`test -d "$${variable}/dist/reference-plugin"`);
      // The pre-fix layout put assets beside dist/ where nothing reads them.
      expect(releaseWorkflow).not.toContain(`test -d "$${variable}/templates"`);
      expect(releaseWorkflow).not.toContain(`test -d "$${variable}/reference-plugin"`);
    }
  });
});
