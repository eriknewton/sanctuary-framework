// fail-before-exempt: reconciles Castle Wall packaging inputs (tsup config, copy scripts, stage/build shell scripts, release workflow, the shared sealed-runtime contract) against each other; the install.ts import of that contract is asserted textually here and behaviorally in test/cli/install.test.ts, which fails before.

/**
 * Whole-set parity for the sealed Castle Wall CLI runtime (rule 5 of the
 * assurance discipline: hand-mirrored registries drift; parity checks the whole
 * set, never the first entry).
 *
 * The signed app runs `Contents/Resources/cli-runtime/dist/cli.js` through its
 * sealed Node, and that bundle reaches siblings under `dist/` by path at run
 * time. These must agree on what those siblings are and are not:
 *
 *   1. the build inputs: `server/tsup.config.ts` entries and the post-build
 *      `server/scripts/copy-*.{js,mjs}` asset copies (the SOURCE of the set);
 *   2. `server/scripts/sealed-cli-runtime-entries.mjs` (the shared contract:
 *      required entries with per-directory sentinels, plus the deny set);
 *   3. `castle-wall-macos/scripts/stage-cli-runtime.sh` (the ONE copy step: it
 *      ships the whole dist tree, its excludes must drop no entry, and each
 *      exclude must have a deny-set counterpart);
 *   4. `server/src/cli/install.ts` (the installer imports the contract);
 *   5. the release workflow (runs the shared gate at both verification sites).
 *
 * This test derives (1) by parsing the inputs and asserts the rest agree. A new
 * tsup entry or copy script fails here until the shared list is extended; a
 * `landsWith` entry is tolerated only while its producer script is absent.
 */
import { afterAll, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import {
  SEALED_CLI_RUNTIME_DIST_DENY,
  SEALED_CLI_RUNTIME_DIST_ENTRIES,
  enforcedSealedCliRuntimeDistEntries,
  installerRequiredSealedCliRuntimeEntries,
  isPendingSealedCliRuntimeEntry,
  sealedCliRuntimeDenyMatch,
  sealedCliRuntimeManifestPath,
} from "../../scripts/sealed-cli-runtime-entries.mjs";

// server/test/structure/<file> -> repo root is four levels up.
const repoRoot = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const serverRoot = join(repoRoot, "server");
const scriptsDir = join(serverRoot, "scripts");
const stageScriptPath = join(repoRoot, "castle-wall-macos", "scripts", "stage-cli-runtime.sh");
const tsupConfig = readFileSync(join(serverRoot, "tsup.config.ts"), "utf8");
const stageScript = readFileSync(stageScriptPath, "utf8");
const buildWrapped = readFileSync(
  join(repoRoot, "castle-wall-macos", "scripts", "build-wrapped.sh"),
  "utf8",
);
const manifestBuilder = readFileSync(join(scriptsDir, "build-castle-wall-runtime-manifest.mjs"), "utf8");
const assertScript = readFileSync(join(scriptsDir, "sealed-cli-runtime-assert.mjs"), "utf8");
const installTs = readFileSync(join(serverRoot, "src", "cli", "install.ts"), "utf8");
const releaseWorkflow = readFileSync(
  join(repoRoot, ".github", "workflows", "castle-wall-macos-release.yml"),
  "utf8",
);

const tmpRoots: string[] = [];
function tmpRoot(prefix: string): string {
  const root = mkdtempSync(join(tmpdir(), prefix));
  tmpRoots.push(root);
  return root;
}

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
 * Every `dist/<path>` a copy script writes, from any of the forms the scripts
 * use: `join(..., "dist", "<literal>")`, `resolve(..., "dist", IDENT)` where
 * `const IDENT = "<literal>"` in the same script, a quoted `dist/<literal>` or
 * `./dist/<literal>`, or a template `` `./dist/${IDENT}` `` / `` `dist/${IDENT}` ``.
 */
export function parseCopyScriptOutputs(source: string): string[] {
  const constants = new Map<string, string>();
  for (const match of source.matchAll(/\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*"([^"]+)"/g)) {
    constants.set(match[1], match[2]);
  }
  const paths = new Set<string>();
  const add = (path: string) => paths.add(path.replace(/^\.?\//, "").replace(/\/$/, ""));
  for (const match of source.matchAll(/"dist"\s*,\s*"([^"]+)"/g)) add(match[1]);
  for (const match of source.matchAll(/"dist"\s*,\s*([A-Za-z_$][\w$]*)\s*[,)]/g)) {
    const literal = constants.get(match[1]);
    if (literal === undefined) throw new Error(`copy script joins "dist" with unresolved identifier ${match[1]}`);
    add(literal);
  }
  for (const match of source.matchAll(/["'`](?:\.\/)?dist\/([A-Za-z0-9_./-]+?)["'`]/g)) add(match[1]);
  for (const match of source.matchAll(/`(?:\.\/)?dist\/\$\{([A-Za-z_$][\w$]*)\}`/g)) {
    const literal = constants.get(match[1]);
    if (literal === undefined) throw new Error(`copy script template names unresolved identifier ${match[1]}`);
    add(literal);
  }
  return [...paths].sort();
}

function copyScriptOutputs(): Map<string, string[]> {
  const outputs = new Map<string, string[]>();
  const scripts = readdirSync(scriptsDir).filter((name) => /^copy-.*\.(m?js)$/.test(name)).sort();
  if (scripts.length === 0) throw new Error("no copy-*.{js,mjs} scripts found under server/scripts");
  for (const name of scripts) outputs.set(name, parseCopyScriptOutputs(readFileSync(join(scriptsDir, name), "utf8")));
  return outputs;
}

/** rsync `--exclude='<pattern>'` patterns in the stage script, in order. */
function stageExcludes(): string[] {
  return [...stageScript.matchAll(/--exclude='([^']+)'/g)].map((match) => match[1]).filter((p) => p !== ".bin");
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

/** The deny glob that corresponds to an rsync exclude pattern. */
function denyCounterpart(exclude: string): string {
  if (exclude.startsWith("/")) return `${exclude.replace(/\/$/, "")}/**`;
  return `**/${exclude}`;
}

function walk(dir: string, root = dir): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory() ? walk(join(dir, entry.name), root) : [relative(root, join(dir, entry.name))],
  );
}

/** A minimal fake dist carrying every enforced entry with its sentinel. */
function writeFakeDist(dist: string): void {
  for (const entry of enforcedSealedCliRuntimeDistEntries()) {
    if (entry.kind === "file") {
      mkdirSync(join(dist, entry.path, ".."), { recursive: true });
      writeFileSync(join(dist, entry.path), `// ${entry.path}\n`);
    } else {
      mkdirSync(join(dist, entry.path, entry.sentinel!, ".."), { recursive: true });
      writeFileSync(join(dist, entry.path, entry.sentinel!), "{}\n");
    }
  }
}

function runStage(distSrc: string, dest: string) {
  return spawnSync("/bin/bash", [stageScriptPath, dest, "--dist-only"], {
    encoding: "utf8",
    env: {
      ...process.env,
      SANCTUARY_CLI_RUNTIME_DIR: distSrc,
      SANCTUARY_CLI_PACKAGE_JSON: join(serverRoot, "package.json"),
    },
  });
}

describe("sealed Castle Wall CLI runtime: whole-set parity", () => {
  const enforced = enforcedSealedCliRuntimeDistEntries();
  const enforcedFiles = enforced.filter((entry) => entry.kind === "file").map((entry) => entry.path).sort();
  const enforcedDirs = enforced.filter((entry) => entry.kind === "dir").map((entry) => entry.path).sort();

  it("lists exactly the tsup entries as file entries", () => {
    expect(enforcedFiles).toEqual(tsupEntryOutputs().sort());
  });

  it("every directory entry names a sentinel file, and every entry names its producer", () => {
    for (const entry of SEALED_CLI_RUNTIME_DIST_ENTRIES) {
      if (entry.kind === "dir") {
        expect(entry.sentinel, `${entry.path} has no sentinel`).toMatch(/\S/);
        expect(entry.sentinel!.startsWith("/")).toBe(false);
        expect(entry.source).toMatch(/^copy-.*\.m?js$/);
      } else {
        expect(entry.source).toBe("tsup");
        expect(entry.sentinel).toBeUndefined();
      }
    }
  });

  it("lists exactly the copy-script dist outputs as directory entries (pending entries excluded)", () => {
    const outputs = copyScriptOutputs();
    // Each present copy script's outputs must be covered by an enforced
    // directory entry (equal to it, or nested under it), and every enforced
    // directory entry must be produced by some present copy script.
    const producedRoots = new Set<string>();
    for (const [script, paths] of outputs) {
      expect(paths.length, `${script} writes nothing under dist/`).toBeGreaterThan(0);
      for (const path of paths) {
        const covering = enforcedDirs.find((dir) => path === dir || path.startsWith(`${dir}/`));
        expect(covering, `${script} writes dist/${path}, which no enforced directory entry covers`).toBeDefined();
        producedRoots.add(covering!);
      }
    }
    expect([...producedRoots].sort()).toEqual(enforcedDirs);
    for (const entry of enforced) {
      if (entry.kind === "dir") expect([...outputs.keys()]).toContain(entry.source);
    }
  });

  it("a landsWith entry is pending only while its producer is absent, and the marker must go when it lands", () => {
    for (const entry of SEALED_CLI_RUNTIME_DIST_ENTRIES) {
      if (!entry.landsWith) {
        expect(isPendingSealedCliRuntimeEntry(entry)).toBe(false);
        continue;
      }
      expect(entry.landsWith).toMatch(/^#\d+$/);
      const producerPresent = existsSync(join(scriptsDir, entry.source));
      expect(
        producerPresent,
        `${entry.source} is present, so ${entry.landsWith} has landed: remove landsWith from ${entry.path}`,
      ).toBe(false);
      expect(isPendingSealedCliRuntimeEntry(entry)).toBe(true);
      // The installer never requires a pending entry; the build gates skip it.
      expect(installerRequiredSealedCliRuntimeEntries()).not.toContain(entry);
      expect(enforced).not.toContain(entry);
    }
  });

  it("parses the #1370 copy-script forms (const-bound identifier and ./dist template)", () => {
    // The two lines from server/scripts/copy-model-manifest-v2-asset.mjs (PR #1370).
    const fixture = [
      'const ASSET_RELATIVE_PATH = "intelligence/model-manifest/model-manifest.v2.json";',
      'const destinationPath = resolve(serverRoot, "dist", ASSET_RELATIVE_PATH);',
      "if (packageJson.exports?.[exportKey] !== `./dist/${ASSET_RELATIVE_PATH}`) {",
    ].join("\n");
    const parsed = parseCopyScriptOutputs(fixture);
    expect(parsed).toEqual(["intelligence/model-manifest/model-manifest.v2.json"]);
    const pending = SEALED_CLI_RUNTIME_DIST_ENTRIES.find((entry) => entry.path === "intelligence/model-manifest");
    expect(pending?.landsWith).toBe("#1370");
    expect(pending?.source).toBe("copy-model-manifest-v2-asset.mjs");
    expect(parsed[0].startsWith(`${pending!.path}/`)).toBe(true);
    expect(parsed[0]).toBe(`${pending!.path}/${pending!.sentinel}`);
    // The existing forms still parse.
    expect(parseCopyScriptOutputs('join(__dirname, "..", "dist", "templates")')).toEqual(["templates"]);
    expect(parseCopyScriptOutputs('resolve(serverRoot, "dist/intelligence/catalog-v3")')).toEqual(["intelligence/catalog-v3"]);
  });

  it("stage-cli-runtime.sh copies the whole dist tree; its excludes drop no required entry and each has a deny counterpart", () => {
    expect(stageScript).toMatch(/rsync -a --delete[\s\S]*?"\$\{CLI_RUNTIME_SRC\}\/" "\$\{CLI_RUNTIME_DEST\}\/dist\/"/);
    expect(stageScript).not.toMatch(/cp "\$\{CLI_RUNTIME_SRC\}\/cli\.js"/);
    const excludes = stageExcludes();
    expect(excludes.length).toBeGreaterThan(0);
    for (const entry of SEALED_CLI_RUNTIME_DIST_ENTRIES) {
      const probe = entry.kind === "file" ? entry.path : `${entry.path}/${entry.sentinel}`;
      for (const pattern of excludes) {
        expect(excludeMatches(pattern, probe), `exclude ${pattern} would drop required entry dist/${probe}`).toBe(false);
      }
      expect(sealedCliRuntimeDenyMatch(probe), `deny set forbids required entry dist/${probe}`).toBeNull();
    }
    for (const pattern of excludes) {
      expect(SEALED_CLI_RUNTIME_DIST_DENY, `exclude ${pattern} has no deny-set counterpart`).toContain(denyCounterpart(pattern));
    }
    // Symlinks and hardlinks are rejected, then the shared gate runs on the staged tree.
    expect(stageScript).toContain("find \"${CLI_RUNTIME_DEST}\" -type l -print -quit");
    expect(stageScript).toContain("find \"${CLI_RUNTIME_DEST}\" -type f -links +1 -print -quit");
    expect(stageScript).toContain('node "${CLI_RUNTIME_ASSERT}" "${CLI_RUNTIME_DEST}/dist"');
    expect(stageScript).toContain("server/scripts/sealed-cli-runtime-assert.mjs");
  });

  it("the deny set covers the classes the runtime must never carry", () => {
    for (const denied of [
      "cli.js.map", "index.d.ts", "cli.d.cts", "x/y.d.mts", "cli.cjs", "boot-runtime/castle-wall-boot-daemon.js",
      "storage.test.js", "a/b.spec.ts", "fixtures/manifest.json", "intelligence/fixtures/x.json",
      "__fixtures__/k.json", "__tests__/t.js", "__snapshots__/s.snap",
      "keys/operator.pem", "a.key", "x.p12", "y.pfx", "id_ed25519", "id_rsa.pub",
      "operator-private-key.json", "seed-phrase.txt", "client-secret.json", ".env", ".env.local",
    ]) {
      expect(sealedCliRuntimeDenyMatch(denied), `${denied} should be denied`).not.toBeNull();
    }
    for (const allowed of [
      "cli.js", "directory-capability-worker.js", "intelligence/index.js",
      "templates/research-assistant/template.json", "reference-plugin/blocklist/governance.yaml",
      "reference-plugin/blocklist/SIGNATURE.json", "reference-plugin/blocklist/first-party-signer.json",
      "intelligence/catalog-v3/schemas/schema-digests.json", "intelligence/catalog-v3/spdx/spdx-expression-3.0.1.abnf",
    ]) {
      expect(sealedCliRuntimeDenyMatch(allowed), `${allowed} should be allowed`).toBeNull();
    }
  });

  it("build-wrapped.sh stages the runtime only through stage-cli-runtime.sh", () => {
    expect(buildWrapped).toContain('CLI_RUNTIME_STAGER="${PKG_DIR}/scripts/stage-cli-runtime.sh"');
    expect(buildWrapped).toMatch(/bash "\$\{CLI_RUNTIME_STAGER\}" "\$\{CLI_RUNTIME_DIR\}"/);
    expect(buildWrapped).not.toMatch(/cp (?:-R )?"\$\{CLI_RUNTIME_SRC\}\//);
    expect(buildWrapped).not.toContain('"${CLI_RUNTIME_DIR}/templates"');
    expect(buildWrapped).not.toContain('"${CLI_RUNTIME_DIR}/reference-plugin"');
  });

  it("the manifest builder and the assert script gate on the shared contract", () => {
    expect(manifestBuilder).toContain('from "./sealed-cli-runtime-entries.mjs"');
    expect(manifestBuilder).toContain("missingSealedCliRuntimeManifestEntries(");
    expect(manifestBuilder).toContain("deniedSealedCliRuntimeManifestPaths(");
    expect(manifestBuilder).toContain("dist_entries: enforcedSealedCliRuntimeDistEntries().map(");
    expect(assertScript).toContain('from "./sealed-cli-runtime-entries.mjs"');
    expect(assertScript).toContain("missingSealedCliRuntimeEntries(");
    expect(assertScript).toContain("sealedCliRuntimeDenyMatch(");
  });

  it("install.ts derives its required set from the shared contract (no hand list)", () => {
    expect(installTs).toContain('from "../../scripts/sealed-cli-runtime-entries.mjs"');
    const block = installTs.match(/const required = new Set\(\[([\s\S]*?)\]\);/);
    expect(block, "install.ts `required` set not found").not.toBeNull();
    expect(block![1]).toContain("...installerRequiredSealedCliRuntimeEntries().map(sealedCliRuntimeManifestPath)");
    // No runtime path is hand-typed beside the spread; the launcher and node stay.
    const literals = [...block![1].matchAll(/"([^"]+)"/g)].map((match) => match[1]);
    expect(literals).toEqual(["MacOS/sanctuary", "Resources/boot-runtime/node"]);
    // The contract the installer enforces covers every bundler entry and every
    // asset directory through its sentinel.
    const installerPaths = installerRequiredSealedCliRuntimeEntries().map(sealedCliRuntimeManifestPath);
    for (const file of tsupEntryOutputs()) expect(installerPaths).toContain(`Resources/cli-runtime/dist/${file}`);
    for (const entry of installerRequiredSealedCliRuntimeEntries()) {
      if (entry.kind === "dir") expect(installerPaths).toContain(`Resources/cli-runtime/dist/${entry.path}/${entry.sentinel}`);
    }
    expect(installTs).toContain("an incomplete sealed runtime is one cause");
  });

  it("the release workflow runs the shared gate at both verification sites and no bare test -d", () => {
    const gateCalls = releaseWorkflow.match(/sealed-cli-runtime-assert\.mjs "\$(?:CLI_RUNTIME|ARTIFACT_CLI_RUNTIME)\/dist"/g) ?? [];
    expect(gateCalls).toHaveLength(2);
    for (const variable of ["CLI_RUNTIME", "ARTIFACT_CLI_RUNTIME"]) {
      expect(releaseWorkflow).toContain(`test -s "$${variable}/dist/directory-capability-worker.js"`);
      expect(releaseWorkflow).toContain(`test -z "$(find "$${variable}" -type f -links +1 -print -quit)"`);
      expect(releaseWorkflow).not.toContain(`test -d "$${variable}/templates"`);
      expect(releaseWorkflow).not.toContain(`test -d "$${variable}/reference-plugin"`);
      expect(releaseWorkflow).not.toContain(`test -d "$${variable}/dist/templates"`);
    }
  });

  it("no ESM entry under dist/ loads a .cjs sibling (the .cjs exclusion stays justified)", () => {
    const dist = join(serverRoot, "dist");
    expect(existsSync(join(dist, "cli.js")), "server/dist is not built").toBe(true);
    for (const file of tsupEntryOutputs()) {
      const source = readFileSync(join(dist, file), "utf8");
      // A relative import or require of a .cjs path would reach a file the stage
      // script excludes; none may exist in the shipped ESM entries.
      expect(source, `${file} loads a .cjs sibling`).not.toMatch(/(?:from|import\(|require\()\s*["']\.{1,2}\/[^"']*\.cjs["']/);
    }
  });

  it("the actual built dist, staged through the script, carries every entry and nothing the deny set forbids", () => {
    const dist = join(serverRoot, "dist");
    expect(existsSync(join(dist, "cli.js")), "server/dist is not built").toBe(true);
    const runtime = join(tmpRoot("sanctuary-sealed-dist-deny-"), "cli-runtime");
    const staged = runStage(dist, runtime);
    expect(staged.status, `${staged.stdout}\n${staged.stderr}`).toBe(0);
    const files = walk(join(runtime, "dist"));
    const denied = files.map((path) => [path, sealedCliRuntimeDenyMatch(path)] as const).filter(([, glob]) => glob !== null);
    expect(denied).toEqual([]);
    for (const entry of enforced) {
      const probe = entry.kind === "file" ? entry.path : `${entry.path}/${entry.sentinel}`;
      expect(files, `staged dist lacks ${probe}`).toContain(probe);
    }
    // Idempotent re-stage: a stale file in the destination is removed (--delete).
    writeFileSync(join(runtime, "dist", "stale-from-previous-build.js"), "");
    const restaged = runStage(dist, runtime);
    expect(restaged.status, `${restaged.stdout}\n${restaged.stderr}`).toBe(0);
    expect(existsSync(join(runtime, "dist", "stale-from-previous-build.js"))).toBe(false);
  });

  it("the stage script refuses a dist that carries a symlink, a hardlink, or a denied file", () => {
    const root = tmpRoot("sanctuary-sealed-stage-reject-");
    // Each plant edits the source dist or the destination before staging.
    const cases: Array<[string, (dist: string, dest: string) => void, RegExp]> = [
      ["symlink", (dist) => symlinkSync(join(dist, "cli.js"), join(dist, "cli-link.js")), /symbolic links/],
      // rsync materializes a source hardlink into an independent file, which is
      // correct; the check guards the DESTINATION, where a pre-existing path
      // hardlinked to bytes outside the seal would survive the copy in place.
      ["hardlink", (_dist, dest) => {
        mkdirSync(dest, { recursive: true });
        writeFileSync(join(root, "outside-the-seal.json"), "{}");
        linkSync(join(root, "outside-the-seal.json"), join(dest, "package.json"));
      }, /hardlinked files/],
      ["denied", (dist) => {
        mkdirSync(join(dist, "fixtures"), { recursive: true });
        writeFileSync(join(dist, "fixtures", "sample.json"), "{}");
      }, /denied file: dist\/fixtures\/sample\.json/],
      ["empty-dir", (dist) => rmSync(join(dist, "templates", "research-assistant", "template.json")), /missing: templates\/research-assistant\/template\.json/],
    ];
    for (const [name, plant, message] of cases) {
      const dist = join(root, name, "dist");
      writeFakeDist(dist);
      plant(dist, join(root, name, "cli-runtime"));
      const result = runStage(dist, join(root, name, "cli-runtime"));
      expect(result.status, `${name}: ${result.stdout}\n${result.stderr}`).not.toBe(0);
      expect(result.stderr, name).toMatch(message);
    }
    // And the clean fake dist passes, so the rejections above are the plants.
    const clean = join(root, "clean", "dist");
    writeFakeDist(clean);
    const ok = runStage(clean, join(root, "clean", "cli-runtime"));
    expect(ok.status, `${ok.stdout}\n${ok.stderr}`).toBe(0);
  });
});

afterAll(() => {
  for (const root of tmpRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});
