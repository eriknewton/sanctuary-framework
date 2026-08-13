// fail-before-exempt: validates Castle Wall release scanner/manifest tooling outside server/src; install and wrap changed tests separately fail against reverted server/src.

import { execFileSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const scanner = fileURLToPath(new URL(
  "../../../castle-wall-macos/scripts/list-cli-runtime-mach-o.mjs",
  import.meta.url,
));
const manifestBuilder = fileURLToPath(new URL(
  "../../scripts/build-castle-wall-runtime-manifest.mjs",
  import.meta.url,
));
const releaseWorkflow = fileURLToPath(new URL(
  "../../../.github/workflows/castle-wall-macos-release.yml",
  import.meta.url,
));
const roots: string[] = [];

function sealedRuntimeAssertion(): string {
  const workflow = readFileSync(releaseWorkflow, "utf8");
  const stepStart = workflow.indexOf("- name: Assert sealed boot runtime");
  const stepEnd = workflow.indexOf("\n      - name:", stepStart + 1);
  const step = workflow.slice(stepStart, stepEnd);
  const assertion = step.match(/node -e '([\s\S]*?)' "\$MANIFEST" "\$MACH_O_COUNT"/);
  if (!assertion) throw new Error("sealed-runtime inline assertion not found");
  return assertion[1];
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("Castle Wall CLI-runtime Mach-O scanner", () => {
  it("executes the sealed-runtime workflow assertion with a relative manifest path", () => {
    const root = mkdtempSync(join(tmpdir(), "sanctuary-release-manifest-assertion-"));
    roots.push(root);
    const manifestPath = "build/Sanctuary-CastleWall.app/Contents/Resources/cli-runtime-manifest.json";
    mkdirSync(join(root, manifestPath, ".."), { recursive: true });
    writeFileSync(join(root, manifestPath), JSON.stringify({
      inventory: {
        file_count: 3,
        total_bytes: 1024,
        mach_o_count: 2,
        package_count: 1,
        package_json_count: 1,
        package_internal_json_count: 0,
        nested_package_count: 0,
        mach_o: [
          "Resources/cli-runtime/node_modules/@lmdb/lmdb-darwin-arm64/lmdb.node",
          "Resources/cli-runtime/node_modules/@msgpackr-extract/msgpackr-extract-darwin-arm64/extract.node",
        ],
      },
      files: [{ path: "Resources/cli-runtime/package.json" }],
    }));

    const output = execFileSync(process.execPath, ["-e", sealedRuntimeAssertion(), manifestPath, "2"], {
      cwd: root,
      encoding: "utf8",
    });
    expect(JSON.parse(output)).toMatchObject({
      file_count: 3,
      installed_package_roots: 1,
      mach_o_count: 2,
    });
  });

  it("fails closed for missing, malformed, and structurally incomplete manifests", () => {
    const root = mkdtempSync(join(tmpdir(), "sanctuary-release-manifest-rejection-"));
    roots.push(root);
    mkdirSync(join(root, "manifests"), { recursive: true });
    writeFileSync(join(root, "manifests/malformed.json"), "{not-json");
    writeFileSync(join(root, "manifests/incomplete.json"), JSON.stringify({ inventory: {} }));

    for (const manifestPath of [
      "manifests/missing.json",
      "manifests/malformed.json",
      "manifests/incomplete.json",
    ]) {
      expect(() => execFileSync(
        process.execPath,
        ["-e", sealedRuntimeAssertion(), manifestPath, "2"],
        { cwd: root, stdio: "pipe" },
      )).toThrow();
    }
  });

  it("recognizes every 32/64-bit thin and fat magic and rejects other files", () => {
    const root = mkdtempSync(join(tmpdir(), "sanctuary-mach-o-scanner-"));
    roots.push(root);
    const magicValues = [
      0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe,
      0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca,
    ];
    for (const [index, magic] of magicValues.entries()) {
      const bytes = Buffer.alloc(8);
      bytes.writeUInt32BE(magic);
      writeFileSync(join(root, `mach-o-${index}`), bytes);
    }
    writeFileSync(join(root, "not-mach-o"), Buffer.from("plain text"));

    const output = execFileSync(process.execPath, [scanner, root], { encoding: "utf8" });
    const found = output.split("\0").filter(Boolean).map((path) => basename(path)).sort();
    expect(found).toEqual(magicValues.map((_, index) => `mach-o-${index}`).sort());
  });

  it("inventories nested installed-package roots without package-internal JSON", () => {
    const root = mkdtempSync(join(tmpdir(), "sanctuary-runtime-inventory-"));
    roots.push(root);
    const contents = join(root, "Sanctuary-CastleWall.app", "Contents");
    const paths = [
      "MacOS/sanctuary",
      "Resources/boot-runtime/node",
      "Resources/cli-runtime/dist/cli.js",
      "Resources/cli-runtime/package.json",
      "Resources/cli-runtime/node_modules/a/package.json",
      "Resources/cli-runtime/node_modules/a/node_modules/@scope/b/package.json",
      "Resources/cli-runtime/node_modules/a/fixtures/package.json",
      "Resources/cli-runtime/node_modules/a/addon.bin",
    ];
    for (const path of paths) mkdirSync(join(contents, path, ".."), { recursive: true });
    writeFileSync(join(contents, "MacOS/sanctuary"), "launcher");
    const node = join(contents, "Resources/boot-runtime/node");
    writeFileSync(node, "#!/bin/sh\necho v22.0.0\n");
    chmodSync(node, 0o755);
    writeFileSync(join(contents, "Resources/cli-runtime/dist/cli.js"), "cli");
    writeFileSync(join(contents, "Resources/cli-runtime/package.json"), JSON.stringify({ name: "cli", version: "1" }));
    writeFileSync(join(contents, "Resources/cli-runtime/node_modules/a/package.json"), JSON.stringify({ name: "a", version: "1" }));
    writeFileSync(join(contents, "Resources/cli-runtime/node_modules/a/node_modules/@scope/b/package.json"), JSON.stringify({ name: "@scope/b", version: "2" }));
    writeFileSync(join(contents, "Resources/cli-runtime/node_modules/a/fixtures/package.json"), JSON.stringify({ name: "fixture", version: "0" }));
    writeFileSync(join(contents, "Resources/cli-runtime/node_modules/a/addon.bin"), "native");
    const inventory = join(root, "mach-o.txt");
    writeFileSync(inventory, "Resources/cli-runtime/node_modules/a/addon.bin\n");

    execFileSync(process.execPath, [
      manifestBuilder,
      join(root, "Sanctuary-CastleWall.app"),
      "a".repeat(40),
      "1.0.0",
    ], { env: { ...process.env, SANCTUARY_MACH_O_INVENTORY_FILE: inventory } });
    const manifest = JSON.parse(readFileSync(
      join(contents, "Resources/cli-runtime-manifest.json"),
      "utf8",
    )) as { inventory: {
      package_count: number;
      package_json_count: number;
      package_internal_json_count: number;
      nested_package_count: number;
      packages: Array<{ path: string }>;
    } };
    expect(manifest.inventory.package_count).toBe(3);
    expect(manifest.inventory.package_json_count).toBe(4);
    expect(manifest.inventory.package_internal_json_count).toBe(1);
    expect(manifest.inventory.nested_package_count).toBe(1);
    expect(manifest.inventory.packages.map((entry) => entry.path)).toEqual([
      "Resources/cli-runtime/node_modules/a/node_modules/@scope/b/package.json",
      "Resources/cli-runtime/node_modules/a/package.json",
      "Resources/cli-runtime/package.json",
    ]);
  });
});
