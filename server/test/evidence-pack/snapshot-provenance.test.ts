// fail-before-exempt: The rows this change adds witness the candidate build script under server/scripts, which this gate does not revert, so they pass on the reverted source by design; each is killed instead by a recorded single-predicate mutant of that script.
import { describe, it, expect, beforeAll, vi } from "vitest";
import { readFileSync, writeFileSync, mkdtempSync, realpathSync, readdirSync, lstatSync } from "node:fs";
import { join, dirname } from "node:path";
import os, { tmpdir } from "node:os";
import { syncBuiltinESMExports } from "node:module";
import { spawnSync, execFileSync } from "node:child_process";
// @ts-expect-error The build script is JavaScript and intentionally has no declaration artifact.
import { validateSource, digest, candidateForTests, NON_RELEASE_MARKER, NON_RELEASE_TEXT } from "../../scripts/build-evidence-pack.mjs";
const SOURCE = execFileSync("/usr/bin/git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const archive = Buffer.from("synthetic source archive");
// Must match the source and installed build record schemas in scripts/build-evidence-pack.mjs.
const metadata = { format: "SANCTUARY_RELEASE_SOURCE_V1", source_revision: SOURCE, source_archive_sha256: digest(archive) };
describe("candidate provenance input boundary", () => {
  it("accepts full matching git and archive provenance", () => { expect(validateSource(metadata, archive, SOURCE, SOURCE)).toEqual(metadata); });
  it.each(["short", "uppercase", "head", "env", "archive", "extra", "missing"])("refuses %s provenance", kind => {
    const m = { ...metadata }; if (kind === "short") m.source_revision = SOURCE.slice(0, 8); if (kind === "uppercase") m.source_revision = SOURCE.toUpperCase(); if (kind === "extra") Object.assign(m, { extra: true }); if (kind === "missing") delete (m as Partial<typeof m>).source_archive_sha256;
    expect(() => validateSource(m, kind === "archive" ? Buffer.from("other") : archive, kind === "short" ? m.source_revision : kind === "env" ? "a".repeat(40) : SOURCE, kind === "short" ? m.source_revision : kind === "head" ? "b".repeat(40) : SOURCE)).toThrow("Source provenance refused");
  });
  it("build command refuses an eight-hex input before bundling", () => { const root = mkdtempSync(join(tmpdir(), "provenance-")); const m = join(root, "source.json"), a = join(root, "archive"); writeFileSync(m, JSON.stringify({ ...metadata, source_revision: SOURCE.slice(0, 8) })); writeFileSync(a, archive); const r = spawnSync(process.execPath, ["scripts/build-evidence-pack.mjs", "--source-metadata", m, "--source-archive", a], { encoding: "utf8" }); expect(r.status).toBe(1); expect(r.stderr).toContain("Source provenance refused"); });
});
describe("installed immutable version", () => {
  let c: Awaited<ReturnType<typeof candidateForTests>>;
  beforeAll(async () => { c = await candidateForTests(); }, 120_000);
  it("runtime environment cannot replace the baked revision", () => { const r = spawnSync(process.execPath, [c.command, "--version"], { env: { ...process.env, SANCTUARY_SOURCE_SHA: "e".repeat(40) }, encoding: "utf8" }); expect(r.status).toBe(0); expect(r.stdout).toBe(`verify-evidence-pack 0.1.0 source_revision=${SOURCE}\n`); });
  it("provenance hashes the final bundle and marks fixture builds non-release", () => { const p = JSON.parse(readFileSync(join(dirname(realpathSync(c.command)), "provenance.json"), "utf8")); expect(Object.keys(p).sort()).toEqual(["format", "package_version", "source_revision", "source_archive_sha256", "verifier_sha256", "dependency_lock_sha256"].sort()); expect(p).toMatchObject({ format: "SANCTUARY_VERIFIER_BUILD_V1", package_version: "0.1.0", source_revision: SOURCE, source_archive_sha256: digest(readFileSync(c.archive)), verifier_sha256: digest(readFileSync(c.command)), dependency_lock_sha256: digest(readFileSync(join(c.tree, "server/package-lock.json"))) }); if (c.fixture) { expect(c.non_release).toBe(true); expect(readFileSync(join(c.root, "NON_RELEASE_FIXTURE"), "utf8")).toContain("not release authentication"); } });
  // Must match NON_RELEASE_MARKER written by buildCandidate in scripts/build-evidence-pack.mjs.
  it("fixture tarball carries its non-release marker into the installed package", () => {
    if (!c.fixture) return;
    expect(c.packed.files.map((f: { path: string }) => f.path)).toContain("dist/" + NON_RELEASE_MARKER);
    expect(execFileSync("tar", ["-xzOf", c.tarball, "package/dist/" + NON_RELEASE_MARKER], { encoding: "utf8" })).toBe(NON_RELEASE_TEXT);
    expect(readFileSync(join(dirname(realpathSync(c.command)), NON_RELEASE_MARKER), "utf8")).toBe(NON_RELEASE_TEXT);
  });
});

// @ts-expect-error The build script is JavaScript and intentionally has no declaration artifact.
import { extractSourceArchive, prepareFixtureCandidate, buildCandidate } from "../../scripts/build-evidence-pack.mjs";
import { mkdirSync, existsSync, renameSync, symlinkSync, unlinkSync, rmdirSync } from "node:fs";
it.each([SOURCE, undefined])("release provenance still refuses a missing explicit revision with head %s", head => { expect(() => validateSource(metadata, archive, undefined, head)).toThrow("Source provenance refused"); });
it.each(["symlink", "hardlink", "fifo"])("source archive refuses nonregular member %s before extraction", kind => {
  const root = mkdtempSync(join(tmpdir(), "archive-members-")), archive = join(root, "source.tar"), target = join(root, "staged"); mkdirSync(target);
  execFileSync("/usr/bin/python3", ["-I", "-S", "-c", `import tarfile,sys,io
with tarfile.open(sys.argv[1], 'w') as archive:
    safe=tarfile.TarInfo('safe'); safe.size=1; archive.addfile(safe,io.BytesIO(b'x'))
    member=tarfile.TarInfo('member'); member.type={'symlink':tarfile.SYMTYPE,'hardlink':tarfile.LNKTYPE,'fifo':tarfile.FIFOTYPE}[sys.argv[2]]; member.linkname='safe'; archive.addfile(member)
`, archive, kind]);
  expect(() => extractSourceArchive(archive, target)).toThrow(); expect(existsSync(join(target, "safe"))).toBe(false);
});
it("source archive admits only regular files and directories", () => {
  const root = mkdtempSync(join(tmpdir(), "archive-positive-")), source = join(root, "source"), target = join(root, "staged"), archive = join(root, "source.tar"); mkdirSync(source); mkdirSync(target); writeFileSync(join(source, "file"), "exact bytes"); execFileSync("tar", ["-cf", archive, "-C", source, "."]);
  extractSourceArchive(archive, target); expect(readFileSync(join(target, "file"), "utf8")).toBe("exact bytes");
});
// Must match the in-place output replacement in scripts/build-evidence-pack.mjs.
it.each(["packages/evidence-pack-verifier/dist", "server/evidence-pack-dist"])("rebuild clears stale files in place in %s", async output => {
  const c = await prepareFixtureCandidate(), destination = join(c.tree, output);
  const before = lstatSync(destination, { bigint: true });
  writeFileSync(join(destination, "stale.js"), "stale");
  await buildCandidate(["--source-metadata", c.metadata, "--source-archive", c.archive], c.tree, SOURCE);
  expect(existsSync(join(destination, "stale.js"))).toBe(false);
  expect(lstatSync(destination, { bigint: true }).ino).toBe(before.ino);
  expect(lstatSync(destination, { bigint: true }).dev).toBe(before.dev);
}, 120_000);
// Must match the staging parent read through os.tmpdir() in buildCandidate in scripts/build-evidence-pack.mjs.
async function entryProvenance(kind: "deleted" | "mismatched" | "matching") {
  const root = mkdtempSync(join(tmpdir(), "entry-provenance-")), tree = join(root, "tree"), staging = join(root, "staging");
  mkdirSync(tree); mkdirSync(staging);
  const source = join(root, "source"); mkdirSync(source); writeFileSync(join(source, "sentinel"), "must not be staged");
  const a = join(root, "source.tar"), m = join(root, "source.json");
  execFileSync("tar", ["-cf", a, "-C", source, "."]);
  writeFileSync(m, JSON.stringify({ ...metadata, source_archive_sha256: digest(readFileSync(a)) }));
  expect(existsSync(join(tree, ".git"))).toBe(false);
  vi.stubEnv("SANCTUARY_SOURCE_SHA", kind === "deleted" ? undefined : kind === "matching" ? SOURCE : (SOURCE[0] === "a" ? "b" : "a").repeat(SOURCE.length));
  // The staging parent is injected on the builtin itself, so the build script's named import sees it whatever the worker pool does with the environment.
  const parent = vi.spyOn(os, "tmpdir").mockReturnValue(staging); syncBuiltinESMExports();
  try {
    // The injection is proven before it is relied on, so an unredirected staging parent fails here instead of leaving the empty-staging check vacuous.
    expect(tmpdir()).toBe(staging);
    // The omitted revision argument exercises the release entry's ambient input before any archive byte is staged.
    const outcome = await buildCandidate(["--source-metadata", m, "--source-archive", a], tree).then(() => "built", (error: Error) => error.message);
    return { outcome, staged: readdirSync(staging).map(name => name.replace(/-[^-]+$/, "")).sort(), tree: readdirSync(tree) };
  } finally { parent.mockRestore(); syncBuiltinESMExports(); vi.unstubAllEnvs(); }
}
it.each(["deleted", "mismatched"] as const)("buildCandidate entry refuses %s environment revision before staging a file", async kind => {
  expect(await entryProvenance(kind)).toEqual({ outcome: "Source provenance refused", staged: [], tree: [] });
});
it("buildCandidate entry positive control stages the same fixture once the environment revision matches", async () => {
  // The same fixture without the revision fault passes provenance and reaches the injected staging parent, so the refusal rows cannot be always-failing.
  const { outcome, staged, tree } = await entryProvenance("matching");
  expect(outcome).not.toContain("Source provenance refused"); expect(staged).toEqual(["pack-archive", "pack-source"]); expect(tree).toEqual([]);
});

// Must match OUTPUT_DIRECTORIES and outputEntries in scripts/build-evidence-pack.mjs.
const OUTPUTS = ["packages/evidence-pack-verifier/dist", "server/evidence-pack-dist"];
describe("rebuild output paths are all checked before either is cleared", () => {
  let c: Awaited<ReturnType<typeof prepareFixtureCandidate>>;
  beforeAll(async () => { c = await prepareFixtureCandidate(); }, 120_000);
  it.each(OUTPUTS.flatMap(output => ["symlink", "file", ...(output === OUTPUTS[1] ? ["subdirectory"] : [])].map(kind => [kind, output])))("rebuild refuses a %s at %s before any removal", async (kind, output) => {
    const destination = join(c.tree, output), aside = destination + ".aside", other = join(c.tree, OUTPUTS.find(path => path !== output)!);
    const listing = (path: string) => readdirSync(path).sort();
    const otherBefore = listing(other); writeFileSync(join(other, "stale.js"), "stale");
    if (kind === "symlink") { renameSync(destination, aside); writeFileSync(join(aside, "stale.js"), "stale"); symlinkSync(aside, destination, "dir"); }
    if (kind === "file") { renameSync(destination, aside); writeFileSync(destination, "not a directory"); }
    if (kind === "subdirectory") mkdirSync(join(destination, "nested"));
    const faultedBefore = kind === "file" ? listing(aside) : listing(destination);
    try {
      await expect(buildCandidate(["--source-metadata", c.metadata, "--source-archive", c.archive], c.tree, SOURCE)).rejects.toThrow(kind === "subdirectory" ? "Unexpected output directory" : "Unexpected output path");
      // Nothing is removed from either output, including the tree a link points at, when any output path is refused.
      expect(listing(other)).toEqual([...otherBefore, "stale.js"].sort());
      expect(kind === "file" ? listing(aside) : listing(destination)).toEqual(faultedBefore);
    } finally {
      unlinkSync(join(other, "stale.js"));
      if (kind === "symlink") { unlinkSync(destination); unlinkSync(join(aside, "stale.js")); renameSync(aside, destination); }
      if (kind === "file") { unlinkSync(destination); renameSync(aside, destination); }
      if (kind === "subdirectory") rmdirSync(join(destination, "nested"));
    }
    expect(listing(other)).toEqual(otherBefore);
  }, 120_000);
});
