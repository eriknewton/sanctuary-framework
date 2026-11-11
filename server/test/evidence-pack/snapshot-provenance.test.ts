// fail-before-exempt: These rows exercise the candidate build script under server/scripts, which this gate does not revert; script mutation checks and unchanged-input controls cover the defended boundaries.
import { describe, it, expect, beforeAll, vi } from "vitest";
import { readFileSync, writeFileSync, mkdtempSync, realpathSync, readdirSync, lstatSync } from "node:fs";
import { join, dirname } from "node:path";
import os, { tmpdir } from "node:os";
import { syncBuiltinESMExports } from "node:module";
import { spawnSync, execFileSync } from "node:child_process";
// @ts-expect-error The build script is JavaScript and intentionally has no declaration artifact.
import { validateSource, digest, candidateForTests, NON_RELEASE_MARKER, NON_RELEASE_TEXT } from "../../scripts/build-evidence-pack.mjs";
const SOURCE = execFileSync("/usr/bin/git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const tempParent = mkdtempSync(join(tmpdir(), "provenance-witness-"));
const scratch = (prefix: string) => mkdtempSync(join(tempParent, prefix));
let artifactNumber = 0;
const artifactArgs = (metadata: string, archive: string, fixture = false) => ["--source-metadata", metadata, "--source-archive", archive, "--artifact-dir", join(tempParent, `artifact-${artifactNumber++}`), "--artifact-mode", fixture ? "fixture" : "release"];
const archive = Buffer.from("synthetic source archive");
// Must match the source and installed build record schemas in scripts/build-evidence-pack.mjs.
const metadata = { format: "SANCTUARY_RELEASE_SOURCE_V1", source_revision: SOURCE, source_archive_sha256: digest(archive) };
describe("candidate provenance input boundary", () => {
  it("accepts full matching git and archive provenance", () => { expect(validateSource(metadata, archive, SOURCE, SOURCE)).toEqual(metadata); });
  it.each(["short", "uppercase", "head", "env", "archive", "extra", "missing"])("refuses %s provenance", kind => {
    const m = { ...metadata }; if (kind === "short") m.source_revision = SOURCE.slice(0, 8); if (kind === "uppercase") m.source_revision = SOURCE.toUpperCase(); if (kind === "extra") Object.assign(m, { extra: true }); if (kind === "missing") delete (m as Partial<typeof m>).source_archive_sha256;
    expect(() => validateSource(m, kind === "archive" ? Buffer.from("other") : archive, kind === "short" ? m.source_revision : kind === "env" ? "a".repeat(40) : SOURCE, kind === "short" ? m.source_revision : kind === "head" ? "b".repeat(40) : SOURCE)).toThrow("Source provenance refused");
  });
  it("build command refuses an eight-hex input before bundling", () => { const root = scratch("provenance-"); const m = join(root, "source.json"), a = join(root, "archive"); writeFileSync(m, JSON.stringify({ ...metadata, source_revision: SOURCE.slice(0, 8) })); writeFileSync(a, archive); const r = spawnSync(process.execPath, ["scripts/build-evidence-pack.mjs", "--source-metadata", m, "--source-archive", a, "--artifact-dir", join(root, "artifact"), "--artifact-mode", "release"], { encoding: "utf8" }); expect(r.status).toBe(1); expect(r.stderr).toContain("Source provenance refused"); });
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
import { mkdirSync, existsSync, renameSync, symlinkSync, cpSync, unlinkSync } from "node:fs";
it.each([SOURCE, undefined])("release provenance still refuses a missing explicit revision with head %s", head => { expect(() => validateSource(metadata, archive, undefined, head)).toThrow("Source provenance refused"); });
it.each(["symlink", "hardlink", "fifo"])("source archive refuses nonregular member %s before extraction", kind => {
  const root = scratch("archive-members-"), archive = join(root, "source.tar"), target = join(root, "staged"); mkdirSync(target);
  execFileSync("/usr/bin/python3", ["-I", "-S", "-c", `import tarfile,sys,io
with tarfile.open(sys.argv[1], 'w') as archive:
    safe=tarfile.TarInfo('safe'); safe.size=1; archive.addfile(safe,io.BytesIO(b'x'))
    member=tarfile.TarInfo('member'); member.type={'symlink':tarfile.SYMTYPE,'hardlink':tarfile.LNKTYPE,'fifo':tarfile.FIFOTYPE}[sys.argv[2]]; member.linkname='safe'; archive.addfile(member)
`, archive, kind]);
  expect(() => extractSourceArchive(archive, target)).toThrow(); expect(existsSync(join(target, "safe"))).toBe(false);
});
it("source archive admits only regular files and directories", () => {
  const root = scratch("archive-positive-"), source = join(root, "source"), target = join(root, "staged"), archive = join(root, "source.tar"); mkdirSync(source); mkdirSync(target); writeFileSync(join(source, "file"), "exact bytes"); execFileSync("tar", ["-cf", archive, "-C", source, "."]);
  extractSourceArchive(archive, target); expect(readFileSync(join(target, "file"), "utf8")).toBe("exact bytes");
});
// Must match the in-place output replacement in scripts/build-evidence-pack.mjs.
it.each(["packages/evidence-pack-verifier/dist", "server/evidence-pack-dist"])("rebuild clears stale files in place in %s", async output => {
  const c = await prepareFixtureCandidate(), destination = join(c.tree, output);
  const before = lstatSync(destination, { bigint: true });
  writeFileSync(join(destination, "stale.js"), "stale");
  await buildCandidate(artifactArgs(c.metadata, c.archive), c.tree, SOURCE);
  expect(existsSync(join(destination, "stale.js"))).toBe(false);
  expect(lstatSync(destination, { bigint: true }).ino).toBe(before.ino);
  expect(lstatSync(destination, { bigint: true }).dev).toBe(before.dev);
}, 120_000);
// Must match the staging parent read through os.tmpdir() in buildCandidate in scripts/build-evidence-pack.mjs.
async function entryProvenance(kind: "deleted" | "mismatched" | "matching") {
  const root = scratch("entry-provenance-"), tree = join(root, "tree"), staging = join(root, "staging");
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
    const outcome = await buildCandidate(["--source-metadata", m, "--source-archive", a, "--artifact-dir", join(root, "artifact"), "--artifact-mode", "release"], tree).then(() => "built", (error: Error) => error.message);
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

// Must match OUTPUT_DIRECTORIES and checkOutput in scripts/build-evidence-pack.mjs.
const OUTPUTS = ["packages/evidence-pack-verifier/dist", "server/evidence-pack-dist"];
describe("rebuild output paths are all checked before either is cleared", () => {
  let c: Awaited<ReturnType<typeof prepareFixtureCandidate>>;
  beforeAll(async () => { c = await prepareFixtureCandidate(); }, 120_000);
  // Each row builds into its own minimal root holding copies of the fixture outputs, so a row that removes files cannot disturb another.
  function outputRoot(): string {
    const root = scratch("output-paths-"); mkdirSync(join(root, "server"));
    symlinkSync(join(c.tree, "server/node_modules"), join(root, "server/node_modules"), "dir");
    cpSync(join(c.tree, "server/package-lock.json"), join(root, "server/package-lock.json"));
    for (const output of OUTPUTS) cpSync(join(c.tree, output), join(root, output), { recursive: true });
    return root;
  }
  it.each(OUTPUTS.flatMap(output => ["symlink", "file", ...(output === OUTPUTS[1] ? ["subdirectory"] : [])].map(kind => [kind, output])))("rebuild refuses a %s at %s before any removal", async (kind, output) => {
    const root = outputRoot(), destination = join(root, output), aside = destination + ".aside", other = join(root, OUTPUTS.find(path => path !== output)!);
    const listing = (path: string) => readdirSync(path).sort();
    writeFileSync(join(other, "stale.js"), "stale"); const otherBefore = listing(other);
    if (kind === "symlink") { renameSync(destination, aside); writeFileSync(join(aside, "stale.js"), "stale"); symlinkSync(aside, destination, "dir"); }
    if (kind === "file") { renameSync(destination, aside); writeFileSync(destination, "not a directory"); }
    if (kind === "subdirectory") mkdirSync(join(destination, "nested"));
    const faulted = kind === "file" ? aside : destination, faultedBefore = listing(faulted);
    await expect(buildCandidate(artifactArgs(c.metadata, c.archive), root, SOURCE)).rejects.toThrow(kind === "subdirectory" ? "Unexpected output directory" : "Unexpected output path");
    // Nothing is removed from either output, including the tree a link points at, when any output path is refused.
    expect(listing(other)).toEqual(otherBefore);
    expect(listing(faulted)).toEqual(faultedBefore);
    expect(lstatSync(destination).isSymbolicLink()).toBe(kind === "symlink");
  }, 120_000);
  const build = (root: string, options: { nonRelease?: boolean; outputsChecked?: (paths: string[]) => void; beforeCopy?: (path: string) => void; afterCopy?: (path: string) => void; beforeHash?: (path: string) => void } = {}) => { const { nonRelease = false, ...faults } = options; return buildCandidate(artifactArgs(c.metadata, c.archive, nonRelease), root, SOURCE, faults); };
  const listing = (path: string) => existsSync(path) ? readdirSync(path).sort() : null;
  // Must match the output-chain walk in checkOutput in scripts/build-evidence-pack.mjs: each ancestor here lies on one output chain.
  const ANCESTORS = [["packages", OUTPUTS[0]], ["packages/evidence-pack-verifier", OUTPUTS[0]], ["server", OUTPUTS[1]]] as const;
  it.each(ANCESTORS.flatMap(([ancestor, output]) => (["existing", "missing"] as const).map(final => [ancestor, final, output] as const)))("rebuild refuses a linked ancestor %s with the final directory %s at %s and changes neither output", async (ancestor, final, output) => {
    const root = outputRoot(), other = join(root, OUTPUTS.find(path => path !== output)!), linked = join(root, ancestor), aside = linked + ".aside";
    for (const path of OUTPUTS) writeFileSync(join(root, path, "stale.js"), "stale");
    renameSync(linked, aside); symlinkSync(aside, linked, "dir");
    // The real directory behind the link is where a clear or copy through the link would land.
    const behind = join(aside, output.slice(ancestor.length + 1));
    if (final === "missing") renameSync(behind, behind + ".moved");
    const before = { other: listing(other), behind: listing(behind) };
    await expect(build(root)).rejects.toThrow("Unexpected output path");
    // Nothing is removed from either output and nothing is created through the link.
    expect({ other: listing(other), behind: listing(behind) }).toEqual(before);
    expect(lstatSync(linked).isSymbolicLink()).toBe(true);
  }, 120_000);
  it.each([...OUTPUTS.flatMap(output => (["directory", "symlink"] as const).map(kind => [kind, output] as const)), ["ancestor", OUTPUTS[1]] as const])("rebuild refuses %s replacement at %s between the check and the first removal", async (kind, output) => {
    const root = outputRoot(), destination = join(root, output), original = destination + ".original", other = join(root, OUTPUTS.find(path => path !== output)!);
    for (const path of OUTPUTS) writeFileSync(join(root, path, "stale.js"), "stale");
    const expected = { destination: listing(destination), other: listing(other) };
    let replaced = 0;
    // The replacement keeps every name in place, so only the held directory identity distinguishes it from the checked output.
    const outputsChecked = () => {
      replaced += 1;
      if (kind === "directory") { renameSync(destination, original); cpSync(original, destination, { recursive: true }); }
      if (kind === "symlink") { renameSync(destination, original); symlinkSync(original, destination, "dir"); }
      if (kind === "ancestor") { const server = join(root, "server"); renameSync(server, server + ".original"); symlinkSync(server + ".original", server, "dir"); }
    };
    await expect(build(root, { outputsChecked })).rejects.toThrow("Output path changed");
    expect(replaced).toBe(1);
    expect({ destination: listing(destination), other: listing(other) }).toEqual(expected);
    if (kind !== "ancestor") expect(listing(original)).toEqual(expected.destination);
  }, 120_000);
  it("rebuild identity recheck admits unchanged outputs after the seam runs", async () => {
    const root = outputRoot(), seen: string[][] = [];
    for (const path of OUTPUTS) writeFileSync(join(root, path, "stale.js"), "stale");
    // The seam runs once with both checked destinations and an unchanged tree still rebuilds, so the identity rows cannot be always-failing.
    await build(root, { outputsChecked: (destinations: string[]) => seen.push(destinations) });
    expect(seen).toEqual([OUTPUTS.map(path => join(realpathSync(root), path))]);
    for (const path of OUTPUTS) expect(existsSync(join(root, path, "stale.js"))).toBe(false);
  }, 120_000);
  // Must match verifyPublished, changedSince and the failure bound in scripts/build-evidence-pack.mjs: a refused build deletes nothing.
  const RELEASE_DIST = ["check-evidence-pack-artifact.js", "provenance.json", "verify-evidence-pack.js"];
  const published = (output: string) => output === OUTPUTS[0] ? RELEASE_DIST : listing(join(c.tree, output))!;
  const otherThan = (output: string) => OUTPUTS.find(path => path !== output)!;
  // A fault fires only at its own output and counts its calls, so every refusal row proves its fault was reached exactly once.
  function at(output: string, fault: (destination: string) => void) {
    let calls = 0;
    return { seam: (destination: string) => { if (destination.endsWith("/" + output)) { calls += 1; fault(destination); } }, calls: () => calls };
  }
  it.each([[OUTPUTS[0], "Output path changed"], [OUTPUTS[1], "Published output refused: output identity changed"]] as const)("rebuild refuses an output directory replaced at %s between the final recheck and the copy", async (output, refusal) => {
    const root = outputRoot(), destination = join(root, output);
    const fault = at(output, path => { renameSync(path, path + ".original"); mkdirSync(path); writeFileSync(join(path, "unlisted.js"), "planted"); });
    await expect(build(root, { beforeCopy: fault.seam })).rejects.toThrow(refusal);
    expect(fault.calls()).toBe(1);
    // Whichever check catches the replacement, the copy that landed in it and the planted entry both stay.
    expect(listing(destination)).toEqual([...published(output), "unlisted.js"].sort());
  }, 120_000);
  it.each((["beforeCopy", "afterCopy"] as const).flatMap(stage => OUTPUTS.map(output => [stage, output] as const)))("rebuild refuses an entry added at %s to %s and keeps every file", async (stage, output) => {
    const root = outputRoot(), fault = at(output, path => writeFileSync(join(path, "unlisted.js"), "planted"));
    await expect(build(root, { [stage]: fault.seam })).rejects.toThrow(`Published output refused: unexpected entry in ${output}; the destination is not trusted`);
    expect(fault.calls()).toBe(1);
    expect({ output: listing(join(root, output)), other: listing(join(root, otherThan(output))) }).toEqual({ output: [...published(output), "unlisted.js"].sort(), other: published(otherThan(output)) });
  }, 120_000);
  it("rebuild refuses a published file whose bytes change after the copy while its size stays the same", async () => {
    const root = outputRoot(), file = join(root, OUTPUTS[0], "verify-evidence-pack.js");
    let tampered = Buffer.alloc(0);
    const fault = at(OUTPUTS[0], () => { tampered = readFileSync(file); tampered[tampered.length - 1] ^= 1; writeFileSync(file, tampered); });
    await expect(build(root, { afterCopy: fault.seam })).rejects.toThrow(`Published output refused: content changed in ${OUTPUTS[0]}`);
    expect(fault.calls()).toBe(1);
    expect(OUTPUTS.map(path => listing(join(root, path)))).toEqual(OUTPUTS.map(published));
    expect(readFileSync(file).equals(tampered)).toBe(true);
  }, 120_000);
  it("release rebuild refuses a non-release marker planted in an output before the copy", async () => {
    const root = outputRoot(), fault = at(OUTPUTS[1], path => writeFileSync(join(path, NON_RELEASE_MARKER), NON_RELEASE_TEXT));
    await expect(build(root, { beforeCopy: fault.seam })).rejects.toThrow(`Published output refused: non-release marker in ${OUTPUTS[1]}`);
    expect(fault.calls()).toBe(1);
    expect(OUTPUTS.map(path => listing(join(root, path)))).toEqual([RELEASE_DIST, [...published(OUTPUTS[1]), NON_RELEASE_MARKER].sort()]);
  }, 120_000);
  // A file at a staged name is not proof the build wrote it, so neither schedule below may delete the foreign file it plants.
  it("rebuild refuses a directory of foreign files swapped in after the last copy and deletes none of them", async () => {
    const root = outputRoot(), destination = join(root, OUTPUTS[1]), aside = destination + ".published";
    const fault = at(OUTPUTS[1], path => { renameSync(path, aside); mkdirSync(path); writeFileSync(join(path, "export-evidence-pack.js"), "foreign"); writeFileSync(join(path, "unlisted.js"), "foreign"); });
    await expect(build(root, { afterCopy: fault.seam })).rejects.toThrow("Published output refused: output identity changed");
    expect(fault.calls()).toBe(1);
    expect({ swapped: listing(destination), aside: listing(aside), first: listing(join(root, OUTPUTS[0])) }).toEqual({ swapped: ["export-evidence-pack.js", "unlisted.js"], aside: published(OUTPUTS[1]), first: RELEASE_DIST });
    for (const name of ["export-evidence-pack.js", "unlisted.js"]) expect(readFileSync(join(destination, name), "utf8")).toBe("foreign");
  }, 120_000);
  it("rebuild refuses a published file replaced by a foreign inode after the last copy and keeps the foreign file", async () => {
    const root = outputRoot(), file = join(root, OUTPUTS[1], "export-evidence-pack.js");
    const fault = at(OUTPUTS[1], () => { unlinkSync(file); writeFileSync(file, "foreign"); });
    await expect(build(root, { afterCopy: fault.seam })).rejects.toThrow(`Published output refused: content changed in ${OUTPUTS[1]}`);
    expect(fault.calls()).toBe(1);
    expect(readFileSync(file, "utf8")).toBe("foreign");
    expect(OUTPUTS.map(path => listing(join(root, path)))).toEqual(OUTPUTS.map(published));
  }, 120_000);
  // Must match the beforeHash seam and the second verification pass in scripts/build-evidence-pack.mjs.
  it("release rebuild refuses a non-release marker created during verification just before the bundle is hashed", async () => {
    const root = outputRoot();
    let faults = 0;
    const beforeHash = (path: string) => { if (path.endsWith(`/${OUTPUTS[0]}/verify-evidence-pack.js`)) { faults += 1; writeFileSync(join(dirname(path), NON_RELEASE_MARKER), NON_RELEASE_TEXT); } };
    await expect(build(root, { beforeHash })).rejects.toThrow(`Published output refused: non-release marker in ${OUTPUTS[0]}`);
    expect(faults).toBe(1);
    expect(listing(join(root, OUTPUTS[0]))).toEqual([NON_RELEASE_MARKER, ...RELEASE_DIST]);
  }, 120_000);
  it("rebuild refuses an output directory replaced by an identical copy during verification before its first file is opened", async () => {
    const root = outputRoot(), first = join(root, OUTPUTS[0]);
    let faults = 0;
    const beforeHash = (path: string) => { if (faults === 0) { faults += 1; const output = dirname(path); renameSync(output, output + ".original"); cpSync(output + ".original", output, { recursive: true }); } };
    await expect(build(root, { beforeHash })).rejects.toThrow("Published output refused: output identity changed");
    expect(faults).toBe(1);
    expect({ copy: listing(first), original: listing(first + ".original") }).toEqual({ copy: RELEASE_DIST, original: RELEASE_DIST });
  }, 120_000);
  it("a refusal after the first output is published leaves that output rebuilt and the second uncleared", async () => {
    const root = outputRoot(), second = join(root, OUTPUTS[1]);
    for (const path of OUTPUTS) writeFileSync(join(root, path, "stale.js"), "stale");
    const before = listing(second);
    // Replacing the second output with a same-named copy after the first is published makes the second output's first recheck refuse.
    const fault = at(OUTPUTS[0], () => { renameSync(second, second + ".original"); cpSync(second + ".original", second, { recursive: true }); });
    await expect(build(root, { afterCopy: fault.seam })).rejects.toThrow("Output path changed");
    expect(fault.calls()).toBe(1);
    // The documented nontransactional outcome: the first output holds the new build, and nothing in the second was removed.
    expect({ first: listing(join(root, OUTPUTS[0])), second: listing(second), original: listing(second + ".original") }).toEqual({ first: RELEASE_DIST, second: before, original: before });
  }, 120_000);
  it.each([false, true])("rebuild with nonRelease %s publishes outputs equal to the staged package when the publication seams change nothing", async nonRelease => {
    const root = outputRoot(), noop = () => undefined;
    for (const path of OUTPUTS) writeFileSync(join(root, path, "stale.js"), "stale");
    // Unchanged-input control: the same seams that refuse above admit an untouched publication, so the refusal rows cannot be always-failing.
    await build(root, { nonRelease, beforeCopy: noop, afterCopy: noop, beforeHash: noop });
    expect(OUTPUTS.map(path => listing(join(root, path)))).toEqual([nonRelease ? [...RELEASE_DIST, NON_RELEASE_MARKER].sort() : RELEASE_DIST, published(OUTPUTS[1])]);
  }, 120_000);
});
