// A1, A18 and A19 fail on a real pre-R1 base build (job 1368 result/base-witness.log).
// A2-A17 and A20 exercise boundaries absent on that base; their evidence is named mutant kills, not fail-before.
// C1/C2 are unchanged-input controls; C4 is a new-feature control.
import { beforeAll, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { readFileSync, writeFileSync, existsSync, readdirSync, lstatSync, symlinkSync, cpSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { gzipSync } from "node:zlib";
import { ARTIFACT_FILES, ARTIFACT_HELP, ARTIFACT_REFUSED, ARTIFACT_USAGE, MAX_ARTIFACT_BYTES, MAX_TAR_BYTES, MAX_MANIFEST_BYTES, registry, memberMode, parseArchive, parseManifest, parseCandidate, parseJson, requireValid, checkArtifact, artifactSuccess, type Parsed } from "../../src/evidence-pack/artifact-policy.mjs";
import { runArtifactCommand } from "../../src/evidence-pack/snapshot-artifact-cli.js";
import { samples, scratch, sample, buildArgs, buildRoot, entries, name, setName, pack, tarBytes, checksum, changed, coherent, retained, pins, installed, parsedRows, malformed, ROOT, type Sample } from "./snapshot-artifact-fixtures.js";
// @ts-expect-error Node build script deliberately has no TypeScript wrapper.
import { buildCandidate, checkDescriptor, checkerArgs, candidateForTests } from "../../scripts/build-evidence-pack.mjs";
let release: Sample, fixture: Sample;
const TIMEOUT = 120_000;
const policy = (s: Sample, tar = s.tar, manifest = s.manifest) => checkArtifact(tar, manifest, pins(s, tar, manifest));
const error = (r: Parsed<unknown>) => r.ok ? "ACCEPTED" : r.error;
function control(s = release) { expect(policy(s).ok).toBe(true); }
function refusal(s: Sample, tar: Buffer, manifest: Buffer = retained(s, tar), expected?: string) {
  const result = policy(s, tar, manifest); expect(result.ok).toBe(false); if (expected) expect(error(result)).toBe(expected);
  const child = installed(s, tar, manifest); expect(child.error).toBeUndefined(); expect(child.status).toBe(1); expect(child.stdout).toBe(""); expect(child.stderr).toBe(ARTIFACT_REFUSED);
}
const script = resolve("scripts/build-evidence-pack.mjs");
const cli = (s: Sample, args: string[]) => spawnSync(process.execPath, [s.checker, ...args], { encoding: "utf8", timeout: 30_000 });
const yaml = createRequire(import.meta.url)("js-yaml") as { load(text: string): { jobs: Record<string, { steps: Array<{ name?: string; run?: string; uses?: string; with?: { path?: string; "if-no-files-found"?: string } }> }> } };
function workflowPlan(text: string) {
  const steps = yaml.load(text).jobs.candidate!.steps;
  expect(text).not.toMatch(/npm\s+pack|\*\.tgz|continue-on-error:|^\s+if:|\|\|\s*true|always\(\)|failure\(\)/m);
  const positions = ["Build candidate", "Check artifact descriptor", "Install packed candidate and record descriptor", "Test packed candidate on Node 22", "Check identical candidate on Node 24", "Recheck artifact before upload"].map(n => steps.findIndex(s => s.name === n));
  expect(positions.every(p => p >= 0)).toBe(true); expect(positions).toEqual([...positions].sort((a, b) => a - b));
  const build = steps[positions[0]!]!.run!;
  expect(build).toMatch(/pull_request\) npm run build:evidence-pack[^\n]+--artifact-mode fixture ;;/);
  expect(build).toMatch(/workflow_dispatch\) npm run build:evidence-pack[^\n]+--artifact-mode release ;;/);
  expect(build).not.toMatch(/--artifact-mode ["'$]/);
  const prArm = build.match(/pull_request\)([^\n]+);;/)![1]!;
  expect([...prArm.matchAll(/--artifact-mode\s+(\S+)/g)].map(match => match[1])).toEqual(["fixture"]);
  const check = "node server/scripts/build-evidence-pack.mjs --check-descriptor /tmp/c13/artifact";
  for (const position of [positions[1]!, positions[4]!, positions[5]!]) expect(steps[position]!.run).toContain(check);
  expect(steps[positions[2]!]!.run).toContain("node server/scripts/build-evidence-pack.mjs --install-candidate /tmp/c13/artifact");
  for (const position of [positions[3]!, positions[4]!]) expect(steps[position]!.run).toContain("test/evidence-pack/snapshot-artifact.test.ts");
  const upload = steps.findIndex(s => s.uses?.startsWith("actions/upload-artifact@")); expect(upload).toBeGreaterThan(positions[5]!);
  expect(steps[upload]!.with!["if-no-files-found"]).toBe("error");
  expect(steps[upload]!.with!.path!.trim().split(/\s+/).sort()).toEqual(["/tmp/c13/artifact/candidate.tgz", "/tmp/c13/artifact/artifact-manifest.json", "/tmp/c13/artifact/candidate.json", "/tmp/c13/artifact/release-source.json", "/tmp/c13/artifact/source.tar", "/tmp/c13/artifact/test-candidate.json", "/tmp/c13/source-ref.json"].sort());
}
describe("packed artifact authority", () => {
  // Memoize two real compiled builds; byte-level faults reuse them. Build schedules compile separately.
  beforeAll(async () => { ({ release, fixture } = await samples()); }, TIMEOUT);
  it("A1 packs once in private staging and checkout changes cannot retarget the receipt", async () => {
    const root = buildRoot(release), dir = join(scratch(), "artifact"); let packed = 0, copied = 0;
    writeFileSync(join(root, "packages/evidence-pack-verifier/dist/verify-evidence-pack.js"), "pre-pack checkout decoy");
    const receipt = await buildCandidate(buildArgs(release, dir, "release"), root, release.receipt.source_revision, {
      packedBytes: (bytes: Buffer, context: { packageRoot: string; packDir: string }) => { packed++; expect(context.packageRoot).not.toContain(root); expect(context.packageRoot).toContain("pack-source-"); expect(readdirSync(context.packDir)).toHaveLength(1); return bytes; },
      copiesObserved: (paths: string[]) => { copied++; writeFileSync(join(paths[0]!, "verify-evidence-pack.js"), "checkout replacement"); writeFileSync(join(paths[0]!, "NON_RELEASE"), "foreign"); },
    });
    expect(packed).toBe(1); expect(copied).toBe(1); expect(receipt).toEqual(checkDescriptor(dir).receipt);
    const accepted = sample(dir, release.checker, root, release.archive, release.metadata, release.command);
    expect(parsedRows(accepted).map(row => row.path)).toEqual(registry("release")); expect(installed(accepted).status).toBe(0);
    expect(readFileSync(join(root, "packages/evidence-pack-verifier/dist/verify-evidence-pack.js"), "utf8")).toBe("checkout replacement"); control();
  }, TIMEOUT);
  it("A2 refuses changed packed payload against pre-pack digests before READY", async () => {
    const root = buildRoot(release), dir = join(scratch(), "artifact"); let faults = 0;
    await expect(buildCandidate(buildArgs(release, dir, "release"), root, release.receipt.source_revision, { packedBytes: (bytes: Buffer) => {
      faults++; const rows = entries(bytes), row = rows.find(r => name(r) === "package/README.md")!; row.bytes[0] ^= 1; return pack(rows);
    } })).rejects.toThrow("member hashes"); expect(faults).toBe(1); expect(existsSync(join(dir, ARTIFACT_FILES.receipt))).toBe(false); control();
  }, TIMEOUT);
  it("A3 compares every staged member including package metadata and both bins", () => {
    for (const path of registry("release")) { const tar = changed(release, rows => { const row = rows.find(r => name(r) === path)!; row.bytes = Buffer.concat([row.bytes, Buffer.from(" ")]); }); refusal(release, tar, retained(release, tar), "member hashes"); } control();
  });
  it("A4 requires the full member set with no addition or omission", () => {
    for (const path of registry("release")) { const tar = pack(entries(release.tar).filter(row => name(row) !== path)); expect(error(parseArchive(tar, "release"))).toBe("archive registry"); refusal(release, tar); }
    const tar = changed(release, rows => { const extra = { header: Buffer.from(rows[0]!.header), bytes: Buffer.from("extra") }; setName(extra, "package/extra"); rows.push(extra); });
    expect(error(parseArchive(tar, "release"))).toBe("archive registry"); refusal(release, tar); control();
  });
  it("A5 refuses release markers with coherent attacker-supplied rows", () => {
    for (const path of ["package/dist/NON_RELEASE", "package/dist/nested/NON_RELEASE", "package/NON_RELEASE/file"]) {
      const tar = changed(release, rows => { const row = { header: Buffer.from(rows[0]!.header), bytes: Buffer.from("marker") }; setName(row, path); rows.push(row); });
      expect(error(parseArchive(tar, "release"))).toBe("release marker"); refusal(release, tar, coherent(release, tar));
    } control();
  });
  it("A6 fixture policy requires the canonical marker bytes and path", () => {
    for (const fault of ["absent", "bytes", "relocated"]) {
      const rows = entries(fixture.tar), index = rows.findIndex(row => name(row).endsWith("/NON_RELEASE"));
      if (fault === "absent") rows.splice(index, 1); else if (fault === "bytes") rows[index]!.bytes = Buffer.from("wrong marker\n"); else setName(rows[index]!, "package/dist/other");
      const tar = pack(rows); expect(error(parseArchive(tar, "fixture"))).toBe(fault === "bytes" ? "fixture marker" : "archive registry"); refusal(fixture, tar, coherent(fixture, tar));
    } control(fixture); expect(installed(fixture).stdout).toBe(artifactSuccess("fixture"));
  });
  it("A7 rejects duplicate headers before a map can hide them", () => {
    for (const path of ["package/LICENSE", "package/package.json"]) { const tar = changed(release, rows => { const row = rows.find(r => name(r) === path)!; rows.unshift(row); }); expect(error(parseArchive(tar, "release"))).toBe("duplicate member"); refusal(release, tar); } control();
  });
  it("A8 refuses links devices FIFO and directory headers", () => {
    for (const type of ["1", "2", "3", "4", "5", "6"]) { const tar = changed(release, rows => { rows[0]!.header[156] = type.charCodeAt(0); }); expect(error(parseArchive(tar, "release"))).toBe("tar type"); refusal(release, tar); } control();
  });
  it("A9 rejects unsafe names aliases PAX/GNU and noncanonical modes", () => {
    for (const path of ["/package/LICENSE", "package/../LICENSE", "package/./LICENSE", "package//LICENSE", "package\\LICENSE"]) { const tar = changed(release, rows => setName(rows[0]!, path)); expect(error(parseArchive(tar, "release"))).toBe("tar path"); refusal(release, tar); }
    for (const type of ["x", "g", "L", "K", "S"]) { const tar = changed(release, rows => { rows[0]!.header[156] = type.charCodeAt(0); }); expect(error(parseArchive(tar, "release"))).toBe("tar type"); refusal(release, tar); }
    const tar = changed(release, rows => { rows[0]!.header.write("000777 \0", 100); }); expect(error(parseArchive(tar, "release"))).toBe("tar mode"); refusal(release, tar); control();
  });
  it("A10 consumes complete gzip and ustar with strict headers and ending", () => {
    for (const [offset, byte] of [[0, 0], [1, 0], [2, 0], [3, 1]]) {
      const tar = Buffer.from(release.tar); tar[offset!] = byte!;
      expect(error(parseArchive(tar, "release"))).toBe("gzip header"); refusal(release, tar);
    }
    const raw = tarBytes(entries(release.tar));
    const badChecksum = Buffer.from(raw); badChecksum[0] ^= 1;
    const badOctal = Buffer.from(raw); badOctal[124] = 0x80; checksum(badOctal.subarray(0, 512));
    const badMagic = Buffer.from(raw); badMagic[257] = 0; checksum(badMagic.subarray(0, 512));
    const badNul = Buffer.from(raw); badNul[99] = 65; checksum(badNul.subarray(0, 512));
    const badPadding = Buffer.from(raw); const first = entries(release.tar)[0]!; badPadding[512 + first.bytes.length] = 1;
    const cases: Array<[Buffer, string]> = [[gzipSync(badChecksum), "tar checksum"], [gzipSync(badOctal), "tar octal"], [gzipSync(badMagic), "tar dialect"], [gzipSync(badNul), "tar nul"], [gzipSync(badPadding), "tar padding"], [gzipSync(raw.subarray(0, -1024)), "tar missing end"], [gzipSync(raw.subarray(0, -512)), "tar end"], [gzipSync(Buffer.concat([raw, Buffer.alloc(512, 1)])), "tar end"], [Buffer.concat([release.tar, gzipSync(Buffer.alloc(0))]), "gzip trailing"], [Buffer.concat([release.tar, Buffer.alloc(8)]), "gzip trailing"]];
    for (const [tar, code] of cases) { expect(error(parseArchive(tar, "release"))).toBe(code); refusal(release, tar); }
    for (const tar of [release.tar.subarray(0, -1), gzipSync(raw.subarray(0, 513))]) { expect(parseArchive(tar, "release").ok).toBe(false); refusal(release, tar); } control();
  });
  it("A11 enforces independent compressed expanded row and manifest budgets", () => {
    const started = Date.now(); expect(error(parseArchive(Buffer.alloc(MAX_ARTIFACT_BYTES + 1), "release"))).toBe("compressed cap");
    expect(error(parseArchive(gzipSync(Buffer.alloc(MAX_TAR_BYTES + 1)), "release"))).toMatch(/larger than|expanded cap/);
    const rows = entries(release.tar); for (let n = 0; n < 2; n++) { const row = { header: Buffer.from(rows[0]!.header), bytes: Buffer.alloc(0) }; setName(row, "package/extra" + n); rows.push(row); }
    expect(error(parseArchive(pack(rows), "release"))).toBe("archive member cap"); expect(error(parseManifest(Buffer.alloc(MAX_MANIFEST_BYTES + 1, 0x20)))).toBe("json cap");
    const m = JSON.parse(release.manifest.toString()); m.members = Array(9).fill(m.members[0]); expect(error(parseManifest(Buffer.from(JSON.stringify(m))))).toBe("member cap"); expect(Date.now() - started).toBeLessThan(30_000); control();
  });
  it("A12 shared manifest parser rejects malformed elements and duplicate keys", () => {
    for (const manifest of malformed(release)) { expect(parseManifest(manifest).ok).toBe(false); refusal(release, release.tar, manifest); }
    const alias = JSON.parse(release.manifest.toString()), keys = Object.keys(alias).sort();
    delete alias[keys[0]!]; delete alias[keys[1]!]; alias[keys.slice(0, 2).join(",")] = true;
    expect(error(parseManifest(Buffer.from(JSON.stringify(alias))))).toBe("manifest keys");
    expect(() => parseJson(Buffer.from('{"a":1,"\\u0061":2}'))).toThrow("duplicate key"); control();
  });
  it("A13 hashes do not substitute for package and provenance semantics", () => {
    const faults: Array<[string, string, unknown]> = [["package.json", "private", false], ["package.json", "bin", {}], ["package.json", "dependencies", {}], ["dist/provenance.json", "source_revision", "f".repeat(40)], ["dist/provenance.json", "source_archive_sha256", "f".repeat(64)], ["dist/provenance.json", "verifier_sha256", "f".repeat(64)], ["dist/provenance.json", "package_version", "9.9.9"]];
    for (const [path, key, value] of faults) { const tar = changed(release, rows => { const row = rows.find(r => name(r) === "package/" + path)!; const obj = JSON.parse(row.bytes.toString()); obj[key] = value; row.bytes = Buffer.from(JSON.stringify(obj)); }); refusal(release, tar, coherent(release, tar), path === "package.json" ? "package semantics" : "provenance semantics"); }
    expect(checkArtifact(release.tar, release.manifest, { ...pins(release), dependency_lock_sha256: "f".repeat(64) }).ok).toBe(false); control();
  });
  it("A14 handoff binds compressed bytes and detached manifest independently", () => {
    for (const which of [ARTIFACT_FILES.tarball, ARTIFACT_FILES.manifest]) {
      const dir = scratch(); for (const file of Object.values(ARTIFACT_FILES)) cpSync(join(release.dir, file), join(dir, file)); writeFileSync(join(dir, which), Buffer.concat([readFileSync(join(dir, which)), Buffer.from(" ")])); expect(() => checkDescriptor(dir)).toThrow("pin mismatch");
      const child = spawnSync(process.execPath, [script, "--check-descriptor", dir], { encoding: "utf8", timeout: 30_000 }); expect(child.status).toBe(1); expect(existsSync(join(dir, "installed"))).toBe(false);
    } control();
  });
  it("A15 requires every pin and treats help as information only", () => {
    const args = checkerArgs(release.dir, release.receipt) as string[];
    for (let index = 0; index < args.length; index += 2) { const missing = [...args]; missing.splice(index, 2); const child = cli(release, missing); expect(child.status).toBe(2); expect(child.stdout).toBe(""); expect(child.stderr).toBe(ARTIFACT_USAGE); }
    expect(cli(release, [...args, "--expect-mode", "release"]).status).toBe(2);
    for (const [flag, value] of [["--expect-source-revision", "f".repeat(40)], ["--expect-mode", "fixture"]]) { const bad = [...args]; bad[bad.indexOf(flag!) + 1] = value!; expect(cli(release, bad).status).toBe(1); }
    expect(cli(release, ["--help"]).stdout).toBe(ARTIFACT_HELP); expect(cli(release, ["--help"]).status).toBe(0);
    const helpExtra = cli(release, ["--help", "--tarball", "/does-not-exist"]); expect(helpExtra.status).toBe(2); expect(helpExtra.stdout).toBe(""); expect(helpExtra.stderr).toBe(ARTIFACT_USAGE);
    const mislabeled = JSON.parse(fixture.manifest.toString()); mislabeled.mode = "release"; refusal(fixture, fixture.tar, Buffer.from(JSON.stringify(mislabeled)));
    expect(cli(fixture, args).status).toBe(1); expect(installed(release).stdout).toBe(artifactSuccess("release")); control();
  });
  it("A16 later copy refusal preserves foreign files and never writes READY", async () => {
    const root = buildRoot(release), dir = join(scratch(), "artifact"); let faults = 0;
    const untouched = join(root, "server/evidence-pack-dist/export-evidence-pack.js"), before = { ino: lstatSync(untouched).ino, bytes: readFileSync(untouched) };
    let copied: { path: string; ino: number; bytes: Buffer } | undefined;
    const unlink = vi.spyOn(fs, "unlinkSync"); syncBuiltinESMExports();
    try {
      await expect(buildCandidate(buildArgs(release, dir, "release"), root, release.receipt.source_revision, { afterCopy: (path: string) => { if (path.endsWith("packages/evidence-pack-verifier/dist")) {
        faults++; writeFileSync(join(path, "foreign"), "keep");
        const tracked = join(path, "verify-evidence-pack.js"); copied = { path: tracked, ino: lstatSync(tracked).ino, bytes: readFileSync(tracked) };
        unlink.mockClear(); // Only the refusal path is counted; ordinary pre-copy clearing is authorized.
        throw new Error("scheduled copy refusal");
      } } })).rejects.toThrow("scheduled copy refusal");
      expect(faults).toBe(1); expect(unlink).not.toHaveBeenCalled();
      expect(lstatSync(untouched).ino).toBe(before.ino); expect(readFileSync(untouched)).toEqual(before.bytes);
      expect(lstatSync(copied!.path).ino).toBe(copied!.ino); expect(readFileSync(copied!.path)).toEqual(copied!.bytes);
      expect(readFileSync(join(root, "packages/evidence-pack-verifier/dist/foreign"), "utf8")).toBe("keep"); expect(existsSync(join(dir, ARTIFACT_FILES.receipt))).toBe(false); expect(existsSync(join(dir, ARTIFACT_FILES.tarball))).toBe(true);
    } finally { unlink.mockRestore(); syncBuiltinESMExports(); }
    control();
  }, TIMEOUT);
  it("A17 requires explicit policy and an exclusive destination", async () => {
    const root = buildRoot(release), dir = join(scratch(), "artifact"), args = buildArgs(release, dir, "release");
    await expect(buildCandidate(args.slice(0, 4), root, release.receipt.source_revision)).rejects.toThrow("explicit mode"); await expect(buildCandidate(args.slice(0, 6), root, release.receipt.source_revision)).rejects.toThrow("explicit mode");
    mkdirSync(dir); writeFileSync(join(dir, "foreign"), "keep"); await expect(buildCandidate(args, root, release.receipt.source_revision)).rejects.toThrow(); const link = join(scratch(), "artifact"); symlinkSync(dir, link); await expect(buildCandidate(buildArgs(release, link, "release"), root, release.receipt.source_revision)).rejects.toThrow();
    expect(readFileSync(join(dir, "foreign"), "utf8")).toBe("keep"); expect(existsSync(join(dir, ARTIFACT_FILES.receipt))).toBe(false); control();
  });
  it("A18 pins the static workflow and executes its descriptor checker", () => {
    const text = readFileSync(join(ROOT, ".github/workflows/evidence-pack-candidate.yml"), "utf8"); workflowPlan(text);
    for (const mutate of [(s: string) => s.replace("npm run build\n", "npm pack\n"), (s: string) => s.replace("/tmp/c13/artifact/candidate.tgz", "packages/evidence-pack-verifier/*.tgz"), (s: string) => s.replace("      - uses: actions/upload-artifact", "      - if: always()\n        uses: actions/upload-artifact"), (s: string) => s.replace("--check-descriptor /tmp/c13/artifact", "--check-descriptor /tmp/c13/artifact || true")]) expect(() => workflowPlan(mutate(text))).toThrow();
    for (const fault of ["none", "archive-only", "metadata-only", ...Object.values(ARTIFACT_FILES), "source.tar", "release-source.json", "source_revision", "source_archive_sha256"]) {
      const dir = scratch(); for (const file of Object.values(ARTIFACT_FILES)) cpSync(join(release.dir, file), join(dir, file));
      if (fault !== "metadata-only") cpSync(release.archive, join(dir, "source.tar"));
      if (fault !== "archive-only") cpSync(release.metadata, join(dir, "release-source.json"));
      const good = ["none", "archive-only", "metadata-only"].includes(fault);
      if (["source_revision", "source_archive_sha256"].includes(fault)) { const metadata = JSON.parse(readFileSync(release.metadata, "utf8")); metadata[fault] = "f".repeat(fault === "source_revision" ? 40 : 64); writeFileSync(join(dir, "release-source.json"), JSON.stringify(metadata)); }
      else if (!good) writeFileSync(join(dir, fault), "changed");
      const child = spawnSync(process.execPath, [script, "--check-descriptor", dir], { encoding: "utf8", timeout: 30_000 });
      expect(child.error).toBeUndefined(); expect(child.status, fault).toBe(good ? 0 : 1);
      if (!good && ["source.tar", "release-source.json", "source_revision", "source_archive_sha256"].includes(fault)) expect(child.stderr).toMatch(/Source archive refused|Source metadata refused|Unexpected token/);
      expect(existsSync(join(dir, "installed"))).toBe(false);
    } control();
  });
  it("A19 installed checker reads every actual member independent of checkout reports", async () => {
    const c = await candidateForTests(); // CI supplies the exact candidate selected for upload.
    const actual = sample(c.artifactDir, c.checker, c.tree, c.archive, c.metadata, c.command); expect(installed(actual).status).toBe(0); expect(parsedRows(actual).map(row => row.path)).toEqual(registry(actual.receipt.mode));
    const decoy = join(scratch(), "pack.json"); writeFileSync(decoy, '{"files":[]}');
    const checkout = join(actual.tree, "packages/evidence-pack-verifier/dist/provenance.json"), old = readFileSync(checkout), oldReport = c.packed.files;
    try {
      writeFileSync(checkout, "checkout decoy"); c.packed.files = [];
      expect(installed(actual).stdout).toBe(artifactSuccess(actual.receipt.mode));
      for (const path of registry(actual.receipt.mode)) {
        const tar = changed(actual, rows => { const row = rows.find(r => name(r) === path)!; row.bytes = Buffer.concat([row.bytes, Buffer.from(" ")]); });
        refusal(actual, tar, retained(actual, tar), path.endsWith("/NON_RELEASE") ? "fixture marker" : "member hashes");
      }
    } finally { writeFileSync(checkout, old); c.packed.files = oldReport; } control();
  }, TIMEOUT);
  it("A20 schema parity and output completion hold at source and installed boundaries", async () => {
    for (const manifest of malformed(release)) { expect(parseManifest(manifest).ok).toBe(false); expect(policy(release, release.tar, manifest).ok).toBe(false); expect(installed(release, release.tar, manifest).status).toBe(1); }
    for (const extra of [{ command: "/bin/true" }, { tarball: "../candidate.tgz" }, { manifest: "/tmp/manifest.json" }, { installPrefix: "/tmp/outside" }]) expect(parseCandidate(Buffer.from(JSON.stringify({ ...release.receipt, ...extra }))).ok).toBe(false);
    const args = checkerArgs(release.dir, release.receipt) as string[];
    for (const asyncFault of [false, true]) { const broken = { write: (_text: string): Promise<void> => { if (asyncFault) return Promise.reject(new Error("broken output")); throw new Error("broken output"); } }, good = { write: async (_text: string) => {} }; expect(await runArtifactCommand(args, "release", broken, good)).toBe(1); expect(await runArtifactCommand([], "release", good, broken)).toBe(1); expect(await runArtifactCommand(["--help"], "release", broken, good)).toBe(1); } control();
  });
  it("A21 anchors a symlinked ancestor for build and descriptor READY", async () => {
    const root = buildRoot(release), parent = scratch(), alias = join(scratch(), "alias");
    symlinkSync(parent, alias, "dir");
    const dir = join(alias, "artifact");
    const receipt = await buildCandidate(buildArgs(release, dir, "release"), root, release.receipt.source_revision);
    expect(receipt).toEqual(checkDescriptor(dir).receipt);
    expect(checkDescriptor(join(parent, "artifact")).receipt).toEqual(receipt);
    const child = spawnSync(process.execPath, [script, "--check-descriptor", dir], { encoding: "utf8", timeout: 30_000 });
    expect(child.status).toBe(0); control();
  }, TIMEOUT);
  it("A22 refuses a final-component symlink in build and descriptor checks", async () => {
    const root = buildRoot(release), link = join(scratch(), "artifact");
    symlinkSync(release.dir, link, "dir");
    const before = readFileSync(join(release.dir, ARTIFACT_FILES.receipt));
    await expect(buildCandidate(buildArgs(release, link, "release"), root, release.receipt.source_revision)).rejects.toThrow(/EEXIST/);
    for (const path of [link, link + "/", link + "/."]) expect(() => checkDescriptor(path)).toThrow("Artifact directory refused");
    expect(readFileSync(join(release.dir, ARTIFACT_FILES.receipt))).toEqual(before); control();
  });
  it("A23 compares dist names by element before and after generated metadata", async () => {
    for (const phase of [1, 2]) {
      const root = buildRoot(release), dir = join(scratch(), "artifact"); let calls = 0, faults = 0;
      const read = fs.readdirSync;
      // The spy wraps the overloaded API; this call site uses the string-name overload.
      const listing = vi.spyOn(fs, "readdirSync").mockImplementation(((...args: Parameters<typeof fs.readdirSync>) => {
        const names = Reflect.apply(read, fs, args);
        if (String(args[0]).includes("pack-source-") && String(args[0]).endsWith("packages/evidence-pack-verifier/dist") && ++calls === phase) { faults++; return [names.sort().join(",")]; }
        return names;
      }) as typeof fs.readdirSync); syncBuiltinESMExports();
      try { await expect(buildCandidate(buildArgs(release, dir, "release"), root, release.receipt.source_revision)).rejects.toThrow("Unexpected verifier artifact"); }
      finally { listing.mockRestore(); syncBuiltinESMExports(); }
      expect(faults).toBe(1); expect(existsSync(join(dir, ARTIFACT_FILES.receipt))).toBe(false);
    } control();
  }, TIMEOUT);
  it("C1 release control with stable existing copies reaches the complete receipt", () => { control(); expect(checkDescriptor(release.dir).receipt.mode).toBe("release"); expect(readdirSync(join(release.tree, "packages/evidence-pack-verifier/dist")).sort()).toEqual(registry("release").filter(p => p.startsWith("package/dist/")).map(p => p.slice("package/dist/".length)).sort()); });
  it("C2 fixture control with initially absent copies reaches the complete receipt", () => { control(fixture); expect(checkDescriptor(fixture.dir).receipt.mode).toBe("fixture"); expect(installed(fixture).stdout).toBe(artifactSuccess("fixture")); });
  it("C4 valid archive and schema round-trip pin modes and all registry rows", () => {
    for (const s of [release, fixture]) { const checked = requireValid(policy(s)); expect(checked.manifest.members).toEqual(parsedRows(s)); expect(checked.expanded_bytes).toBeLessThan(MAX_TAR_BYTES); expect(s.tar.length).toBeLessThan(MAX_ARTIFACT_BYTES); expect(parseManifest(Buffer.from(JSON.stringify(checked.manifest)))).toEqual({ ok: true, value: checked.manifest }); expect(requireValid(parseCandidate(Buffer.from(JSON.stringify(s.receipt))))).toEqual(s.receipt); for (const row of entries(s.tar)) expect(parseInt(row.header.subarray(100, 108).toString(), 8)).toBe(memberMode(name(row))); expect(lstatSync(s.checker).mode & 0o111).not.toBe(0); expect(installed(s).status).toBe(0); }
  });
});
