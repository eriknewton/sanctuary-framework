/** Installed classification precedes every command; synthetic controls retain snapshot semantics. R3 */
import { beforeAll, describe, expect, it } from "vitest";
import { readFileSync, writeFileSync, mkdirSync, cpSync, realpathSync, symlinkSync, unlinkSync, chmodSync, lstatSync, type BigIntStats } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync, execFileSync } from "node:child_process";
import { observePackageMarker, parseMarkerState, markerRefusal, NON_RELEASE_REFUSAL, PACKAGE_MARKER_UNAVAILABLE, MAX_PACKAGE_COMPONENTS, MAX_PACKAGE_PATH_BYTES, type MarkerFS } from "../../src/evidence-pack/snapshot-package-marker.js";
import { runInstalledOfflineCommand } from "../../src/evidence-pack/snapshot-installed-cli.js";
import { ARTIFACT_HELP, artifactSuccess, NON_RELEASE_MARKER, NON_RELEASE_TEXT, digest, parseArchive, requireValid } from "../../src/evidence-pack/artifact-policy.mjs";
import { scratch, functionalCandidateForTests } from "./snapshot-artifact-fixtures.js";
import { fixture, syncAudit } from "./snapshot-fixtures.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
// @ts-expect-error The Node build script intentionally has no declaration wrapper.
import { candidateForTests, prepareFixtureCandidate, checkerArgs } from "../../scripts/build-evidence-pack.mjs";
let candidate: Awaited<ReturnType<typeof candidateForTests>>, marked: typeof candidate, control: typeof candidate;
const TIMEOUT = 30_000;
const HELP = "Usage: verify-evidence-pack --pack <directory> --public-key-file <file> --trust-descriptor-file <file> --expect-manifest-digest <sha256:hex> [--json]\nverify-evidence-pack --help\nverify-evidence-pack --version\n";
const run = (command: string, args: string[], options: { cwd?: string; env?: NodeJS.ProcessEnv; preload?: string; preserve?: boolean } = {}) => {
  const home = scratch();
  return spawnSync(process.env.EVIDENCE_PACK_TEST_NODE ?? process.execPath, [...(options.preload ? ["--import", options.preload] : []), ...(options.preserve ? ["--preserve-symlinks-main"] : []), command, ...args], { cwd: options.cwd ?? home, env: { PATH: process.env.PATH, ...options.env, HOME: home, SANCTUARY_STORAGE_PATH: join(home, "state") }, encoding: "utf8", timeout: TIMEOUT });
};
function refused(r: ReturnType<typeof run>, line = NON_RELEASE_REFUSAL) { expect(r.error).toBeUndefined(); expect(r.status, r.stderr + r.stdout).toBe(1); expect(r.stdout).toBe(""); expect(r.stderr).toBe(line); }
function paired() { expect(run(control.command, ["--version"]).status).toBe(0); refused(run(marked.command, ["--version"])); }
function delivery(status = "PASS") {
  const f = fixture(), root = scratch(), pack = join(root, "pack"); mkdirSync(pack);
  if (status === "PARTIAL") { for (const row of f.records) if (row.type === "checkpoint") { row.unsigned = true; row.signature = null; row.signer_kid = null; delete row.public_key; } syncAudit(f); }
  for (const file of f.capture.files) writeFileSync(join(pack, Buffer.from(file.name).toString()), file.bytes);
  if (status === "FAIL") writeFileSync(join(pack, C.PDF_FILENAME), "changed");
  writeFileSync(join(root, "key"), f.pins.packKey); writeFileSync(join(root, "trust"), f.pins.descriptorBytes);
  return { root, pack, args: ["--pack", pack, "--public-key-file", join(root, "key"), "--trust-descriptor-file", join(root, "trust"), "--expect-manifest-digest", f.pins.expectedManifestDigest] };
}
function copyPackage(source = marked) {
  const root = join(scratch(), "package"); cpSync(dirname(dirname(realpathSync(source.command))), root, { recursive: true });
  return { root, command: join(root, "dist/verify-evidence-pack.js"), checker: join(root, "dist/check-evidence-pack-artifact.js"), marker: join(root, "dist", NON_RELEASE_MARKER) };
}
function preload(source: string) { const file = join(scratch(), "observe.mjs"); writeFileSync(file, source); return file; }
function noContent(command: string, args: string[], paths: string[], line: string) {
  const hook = preload(`import fs from 'node:fs'; import fsp from 'node:fs/promises'; import {syncBuiltinESMExports} from 'node:module';
let reads=0; const paths=${JSON.stringify(paths)};
for(const object of [fs,fsp]) for(const key of ['readFile','readFileSync','open','openSync','realpath','realpathSync','readlink','readlinkSync']) if(typeof object[key]==='function'){const native=object[key];object[key]=(...args)=>{if(paths.includes(String(args[0]))){reads++;throw Error('forbidden content access');}return native(...args);};}
syncBuiltinESMExports();process.on('exit',()=>process.stderr.write('READS '+reads+'\\n'));`);
  const r = run(command, args, { preload: hook }); expect(r.error).toBeUndefined(); expect(r.status).toBe(1); expect(r.stdout).toBe(""); expect(r.stderr).toBe(line + "READS 0\n");
}
const tracePreload = () => preload(`import fs from 'node:fs'; import fsp from 'node:fs/promises'; import {syncBuiltinESMExports} from 'node:module';
const native = fs.lstatSync, open = fsp.open; const paths=[]; let opens=0;
fs.lstatSync=(...args)=>{ paths.push(args[0]); return native(...args); }; fsp.open=(...args)=>{opens++; return open(...args);}; syncBuiltinESMExports();
process.on('exit',()=>process.stderr.write('TRACE '+JSON.stringify({paths,opens})+'\\n'));`);
function traced(r: ReturnType<typeof run>) { const lines = r.stderr.split("TRACE "); expect(lines).toHaveLength(2); return { diagnostic: lines[0], trace: JSON.parse(lines[1]!) as { paths: string[]; opens: number } }; }
function schedule(change?: (call: number, path: string, stat: BigIntStats) => BigIntStats): { fs: MarkerFS; calls: string[] } {
  const calls: string[] = [], directory = lstatSync(dirname(dirname(realpathSync(control.command))), { bigint: true });
  return { calls, fs: { lstatSync(path) { calls.push(path); if (change) return change(calls.length, path, directory); if (calls.length === 2) throw Object.assign(new Error("missing"), { code: "ENOENT" }); return directory; } } };
}
const url = "file:///synthetic/package/dist/verify-evidence-pack.js";
function verdicts(command: string) {
  for (const [status, exit] of [["PASS", 0], ["PARTIAL", 10], ["FAIL", 1]] as const) {
    const d = delivery(status);
    for (const json of [false, true]) { const r = run(command, [...d.args, ...(json ? ["--json"] : [])]); expect(r.error).toBeUndefined(); expect(r.status, r.stderr + r.stdout).toBe(exit); expect(r.stderr).toBe(""); if (json) expect(JSON.parse(r.stdout)).toMatchObject({ format: C.RESULT_FORMAT, status, exit_code: exit, accepted: status === "PASS" }); else expect(r.stdout.startsWith(C.HUMAN[status] + "\n")).toBe(true); }
  }
}
beforeAll(async () => {
  candidate = await candidateForTests(); marked = candidate.fixture ? candidate : await prepareFixtureCandidate(); control = await functionalCandidateForTests();
}, 120_000);
describe("installed package classification", () => {
  it("refuses marked snapshot verification before evidence reads M1", () => {
    paired(); const d = delivery();
    for (const json of [false, true]) { const r = run(marked.command, [...d.args, ...(json ? ["--json"] : [])], { preload: tracePreload() }); const t = traced(r); refused({ ...r, stderr: t.diagnostic! }); expect(t.trace.opens).toBe(0); expect(t.trace.paths).toHaveLength(3); }
    const args = checkerArgs(control.artifactDir, control.receipt);
    refused(run(marked.checker, args)); expect(run(marked.checker, checkerArgs(marked.artifactDir, marked.receipt)).status).toBe(0); expect(run(marked.checker, ["--help"]).stdout).toBe(ARTIFACT_HELP);
  });
  it("refuses a planted marker in the release-built checker M1-release", () => {
    const c = copyPackage(control), args = checkerArgs(control.artifactDir, control.receipt);
    const clean = run(c.checker, args); expect(clean.status).toBe(0); expect(clean.stdout).toBe(artifactSuccess("release")); expect(clean.stderr).toBe("");
    writeFileSync(c.marker, NON_RELEASE_TEXT);
    refused(run(c.checker, args));
    const fixtureCheck = run(c.checker, checkerArgs(marked.artifactDir, marked.receipt));
    expect(fixtureCheck.status).toBe(0); expect(fixtureCheck.stdout).toBe(artifactSuccess("fixture")); expect(fixtureCheck.stderr).toBe("");
    const help = run(c.checker, ["--help"]); expect(help.status).toBe(0); expect(help.stdout).toBe(ARTIFACT_HELP); expect(help.stderr).toBe("");
  });
  it("classifies help and version on the actual candidate M2", () => {
    paired(); for (const arg of ["--help", "--version"]) {
      refused(run(marked.command, [arg]));
      const r = run(control.command, [arg]); expect(r.status).toBe(0); expect(r.stderr).toBe(""); expect(r.stdout).toBe(arg === "--help" ? HELP : `verify-evidence-pack 0.1.0 source_revision=${control.receipt.source_revision}\n`);
      const actual = run(candidate.command, [arg]); if (candidate.fixture) refused(actual); else { expect(actual.status).toBe(0); expect(actual.stdout).toBe(r.stdout); expect(actual.stderr).toBe(""); }
    }
  });
  it("classifies regular markers without consuming their bytes M3", () => {
    paired(); const c = copyPackage();
    const guard = preload(`import fs from 'node:fs'; import {syncBuiltinESMExports} from 'node:module'; for(const key of ['openSync','readFileSync']){const original=fs[key];fs[key]=(...args)=>{if(String(args[0])===${JSON.stringify(c.marker)}) throw Error('marker content opened');return original(...args);};} syncBuiltinESMExports();`);
    for (const bytes of ["", "arbitrary", NON_RELEASE_TEXT]) { writeFileSync(c.marker, bytes); chmodSync(c.marker, 0); try { refused(run(c.command, ["--version"], { preload: guard })); } finally { chmodSync(c.marker, 0o600); } }
  });
  it("refuses dangling marker links without following a target M4", () => {
    paired(); const c = copyPackage(); unlinkSync(c.marker); const target = join(scratch(), "missing"); symlinkSync(target, c.marker); noContent(c.command, ["--help"], [c.marker, target], PACKAGE_MARKER_UNAVAILABLE);
  });
  it("refuses special marker entries promptly without target access M5", () => {
    paired(); for (const type of ["directory", "fifo", "link"]) {
      const c = copyPackage(); unlinkSync(c.marker); const target = join(scratch(), "sentinel"); writeFileSync(target, "unchanged");
      if (type === "directory") mkdirSync(c.marker); else if (type === "fifo") execFileSync("mkfifo", [c.marker]); else symlinkSync(target, c.marker);
      noContent(c.command, ["--version"], [c.marker, target], PACKAGE_MARKER_UNAVAILABLE); expect(readFileSync(target, "utf8")).toBe("unchanged");
    }
  });
  it("refuses unavailable package observations and release checker use M6", () => {
    paired(); const c = copyPackage(control), root = c.root;
    for (const code of ["ENOENT", "EACCES", "EIO"]) {
      const hook = preload(`import fs from 'node:fs'; import {syncBuiltinESMExports} from 'node:module'; const native=fs.lstatSync; let faults=0;fs.lstatSync=(path,...rest)=>{if(path===${JSON.stringify(root)}){faults++;throw Object.assign(Error('scheduled'),{code:${JSON.stringify(code)}});}return native(path,...rest);};syncBuiltinESMExports();process.on('exit',()=>process.stderr.write('FAULTS '+faults+'\\n'));`);
      for (const [command, args] of [[c.command, ["--version"]], [c.checker, checkerArgs(control.artifactDir, control.receipt)]] as const) { const r = run(command, args, { preload: hook }); expect(r.stderr).toBe(PACKAGE_MARKER_UNAVAILABLE + "FAULTS 1\n"); expect(r.status).toBe(1); expect(r.stdout).toBe(""); }
      expect(run(c.checker, ["--help"], { preload: hook }).stdout).toBe(ARTIFACT_HELP);
    }
    const absent = schedule(); expect(observePackageMarker(url, absent.fs)).toEqual({ kind: "absent" }); expect(absent.calls).toHaveLength(3);
  });
  it("checks package root types while permitting ancestor relocation M7", () => {
    paired(); expect(observePackageMarker(pathToFileURL(realpathSync(control.command)).href, { lstatSync })).toEqual({ kind: "absent" }); const c = copyPackage(control), parent = scratch(), alias = join(parent, "alias"); symlinkSync(c.root, alias);
    expect(observePackageMarker(pathToFileURL(join(alias, "dist/verify-evidence-pack.js")).href, { lstatSync })).toEqual({ kind: "unknown" });
    const file = join(parent, "file"); writeFileSync(file, "regular"); expect(observePackageMarker(pathToFileURL(join(file, "dist/verify-evidence-pack.js")).href, { lstatSync })).toEqual({ kind: "unknown" });
    const ancestor = join(parent, "ancestor"); symlinkSync(dirname(c.root), ancestor); const relocated = join(ancestor, "package/dist/verify-evidence-pack.js");
    expect(observePackageMarker(pathToFileURL(relocated).href, { lstatSync })).toEqual({ kind: "absent" }); expect(run(relocated, ["--version"]).status).toBe(0);
    // The binding four-step contract does not inspect dist independently: a missing dist gives final ENOENT.
    const noDist = join(parent, "no-dist"); mkdirSync(noDist); expect(observePackageMarker(pathToFileURL(join(noDist, "dist/verify-evidence-pack.js")).href, { lstatSync })).toEqual({ kind: "absent" });
    const regularDist = join(parent, "regular-dist"); mkdirSync(regularDist); writeFileSync(join(regularDist, "dist"), "regular"); expect(observePackageMarker(pathToFileURL(join(regularDist, "dist/verify-evidence-pack.js")).href, { lstatSync })).toEqual({ kind: "unknown" });
    const linkedDist = join(parent, "linked-dist"); mkdirSync(linkedDist); symlinkSync(dirname(c.command), join(linkedDist, "dist")); expect(observePackageMarker(pathToFileURL(join(linkedDist, "dist/verify-evidence-pack.js")).href, { lstatSync })).toEqual({ kind: "absent" });
  });
  it("refuses root types before observing the marker M7-first-root", () => {
    const c = copyPackage(control), parent = scratch(), alias = join(parent, "alias"), file = join(parent, "file");
    symlinkSync(c.root, alias); writeFileSync(file, "regular");
    for (const root of [alias, file]) {
      const calls: string[] = [];
      const fs: MarkerFS = { lstatSync(path, options) { calls.push(path); return lstatSync(path, options); } };
      expect(observePackageMarker(pathToFileURL(join(root, "dist/verify-evidence-pack.js")).href, fs)).toEqual({ kind: "unknown" });
      expect(calls).toEqual([root]);
    }
  });
  it("rechecks package identity after the marker observation M8", () => {
    paired(); expect(observePackageMarker(url, schedule().fs)).toEqual({ kind: "absent" }); for (const field of ["dev", "ino"]) {
      const s = schedule((call, _path, stat) => { if (call === 2) throw Object.assign(new Error("absent"), { code: "ENOENT" }); return call === 3 ? Object.assign(Object.create(stat) as BigIntStats, { [field]: stat[field as "dev" | "ino"] + 1n }) : stat; });
      expect(observePackageMarker(url, s.fs)).toEqual({ kind: "unknown" }); expect(s.calls).toEqual(["/synthetic/package", "/synthetic/package/dist/NON_RELEASE", "/synthetic/package"]);
    }
    for (const type of ["file", "link"]) { const s = schedule((call, _path, stat) => { if (call === 2) throw Object.assign(new Error("absent"), { code: "ENOENT" }); return call === 3 ? Object.assign(Object.create(stat) as BigIntStats, { isDirectory: () => type === "link", isSymbolicLink: () => type === "link" }) : stat; }); expect(observePackageMarker(url, s.fs)).toEqual({ kind: "unknown" }); expect(s.calls).toHaveLength(3); }
    const s = schedule(); expect(observePackageMarker(url, s.fs)).toEqual({ kind: "absent" }); expect(s.calls).toHaveLength(3);
  });
  it("maps each scheduled syscall error to unknown M9", () => {
    paired(); expect(observePackageMarker(url, schedule().fs)).toEqual({ kind: "absent" }); for (const code of ["EACCES", "EIO", "ELOOP", "EPERM", "ENOTDIR"]) for (const faultAt of [1, 2, 3]) {
      let faults = 0; const s = schedule((call, _path, stat) => { if (call === faultAt) { faults++; throw Object.assign(new Error("fault"), { code }); } if (call === 2) throw Object.assign(new Error("absent"), { code: "ENOENT" }); return stat; });
      expect(observePackageMarker(url, s.fs)).toEqual({ kind: "unknown" }); expect(faults).toBe(1);
    }
    expect(observePackageMarker(url, schedule().fs)).toEqual({ kind: "absent" });
  });
  it("uses the loader entry despite cwd input and bin aliases M10", () => {
    paired(); const d = delivery(); writeFileSync(join(d.root, NON_RELEASE_MARKER), "decoy");
    refused(run(marked.command, d.args, { cwd: d.root })); expect(run(control.command, ["--version"], { cwd: d.root }).status).toBe(0);
    writeFileSync(join(d.pack, NON_RELEASE_MARKER), "decoy"); refused(run(marked.command, d.args, { cwd: d.pack }));
    expect(run(control.command, ["--help"]).stdout).toBe(HELP); refused(run(control.command, ["--help"], { preserve: true }), PACKAGE_MARKER_UNAVAILABLE);
  });
  it("has no ambient or argument classification bypass M11", () => {
    paired(); for (const env of [{}, { NODE_ENV: "test", NON_RELEASE: "0", EVIDENCE_PACK_SKIP_MARKER: "1", SANCTUARY_ARTIFACT_MODE: "release", SANCTUARY_SOURCE_SHA: "f".repeat(40) }]) for (const args of [["--version"], ["--help"], ["--skip-marker"], ["--allow-non-release"], ["--json"], []]) refused(run(marked.command, args, { env }));
  });
  it("runs one reader before every installed command branch M12", () => {
    paired(); const d = delivery();
    for (const args of [[], ["--invalid"], ["--help"], ["--version"], d.args, [...d.args, "--json"]]) {
      const r = run(marked.command, args, { preload: tracePreload() }), t = traced(r), root = dirname(dirname(realpathSync(marked.command)));
      refused({ ...r, stderr: t.diagnostic! }); expect(t.trace.paths).toEqual([root, join(root, "dist/NON_RELEASE"), root]); expect(t.trace.opens).toBe(0);
    }
    const r = run(control.command, [...d.args, "--json"], { preload: tracePreload() }), t = traced(r); expect(r.status, r.stderr).toBe(0); expect(JSON.parse(r.stdout).status).toBe("PASS"); expect(t.trace.opens).toBeGreaterThan(0); expect(t.trace.paths.filter(p => p.endsWith("/NON_RELEASE"))).toHaveLength(1);
  });
  it("retains failure on synchronous and asynchronous output errors M13", async () => {
    paired(); for (const asyncFault of [false, true]) {
      let calls = 0; const broken = (_text: string): Promise<void> => { calls++; if (asyncFault) return Promise.reject(new Error("output")); throw new Error("output"); }, good = async (_text: string) => {};
      expect(await runInstalledOfflineCommand(["--help"], pathToFileURL(realpathSync(marked.command)).href, { stdout: good, stderr: broken })).toBe(1); expect(calls).toBe(1); calls = 0;
      expect(await runInstalledOfflineCommand(["--help"], pathToFileURL(realpathSync(control.command)).href, { stdout: broken, stderr: good })).toBe(1); expect(calls).toBe(1);
    }
    // Emit during a successful command's write, before its returned zero reaches the built footer.
    for (const [command, output] of [[control.command, HELP], [control.checker, ARTIFACT_HELP]]) for (const stream of ["stdout", "stderr"]) {
      const hook = preload(`const native=process.stdout.write.bind(process.stdout);let faults=0;process.stdout.write=(...args)=>{const callback=args.at(-1);if(typeof callback!=='function')throw Error('write callback required');args[args.length-1]=(...result)=>{callback(...result);if(!faults){faults++;process[${JSON.stringify(stream)}].emit('error',Error('scheduled stream failure'));}};return native(...args);};process.on('exit',()=>process.stderr.write('STREAM_ERRORS '+faults+'\\n'));`);
      const r = run(command!, ["--help"], { preload: hook });
      expect(r.error).toBeUndefined(); expect(r.status, r.stderr).toBe(1); expect(r.stdout).toBe(output); expect(r.stderr).toBe("STREAM_ERRORS 1\n");
    }
  });
  it("limits isolation observations to exact package paths M14", () => {
    paired(); const root = scratch(), bundle = realpathSync(control.command), packageRoot = dirname(dirname(bundle));
    const isolation = join(control.tree, "server/evidence-pack-dist/evidence-pack-drill-isolation.js");
    for (const writable of [false, true]) {
      const hook = preload(`import {installIsolation} from ${JSON.stringify(isolation)}; installIsolation(${JSON.stringify(root)}, ${JSON.stringify(bundle)}, ${writable});`);
      for (const path of [packageRoot, dirname(bundle), join(dirname(bundle), NON_RELEASE_MARKER)]) {
        const script = join(root, "allow.mjs"); writeFileSync(script, `import fs from 'node:fs';try{fs.lstatSync(${JSON.stringify(path)},{bigint:true});}catch(e){if(e.code!=='ENOENT')throw e;}`);
        const r = run(script, [], { preload: hook }); expect(r.status, r.stderr).toBe(0); expect(JSON.parse(r.stderr)).toMatchObject({ denied: 0, enumerations: 0, markerObservations: 1 });
      }
      const nested = copyPackage(control), nestedRoot = dirname(nested.root);
      const nestedHook = preload(`import {installIsolation} from ${JSON.stringify(isolation)}; installIsolation(${JSON.stringify(nestedRoot)}, ${JSON.stringify(nested.command)}, ${writable});`);
      const nestedScript = join(nestedRoot, "deny-marker.mjs"); writeFileSync(nestedScript, `import fs from 'node:fs';fs.readFileSync(${JSON.stringify(nested.marker)});`);
      const nestedRun = run(nestedScript, [], { preload: nestedHook }); expect(nestedRun.status).toBe(1); expect(nestedRun.stderr).toContain('"denied":1');
      for (const expression of [`fs.readFileSync(${JSON.stringify(join(dirname(bundle), NON_RELEASE_MARKER))})`, `fs.lstatSync(${JSON.stringify(dirname(packageRoot))},{bigint:true})`, `fs.realpathSync(${JSON.stringify(packageRoot)})`, `fs.lstatSync(${JSON.stringify(packageRoot)},{bigint:true,throwIfNoEntry:false})`, `fs.lstatSync(${JSON.stringify(packageRoot)},Object.assign(Object.create({bigint:true}),{throwIfNoEntry:false}))`, `fs.lstatSync(${JSON.stringify(packageRoot)},Object.assign(Object.create({throwIfNoEntry:false}),{bigint:true}))`]) {
        const script = join(root, "deny.mjs"); writeFileSync(script, `import fs from 'node:fs';${expression};`); const r = run(script, [], { preload: hook }); expect(r.status).toBe(1); expect(r.stderr).toContain('"denied":1');
      }
    }
  });
  it("validates observation states and unnormalized loader layouts M15", () => {
    paired(); expect(markerRefusal(observePackageMarker(url, schedule().fs))).toBeUndefined(); for (const value of [undefined, null, false, true, "ABSENT\n", {}, [], { kind: "ABSENT" }, { kind: "absent", extra: true }, { kind: false }, Object.assign(Object.create({ kind: "absent" }) as object, { extra: true })]) { expect(parseMarkerState(value)).toEqual({ kind: "unknown" }); expect(markerRefusal(value)).toBe(PACKAGE_MARKER_UNAVAILABLE); }
    for (const kind of ["absent", "present", "unknown"]) expect(parseMarkerState({ kind })).toEqual({ kind });
    for (const path of ["file:///tmp/pkg\\..\\..\\etc/dist/verify-evidence-pack.js", "file:///tmp/pkg%5C..%5C..%5Cetc/dist/verify-evidence-pack.js", "file:///tmp/pkg%5c..%5c..%5cetc/dist/verify-evidence-pack.js", url + "?x=1", url + "#frag", "https://example.invalid/dist/verify-evidence-pack.js", "file:///package/dist/other.js", "file:///package//dist/verify-evidence-pack.js", "file:///package/./dist/verify-evidence-pack.js", "file:///package/%2e%2e/dist/verify-evidence-pack.js", "file:///package/%2Fdist/verify-evidence-pack.js", "file:///" + "a".repeat(MAX_PACKAGE_PATH_BYTES) + "/dist/verify-evidence-pack.js", "file:///" + "a/".repeat(MAX_PACKAGE_COMPONENTS) + "dist/verify-evidence-pack.js"]) { const s = schedule(); expect(observePackageMarker(path, s.fs)).toEqual({ kind: "unknown" }); expect(s.calls).toHaveLength(0); }
    expect(markerRefusal(observePackageMarker(url, schedule().fs))).toBeUndefined();
    const config = readFileSync(resolve("tsup.evidence-pack.config.ts"), "utf8"); expect(config).toContain('"verify-evidence-pack": "src/evidence-pack/snapshot-installed-cli.ts"'); expect(config).toContain("runInstalledOfflineCommand(process.argv.slice(2), import.meta.url, offlineIO)");
  });
  it("keeps fixture and functional control artifacts distinct and coherent M16", () => {
    paired(); expect(marked.artifactDir).not.toBe(control.artifactDir); expect(marked.command).not.toBe(control.command);
    for (const c of [marked, control]) {
      expect(c.command).toBe(join(c.artifactDir, "installed/node_modules/.bin/verify-evidence-pack")); expect(digest(readFileSync(c.tarball))).toBe(c.receipt.tarball_sha256);
      const members = requireValid(parseArchive(readFileSync(c.tarball), c.receipt.mode)).members;
      const bin = members.find(row => row.path === "package/dist/verify-evidence-pack.js")!; expect(digest(readFileSync(c.command))).toBe(digest(bin.bytes));
    }
    expect(readFileSync(join(dirname(realpathSync(marked.command)), NON_RELEASE_MARKER), "utf8")).toBe(NON_RELEASE_TEXT);
    if (candidate.fixture) { expect(control.synthetic).toBe(true); expect(control.authenticated_release).toBe(false); }
    verdicts(control.command);
  });
  it("preserves marker-free bytes and the trusted-installation bound C3", () => {
    expect(run(control.command, ["--help"]).stdout).toBe(HELP); expect(run(control.command, ["--version"]).stdout).toBe(`verify-evidence-pack 0.1.0 source_revision=${control.receipt.source_revision}\n`); verdicts(control.command);
    // Deleting the marker from a separate copy admits use: absence does not authenticate the original artifact.
    const copied = copyPackage(); unlinkSync(copied.marker); const d = delivery(); const r = run(copied.command, [...d.args, "--json"]); expect(r.status, r.stderr).toBe(0); expect(JSON.parse(r.stdout).status).toBe("PASS");
  });
});
