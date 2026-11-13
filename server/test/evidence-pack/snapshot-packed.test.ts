/** Installed consumers preserve snapshot semantics within the isolation boundary. R3 */
import { beforeAll, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, realpathSync, symlinkSync, chmodSync, lstatSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { join, resolve, dirname, basename } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync, execFileSync } from "node:child_process";
// @ts-expect-error The build script is JavaScript and intentionally has no declaration artifact.
import { candidateForTests } from "../../scripts/build-evidence-pack.mjs";
import { functionalCandidateForTests } from "./snapshot-artifact-fixtures.js";
import { fixture, syncAudit } from "./snapshot-fixtures.js";
import { verifyAuditChainContent } from "../../src/cli/audit-chain-verify.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
let c: Awaited<ReturnType<typeof candidateForTests>>;
const TIMEOUT_MS = 30_000;
function isolated(attack?: string, status = "PASS", alias = false, writable = false) {
  const f = fixture(), root = mkdtempSync(join(tmpdir(), "isolated-")), pack = join(root, "pack"); mkdirSync(pack);
  if (status === "PARTIAL") { for (const row of f.records) if (row.type === "checkpoint") { row.unsigned = true; row.signature = null; row.signer_kid = null; delete row.public_key; } syncAudit(f); }
  for (const file of f.capture.files) writeFileSync(join(pack, Buffer.from(file.name).toString()), file.bytes);
  if (status === "FAIL") writeFileSync(join(pack, C.PDF_FILENAME), "changed");
  writeFileSync(join(root, "key"), f.pins.packKey); writeFileSync(join(root, "trust"), f.pins.descriptorBytes);
  symlinkSync(join(root, "key"), join(root, "inside-link"));
  const outside = mkdtempSync(join(tmpdir(), "outside-")); writeFileSync(join(outside, "secret"), "synthetic");
  symlinkSync(join(outside, "secret"), join(root, "link")); symlinkSync(outside, join(root, "parent-link"));
  mkdirSync(join(root, "denied-home")); writeFileSync(join(root, "denied-home/secret"), "synthetic"); symlinkSync(join(root, "denied-home"), join(root, "home-alias"));
  const preload = join(c.tree, "server/evidence-pack-dist/evidence-pack-drill-isolation.js");
  const target = attack ? join(root, "attack.mjs") : c.command;
  if (attack) writeFileSync(target, attack);
  const args = attack ? [] : ["--pack", pack, "--public-key-file", join(root, "key"), "--trust-descriptor-file", join(root, "trust"), "--expect-manifest-digest", f.pins.expectedManifestDigest, "--json"];
  const listingPaths = [pack, ...f.capture.files.map(file => join(pack, Buffer.from(file.name).toString()))];
  const expectedEnumerations = listingPaths.reduce((count, path) => count + 1 + (process.platform === "darwin" ? execFileSync("/usr/bin/xattr", ["-s", path], { encoding: "utf8" }).split("\n").filter(Boolean).length : 0), 0);
  let allowedRoot = root;
  if (alias) { const link = join(mkdtempSync(join(tmpdir(), "alias-")), "parent"); symlinkSync(dirname(root), link); allowedRoot = join(link, basename(root)); }
  const activePreload = writable ? join(root, "writable-preload.mjs") : preload;
  if (writable) writeFileSync(activePreload, `const root = process.env.EVIDENCE_PACK_ISOLATION_ROOT, bundle = process.env.EVIDENCE_PACK_ISOLATION_BUNDLE; delete process.env.EVIDENCE_PACK_ISOLATION_BUNDLE; const { installIsolation } = await import(${JSON.stringify(preload)}); installIsolation(root, bundle, true);`);
  const result = spawnSync(process.env.EVIDENCE_PACK_TEST_NODE ?? process.execPath, ["--import", activePreload, target, ...args], { env: { ...process.env, PATH: process.env.PATH, HOME: join(root, "denied-home"), EVIDENCE_PACK_ISOLATION_ROOT: allowedRoot, EVIDENCE_PACK_ISOLATION_BUNDLE: realpathSync(target), NODE_OPTIONS: "--max-old-space-size=3072" }, encoding: "utf8", timeout: TIMEOUT_MS });
  return { ...result, expectedEnumerations };
}
describe("packed recipient consumer", () => {
  beforeAll(async () => { c = await functionalCandidateForTests(); }, 120_000);
  it.each(["PASS", "PARTIAL", "FAIL"])("installed bundle isolates every verdict %s with an exact enumeration count", status => {
    const r = isolated(undefined, status); expect(r.error).toBeUndefined(); expect(r.status, r.stderr + r.stdout).toBe(status === "PASS" ? C.EXIT_PASS : status === "PARTIAL" ? C.EXIT_PARTIAL : C.EXIT_FAIL);
    expect(JSON.parse(r.stdout)).toMatchObject({ status, accepted: status === "PASS" });
    expect(JSON.parse(r.stderr)).toEqual({ isolation: true, denied: 0, enumerations: r.expectedEnumerations, markerObservations: 3 });
  });
  it("installed bundle accepts a canonical root reached through a symlinked temp parent", () => { const r = isolated(undefined, "PASS", true); expect(r.status, r.stderr + r.stdout).toBe(C.EXIT_PASS); expect(JSON.parse(r.stderr)).toEqual({ isolation: true, denied: 0, enumerations: r.expectedEnumerations, markerObservations: 3 }); });
  it.each([
    'import fs from "node:fs"; fs.readFileSync(process.env.EVIDENCE_PACK_ISOLATION_ROOT+"/link");',
    'import fs from "node:fs"; fs.readFileSync(process.env.EVIDENCE_PACK_ISOLATION_ROOT+"/inside-link");',
    'import fs from "node:fs"; fs.readFileSync(process.env.EVIDENCE_PACK_ISOLATION_ROOT+"/parent-link/secret");',
    'import fs from "node:fs"; fs.readFileSync(process.env.EVIDENCE_PACK_ISOLATION_ROOT+"/home-alias/secret");',
    'import cp from "node:child_process"; cp.spawnSync("/bin/true", []);',
    'import cp from "node:child_process"; cp.execFileSync("python3", ["-c", "print(1)"]);',
    'import net from "node:net"; net.connect(80,"127.0.0.1");',
    'import http2 from "node:http2"; http2.connect("http://127.0.0.1");',
    'import http2 from "node:http2"; http2.createServer();',
    'import https from "node:https"; https.get("https://127.0.0.1");',
    'import tls from "node:tls"; tls.connect(443,"127.0.0.1");',
    'import dgram from "node:dgram"; dgram.createSocket("udp4");',
    'import inspector from "node:inspector"; inspector.open();',
    'import workers from "node:worker_threads"; new workers.Worker("", {eval:true});',
    'await fetch("https://example.invalid");',
    'import fs from "node:fs"; fs.readFileSync(process.env.HOME+"/secret");',
    'import fs from "node:fs"; await fs.openAsBlob(process.env.HOME+"/secret");',
    'import fs from "node:fs"; fs.globSync(process.env.HOME+"/*");',
    'import fs from "node:fs/promises"; for await (const entry of fs.glob(process.env.HOME+"/*")) void entry;',
    'import fs from "node:fs"; process.chdir(process.env.EVIDENCE_PACK_ISOLATION_ROOT); fs.globSync("pack", { cwd: process.env.HOME });',
    'import fs from "node:fs"; fs.globSync([process.env.EVIDENCE_PACK_ISOLATION_ROOT+"/pack", process.env.HOME+"/*"]);',
    'import fs from "node:fs/promises"; process.chdir(process.env.EVIDENCE_PACK_ISOLATION_ROOT); for await (const entry of fs.glob("pack", { cwd: process.env.HOME })) void entry;',
    'import fs from "node:fs"; fs.watch(process.env.HOME).close();',
    'import fs from "node:fs"; fs.watchFile(process.env.HOME+"/secret", () => undefined);',
    'import fs from "node:fs"; fs.statfsSync(process.env.HOME);',
    'import fs from "node:fs"; fs.utimesSync(process.env.EVIDENCE_PACK_ISOLATION_ROOT+"/pack", 0, 0);',
    'import fs from "node:fs/promises"; await fs.readFile("/tmp/operator/.sanctuary/state");',
    'import cp from "node:child_process"; cp.execFileSync("/usr/bin/env", ["python3", "-c", "print(1)"]);',
    // These rows cover computed dynamic import specifiers and createRequire loads of builtin modules, each of which the runtime mediation must deny.
    'const name = ["node", "net"].join(":"); const net = await import(name); net.connect(80, "127.0.0.1");',
    'const name = ["node", "child_process"].join(":"); const cp = await import(name); cp.spawnSync("/bin/true", []);',
    'import { createRequire } from "node:module"; createRequire(import.meta.url)("node:net").connect(80, "127.0.0.1");',
    'import { createRequire } from "node:module"; createRequire(import.meta.url)("node:child_process").execFileSync("/usr/bin/env", ["true"]);',
  ])("isolation detects forbidden reach %s", attack => { const r = isolated(attack); expect(r.status).toBe(1); expect(r.stderr).toContain('"denied":1'); });
  it("package contains exactly its allowlisted bundle provenance and notices", async () => {
    const c = await candidateForTests();
    const files = c.packed.files.map((f: { path: string }) => f.path).sort();
    // Must match NON_RELEASE_MARKER written by buildCandidate in scripts/build-evidence-pack.mjs: only a fixture build packs the marker.
    expect(files).toEqual(["LICENSE", "README.md", "THIRD_PARTY_NOTICES.md", "dist/check-evidence-pack-artifact.js", "dist/provenance.json", "dist/verify-evidence-pack.js", "package.json", ...(c.fixture ? ["dist/NON_RELEASE"] : [])].sort());
    const pkg = JSON.parse(readFileSync(join(dirname(realpathSync(c.command)), "../package.json"), "utf8"));
    expect(pkg).toMatchObject({ private: true, author: "Erik Newton", license: "Apache-2.0", engines: { node: ">=22.0.0" }, bin: { "verify-evidence-pack": "dist/verify-evidence-pack.js", "check-evidence-pack-artifact": "dist/check-evidence-pack-artifact.js" } }); expect(pkg.dependencies).toBeUndefined(); expect(pkg.scripts).toBeUndefined();
    const bundle = readFileSync(c.command, "utf8"); expect(bundle).not.toMatch(FORBIDDEN_BUNDLE);
  });
  it("candidate workflow has read-only authority and immutable actions", () => {
    const source = readFileSync(resolve("../.github/workflows/evidence-pack-candidate.yml"), "utf8");
    expect(source).toMatch(/^permissions:\n  contents: read$/m); expect(source).toMatch(/^  pull_request:$/m); expect(source).toMatch(/^  workflow_dispatch:$/m);
    expect(source).not.toMatch(/npm publish|id-token:|secrets\.|NODE_AUTH_TOKEN|pull_request_target:|^  push:/m);
    const refs = [...source.matchAll(/uses: ([^\s#]+)/g)].map(x => x[1]); expect(refs.length).toBeGreaterThan(0); expect(refs.every(x => /@[0-9a-f]{40}$/.test(x))).toBe(true);
  });
  it("public recipient and drill text state signed-set bounds with no claimed run", () => {
    for (const name of ["../docs/evidence-pack-recipient-v0.md", "../docs/audit/evidence-pack-v0-drill.md", "../packages/evidence-pack-verifier/README.md"]) { const text = readFileSync(name, "utf8"); expect(text).not.toContain(String.fromCharCode(0x2014)); expect(text).toContain("outside the signed set"); expect(text).toContain("Darwin"); expect(text).not.toMatch(PUBLIC_TEXT_FORBIDDEN); }
    expect(readFileSync("../docs/audit/evidence-pack-v0-drill.md", "utf8")).toContain("No second-Mac results have been recorded.");
  });
});

it("synthetic fixture creates advances and exports through one isolated producer bundle", async () => {
  c ??= await functionalCandidateForTests();
  mkdirSync("/tmp/v70", { recursive: true, mode: 0o700 }); const root = "/tmp/v70/test-" + randomUUID(); mkdirSync(root, { mode: 0o700 });
  const script = join(c.tree, "server/evidence-pack-dist/evidence-pack-drill-fixture.js");
  const run = (args: string[]) => spawnSync(process.execPath, [script, args[0], "--root", root, ...args.slice(1)], { encoding: "utf8", timeout: TIMEOUT_MS, env: { ...process.env, HOME: root + "/home" } });
  for (const args of [["create"], ["export", "--name", "pack-stale"], ["advance"], ["export", "--name", "pack"], ["export", "--name", "pack-other"]]) { const r = run(args); expect(r.status, r.stderr).toBe(0); expect(r.stderr).toContain('"denied":0'); }
  expect(run(["create"]).status).toBe(1);
  const tamper = spawnSync("python3", ["scripts/evidence-pack-drill-tamper.py", "--source", join(root, "pack"), "--output", join(root, "tamper")], { encoding: "utf8", timeout: TIMEOUT_MS }); expect(tamper.status, tamper.stderr).toBe(0);
  expect(verifyAuditChainContent(readFileSync(join(root, "tamper/shortened-file", C.AUDIT_FILENAME), "utf8"), { publicKey: readFileSync(join(root, "pack-key.txt"), "utf8").trim() }).verdict).toBe("PASS");
  for (const [key, trust, code] of [["wrong-key.txt", "pack-trust.json", C.HARD.pin_invalid], ["wrong-key.txt", "pack-wrong-trust.json", C.HARD.manifest_signature_invalid]]) {
    const receipt = JSON.parse(readFileSync(join(root, "pack-receipt.json"), "utf8"));
    const result = spawnSync(process.execPath, [c.command, "--pack", join(root, "pack"), "--public-key-file", join(root, key), "--trust-descriptor-file", join(root, trust), "--expect-manifest-digest", receipt.manifest_digest, "--json"], { encoding: "utf8", timeout: TIMEOUT_MS });
    expect(result.status).toBe(C.EXIT_FAIL); expect(JSON.parse(result.stdout).findings[0].code).toBe(code);
  }
  const stale = JSON.parse(readFileSync(join(root, "pack-stale-receipt.json"), "utf8")), current = JSON.parse(readFileSync(join(root, "pack-receipt.json"), "utf8")); expect(stale.manifest_digest).not.toBe(current.manifest_digest);
  for (const name of ["pack-stale", "pack", "pack-other"]) { const receipt = JSON.parse(readFileSync(join(root, name + "-receipt.json"), "utf8")); const r = spawnSync(process.execPath, [c.command, "--pack", join(root, name), "--public-key-file", join(root, "pack-key.txt"), "--trust-descriptor-file", join(root, name + "-trust.json"), "--expect-manifest-digest", receipt.manifest_digest, "--json"], { encoding: "utf8", timeout: TIMEOUT_MS }); expect(r.status, r.stderr + r.stdout).toBe(0); expect(JSON.parse(r.stdout)).toMatchObject({ status: "PASS", accepted: true }); }
}, 120_000);

import { rootPath } from "../../scripts/evidence-pack-drill-fixture.js";
import { vi } from "vitest";
vi.mock("node:fs/promises", async importOriginal => ({ ...await importOriginal<typeof import("node:fs/promises")>() }));
import { createRequire } from "node:module";
const yaml = createRequire(import.meta.url)("js-yaml") as { load: (text: string) => { permissions: unknown; on: Record<string, unknown>; jobs: Record<string, { permissions?: unknown; steps: { run?: string; uses?: string }[] }> } };
function workflowPolicy(source: string) {
  const workflow = yaml.load(source);
  expect(workflow.permissions).toEqual({ contents: "read" }); expect(Object.keys(workflow.on).sort()).toEqual(["pull_request", "workflow_dispatch"]);
  for (const job of Object.values(workflow.jobs)) {
    expect(job.permissions).toBeUndefined();
    for (const step of job.steps) {
      expect(step.run ?? "").not.toMatch(/\bnpm\s+(?:pub\w*|publish)\b|\bgh\s+release\s+(?:upload|create)\b|\byarn\s+(?:npm\s+)?publish\b|\bpnpm\s+publish\b/);
      if (step.uses) expect(step.uses).toMatch(/@[0-9a-f]{40}$/);
    }
  }
}
it("parsed candidate workflow restricts every job and publication command", () => { workflowPolicy(readFileSync(resolve("../.github/workflows/evidence-pack-candidate.yml"), "utf8")); });
it.each(["job-authority", "npm-alias", "release-upload"])("workflow policy rejects %s", kind => {
  const source = readFileSync(resolve("../.github/workflows/evidence-pack-candidate.yml"), "utf8");
  const mutation = kind === "job-authority" ? source.replace("    runs-on:", "    permissions: { contents: write }\n    runs-on:") : source.replace("          npm ci", `          ${kind === "npm-alias" ? "npm pub" : "gh release upload v1 file"}\n          npm ci`);
  expect(() => workflowPolicy(mutation)).toThrow();
});
it("both workflow runtimes use the packed descriptor and dispatch restricts refs", () => {
  const source = readFileSync(resolve("../.github/workflows/evidence-pack-candidate.yml"), "utf8");
  expect(source).toContain("EVIDENCE_PACK_TEST_CANDIDATE: /tmp/c13/artifact/test-candidate.json");
  expect(source.indexOf("Install packed candidate and record descriptor")).toBeLessThan(source.indexOf("Test packed candidate on Node 22"));
  expect(source).toContain("refs/heads/main|refs/tags/v*"); expect(source).toContain('*) exit 1');
  expect(source).toContain('non_release:process.env.CANDIDATE_EVENT === "pull_request"'); expect(source).toContain("evidence-pack-nonrelease-");
  expect(source.match(/env -u SANCTUARY_SOURCE_SHA npx vitest run/g)).toHaveLength(2);
});
it.each(["parent-link", "root-link", "parent-mode", "root-mode", "parent-owner", "root-owner"])("fixture root refuses %s before writes", async kind => {
  const base = mkdtempSync(join(tmpdir(), "root-boundary-")), allowed = join(base, "allowed"), root = join(allowed, "root"), other = join(base, "other");
  mkdirSync(other, { mode: 0o700 });
  if (kind === "parent-link") symlinkSync(other, allowed); else mkdirSync(allowed, { mode: 0o700 });
  if (kind === "root-link") symlinkSync(other, root); else mkdirSync(root, { mode: 0o700 });
  if (kind.endsWith("mode")) chmodSync(kind === "parent-mode" ? allowed : root, 0o755);
  const stat = vi.spyOn(await import("node:fs/promises"), "lstat");
  if (kind.endsWith("owner")) {
    const native = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
    stat.mockImplementation(async (...args: Parameters<typeof native.lstat>) => { const result = await Reflect.apply(native.lstat, native, args); if (String(args[0]) === (kind === "parent-owner" ? allowed : root)) Object.assign(result, { uid: Number(result.uid) + 1 }); return result; });
  }
  try { await expect(rootPath(root, allowed)).rejects.toThrow(); } finally { stat.mockRestore(); }
});
it("fixture root accepts private owned directories beneath a symlinked temp ancestor", async () => {
  const base = mkdtempSync(join(tmpdir(), "root-positive-")), allowed = join(base, "allowed"), root = join(allowed, "root"), link = join(base, "alias");
  mkdirSync(allowed, { mode: 0o700 }); mkdirSync(root, { mode: 0o700 }); symlinkSync(allowed, link);
  expect(await rootPath(join(link, "root"), allowed)).toBe(realpathSync(root)); expect(lstatSync(root).isDirectory()).toBe(true);
});

// Must match the runtime denials in scripts/evidence-pack-drill-isolation.ts.
const FORBIDDEN_BUNDLE = /createSanctuaryServer|FilesystemStorage|installInMemoryKeychainStore|from ["']@|from ["'](?:node:)?(?:net|tls|http|http2|https|dns|dgram|inspector|worker_threads)["']/;
it.each(["http2", "https", "tls", "dgram", "inspector", "worker_threads"])("bundle import guard rejects node:%s", name => { expect(`import module from "node:${name}";`).toMatch(FORBIDDEN_BUNDLE); });

it.each([["workflow_dispatch", "refs/heads/main", 0], ["workflow_dispatch", "refs/tags/v1", 0], ["workflow_dispatch", "refs/heads/topic", 1], ["pull_request", "refs/pull/1/merge", 0]])("candidate ref guard handles %s %s", (event, ref, exit) => {
  const workflow = yaml.load(readFileSync(resolve("../.github/workflows/evidence-pack-candidate.yml"), "utf8"));
  const source = workflow.jobs.candidate.steps.find(step => step.run?.includes('case "$CANDIDATE_REF"'))?.run ?? "";
  const guard = source.match(/if \[ "\$CANDIDATE_EVENT"[^]*?\nfi/)?.[0]; expect(guard).toBeDefined();
  // The shell witness retains the test marker so child processes stay within the test isolation policy.
  expect(spawnSync("/bin/sh", ["-c", guard!], { env: { ...process.env, CANDIDATE_EVENT: String(event), CANDIDATE_REF: String(ref) } }).status).toBe(exit);
});
it("public procedure supplies complete synthetic pins and platform bounds", () => {
  const drill = readFileSync("../docs/audit/evidence-pack-v0-drill.md", "utf8"), recipient = readFileSync("../docs/evidence-pack-recipient-v0.md", "utf8"), readme = readFileSync("../packages/evidence-pack-verifier/README.md", "utf8");
  expect(drill).toContain('test ! -L /tmp/v70'); expect(drill).toContain('mkdir -m 700 /tmp/v70'); expect(drill).toContain('npm run build:evidence-pack');
  expect(drill).toContain("['pack-key.txt', 'wrong-key.txt']"); expect(drill).toContain("root / 'pack-wrong-trust.json'");
  for (const text of [recipient, readme]) { expect(text).toContain('/usr/bin/xattr'); expect(text).toContain('/usr/bin/python3'); expect(text).toContain('enumerator_unavailable'); expect(text).toContain('changed and restored'); expect(text).toContain('--offline'); }
});

const PUBLIC_TEXT_FORBIDDEN = /\.(?:[cm]?[jt]s|py):\d+|#L\d+|defect|bypass|drill passed/i;
it.each(["example.py:12", "example.ts:12", "example#L12"])("documentation anchor guard recognizes %s", anchor => { expect(anchor).toMatch(PUBLIC_TEXT_FORBIDDEN); });
it("isolation refuses value lookup output even with the permitted executable", async () => {
  c ??= await functionalCandidateForTests();
  const { METADATA_TIMEOUT_MS, METADATA_OUTPUT_LIMIT } = await import("../../src/evidence-pack/snapshot-offline-cli.js");
  const attack = `import cp from "node:child_process"; cp.spawnSync("/usr/bin/xattr", ["-s", "-p", "com.apple.provenance", process.env.EVIDENCE_PACK_ISOLATION_ROOT+"/key"], {env:{LC_ALL:"C"},shell:false,timeout:${METADATA_TIMEOUT_MS},maxBuffer:${METADATA_OUTPUT_LIMIT},stdio:["ignore","pipe","ignore"]});`;
  const result = isolated(attack); expect(result.status).toBe(C.EXIT_FAIL); expect(result.stderr).toContain('"denied":1');
}, 120_000);

// Must match the parent prerequisite block in docs/audit/evidence-pack-v0-drill.md.
it.each(["mkdir", "owner", "mode", "valid"])("drill shell parent prerequisite handles %s", kind => {
  const doc = readFileSync("../docs/audit/evidence-pack-v0-drill.md", "utf8");
  const block = doc.slice(doc.indexOf("test ! -L /tmp/v70"), doc.indexOf("mkdir -m 700 /tmp/v70/mac-a"));
  const root = mkdtempSync(join(tmpdir(), "doc-parent-")), parent = join(root, "v70");
  if (kind !== "mkdir") mkdirSync(parent);
  const script = `mkdir() { command mkdir "$@"; return 1; }
stat() { case "$2" in %u) printf '%s' '${kind === "owner" ? "wrong-owner" : process.getuid!()}' ;; %Lp) printf '%s' '${kind === "mode" ? "755" : "700"}' ;; esac; }
${block.replaceAll("/tmp/v70", parent)}
printf reached`;
  const result = spawnSync("/bin/sh", ["-c", script], { env: { ...process.env }, encoding: "utf8" });
  expect(result.status).toBe(kind === "valid" ? C.EXIT_PASS : C.EXIT_FAIL);
  expect(result.stdout).toBe(kind === "valid" ? "reached" : "");
});

it.each([false, true])("isolation refuses legacy exporter argv with writable %s", async writable => {
  c ??= await functionalCandidateForTests();
  const { METADATA_TIMEOUT_MS, METADATA_OUTPUT_LIMIT, LINUX_METADATA_PROGRAM } = await import("../../src/evidence-pack/snapshot-offline-cli.js");
  for (const [command, prefix] of [["/usr/bin/xattr", []], ["/usr/bin/xattr", ["-p", "com.apple.provenance"]], ["python3", ["-c", LINUX_METADATA_PROGRAM]]] as const) {
    const attack = `import cp from "node:child_process"; cp.execFile(${JSON.stringify(command)}, [...${JSON.stringify(prefix)}, process.env.EVIDENCE_PACK_ISOLATION_ROOT+"/key"], {env:{LC_ALL:"C"},shell:false,timeout:${METADATA_TIMEOUT_MS},maxBuffer:${METADATA_OUTPUT_LIMIT},stdio:"ignore"}, () => {});`;
    const result = isolated(attack, "PASS", false, writable);
    expect(result.stderr).toContain('"denied":1'); expect(result.status).toBe(C.EXIT_FAIL);
  }
}, 120_000);

it.each([false, true])("isolation refuses synchronous legacy exporter argv with closed options and writable %s", async writable => {
  c ??= await functionalCandidateForTests();
  const { METADATA_TIMEOUT_MS, METADATA_OUTPUT_LIMIT, LINUX_METADATA_PROGRAM } = await import("../../src/evidence-pack/snapshot-offline-cli.js");
  // Each row uses an admitted subprocess key and the closed listing options, so only the exact argv shape can refuse it.
  const closed = `{env:{LC_ALL:"C"},shell:false,timeout:${METADATA_TIMEOUT_MS},maxBuffer:${METADATA_OUTPUT_LIMIT},stdio:["ignore","pipe","ignore"]}`;
  for (const [key, command, prefix] of [["execFileSync", "/usr/bin/xattr", []], ["spawnSync", "/usr/bin/xattr", ["-p", "com.apple.provenance"]], ["execFileSync", "/usr/bin/python3", ["-c", LINUX_METADATA_PROGRAM]]] as const) {
    const attack = `import cp from "node:child_process"; cp.${key}(${JSON.stringify(command)}, [...${JSON.stringify(prefix)}, process.env.EVIDENCE_PACK_ISOLATION_ROOT+"/key"], ${closed});`;
    const result = isolated(attack, "PASS", false, writable);
    expect(result.stderr).toContain('"denied":1'); expect(result.status).toBe(C.EXIT_FAIL);
  }
}, 120_000);
