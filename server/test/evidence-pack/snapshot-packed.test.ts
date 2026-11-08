import { beforeAll, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, realpathSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { join, resolve, dirname } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
// @ts-expect-error The build script is JavaScript and intentionally has no declaration artifact.
import { candidateForTests } from "../../scripts/build-evidence-pack.mjs";
import { fixture } from "./snapshot-fixtures.js";
import { verifyAuditChainContent } from "../../src/cli/audit-chain-verify.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";
let c: Awaited<ReturnType<typeof candidateForTests>>;
const TIMEOUT_MS = 30_000;
const ROOT_AND_MANIFEST_LISTINGS = 2;
beforeAll(async () => { c = await candidateForTests(); }, 120_000);
function isolated(attack?: string) {
  const f = fixture(), root = mkdtempSync(join(tmpdir(), "isolated-")), pack = join(root, "pack"); mkdirSync(pack);
  for (const file of f.capture.files) writeFileSync(join(pack, Buffer.from(file.name).toString()), file.bytes);
  writeFileSync(join(root, "key"), f.pins.packKey); writeFileSync(join(root, "trust"), f.pins.descriptorBytes);
  const preload = join(c.tree, "server/evidence-pack-dist/evidence-pack-drill-isolation.js");
  const target = attack ? join(root, "attack.mjs") : c.command;
  if (attack) writeFileSync(target, attack);
  const args = attack ? [] : ["--pack", pack, "--public-key-file", join(root, "key"), "--trust-descriptor-file", join(root, "trust"), "--expect-manifest-digest", f.pins.expectedManifestDigest, "--json"];
  return spawnSync(process.env.EVIDENCE_PACK_TEST_NODE ?? process.execPath, ["--import", preload, target, ...args], { env: { ...process.env, PATH: process.env.PATH, HOME: join(root, "denied-home"), EVIDENCE_PACK_ISOLATION_ROOT: root, EVIDENCE_PACK_ISOLATION_BUNDLE: realpathSync(target), NODE_OPTIONS: "--max-old-space-size=3072" }, encoding: "utf8", timeout: TIMEOUT_MS });
}
describe("packed recipient consumer", () => {
  it("installed bundle accepts with no network keychain HOME or storage access", () => { const r = isolated(); expect(r.error).toBeUndefined(); expect(r.status, r.stderr + r.stdout).toBe(0); expect(JSON.parse(r.stdout)).toMatchObject({ status: "PASS", accepted: true, exit_code: 0 }); const observed = JSON.parse(r.stderr); expect(observed).toMatchObject({ isolation: true, denied: 0 }); const listings = Object.keys(C.FIXED_FILES).length + ROOT_AND_MANIFEST_LISTINGS; if (process.platform === "linux") expect(observed.enumerations).toBe(listings); else { expect(observed.enumerations).toBeGreaterThanOrEqual(listings); expect(observed.enumerations).toBeLessThanOrEqual(listings * (1 + C.OS_ATTACHED_METADATA.length)); } });
  it.each([
    'import cp from "node:child_process"; cp.spawnSync("/bin/true", []);',
    'import cp from "node:child_process"; cp.execFileSync("python3", ["-c", "print(1)"]);',
    'import net from "node:net"; net.connect(80,"127.0.0.1");',
    'await fetch("https://example.invalid");',
    'import fs from "node:fs"; fs.readFileSync(process.env.HOME+"/secret");',
    'import fs from "node:fs/promises"; await fs.readFile("/tmp/operator/.sanctuary/state");',
    'import cp from "node:child_process"; cp.execFileSync("/usr/bin/env", ["python3", "-c", "print(1)"]);',
  ])("isolation detects forbidden reach %s", attack => { const r = isolated(attack); expect(r.status).toBe(1); expect(r.stderr).toContain('"denied":1'); });
  it("package contains exactly its allowlisted bundle provenance and notices", () => {
    const files = c.packed.files.map((f: { path: string }) => f.path).sort();
    expect(files).toEqual(["LICENSE", "README.md", "THIRD_PARTY_NOTICES.md", "dist/provenance.json", "dist/verify-evidence-pack.js", "package.json"].sort());
    const pkg = JSON.parse(readFileSync(join(dirname(realpathSync(c.command)), "../package.json"), "utf8"));
    expect(pkg).toMatchObject({ private: true, author: "Erik Newton", license: "Apache-2.0", engines: { node: ">=22.0.0" }, bin: { "verify-evidence-pack": "dist/verify-evidence-pack.js" } }); expect(pkg.dependencies).toBeUndefined(); expect(pkg.scripts).toBeUndefined();
    const bundle = readFileSync(c.command, "utf8"); expect(bundle).not.toMatch(/createSanctuaryServer|FilesystemStorage|installInMemoryKeychainStore|from ["']@|from ["'](?:node:)?(?:net|tls|http|https|dns|dgram|worker_threads)["']/);
  });
  it("candidate workflow has read-only authority and immutable actions", () => {
    const source = readFileSync(resolve("../.github/workflows/evidence-pack-candidate.yml"), "utf8");
    expect(source).toMatch(/^permissions:\n  contents: read$/m); expect(source).toMatch(/^  pull_request:$/m); expect(source).toMatch(/^  workflow_dispatch:$/m);
    expect(source).not.toMatch(/npm publish|id-token:|secrets\.|NODE_AUTH_TOKEN|pull_request_target:|^  push:/m);
    const refs = [...source.matchAll(/uses: ([^\s#]+)/g)].map(x => x[1]); expect(refs.length).toBeGreaterThan(0); expect(refs.every(x => /@[0-9a-f]{40}$/.test(x))).toBe(true);
  });
  it("public recipient and drill text state signed-set bounds with no claimed run", () => {
    for (const name of ["../docs/evidence-pack-recipient-v0.md", "../docs/audit/evidence-pack-v0-drill.md"]) { const text = readFileSync(name, "utf8"); expect(text).not.toContain(String.fromCharCode(0x2014)); expect(text).toContain("outside the signed set"); expect(text).toContain("Darwin"); expect(text).not.toMatch(/\.[cm]?[jt]s:\d+|defect|bypass|drill passed/i); }
    expect(readFileSync("../docs/audit/evidence-pack-v0-drill.md", "utf8")).toContain("No second-Mac results have been recorded.");
  });
});

it("synthetic fixture creates advances and exports through one isolated producer bundle", () => {
  mkdirSync("/tmp/v70", { recursive: true, mode: 0o700 }); const root = "/tmp/v70/test-" + randomUUID();
  const script = join(c.tree, "server/evidence-pack-dist/evidence-pack-drill-fixture.js");
  const run = (args: string[]) => spawnSync(process.execPath, [script, args[0], "--root", root, ...args.slice(1)], { encoding: "utf8", timeout: TIMEOUT_MS, env: { ...process.env, HOME: root + "/home" } });
  for (const args of [["create"], ["export", "--name", "pack-stale"], ["advance"], ["export", "--name", "pack"], ["export", "--name", "pack-other"]]) { const r = run(args); expect(r.status, r.stderr).toBe(0); expect(r.stderr).toContain('"denied":0'); }
  expect(run(["create"]).status).toBe(1);
  const tamper = spawnSync("python3", ["scripts/evidence-pack-drill-tamper.py", "--source", join(root, "pack"), "--output", join(root, "tamper")], { encoding: "utf8", timeout: TIMEOUT_MS }); expect(tamper.status, tamper.stderr).toBe(0);
  expect(verifyAuditChainContent(readFileSync(join(root, "tamper/shortened-file", C.AUDIT_FILENAME), "utf8"), { publicKey: readFileSync(join(root, "pack-key.txt"), "utf8").trim() }).verdict).toBe("PASS");
  const stale = JSON.parse(readFileSync(join(root, "pack-stale-receipt.json"), "utf8")), current = JSON.parse(readFileSync(join(root, "pack-receipt.json"), "utf8")); expect(stale.manifest_digest).not.toBe(current.manifest_digest);
  for (const name of ["pack-stale", "pack", "pack-other"]) { const receipt = JSON.parse(readFileSync(join(root, name + "-receipt.json"), "utf8")); const r = spawnSync(process.execPath, [c.command, "--pack", join(root, name), "--public-key-file", join(root, "pack-key.txt"), "--trust-descriptor-file", join(root, name + "-trust.json"), "--expect-manifest-digest", receipt.manifest_digest, "--json"], { encoding: "utf8", timeout: TIMEOUT_MS }); expect(r.status, r.stderr + r.stdout).toBe(0); expect(JSON.parse(r.stdout)).toMatchObject({ status: "PASS", accepted: true }); }
}, 120_000);
