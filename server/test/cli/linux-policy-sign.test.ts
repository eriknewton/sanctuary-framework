/** Workstation signing binds explicit Linux identity before publishing bytes. */
import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { buildInstallBundle } from "../../src/cli/linux-policy-sign.js";
import { castleWallSigningKeyId, verifyManifestSignature } from "../../src/castle-wall/allowlist/parse.js";
import type { SignedManifest } from "../../src/castle-wall/allowlist/manifest.js";
import { composeEffectiveRules } from "../../src/castle-wall/allowlist/habeas-port.js";
import { buildSignedManifest } from "../../src/castle-wall/runtime/manifest-publisher.js";

const seed = new Uint8Array(32).fill(7);
const publicKey = ed25519.getPublicKey(seed);
const signer = { signingKeyId: castleWallSigningKeyId(publicKey), sign: (b: Uint8Array) => ed25519.sign(b, seed) };
const input = { fortressId: "0123456789abcdef", generation: 10, issuedAt: "2026-10-01T00:00:00Z", rules: [], signer, agentOrigin: { mode: "uid", agent_uid: 60123, system_uid_allow_ceiling: 1000 } };
describe("install policy signer", () => {
  it("uses the existing producer's exact manifest bytes", async () => {
    const bundle = await buildInstallBundle(input, publicKey);
    const signed = JSON.parse(Buffer.from(bundle.manifest_b64url, "base64url").toString()) as SignedManifest;
    expect(signed).toEqual((await buildSignedManifest({ ...input, rules: composeEffectiveRules({ operatorRules: [], resolvers: [], createdAt: input.issuedAt }) })).signed);
    expect(verifyManifestSignature(signed, publicKey).ok).toBe(true);
    expect(bundle.rules).toHaveLength(1);
  });
  it.each([undefined, null, {}, { mode: "nat", system_uid_allow_ceiling: 1000 }, { mode: "uid", agent_uid: 0, system_uid_allow_ceiling: 1000 }, { mode: "uid", agent_uid: 60123, gate_uid: 60125, system_uid_allow_ceiling: 1000 }])("refuses absent or unusable origin before signing: %j", async (agentOrigin) => {
    let calls = 0;
    await expect(buildInstallBundle({ ...input, agentOrigin, signer: { ...signer, sign: () => { calls++; return new Uint8Array(64); } } }, publicKey)).rejects.toThrow();
    expect(calls).toBe(0);
  });
  it.each([undefined, 0, -1, Number.MAX_SAFE_INTEGER + 1, 1.5])("refuses invalid generation %s", async (generation) => {
    await expect(buildInstallBundle({ ...input, generation }, publicKey)).rejects.toThrow();
  });
  it("refuses an invalid emitted signature", async () => {
    await expect(buildInstallBundle({ ...input, signer: { ...signer, sign: () => new Uint8Array(64) } }, publicKey)).rejects.toThrow("emitted manifest identity refused");
  });
  it("bounds the complete encoded bundle", async () => {
    const rules = Array.from({ length: 160 }, (_, i) => ({ id: `bounded-${i}`, schema_version: 1 as const, created_at: input.issuedAt, description: "x".repeat(1024), match: { ip: "127.0.0.1", port: 41003, protocol: "tcp" as const }, scope: {}, disposition: "allow" as const }));
    await expect(buildInstallBundle({ ...input, rules }, publicKey)).rejects.toThrow("policy bundle exceeds quota");
  });
  it("requires the existing fortress grammar before invoking the signer", async () => {
    let calls = 0;
    await expect(buildInstallBundle({ ...input, fortressId: "NOT_A_FORTRESS", signer: { ...signer, sign: () => { calls++; return new Uint8Array(64); } } }, publicKey)).rejects.toThrow();
    expect(calls).toBe(0);
  });
  it("refuses Linux-incompatible rules before signing", async () => {
    const rules = [{ id: "test", schema_version: 1 as const, created_at: input.issuedAt, match: { host: "example.com" }, scope: {}, disposition: "allow" as const }];
    await expect(buildInstallBundle({ ...input, rules }, publicKey)).rejects.toThrow();
  });
});

// The package's real executable is the consumer: npm-style links and inherited fd 3 must work.
import { mkdtempSync, writeFileSync, openSync, closeSync, readFileSync, symlinkSync, existsSync, rmSync, chmodSync, mkdirSync, statSync, realpathSync } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
it("the packaged entry signs through an npm-style link and refuses key/output custody faults", () => {
  const dir = mkdtempSync(join(tmpdir(), "linux-policy-sign-"));
  try {
    const key = join(dir, "seed"); writeFileSync(key, seed, { mode: 0o600 });
    const rules = join(dir, "rules.json"); writeFileSync(rules, "[]");
    const entry = join(dir, "sign"); symlinkSync(resolve("bin/sanctuary-linux-policy-sign"), entry);
    const output = join(dir, "bundle.json");
    const argv = ["--fortress-id", input.fortressId, "--agent-uid", "60123", "--system-uid-ceiling", "1000", "--generation", "10", "--rules", rules, "--key-fd", "3", "--output", output];
    const run = (fd: number, args = argv) => spawnSync(entry, args, { stdio: ["ignore", "pipe", "pipe", fd], timeout: 10_000 });
    const fd = openSync(key, "r");
    try {
      const signedResult = run(fd);
      expect(signedResult.status, signedResult.stderr?.toString()).toBe(0);
      const bundle = JSON.parse(readFileSync(output, "utf8"));
      const signed = JSON.parse(Buffer.from(bundle.manifest_b64url, "base64url").toString()) as SignedManifest;
      expect(verifyManifestSignature(signed, publicKey).ok).toBe(true);
      const before = readFileSync(output);
      expect(run(fd).status).not.toBe(0);
      expect(readFileSync(output)).toEqual(before);
      const linkedOutput = join(dir, "linked.json"); symlinkSync(output, linkedOutput);
      expect(run(fd, argv.map(a => a === output ? linkedOutput : a)).status).not.toBe(0);
      const bad = join(dir, "bad.json");
      expect(run(fd, argv.map(a => a === output ? bad : a === "3" ? "0" : a)).status).not.toBe(0);
      expect(existsSync(bad)).toBe(false);
    } finally { closeSync(fd); }
    for (const size of [31, 33]) {
      const wrong = join(dir, `seed-${size}`); writeFileSync(wrong, Buffer.alloc(size, 7), { mode: 0o600 });
      const wrongFd = openSync(wrong, "r");
      try { expect(run(wrongFd, argv.map(a => a === output ? join(dir, `wrong-${size}`) : a)).status).not.toBe(0); } finally { closeSync(wrongFd); }
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

it("refuses the install profile's inclusive system uid ceiling", async () => {
  await expect(buildInstallBundle({ ...input, agentOrigin: { mode: "uid", agent_uid: 1000, system_uid_allow_ceiling: 1000 } }, publicKey)).rejects.toThrow("uid");
});
it("the packaged signer ignores PATH helpers while holding the key descriptor", () => {
  const dir = mkdtempSync(join(tmpdir(), "signer-path-"));
  try {
    const marker = join(dir, "helper-ran");
    for (const name of ["node", "perl", "readlink", "dirname", "stat", "uname"]) writeFileSync(join(dir, name), `#!/bin/sh\nprintf leaked > '${marker}'\nexit 91\n`, { mode: 0o755 });
    const key = join(dir, "seed"); writeFileSync(key, seed, { mode: 0o600 });
    const rules = join(dir, "rules"); writeFileSync(rules, "[]");
    const fd = openSync(key, "r");
    try {
      const result = spawnSync(resolve("bin/sanctuary-linux-policy-sign"), ["--fortress-id", input.fortressId, "--agent-uid", "60123", "--system-uid-ceiling", "1000", "--generation", "10", "--rules", rules, "--key-fd", "3", "--output", join(dir, "out")], { env: { ...process.env, PATH: dir }, stdio: ["ignore", "pipe", "pipe", fd], timeout: 10_000 });
      expect(existsSync(marker)).toBe(false);
      expect(result.status, result.stderr?.toString()).toBe(0);
      // Exercise the packaged resolver with a private candidate, without changing
      // system installations: writable/user-owned ancestors must never grant custody.
      const launcher = readFileSync(resolve("bin/sanctuary-linux-policy-sign"), "utf8");
      const unsafeEntry = join(dir, "unsafe-sign");
      const candidates = `qw(${join(dir, "node")})`;
      writeFileSync(unsafeEntry, launcher.replace(/qw\(\/usr\/local\/bin\/node \/opt\/homebrew\/bin\/node\)/, candidates)
        .replace(/qw\(\/usr\/bin\/node \/usr\/local\/bin\/node\)/, candidates), { mode: 0o755 });
      const refused = spawnSync(unsafeEntry, [], { stdio: ["ignore", "pipe", "pipe", fd], timeout: 10_000 });
      expect(refused.status).toBe(1);
      expect(existsSync(marker)).toBe(false);
    } finally { closeSync(fd); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
it("direct invocation requires both inherited core limits to be zero", () => {
  const dir = mkdtempSync(join(tmpdir(), "signer-core-"));
  try {
    const key = join(dir, "seed"); writeFileSync(key, seed, { mode: 0o600 });
    const rules = join(dir, "rules"); writeFileSync(rules, "[]");
    const fd = openSync(key, "r");
    try {
      // A host that already locked the hard limit at zero cannot raise it for a
      // negative fixture. That host legitimately admits this zero/zero entry.
      const hard = spawnSync("/bin/sh", ["-c", "ulimit -H -c"], { encoding: "utf8", timeout: 1000 });
      expect(hard.status).toBe(0);
      expect(hard.stdout.trim()).toMatch(/^(?:[0-9]+|unlimited)$/);
      const result = spawnSync("/bin/sh", ["-c", 'ulimit -S -c 0; exec "$@"', "core-test", process.execPath, resolve("dist/linux-policy-sign.js"), "--fortress-id", input.fortressId, "--agent-uid", "60123", "--system-uid-ceiling", "1000", "--generation", "10", "--rules", rules, "--key-fd", "3", "--output", join(dir, "out")], { stdio: ["ignore", "pipe", "pipe", fd], timeout: 10_000 });
      const dumpsPermanentlyDisabled = hard.stdout.trim() === "0";
      expect(result.status).toBe(dumpsPermanentlyDisabled ? 0 : 1);
      expect(existsSync(join(dir, "out"))).toBe(dumpsPermanentlyDisabled);
    } finally { closeSync(fd); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// These resolver fixtures keep OS installations untouched. Only ownership and
// ancestors outside the disposable tree are modeled; access checks remain real.
function resolverFixture(launcher: string, dir: string): string {
  const perl = launcher.split("exec /usr/bin/perl -T -e '\n")[1]!.split("my @candidates")[0]!;
  const prefix = JSON.stringify(dir);
  return perl.replace("my ($path) = @_;", `my ($path) = @_; return 1 unless index($path, ${prefix}) == 0;`)
    .replace("$s[4] == 0", "$s[4] == $>");
}

it.skipIf(process.platform !== "darwin" || process.getuid?.() === 0)("kernel access checks refuse ACL-writable interpreter files and ancestors", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "signer-acl-")));
  const launcher = readFileSync(resolve("bin/sanctuary-linux-policy-sign"), "utf8");
  const perl = resolverFixture(launcher, dir);
  const aclPaths: string[] = [];
  try {
    const node = join(dir, "node");
    writeFileSync(node, "fixture", { mode: 0o555 });
    for (const path of [node, dir]) {
      chmodSync(path, 0o555);
      const rights = path === dir ? "add_file,add_subdirectory,delete_child" : "write,append";
      const acl = spawnSync("/bin/chmod", ["+a", `user:${userInfo().username} allow ${rights}`, path], { encoding: "utf8" });
      expect(acl.status, acl.stderr).toBe(0);
      aclPaths.push(path);
      expect(statSync(path).mode & 0o222).toBe(0);
      const access = spawnSync("/usr/bin/perl", ["-e", 'print((-w $ARGV[0]) ? "mode-write" : "mode-read"); { use filetest "access"; print((-w $ARGV[0]) ? ":access-write" : ":access-read"); }', path], { encoding: "utf8" });
      expect(access.stdout).toBe("mode-read:access-write");
      // Prove the ACL grants an actual mutation, not just a metadata observation.
      if (path === node) writeFileSync(node, "rewritten");
      else writeFileSync(join(dir, "child"), "created");
      const checked = spawnSync("/usr/bin/perl", ["-e", perl + '\nexit(trusted_entry($ARGV[0]) ? 91 : 0);', path], { encoding: "utf8" });
      expect(checked.status, checked.stderr).toBe(0);
      spawnSync("/bin/chmod", ["-N", path]);
    }
  } finally {
    for (const path of aclPaths) spawnSync("/bin/chmod", ["-N", path]);
    chmodSync(dir, 0o700);
    rmSync(dir, { recursive: true, force: true });
  }
});

it("the resolver checks intermediate symlink ancestors before canonicalizing", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "signer-hops-")));
  const launcher = readFileSync(resolve("bin/sanctuary-linux-policy-sign"), "utf8");
  const perl = resolverFixture(launcher, dir);
  try {
    const safe = join(dir, "safe"); mkdirSync(safe);
    const hop = join(dir, "hop"); mkdirSync(hop);
    const node = join(safe, "node"); writeFileSync(node, "fixture", { mode: 0o555 });
    symlinkSync("../safe/node", join(hop, "node"));
    symlinkSync("hop/node", join(dir, "candidate"));
    const check = () => spawnSync("/usr/bin/perl", ["-e", perl + '\nexit(defined(trusted_path($ARGV[0])) ? 0 : 1);', join(dir, "candidate")], { encoding: "utf8" });
    chmodSync(dir, 0o555); chmodSync(safe, 0o555); chmodSync(hop, 0o555);
    expect(check().status).toBe(0);
    // Group/other writes are always refused, including when tests run as root.
    chmodSync(hop, 0o777);
    const refused = check();
    expect(refused.status, refused.stderr).toBe(1);
  } finally {
    chmodSync(dir, 0o700); chmodSync(join(dir, "safe"), 0o700); chmodSync(join(dir, "hop"), 0o700);
    rmSync(dir, { recursive: true, force: true });
  }
});
