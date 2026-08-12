import { afterEach, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = join(fileURLToPath(import.meta.url), "..", "..", "..");
const serverRoot = join(repoRoot, "server");
const signer = join(repoRoot, "scripts", "sign-release-artifact.mjs");
const verifier = join(repoRoot, "scripts", "verify-release-artifact.mjs");
const dirs: string[] = [];

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "sanctuary-release-artifact-"));
  dirs.push(dir);
  const tarball = join(dir, "sanctuary-framework-mcp-server-9.8.7.tgz");
  const manifest = join(dir, "release-manifest.json");
  const packageDir = join(dir, "package");
  mkdirSync(packageDir);
  writeFileSync(join(packageDir, "package.json"), JSON.stringify({ name: "@sanctuary-framework/mcp-server", version: "9.8.7" }));
  writeFileSync(join(packageDir, "payload.bin"), randomBytes(256));
  execFileSync("tar", ["-czf", tarball, "-C", dir, "package"]);

  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateDer = privateKey.export({ format: "der", type: "pkcs8" });
  const publicDer = publicKey.export({ format: "der", type: "spki" });
  const seed = privateDer.subarray(-32).toString("base64url");
  const publicKeyB64url = publicDer.subarray(-32).toString("base64url");
  return { dir, manifest, publicKeyB64url, seed, tarball };
}

function runSigner(f: ReturnType<typeof fixture>, overrides: Record<string, string> = {}) {
  execFileSync(process.execPath, [signer, "--tarball", f.tarball, "--version", "9.8.7", "--out", f.manifest, "--expected-public-key", overrides.publicKey ?? f.publicKeyB64url], {
    env: { ...process.env, RELEASE_SIGNING_KEY: overrides.seed ?? f.seed },
    stdio: "pipe",
  });
}

function runVerifier(f: ReturnType<typeof fixture>, version = "9.8.7") {
  return execFileSync(process.execPath, [verifier, "--tarball", f.tarball, "--manifest", f.manifest, "--version", version, "--expected-public-key", f.publicKeyB64url], { stdio: "pipe" });
}

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("exact release artifact signing pipeline", () => {
  it("signs and verifies the exact tarball bytes", () => {
    const f = fixture();
    runSigner(f);
    expect(runVerifier(f).toString()).toContain("Verified sanctuary-framework-mcp-server-9.8.7.tgz");

    const realTarball = `${f.tarball}.real`;
    renameSync(f.tarball, realTarball);
    symlinkSync(realTarball, f.tarball);
    expect(() => runSigner(f)).toThrow(/tarball is not a readable regular file/);
    expect(() => runVerifier(f)).toThrow(/tarball is not a readable regular file/);
  });

  it("refuses a signing seed that does not match the shipped public key", () => {
    const f = fixture();
    const other = fixture();
    expect(() => runSigner(f, { seed: other.seed })).toThrow(/signing seed does not match/);
  });

  it("refuses tarball mutation after signing", () => {
    const f = fixture();
    runSigner(f);
    writeFileSync(f.tarball, Buffer.concat([readFileSync(f.tarball), Buffer.from("tampered")]));
    expect(() => runVerifier(f)).toThrow(/tarball hash mismatch|not a bounded valid gzip archive/);
  });

  it("refuses a version other than the signed version", () => {
    const f = fixture();
    runSigner(f);
    expect(() => runVerifier(f, "9.8.8")).toThrow(/manifest shape or version is invalid/);
  });

  it("refuses a signature mutation", () => {
    const f = fixture();
    runSigner(f);
    const parsed = JSON.parse(readFileSync(f.manifest, "utf8"));
    parsed.signature = `${parsed.signature.startsWith("A") ? "B" : "A"}${parsed.signature.slice(1)}`;
    writeFileSync(f.manifest, JSON.stringify(parsed));
    expect(() => runVerifier(f)).toThrow(/signature is invalid/);
  });

  it("accepts the repository's real npm pack format", () => {
    const dir = mkdtempSync(join(tmpdir(), "sanctuary-real-npm-pack-"));
    dirs.push(dir);
    const packed = JSON.parse(execFileSync("npm", ["pack", "--json", "--ignore-scripts", "--pack-destination", dir], {
      cwd: serverRoot,
      encoding: "utf8",
      env: { ...process.env, npm_config_cache: join(dir, "npm-cache") },
    }));
    expect(packed).toHaveLength(1);
    const packageJson = JSON.parse(readFileSync(join(serverRoot, "package.json"), "utf8"));
    const tarball = join(dir, packed[0].filename);
    const manifest = join(dir, "release-manifest.json");
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("base64url");
    const publicKeyB64url = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64url");
    execFileSync(process.execPath, [signer, "--tarball", tarball, "--version", packageJson.version, "--out", manifest, "--expected-public-key", publicKeyB64url], {
      env: { ...process.env, RELEASE_SIGNING_KEY: seed },
      stdio: "pipe",
    });
    expect(execFileSync(process.execPath, [verifier, "--tarball", tarball, "--manifest", manifest, "--version", packageJson.version, "--expected-public-key", publicKeyB64url], { encoding: "utf8" })).toContain("Verified sanctuary-framework-mcp-server-");
  }, 90_000);
});
