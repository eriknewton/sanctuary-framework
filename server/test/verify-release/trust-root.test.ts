/**
 * The committed trusted root: its exact bytes, the one place it is loaded
 * from, the only trust-material construction, and the absence of any Sigstore
 * client in the verifier.
 */
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { TRUSTED_ROOT_RELATIVE_PATH, readTrustedRootBytes, resolveTrustedRootPath } from "../../src/verify-release/trust-root.js";
import { state_BUNDLE_SELECT, state_SIGSTORE } from "../../src/verify-release/sigstore.js";
import { TRUSTED_ROOT_PATH, denyAllNetwork, slsaBundle184 } from "./helpers.js";

denyAllNetwork();

/** Must match EXPECTED_TRUSTED_ROOT_SHA256 in server/scripts/copy-verify-release-trusted-root.mjs and src/verify-release/README.md. */
const TRUSTED_ROOT_SHA256 = "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66";
const SERVER = join(__dirname, "..", "..");
const MODULE_DIR = join(SERVER, "src", "verify-release");

describe("committed trusted root", () => {
  it("has the pinned bytes, and the copy script and README carry the same pin", () => {
    const bytes = readFileSync(TRUSTED_ROOT_PATH);
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(TRUSTED_ROOT_SHA256);
    expect(readFileSync(join(SERVER, "scripts", "copy-verify-release-trusted-root.mjs"), "utf8")).toContain(`EXPECTED_TRUSTED_ROOT_SHA256 = "${TRUSTED_ROOT_SHA256}"`);
    expect(readFileSync(join(MODULE_DIR, "README.md"), "utf8")).toContain(TRUSTED_ROOT_SHA256);
    expect(readFileSync(join(SERVER, "scripts", "copy-verify-release-trusted-root.mjs"), "utf8")).toContain(`TRUSTED_ROOT_RELATIVE_PATH = "${TRUSTED_ROOT_RELATIVE_PATH}"`);
  });

  it("the production loader reads exactly the committed bytes from the source module's folder", async () => {
    expect(resolveTrustedRootPath()).toBe(TRUSTED_ROOT_PATH);
    const bytes = await readTrustedRootBytes();
    expect(createHash("sha256").update(bytes!).digest("hex")).toBe(TRUSTED_ROOT_SHA256);
  });

  it("from the bundled dist/cli.js the root resolves beside it under dist/verify-release", () => {
    const cli = pathToFileURL(join(SERVER, "dist", "cli.js")).href;
    expect(resolveTrustedRootPath(cli)).toBe(join(SERVER, "dist", "verify-release", "trusted_root.json"));
  });

  it("the built dist copy has the pinned bytes", () => {
    const bytes = readFileSync(join(SERVER, "dist", "verify-release", "trusted_root.json"));
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(TRUSTED_ROOT_SHA256);
  });

  it("a one-byte mutation of the committed root, loaded through the production reader, refuses the real 1.8.4 bundle", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vr-root-"));
    try {
      const bytes = Buffer.from(readFileSync(TRUSTED_ROOT_PATH));
      // Byte inside the Rekor v1 public key's base64 (the key that signed the 1.8.4 SET).
      const text = bytes.toString("utf8");
      const keyStart = text.indexOf("\"rawBytes\"", text.indexOf("https://rekor.sigstore.dev"));
      const at = text.indexOf("MFkw", keyStart) + 40;
      bytes[at] = bytes[at] === 0x41 ? 0x42 : 0x41;
      const path = join(dir, "trusted_root.json");
      writeFileSync(path, bytes);
      const mutated = await readTrustedRootBytes(path);
      expect(mutated!.equals(bytes)).toBe(true);
      const selected = state_BUNDLE_SELECT({ attestations: [{ bundle: slsaBundle184() }] });
      const result = await state_SIGSTORE((selected as any).evidence, mutated);
      expect(result.ok).toBe(false);
      expect((result as { reason: string }).reason).toMatch(/^sigstore-invalid:/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("the reader refuses a missing file, a directory, an oversize file and a symlink to a directory", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vr-root-"));
    try {
      expect(await readTrustedRootBytes(join(dir, "absent.json"))).toBeNull();
      mkdirSync(join(dir, "folder"));
      expect(await readTrustedRootBytes(join(dir, "folder"))).toBeNull();
      writeFileSync(join(dir, "big.json"), Buffer.alloc(64 * 1024 + 1, 0x20));
      expect(await readTrustedRootBytes(join(dir, "big.json"))).toBeNull();
      symlinkSync(join(dir, "folder"), join(dir, "link"));
      expect(await readTrustedRootBytes(join(dir, "link"))).toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("trust material construction", () => {
  const sources = readdirSync(MODULE_DIR).filter(name => name.endsWith(".ts"))
    .map(name => [name, readFileSync(join(MODULE_DIR, name), "utf8")] as const);
  /** Code lines only: doc comments may name the construction without performing it. */
  const code = (text: string) => text.split("\n").filter(line => !/^\s*(\*|\/\/|\/\*)/.test(line)).join("\n");
  const all = sources.map(([, text]) => text).join("\n");

  it("has exactly one TrustedRoot.fromJSON and one toTrustMaterial, both in sigstore.ts", () => {
    const count = (pattern: RegExp) => sources.flatMap(([name, text]) => [...code(text).matchAll(pattern)].map(() => name));
    expect(count(/TrustedRoot\.fromJSON\(/g)).toEqual(["sigstore.ts"]);
    expect(count(/toTrustMaterial\(/g)).toEqual(["sigstore.ts"]);
  });

  it("imports no Sigstore client: no TUF, signing, Rekor, Fulcio or CT client package", () => {
    const specifiers = [...all.matchAll(/(?:from|import)\s*\(?\s*"([^"]+)"/g)].map(match => match[1]!);
    const external = [...new Set(specifiers.filter(s => !s.startsWith(".") && !s.startsWith("node:")))].sort();
    expect(external).toEqual(["@sigstore/bundle", "@sigstore/protobuf-specs", "@sigstore/verify"]);
  });

  it("the Sigstore packages are reached only through dynamic import", () => {
    expect(all).not.toMatch(/^import[^;]*from\s*"@sigstore\//m);
    expect(all).not.toMatch(/^import[^;]*from\s*"tar"/m);
  });
});
