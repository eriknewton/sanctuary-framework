/**
 * `sanctuary secrets` CLI Tests
 *
 * These test the CLI command router end-to-end with an isolated storage
 * path and temp keychain. Since the backend is the real macOS Keychain,
 * these tests are darwin-only (skip elsewhere). CI on linux/windows will
 * skip this file.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable, Readable } from "node:stream";
import { runSecretsCommand } from "../../src/cli/secrets.js";
import { KeychainBackend } from "../../src/l3-disclosure/broker/keychain-backend.js";

const isDarwin = process.platform === "darwin";
const describeIfDarwin = isDarwin ? describe : describe.skip;

class StringWritable extends Writable {
  chunks: string[] = [];
  _write(chunk: Buffer | string, _enc: BufferEncoding, cb: (err?: Error) => void) {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

function stdinFromString(s: string): NodeJS.ReadableStream & { isTTY?: boolean } {
  const stream = Readable.from([Buffer.from(s)]) as unknown as NodeJS.ReadableStream & {
    isTTY?: boolean;
  };
  stream.isTTY = false;
  return stream;
}

describeIfDarwin("sanctuary secrets CLI", () => {
  let tempDir: string;
  let keychainPath: string;
  const PP = "test-pp-cli-4a6d";

  beforeEach(async () => {
    tempDir = mkdtempSync(join(tmpdir(), "sanctuary-cli-secrets-"));
    // openBroker reads $HOME/Library/Keychains/sanctuary.keychain-db. We
    // set HOME=tempDir in each run, so create the keychain at that path.
    const mkdirSync = (await import("node:fs")).mkdirSync;
    mkdirSync(join(tempDir, "Library", "Keychains"), { recursive: true });
    keychainPath = join(tempDir, "Library", "Keychains", "sanctuary.keychain-db");
    const kb = new KeychainBackend({ keychainPath });
    await kb.ensureInitialized(PP);
  });

  afterEach(async () => {
    try {
      const kb = new KeychainBackend({ keychainPath });
      await kb.unlock(PP);
      for (const name of await kb.listSecretNames()) {
        try {
          await kb.deleteSecret(name);
        } catch {}
      }
    } catch {}
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  async function run(argv: string[], stdinStr = "") {
    const out = new StringWritable();
    const err = new StringWritable();
    // Inject the KeychainBackend pointing at our temp path via env override.
    // The open helper reads SANCTUARY_STORAGE_PATH -> loadConfig -> storage_path.
    // We also set the passphrase so no keychain prompt occurs.
    const prevStorage = process.env.SANCTUARY_STORAGE_PATH;
    const prevPP = process.env.SANCTUARY_PASSPHRASE;
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_PASSPHRASE = PP;
    const prevHome = process.env.HOME;
    process.env.HOME = tempDir;

    try {
      const code = await runSecretsCommand({
        argv,
        out,
        err,
        stdin: stdinFromString(stdinStr),
        passphrase: PP,
        storagePath: tempDir,
      });
      return { code, out: out.text, err: err.text };
    } finally {
      process.env.SANCTUARY_STORAGE_PATH = prevStorage;
      process.env.SANCTUARY_PASSPHRASE = prevPP;
      process.env.HOME = prevHome;
    }
  }

  it("prints usage for bare or --help invocation", async () => {
    const r = await run([]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("Usage:");
  });

  it("add -> list -> rotate -> list shows the new secret", async () => {
    let r = await run(["add", "gmail_oauth"], "value-abc\n");
    expect(r.code).toBe(0);
    expect(r.out).toContain("Stored secret: gmail_oauth");

    r = await run(["list"]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("gmail_oauth");

    r = await run(["rotate", "gmail_oauth"], "value-def\n");
    expect(r.code).toBe(0);
    expect(r.out).toContain("Rotated secret: gmail_oauth");
  });

  it("grant writes to broker-policy.json", async () => {
    await run(["add", "gmail_oauth"], "v\n");
    const r = await run(["grant", "gmail-triage", "gmail_oauth", "--scope", "read", "--ttl", "600"]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("Granted: gmail-triage -> gmail_oauth");
    const policyPath = join(tempDir, "broker-policy.json");
    expect(existsSync(policyPath)).toBe(true);
    const body = JSON.parse(readFileSync(policyPath, "utf8"));
    expect(body.skills[0].name).toBe("gmail-triage");
    expect(body.skills[0].secrets[0]).toMatchObject({ name: "gmail_oauth", scope: "read", ttl: 600 });
  });

  it("revoke removes the grant", async () => {
    await run(["add", "gmail_oauth"], "v\n");
    await run(["grant", "gmail-triage", "gmail_oauth"]);
    const r = await run(["revoke", "gmail-triage", "gmail_oauth"]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("Revoked: gmail-triage -> gmail_oauth");
    const policyPath = join(tempDir, "broker-policy.json");
    const body = JSON.parse(readFileSync(policyPath, "utf8"));
    const skill = body.skills.find((s: { name: string }) => s.name === "gmail-triage");
    expect(skill?.secrets).toEqual([]);
  });

  it("rejects invalid scope on grant", async () => {
    const r = await run(["grant", "s", "x", "--scope", "full"]);
    expect(r.code).toBe(2);
    expect(r.err).toContain("--scope must be");
  });

  it("rejects invalid ttl on grant", async () => {
    const r = await run(["grant", "s", "x", "--ttl", "-5"]);
    expect(r.code).toBe(2);
    expect(r.err).toContain("--ttl must be");
  });

  it("delete removes a secret", async () => {
    await run(["add", "gmail_oauth"], "v\n");
    const r = await run(["delete", "gmail_oauth"]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("Deleted secret: gmail_oauth");
  });

  it("audit returns broker-scoped entries", async () => {
    await run(["add", "gmail_oauth"], "v\n");
    await run(["grant", "s", "gmail_oauth"]);
    const r = await run(["audit"]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("broker_secret_added");
    expect(r.out).toContain("broker_secret_granted");
  });

  it("unknown subcommand returns code 2", async () => {
    const r = await run(["frobnicate"]);
    expect(r.code).toBe(2);
    expect(r.err).toContain("Unknown subcommand");
  });
});
