/**
 * `sanctuary license` CLI tests (PR-1 — fleet license issuance).
 *
 * Verifies the SELL-side surface end to end against a real keychain-free
 * fortress seeded WITH a default operator identity (the issuer):
 *   - `issue` prints a license token that INDEPENDENTLY resolves `granted` and
 *     appends a tamper-evident ledger row; no secret-key material in output.
 *   - `list` reflects issued + revoked state; `--json` round-trips.
 *   - `revoke` marks the row and surfaces in `list`.
 *   - Fail-closed non-zero exits: unknown tier, past expiry, negative nodes,
 *     no fortress unlock, unknown licenseId on revoke — none leak a secret.
 *
 * The fortress is seeded keychain-free (mocked `security` exec) so the real
 * macOS login keychain is never touched — the pattern in identity-create.test.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Writable } from "node:stream";
import { runLicenseCommand } from "../../src/cli/license.js";
import { fromBase64url } from "../../src/core/encoding.js";
import { runInit as runInitRaw, type InitOptions } from "../../src/wrap/init.js";
import type { ExecResult } from "../../src/wrap/passphrase.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { resolveCliMasterKey } from "../../src/core/master-custody.js";
import {
  resolveEntitlement,
  type EntitlementToken,
} from "../../src/entitlement/index.js";

// ── Keychain-free fortress seeding (mirrors identity-create.test.ts) ──────
type ExecCall = { cmd: string; args: string[]; input?: string };

function unescapeSecurityToken(value: string): string {
  return value.replace(/\\(.)/g, "$1");
}
function readSecurityToken(input: string | undefined, flag: string): string {
  const escapedFlag = flag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = input?.match(
    new RegExp(`${escapedFlag} "((?:[^"\\\\]|\\\\.)*)"`),
  );
  return match ? unescapeSecurityToken(match[1]!) : "";
}
function makeRecoveryKeychainMock(): {
  exec: (cmd: string, args: string[], input?: string) => Promise<ExecResult>;
} {
  const calls: ExecCall[] = [];
  const stored = new Map<string, string>();
  const keyFor = (a: string, s: string): string => `${a}:${s}`;
  const exec = async (
    cmd: string,
    args: string[],
    input?: string,
  ): Promise<ExecResult> => {
    calls.push(input === undefined ? { cmd, args } : { cmd, args, input });
    if (cmd !== "security") return { stdout: "", stderr: "unknown", code: 1 };
    if (args[0] === "-i") {
      stored.set(
        keyFor(readSecurityToken(input, "-a"), readSecurityToken(input, "-s")),
        readSecurityToken(input, "-w"),
      );
      return { stdout: "", stderr: "", code: 0 };
    }
    if (args[0] === "find-generic-password") {
      const account = args[args.indexOf("-a") + 1] ?? "";
      const service = args[args.indexOf("-s") + 1] ?? "";
      const value = stored.get(keyFor(account, service));
      if (value) return { stdout: value + "\n", stderr: "", code: 0 };
      return { stdout: "", stderr: "not found", code: 44 };
    }
    return { stdout: "", stderr: "unknown", code: 1 };
  };
  return { exec };
}
async function runInit(
  options: InitOptions,
): Promise<Awaited<ReturnType<typeof runInitRaw>>> {
  const keychain = makeRecoveryKeychainMock();
  return runInitRaw(options, {
    recoveryKeychain: {
      home: "/tmp/sanctuary-test-home",
      platformOverride: "darwin",
      exec: keychain.exec,
    },
  });
}
function extractRecoveryKey(fileContent: string): string {
  const keyLine = fileContent
    .split("\n")
    .map((l) => l.trim())
    .find((l) => /^[A-Za-z0-9_-]{43}$/.test(l));
  if (!keyLine) throw new Error("recovery key not found");
  return keyLine;
}
class StringWritable extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void,
  ): void {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

/** Seed a keychain-free fortress WITH a default operator identity (the issuer). */
async function seedFortressWithIdentity(
  fortressPath: string,
): Promise<string> {
  const result = await runInit({
    fortress: fortressPath,
    noConfirm: true,
    noPin: true,
    noIdentity: false, // mint the default operator identity (the issuer)
  });
  const recoveryFile = await readFile(result.recoveryKeyDisclosurePath, "utf-8");
  return extractRecoveryKey(recoveryFile);
}

/** Decode a printed license token (base64url of JSON {claims,signature}). */
function decodeLicense(encoded: string): EntitlementToken {
  const json = new TextDecoder().decode(fromBase64url(encoded.trim()));
  return JSON.parse(json) as EntitlementToken;
}

/** Recover the issuer (default operator identity) public key from a fortress. */
async function issuerPublicKey(
  fortressPath: string,
  recoveryKey: string,
): Promise<Uint8Array> {
  const storage = new FilesystemStorage(join(fortressPath, "state"));
  const masterKey = await resolveCliMasterKey(storage, {
    recoveryKey,
    storagePathHint: fortressPath,
  });
  try {
    const mgr = new IdentityManager(storage, masterKey);
    await mgr.load();
    const id = mgr.getDefault();
    if (!id) throw new Error("no default identity");
    const b64 = id.public_key.replace(/-/g, "+").replace(/_/g, "/");
    return new Uint8Array(Buffer.from(b64, "base64"));
  } finally {
    masterKey.fill(0);
  }
}

const FUTURE = "2030-01-01T00:00:00Z";

describe("sanctuary license — help + arg validation (no fortress needed)", () => {
  it("prints usage on --help (exit 0)", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runLicenseCommand({ argv: ["--help"], out, err, env: {} });
    expect(code).toBe(0);
    expect(out.text).toContain("sanctuary license");
    expect(out.text).toContain("issue");
  });

  it("unknown verb → non-zero", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runLicenseCommand({ argv: ["bogus"], out, err, env: {} });
    expect(code).toBe(1);
    expect(err.text).toContain("unknown verb");
  });

  it("issue with unknown tier → exit 1, no secret", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: ["issue", "--tier", "root", "--subject", "x", "--nodes", "5", "--expires", FUTURE],
      out,
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toContain("--tier");
  });

  it("issue with community tier is rejected (paid-only)", async () => {
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: ["issue", "--tier", "community", "--subject", "x", "--nodes", "5", "--expires", FUTURE],
      out: new StringWritable(),
      err,
      env: {},
    });
    expect(code).toBe(1);
  });

  it("issue with a past expiry → exit 1", async () => {
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: ["issue", "--tier", "fleet", "--subject", "x", "--nodes", "5", "--expires", "2000-01-01T00:00:00Z"],
      out: new StringWritable(),
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toContain("past");
  });

  it("issue with negative nodes → exit 1", async () => {
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: ["issue", "--tier", "fleet", "--subject", "x", "--nodes", "-3", "--expires", FUTURE],
      out: new StringWritable(),
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toContain("--nodes");
  });

  it("issue with an unknown feature → exit 1", async () => {
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: [
        "issue", "--tier", "fleet", "--subject", "x", "--nodes", "5",
        "--expires", FUTURE, "--features", "roster,teleport",
      ],
      out: new StringWritable(),
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toContain("unknown feature");
  });

  it("issue with valid flags but NO fortress unlock → exit 1, actionable, no secret", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: ["issue", "--tier", "fleet", "--subject", "x", "--nodes", "5", "--expires", FUTURE],
      out,
      err,
      env: {}, // no passphrase / recovery key
    });
    expect(code).toBe(1);
    expect(err.text).toMatch(/unlocked operator identity is required|keychain/);
    expect(out.text).toBe("");
  });
});

describe("sanctuary license — end-to-end (keychain-free fortress)", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkdtemp(join(tmpdir(), "sanctuary-license-test-"));
  });
  afterEach(async () => {
    delete process.env.SANCTUARY_STORAGE_PATH;
    delete process.env.SANCTUARY_RECOVERY_KEY;
    try {
      await rm(tmp, { recursive: true, force: true });
    } catch {
      // best-effort
    }
  });

  it("issue prints a token that independently resolves granted; no secret leaks", async () => {
    const fortressPath = join(tmp, "f");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: [
        "issue", "--fortress", fortressPath,
        "--tier", "fleet", "--subject", "acme-fleet",
        "--nodes", "25", "--period", "annual", "--expires", FUTURE,
        "--features", "roster,policy-dist,console",
      ],
      out,
      err,
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(code).toBe(0);
    expect(err.text).toBe("");

    const token = decodeLicense(out.text);
    expect(token.claims).toBeTruthy();
    expect(token.signature).toBeTruthy();
    // No secret-key material in the printed output — the token is claims+signature only.
    expect(out.text).not.toMatch(/private/i);

    // Full chain: the printed token INDEPENDENTLY resolves granted against the
    // issuer's public key (recovered from the fortress). This proves the CLI
    // signed a real, verifiable v2 license.
    const pub = await issuerPublicKey(fortressPath, recoveryKey);
    const resolved = resolveEntitlement({
      token,
      issuerPublicKey: pub,
      now: Math.floor(Date.parse(FUTURE) / 1000) - 86_400, // one day before expiry
    });
    expect(resolved.granted).toBe(true);
    expect(resolved.tier).toBe("fleet");
    expect(resolved.entitledCount).toBe(25);
    expect(resolved.period).toBe("annual");
    expect(resolved.featureFlags).toEqual(["console", "policy-dist", "roster"]);
  });

  it("list reflects an issued license, and revoke marks it revoked", async () => {
    const fortressPath = join(tmp, "f2");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;
    const env = { SANCTUARY_RECOVERY_KEY: recoveryKey };

    // Issue.
    const issueOut = new StringWritable();
    const issueCode = await runLicenseCommand({
      argv: [
        "issue", "--fortress", fortressPath, "--tier", "team",
        "--subject", "beta-co", "--nodes", "5", "--expires", FUTURE,
      ],
      out: issueOut,
      err: new StringWritable(),
      env,
    });
    expect(issueCode).toBe(0);
    const token = decodeLicense(issueOut.text);
    const licenseId = (token.claims as { licenseId: string }).licenseId;

    // list --json shows it, not revoked.
    const listOut = new StringWritable();
    const listCode = await runLicenseCommand({
      argv: ["list", "--fortress", fortressPath, "--json"],
      out: listOut,
      err: new StringWritable(),
      env,
    });
    expect(listCode).toBe(0);
    const listed = JSON.parse(listOut.text) as Array<{
      licenseId: string;
      subject: string;
      revoked: boolean;
    }>;
    expect(listed).toHaveLength(1);
    expect(listed[0]!.licenseId).toBe(licenseId);
    expect(listed[0]!.subject).toBe("beta-co");
    expect(listed[0]!.revoked).toBe(false);

    // Revoke.
    const revCode = await runLicenseCommand({
      argv: ["revoke", licenseId, "--fortress", fortressPath, "--reason", "test"],
      out: new StringWritable(),
      err: new StringWritable(),
      env,
    });
    expect(revCode).toBe(0);

    // list now shows revoked.
    const list2 = new StringWritable();
    await runLicenseCommand({
      argv: ["list", "--fortress", fortressPath, "--json"],
      out: list2,
      err: new StringWritable(),
      env,
    });
    const listed2 = JSON.parse(list2.text) as Array<{ revoked: boolean; revokeReason: string | null }>;
    expect(listed2[0]!.revoked).toBe(true);
    expect(listed2[0]!.revokeReason).toBe("test");
  });

  it("revoke of an unknown licenseId → exit 1", async () => {
    const fortressPath = join(tmp, "f3");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: ["revoke", "does-not-exist", "--fortress", fortressPath],
      out: new StringWritable(),
      err,
      env: { SANCTUARY_RECOVERY_KEY: recoveryKey },
    });
    expect(code).toBe(1);
    expect(err.text).toMatch(/unknown/);
  });

  it("list on a fortress with no ledger prints the empty message (exit 0)", async () => {
    const fortressPath = join(tmp, "f4");
    await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;
    const out = new StringWritable();
    const code = await runLicenseCommand({
      argv: ["list", "--fortress", fortressPath],
      out,
      err: new StringWritable(),
      env: {},
    });
    expect(code).toBe(0);
    expect(out.text).toContain("No licenses issued yet");
  });

  it("list on a TAMPERED on-disk ledger exits non-zero with a loud warning, never renders it as trusted", async () => {
    const fortressPath = join(tmp, "f5");
    const recoveryKey = await seedFortressWithIdentity(fortressPath);
    delete process.env.SANCTUARY_STORAGE_PATH;
    const env = { SANCTUARY_RECOVERY_KEY: recoveryKey };

    // Issue a real license so there is a signed ledger on disk.
    const issueOut = new StringWritable();
    const issueCode = await runLicenseCommand({
      argv: [
        "issue", "--fortress", fortressPath, "--tier", "fleet",
        "--subject", "victim", "--nodes", "5", "--expires", FUTURE,
      ],
      out: issueOut,
      err: new StringWritable(),
      env,
    });
    expect(issueCode).toBe(0);

    // Tamper the ledger file on disk: inflate the signed entitledCount. (We do
    // NOT repair the rowHash here; the point is the CLI runs the integrity check
    // AT ALL and refuses to display a tampered ledger — exit non-zero.)
    const ledgerPath = join(fortressPath, "state", "fleet-license-ledger.json");
    const raw = JSON.parse(await readFile(ledgerPath, "utf-8")) as {
      rows: Array<{ token: { claims: { entitledCount: number } } }>;
    };
    raw.rows[0]!.token.claims.entitledCount = 999_999;
    const { writeFile } = await import("node:fs/promises");
    await writeFile(ledgerPath, JSON.stringify(raw, null, 2) + "\n");

    // list must FAIL closed: non-zero exit + a loud tamper warning on stderr,
    // and it must NOT print the (tampered) license rows as if trusted.
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runLicenseCommand({
      argv: ["list", "--fortress", fortressPath],
      out,
      err,
      env: {},
    });
    expect(code).toBe(1);
    expect(err.text).toMatch(/FAILED its integrity check|TAMPERED/);
    expect(out.text).not.toContain("victim");

    // Same for --json: no trusted rows are emitted on tamper.
    const jsonOut = new StringWritable();
    const jsonErr = new StringWritable();
    const jsonCode = await runLicenseCommand({
      argv: ["list", "--fortress", fortressPath, "--json"],
      out: jsonOut,
      err: jsonErr,
      env: {},
    });
    expect(jsonCode).toBe(1);
    expect(jsonOut.text).toBe("");
    expect(jsonErr.text).toMatch(/TAMPERED|integrity check/);
  });
});
